//! OIDC tokens in Cloudflare Workers: verifying them, for any issuer (GitHub
//! Actions, GitLab, Cloudflare Access, or a broker that issues its own), and
//! signing them, for a Worker that is an issuer.
//!
//! A token picks its [`Provider`] by its `iss` claim, which must be one a
//! provider names exactly. Its RS256 signature is checked with the runtime's
//! WebCrypto against that issuer's keys, found through its discovery document
//! (or a configured `jwks_uri`) and never through anything in the token. Then
//! its `iss`, `aud`, `exp` and `nbf` are checked, and it's accepted if one of
//! the provider's [`ClaimSet`]s matches.
//!
//! Keys are cached per isolate, and so is each token's outcome until it
//! expires: [`verified`] reads it back, so whoever verified a token can hand
//! its [`Identity`] to whatever runs next without verifying it again.
//!
//! A Worker that issues its own tokens signs them with a [`SigningKey`], an RSA
//! key imported into WebCrypto, and publishes its [`SigningKey::public_jwk`].
//!
//! The futures aren't `Send`: they hold JavaScript values. A Worker is
//! single-threaded, so a caller that needs `Send`, such as an axum handler,
//! wraps them in `worker::send::SendFuture`.

mod claims;
mod crypto;

use std::{cell::RefCell, collections::HashMap, fmt};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use worker::{AbortSignal, Date, Fetch, Method, Request};

pub use crate::{
    claims::ClaimSet,
    crypto::{ALGORITHM, KeyError, SignedToken, SigningKey},
};

/// Clock tolerance for `exp` and `nbf`.
const LEEWAY_SECS: u64 = 60;

/// How long a fetched JWKS is trusted before it's fetched again.
const JWKS_TTL_MS: u64 = 10 * 60 * 1000;

/// An unknown `kid` refetches an issuer's JWKS at most this often, so tokens
/// with made-up key IDs can't make the Worker hammer the issuer.
const JWKS_MIN_REFETCH_MS: u64 = 30 * 1000;

/// How long an issuer has to answer.
const FETCH_TIMEOUT_MS: u32 = 10 * 1000;

thread_local! {
    /// Each issuer's signing keys, by issuer.
    static JWKS: RefCell<HashMap<String, KeySet>> = RefCell::new(HashMap::new());
    static CACHE: RefCell<IdentityCache> = RefCell::new(IdentityCache::new());
}

/// An OIDC issuer whose tokens are accepted, and which of them.
pub trait Provider {
    /// Matched exactly against a token's `iss`.
    fn issuer(&self) -> &str;
    /// A value the token's `aud` must have. A trailing `/` is ignored, here
    /// and in the token.
    fn audience(&self) -> &str;
    /// Where its keys are. `None` means its discovery document says.
    fn jwks_uri(&self) -> Option<&str>;
    /// A token is accepted if any of these matches; the first one wins.
    fn claims(&self) -> &[ClaimSet];
}

/// Whom a verified token identifies.
#[derive(Clone, Debug, PartialEq)]
pub struct Identity {
    /// The token's `iss`: the issuer of the provider that took it.
    pub issuer: String,
    /// The token's claims.
    pub claims: Map<String, Value>,
    /// The index of the provider's claim set that matched.
    pub claim_set: usize,
}

impl Identity {
    /// The token's `sub`, if it has one.
    pub fn subject(&self) -> Option<&str> {
        let sub = self.claims.get("sub").and_then(Value::as_str);
        sub.filter(|sub| !sub.is_empty())
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let subject = self.subject().unwrap_or("unknown");
        write!(
            f,
            "{subject} from {} (claims[{}])",
            self.issuer, self.claim_set
        )
    }
}

/// Why a token was not accepted.
#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// A missing or invalid token, or one from an issuer no provider is for.
    Unauthorized(String),
    /// A valid token none of its provider's claim sets matches. Which would
    /// have isn't said: that's the configuration, not the caller's to probe.
    Forbidden {
        /// The token's `iss`.
        issuer: String,
        /// The token's `sub`.
        subject: Option<String>,
    },
    /// An issuer's discovery document or keys couldn't be had. Not the
    /// caller's fault.
    Upstream(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized(message) | Self::Upstream(message) => f.write_str(message),
            Self::Forbidden { issuer, .. } => {
                write!(f, "the token matches none of {issuer}'s claim sets")
            }
        }
    }
}

impl std::error::Error for Error {}

fn invalid(what: &str) -> Error {
    Error::Unauthorized(format!("invalid token: {what}"))
}

/// Verifies `token` against the provider its `iss` names, and keeps the
/// outcome for [`verified`] until the token expires.
///
/// # Errors
///
/// Why the token isn't accepted.
pub async fn verify<P: Provider>(token: &str, providers: &[P]) -> Result<Identity, Error> {
    let now_ms = Date::now().as_millis();
    let key = IdentityCache::key(token);
    if let Some(result) = CACHE.with_borrow(|cache| cache.get(&key, now_ms)) {
        return result;
    }

    let jwt = Jwt::decode(token)?;
    let provider = find_by_claims(providers, &jwt.claims)?;
    let result = verify_token(provider, &jwt, now_ms).await;
    // A verified token's identity can't change, so both outcomes hold until
    // it expires. Expiry and other time-based failures are not cached.
    if matches!(result, Ok(_) | Err(Error::Forbidden { .. }))
        && let Some(exp) = jwt.claims.get("exp").and_then(Value::as_u64)
    {
        let expires_at = (exp + LEEWAY_SECS) * 1000;
        CACHE.with_borrow_mut(|cache| cache.insert(key, result.clone(), expires_at, now_ms));
    }
    result
}

/// The identity of `token`, if [`verify`] accepted it in this isolate and it
/// hasn't expired since.
pub fn verified(token: &str) -> Option<Identity> {
    let key = IdentityCache::key(token);
    CACHE
        .with_borrow(|cache| cache.get(&key, Date::now().as_millis()))
        .and_then(Result::ok)
}

/// Whether `url` is somewhere keys may be fetched from: HTTPS, or plain HTTP
/// on a loopback address, for a local issuer in development.
///
/// # Errors
///
/// Why it isn't.
pub fn check_url(url: &str) -> Result<(), &'static str> {
    let loopback = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
        .iter()
        .any(|prefix| {
            url.strip_prefix(prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/']))
        });
    let https = url
        .strip_prefix("https://")
        .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'));
    if url.contains(char::is_whitespace) || !(https || loopback) {
        return Err("must be an https:// URL");
    }
    Ok(())
}

/// The provider a token's claims say it comes from, by its `iss`, read
/// unverified only to pick the keys to verify it with.
fn find_by_claims<'p, P: Provider>(
    providers: &'p [P],
    claims: &Map<String, Value>,
) -> Result<&'p P, Error> {
    let iss = claims
        .get("iss")
        .and_then(Value::as_str)
        .unwrap_or_default();
    providers
        .iter()
        .find(|provider| provider.issuer() == iss)
        .ok_or_else(|| {
            let shown: String = iss.chars().take(200).collect();
            Error::Unauthorized(format!("no provider is for issuer {shown}"))
        })
}

/// Verifies `jwt`, a token that claims to come from `provider`, and matches
/// it against the provider's claim sets.
async fn verify_token<P: Provider>(
    provider: &P,
    jwt: &Jwt<'_>,
    now_ms: u64,
) -> Result<Identity, Error> {
    let jwk = find_key(provider, jwt.kid.as_deref(), now_ms).await?;
    if !jwk
        .verify_rs256(jwt.signing_input.as_bytes(), &jwt.signature)
        .await?
    {
        return Err(invalid("bad signature"));
    }
    check_claims(provider, &jwt.claims, now_ms / 1000)
}

/// Checks the claims of a token whose signature `provider`'s keys verified.
fn check_claims<P: Provider>(
    provider: &P,
    claims: &Map<String, Value>,
    now_secs: u64,
) -> Result<Identity, Error> {
    let claim = |name| claims.get(name);

    if claim("iss").and_then(Value::as_str) != Some(provider.issuer()) {
        return Err(invalid("wrong issuer"));
    }

    let expected = provider.audience().trim_end_matches('/');
    let ours = |aud: &Value| {
        aud.as_str()
            .is_some_and(|aud| aud.trim_end_matches('/') == expected)
    };
    let audience_ok = match claim("aud") {
        Some(Value::Array(auds)) => auds.iter().any(ours),
        Some(aud) => ours(aud),
        None => false,
    };
    if !audience_ok {
        let got = match claim("aud") {
            Some(Value::String(aud)) => aud.clone(),
            Some(Value::Array(auds)) => auds
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", "),
            _ => "missing".to_string(),
        };
        let got: String = got.chars().take(200).collect();
        return Err(Error::Unauthorized(format!(
            "token audience is {got}, expected {}",
            provider.audience()
        )));
    }

    let Some(exp) = claim("exp").and_then(Value::as_u64) else {
        return Err(invalid("missing exp"));
    };
    if now_secs >= exp + LEEWAY_SECS {
        return Err(Error::Unauthorized("token expired".to_string()));
    }
    if let Some(nbf) = claim("nbf").and_then(Value::as_u64)
        && nbf > now_secs + LEEWAY_SECS
    {
        return Err(Error::Unauthorized("token not valid yet".to_string()));
    }

    let issuer = provider.issuer().to_string();
    match provider.claims().iter().position(|set| set.matches(claims)) {
        Some(claim_set) => Ok(Identity {
            issuer,
            claims: claims.clone(),
            claim_set,
        }),
        None => Err(Error::Forbidden {
            issuer,
            subject: claim("sub").and_then(Value::as_str).map(String::from),
        }),
    }
}

async fn find_key<P: Provider>(provider: &P, kid: Option<&str>, now_ms: u64) -> Result<Jwk, Error> {
    let unknown = || invalid("unknown signing key");
    let issuer = provider.issuer();

    match JWKS.with_borrow(|sets| KeySet::lookup(sets.get(issuer), kid, now_ms)) {
        Lookup::Hit(key) => return Ok(key),
        Lookup::Unknown => return Err(unknown()),
        Lookup::Fetch => {}
    }

    let set = fetch_jwks(provider, now_ms).await?;
    let key = set.find(kid).cloned();
    JWKS.with_borrow_mut(|sets| sets.insert(issuer.to_string(), set));
    key.ok_or_else(unknown)
}

async fn fetch_jwks<P: Provider>(provider: &P, now_ms: u64) -> Result<KeySet, Error> {
    let issuer = provider.issuer();
    let jwks_uri = match provider.jwks_uri() {
        Some(jwks_uri) => jwks_uri.to_string(),
        None => {
            let url = format!(
                "{}/.well-known/openid-configuration",
                issuer.trim_end_matches('/')
            );
            let discovery: Discovery = fetch_json(&url).await?;
            // OIDC Discovery requires the document to name its own issuer, so
            // one issuer can't hand out another's keys.
            if discovery.issuer != issuer {
                return Err(Error::Upstream(format!(
                    "{url} is for issuer {}, not {issuer}",
                    discovery.issuer
                )));
            }
            check_url(&discovery.jwks_uri)
                .map_err(|why| Error::Upstream(format!("{url}: jwks_uri {why}")))?;
            discovery.jwks_uri
        }
    };
    let jwks: Jwks = fetch_json(&jwks_uri).await?;
    Ok(KeySet::parse(jwks, now_ms))
}

async fn fetch_json<T: DeserializeOwned>(url: &str) -> Result<T, Error> {
    let upstream = |err: worker::Error| Error::Upstream(format!("fetching {url}: {err}"));

    // `Request::new` hands the URL to the runtime; `Url::parse` would pull the
    // `url` crate and its IDNA tables into the bundle.
    let req = Request::new(url, Method::Get).map_err(upstream)?;
    let signal = AbortSignal::from(web_sys::AbortSignal::timeout_with_u32(FETCH_TIMEOUT_MS));
    let mut resp = Fetch::Request(req)
        .send_with_signal(&signal)
        .await
        .map_err(upstream)?;
    if resp.status_code() != 200 {
        return Err(Error::Upstream(format!(
            "fetching {url} returned {}",
            resp.status_code()
        )));
    }
    resp.json().await.map_err(upstream)
}

/// A decoded, not yet verified, JWT.
struct Jwt<'a> {
    kid: Option<String>,
    claims: Map<String, Value>,
    /// `<header>.<payload>`, the bytes the signature covers.
    signing_input: &'a str,
    signature: Vec<u8>,
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    kid: Option<String>,
}

impl<'a> Jwt<'a> {
    fn decode(jwt: &'a str) -> Result<Self, Error> {
        let not_a_jwt = || invalid("not a JWT");
        let segment = |s: &str| URL_SAFE_NO_PAD.decode(s).map_err(|_| not_a_jwt());

        let parts: Vec<&str> = jwt.split('.').collect();
        let [header, payload, signature] = parts[..] else {
            return Err(not_a_jwt());
        };

        let header: JwtHeader =
            serde_json::from_slice(&segment(header)?).map_err(|_| not_a_jwt())?;
        let claims = serde_json::from_slice(&segment(payload)?).map_err(|_| not_a_jwt())?;
        if header.alg != ALGORITHM {
            return Err(invalid("alg must be RS256"));
        }

        Ok(Jwt {
            kid: header.kid,
            claims,
            signing_input: &jwt[..jwt.len() - signature.len() - 1],
            signature: segment(signature)?,
        })
    }
}

/// The part of an issuer's discovery document read.
#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<RawJwk>,
}

#[derive(Deserialize)]
struct RawJwk {
    kty: String,
    kid: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
struct Jwk {
    kid: Option<String>,
    n: String,
    e: String,
}

impl Jwk {
    /// Verifies an RS256 signature with WebCrypto.
    async fn verify_rs256(&self, signing_input: &[u8], signature: &[u8]) -> Result<bool, Error> {
        crypto::verify_rs256(&self.n, &self.e, signing_input, signature)
            .await
            .map_err(|err| Error::Upstream(err.to_string()))
    }
}

/// An issuer's signing keys, cached per isolate.
struct KeySet {
    keys: Vec<Jwk>,
    fetched_at: u64,
}

#[derive(Debug, PartialEq)]
enum Lookup {
    Hit(Jwk),
    Fetch,
    /// Unknown `kid`, and the JWKS was fetched too recently to try again.
    Unknown,
}

impl KeySet {
    fn parse(jwks: Jwks, fetched_at: u64) -> Self {
        let keys = jwks
            .keys
            .into_iter()
            .filter(|key| key.kty == "RSA")
            .filter_map(|key| {
                Some(Jwk {
                    kid: key.kid,
                    n: key.n?,
                    e: key.e?,
                })
            })
            .collect();
        Self { keys, fetched_at }
    }

    /// The key with this `kid`; without one, the only key there is.
    fn find(&self, kid: Option<&str>) -> Option<&Jwk> {
        match kid {
            Some(kid) => self.keys.iter().find(|key| key.kid.as_deref() == Some(kid)),
            None => match self.keys.as_slice() {
                [only] => Some(only),
                _ => None,
            },
        }
    }

    fn lookup(set: Option<&KeySet>, kid: Option<&str>, now_ms: u64) -> Lookup {
        let Some(set) = set else {
            return Lookup::Fetch;
        };
        let age = now_ms.saturating_sub(set.fetched_at);
        match set.find(kid) {
            Some(key) if age < JWKS_TTL_MS => Lookup::Hit(key.clone()),
            Some(_) => Lookup::Fetch,
            None if age < JWKS_MIN_REFETCH_MS => Lookup::Unknown,
            None => Lookup::Fetch,
        }
    }
}

/// Per-isolate cache of verification outcomes, keyed by the SHA-256 of the
/// token so raw tokens are never stored.
///
/// Holds refusals as well as identities, so a token no claim set allows isn't
/// verified again on every request either.
struct IdentityCache {
    entries: HashMap<[u8; 32], (u64, Result<Identity, Error>)>,
}

impl IdentityCache {
    /// Upper bound on entries, so a flood of distinct tokens can't grow the
    /// isolate's memory without limit.
    const MAX_ENTRIES: usize = 1024;

    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn key(token: &str) -> [u8; 32] {
        Sha256::digest(token.as_bytes()).into()
    }

    fn get(&self, key: &[u8; 32], now_ms: u64) -> Option<Result<Identity, Error>> {
        self.entries
            .get(key)
            .filter(|(expires_at, _)| now_ms < *expires_at)
            .map(|(_, result)| result.clone())
    }

    fn insert(
        &mut self,
        key: [u8; 32],
        result: Result<Identity, Error>,
        expires_at: u64,
        now_ms: u64,
    ) {
        if self.entries.len() >= Self::MAX_ENTRIES {
            self.entries
                .retain(|_, (expires_at, _)| now_ms < *expires_at);
        }
        if self.entries.len() >= Self::MAX_ENTRIES {
            self.entries.clear();
        }
        self.entries.insert(key, (expires_at, result));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const NOW: u64 = 1_800_000_000;
    const ISSUER: &str = "https://token.actions.githubusercontent.com";
    const AUDIENCE: &str = "https://cf-oidc-exchange.example.com";

    struct TestProvider {
        issuer: &'static str,
        claims: Vec<ClaimSet>,
    }

    impl Provider for TestProvider {
        fn issuer(&self) -> &str {
            self.issuer
        }
        fn audience(&self) -> &str {
            AUDIENCE
        }
        fn jwks_uri(&self) -> Option<&str> {
            None
        }
        fn claims(&self) -> &[ClaimSet] {
            &self.claims
        }
    }

    fn provider(claims: Value) -> TestProvider {
        TestProvider {
            issuer: ISSUER,
            claims: serde_json::from_value(claims).unwrap(),
        }
    }

    fn claims() -> Map<String, Value> {
        json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "repo:example-org/app:ref:refs/heads/main",
            "exp": NOW + 300,
            "nbf": NOW - 10,
            "iat": NOW - 10,
            "repository_owner_id": "100000001",
            "ref": "refs/heads/main",
        })
        .as_object()
        .unwrap()
        .clone()
    }

    fn identity() -> Result<Identity, Error> {
        Ok(Identity {
            issuer: ISSUER.to_string(),
            claims: claims(),
            claim_set: 0,
        })
    }

    #[test]
    fn identity_cache_expires_entries() {
        let mut cache = IdentityCache::new();
        let key = IdentityCache::key("token");
        cache.insert(key, identity(), 100, 0);
        assert_eq!(cache.get(&key, 99), Some(identity()));
        assert_eq!(cache.get(&key, 100), None);
    }

    #[test]
    fn identity_cache_holds_refusals() {
        let mut cache = IdentityCache::new();
        let key = IdentityCache::key("token");
        let refused = Err(Error::Forbidden {
            issuer: ISSUER.to_string(),
            subject: None,
        });
        cache.insert(key, refused.clone(), 100, 0);
        assert_eq!(cache.get(&key, 0), Some(refused));
    }

    #[test]
    fn identity_cache_is_bounded() {
        let mut cache = IdentityCache::new();
        for i in 0..=IdentityCache::MAX_ENTRIES {
            cache.insert(IdentityCache::key(&i.to_string()), identity(), 100, 0);
        }
        assert!(cache.entries.len() <= IdentityCache::MAX_ENTRIES);
    }

    #[test]
    fn identity_is_shown_with_its_issuer() {
        assert_eq!(
            identity().unwrap().to_string(),
            "repo:example-org/app:ref:refs/heads/main from https://token.actions.githubusercontent.com (claims[0])"
        );
    }

    #[test]
    fn picks_the_provider_by_the_tokens_issuer() {
        let providers = [provider(json!([{ "ref": "x" }]))];
        assert_eq!(
            find_by_claims(&providers, &claims()).unwrap().issuer(),
            ISSUER
        );

        let mut other = claims();
        other.insert("iss".into(), "https://other.example.com".into());
        assert_eq!(
            find_by_claims(&providers, &other).err(),
            Some(Error::Unauthorized(
                "no provider is for issuer https://other.example.com".into()
            ))
        );
    }

    #[test]
    fn check_claims_returns_the_first_matching_set() {
        let provider = provider(
            json!([{ "ref": "refs/heads/release" }, { "repository_owner_id": "100000001" }]),
        );
        let identity = check_claims(&provider, &claims(), NOW).unwrap();
        assert_eq!(identity.claim_set, 1);
        assert_eq!(identity.claims, claims());
    }

    #[test]
    fn check_claims_accepts_an_audience_array_and_a_trailing_slash() {
        let provider = provider(json!([{ "ref": "refs/heads/main" }]));
        for aud in [
            json!(["https://other.example.com", AUDIENCE]),
            json!(format!("{AUDIENCE}/")),
        ] {
            let mut claims = claims();
            claims.insert("aud".into(), aud.clone());
            assert!(check_claims(&provider, &claims, NOW).is_ok(), "{aud}");
        }
    }

    #[test]
    fn check_claims_says_what_is_wrong() {
        let provider = provider(json!([{ "ref": "refs/heads/main" }]));
        let cases: [(&str, Value, &str); 6] = [
            (
                "iss",
                json!("https://other.example.com"),
                "invalid token: wrong issuer",
            ),
            (
                "aud",
                json!("sts.amazonaws.com"),
                "token audience is sts.amazonaws.com, expected https://cf-oidc-exchange.example.com",
            ),
            (
                "aud",
                Value::Null,
                "token audience is missing, expected https://cf-oidc-exchange.example.com",
            ),
            ("exp", json!(NOW - LEEWAY_SECS), "token expired"),
            ("nbf", json!(NOW + LEEWAY_SECS + 1), "token not valid yet"),
            ("exp", Value::Null, "invalid token: missing exp"),
        ];
        for (claim, value, expected) in cases {
            let mut claims = claims();
            claims.insert(claim.into(), value);
            assert_eq!(
                check_claims(&provider, &claims, NOW),
                Err(Error::Unauthorized(expected.to_string())),
                "{claim}"
            );
        }
    }

    #[test]
    fn check_claims_tolerates_clock_skew() {
        let provider = provider(json!([{ "ref": "refs/heads/main" }]));
        let mut claims = claims();
        claims.insert("nbf".into(), json!(NOW + LEEWAY_SECS));
        assert!(check_claims(&provider, &claims, NOW).is_ok());
        assert!(check_claims(&provider, &claims, NOW + 300 + LEEWAY_SECS - 1).is_ok());
    }

    #[test]
    fn check_claims_forbids_when_no_set_matches() {
        let provider = provider(json!([{ "ref": "refs/heads/release" }]));
        let err = check_claims(&provider, &claims(), NOW).unwrap_err();
        assert_eq!(
            err,
            Error::Forbidden {
                issuer: ISSUER.to_string(),
                subject: Some("repo:example-org/app:ref:refs/heads/main".to_string()),
            }
        );
        assert_eq!(
            err.to_string(),
            "the token matches none of https://token.actions.githubusercontent.com's claim sets"
        );
    }

    fn segment(value: Value) -> String {
        URL_SAFE_NO_PAD.encode(value.to_string())
    }

    #[test]
    fn decode_splits_a_jwt() {
        let header = segment(json!({ "alg": "RS256", "kid": "key-1" }));
        let payload = segment(Value::Object(claims()));
        let jwt = format!("{header}.{payload}.c2ln");

        let token = Jwt::decode(&jwt).expect("should decode");
        assert_eq!(token.kid.as_deref(), Some("key-1"));
        assert_eq!(token.signing_input, format!("{header}.{payload}"));
        assert_eq!(token.signature, b"sig");
        assert_eq!(token.claims, claims());
    }

    #[test]
    fn decode_rejects_anything_else() {
        let payload = segment(json!({ "iss": ISSUER }));
        let cases = [
            ("gho_notAJwt".to_string(), "not a JWT"),
            ("not.a.jwt".to_string(), "not a JWT"),
            ("a.b.c.d".to_string(), "not a JWT"),
            (
                format!("{}.{payload}.c2ln", segment(json!({ "alg": "none" }))),
                "alg must be RS256",
            ),
            (
                format!("{}.{payload}.c2ln", segment(json!({ "alg": "HS256" }))),
                "alg must be RS256",
            ),
        ];
        for (jwt, expected) in cases {
            assert_eq!(Jwt::decode(&jwt).err(), Some(invalid(expected)), "{jwt}");
        }
    }

    #[test]
    fn keyset_keeps_rsa_keys_and_refetches_sparingly() {
        let jwks: Jwks = serde_json::from_value(json!({ "keys": [
            { "kty": "RSA", "kid": "key-1", "n": "AQAB", "e": "AQAB" },
            { "kty": "EC", "kid": "key-2", "x": "AA", "y": "AA" },
        ]}))
        .unwrap();
        let set = KeySet::parse(jwks, 0);
        assert_eq!(set.keys.len(), 1);

        assert_eq!(KeySet::lookup(None, Some("key-1"), 0), Lookup::Fetch);
        assert!(matches!(
            KeySet::lookup(Some(&set), Some("key-1"), 1),
            Lookup::Hit(_)
        ));
        // Without a kid, the only key.
        assert!(matches!(
            KeySet::lookup(Some(&set), None, 1),
            Lookup::Hit(_)
        ));
        assert_eq!(
            KeySet::lookup(Some(&set), Some("key-1"), JWKS_TTL_MS),
            Lookup::Fetch
        );
        assert_eq!(
            KeySet::lookup(Some(&set), Some("key-2"), 1),
            Lookup::Unknown
        );
        assert_eq!(
            KeySet::lookup(Some(&set), Some("key-2"), JWKS_MIN_REFETCH_MS),
            Lookup::Fetch
        );
    }

    #[test]
    fn allows_http_only_on_loopback() {
        for url in [
            "https://issuer.example.com",
            "http://127.0.0.1:8788",
            "http://localhost",
            "http://[::1]:9000/oidc",
        ] {
            assert_eq!(check_url(url), Ok(()), "{url}");
        }
        for url in [
            "http://issuer.example.com",
            "https://",
            "http://127.0.0.1.example.com",
            "http://localhost.example.com",
            "https://issuer.example.com/a b",
        ] {
            assert!(check_url(url).is_err(), "{url}");
        }
    }
}
