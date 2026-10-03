//! OIDC tokens in Cloudflare Workers: verifying them, for any issuer (GitHub
//! Actions, GitLab, Cloudflare Access, or a broker that issues its own), and
//! signing them, for a Worker that is an issuer.
//!
//! Accepting a token takes two steps:
//!
//! 1. [`verify`] validates it as RFC 7519 §7.2 and RFC 8725 say. It picks its
//!    [`Provider`] by its `iss` claim, which must be one a provider names
//!    exactly, and checks its JOSE [`Header`]. Its RS256 signature is checked
//!    with the runtime's WebCrypto against that issuer's keys, found through
//!    its OpenID Provider Metadata (or a configured `jwks_uri`) and never
//!    through anything in the token. Then its registered [`Claims`] are
//!    validated: `iss`, `aud`, `exp` and `nbf`.
//! 2. [`authorize`] matches its claims against [`ClaimRule`]s: the policy,
//!    which no RFC says anything about.
//!
//! Keys are cached per isolate, and so is each verified token until it
//! expires: [`verified`] reads it back, so whoever verified a token can hand
//! it to whatever runs next without verifying it again.
//!
//! A Worker that issues its own tokens signs them with a [`SigningKey`], an RSA
//! key imported into WebCrypto, and publishes its [`SigningKey::public_jwk`].
//!
//! The futures aren't `Send`: they hold JavaScript values. A Worker is
//! single-threaded, so a caller that needs `Send`, such as an axum handler,
//! wraps them in `worker::send::SendFuture`.

mod crypto;
mod jwks;
mod jwt;
mod rule;

use std::{cell::RefCell, collections::HashMap, fmt};

use sha2::{Digest, Sha256};
use worker::Date;

use crate::jwt::{LEEWAY_SECS, Unverified};
pub use crate::{
    crypto::{ALGORITHM, AT_JWT, JWT, KeyError, SignedToken, SigningKey},
    jwt::{AccessTokenClaims, Claims, Header, Jwt},
    rule::ClaimRule,
};

thread_local! {
    static VERIFIED: RefCell<VerifiedCache> = RefCell::new(VerifiedCache::new());
}

/// An OpenID Provider whose tokens are accepted: the issuer, and what its
/// tokens must be to be verified. Implement it on your configuration's type.
pub trait Provider {
    /// Its issuer identifier, matched exactly against a token's `iss`.
    fn issuer(&self) -> &str;

    /// The audience a token's `aud` must contain: whoever verifies it. A
    /// trailing `/` is ignored, here and in the token.
    fn audience(&self) -> &str;

    /// Where its JWK Set is. `None`, the default, reads it from the
    /// `jwks_uri` of its OpenID Provider Metadata.
    fn jwks_uri(&self) -> Option<&str> {
        None
    }

    /// The `typ` its tokens must have (RFC 8725 §3.11), such as `at+jwt`, so
    /// another kind of token it issues can't pass for one. `None`, the
    /// default, takes any.
    fn typ(&self) -> Option<&str> {
        None
    }
}

/// Why a token isn't accepted, as the error codes of RFC 6750 §3.1 (and RFC
/// 6749 §4.1.2.1, for an issuer that can't be reached) have it.
#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// `invalid_token`: malformed, not signed by its issuer's keys, for
    /// another audience, expired, or from an issuer no provider is for.
    InvalidToken(String),
    /// `insufficient_scope`: a valid token none of the [`ClaimRule`]s
    /// matches. Which would have isn't said: that's the configuration, not
    /// the caller's to probe.
    InsufficientScope {
        /// The token's `iss`.
        issuer: String,
        /// The token's `sub`.
        subject: Option<String>,
    },
    /// `temporarily_unavailable`: the issuer's metadata or keys couldn't be
    /// had. Not the caller's fault.
    TemporarilyUnavailable(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidToken(message) | Self::TemporarilyUnavailable(message) => {
                f.write_str(message)
            }
            Self::InsufficientScope { issuer, .. } => {
                write!(f, "the token matches none of {issuer}'s claim rules")
            }
        }
    }
}

impl std::error::Error for Error {}

fn invalid(what: &str) -> Error {
    Error::InvalidToken(format!("invalid token: {what}"))
}

/// Verifies `token`, a JWT, against the provider its `iss` names: its
/// header, its signature, then its registered claims. Returns that provider
/// and the token, which [`verified`] gives back until it expires.
///
/// # Errors
///
/// [`Error::InvalidToken`] when it isn't valid, and
/// [`Error::TemporarilyUnavailable`] when its issuer's keys can't be had.
pub async fn verify<'p, P: Provider>(
    token: &str,
    providers: &'p [P],
) -> Result<(&'p P, Jwt), Error> {
    let now_ms = Date::now().as_millis();
    let key = VerifiedCache::key(token);
    if let Some(jwt) = VERIFIED.with_borrow(|cache| cache.get(&key, now_ms)) {
        // Its signature holds; its claims are checked again, as cheap as
        // that is, against the provider it's from now.
        let provider = find_provider(providers, &jwt.claims)?;
        check_header(provider, &jwt.header)?;
        jwt.claims
            .validate(provider.issuer(), provider.audience(), now_ms / 1000)?;
        return Ok((provider, jwt));
    }

    let Unverified {
        jwt,
        signing_input,
        signature,
    } = Unverified::decode(token)?;
    let provider = find_provider(providers, &jwt.claims)?;
    check_header(provider, &jwt.header)?;
    let rsa_key = jwks::find_key(provider, jwt.header.kid.as_deref(), now_ms).await?;
    if !rsa_key.verify(signing_input.as_bytes(), &signature).await? {
        return Err(invalid("bad signature"));
    }
    jwt.claims
        .validate(provider.issuer(), provider.audience(), now_ms / 1000)?;

    if let Some(exp) = jwt.claims.exp() {
        let expires_at = (exp + LEEWAY_SECS) * 1000;
        VERIFIED.with_borrow_mut(|cache| cache.insert(key, jwt.clone(), expires_at, now_ms));
    }
    Ok((provider, jwt))
}

/// The index of the first of `rules` that `claims` match: what lets a
/// verified token in.
///
/// # Errors
///
/// [`Error::InsufficientScope`] when none does.
pub fn authorize(claims: &Claims, rules: &[ClaimRule]) -> Result<usize, Error> {
    rules
        .iter()
        .position(|rule| rule.matches(claims))
        .ok_or_else(|| Error::InsufficientScope {
            issuer: claims.iss().unwrap_or_default().to_string(),
            subject: claims.sub().map(String::from),
        })
}

/// `token`, if [`verify`] accepted it in this isolate and it hasn't expired
/// since.
pub fn verified(token: &str) -> Option<Jwt> {
    let key = VerifiedCache::key(token);
    VERIFIED.with_borrow(|cache| cache.get(&key, Date::now().as_millis()))
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
fn find_provider<'p, P: Provider>(providers: &'p [P], claims: &Claims) -> Result<&'p P, Error> {
    let iss = claims.iss().unwrap_or_default();
    providers
        .iter()
        .find(|provider| provider.issuer() == iss)
        .ok_or_else(|| {
            let shown: String = iss.chars().take(200).collect();
            Error::InvalidToken(format!("no provider is for issuer {shown}"))
        })
}

/// What `provider` needs of a token's JOSE Header beyond what decoding it
/// checked: its `typ`, if the provider names one.
fn check_header<P: Provider>(provider: &P, header: &Header) -> Result<(), Error> {
    match provider.typ() {
        Some(typ) if !header.typ_is(typ) => Err(invalid(&format!("typ must be {typ}"))),
        _ => Ok(()),
    }
}

/// Per-isolate cache of verified tokens, keyed by the SHA-256 of the token
/// so raw tokens are never stored.
struct VerifiedCache {
    entries: HashMap<[u8; 32], (u64, Jwt)>,
}

impl VerifiedCache {
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

    fn get(&self, key: &[u8; 32], now_ms: u64) -> Option<Jwt> {
        self.entries
            .get(key)
            .filter(|(expires_at, _)| now_ms < *expires_at)
            .map(|(_, jwt)| jwt.clone())
    }

    fn insert(&mut self, key: [u8; 32], jwt: Jwt, expires_at: u64, now_ms: u64) {
        if self.entries.len() >= Self::MAX_ENTRIES {
            self.entries
                .retain(|_, (expires_at, _)| now_ms < *expires_at);
        }
        if self.entries.len() >= Self::MAX_ENTRIES {
            self.entries.clear();
        }
        self.entries.insert(key, (expires_at, jwt));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value, json};

    use super::*;

    const NOW: u64 = 1_800_000_000;
    const ISSUER: &str = "https://token.actions.githubusercontent.com";
    const AUDIENCE: &str = "https://cf-oidc-exchange.example.com";

    struct TestProvider {
        typ: Option<&'static str>,
    }

    impl Provider for TestProvider {
        fn issuer(&self) -> &str {
            ISSUER
        }
        fn audience(&self) -> &str {
            AUDIENCE
        }
        fn typ(&self) -> Option<&str> {
            self.typ
        }
    }

    fn claims() -> Claims {
        let claims: Map<String, Value> = json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "repo:example-org/app:ref:refs/heads/main",
            "exp": NOW + 300,
            "repository_owner_id": "100000001",
            "ref": "refs/heads/main",
        })
        .as_object()
        .unwrap()
        .clone();
        claims.into()
    }

    fn jwt() -> Jwt {
        Jwt {
            header: Header {
                alg: ALGORITHM.into(),
                kid: Some("key-1".into()),
                typ: Some("JWT".into()),
            },
            claims: claims(),
        }
    }

    fn rules(rules: Value) -> Vec<ClaimRule> {
        serde_json::from_value(rules).unwrap()
    }

    #[test]
    fn cache_expires_entries() {
        let mut cache = VerifiedCache::new();
        let key = VerifiedCache::key("token");
        cache.insert(key, jwt(), 100, 0);
        assert_eq!(cache.get(&key, 99), Some(jwt()));
        assert_eq!(cache.get(&key, 100), None);
    }

    #[test]
    fn cache_is_bounded() {
        let mut cache = VerifiedCache::new();
        for i in 0..=VerifiedCache::MAX_ENTRIES {
            cache.insert(VerifiedCache::key(&i.to_string()), jwt(), 100, 0);
        }
        assert!(cache.entries.len() <= VerifiedCache::MAX_ENTRIES);
    }

    #[test]
    fn picks_the_provider_by_the_tokens_issuer() {
        let providers = [TestProvider { typ: None }];
        assert_eq!(
            find_provider(&providers, &claims()).unwrap().issuer(),
            ISSUER
        );

        let mut other: Map<String, Value> = claims().into();
        other.insert("iss".into(), "https://other.example.com".into());
        assert_eq!(
            find_provider(&providers, &other.into()).err(),
            Some(Error::InvalidToken(
                "no provider is for issuer https://other.example.com".into()
            ))
        );
    }

    #[test]
    fn checks_the_typ_a_provider_names() {
        let header = jwt().header;
        assert_eq!(check_header(&TestProvider { typ: None }, &header), Ok(()));
        assert_eq!(
            check_header(&TestProvider { typ: Some("jwt") }, &header),
            Ok(())
        );
        assert_eq!(
            check_header(
                &TestProvider {
                    typ: Some("at+jwt")
                },
                &header
            ),
            Err(invalid("typ must be at+jwt"))
        );
    }

    #[test]
    fn authorize_returns_the_first_matching_rule() {
        let rules = rules(json!([
            { "ref": "refs/heads/release" },
            { "repository_owner_id": "100000001" },
            { "ref": "refs/heads/*" },
        ]));
        assert_eq!(authorize(&claims(), &rules), Ok(1));
    }

    #[test]
    fn authorize_refuses_when_no_rule_matches() {
        let err =
            authorize(&claims(), &rules(json!([{ "ref": "refs/heads/release" }]))).unwrap_err();
        assert_eq!(
            err,
            Error::InsufficientScope {
                issuer: ISSUER.to_string(),
                subject: Some("repo:example-org/app:ref:refs/heads/main".to_string()),
            }
        );
        assert_eq!(
            err.to_string(),
            "the token matches none of https://token.actions.githubusercontent.com's claim rules"
        );
        assert!(authorize(&claims(), &[]).is_err(), "no rules, no access");
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
