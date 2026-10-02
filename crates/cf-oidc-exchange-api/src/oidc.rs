//! OIDC tokens: which provider a token is from, and whether it's genuine.
//!
//! A token picks its provider by its `iss`, which must name one exactly. Its
//! signature is checked against that issuer's keys, found through its discovery
//! document (or the provider's `jwks_uri`) and never through anything in the
//! token. Then the standard claims are checked; the provider's and profiles'
//! claims are checked when a profile is picked.

use std::{cell::RefCell, collections::HashMap, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{
    error::{ErrorCode, HttpError},
    policy::{Claims, Provider, ProviderType, is_issuer_url},
    webcrypto,
};

/// Clock tolerance for `exp` and `nbf`.
const LEEWAY_SECS: u64 = 30;

/// How long fetched keys are trusted before they're fetched again.
const KEYS_MAX_AGE_MS: u64 = 10 * 60 * 1000;

/// An unknown `kid` refetches an issuer's keys at most this often, so tokens with
/// made-up key IDs can't make the broker hammer the issuer.
const KEYS_COOLDOWN_MS: u64 = 30 * 1000;

const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

thread_local! {
    /// Each issuer's keys, by issuer.
    static KEYS: RefCell<HashMap<String, KeySet>> = RefCell::new(HashMap::new());
}

fn invalid(detail: impl Into<String>) -> HttpError {
    HttpError::new(ErrorCode::Unauthorized, "invalid_jwt").with_detail(detail)
}

fn unavailable(detail: impl Into<String>) -> HttpError {
    HttpError::new(ErrorCode::UpstreamError, "jwks_unavailable").with_detail(detail)
}

/// The first 200 characters of something a caller sent, for the audit log.
pub fn shown(value: &str) -> String {
    value.chars().take(200).collect()
}

/// A decoded, not yet verified, JWT.
pub struct Jwt<'a> {
    kid: Option<String>,
    pub claims: Claims,
    /// `<header>.<payload>`, the bytes the signature covers.
    signing_input: &'a str,
    signature: Vec<u8>,
}

impl<'a> Jwt<'a> {
    pub fn decode(jwt: &'a str) -> Result<Self, HttpError> {
        #[derive(Deserialize)]
        struct Header {
            alg: String,
            kid: Option<String>,
        }
        let not_a_jwt = || invalid("not a JWT");
        let segment = |s: &str| URL_SAFE_NO_PAD.decode(s).map_err(|_| not_a_jwt());

        let parts: Vec<&str> = jwt.split('.').collect();
        let [header, payload, signature] = parts[..] else {
            return Err(not_a_jwt());
        };
        let header: Header = serde_json::from_slice(&segment(header)?).map_err(|_| not_a_jwt())?;
        let claims = serde_json::from_slice(&segment(payload)?).map_err(|_| not_a_jwt())?;
        if header.alg != "RS256" {
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

/// The OIDC provider whose issuer the token names. Its `iss` is read unverified,
/// only to pick the keys to verify it with; the claims check reads it again.
pub fn provider_for<'p>(jwt: &Jwt, providers: &'p [Provider]) -> Result<&'p Provider, HttpError> {
    let iss = jwt
        .claims
        .get("iss")
        .and_then(Value::as_str)
        .unwrap_or_default();
    providers
        .iter()
        .find(|p| p.kind == ProviderType::Oidc && p.issuer == iss)
        .ok_or_else(|| {
            HttpError::new(ErrorCode::Unauthorized, "unknown_issuer").with_detail(shown(iss))
        })
}

/// Verifies an OIDC token from `provider`: its RS256 signature against the
/// issuer's keys, then `iss`, `aud`, `exp`, `iat` and `nbf`.
pub async fn verify(jwt: Jwt<'_>, provider: &Provider, now_ms: u64) -> Result<Claims, HttpError> {
    let key = find_key(provider, jwt.kid.as_deref(), now_ms).await?;
    let verified =
        webcrypto::verify_rs256(&key.n, &key.e, jwt.signing_input.as_bytes(), &jwt.signature)
            .await
            .map_err(|err| HttpError::new(ErrorCode::Internal, "webcrypto").with_detail(err))?;
    if !verified {
        return Err(invalid("bad signature"));
    }
    check_claims(&jwt.claims, provider, now_ms / 1000)?;
    Ok(jwt.claims)
}

/// The standard claims of a token whose signature verified.
pub fn check_claims(claims: &Claims, provider: &Provider, now: u64) -> Result<(), HttpError> {
    let claim = |name| claims.get(name);
    if claim("iss").and_then(Value::as_str) != Some(provider.issuer.as_str()) {
        return Err(invalid("wrong issuer"));
    }
    let audience = provider.audience.as_deref().unwrap_or_default();
    let ours = |aud: &Value| aud.as_str() == Some(audience);
    let audience_ok = match claim("aud") {
        Some(Value::Array(auds)) => auds.iter().any(ours),
        Some(aud) => ours(aud),
        None => false,
    };
    if !audience_ok {
        return Err(invalid("wrong audience"));
    }
    let Some(exp) = claim("exp").and_then(Value::as_u64) else {
        return Err(invalid("missing exp"));
    };
    if claim("iat").and_then(Value::as_u64).is_none() {
        return Err(invalid("missing iat"));
    }
    if now >= exp + LEEWAY_SECS {
        return Err(invalid("expired"));
    }
    if let Some(nbf) = claim("nbf").and_then(Value::as_u64)
        && nbf > now + LEEWAY_SECS
    {
        return Err(invalid("not yet valid"));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq)]
struct Jwk {
    kid: Option<String>,
    n: String,
    e: String,
}

/// An issuer's keys, cached per isolate.
struct KeySet {
    keys: Vec<Jwk>,
    fetched_at: u64,
}

#[derive(Debug, PartialEq)]
enum Lookup {
    Hit(Jwk),
    Fetch,
    /// No such key, and the keys were fetched too recently to try again.
    Miss,
}

impl KeySet {
    fn parse(jwks: Value, fetched_at: u64) -> Self {
        #[derive(Deserialize)]
        struct RawJwk {
            kty: String,
            kid: Option<String>,
            n: Option<String>,
            e: Option<String>,
        }
        let keys = jwks
            .get("keys")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|key| serde_json::from_value::<RawJwk>(key.clone()).ok())
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
            Some(key) if age < KEYS_MAX_AGE_MS => Lookup::Hit(key.clone()),
            Some(_) => Lookup::Fetch,
            None if age < KEYS_COOLDOWN_MS => Lookup::Miss,
            None => Lookup::Fetch,
        }
    }
}

async fn find_key(provider: &Provider, kid: Option<&str>, now_ms: u64) -> Result<Jwk, HttpError> {
    let unknown = || invalid("no matching key");
    match KEYS.with_borrow(|sets| KeySet::lookup(sets.get(&provider.issuer), kid, now_ms)) {
        Lookup::Hit(key) => return Ok(key),
        Lookup::Miss => return Err(unknown()),
        Lookup::Fetch => {}
    }
    let set = KeySet::parse(get_json(&jwks_uri(provider).await?).await?, now_ms);
    let key = set.find(kid).cloned();
    KEYS.with_borrow_mut(|sets| sets.insert(provider.issuer.clone(), set));
    key.ok_or_else(unknown)
}

/// Where an issuer's keys are: its configured `jwks_uri`, or what its discovery
/// document says, which must name the same issuer, so one issuer can't hand out
/// another's keys.
async fn jwks_uri(provider: &Provider) -> Result<String, HttpError> {
    if let Some(uri) = &provider.jwks_uri {
        return Ok(uri.clone());
    }
    #[derive(Deserialize)]
    struct Discovery {
        issuer: Option<Value>,
        jwks_uri: Option<Value>,
    }
    let url = format!(
        "{}/.well-known/openid-configuration",
        provider.issuer.trim_end_matches('/')
    );
    let doc: Discovery = get_json(&url).await?;
    if doc.issuer.as_ref().and_then(Value::as_str) != Some(provider.issuer.as_str()) {
        let named = match doc.issuer {
            Some(Value::String(issuer)) => issuer,
            other => other.map(|i| i.to_string()).unwrap_or_default(),
        };
        return Err(unavailable(format!(
            "{url} is for issuer {}",
            shown(&named)
        )));
    }
    match doc.jwks_uri.as_ref().and_then(Value::as_str) {
        Some(uri) if is_issuer_url(uri) => Ok(uri.to_string()),
        _ => Err(unavailable(format!(
            "{url}: jwks_uri must be an https:// URL"
        ))),
    }
}

async fn get_json<T: DeserializeOwned>(url: &str) -> Result<T, HttpError> {
    let failed = |err: reqwest::Error| unavailable(format!("{url}: {err}"));
    let response = reqwest::Client::new()
        .get(url)
        .timeout(FETCH_TIMEOUT)
        .send()
        .await
        .map_err(failed)?;
    if !response.status().is_success() {
        return Err(unavailable(format!(
            "{url}: returned {}",
            response.status().as_u16()
        )));
    }
    response.json().await.map_err(failed)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const NOW: u64 = 1_800_000_000;
    const ISSUER: &str = "https://token.actions.githubusercontent.com";
    const AUDIENCE: &str = "https://cf-auth.example.com";

    fn provider() -> Provider {
        Provider {
            name: "github".into(),
            kind: ProviderType::Oidc,
            issuer: ISSUER.into(),
            audience: Some(AUDIENCE.into()),
            jwks_uri: None,
            claims: Default::default(),
        }
    }

    fn claims(overrides: Value) -> Claims {
        let mut claims =
            json!({ "iss": ISSUER, "aud": AUDIENCE, "exp": NOW + 300, "iat": NOW - 10 })
                .as_object()
                .unwrap()
                .clone();
        for (key, value) in overrides.as_object().unwrap() {
            if value.is_null() {
                claims.remove(key);
            } else {
                claims.insert(key.clone(), value.clone());
            }
        }
        claims
    }

    fn check(overrides: Value) -> Option<String> {
        check_claims(&claims(overrides), &provider(), NOW)
            .err()
            .and_then(|err| err.detail)
    }

    fn segment(value: Value) -> String {
        URL_SAFE_NO_PAD.encode(value.to_string())
    }

    #[test]
    fn accepts_valid_claims() {
        assert_eq!(check(json!({})), None);
        assert_eq!(check(json!({ "aud": ["other", AUDIENCE] })), None);
    }

    #[test]
    fn refuses_the_wrong_issuer_and_audience() {
        assert_eq!(
            check(json!({ "iss": "https://evil.example.com" })).as_deref(),
            Some("wrong issuer")
        );
        // A token requested for AWS, or GitHub's default audience.
        for aud in [
            json!("sts.amazonaws.com"),
            json!("https://github.com/example-org"),
            json!(null),
        ] {
            assert_eq!(
                check(json!({ "aud": aud })).as_deref(),
                Some("wrong audience")
            );
        }
    }

    #[test]
    fn tolerates_30s_of_clock_skew() {
        assert_eq!(check(json!({ "exp": NOW - 10 })), None);
        assert_eq!(
            check(json!({ "exp": NOW - 30 })).as_deref(),
            Some("expired")
        );
        assert_eq!(check(json!({ "nbf": NOW + 30 })), None);
        assert_eq!(
            check(json!({ "nbf": NOW + 31 })).as_deref(),
            Some("not yet valid")
        );
    }

    #[test]
    fn requires_exp_and_iat() {
        assert_eq!(
            check(json!({ "exp": null })).as_deref(),
            Some("missing exp")
        );
        assert_eq!(
            check(json!({ "iat": null })).as_deref(),
            Some("missing iat")
        );
    }

    #[test]
    fn decodes_a_jwt_and_refuses_anything_else() {
        let header = segment(json!({ "alg": "RS256", "kid": "k1" }));
        let payload = segment(json!({ "iss": ISSUER }));
        let jwt = format!("{header}.{payload}.c2ln");
        let decoded = Jwt::decode(&jwt).unwrap();
        assert_eq!(decoded.kid.as_deref(), Some("k1"));
        assert_eq!(decoded.signing_input, format!("{header}.{payload}"));
        assert_eq!(decoded.signature, b"sig");

        let reason = |jwt: &str| Jwt::decode(jwt).err().and_then(|err| err.detail);
        assert_eq!(reason("gho_notAJwt").as_deref(), Some("not a JWT"));
        assert_eq!(reason("not.a.jwt").as_deref(), Some("not a JWT"));
        let hs256 = format!("{}.{payload}.c2ln", segment(json!({ "alg": "HS256" })));
        assert_eq!(reason(&hs256).as_deref(), Some("alg must be RS256"));
    }

    #[test]
    fn picks_the_provider_by_the_tokens_issuer() {
        let people = Provider {
            name: "people".into(),
            kind: ProviderType::GithubUser,
            issuer: "https://github.com".into(),
            audience: None,
            jwks_uri: None,
            claims: Default::default(),
        };
        let providers = [people, provider()];
        let jwt = |iss: &str| {
            let payload = segment(json!({ "iss": iss }));
            format!("{}.{payload}.c2ln", segment(json!({ "alg": "RS256" })))
        };
        let token = jwt(ISSUER);
        assert_eq!(
            provider_for(&Jwt::decode(&token).unwrap(), &providers)
                .unwrap()
                .name,
            "github"
        );
        // A person's provider never takes OIDC tokens, even one that names its issuer.
        let token = jwt("https://github.com");
        let err = provider_for(&Jwt::decode(&token).unwrap(), &providers).unwrap_err();
        assert_eq!(
            (err.reason, err.detail.as_deref()),
            ("unknown_issuer", Some("https://github.com"))
        );
    }

    #[test]
    fn looks_keys_up_by_kid_and_refetches_unknown_ones_after_a_cooldown() {
        let set = KeySet::parse(
            json!({ "keys": [
                { "kty": "RSA", "kid": "k1", "n": "n1", "e": "AQAB" },
                { "kty": "EC", "kid": "k2", "x": "x", "y": "y" },
            ]}),
            NOW,
        );
        assert_eq!(set.keys.len(), 1);
        assert!(matches!(
            KeySet::lookup(Some(&set), Some("k1"), NOW),
            Lookup::Hit(_)
        ));
        // Without a kid, the only key.
        assert!(matches!(
            KeySet::lookup(Some(&set), None, NOW),
            Lookup::Hit(_)
        ));
        assert_eq!(
            KeySet::lookup(Some(&set), Some("k9"), NOW + 1),
            Lookup::Miss
        );
        assert_eq!(
            KeySet::lookup(Some(&set), Some("k9"), NOW + KEYS_COOLDOWN_MS),
            Lookup::Fetch
        );
        assert_eq!(
            KeySet::lookup(Some(&set), Some("k1"), NOW + KEYS_MAX_AGE_MS),
            Lookup::Fetch
        );
        assert_eq!(KeySet::lookup(None, Some("k1"), NOW), Lookup::Fetch);
    }
}
