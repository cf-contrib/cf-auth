//! The broker's own tokens, for profiles with another service's `audience`:
//! RS256 JWTs signed with WebCrypto, verifiable with the keys at `/.well-known/jwks`.

use std::{cell::RefCell, collections::BTreeSet, rc::Rc};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use cf_oidc_exchange_sdk::v1::{Error, ErrorCode};
use serde_json::{Map, Value, json};

use crate::{
    service::config::Claims,
    webcrypto::{self, PrivateKey},
};

/// What OIDC verifiers support by default, cf-nix-cache included.
pub const ALGORITHM: &str = "RS256";

/// The smallest RSA key accepted, as NIST requires.
const MIN_MODULUS_BITS: usize = 2048;

/// Verified claims always copied into the broker's tokens when the caller's token
/// has them, under the issuer's own names, so a service's rules keep working:
/// GitHub's. Other issuers' claims are copied when the policy matches on them.
/// None are secret; `team_ids` is left out, as it can be long.
const COPIED: [&str; 16] = [
    "repository",
    "repository_id",
    "repository_owner",
    "repository_owner_id",
    "ref",
    "ref_type",
    "environment",
    "event_name",
    "workflow_ref",
    "job_workflow_ref",
    "run_id",
    "run_attempt",
    "runner_environment",
    "actor",
    "actor_id",
    "repository_permission",
];

pub struct SigningKey {
    key: PrivateKey,
    /// The public key's RFC 7638 thumbprint, so a new key gets a new `kid`
    /// without any configuration.
    pub kid: String,
}

impl SigningKey {
    /// The public half as published in the JWKS.
    pub fn public_jwk(&self) -> Value {
        json!({ "kty": "RSA", "n": self.key.n, "e": self.key.e, "kid": self.kid, "alg": ALGORITHM, "use": "sig" })
    }
}

thread_local! {
    /// Imported once per isolate and keyed by the PEM, so a rotated key is imported again.
    static CACHED: RefCell<Option<(String, Rc<SigningKey>)>> = const { RefCell::new(None) };
}

fn unavailable(why: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::Misconfigured, format!("the signing key: {why}"))
}

/// The DER inside a PKCS#8 PEM, as `openssl genpkey -algorithm RSA` writes it.
fn pkcs8_der(pem: &str) -> Option<Vec<u8>> {
    let body = pem
        .trim()
        .strip_prefix("-----BEGIN PRIVATE KEY-----")?
        .strip_suffix("-----END PRIVATE KEY-----")?;
    let base64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    STANDARD.decode(base64).ok()
}

/// The RSA signing key in `pem`, a PKCS#8 PEM.
pub async fn signing_key(pem: &str) -> Result<Rc<SigningKey>, Error> {
    if let Some(key) = CACHED.with_borrow(|cached| {
        cached
            .as_ref()
            .filter(|(cached, _)| cached == pem)
            .map(|(_, key)| key.clone())
    }) {
        return Ok(key);
    }

    let not_rsa = || unavailable("not an RSA private key in PKCS#8 PEM");
    let der = pkcs8_der(pem).ok_or_else(not_rsa)?;
    let key = webcrypto::import_pkcs8(&der).await.map_err(|_| not_rsa())?;
    let bits = URL_SAFE_NO_PAD.decode(&key.n).map_or(0, |n| n.len() * 8);
    if bits < MIN_MODULUS_BITS {
        return Err(unavailable(format!(
            "RSA key is {bits} bits, at least {MIN_MODULUS_BITS} needed"
        )));
    }
    // RFC 7638: the required members, in lexicographic order, without whitespace.
    let canonical = format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, key.e, key.n);
    let digest = webcrypto::sha256(canonical.as_bytes())
        .await
        .map_err(unavailable)?;
    let key = Rc::new(SigningKey {
        key,
        kid: URL_SAFE_NO_PAD.encode(digest),
    });
    CACHED.with_borrow_mut(|cached| *cached = Some((pem.to_string(), key.clone())));
    Ok(key)
}

pub struct IssueRequest<'a> {
    /// The broker's own URL.
    pub issuer: &'a str,
    pub audience: &'a str,
    /// The caller's `sub` from its issuer, or `user:<actor_id>` for a person.
    pub subject: String,
    /// The provider the caller's token came from.
    pub provider: &'a str,
    pub profile: &'a str,
    /// Claims the policy matched on, also copied, so a service can match on the same ones.
    pub matched: Vec<&'a str>,
    pub claims: &'a Claims,
    /// The profile's TTL, in milliseconds.
    pub ttl: u64,
    /// Unix seconds the token mustn't outlive: the presented token's `exp`, when it has one.
    pub not_after: Option<u64>,
}

pub struct Issued {
    pub jwt: String,
    pub jti: String,
    pub expires_at: u64,
}

/// The claims of a token for another service, issued at `now` (Unix seconds).
/// It never outlives the token the caller presented.
pub fn payload(
    req: &IssueRequest,
    jti: &str,
    now: u64,
) -> Result<(Map<String, Value>, u64), Error> {
    let expires_at = (now + req.ttl / 1000).min(req.not_after.unwrap_or(u64::MAX));
    // The caller's token was accepted with clock tolerance; a token that can't live at all isn't issued.
    if expires_at <= now {
        return Err(Error::new(
            ErrorCode::Unauthorized,
            "the subject token has expired",
        ));
    }

    let names: BTreeSet<&str> = COPIED
        .iter()
        .copied()
        .chain(req.matched.iter().copied())
        .collect();
    let mut claims = Map::new();
    for name in names {
        if let Some(value) = req
            .claims
            .get(name)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
        {
            claims.insert(name.into(), value.into());
        }
    }
    for (name, value) in [
        ("provider", json!(req.provider)),
        ("profile", json!(req.profile)),
        ("iss", json!(req.issuer)),
        ("aud", json!(req.audience)),
        ("sub", json!(req.subject)),
        ("iat", json!(now)),
        ("nbf", json!(now)),
        ("exp", json!(expires_at)),
        ("jti", json!(jti)),
    ] {
        claims.insert(name.into(), value);
    }
    Ok((claims, expires_at))
}

/// Signs a token for another service.
pub async fn issue(key: &SigningKey, req: &IssueRequest<'_>, now: u64) -> Result<Issued, Error> {
    let internal = |why: String| Error::new(ErrorCode::InternalError, format!("WebCrypto: {why}"));
    let jti = webcrypto::random_uuid().map_err(internal)?;
    let (claims, expires_at) = payload(req, &jti, now)?;
    let header = json!({ "alg": ALGORITHM, "kid": key.kid, "typ": "JWT" });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(Value::Object(claims).to_string())
    );
    let signature = webcrypto::sign_rs256(&key.key, signing_input.as_bytes())
        .await
        .map_err(internal)?;
    Ok(Issued {
        jwt: format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature)),
        jti,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn request<'a>(claims: &'a Claims, not_after: Option<u64>) -> IssueRequest<'a> {
        IssueRequest {
            issuer: "https://cf-oidc-exchange.example.com",
            audience: "https://cf-nix-cache.example.com",
            subject: "repo:example-org/api:ref:refs/heads/main".into(),
            provider: "github",
            profile: "nix-push",
            matched: vec!["ref", "groups"],
            claims,
            ttl: 15 * 60_000,
            not_after,
        }
    }

    #[test]
    fn copies_githubs_claims_and_the_matched_ones() {
        let claims = json!({
            "repository": "example-org/api",
            "ref": "refs/heads/main",
            "actor": "",
            "team_ids": ["400000005"],
            "groups": "deployers",
            "email": "someone@example.com",
        });
        let (payload, expires_at) =
            payload(&request(claims.as_object().unwrap(), None), "jti-1", NOW).unwrap();
        assert_eq!(expires_at, NOW + 900);
        assert_eq!(
            Value::Object(payload),
            json!({
                "repository": "example-org/api",
                "ref": "refs/heads/main",
                "groups": "deployers",
                "provider": "github",
                "profile": "nix-push",
                "iss": "https://cf-oidc-exchange.example.com",
                "aud": "https://cf-nix-cache.example.com",
                "sub": "repo:example-org/api:ref:refs/heads/main",
                "iat": NOW,
                "nbf": NOW,
                "exp": NOW + 900,
                "jti": "jti-1",
            })
        );
    }

    #[test]
    fn never_outlives_the_callers_token() {
        let claims = Claims::new();
        let (_, expires_at) = payload(&request(&claims, Some(NOW + 60)), "j", NOW).unwrap();
        assert_eq!(expires_at, NOW + 60);
        let err = payload(&request(&claims, Some(NOW)), "j", NOW).unwrap_err();
        assert_eq!(err.message, "the subject token has expired");
    }

    #[test]
    fn reads_a_pkcs8_pem() {
        let pem = "-----BEGIN PRIVATE KEY-----\nAAEC\nAwQ=\n-----END PRIVATE KEY-----\n";
        assert_eq!(pkcs8_der(pem), Some(vec![0, 1, 2, 3, 4]));
        assert_eq!(
            pkcs8_der("-----BEGIN RSA PRIVATE KEY-----\nAAEC\n-----END RSA PRIVATE KEY-----"),
            None
        );
        assert_eq!(pkcs8_der("not a pem"), None);
    }
}
