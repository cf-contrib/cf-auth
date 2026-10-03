//! Issuers' keys: a JWK Set (RFC 7517 §5), found at the `jwks_uri` a
//! provider configures or its metadata names (OpenID Connect Discovery 1.0
//! §4, or RFC 8414 §3), and cached per isolate.

use std::{cell::RefCell, collections::HashMap};

use serde::{Deserialize, de::DeserializeOwned};
use worker::{AbortSignal, Fetch, Method, Request};

use crate::{Error, Provider, check_url, crypto, crypto::ALGORITHM, invalid};

/// How long a fetched JWK Set is trusted before it's fetched again.
const JWKS_TTL_MS: u64 = 10 * 60 * 1000;

/// An unknown `kid` refetches an issuer's JWK Set at most this often, so
/// tokens with made-up key IDs can't make the Worker hammer the issuer.
const JWKS_MIN_REFETCH_MS: u64 = 30 * 1000;

/// How long an issuer has to answer.
const FETCH_TIMEOUT_MS: u32 = 10 * 1000;

thread_local! {
    /// Each issuer's keys, by issuer.
    static KEYS: RefCell<HashMap<String, KeySet>> = RefCell::new(HashMap::new());
}

/// The key of `provider`'s that `kid` names: the issuer's only one when
/// there's no `kid`.
pub(crate) async fn find_key<P: Provider>(
    provider: &P,
    kid: Option<&str>,
    now_ms: u64,
) -> Result<RsaKey, Error> {
    let unknown = || invalid("unknown signing key");
    let issuer = provider.issuer();

    match KEYS.with_borrow(|sets| KeySet::lookup(sets.get(issuer), kid, now_ms)) {
        Lookup::Hit(key) => return Ok(key),
        Lookup::Unknown => return Err(unknown()),
        Lookup::Fetch => {}
    }

    let set = fetch_keys(provider, now_ms).await?;
    let key = set.find(kid).cloned();
    KEYS.with_borrow_mut(|sets| sets.insert(issuer.to_string(), set));
    key.ok_or_else(unknown)
}

async fn fetch_keys<P: Provider>(provider: &P, now_ms: u64) -> Result<KeySet, Error> {
    let jwks_uri = match provider.jwks_uri() {
        Some(jwks_uri) => jwks_uri.to_string(),
        None => metadata_jwks_uri(provider.issuer()).await?,
    };
    let jwks: JwkSet = fetch_json(&jwks_uri).await?;
    Ok(KeySet::parse(jwks, now_ms))
}

/// The `jwks_uri` in `issuer`'s metadata: its OpenID Provider Metadata, or,
/// when it publishes none, its Authorization Server Metadata.
async fn metadata_jwks_uri(issuer: &str) -> Result<String, Error> {
    let mut failures = Vec::new();
    for url in metadata_urls(issuer) {
        match fetch_json::<Metadata>(&url).await {
            Ok(metadata) => return metadata.jwks_uri(issuer, &url),
            Err(err) => failures.push(err.to_string()),
        }
    }
    Err(Error::TemporarilyUnavailable(failures.join("; ")))
}

/// Where `issuer` publishes its metadata, in the order tried:
///
/// - OpenID Connect Discovery 1.0 §4 appends
///   `/.well-known/openid-configuration` to the issuer;
/// - RFC 8414 §3.1 puts `/.well-known/oauth-authorization-server` between
///   its host and its path.
///
/// A trailing `/` on the issuer is dropped first, as both say.
fn metadata_urls(issuer: &str) -> [String; 2] {
    let issuer = issuer.trim_end_matches('/');
    let host_end = issuer
        .find("://")
        .and_then(|scheme| issuer[scheme + 3..].find('/').map(|path| scheme + 3 + path))
        .unwrap_or(issuer.len());
    let (origin, path) = issuer.split_at(host_end);
    [
        format!("{issuer}/.well-known/openid-configuration"),
        format!("{origin}/.well-known/oauth-authorization-server{path}"),
    ]
}

async fn fetch_json<T: DeserializeOwned>(url: &str) -> Result<T, Error> {
    let unavailable =
        |err: worker::Error| Error::TemporarilyUnavailable(format!("fetching {url}: {err}"));

    // `Request::new` hands the URL to the runtime; `Url::parse` would pull the
    // `url` crate and its IDNA tables into the bundle.
    let req = Request::new(url, Method::Get).map_err(unavailable)?;
    let signal = AbortSignal::from(web_sys::AbortSignal::timeout_with_u32(FETCH_TIMEOUT_MS));
    let mut resp = Fetch::Request(req)
        .send_with_signal(&signal)
        .await
        .map_err(unavailable)?;
    if resp.status_code() != 200 {
        return Err(Error::TemporarilyUnavailable(format!(
            "fetching {url} returned {}",
            resp.status_code()
        )));
    }
    resp.json().await.map_err(unavailable)
}

/// What's read of an issuer's metadata: OpenID Provider Metadata (OpenID
/// Connect Discovery 1.0 §3) or Authorization Server Metadata (RFC 8414 §2),
/// whose `issuer` and `jwks_uri` mean the same.
#[derive(Deserialize)]
struct Metadata {
    issuer: String,
    jwks_uri: Option<String>,
}

impl Metadata {
    /// Its `jwks_uri`, if it's `issuer`'s, fetched from `url`. The metadata
    /// must name its own issuer (OpenID Connect Discovery 1.0 §4.3, RFC 8414
    /// §3.3), so one issuer can't hand out another's keys.
    fn jwks_uri(self, issuer: &str, url: &str) -> Result<String, Error> {
        let unavailable = |why: String| Err(Error::TemporarilyUnavailable(format!("{url}: {why}")));
        if self.issuer != issuer {
            return unavailable(format!("is for issuer {}, not {issuer}", self.issuer));
        }
        let Some(jwks_uri) = self.jwks_uri else {
            return unavailable("names no jwks_uri".to_string());
        };
        if let Err(why) = check_url(&jwks_uri) {
            return unavailable(format!("jwks_uri {why}"));
        }
        Ok(jwks_uri)
    }
}

/// A JWK Set (RFC 7517 §5).
#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

/// A JWK (RFC 7517 §4), with the members an RSA public key (RFC 7518 §6.3.1)
/// is read by.
#[derive(Deserialize)]
struct Jwk {
    kty: String,
    #[serde(rename = "use")]
    use_: Option<String>,
    key_ops: Option<Vec<String>>,
    alg: Option<String>,
    kid: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

impl Jwk {
    /// Whether it may verify RS256 signatures: an RSA key that, if it says
    /// what it's for, says signatures (RFC 7517 §4.2, §4.3) with RS256
    /// (§4.4; RFC 8725 §3.1).
    fn verifies_rs256(&self) -> bool {
        self.kty == "RSA"
            && self.use_.as_deref().is_none_or(|use_| use_ == "sig")
            && (self.key_ops.as_ref()).is_none_or(|ops| ops.iter().any(|op| op == "verify"))
            && self.alg.as_deref().is_none_or(|alg| alg == ALGORITHM)
    }
}

/// An issuer's RSA public key.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RsaKey {
    kid: Option<String>,
    n: String,
    e: String,
}

impl RsaKey {
    /// Whether `signature` is its RS256 signature of `signing_input`, checked
    /// with WebCrypto.
    pub(crate) async fn verify(
        &self,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error> {
        crypto::verify_rs256(&self.n, &self.e, signing_input, signature)
            .await
            .map_err(|err| Error::TemporarilyUnavailable(err.to_string()))
    }
}

/// An issuer's keys, cached per isolate.
struct KeySet {
    keys: Vec<RsaKey>,
    fetched_at: u64,
}

#[derive(Debug, PartialEq)]
enum Lookup {
    Hit(RsaKey),
    Fetch,
    /// Unknown `kid`, and the JWK Set was fetched too recently to try again.
    Unknown,
}

impl KeySet {
    /// The keys in `jwks` that verify RS256 signatures. Any others are
    /// skipped, as RFC 7517 §5 says keys that aren't understood are.
    fn parse(jwks: JwkSet, fetched_at: u64) -> Self {
        let keys = jwks
            .keys
            .into_iter()
            .filter(Jwk::verifies_rs256)
            .filter_map(|key| {
                Some(RsaKey {
                    kid: key.kid,
                    n: key.n?,
                    e: key.e?,
                })
            })
            .collect();
        Self { keys, fetched_at }
    }

    /// The key with this `kid`; without one, the only key there is.
    fn find(&self, kid: Option<&str>) -> Option<&RsaKey> {
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn keeps_only_keys_that_verify_rs256() {
        let jwks: JwkSet = serde_json::from_value(json!({ "keys": [
            { "kty": "RSA", "kid": "plain", "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "kid": "sig", "use": "sig", "alg": "RS256", "key_ops": ["verify"], "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "kid": "enc", "use": "enc", "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "kid": "rs512", "alg": "RS512", "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "kid": "encrypt", "key_ops": ["encrypt"], "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "kid": "no-modulus", "e": "AQAB" },
            { "kty": "EC", "kid": "ec", "x": "AA", "y": "AA" },
        ]}))
        .unwrap();
        let set = KeySet::parse(jwks, 0);
        let kids: Vec<_> = set
            .keys
            .iter()
            .filter_map(|key| key.kid.as_deref())
            .collect();
        assert_eq!(kids, ["plain", "sig"]);
    }

    #[test]
    fn finds_metadata_where_both_specs_put_it() {
        assert_eq!(
            metadata_urls("https://broker.example.com"),
            [
                "https://broker.example.com/.well-known/openid-configuration",
                "https://broker.example.com/.well-known/oauth-authorization-server",
            ]
        );
        assert_eq!(
            metadata_urls("https://gitlab.example.com/tenant/"),
            [
                "https://gitlab.example.com/tenant/.well-known/openid-configuration",
                "https://gitlab.example.com/.well-known/oauth-authorization-server/tenant",
            ]
        );
        assert_eq!(
            metadata_urls("http://127.0.0.1:8788"),
            [
                "http://127.0.0.1:8788/.well-known/openid-configuration",
                "http://127.0.0.1:8788/.well-known/oauth-authorization-server",
            ]
        );
    }

    #[test]
    fn metadata_must_be_the_issuers_own() {
        const ISSUER: &str = "https://broker.example.com";
        const URL: &str = "https://broker.example.com/.well-known/oauth-authorization-server";
        let metadata =
            |value: serde_json::Value| -> Metadata { serde_json::from_value(value).unwrap() };

        assert_eq!(
            metadata(json!({ "issuer": ISSUER, "jwks_uri": "https://broker.example.com/jwks" }))
                .jwks_uri(ISSUER, URL),
            Ok("https://broker.example.com/jwks".to_string())
        );
        for (value, why) in [
            (
                json!({ "issuer": "https://other.example.com", "jwks_uri": "https://other.example.com/jwks" }),
                "is for issuer https://other.example.com, not https://broker.example.com",
            ),
            (json!({ "issuer": ISSUER }), "names no jwks_uri"),
            (
                json!({ "issuer": ISSUER, "jwks_uri": "http://broker.example.com/jwks" }),
                "jwks_uri must be an https:// URL",
            ),
        ] {
            assert_eq!(
                metadata(value).jwks_uri(ISSUER, URL),
                Err(Error::TemporarilyUnavailable(format!("{URL}: {why}")))
            );
        }
    }

    #[test]
    fn refetches_sparingly() {
        let jwks: JwkSet = serde_json::from_value(json!({ "keys": [
            { "kty": "RSA", "kid": "key-1", "n": "AQAB", "e": "AQAB" },
        ]}))
        .unwrap();
        let set = KeySet::parse(jwks, 0);

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
}
