//! JWKs (RFC 7517): an issuer's JWK Set, and the RSA public keys (RFC 7518
//! §6.3) in it that verify RS256 signatures.

use serde::Deserialize;

use crate::{ALGORITHM, Error, webcrypto};

/// A JWK Set (RFC 7517 §5).
#[derive(Deserialize)]
pub(crate) struct JwkSet {
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
    /// Its `kid`, if it has one.
    pub(crate) fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// Whether `signature` is its RS256 signature of `signing_input`, checked
    /// with WebCrypto.
    pub(crate) async fn verify(
        &self,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error> {
        webcrypto::verify_rs256(&self.n, &self.e, signing_input, signature)
            .await
            .map_err(|err| Error::TemporarilyUnavailable(err.to_string()))
    }
}

impl JwkSet {
    /// The keys in it that verify RS256 signatures. Any others are skipped, as
    /// RFC 7517 §5 says keys that aren't understood are.
    pub(crate) fn rs256_keys(self) -> Vec<RsaKey> {
        self.keys
            .into_iter()
            .filter(Jwk::verifies_rs256)
            .filter_map(|key| {
                Some(RsaKey {
                    kid: key.kid,
                    n: key.n?,
                    e: key.e?,
                })
            })
            .collect()
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
        let keys = jwks.rs256_keys();
        let kids: Vec<_> = keys.iter().filter_map(RsaKey::kid).collect();
        assert_eq!(kids, ["plain", "sig"]);
    }
}
