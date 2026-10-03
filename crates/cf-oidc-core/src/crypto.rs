//! RS256 through the runtime's WebCrypto: verifying an issuer's signatures,
//! and signing tokens, for a Worker that issues its own. No RSA crate ends up
//! in the wasm, and a signing key never leaves WebCrypto.

use std::fmt;

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde_json::{Map, Value, json};
use web_sys::{CryptoKey, SubtleCrypto, WorkerGlobalScope};
use worker::{
    js_sys::{self, Uint8Array},
    wasm_bindgen::{JsCast, JsValue},
    wasm_bindgen_futures::JsFuture,
};

use crate::Claims;

/// What tokens are signed with, and what OIDC verifiers support by default.
pub const ALGORITHM: &str = "RS256";

/// The smallest RSA key accepted, as NIST requires.
const MIN_MODULUS_BITS: usize = 2048;

/// What WebCrypto refused: a key that can't be imported, or a signature it
/// can't make or check.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyError(String);

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KeyError {}

/// An RSA private key, imported into WebCrypto to sign tokens with RS256.
pub struct SigningKey {
    key: CryptoKey,
    /// The public key, base64url.
    n: String,
    e: String,
    /// The public key's RFC 7638 thumbprint, so a new key gets a new `kid`
    /// without any configuration.
    kid: String,
}

/// A token [`SigningKey::sign`] signed.
pub struct SignedToken {
    /// The token, a JWT.
    pub jwt: String,
    /// Its `jti`, which signing gave it.
    pub jti: String,
}

impl SigningKey {
    /// The RSA key in `pem`, a PKCS#8 PEM, as `openssl genpkey -algorithm RSA`
    /// writes it.
    ///
    /// # Errors
    ///
    /// When it isn't an RSA private key in PKCS#8 PEM, or has fewer than 2048
    /// bits.
    pub async fn import(pem: &str) -> Result<Self, KeyError> {
        let not_rsa = || KeyError("not an RSA private key in PKCS#8 PEM".to_string());
        let der = pkcs8_der(pem).ok_or_else(not_rsa)?;

        let subtle = subtle()?;
        let usages = js_sys::Array::of1(&JsValue::from_str("sign"));
        // Extractable, so its public half can be exported to publish.
        let imported = subtle.import_key_with_object(
            "pkcs8",
            &Uint8Array::from(&der[..]),
            &rs256()?,
            true,
            &usages,
        );
        let key: CryptoKey = promised(imported)
            .await
            .map_err(|_| not_rsa())?
            .unchecked_into();
        let jwk = promised(subtle.export_key("jwk", &key)).await?;
        let jwk: String = js_sys::JSON::stringify(&jwk).map_err(webcrypto)?.into();
        let jwk: Value = serde_json::from_str(&jwk).unwrap_or_default();
        let (Some(n), Some(e)) = (jwk["n"].as_str(), jwk["e"].as_str()) else {
            return Err(not_rsa());
        };

        let bits = URL_SAFE_NO_PAD.decode(n).map_or(0, |n| n.len() * 8);
        if bits < MIN_MODULUS_BITS {
            return Err(KeyError(format!(
                "RSA key is {bits} bits, at least {MIN_MODULUS_BITS} needed"
            )));
        }
        // RFC 7638: the required members, in lexicographic order, without
        // whitespace.
        let canonical = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
        let digest =
            promised(subtle.digest_with_str_and_buffer_source(
                "SHA-256",
                &Uint8Array::from(canonical.as_bytes()),
            ))
            .await?;
        Ok(Self {
            key,
            n: n.to_string(),
            e: e.to_string(),
            kid: URL_SAFE_NO_PAD.encode(Uint8Array::new(&digest).to_vec()),
        })
    }

    /// The key's ID: its public key's thumbprint.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The public half, as a JWKS publishes it.
    pub fn public_jwk(&self) -> Value {
        json!({ "kty": "RSA", "n": self.n, "e": self.e, "kid": self.kid, "alg": ALGORITHM, "use": "sig" })
    }

    /// Signs `claims` as a JWT, with a fresh random `jti`.
    ///
    /// # Errors
    ///
    /// When WebCrypto fails.
    pub async fn sign(&self, claims: Claims) -> Result<SignedToken, KeyError> {
        let scope = js_sys::global().unchecked_into::<WorkerGlobalScope>();
        let jti = scope.crypto().map_err(webcrypto)?.random_uuid();
        let mut claims: Map<String, Value> = claims.into();
        claims.insert("jti".to_string(), json!(jti));

        let header = json!({ "alg": ALGORITHM, "kid": self.kid, "typ": "JWT" });
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(Value::Object(claims).to_string())
        );
        let signature = promised(subtle()?.sign_with_object_and_buffer_source(
            &rs256()?,
            &self.key,
            &Uint8Array::from(signing_input.as_bytes()),
        ))
        .await?;
        let signature = URL_SAFE_NO_PAD.encode(Uint8Array::new(&signature).to_vec());
        Ok(SignedToken {
            jwt: format!("{signing_input}.{signature}"),
            jti,
        })
    }
}

/// Verifies an RS256 (RSASSA-PKCS1-v1_5 with SHA-256) signature with the RSA
/// public key `n` and `e`, base64url. A signature WebCrypto refuses to check,
/// such as one of the wrong length, doesn't verify.
pub(crate) async fn verify_rs256(
    n: &str,
    e: &str,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<bool, KeyError> {
    let subtle = subtle()?;
    let algorithm = rs256()?;
    let jwk = json!({ "kty": "RSA", "n": n, "e": e, "alg": ALGORITHM });
    let jwk: js_sys::Object = js_sys::JSON::parse(&jwk.to_string())
        .map(JsCast::unchecked_into)
        .map_err(webcrypto)?;
    let usages = js_sys::Array::of1(&JsValue::from_str("verify"));
    let key: CryptoKey =
        promised(subtle.import_key_with_object("jwk", &jwk, &algorithm, false, &usages))
            .await?
            .unchecked_into();

    let verified = subtle.verify_with_object_and_buffer_source_and_buffer_source(
        &algorithm,
        &key,
        &Uint8Array::from(signature),
        &Uint8Array::from(signing_input),
    );
    match verified {
        Ok(promise) => {
            Ok(JsFuture::from(promise).await.ok().and_then(|v| v.as_bool()) == Some(true))
        }
        Err(_) => Ok(false),
    }
}

fn webcrypto(err: JsValue) -> KeyError {
    let why = err
        .dyn_ref::<js_sys::Error>()
        .map(|err| String::from(err.message()))
        .unwrap_or_else(|| format!("{err:?}"));
    KeyError(format!("WebCrypto: {why}"))
}

fn subtle() -> Result<SubtleCrypto, KeyError> {
    let scope = js_sys::global().unchecked_into::<WorkerGlobalScope>();
    Ok(scope.crypto().map_err(webcrypto)?.subtle())
}

async fn promised(promise: Result<js_sys::Promise, JsValue>) -> Result<JsValue, KeyError> {
    JsFuture::from(promise.map_err(webcrypto)?)
        .await
        .map_err(webcrypto)
}

fn rs256() -> Result<js_sys::Object, KeyError> {
    js_sys::JSON::parse(r#"{"name":"RSASSA-PKCS1-v1_5","hash":"SHA-256"}"#)
        .map(JsCast::unchecked_into)
        .map_err(webcrypto)
}

/// The DER inside a PKCS#8 PEM.
fn pkcs8_der(pem: &str) -> Option<Vec<u8>> {
    let body = pem
        .trim()
        .strip_prefix("-----BEGIN PRIVATE KEY-----")?
        .strip_suffix("-----END PRIVATE KEY-----")?;
    let base64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    STANDARD.decode(base64).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

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
