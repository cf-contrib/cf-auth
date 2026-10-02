//! RS256 through the runtime's WebCrypto, as cf-nix-cache does: no RSA crate
//! ends up in the wasm, and the private key never leaves the runtime's crypto.

use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use web_sys::{CryptoKey, SubtleCrypto, WorkerGlobalScope};
use worker::{
    js_sys::{self, Uint8Array},
    wasm_bindgen::{JsCast, JsValue},
    wasm_bindgen_futures::JsFuture,
};

/// What WebCrypto said went wrong.
pub type CryptoError = String;

fn failed(err: JsValue) -> CryptoError {
    err.dyn_ref::<js_sys::Error>()
        .map(|err| String::from(err.message()))
        .unwrap_or_else(|| format!("{err:?}"))
}

fn subtle() -> Result<SubtleCrypto, CryptoError> {
    let scope = js_sys::global().unchecked_into::<WorkerGlobalScope>();
    Ok(scope.crypto().map_err(failed)?.subtle())
}

/// A JSON value as the JS object WebCrypto takes.
fn object(value: &impl Serialize) -> Result<js_sys::Object, CryptoError> {
    let text = serde_json::to_string(value).map_err(|err| err.to_string())?;
    js_sys::JSON::parse(&text)
        .map(JsCast::unchecked_into)
        .map_err(failed)
}

fn rs256() -> Result<js_sys::Object, CryptoError> {
    object(&json!({ "name": "RSASSA-PKCS1-v1_5", "hash": "SHA-256" }))
}

async fn resolve(promise: Result<js_sys::Promise, JsValue>) -> Result<JsValue, CryptoError> {
    JsFuture::from(promise.map_err(failed)?)
        .await
        .map_err(failed)
}

/// A random UUID, for a token's `jti`.
pub fn random_uuid() -> Result<String, CryptoError> {
    let scope = js_sys::global().unchecked_into::<WorkerGlobalScope>();
    Ok(scope.crypto().map_err(failed)?.random_uuid())
}

/// Verifies an RS256 signature with an RSA public key given as `n` and `e`.
/// A signature WebCrypto refuses to check, such as one of the wrong length,
/// doesn't verify.
pub async fn verify_rs256(
    n: &str,
    e: &str,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<bool, CryptoError> {
    let subtle = subtle()?;
    let algorithm = rs256()?;
    let jwk = object(&json!({ "kty": "RSA", "n": n, "e": e, "alg": "RS256" }))?;
    let usages = js_sys::Array::of1(&JsValue::from_str("verify"));
    let key: CryptoKey =
        resolve(subtle.import_key_with_object("jwk", &jwk, &algorithm, false, &usages))
            .await?
            .unchecked_into();

    let verified = subtle.verify_with_object_and_buffer_source_and_buffer_source(
        &algorithm,
        &key,
        &Uint8Array::from(signature),
        &Uint8Array::from(signing_input),
    );
    match verified {
        Ok(promise) => Ok(JsFuture::from(promise)
            .await
            .ok()
            .and_then(|value| value.as_bool())
            == Some(true)),
        Err(_) => Ok(false),
    }
}

/// An RSA private key imported for RS256 signing, with its public half.
pub struct PrivateKey {
    key: CryptoKey,
    /// The public key's `n` and `e`, base64url.
    pub n: String,
    pub e: String,
}

/// Imports a PKCS#8 DER RSA private key for RS256 signing.
pub async fn import_pkcs8(der: &[u8]) -> Result<PrivateKey, CryptoError> {
    let subtle = subtle()?;
    let algorithm = rs256()?;
    let usages = js_sys::Array::of1(&JsValue::from_str("sign"));
    // Extractable, so its public half can be exported to publish.
    let key: CryptoKey = resolve(subtle.import_key_with_object(
        "pkcs8",
        &Uint8Array::from(der),
        &algorithm,
        true,
        &usages,
    ))
    .await?
    .unchecked_into();

    #[derive(serde::Deserialize)]
    struct Public {
        n: String,
        e: String,
    }
    let public: Public = from_js(&resolve(subtle.export_key("jwk", &key)).await?)?;
    Ok(PrivateKey {
        key,
        n: public.n,
        e: public.e,
    })
}

/// Signs with RS256.
pub async fn sign_rs256(key: &PrivateKey, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let subtle = subtle()?;
    let signature = resolve(subtle.sign_with_object_and_buffer_source(
        &rs256()?,
        &key.key,
        &Uint8Array::from(data),
    ))
    .await?;
    Ok(Uint8Array::new(&signature).to_vec())
}

/// SHA-256 of `data`.
pub async fn sha256(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let digest =
        resolve(subtle()?.digest_with_str_and_buffer_source("SHA-256", &Uint8Array::from(data)))
            .await?;
    Ok(Uint8Array::new(&digest).to_vec())
}

fn from_js<T: DeserializeOwned>(value: &JsValue) -> Result<T, CryptoError> {
    let text: String = js_sys::JSON::stringify(value).map_err(failed)?.into();
    serde_json::from_str::<Value>(&text)
        .and_then(serde_json::from_value)
        .map_err(|err| err.to_string())
}
