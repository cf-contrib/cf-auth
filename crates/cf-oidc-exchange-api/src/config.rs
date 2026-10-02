//! The Worker's configuration: the policy, and the bindings. Fails closed: any
//! problem is a `500 misconfigured`.

use std::{cell::RefCell, rc::Rc};

use worker::{
    Env, js_sys,
    wasm_bindgen::{JsCast, JsValue},
};

use crate::{
    audit::Audit,
    cloudflare::{self, Cloudflare},
    error::{ErrorCode, HttpError},
    github,
    issuer::{self, SigningKey},
    policy::{Policy, PolicyError, load_policy},
};

/// The account the broker token belongs to and tokens are minted in.
const ACCOUNT_ID: &str = "CF_OIDC_BROKER_ACCOUNT_ID";

/// Account-owned token with "Account API Tokens Write", plus R2 permissions
/// covering what profiles' `buckets` delegate. Must be a Secrets Store binding.
const BROKER_TOKEN: &str = "CF_OIDC_BROKER_TOKEN";

/// RSA private key (PKCS#8 PEM, at least 2048 bits) the broker signs its own
/// tokens with. Optional: without it, the broker issues none and publishes no
/// keys. Must be a Secrets Store binding.
const SIGNING_KEY: &str = "CF_OIDC_BROKER_SIGNING_KEY";

/// Where the entry module puts `policy.json`, which Terraform uploads beside the
/// Worker as a text module. See `worker/entry.js`.
const POLICY_GLOBAL: &str = "CF_OIDC_EXCHANGE_POLICY";

/// The policy, loaded, and what it was loaded from.
struct Loaded {
    raw: String,
    account_id: String,
    result: Result<Rc<Policy>, PolicyError>,
}

thread_local! {
    // Parsed once per isolate. The policy and env are fixed for the lifetime of a deployment.
    static LOADED: RefCell<Option<Loaded>> = const { RefCell::new(None) };
}

fn misconfigured(reason: &'static str, detail: impl Into<String>) -> HttpError {
    HttpError::new(ErrorCode::Misconfigured, reason).with_detail(detail)
}

/// The policy file's text: a string, or the parsed object when a bundler has
/// already inlined it.
fn policy_text() -> Result<String, HttpError> {
    let not_loaded = || misconfigured("invalid_policy", "policy.json is not loaded");
    let value = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str(POLICY_GLOBAL))
        .map_err(|_| not_loaded())?;
    if let Some(text) = value.as_string() {
        return Ok(text);
    }
    if value.is_object() {
        return js_sys::JSON::stringify(&value)
            .map(String::from)
            .map_err(|_| not_loaded());
    }
    Err(not_loaded())
}

/// Which bindings the Worker reads, and the policy. Always the constants above
/// and the policy module, except in a `stand-ins` build, where the integration
/// tests choose them.
struct Bindings {
    account_id: String,
    broker_token: String,
    signing_key: String,
    policy: String,
}

impl Bindings {
    async fn read(env: &Env) -> Result<Self, HttpError> {
        #[cfg(feature = "stand-ins")]
        if let Ok(url) = env.var("CF_OIDC_EXCHANGE_SCENARIO_URL") {
            return Self::scenario(&url.to_string()).await;
        }
        Ok(Self {
            account_id: env
                .var(ACCOUNT_ID)
                .map(|var| var.to_string())
                .unwrap_or_default(),
            broker_token: BROKER_TOKEN.into(),
            signing_key: SIGNING_KEY.into(),
            policy: policy_text()?,
        })
    }

    /// The integration tests' scenario: the policy, the account, and which
    /// bindings hold the broker token and the signing key.
    #[cfg(feature = "stand-ins")]
    async fn scenario(url: &str) -> Result<Self, HttpError> {
        #[derive(serde::Deserialize)]
        struct Scenario {
            policy: serde_json::Value,
            account_id: String,
            broker_token: String,
            signing_key: String,
        }
        let failed = |err: reqwest::Error| misconfigured("scenario_unavailable", err.to_string());
        let scenario: Scenario = reqwest::get(url)
            .await
            .map_err(failed)?
            .json()
            .await
            .map_err(failed)?;
        Ok(Self {
            account_id: scenario.account_id,
            broker_token: scenario.broker_token,
            signing_key: scenario.signing_key,
            policy: match scenario.policy {
                serde_json::Value::String(text) => text,
                other => other.to_string(),
            },
        })
    }
}

pub struct Config {
    pub policy: Rc<Policy>,
    pub account_id: String,
    broker_token: String,
    signing_key: String,
    env: Env,
}

impl Config {
    /// Loads the policy, or the copy already loaded, and checks the bindings it needs.
    pub async fn load(env: &Env) -> Result<Self, HttpError> {
        let Bindings {
            account_id,
            broker_token,
            signing_key,
            policy: raw,
        } = Bindings::read(env).await?;
        if account_id.is_empty() {
            return Err(misconfigured(
                "misconfigured",
                format!("{ACCOUNT_ID} must be set"),
            ));
        }
        let policy = LOADED.with_borrow_mut(|loaded| {
            let stale = loaded
                .as_ref()
                .is_none_or(|l| l.raw != raw || l.account_id != account_id);
            if stale {
                let result =
                    load_policy(&serde_json::Value::String(raw.clone()), Some(&account_id))
                        .map(Rc::new);
                match &result {
                    Ok(policy) => Audit::new("policy.loaded")
                        .with("profiles", policy.profiles.len())
                        .emit(),
                    Err(err) => Audit::new("policy.invalid")
                        .with("issues", err.issues.clone())
                        .emit(),
                }
                *loaded = Some(Loaded {
                    raw,
                    account_id: account_id.clone(),
                    result,
                });
            }
            loaded.as_ref().map(|l| l.result.clone())
        });
        match policy {
            Some(Ok(policy)) => Ok(Self {
                policy,
                account_id,
                broker_token,
                signing_key,
                env: env.clone(),
            }),
            _ => Err(HttpError::new(ErrorCode::Misconfigured, "invalid_policy")),
        }
    }

    /// A secret from a Secrets Store binding, read on every use, never cached
    /// here. A plain Worker secret is refused rather than accepted as a weaker setup.
    async fn secret(&self, binding: &str, reason: &'static str) -> Result<String, HttpError> {
        let store = self.env.secret_store(binding).map_err(|_| {
            misconfigured(reason, format!("{binding} must be a Secrets Store binding"))
        })?;
        match store.get().await {
            Ok(Some(value)) if !value.is_empty() => Ok(value),
            Ok(_) => Err(misconfigured(reason, "empty value")),
            Err(err) => Err(misconfigured(reason, err.to_string())),
        }
    }

    /// The Cloudflare API, as the broker token.
    pub async fn cloudflare(&self) -> Result<Cloudflare, HttpError> {
        let token = self
            .secret(&self.broker_token, "broker_token_unavailable")
            .await?;
        Ok(Cloudflare::new(
            &self.cloudflare_api(),
            &self.account_id,
            &token,
        ))
    }

    /// Whether a signing key is bound at all. Without one, the broker issues no
    /// tokens of its own and publishes no keys.
    pub fn has_signing_key(&self) -> bool {
        let env: &JsValue = self.env.as_ref();
        js_sys::Reflect::get(env.unchecked_ref(), &JsValue::from_str(&self.signing_key))
            .is_ok_and(|binding| !binding.is_undefined())
    }

    pub async fn signing_key(&self) -> Result<Rc<SigningKey>, HttpError> {
        let pem = self
            .secret(&self.signing_key, "signing_key_unavailable")
            .await?;
        issuer::signing_key(&pem).await
    }

    pub fn github_api(&self) -> String {
        self.upstream("CF_OIDC_EXCHANGE_GITHUB_API_URL", github::API_URL)
    }

    pub fn cloudflare_api(&self) -> String {
        self.upstream("CF_OIDC_EXCHANGE_CLOUDFLARE_API_URL", cloudflare::API_URL)
    }

    /// An upstream's base URL. Only a `stand-ins` build, for the integration
    /// tests, takes another one from the environment.
    #[allow(unused_variables)]
    fn upstream(&self, binding: &str, default: &str) -> String {
        #[cfg(feature = "stand-ins")]
        if let Ok(url) = self.env.var(binding) {
            return url.to_string();
        }
        default.to_string()
    }
}
