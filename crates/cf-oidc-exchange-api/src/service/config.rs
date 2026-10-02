//! The Worker's configuration, read from its bindings.
//!
//! [`Config::from_env`] is the only place that reads `Env`: the crate root
//! builds one per request and hands it to the handler, which takes what it
//! needs from it.
//!
//! An unset account, an invalid policy, or a broker token that isn't a Secrets
//! Store binding fails it, and the Worker serves nothing until it's fixed. The
//! secrets' values are read only when they're used, since reading is async, and
//! never cached, so a rotated one takes effect at once.
//!
//! The policy is loaded here, once per isolate, from the `policy.json` module
//! beside the Worker. Its format and guardrails are in [`crate::policy`].

use std::{cell::RefCell, sync::Arc};

use cf_oidc_exchange_sdk::v1::{Error, ErrorCode};
use serde_json::Value;
use worker::{Env, SecretStore, js_sys, wasm_bindgen::JsValue};

use crate::{
    audit::Audit,
    cloudflare::{self, Cloudflare},
    github,
    issuer::{self, SigningKey},
    policy::{Policy, PolicyError, load_policy},
};

/// The binding of the account the broker token belongs to and tokens are
/// minted in.
pub const ACCOUNT_KEY: &str = "CF_OIDC_EXCHANGE_API_ACCOUNT_ID";

/// The binding of the broker token: account-owned, with "Account API Tokens
/// Write", plus R2 permissions covering what profiles' `buckets` delegate.
pub const BROKER_TOKEN_KEY: &str = "CF_OIDC_EXCHANGE_API_BROKER_TOKEN";

/// The binding of the RSA private key (PKCS#8 PEM, at least 2048 bits) the
/// broker signs its own tokens with. Optional: without it, the broker issues
/// none and publishes no keys.
pub const SIGNING_KEY_KEY: &str = "CF_OIDC_EXCHANGE_API_SIGNING_KEY";

/// Where the entry module puts `policy.json`, which Terraform uploads beside the
/// Worker as a text module. See `worker/entry.js`.
const POLICY_GLOBAL: &str = "CF_OIDC_EXCHANGE_API_POLICY";

thread_local! {
    // Parsed once per isolate. The policy and env are fixed for the lifetime of a deployment.
    static LOADED: RefCell<Option<Loaded>> = const { RefCell::new(None) };
}

/// The policy, loaded, and what it was loaded from.
struct Loaded {
    raw: String,
    account_id: String,
    result: Result<Arc<Policy>, PolicyError>,
}

/// What the Worker is configured with, from its bindings.
pub struct Config {
    /// `CF_OIDC_EXCHANGE_API_ACCOUNT_ID`.
    account_id: String,
    /// `policy.json`, loaded and checked against the account.
    policy: Arc<Policy>,
    /// `CF_OIDC_EXCHANGE_API_BROKER_TOKEN`'s binding, not yet its value.
    broker_token: SecretConfig,
    /// `CF_OIDC_EXCHANGE_API_SIGNING_KEY`'s binding, which may be unbound.
    signing_key: SecretConfig,
    /// Where GitHub's API and Cloudflare's are.
    github_api: String,
    cloudflare_api: String,
}

impl Config {
    /// Reads the Worker's bindings, and loads the policy.
    ///
    /// Async only because a `stand-ins` build, for the integration tests, takes
    /// its bindings from the running test's scenario.
    ///
    /// # Errors
    ///
    /// When the account isn't set, the policy is invalid, or a secret isn't a
    /// Secrets Store binding.
    pub async fn from_env(env: &Env) -> Result<Self, Error> {
        let bindings = Bindings::from_env(env).await?;
        if bindings.account_id.is_empty() {
            return Err(misconfigured(format!("{ACCOUNT_KEY} must be set")));
        }
        let policy = load(&bindings.policy, &bindings.account_id)?;
        Ok(Self {
            account_id: bindings.account_id,
            policy,
            broker_token: SecretConfig::from_env(env, &bindings.broker_token, true)?,
            signing_key: SecretConfig::from_env(env, &bindings.signing_key, false)?,
            github_api: upstream(env, "CF_OIDC_EXCHANGE_API_GITHUB_URL", github::API_URL),
            cloudflare_api: upstream(
                env,
                "CF_OIDC_EXCHANGE_API_CLOUDFLARE_URL",
                cloudflare::API_URL,
            ),
        })
    }

    /// The account tokens are minted in.
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// The policy.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Where GitHub's API is.
    pub fn github_api(&self) -> &str {
        &self.github_api
    }

    /// Where Cloudflare's API is.
    pub fn cloudflare_api(&self) -> &str {
        &self.cloudflare_api
    }

    /// The Cloudflare API, as the broker token, read now.
    pub async fn cloudflare(&self) -> Result<Cloudflare, Error> {
        let token = self.broker_token.read().await?;
        Ok(Cloudflare::new(
            &self.cloudflare_api,
            &self.account_id,
            &token,
        ))
    }

    /// Whether a signing key is bound. Without one, the broker issues no tokens
    /// of its own and publishes no keys.
    pub fn has_signing_key(&self) -> bool {
        self.signing_key.store.is_some()
    }

    /// The signing key, read now.
    pub async fn signing_key(&self) -> Result<std::rc::Rc<SigningKey>, Error> {
        issuer::signing_key(&self.signing_key.read().await?).await
    }
}

fn misconfigured(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::Misconfigured, message)
}

/// Whether `env` has a binding named `name`, of whatever type.
fn is_bound(env: &Env, name: &str) -> bool {
    js_sys::Reflect::get(env.as_ref(), &JsValue::from_str(name))
        .is_ok_and(|binding| !binding.is_undefined())
}

/// An upstream's base URL. Only a `stand-ins` build, for the integration tests,
/// takes another one from the environment.
#[allow(unused_variables)]
fn upstream(env: &Env, binding: &str, default: &str) -> String {
    #[cfg(feature = "stand-ins")]
    if let Ok(url) = env.var(binding) {
        return url.to_string();
    }
    default.to_string()
}

/// Loads the policy in `raw` for the account, or the copy already loaded.
fn load(raw: &str, account_id: &str) -> Result<Arc<Policy>, Error> {
    let loaded = LOADED.with_borrow_mut(|loaded| {
        let stale = loaded
            .as_ref()
            .is_none_or(|l| l.raw != raw || l.account_id != account_id);
        if stale {
            let result = load_policy(&Value::String(raw.into()), Some(account_id)).map(Arc::new);
            match &result {
                Ok(policy) => Audit::new("policy.loaded")
                    .with("profiles", policy.profiles.len())
                    .emit(),
                Err(err) => Audit::new("policy.invalid")
                    .with("issues", err.issues.clone())
                    .emit(),
            }
            *loaded = Some(Loaded {
                raw: raw.into(),
                account_id: account_id.into(),
                result,
            });
        }
        loaded.as_ref().map(|l| l.result.clone())
    });
    match loaded {
        Some(Ok(policy)) => Ok(policy),
        _ => Err(misconfigured(
            "the policy is invalid; its policy.invalid line says why",
        )),
    }
}

/// A secret in Secrets Store: its binding, read when it's used. A plain Worker
/// secret is refused rather than accepted as a weaker setup.
struct SecretConfig {
    binding: String,
    /// `None` when nothing is bound under `binding`.
    store: Option<SecretStore>,
}

impl SecretConfig {
    /// The secret bound as `binding`. Unbound is an error only if it's
    /// `required`; bound as anything but a Secrets Store secret always is.
    fn from_env(env: &Env, binding: &str, required: bool) -> Result<Self, Error> {
        let store = match env.secret_store(binding) {
            Ok(store) => Some(store),
            Err(_) if required || is_bound(env, binding) => {
                return Err(misconfigured(format!(
                    "{binding} must be a Secrets Store binding"
                )));
            }
            Err(_) => None,
        };
        Ok(Self {
            binding: binding.into(),
            store,
        })
    }

    async fn read(&self) -> Result<String, Error> {
        let binding = &self.binding;
        let Some(store) = &self.store else {
            return Err(misconfigured(format!("{binding} isn't bound")));
        };
        match store.get().await {
            Ok(Some(value)) if !value.is_empty() => Ok(value),
            Ok(_) => Err(misconfigured(format!("{binding} is empty"))),
            Err(err) => Err(misconfigured(format!("{binding} can't be read: {err}"))),
        }
    }
}

/// Which bindings the Worker reads, and the policy's text. Always the constants
/// above and the policy module, except in a `stand-ins` build, where the
/// integration tests choose them.
struct Bindings {
    account_id: String,
    broker_token: String,
    signing_key: String,
    policy: String,
}

impl Bindings {
    async fn from_env(env: &Env) -> Result<Self, Error> {
        #[cfg(feature = "stand-ins")]
        if let Ok(url) = env.var("CF_OIDC_EXCHANGE_API_SCENARIO_URL") {
            return Self::scenario(&url.to_string()).await;
        }
        Ok(Self {
            account_id: env
                .var(ACCOUNT_KEY)
                .map(|var| var.to_string())
                .unwrap_or_default(),
            broker_token: BROKER_TOKEN_KEY.into(),
            signing_key: SIGNING_KEY_KEY.into(),
            policy: Self::policy_text()?,
        })
    }

    /// The policy file's text: a string, or the parsed object when a bundler
    /// has already inlined it.
    fn policy_text() -> Result<String, Error> {
        let not_loaded = || misconfigured("policy.json is not loaded");
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

    /// The integration tests' scenario: the policy, the account, and which
    /// bindings hold the broker token and the signing key.
    #[cfg(feature = "stand-ins")]
    async fn scenario(url: &str) -> Result<Self, Error> {
        #[derive(serde::Deserialize)]
        struct Scenario {
            policy: Value,
            account_id: String,
            broker_token: String,
            signing_key: String,
        }
        let failed = |err: reqwest::Error| misconfigured(format!("the scenario: {err}"));
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
                Value::String(text) => text,
                other => other.to_string(),
            },
        })
    }
}
