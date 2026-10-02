//! Handler implementations for the generated API trait.
//!
//! Every operation of the broker's API is implemented, in
//! [`ExchangeServiceHandler`]: the token exchange, revocation, and the
//! discovery document and keys services verify the broker's own tokens with.
//!
//! # Send
//!
//! The generated trait wants `Send` futures, so axum can serve them on any
//! thread. Fetch, Secrets Store and WebCrypto futures aren't `Send`: they hold
//! JavaScript values. A Worker is single-threaded, so each method runs its body
//! in a `SendFuture`, which asserts it.
//!
//! # Errors
//!
//! Each method returns its operation's response enum, one variant per status
//! the spec declares, so a status the spec doesn't list can't be returned. A
//! caller's mistake (400 to 404) says what it was. A fault of the broker's (500,
//! 502) doesn't say why: that goes to the log. A refused exchange or revocation
//! is audited with the whole message either way.
//!
//! # Configuration
//!
//! The policy is loaded once per isolate, from the `policy.json` module beside
//! the Worker, and checked against the account. Secrets come from Secrets
//! Store only, and are read on every use, so a rotated one takes effect at
//! once. Any problem with either is a `500 misconfigured`: the broker fails
//! closed.

use std::{cell::RefCell, rc::Rc};

use cf_oidc_exchange_sdk::v1::{
    self, BucketCredentials, Discovery, Error, ErrorCode, ExchangeServiceApi, IssuedTokenType,
    Jwks, JwksKeysItem, TokenExchangeRequest,
    TokenExchangeRequestSubjectTokenType as SubjectTokenType, TokenExchangeResponse,
    TokenExchangeResponseTokenType as TokenType, TokenRevocationRequest,
};
use serde_json::Value;
use worker::{
    Env, console_error, js_sys,
    send::SendFuture,
    wasm_bindgen::{JsCast, JsValue},
};

use crate::{
    audit::Audit,
    cloudflare::{self, BucketGrant, Cloudflare, MintedToken, rfc3339, token_name},
    github::{self, UserCheck},
    issuer::{self, ALGORITHM, IssueRequest, SigningKey},
    oidc::{self, Jwt, shown},
    policy::{
        CLOUDFLARE_AUDIENCE, Claims, Policy, PolicyError, Profile, Provider, ProviderType,
        clamp_ttl, load_policy, r2_prefixes, select_profile,
    },
};

/// The binding of the account the broker token belongs to and tokens are
/// minted in.
const ACCOUNT_KEY: &str = "CF_OIDC_EXCHANGE_API_ACCOUNT_ID";

/// The binding of the broker token: account-owned, with "Account API Tokens
/// Write", plus R2 permissions covering what profiles' `buckets` delegate.
const BROKER_TOKEN_KEY: &str = "CF_OIDC_EXCHANGE_API_BROKER_TOKEN";

/// The binding of the RSA private key (PKCS#8 PEM, at least 2048 bits) the
/// broker signs its own tokens with. Optional: without it, the broker issues
/// none and publishes no keys.
const SIGNING_KEY_KEY: &str = "CF_OIDC_EXCHANGE_API_SIGNING_KEY";

/// Where the entry module puts `policy.json`, which Terraform uploads beside the
/// Worker as a text module. See `worker/entry.js`.
const POLICY_GLOBAL: &str = "CF_OIDC_EXCHANGE_API_POLICY";

/// The token exchange grant, RFC 8693's.
const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

thread_local! {
    // Parsed once per isolate. The policy and env are fixed for the lifetime of a deployment.
    static LOADED: RefCell<Option<Loaded>> = const { RefCell::new(None) };
}

/// The policy, loaded, and what it was loaded from.
struct Loaded {
    raw: String,
    account_id: String,
    result: Result<Rc<Policy>, PolicyError>,
}

fn now_ms() -> u64 {
    worker::Date::now().as_millis()
}

fn misconfigured(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::Misconfigured, message)
}

/// What a caller is told of a fault of the broker's, instead of why. `None` for
/// the caller's own mistakes, which say what they were.
fn generic(code: &ErrorCode) -> Option<&'static str> {
    match code {
        ErrorCode::Misconfigured => Some("the broker is misconfigured; its logs say why"),
        ErrorCode::InternalError => Some("the broker failed; its logs say why"),
        ErrorCode::UpstreamError => {
            Some("a service the broker relies on failed; its logs say which")
        }
        _ => None,
    }
}

/// The error a caller gets: the error itself for a mistake of theirs, and for a
/// fault of the broker's the code alone, with why logged.
fn public(err: Error) -> Error {
    match generic(&err.error) {
        Some(message) => {
            console_error!("{err}");
            Error::new(err.error, message)
        }
        None => err,
    }
}

/// The Worker's configuration: the policy, and the bindings it reads.
struct Config {
    policy: Rc<Policy>,
    account_id: String,
    /// The bindings of the broker token and the signing key.
    broker_token: String,
    signing_key: String,
    env: Env,
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
    async fn read(env: &Env) -> Result<Self, Error> {
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

impl Config {
    /// Loads the policy, or the copy already loaded, and the bindings to read.
    async fn load(env: &Env) -> Result<Self, Error> {
        let Bindings {
            account_id,
            broker_token,
            signing_key,
            policy: raw,
        } = Bindings::read(env).await?;
        if account_id.is_empty() {
            return Err(misconfigured(format!("{ACCOUNT_KEY} must be set")));
        }
        let policy = LOADED.with_borrow_mut(|loaded| {
            let stale = loaded
                .as_ref()
                .is_none_or(|l| l.raw != raw || l.account_id != account_id);
            if stale {
                let result =
                    load_policy(&Value::String(raw.clone()), Some(&account_id)).map(Rc::new);
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
            _ => Err(misconfigured(
                "the policy is invalid; its policy.invalid line says why",
            )),
        }
    }

    /// A secret from a Secrets Store binding, read on every use, never cached
    /// here. A plain Worker secret is refused rather than accepted as a weaker
    /// setup.
    async fn secret(&self, binding: &str) -> Result<String, Error> {
        let store = self
            .env
            .secret_store(binding)
            .map_err(|_| misconfigured(format!("{binding} must be a Secrets Store binding")))?;
        match store.get().await {
            Ok(Some(value)) if !value.is_empty() => Ok(value),
            Ok(_) => Err(misconfigured(format!("{binding} is empty"))),
            Err(err) => Err(misconfigured(format!("{binding} can't be read: {err}"))),
        }
    }

    /// The Cloudflare API, as the broker token.
    async fn cloudflare(&self) -> Result<Cloudflare, Error> {
        let token = self.secret(&self.broker_token).await?;
        Ok(Cloudflare::new(
            &self.cloudflare_api(),
            &self.account_id,
            &token,
        ))
    }

    /// Whether a signing key is bound at all. Without one, the broker issues no
    /// tokens of its own and publishes no keys.
    fn has_signing_key(&self) -> bool {
        let env: &JsValue = self.env.as_ref();
        js_sys::Reflect::get(env.unchecked_ref(), &JsValue::from_str(&self.signing_key))
            .is_ok_and(|binding| !binding.is_undefined())
    }

    async fn signing_key(&self) -> Result<Rc<SigningKey>, Error> {
        let pem = self.secret(&self.signing_key).await?;
        issuer::signing_key(&pem).await
    }

    fn github_api(&self) -> String {
        self.upstream("CF_OIDC_EXCHANGE_API_GITHUB_URL", github::API_URL)
    }

    fn cloudflare_api(&self) -> String {
        self.upstream("CF_OIDC_EXCHANGE_API_CLOUDFLARE_URL", cloudflare::API_URL)
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

/// A verified caller of `/oauth/token`.
struct Caller<'p> {
    provider: &'p Provider,
    claims: Claims,
}

/// The broker's own exchange parameters, and what the caller asked for.
struct Exchange<'r> {
    kind: ProviderType,
    token: &'r str,
    /// Cloudflare, or a service the policy issues the broker's own tokens for.
    audience: &'r str,
    profile: Option<&'r str>,
    ttl: Option<&'r str>,
    repository: Option<&'r str>,
}

impl<'r> Exchange<'r> {
    /// Checks what the generated validation can't: which audience, and what it
    /// can hand out.
    fn read(request: &'r TokenExchangeRequest, policy: &Policy) -> Result<Self, Error> {
        let audience = request.audience.as_deref().unwrap_or(CLOUDFLARE_AUDIENCE);
        if audience.is_empty() {
            return Err(Error::new(
                ErrorCode::BadRequest,
                "audience must not be empty",
            ));
        }
        // Cloudflare credentials, or a JWT for any other service.
        let issuable = match (
            audience == CLOUDFLARE_AUDIENCE,
            &request.requested_token_type,
        ) {
            (_, None) => true,
            (true, Some(t)) => matches!(
                t,
                IssuedTokenType::UrnIetfParamsOauthTokenTypeAccessToken
                    | IssuedTokenType::UrnCfOidcAuthParamsOauthTokenTypeR2Credentials
            ),
            (false, Some(t)) => matches!(
                t,
                IssuedTokenType::UrnIetfParamsOauthTokenTypeJwt
                    | IssuedTokenType::UrnIetfParamsOauthTokenTypeAccessToken
            ),
        };
        if let (false, Some(requested)) = (issuable, &request.requested_token_type) {
            return Err(Error::new(
                ErrorCode::BadRequest,
                format!("{requested} can't be issued for {}", shown(audience)),
            ));
        }
        // Nothing is verified for an audience the policy doesn't know.
        if audience != CLOUDFLARE_AUDIENCE
            && !policy.profiles.iter().any(|p| p.audience == audience)
        {
            return Err(Error::new(
                ErrorCode::BadRequest,
                format!("no profile is for audience {}", shown(audience)),
            ));
        }
        let kind = match request.subject_token_type {
            SubjectTokenType::UrnIetfParamsOauthTokenTypeIdToken
            | SubjectTokenType::UrnIetfParamsOauthTokenTypeJwt => ProviderType::Oidc,
            SubjectTokenType::UrnIetfParamsOauthTokenTypeAccessToken => ProviderType::GithubUser,
        };
        Ok(Self {
            kind,
            token: &request.subject_token,
            audience,
            profile: request.profile.as_deref(),
            ttl: request.ttl.as_deref(),
            // Only a person names the repo; a job's token already does.
            repository: request
                .repository
                .as_deref()
                .filter(|_| kind == ProviderType::GithubUser),
        })
    }
}

/// The broker's API, over the Worker's bindings.
#[derive(Clone)]
pub struct ExchangeServiceHandler {
    env: Env,
}

impl ExchangeServiceHandler {
    /// Creates a handler over the Worker's bindings.
    pub fn new(env: Env) -> Self {
        Self { env }
    }

    /// Deletes expired `cf-oidc:` tokens, for the hourly cron. Returns how many.
    pub async fn cleanup(&self) -> Result<usize, Error> {
        let config = Config::load(&self.env).await?;
        config.cloudflare().await?.cleanup(now_ms()).await
    }

    /// Authenticates the caller, whose token is in the body.
    async fn authenticate<'p>(
        config: &Config,
        policy: &'p Policy,
        exchange: &Exchange<'_>,
    ) -> Result<Caller<'p>, Error> {
        if exchange.kind == ProviderType::Oidc {
            let jwt = Jwt::decode(exchange.token)?;
            let provider = oidc::provider_for(&jwt, &policy.providers)?;
            let claims = oidc::verify(jwt, provider, now_ms()).await?;
            return Ok(Caller { provider, claims });
        }

        // The provider for people, and its enabled profiles: none means a 404, so
        // the broker doesn't call GitHub for people it serves nothing.
        let provider = policy
            .providers
            .iter()
            .find(|p| p.kind == ProviderType::GithubUser);
        let profiles: Vec<&Profile> = policy
            .profiles
            .iter()
            .filter(|p| Some(p.provider.as_str()) == provider.map(|p| p.name.as_str()) && p.enabled)
            .collect();
        let Some(provider) = provider.filter(|_| !profiles.is_empty()) else {
            return Err(Error::new(ErrorCode::NotFound, "no profile is for people"));
        };
        // Teams cost extra GitHub calls, so they're only looked up if a profile
        // that could match needs them.
        let teams = profiles
            .iter()
            .filter(|p| exchange.profile.is_none_or(|name| p.name == name))
            .any(|p| p.claims.contains_key("team_id"));
        let owner_ids = provider
            .claims
            .get("repository_owner_id")
            .map(Vec::as_slice)
            .unwrap_or_default();
        let check = UserCheck { owner_ids, teams };
        let claims = github::verify_user(
            &config.github_api(),
            exchange.token,
            exchange.repository,
            check,
        )
        .await?;
        Ok(Caller { provider, claims })
    }

    /// The broker's own token, for a profile with another service's `audience`.
    async fn service_token(
        config: &Config,
        caller: &Caller<'_>,
        profile: &Profile,
        ttl: u64,
    ) -> Result<TokenExchangeResponse, Error> {
        let key = config.signing_key().await?;
        let Caller { provider, claims } = caller;
        let text = |name: &str| claims.get(name).and_then(Value::as_str);
        let subject = match (provider.kind, text("actor_id"), text("sub")) {
            (ProviderType::GithubUser, Some(actor_id), _) => format!("user:{actor_id}"),
            (ProviderType::Oidc, _, Some(sub)) => sub.to_string(),
            _ => format!("{}:unknown", provider.name),
        };
        let now = now_ms() / 1000;
        let request = IssueRequest {
            issuer: &config.policy.issuer,
            audience: &profile.audience,
            subject,
            provider: &provider.name,
            profile: &profile.name,
            matched: profile.claims.keys().map(String::as_str).collect(),
            claims,
            ttl,
            // A job's OIDC token has an expiry; a person's GitHub token doesn't.
            not_after: claims.get("exp").and_then(Value::as_u64),
        };
        let issued = issuer::issue(&key, &request, now).await?;
        Audit::new("token.issue")
            .caller(Some(&provider.name), Some(&profile.name), Some(claims))
            .with("audience", profile.audience.as_str())
            .with("jti", issued.jti.as_str())
            .with("expires_on", rfc3339(issued.expires_at * 1000))
            .emit();
        Ok(TokenExchangeResponse {
            access_token: Some(issued.jwt),
            account_id: None,
            buckets: None,
            expires_at: issued.expires_at as i64,
            expires_in: issued.expires_at.saturating_sub(now) as i64,
            issued_token_type: IssuedTokenType::UrnIetfParamsOauthTokenTypeJwt,
            profile: profile.name.clone(),
            token_id: None,
            token_type: TokenType::Bearer,
        })
    }

    /// A Cloudflare API token, R2 credentials, or both, as the profile has them.
    async fn cloudflare_credentials(
        config: &Config,
        caller: &Caller<'_>,
        profile: &Profile,
        ttl: u64,
    ) -> Result<TokenExchangeResponse, Error> {
        let Caller { provider, claims } = caller;
        let audit = |event| {
            Audit::new(event).caller(Some(&provider.name), Some(&profile.name), Some(claims))
        };

        // Filled in before anything is minted, so an unusable claim leaves nothing behind.
        let buckets = profile.buckets.as_deref().unwrap_or_default();
        let prefixes = buckets
            .iter()
            .map(|bucket| r2_prefixes(bucket, claims))
            .collect::<Result<Vec<_>, _>>()?;

        let cloudflare = config.cloudflare().await?;
        let now = now_ms();
        let mut token: Option<MintedToken> = None;
        if let Some(policies) = &profile.policies {
            let minted = cloudflare
                .mint(policies, token_name(claims, provider), ttl, now)
                .await?;
            audit("token.mint")
                .with("token_id", minted.token_id.as_str())
                .with("expires_on", minted.expires_on.as_str())
                .emit();
            token = Some(minted);
        }

        let mut issued: Vec<BucketGrant> = Vec::new();
        for (bucket, prefixes) in buckets.iter().zip(prefixes) {
            match cloudflare.issue_r2(bucket, prefixes, ttl, now).await {
                Ok(grant) => {
                    audit("r2.issued")
                        .with("bucket", grant.name.as_str())
                        .with("prefixes", grant.prefixes.clone())
                        .with(
                            "permission",
                            serde_json::to_value(bucket.permission).unwrap_or_default(),
                        )
                        .with("expires_on", grant.expires_on.as_str())
                        .emit();
                    issued.push(grant);
                }
                Err(err) => {
                    // Half a profile isn't handed out. Credentials already issued
                    // can't be revoked, but nobody has them.
                    if let Some(token) = &token {
                        cloudflare.discard(&token.token_id).await;
                    }
                    return Err(err);
                }
            }
        }

        let failed = |what: String| Error::new(ErrorCode::InternalError, what);
        let expires_on = token
            .as_ref()
            .map(|t| t.expires_on.clone())
            .or_else(|| issued.first().map(|b| b.expires_on.clone()))
            .ok_or_else(|| {
                failed(format!(
                    "profile {} has neither a token nor buckets",
                    profile.name
                ))
            })?;
        let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_on)
            .map(|at| at.timestamp())
            .unwrap_or_default();
        let buckets = issued
            .into_iter()
            .map(|grant| {
                Ok(BucketCredentials {
                    access_key_id: grant.access_key_id,
                    endpoint: grant.endpoint,
                    expires_on: grant
                        .expires_on
                        .parse()
                        .map_err(|_| failed(format!("expires_on {}", grant.expires_on)))?,
                    name: grant.name,
                    prefixes: grant.prefixes,
                    secret_access_key: grant.secret_access_key,
                    session_token: grant.session_token,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let (access_token, token_id, issued_token_type, token_type) = match token {
            Some(token) => (
                Some(token.token),
                Some(token.token_id),
                IssuedTokenType::UrnIetfParamsOauthTokenTypeAccessToken,
                TokenType::Bearer,
            ),
            None => (
                None,
                None,
                IssuedTokenType::UrnCfOidcAuthParamsOauthTokenTypeR2Credentials,
                TokenType::NA,
            ),
        };
        Ok(TokenExchangeResponse {
            access_token,
            account_id: Some(config.account_id.clone()),
            buckets: (!buckets.is_empty()).then_some(buckets),
            expires_at,
            expires_in: (expires_at - (now / 1000) as i64).max(0),
            issued_token_type,
            profile: profile.name.clone(),
            token_id,
            token_type,
        })
    }
}

#[async_trait::async_trait]
impl ExchangeServiceApi for ExchangeServiceHandler {
    /// POST /oauth/token
    ///
    /// An RFC 8693 token exchange: the caller's token, checked against the
    /// providers, for what the profile it matches hands out.
    async fn exchange_token(&self, request: TokenExchangeRequest) -> v1::ExchangeTokenResponse {
        SendFuture::new(async move {
            let mut caller: Option<Caller> = None;
            let mut profile: Option<String> = request.profile.clone();
            let config = Config::load(&self.env).await;
            let exchanged = async {
                let config = config.as_ref().map_err(Clone::clone)?;
                let policy = &config.policy;
                let exchange = Exchange::read(&request, policy)?;
                let verified = Self::authenticate(config, policy, &exchange).await?;
                let caller = caller.insert(verified);
                let selected = select_profile(
                    policy,
                    &caller.provider.name,
                    &caller.claims,
                    exchange.profile,
                    exchange.audience,
                )?;
                profile = Some(selected.name.clone());
                let ttl = clamp_ttl(exchange.ttl, selected)?;
                if selected.audience == CLOUDFLARE_AUDIENCE {
                    Self::cloudflare_credentials(config, caller, selected, ttl).await
                } else {
                    Self::service_token(config, caller, selected, ttl).await
                }
            };

            match exchanged.await {
                Ok(response) => v1::ExchangeTokenResponse::Ok(response),
                Err(err) => {
                    Audit::new("token.deny")
                        .caller(
                            caller.as_ref().map(|c| c.provider.name.as_str()),
                            profile.as_deref(),
                            caller.as_ref().map(|c| &c.claims),
                        )
                        .with("error", err.error.as_str())
                        .with("message", err.message.as_str())
                        .emit();
                    let code = err.error.clone();
                    let err = public(err);
                    match code {
                        ErrorCode::BadRequest => v1::ExchangeTokenResponse::BadRequest(err),
                        ErrorCode::Unauthorized => v1::ExchangeTokenResponse::Unauthorized(err),
                        ErrorCode::Forbidden => v1::ExchangeTokenResponse::Forbidden(err),
                        ErrorCode::NotFound => v1::ExchangeTokenResponse::NotFound(err),
                        ErrorCode::UpstreamError => v1::ExchangeTokenResponse::BadGateway(err),
                        ErrorCode::Misconfigured | ErrorCode::InternalError => {
                            v1::ExchangeTokenResponse::InternalServerError(err)
                        }
                    }
                }
            }
        })
        .await
    }

    /// POST /oauth/revoke
    ///
    /// An RFC 7009 revocation of a token the broker minted. Holding the token
    /// is the proof. Answers `Ok` whether the token was revoked or already gone.
    async fn revoke_token(&self, request: TokenRevocationRequest) -> v1::RevokeTokenResponse {
        SendFuture::new(async move {
            let revoked = async {
                let config = Config::load(&self.env).await?;
                let cloudflare = config.cloudflare().await?;
                cloudflare
                    .revoke(&config.cloudflare_api(), &request.token)
                    .await
            };
            let audit = Audit::new("token.revoke");
            match revoked.await {
                Ok(Some(id)) => {
                    audit.with("token_id", id).emit();
                    v1::RevokeTokenResponse::Ok
                }
                Ok(None) => {
                    audit.with("reason", "already_gone").emit();
                    v1::RevokeTokenResponse::Ok
                }
                Err(err) => {
                    audit
                        .with("error", err.error.as_str())
                        .with("message", err.message.as_str())
                        .emit();
                    let code = err.error.clone();
                    let err = public(err);
                    match code {
                        ErrorCode::BadRequest => v1::RevokeTokenResponse::BadRequest(err),
                        ErrorCode::Forbidden => v1::RevokeTokenResponse::Forbidden(err),
                        ErrorCode::UpstreamError => v1::RevokeTokenResponse::BadGateway(err),
                        _ => v1::RevokeTokenResponse::InternalServerError(err),
                    }
                }
            }
        })
        .await
    }

    /// GET /.well-known/openid-configuration
    ///
    /// The broker's discovery document, so services can find its keys and
    /// endpoints. It issues tokens by exchange only, so there's no
    /// authorization endpoint: it isn't a login provider.
    async fn discovery(&self) -> v1::DiscoveryResponse {
        SendFuture::new(async move {
            let document = async {
                let config = Config::load(&self.env).await?;
                let issuer = &config.policy.issuer;
                let url = |path: &str| {
                    format!("{issuer}{path}")
                        .parse()
                        .map_err(|_| misconfigured(format!("issuer {issuer} makes no URLs")))
                };
                Ok::<_, Error>(Discovery {
                    issuer: issuer.clone(),
                    jwks_uri: url("/.well-known/jwks")?,
                    token_endpoint: url("/oauth/token")?,
                    revocation_endpoint: url("/oauth/revoke")?,
                    grant_types_supported: vec![TOKEN_EXCHANGE.into()],
                    token_endpoint_auth_methods_supported: Some(vec!["none".into()]),
                    revocation_endpoint_auth_methods_supported: Some(vec!["none".into()]),
                    subject_types_supported: Some(vec!["public".into()]),
                    id_token_signing_alg_values_supported: Some(vec![ALGORITHM.into()]),
                })
            };
            match document.await {
                Ok(document) => v1::DiscoveryResponse::Ok(document),
                Err(err) => v1::DiscoveryResponse::InternalServerError(public(err)),
            }
        })
        .await
    }

    /// GET /.well-known/jwks
    ///
    /// The broker's public key, or none when no signing key is bound.
    async fn jwks(&self) -> v1::JwksResponse {
        SendFuture::new(async move {
            let keys = async {
                let config = Config::load(&self.env).await?;
                if !config.has_signing_key() {
                    return Ok(Jwks { keys: vec![] });
                }
                let key = config.signing_key().await?;
                let jwk: JwksKeysItem =
                    serde_json::from_value(key.public_jwk()).map_err(|err| {
                        Error::new(ErrorCode::InternalError, format!("the public key: {err}"))
                    })?;
                Ok::<_, Error>(Jwks { keys: vec![jwk] })
            };
            match keys.await {
                Ok(jwks) => v1::JwksResponse::Ok(jwks),
                Err(err) => v1::JwksResponse::InternalServerError(public(err)),
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use cf_oidc_exchange_sdk::v1::TokenExchangeRequestGrantType;
    use serde_json::json;

    use super::*;

    fn policy() -> Policy {
        let policy = json!({
            "version": 2,
            "issuer": "https://cf-oidc-exchange.example.com",
            "providers": [{ "name": "github", "issuer": "https://token.actions.githubusercontent.com", "audience": "https://cf-oidc-exchange.example.com", "claims": { "repository_owner_id": "100000001" } }],
            "profiles": [
                { "name": "deploy", "claims": { "ref": "refs/heads/main" }, "token": { "policies": [{ "permissions": ["DNS Write"], "resources": { "com.cloudflare.api.account.zone.fedcba9876543210fedcba9876543210": "*" } }] } },
                { "name": "nix-push", "audience": "https://cf-nix-cache.example.com", "claims": { "ref": "refs/heads/main" } },
            ],
        });
        load_policy(&policy, None).unwrap()
    }

    fn request(audience: Option<&str>, requested: Option<IssuedTokenType>) -> TokenExchangeRequest {
        let mut request = TokenExchangeRequest::new(
            TokenExchangeRequestGrantType::UrnIetfParamsOauthGrantTypeTokenExchange,
            "a.b.c".into(),
            SubjectTokenType::UrnIetfParamsOauthTokenTypeIdToken,
        );
        request.audience = audience.map(String::from);
        request.requested_token_type = requested;
        request
    }

    /// Why the exchange is refused before anything is verified, if it is.
    fn refusal(request: &TokenExchangeRequest) -> Option<String> {
        Exchange::read(request, &policy())
            .err()
            .map(|err| err.message)
    }

    #[test]
    fn defaults_to_the_cloudflare_audience() {
        let policy = policy();
        let request = request(None, None);
        assert_eq!(
            Exchange::read(&request, &policy).unwrap().audience,
            CLOUDFLARE_AUDIENCE
        );
    }

    #[test]
    fn refuses_an_audience_no_profile_is_for() {
        assert_eq!(
            refusal(&request(Some("https://other.example.com"), None)).as_deref(),
            Some("no profile is for audience https://other.example.com")
        );
        assert_eq!(
            refusal(&request(Some(""), None)).as_deref(),
            Some("audience must not be empty")
        );
        assert_eq!(
            refusal(&request(Some("https://cf-nix-cache.example.com"), None)),
            None
        );
    }

    #[test]
    fn refuses_token_types_the_audience_cant_have() {
        let jwt = Some(IssuedTokenType::UrnIetfParamsOauthTokenTypeJwt);
        let r2 = Some(IssuedTokenType::UrnCfOidcAuthParamsOauthTokenTypeR2Credentials);
        assert_eq!(
            refusal(&request(None, jwt.clone())).as_deref(),
            Some(
                "urn:ietf:params:oauth:token-type:jwt can't be issued for https://api.cloudflare.com"
            )
        );
        assert_eq!(refusal(&request(None, r2.clone())), None);
        let cache = Some("https://cf-nix-cache.example.com");
        assert!(refusal(&request(cache, r2)).is_some());
        assert_eq!(refusal(&request(cache, jwt)), None);
    }

    #[test]
    fn tells_callers_their_mistakes_but_not_the_brokers_faults() {
        for code in [
            ErrorCode::BadRequest,
            ErrorCode::Unauthorized,
            ErrorCode::Forbidden,
            ErrorCode::NotFound,
        ] {
            assert_eq!(generic(&code), None, "{code}");
        }
        for code in [
            ErrorCode::Misconfigured,
            ErrorCode::InternalError,
            ErrorCode::UpstreamError,
        ] {
            assert!(generic(&code).is_some(), "{code}");
        }
    }
}
