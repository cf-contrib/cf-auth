//! The broker's API: every operation of the SDK's `ExchangeServiceApi`, in
//! [`ExchangeServiceHandler`], over the policy and secrets in the Worker's
//! [`Config`]: the token exchange, revocation, and the discovery document and
//! keys services verify the broker's own tokens with.
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
//! # Exchanges
//!
//! No method authenticates: by the time an exchange reaches one, the auth
//! [`layer`](super::layer) has, and the handler takes the caller's identity
//! from it.

use std::{collections::BTreeSet, sync::Arc};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use cf_oidc_exchange_sdk::v1::{
    self, BucketCredentials, Discovery, Error, ErrorCode, ExchangeServiceApi, IssuedTokenType,
    Jwks, TokenExchangeRequest, TokenExchangeRequestSubjectTokenType as SubjectTokenType,
    TokenExchangeResponse, TokenExchangeResponseTokenType as TokenType, TokenRevocationRequest,
};
use chrono::{DateTime, SecondsFormat, Utc};
use cloudflare::v4::{
    ApiOpError, HttpClient, IamCreatePayload, IamEffect, IamPermissionGroup,
    IamPolicyWithPermissionGroupsAndResources, IamResources, IamResourcesTypeObjectNested,
    IamResourcesTypeObjectNestedAdditionalProperty, IamResourcesTypeObjectString,
    R2TempAccessCredsRequest, R2TempAccessCredsRequestPermission,
};
use serde::ser::{Serialize, SerializeMap, Serializer};
use serde_json::{Map, Value, json};
use web_sys::{CryptoKey, SubtleCrypto, WorkerGlobalScope};
use worker::{
    console_error, console_log, console_warn,
    js_sys::{self, Uint8Array},
    send::SendFuture,
    wasm_bindgen::{JsCast, JsValue},
    wasm_bindgen_futures::JsFuture,
};

use super::{
    config::{
        BucketConfig, BucketPermission, CLOUDFLARE_AUDIENCE, Config, Effect, MIN_TTL, PolicyConfig,
        ProfileConfig, ProviderConfig, ResourceValue, TokenPolicy, parse_duration,
    },
    layer::{self, Identity},
};

/// The token exchange grant, RFC 8693's.
const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// What the broker signs its own tokens with, which OIDC verifiers support by
/// default, cf-nix-cache included.
const ALGORITHM: &str = "RS256";

/// The smallest RSA signing key accepted, as NIST requires.
const MIN_MODULUS_BITS: usize = 2048;

/// Every minted token's name starts with this. Revocation and the cleanup
/// never touch anything else.
const TOKEN_PREFIX: &str = "cf-oidc:";

/// The longest token name Cloudflare takes.
const NAME_MAX: usize = 120;

/// Tokens listed per page by the cleanup.
const PAGE_SIZE: usize = 50;

const ACCOUNT_SCOPE: &str = "com.cloudflare.api.account";
const ZONE_SCOPE: &str = "com.cloudflare.api.account.zone";
const R2_SCOPE: &str = "com.cloudflare.edge.r2.bucket";

fn now_ms() -> u64 {
    worker::Date::now().as_millis()
}

/// A configuration the handler can't work with: a secret that can't be read, a
/// key that isn't one.
fn misconfigured(why: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::Misconfigured, why.to_string())
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

/// The broker's API, over the Worker's configuration.
#[derive(Clone)]
pub struct ExchangeServiceHandler {
    config: Arc<Config>,
}

impl ExchangeServiceHandler {
    /// A handler over the Worker's configuration, shared with the auth layer.
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    /// The Cloudflare API, as the Cloudflare token, read now.
    async fn cloudflare(&self) -> Result<Cloudflare, Error> {
        let token = self
            .config
            .cloudflare_token()
            .await
            .map_err(misconfigured)?;
        Ok(Cloudflare::new(
            self.config.cloudflare_api(),
            self.config.account_id(),
            &token,
        ))
    }

    /// The signing key, read now, or `None` if none is bound.
    async fn signing_key(&self) -> Result<Option<SigningKey>, Error> {
        match self.config.signing_key().await.map_err(misconfigured)? {
            Some(pem) => SigningKey::import(&pem).await.map(Some),
            None => Ok(None),
        }
    }

    /// Deletes expired `cf-oidc:` tokens, for the hourly cron. Returns how many.
    pub async fn cleanup(&self) -> Result<usize, Error> {
        self.cloudflare().await?.cleanup(now_ms()).await
    }

    /// The broker's own token, for a profile with another service's `audience`.
    async fn service_token(
        &self,
        caller: &Caller<'_>,
        profile: &ProfileConfig,
        ttl: u64,
    ) -> Result<TokenExchangeResponse, Error> {
        let Some(key) = self.signing_key().await? else {
            return Err(misconfigured(format!(
                "a token for {} needs a signing key, and none is bound",
                profile.audience
            )));
        };
        let now = now_ms() / 1000;
        let issued = key
            .issue(&self.config.policy().issuer, caller, profile, ttl, now)
            .await?;
        caller
            .audit("token.issue", Some(profile))
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
        &self,
        caller: &Caller<'_>,
        profile: &ProfileConfig,
        ttl: u64,
    ) -> Result<TokenExchangeResponse, Error> {
        // Filled in before anything is minted, so an unusable claim leaves
        // nothing behind.
        let buckets = profile.buckets.as_deref().unwrap_or_default();
        let prefixes = buckets
            .iter()
            .map(|bucket| {
                bucket
                    .prefixes
                    .iter()
                    .map(|prefix| prefix.fill(&caller.identity.claims))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|why| {
                        Error::new(
                            ErrorCode::Forbidden,
                            format!("bucket {}: {why}", bucket.name),
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let cloudflare = self.cloudflare().await?;
        let now = now_ms();
        let mut token: Option<MintedToken> = None;
        if let Some(config) = &profile.token {
            let minted = cloudflare
                .mint(&config.policies, caller.token_name(), ttl, now)
                .await?;
            caller
                .audit("token.mint", Some(profile))
                .with("token_id", minted.token_id.as_str())
                .with("expires_on", minted.expires_on.as_str())
                .emit();
            token = Some(minted);
        }

        let expires_on = rfc3339(now + ttl);
        let mut issued = Vec::new();
        for (bucket, prefixes) in buckets.iter().zip(prefixes) {
            match cloudflare.issue_r2(bucket, &prefixes, ttl).await {
                Ok(credentials) => {
                    caller
                        .audit("r2.issued", Some(profile))
                        .with("bucket", bucket.name.as_str())
                        .with("prefixes", prefixes.clone())
                        .with("permission", json!(bucket.permission))
                        .with("expires_on", expires_on.as_str())
                        .emit();
                    issued.push(BucketCredentials {
                        access_key_id: credentials.access_key_id,
                        endpoint: format!(
                            "https://{}.r2.cloudflarestorage.com",
                            self.config.account_id()
                        ),
                        expires_on: datetime(now + ttl),
                        name: bucket.name.clone(),
                        prefixes,
                        secret_access_key: credentials.secret_access_key,
                        session_token: credentials.session_token,
                    });
                }
                Err(err) => {
                    // Half a profile isn't handed out. Credentials already
                    // issued can't be revoked, but nobody has them.
                    if let Some(token) = &token {
                        cloudflare.discard(&token.token_id).await;
                    }
                    return Err(err);
                }
            }
        }

        let expires_at = match &token {
            Some(token) => token.expires_at,
            None => ((now + ttl) / 1000) as i64,
        };
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
            account_id: Some(self.config.account_id().into()),
            buckets: (!issued.is_empty()).then_some(issued),
            expires_at,
            expires_in: (expires_at - (now / 1000) as i64).max(0),
            issued_token_type,
            profile: profile.name.clone(),
            token_id,
            token_type,
        })
    }
}

/// Milliseconds since the epoch, in whole seconds, which is what the tokens
/// API takes.
fn datetime(ms: u64) -> DateTime<Utc> {
    DateTime::from_timestamp((ms / 1000) as i64, 0).unwrap_or_default()
}

/// [`datetime`], as RFC 3339.
fn rfc3339(ms: u64) -> String {
    datetime(ms).to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[async_trait::async_trait]
impl ExchangeServiceApi for ExchangeServiceHandler {
    /// `POST /oauth/token`: an RFC 8693 token exchange. The caller's token,
    /// which the auth layer verified, for what the profile it matches hands
    /// out.
    async fn exchange_token(&self, request: TokenExchangeRequest) -> v1::ExchangeTokenResponse {
        SendFuture::new(async move {
            let policy = self.config.policy();
            let mut caller: Option<Caller> = None;
            let mut named: Option<&ProfileConfig> = None;
            let exchanged = async {
                let exchange = Exchange::read(&request, policy)?;
                let caller = caller.insert(Caller::of(&request.subject_token, policy)?);
                let profile = select_profile(policy, caller, exchange.profile, exchange.audience)?;
                named = Some(profile);
                let ttl = clamp_ttl(exchange.ttl, profile)?;
                if profile.audience == CLOUDFLARE_AUDIENCE {
                    self.cloudflare_credentials(caller, profile, ttl).await
                } else {
                    self.service_token(caller, profile, ttl).await
                }
            };

            match exchanged.await {
                Ok(response) => v1::ExchangeTokenResponse::Ok(response),
                Err(err) => {
                    let audit = match &caller {
                        Some(caller) => caller.audit("token.deny", named),
                        None => Audit::new("token.deny"),
                    };
                    audit
                        .with("profile", request.profile.as_deref())
                        .with("error", err.error.as_str())
                        .with("message", err.message.as_str())
                        .emit();
                    let code = err.error.clone();
                    let err = public(err);
                    match code {
                        ErrorCode::BadRequest => v1::ExchangeTokenResponse::BadRequest(err),
                        ErrorCode::Unauthorized => v1::ExchangeTokenResponse::Unauthorized(err),
                        ErrorCode::Forbidden => v1::ExchangeTokenResponse::Forbidden(err),
                        ErrorCode::UpstreamError => v1::ExchangeTokenResponse::BadGateway(err),
                        // Nothing in an exchange is a 404.
                        ErrorCode::NotFound
                        | ErrorCode::Misconfigured
                        | ErrorCode::InternalError => {
                            v1::ExchangeTokenResponse::InternalServerError(err)
                        }
                    }
                }
            }
        })
        .await
    }

    /// `POST /oauth/revoke`: an RFC 7009 revocation of a token the broker
    /// minted. Holding the token is the proof. Answers `Ok` whether the token
    /// was revoked or already gone.
    async fn revoke_token(&self, request: TokenRevocationRequest) -> v1::RevokeTokenResponse {
        SendFuture::new(async move {
            let revoked = async {
                let cloudflare = self.cloudflare().await?;
                cloudflare
                    .revoke(self.config.cloudflare_api(), &request.token)
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

    /// `GET /.well-known/openid-configuration`: the broker's discovery
    /// document, so services can find its keys and endpoints. It issues tokens
    /// by exchange only, so there's no authorization endpoint: it isn't a
    /// login provider.
    async fn discovery(&self) -> v1::DiscoveryResponse {
        let issuer = &self.config.policy().issuer;
        let url = |path: &str| format!("{issuer}{path}").parse();
        let (Ok(jwks_uri), Ok(token_endpoint), Ok(revocation_endpoint)) = (
            url("/.well-known/jwks"),
            url("/oauth/token"),
            url("/oauth/revoke"),
        ) else {
            let err = misconfigured(format!("issuer {issuer} makes no URLs"));
            return v1::DiscoveryResponse::InternalServerError(public(err));
        };
        v1::DiscoveryResponse::Ok(Discovery {
            issuer: issuer.clone(),
            jwks_uri,
            token_endpoint,
            revocation_endpoint,
            grant_types_supported: vec![TOKEN_EXCHANGE.into()],
            token_endpoint_auth_methods_supported: Some(vec!["none".into()]),
            revocation_endpoint_auth_methods_supported: Some(vec!["none".into()]),
            subject_types_supported: Some(vec!["public".into()]),
            id_token_signing_alg_values_supported: Some(vec![ALGORITHM.into()]),
        })
    }

    /// `GET /.well-known/jwks`: the broker's public key, or none when no
    /// signing key is bound.
    async fn jwks(&self) -> v1::JwksResponse {
        SendFuture::new(async move {
            let keys = async {
                let Some(key) = self.signing_key().await? else {
                    return Ok(Jwks { keys: vec![] });
                };
                let jwk = serde_json::from_value(key.public_jwk())
                    .map_err(|err| misconfigured(format!("the public key: {err}")))?;
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

/// The broker's own exchange parameters, and what the caller asked for.
struct Exchange<'r> {
    /// Cloudflare, or a service the policy issues the broker's own tokens for.
    audience: &'r str,
    profile: Option<&'r str>,
    ttl: Option<&'r str>,
}

impl<'r> Exchange<'r> {
    /// Checks what the generated validation can't: which audience, and what it
    /// can hand out.
    fn read(request: &'r TokenExchangeRequest, policy: &PolicyConfig) -> Result<Self, Error> {
        let bad_request = |message: String| Err(Error::new(ErrorCode::BadRequest, message));
        let audience = request.audience.as_deref().unwrap_or(CLOUDFLARE_AUDIENCE);
        if audience.is_empty() {
            return bad_request("audience must not be empty".into());
        }
        let shown: String = audience.chars().take(200).collect();
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
            return bad_request(format!("{requested} can't be issued for {shown}"));
        }
        if audience != CLOUDFLARE_AUDIENCE
            && !policy.profiles.iter().any(|p| p.audience == audience)
        {
            return bad_request(format!("no profile is for audience {shown}"));
        }
        // `id_token` and `jwt` alike: an OIDC token is a JWT.
        let (SubjectTokenType::UrnIetfParamsOauthTokenTypeIdToken
        | SubjectTokenType::UrnIetfParamsOauthTokenTypeJwt) = request.subject_token_type;
        Ok(Self {
            audience,
            profile: request.profile.as_deref(),
            ttl: request.ttl.as_deref(),
        })
    }
}

/// The caller of an exchange: who the auth layer verified it is, and its
/// provider.
struct Caller<'p> {
    identity: Identity,
    provider: &'p ProviderConfig,
}

impl<'p> Caller<'p> {
    /// The caller presenting `token`, as the auth layer verified it.
    fn of(token: &str, policy: &'p PolicyConfig) -> Result<Self, Error> {
        let identity = layer::identity(token)?;
        let provider = policy
            .providers
            .iter()
            .find(|provider| provider.name == identity.provider)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Unauthorized,
                    "the subject token's provider is gone",
                )
            })?;
        Ok(Self { identity, provider })
    }

    /// The claims its provider's and `profile`'s claim sets match on: what's
    /// worth writing down about a caller, and copying into the broker's own
    /// tokens. Never secret.
    fn matched<'a>(&'a self, profile: Option<&'a ProfileConfig>) -> BTreeSet<&'a str> {
        let profile = profile.map(|p| p.claims.as_slice()).unwrap_or_default();
        self.provider
            .claims
            .iter()
            .chain(profile)
            .flat_map(|set| set.names())
            .collect()
    }

    /// The token's `sub`, if it has one.
    fn subject(&self) -> Option<&str> {
        let sub = self.identity.claims.get("sub").and_then(Value::as_str);
        sub.filter(|sub| !sub.is_empty())
    }

    /// `cf-oidc:<provider>:<sub>`, whatever the issuer, cut to fit.
    fn token_name(&self) -> String {
        let sub = self.subject().unwrap_or("unknown");
        let name = format!("{TOKEN_PREFIX}{}:{sub}", self.provider.name);
        name.chars().take(NAME_MAX).collect()
    }

    /// An audit line about the caller, and the profile it gets.
    fn audit(&self, event: &'static str, profile: Option<&ProfileConfig>) -> Audit {
        Audit::new(event).caller(
            Some(&self.provider.name),
            profile.map(|p| p.name.as_str()),
            Some(&self.identity.claims),
            self.matched(profile),
        )
    }
}

/// Picks the profile to issue with, among those for the caller's provider and
/// `audience` only, or refuses with a `403` that says why. The token must
/// match one of the profile's claim sets; the layer held it to its provider's.
fn select_profile<'a>(
    policy: &'a PolicyConfig,
    caller: &Caller,
    requested: Option<&str>,
    audience: &str,
) -> Result<&'a ProfileConfig, Error> {
    let forbidden = |message: String| Err(Error::new(ErrorCode::Forbidden, message));
    let provider = &caller.provider.name;
    let matches = |p: &ProfileConfig| {
        p.enabled
            && p.claims
                .iter()
                .any(|set| set.matches(&caller.identity.claims))
    };
    let mut profiles = policy
        .profiles
        .iter()
        .filter(|p| p.provider == *provider && p.audience == audience);

    if let Some(requested) = requested {
        if let Some(profile) = profiles.find(|p| p.name == requested)
            && matches(profile)
        {
            return Ok(profile);
        }
        return forbidden(match policy.profiles.iter().find(|p| p.name == requested) {
            None => format!("unknown profile {requested}"),
            Some(named) if named.provider != *provider => {
                format!("profile {requested} isn't for provider {provider}")
            }
            Some(named) if named.audience != audience => {
                format!("profile {requested} isn't for {audience}")
            }
            Some(named) if !named.enabled => format!("profile {requested} is disabled"),
            Some(_) => format!("profile {requested} doesn't match the token"),
        });
    }

    let candidates: Vec<&ProfileConfig> = profiles.filter(|p| matches(p)).collect();
    match candidates.as_slice() {
        [] => forbidden("no profile matches the token".into()),
        [profile] => Ok(profile),
        several => {
            let names: Vec<&str> = several.iter().map(|p| p.name.as_str()).collect();
            forbidden(format!(
                "profiles {} all match the token: name one",
                names.join(", ")
            ))
        }
    }
}

/// The requested TTL, against the profile's, in milliseconds. Requests above
/// `max_ttl` are clamped, not refused.
fn clamp_ttl(requested: Option<&str>, profile: &ProfileConfig) -> Result<u64, Error> {
    let Some(requested) = requested else {
        return Ok(profile.ttl);
    };
    match parse_duration(requested) {
        Some(ttl) if ttl >= MIN_TTL => Ok(ttl.min(profile.max_ttl)),
        _ => Err(Error::new(
            ErrorCode::BadRequest,
            format!("ttl {requested} isn't a duration of at least 1m"),
        )),
    }
}

/// An audit line, in Workers Logs, one JSON object per event. Never token
/// values, R2 secrets or raw JWTs.
#[must_use]
pub struct Audit {
    /// In the order they were added, which is the order they're written in.
    fields: Vec<(String, Value)>,
}

impl Audit {
    pub fn new(event: &'static str) -> Self {
        Self {
            fields: vec![("event".into(), event.into())],
        }
    }

    /// Adds a field, unless it's absent or already there.
    pub fn with(mut self, key: &str, value: impl Into<Value>) -> Self {
        let value = value.into();
        if !value.is_null() && !self.fields.iter().any(|(k, _)| k == key) {
            self.fields.push((key.into(), value));
        }
        self
    }

    /// Adds the provider and profile, and who the caller is: their token's
    /// `sub`, and the claims in `names`, which the policy matches on.
    pub fn caller<'n>(
        mut self,
        provider: Option<&str>,
        profile: Option<&str>,
        claims: Option<&Map<String, Value>>,
        names: impl IntoIterator<Item = &'n str>,
    ) -> Self {
        self = self.with("provider", provider).with("profile", profile);
        let names: BTreeSet<&str> = names.into_iter().collect();
        for key in std::iter::once("sub").chain(names) {
            let value = claims.and_then(|claims| claims.get(key));
            // Only what's worth writing down: a string, number or boolean.
            let scalar = |value: &&Value| match value {
                Value::String(text) => !text.is_empty(),
                Value::Number(_) | Value::Bool(_) => true,
                _ => false,
            };
            if let Some(value) = value.filter(scalar) {
                self = self.with(key, value.clone());
            }
        }
        self
    }

    /// Writes the line: a warning for a refusal.
    pub fn emit(self) {
        let line = serde_json::to_string(&self).unwrap_or_default();
        if self.fields[0].1 == "token.deny" {
            console_warn!("{line}");
        } else {
            console_log!("{line}");
        }
    }
}

impl Serialize for Audit {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.fields.len()))?;
        for (key, value) in &self.fields {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

/// A Cloudflare API failure, reported as a `502`.
fn upstream<E: std::fmt::Debug>(what: &str, err: ApiOpError<E>) -> Error {
    let why = match &err {
        ApiOpError::Api(api) => format!("returned {}", api.status),
        ApiOpError::Transport(err) => err.to_string(),
    };
    Error::new(
        ErrorCode::UpstreamError,
        format!("Cloudflare: {what}: {why}"),
    )
}

fn missing(what: &str) -> Error {
    Error::new(
        ErrorCode::UpstreamError,
        format!("Cloudflare: {what} returned nothing"),
    )
}

/// The status Cloudflare answered with, if it answered.
fn status<E: std::fmt::Debug>(err: &ApiOpError<E>) -> Option<u16> {
    err.api().map(|api| api.status)
}

/// The Cloudflare API, as the Cloudflare token.
struct Cloudflare {
    client: HttpClient,
    account_id: String,
}

/// A token the broker minted.
struct MintedToken {
    token: String,
    token_id: String,
    expires_on: String,
    /// `expires_on`, in seconds since the epoch.
    expires_at: i64,
}

/// R2 temporary credentials for a bucket.
struct R2Credentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
}

/// A permission group: its ID, and what the policies name it by.
struct Group {
    id: String,
    name: String,
    scopes: Vec<String>,
}

impl Cloudflare {
    fn new(api_url: &str, account_id: &str, token: &str) -> Self {
        Self {
            client: HttpClient::new().with_base_url(api_url).with_api_key(token),
            account_id: account_id.into(),
        }
    }

    /// Mints a token. Not retried: a create that failed midway leaves an orphan
    /// the cleanup removes.
    async fn mint(
        &self,
        policies: &[TokenPolicy],
        name: String,
        ttl: u64,
        now_ms: u64,
    ) -> Result<MintedToken, Error> {
        let policies = self.resolve(policies).await?;
        let expires_on = datetime(now_ms + ttl);
        let payload = IamCreatePayload {
            condition: None,
            expires_on: Some(expires_on),
            name,
            not_before: None,
            policies,
        };
        let created = self
            .client
            .account_api_tokens_create_token(&self.account_id, payload)
            .await
            .map_err(|err| upstream("tokens.create", err))?
            .result
            .ok_or_else(|| missing("tokens.create"))?;
        let (Some(token_id), Some(token)) = (created.id, created.value) else {
            return Err(missing("tokens.create"));
        };
        let expires_on = created.expires_on.unwrap_or(expires_on);
        Ok(MintedToken {
            token,
            token_id,
            expires_on: expires_on.to_rfc3339_opts(SecondsFormat::Secs, true),
            expires_at: expires_on.timestamp(),
        })
    }

    /// Deletes a token that was minted but won't be handed out. Best effort:
    /// the cleanup is the fallback.
    async fn discard(&self, token_id: &str) {
        let deleted = self
            .client
            .account_api_tokens_delete_token(&self.account_id, token_id)
            .await;
        let audit = Audit::new("token.revoke").with("token_id", token_id);
        match deleted {
            Ok(_) => audit.with("reason", "discarded").emit(),
            Err(err) => audit
                .with("reason", "discard_failed")
                .with("detail", err.to_string())
                .emit(),
        }
    }

    /// Revokes a token the caller presents. Holding it is the proof of
    /// authorization. Returns the deleted token's ID, or `None` if it was
    /// already gone.
    async fn revoke(&self, api_url: &str, presented: &str) -> Result<Option<String>, Error> {
        let presenter = HttpClient::new()
            .with_base_url(api_url)
            .with_api_key(presented);
        // The API's answer for a token it doesn't recognize: invalid, expired,
        // deleted, another account's.
        let id = match presenter
            .account_api_tokens_verify_token(&self.account_id)
            .await
        {
            Ok(verified) => match verified.result {
                Some(result) => result.id,
                None => return Ok(None),
            },
            Err(err) if matches!(status(&err), Some(400 | 401 | 403 | 404)) => return Ok(None),
            Err(err) => return Err(upstream("tokens.verify", err)),
        };

        let name = match self
            .client
            .account_api_tokens_token_details(&self.account_id, &id)
            .await
        {
            Ok(details) => details.result.and_then(|token| token.name),
            Err(err) if status(&err) == Some(404) => return Ok(None),
            Err(err) => return Err(upstream("tokens.get", err)),
        };
        if !name.is_some_and(|name| name.starts_with(TOKEN_PREFIX)) {
            return Err(Error::new(
                ErrorCode::Forbidden,
                format!("token {id} wasn't minted by the broker, so it isn't revoked here"),
            ));
        }

        match self
            .client
            .account_api_tokens_delete_token(&self.account_id, &id)
            .await
        {
            Ok(_) => Ok(Some(id)),
            Err(err) if status(&err) == Some(404) => Ok(Some(id)),
            Err(err) => Err(upstream("tokens.delete", err)),
        }
    }

    /// Deletes expired `cf-oidc:` tokens. Returns how many were removed.
    async fn cleanup(&self, now_ms: u64) -> Result<usize, Error> {
        // Collect first: deleting while paginating would shift later pages and
        // skip tokens.
        let mut expired = Vec::new();
        for page in 1.. {
            let tokens = self
                .client
                .account_api_tokens_list_tokens(
                    &self.account_id,
                    Some(page as f64),
                    Some(PAGE_SIZE as f64),
                    None,
                    Some(true),
                )
                .await
                .map_err(|err| upstream("tokens.list", err))?
                .result
                .unwrap_or_default();
            let count = tokens.len();
            for token in tokens {
                let (Some(id), Some(name), Some(expires_on)) =
                    (token.id, token.name, token.expires_on)
                else {
                    continue;
                };
                let lapsed = token.status == Some(cloudflare::v4::IamTokenStatus::Expired)
                    || expires_on.timestamp_millis() as u64 <= now_ms;
                if name.starts_with(TOKEN_PREFIX) && lapsed {
                    expired.push((id, name, expires_on));
                }
            }
            if count < PAGE_SIZE {
                break;
            }
        }

        let mut deleted = 0;
        for (id, name, expires_on) in expired {
            match self
                .client
                .account_api_tokens_delete_token(&self.account_id, &id)
                .await
            {
                Ok(_) => {
                    deleted += 1;
                    let expires_on = expires_on.to_rfc3339_opts(SecondsFormat::Secs, true);
                    Audit::new("token.cleanup")
                        .with("token_id", id)
                        .with("name", name)
                        .with("expires_on", expires_on)
                        .emit();
                }
                Err(err) if status(&err) == Some(404) => {}
                Err(err) => return Err(upstream("tokens.delete", err)),
            }
        }
        Ok(deleted)
    }

    /// Creates temporary S3 credentials for a bucket, limited to `prefixes`
    /// (filled in), with the Cloudflare token as their parent.
    async fn issue_r2(
        &self,
        bucket: &BucketConfig,
        prefixes: &[String],
        ttl: u64,
    ) -> Result<R2Credentials, Error> {
        // The token's ID is its R2 access key ID.
        let parent_access_key_id = self
            .client
            .account_api_tokens_verify_token(&self.account_id)
            .await
            .map_err(|err| upstream("tokens.verify", err))?
            .result
            .ok_or_else(|| missing("tokens.verify"))?
            .id;
        let request = R2TempAccessCredsRequest {
            bucket: bucket.name.clone(),
            objects: None,
            parent_access_key_id,
            permission: match bucket.permission {
                BucketPermission::ObjectReadWrite => {
                    R2TempAccessCredsRequestPermission::ObjectReadWrite
                }
                BucketPermission::ObjectReadOnly => {
                    R2TempAccessCredsRequestPermission::ObjectReadOnly
                }
            },
            prefixes: (!prefixes.is_empty()).then(|| prefixes.to_vec()),
            ttl_seconds: (ttl / 1000) as f64,
        };
        let creds = self
            .client
            .r2_create_temp_access_credentials(&self.account_id, request)
            .await
            .map_err(|err| upstream("temporaryCredentials.create", err))?
            .result;
        let (Some(access_key_id), Some(secret_access_key), Some(session_token)) = (
            creds.access_key_id,
            creds.secret_access_key,
            creds.session_token,
        ) else {
            return Err(missing("temporaryCredentials.create"));
        };
        Ok(R2Credentials {
            access_key_id,
            secret_access_key,
            session_token,
        })
    }

    /// Resolves permission-group names to IDs; resources are already in the
    /// API's shape. An unknown name is a configuration error, never a silent
    /// drop.
    async fn resolve(
        &self,
        policies: &[TokenPolicy],
    ) -> Result<Vec<IamPolicyWithPermissionGroupsAndResources>, Error> {
        let groups: Vec<Group> = self
            .client
            .account_api_tokens_list_permission_groups(&self.account_id, None::<&str>, None::<&str>)
            .await
            .map_err(|err| upstream("permissionGroups.list", err))?
            .result
            .unwrap_or_default()
            .into_iter()
            .filter_map(|group| {
                Some(Group {
                    id: group.id?,
                    name: group.name?,
                    scopes: group.scopes.unwrap_or_default(),
                })
            })
            .collect();
        policies
            .iter()
            .map(|policy| {
                let scope = scope_for(policy);
                let permission_groups = policy
                    .permissions
                    .iter()
                    .map(|name| {
                        pick_group(&groups, name, scope).map(|group| IamPermissionGroup {
                            id: group.id.clone(),
                            meta: None,
                            name: None,
                        })
                    })
                    .collect::<Result<_, _>>()?;
                Ok(IamPolicyWithPermissionGroupsAndResources {
                    effect: match policy.effect {
                        Effect::Allow => IamEffect::Allow,
                        Effect::Deny => IamEffect::Deny,
                    },
                    id: None,
                    permission_groups,
                    resources: resources(policy),
                })
            })
            .collect()
    }
}

/// A policy's resources in the API's shape: all `"*"`-style values, or all
/// nested maps, as the policy's checks made sure.
fn resources(policy: &TokenPolicy) -> IamResources {
    let flat: Option<_> = policy
        .resources
        .iter()
        .map(|(key, value)| match value {
            ResourceValue::Scope(scope) => Some((key.clone(), scope.clone())),
            ResourceValue::Nested(_) => None,
        })
        .collect();
    if let Some(additional_properties) = flat {
        return IamResources::IamResourcesTypeObjectString(IamResourcesTypeObjectString {
            additional_properties,
        });
    }
    let additional_properties = policy
        .resources
        .iter()
        .filter_map(|(key, value)| match value {
            ResourceValue::Nested(nested) => Some((
                key.clone(),
                IamResourcesTypeObjectNestedAdditionalProperty {
                    additional_properties: nested.clone(),
                },
            )),
            ResourceValue::Scope(_) => None,
        })
        .collect();
    IamResources::IamResourcesTypeObjectNested(IamResourcesTypeObjectNested {
        additional_properties,
    })
}

/// The scope a permission group needs for these resources, used to pick
/// between same-named groups.
fn scope_for(policy: &TokenPolicy) -> &'static str {
    let zone = format!("{ZONE_SCOPE}.");
    let keys = || policy.resources.keys();
    if keys().any(|k| k.starts_with(R2_SCOPE)) {
        return R2_SCOPE;
    }
    if keys().any(|k| k.starts_with(&zone)) {
        return ZONE_SCOPE;
    }
    // Nested form: `account.<id>: { "account.zone.*": "*" }` grants every zone
    // in the account.
    let nested = policy.resources.values().any(|value| match value {
        ResourceValue::Nested(nested) => nested.keys().any(|k| k.starts_with(&zone)),
        ResourceValue::Scope(_) => false,
    });
    if nested { ZONE_SCOPE } else { ACCOUNT_SCOPE }
}

fn pick_group<'g>(groups: &'g [Group], name: &str, scope: &str) -> Result<&'g Group, Error> {
    let named: Vec<&Group> = groups.iter().filter(|g| g.name == name).collect();
    if let [group] = named.as_slice() {
        return Ok(group);
    }
    let scoped: Vec<&Group> = named
        .iter()
        .copied()
        .filter(|g| g.scopes.iter().any(|s| s == scope))
        .collect();
    if let [group] = scoped.as_slice() {
        return Ok(group);
    }
    Err(misconfigured(if named.is_empty() {
        format!("no permission group is named {name}")
    } else {
        format!("several permission groups are named {name}, at no one scope of the resources")
    }))
}

/// The RSA key the broker signs its own tokens with, imported into WebCrypto,
/// so it never leaves the runtime's crypto.
struct SigningKey {
    key: CryptoKey,
    /// The public key, base64url.
    n: String,
    e: String,
    /// The public key's RFC 7638 thumbprint, so a new key gets a new `kid`
    /// without any configuration.
    kid: String,
}

/// A token for another service, signed.
struct Issued {
    jwt: String,
    jti: String,
    /// Seconds since the epoch.
    expires_at: u64,
}

fn webcrypto(err: JsValue) -> Error {
    let why = err
        .dyn_ref::<js_sys::Error>()
        .map(|err| String::from(err.message()))
        .unwrap_or_else(|| format!("{err:?}"));
    Error::new(ErrorCode::InternalError, format!("WebCrypto: {why}"))
}

fn subtle() -> Result<SubtleCrypto, Error> {
    let scope = js_sys::global().unchecked_into::<WorkerGlobalScope>();
    Ok(scope.crypto().map_err(webcrypto)?.subtle())
}

async fn promised(promise: Result<js_sys::Promise, JsValue>) -> Result<JsValue, Error> {
    JsFuture::from(promise.map_err(webcrypto)?)
        .await
        .map_err(webcrypto)
}

fn rs256() -> Result<js_sys::Object, Error> {
    js_sys::JSON::parse(r#"{"name":"RSASSA-PKCS1-v1_5","hash":"SHA-256"}"#)
        .map(JsCast::unchecked_into)
        .map_err(webcrypto)
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

impl SigningKey {
    /// The RSA key in `pem`, a PKCS#8 PEM.
    async fn import(pem: &str) -> Result<Self, Error> {
        let unusable = |why: &str| misconfigured(format!("the signing key: {why}"));
        let not_rsa = || unusable("not an RSA private key in PKCS#8 PEM");
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
            return Err(unusable(&format!(
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

    /// The public half, as the JWKS publishes it.
    fn public_jwk(&self) -> Value {
        json!({ "kty": "RSA", "n": self.n, "e": self.e, "kid": self.kid, "alg": ALGORITHM, "use": "sig" })
    }

    /// Signs a token for the service `profile` is for, issued at `now`
    /// (seconds since the epoch).
    async fn issue(
        &self,
        issuer: &str,
        caller: &Caller<'_>,
        profile: &ProfileConfig,
        ttl: u64,
        now: u64,
    ) -> Result<Issued, Error> {
        let scope = js_sys::global().unchecked_into::<WorkerGlobalScope>();
        let jti = scope.crypto().map_err(webcrypto)?.random_uuid();
        let (claims, expires_at) = payload(issuer, caller, profile, ttl, &jti, now)?;
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
        Ok(Issued {
            jwt: format!("{signing_input}.{signature}"),
            jti,
            expires_at,
        })
    }
}

/// The claims of a token for another service, issued at `now` (seconds since
/// the epoch), and when it expires. It never outlives the token the caller
/// presented.
///
/// It has the claims the policy matched on, under the issuer's names, so the
/// service can match on the same ones. Nothing else: an issuer's other claims,
/// such as an email, stay behind.
fn payload(
    issuer: &str,
    caller: &Caller,
    profile: &ProfileConfig,
    ttl: u64,
    jti: &str,
    now: u64,
) -> Result<(Map<String, Value>, u64), Error> {
    let claims = &caller.identity.claims;
    let not_after = claims
        .get("exp")
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX);
    let expires_at = (now + ttl / 1000).min(not_after);
    // The caller's token was accepted with clock tolerance; a token that can't
    // live at all isn't issued.
    if expires_at <= now {
        return Err(Error::new(
            ErrorCode::Unauthorized,
            "the subject token has expired",
        ));
    }

    let mut payload = Map::new();
    for name in caller.matched(Some(profile)) {
        if let Some(value) = claims.get(name).filter(|value| copyable(value)) {
            payload.insert(name.into(), value.clone());
        }
    }
    let subject = match caller.subject() {
        Some(sub) => sub.to_string(),
        None => format!("{}:unknown", caller.provider.name),
    };
    for (name, value) in [
        ("provider", json!(caller.provider.name)),
        ("profile", json!(profile.name)),
        ("iss", json!(issuer)),
        ("aud", json!(profile.audience)),
        ("sub", json!(subject)),
        ("iat", json!(now)),
        ("nbf", json!(now)),
        ("exp", json!(expires_at)),
        ("jti", json!(jti)),
    ] {
        payload.insert(name.into(), value);
    }
    Ok((payload, expires_at))
}

/// Whether a claim's value is one to copy: a string, number or boolean, or a
/// list of them, as claim sets match on.
fn copyable(value: &Value) -> bool {
    match value {
        Value::String(text) => !text.is_empty(),
        Value::Number(_) | Value::Bool(_) => true,
        Value::Array(values) => values.iter().all(|v| !v.is_array() && copyable(v)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use cf_oidc_exchange_sdk::v1::TokenExchangeRequestGrantType;

    use super::*;
    use crate::service::config::tests::{CACHE, NOW, claims, parse, policy};

    fn caller<'p>(policy: &'p PolicyConfig, claims: Map<String, Value>) -> Caller<'p> {
        Caller {
            identity: Identity {
                provider: "github".into(),
                claims,
            },
            provider: &policy.providers[0],
        }
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

    /// Why the exchange is refused before a profile is picked, if it is.
    fn refusal(request: &TokenExchangeRequest) -> Option<String> {
        Exchange::read(request, &parse(&policy()))
            .err()
            .map(|err| err.message)
    }

    #[test]
    fn defaults_to_the_cloudflare_audience() {
        let policy = parse(&policy());
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
        assert_eq!(refusal(&request(Some(CACHE), None)), None);
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
        assert!(refusal(&request(Some(CACHE), r2)).is_some());
        assert_eq!(refusal(&request(Some(CACHE), jwt)), None);
    }

    /// The profile a caller with `claims` gets, or why not.
    fn selected(
        policy: &Value,
        claims: Map<String, Value>,
        requested: Option<&str>,
        audience: &str,
    ) -> Result<String, String> {
        let policy = parse(policy);
        let caller = caller(&policy, claims);
        select_profile(&policy, &caller, requested, audience)
            .map(|profile| profile.name.clone())
            .map_err(|err| err.message)
    }

    fn ok(name: &str) -> Result<String, String> {
        Ok(name.to_string())
    }

    fn err(message: &str) -> Result<String, String> {
        Err(message.to_string())
    }

    #[test]
    fn selects_the_one_matching_profile_or_says_why_not() {
        let policy = policy();
        let main = claims();
        assert_eq!(
            selected(&policy, main.clone(), None, CLOUDFLARE_AUDIENCE),
            ok("deploy")
        );
        assert_eq!(selected(&policy, main.clone(), None, CACHE), ok("nix-push"));

        let mut dev = claims();
        dev.insert("ref".into(), "refs/heads/dev".into());
        let cases = [
            (
                dev.clone(),
                None,
                CLOUDFLARE_AUDIENCE,
                "no profile matches the token",
            ),
            (
                dev,
                Some("deploy"),
                CLOUDFLARE_AUDIENCE,
                "profile deploy doesn't match the token",
            ),
            (
                main.clone(),
                Some("nope"),
                CLOUDFLARE_AUDIENCE,
                "unknown profile nope",
            ),
            (
                main,
                Some("deploy"),
                CACHE,
                "profile deploy isn't for https://cf-nix-cache.example.com",
            ),
        ];
        for (claims, requested, audience, expected) in cases {
            assert_eq!(
                selected(&policy, claims, requested, audience),
                err(expected)
            );
        }
    }

    #[test]
    fn refuses_when_several_profiles_match_and_none_is_named() {
        let mut policy = policy();
        let mut again = policy["profiles"][0].clone();
        again["name"] = json!("deploy-again");
        policy["profiles"].as_array_mut().unwrap().push(again);
        assert_eq!(
            selected(&policy, claims(), None, CLOUDFLARE_AUDIENCE),
            err("profiles deploy, deploy-again all match the token: name one")
        );
        assert_eq!(
            selected(&policy, claims(), Some("deploy-again"), CLOUDFLARE_AUDIENCE),
            ok("deploy-again")
        );
    }

    #[test]
    fn never_matches_a_disabled_profile_even_by_name() {
        let mut policy = policy();
        policy["profiles"][0]["enabled"] = json!(false);
        assert_eq!(
            selected(&policy, claims(), Some("deploy"), CLOUDFLARE_AUDIENCE),
            err("profile deploy is disabled")
        );
        assert_eq!(
            selected(&policy, claims(), None, CLOUDFLARE_AUDIENCE),
            err("no profile matches the token")
        );
    }

    #[test]
    fn never_gives_one_providers_token_anothers_profile() {
        let mut policy = policy();
        policy["providers"].as_array_mut().unwrap().push(json!({ "name": "gitlab", "issuer": "https://gitlab.com", "audience": "https://cf-oidc-exchange.example.com", "claims": [{ "ref": "refs/heads/main" }] }));
        policy["profiles"][0]["provider"] = json!("gitlab");
        policy["profiles"][1]["provider"] = json!("github");
        assert_eq!(
            selected(&policy, claims(), Some("deploy"), CLOUDFLARE_AUDIENCE),
            err("profile deploy isn't for provider github")
        );
    }

    #[test]
    fn clamps_the_ttl_to_max_ttl_and_rejects_nonsense() {
        let policy = parse(&policy());
        let profile = &policy.profiles[0];
        assert_eq!(clamp_ttl(None, profile).ok(), Some(15 * 60_000));
        assert_eq!(clamp_ttl(Some("5m"), profile).ok(), Some(5 * 60_000));
        assert_eq!(clamp_ttl(Some("12h"), profile).ok(), Some(60 * 60_000));
        for ttl in ["30s", "forever", "600"] {
            assert!(clamp_ttl(Some(ttl), profile).is_err(), "{ttl}");
        }
    }

    #[test]
    fn names_tokens_after_the_provider_and_the_subject() {
        let policy = parse(&policy());
        assert_eq!(
            caller(&policy, claims()).token_name(),
            "cf-oidc:github:repo:example-org/app:ref:refs/heads/main"
        );
        assert_eq!(
            caller(&policy, Map::new()).token_name(),
            "cf-oidc:github:unknown"
        );

        let mut long = claims();
        long.insert("sub".into(), "x".repeat(200).into());
        let name = caller(&policy, long).token_name();
        assert_eq!(name.chars().count(), 120);
        assert!(name.starts_with("cf-oidc:github:xxx"));
    }

    #[test]
    fn audits_who_without_anything_else() {
        let policy = parse(&policy());
        let mut claims = claims();
        claims.insert("email".into(), "someone@example.com".into());
        let audit = caller(&policy, claims)
            .audit("token.mint", Some(&policy.profiles[0]))
            .with("token_id", "tok-1")
            .with("detail", None::<String>)
            .with("token_id", "tok-2");
        assert_eq!(
            serde_json::to_value(&audit).unwrap(),
            json!({
                "event": "token.mint",
                "provider": "github",
                "profile": "deploy",
                "sub": "repo:example-org/app:ref:refs/heads/main",
                "ref": "refs/heads/main",
                "repository": "example-org/app",
                "repository_owner_id": "100000001",
                "token_id": "tok-1",
            })
        );
    }

    #[test]
    fn copies_only_the_claims_the_policy_matches_on() {
        let policy = parse(&policy());
        let mut matched = claims();
        matched.insert("email".into(), "someone@example.com".into());
        let (issued, expires_at) = payload(
            "https://cf-oidc-exchange.example.com",
            &caller(&policy, matched),
            &policy.profiles[1],
            15 * 60_000,
            "jti-1",
            NOW,
        )
        .unwrap();
        assert_eq!(expires_at, NOW + 300, "never past the caller's own token");
        assert_eq!(
            Value::Object(issued),
            json!({
                "ref": "refs/heads/main",
                "repository_owner_id": "100000001",
                "provider": "github",
                "profile": "nix-push",
                "iss": "https://cf-oidc-exchange.example.com",
                "aud": CACHE,
                "sub": "repo:example-org/app:ref:refs/heads/main",
                "iat": NOW,
                "nbf": NOW,
                "exp": NOW + 300,
                "jti": "jti-1",
            })
        );

        let mut expired = claims();
        expired.insert("exp".into(), json!(NOW));
        let err = payload(
            "https://x.example.com",
            &caller(&policy, expired),
            &policy.profiles[1],
            60_000,
            "j",
            NOW,
        )
        .unwrap_err();
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

    #[test]
    fn writes_rfc3339_without_fractions() {
        assert_eq!(rfc3339(1_800_000_000_123), "2027-01-15T08:00:00Z");
    }

    fn token_policy(resources: Value) -> TokenPolicy {
        serde_json::from_value(json!({ "permissions": ["x"], "resources": resources })).unwrap()
    }

    #[test]
    fn picks_the_scope_from_the_resources() {
        let zone = "com.cloudflare.api.account.zone.fedcba9876543210fedcba9876543210";
        let account = "com.cloudflare.api.account.0123456789abcdef0123456789abcdef";
        assert_eq!(scope_for(&token_policy(json!({ zone: "*" }))), ZONE_SCOPE);
        assert_eq!(
            scope_for(&token_policy(json!({ account: "*" }))),
            ACCOUNT_SCOPE
        );
        assert_eq!(
            scope_for(&token_policy(
                json!({ account: { "com.cloudflare.api.account.zone.*": "*" } })
            )),
            ZONE_SCOPE
        );
        assert_eq!(
            scope_for(&token_policy(
                json!({ "com.cloudflare.edge.r2.bucket.x_default_y": "*" })
            )),
            R2_SCOPE
        );
    }

    #[test]
    fn picks_permission_groups_by_name_then_scope() {
        let group = |id: &str, name: &str, scope: &str| Group {
            id: id.into(),
            name: name.into(),
            scopes: vec![scope.into()],
        };
        let groups = [
            group("pg-dns-write", "DNS Write", ZONE_SCOPE),
            group("pg-lb-write-account", "Load Balancers Write", ACCOUNT_SCOPE),
            group("pg-lb-write-zone", "Load Balancers Write", ZONE_SCOPE),
        ];
        let pick = |name, scope| {
            pick_group(&groups, name, scope)
                .map(|g| g.id.as_str())
                .map_err(|err| err.message)
        };
        assert_eq!(pick("DNS Write", ACCOUNT_SCOPE), Ok("pg-dns-write"));
        assert_eq!(
            pick("Load Balancers Write", ZONE_SCOPE),
            Ok("pg-lb-write-zone")
        );
        assert_eq!(
            pick("Load Balancers Write", ACCOUNT_SCOPE),
            Ok("pg-lb-write-account")
        );
        assert_eq!(
            pick("Load Balancers Write", R2_SCOPE),
            Err("several permission groups are named Load Balancers Write, at no one scope of the resources".into())
        );
        assert_eq!(
            pick("Nope", ACCOUNT_SCOPE),
            Err("no permission group is named Nope".into())
        );
    }

    #[test]
    fn passes_resources_through_in_either_form() {
        let json = |resources: Value| serde_json::to_value(resources_of(resources)).unwrap();
        fn resources_of(value: Value) -> IamResources {
            resources(&token_policy(value))
        }
        let flat = json!({ "com.cloudflare.api.account.zone.z": "*" });
        let nested =
            json!({ "com.cloudflare.api.account.a": { "com.cloudflare.api.account.zone.*": "*" } });
        assert_eq!(json(flat.clone()), flat);
        assert_eq!(json(nested.clone()), nested);
    }
}
