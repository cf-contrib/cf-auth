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

use std::sync::Arc;

use cf_oidc_core::{ALGORITHM, Identity, SigningKey};
use cf_oidc_exchange_sdk::v1::{
    self, BucketCredentials, Discovery, Error, ErrorCode, ExchangeServiceApi, IssuedTokenType,
    Jwks, TokenExchangeRequest, TokenExchangeRequestSubjectTokenType as SubjectTokenType,
    TokenExchangeResponse, TokenExchangeResponseTokenType as TokenType, TokenRevocationRequest,
};
use chrono::{DateTime, Utc};
use cloudflare::v4::{
    ApiOpError, HttpClient, IamCreatePayload, IamEffect, IamPermissionGroup,
    IamPolicyWithPermissionGroupsAndResources, R2TempAccessCredsRequest,
    R2TempAccessCredsRequestPermission,
};
use serde_json::{Map, Value, json};
use tracing::{error, info, warn};
use worker::{Date, send::SendFuture};

use super::config::{
    BucketConfig, BucketPermission, CLOUDFLARE_AUDIENCE, Config, Effect, PolicyConfig,
    ProfileConfig, ProviderConfig, TokenPolicyConfig,
};

/// The token exchange grant, RFC 8693's.
const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// Every minted token's name starts with this. Revocation and the cleanup
/// never touch anything else.
const TOKEN_PREFIX: &str = "cf-oidc:";

/// The longest token name Cloudflare takes.
const NAME_MAX: usize = 120;

/// Tokens listed per page by the cleanup.
const PAGE_SIZE: usize = 50;

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
            .map_err(|err| Error::new(ErrorCode::Misconfigured, err.to_string()))?;
        Ok(Cloudflare::new(
            self.config.cloudflare_url(),
            self.config.account_id(),
            &token,
        ))
    }

    /// The signing key, read now, or `None` if none is bound.
    async fn signing_key(&self) -> Result<Option<SigningKey>, Error> {
        match self
            .config
            .signing_key()
            .await
            .map_err(|err| Error::new(ErrorCode::Misconfigured, err.to_string()))?
        {
            Some(pem) => SigningKey::import(&pem).await.map(Some).map_err(|err| {
                Error::new(ErrorCode::Misconfigured, format!("the signing key: {err}"))
            }),
            None => Ok(None),
        }
    }

    /// Deletes expired `cf-oidc:` tokens, for the hourly cron. Returns how many.
    pub async fn cleanup(&self) -> Result<usize, Error> {
        self.cloudflare()
            .await?
            .cleanup(Date::now().as_millis())
            .await
    }

    /// The broker's own token, for a profile with another service's `audience`.
    async fn service_token(
        &self,
        caller: &Caller<'_>,
        profile: &ProfileConfig,
        ttl: u64,
    ) -> Result<TokenExchangeResponse, Error> {
        let Some(key) = self.signing_key().await? else {
            return Err(Error::new(
                ErrorCode::Misconfigured,
                format!(
                    "a token for {} needs a signing key, and none is bound",
                    profile.audience
                ),
            ));
        };
        let now = Date::now().as_millis() / 1000;
        let (claims, expires_at) =
            payload(&self.config.policy().issuer, caller, profile, ttl, now)?;
        let signed = key.sign(claims).await.map_err(|err| {
            Error::new(ErrorCode::InternalError, format!("signing a token: {err}"))
        })?;
        info!(
            event = "token.issue",
            provider = %caller.provider.name,
            profile = %profile.name,
            sub = caller.identity.subject(),
            claims = %serde_json::Value::Object(caller.matched(Some(profile))),
            audience = %profile.audience,
            jti = %signed.jti,
            expires_at,
        );
        Ok(TokenExchangeResponse {
            access_token: Some(signed.jwt),
            account_id: None,
            buckets: None,
            expires_at: expires_at as i64,
            expires_in: expires_at.saturating_sub(now) as i64,
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
        let now = Date::now().as_millis() / 1000;
        // In whole seconds, which is what the tokens API takes.
        let expires_on = DateTime::from_timestamp((now + ttl / 1000) as i64, 0).unwrap_or_default();
        let mut token: Option<ApiToken> = None;
        if let Some(config) = &profile.token {
            let minted = cloudflare
                .mint(&config.policies, caller.token_name(), expires_on)
                .await?;
            info!(
                event = "token.mint",
                provider = %caller.provider.name,
                profile = %profile.name,
                sub = caller.identity.subject(),
                claims = %serde_json::Value::Object(caller.matched(Some(profile))),
                token_id = %minted.token_id,
                expires_at = minted.expires_on.timestamp(),
            );
            token = Some(minted);
        }

        let mut issued = Vec::new();
        for (bucket, prefixes) in buckets.iter().zip(prefixes) {
            match cloudflare.issue_r2(bucket, &prefixes, ttl).await {
                Ok(credentials) => {
                    info!(
                        event = "r2.issued",
                        provider = %caller.provider.name,
                        profile = %profile.name,
                        sub = caller.identity.subject(),
                        claims = %serde_json::Value::Object(caller.matched(Some(profile))),
                        bucket = %bucket.name,
                        prefixes = ?prefixes,
                        permission = bucket.permission.as_str(),
                        expires_at = expires_on.timestamp(),
                    );
                    issued.push(BucketCredentials {
                        access_key_id: credentials.access_key_id,
                        endpoint: format!(
                            "https://{}.r2.cloudflarestorage.com",
                            self.config.account_id()
                        ),
                        expires_on,
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

        let expires_at = token
            .as_ref()
            .map_or(expires_on, |t| t.expires_on)
            .timestamp();
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
            expires_in: (expires_at - now as i64).max(0),
            issued_token_type,
            profile: profile.name.clone(),
            token_id,
            token_type,
        })
    }
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
                // What the generated validation can't check: the audience,
                // and whether what's asked for can be issued for it.
                // Cloudflare's gets Cloudflare credentials; any other, a
                // JWT.
                let bad_request = |message: String| Err(Error::new(ErrorCode::BadRequest, message));
                let audience = request.audience.as_deref().unwrap_or(CLOUDFLARE_AUDIENCE);
                if audience.is_empty() {
                    return bad_request("audience must not be empty".into());
                }
                let shown: String = audience.chars().take(200).collect();
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

                let caller = caller.insert(Caller::of(&request.subject_token, policy)?);
                let profile = policy
                    .profile_for(
                        &caller.provider.name,
                        &caller.identity.claims,
                        request.profile.as_deref(),
                        audience,
                    )
                    .map_err(|why| Error::new(ErrorCode::Forbidden, why))?;
                named = Some(profile);
                let ttl = profile
                    .ttl_for(request.ttl.as_deref())
                    .map_err(|why| Error::new(ErrorCode::BadRequest, why))?;
                if profile.audience == CLOUDFLARE_AUDIENCE {
                    self.cloudflare_credentials(caller, profile, ttl).await
                } else {
                    self.service_token(caller, profile, ttl).await
                }
            };

            match exchanged.await {
                Ok(response) => v1::ExchangeTokenResponse::Ok(response),
                Err(err) => {
                    let profile = named
                        .map(|p| p.name.as_str())
                        .or(request.profile.as_deref());
                    warn!(
                        event = "token.deny",
                        provider = caller.as_ref().map(|c| c.provider.name.as_str()),
                        profile,
                        sub = caller.as_ref().and_then(|c| c.identity.subject()),
                        claims = caller.as_ref().map(|c| display(serde_json::Value::Object(c.matched(named)))),
                        error = err.error.as_str(),
                        message = %err.message,
                    );
                    // A caller's mistake says what it was. A fault of the
                    // broker's doesn't: the log line does.
                    match err.error {
                        ErrorCode::BadRequest => v1::ExchangeTokenResponse::BadRequest(err),
                        ErrorCode::Unauthorized => v1::ExchangeTokenResponse::Unauthorized(err),
                        ErrorCode::Forbidden => v1::ExchangeTokenResponse::Forbidden(err),
                        ErrorCode::UpstreamError => {
                            v1::ExchangeTokenResponse::BadGateway(Error::new(
                                err.error,
                                "a service the broker relies on failed; its logs say which",
                            ))
                        }
                        // Nothing in an exchange is a 404.
                        ErrorCode::NotFound
                        | ErrorCode::Misconfigured
                        | ErrorCode::InternalError => {
                            v1::ExchangeTokenResponse::InternalServerError(Error::new(
                                err.error,
                                "the broker failed; its logs say why",
                            ))
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
                    .revoke(self.config.cloudflare_url(), &request.token)
                    .await
            };
            match revoked.await {
                Ok(Some(token_id)) => {
                    info!(event = "token.revoke", token_id);
                    v1::RevokeTokenResponse::Ok
                }
                Ok(None) => {
                    info!(event = "token.revoke", reason = "already_gone");
                    v1::RevokeTokenResponse::Ok
                }
                Err(err) => {
                    warn!(
                        event = "token.revoke",
                        error = err.error.as_str(),
                        message = %err.message,
                    );
                    // As for an exchange: the broker's faults say why only in
                    // the log line.
                    match err.error {
                        ErrorCode::BadRequest => v1::RevokeTokenResponse::BadRequest(err),
                        ErrorCode::Forbidden => v1::RevokeTokenResponse::Forbidden(err),
                        ErrorCode::UpstreamError => {
                            v1::RevokeTokenResponse::BadGateway(Error::new(
                                err.error,
                                "a service the broker relies on failed; its logs say which",
                            ))
                        }
                        _ => v1::RevokeTokenResponse::InternalServerError(Error::new(
                            err.error,
                            "the broker failed; its logs say why",
                        )),
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
            error!(%issuer, "the issuer makes no URLs");
            return v1::DiscoveryResponse::InternalServerError(Error::new(
                ErrorCode::Misconfigured,
                "the broker is misconfigured; its logs say why",
            ));
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
                let jwk = serde_json::from_value(key.public_jwk()).map_err(|err| {
                    Error::new(ErrorCode::Misconfigured, format!("the public key: {err}"))
                })?;
                Ok::<_, Error>(Jwks { keys: vec![jwk] })
            };
            match keys.await {
                Ok(jwks) => v1::JwksResponse::Ok(jwks),
                Err(err) => {
                    error!(error = err.error.as_str(), message = %err.message);
                    v1::JwksResponse::InternalServerError(Error::new(
                        err.error,
                        "the broker failed; its logs say why",
                    ))
                }
            }
        })
        .await
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
        let unauthorized = |why: &str| Error::new(ErrorCode::Unauthorized, why);
        let identity = cf_oidc_core::verified(token)
            .ok_or_else(|| unauthorized("the subject token wasn't verified"))?;
        let provider = policy
            .provider_for(&identity.claims)
            .map_err(|why| unauthorized(&why))?;
        Ok(Self { identity, provider })
    }

    /// The claims its provider's and `profile`'s claim sets match on, with
    /// their values: what's worth writing down about a caller, and copying
    /// into the broker's own tokens. Never secret.
    fn matched(&self, profile: Option<&ProfileConfig>) -> Map<String, Value> {
        let profile = profile.map(|p| p.claims.as_slice()).unwrap_or_default();
        self.provider
            .claims
            .iter()
            .chain(profile)
            .flat_map(|set| set.names())
            .filter_map(|name| {
                let value = self.identity.claims.get(name).filter(|v| copyable(v))?;
                Some((name.to_string(), value.clone()))
            })
            .collect()
    }

    /// `cf-oidc:<provider>:<sub>`, whatever the issuer, cut to fit.
    fn token_name(&self) -> String {
        let sub = self.identity.subject().unwrap_or("unknown");
        let name = format!("{TOKEN_PREFIX}{}:{sub}", self.provider.name);
        name.chars().take(NAME_MAX).collect()
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
struct ApiToken {
    token: String,
    token_id: String,
    expires_on: DateTime<Utc>,
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
        policies: &[TokenPolicyConfig],
        name: String,
        expires_on: DateTime<Utc>,
    ) -> Result<ApiToken, Error> {
        let policies = self.resolve(policies).await?;
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
        Ok(ApiToken {
            token,
            token_id,
            expires_on: created.expires_on.unwrap_or(expires_on),
        })
    }

    /// Deletes a token that was minted but won't be handed out. Best effort:
    /// the cleanup is the fallback.
    async fn discard(&self, token_id: &str) {
        let deleted = self
            .client
            .account_api_tokens_delete_token(&self.account_id, token_id)
            .await;
        match deleted {
            Ok(_) => info!(event = "token.revoke", token_id, reason = "discarded"),
            Err(err) => error!(
                event = "token.revoke",
                token_id,
                reason = "discard_failed",
                detail = %err,
            ),
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
                    info!(
                        event = "token.cleanup",
                        token_id = %id,
                        name = %name,
                        expires_at = expires_on.timestamp(),
                    );
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
        policies: &[TokenPolicyConfig],
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
                let scope = policy.scope();
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
                    resources: policy.iam_resources(),
                })
            })
            .collect()
    }
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
    Err(Error::new(
        ErrorCode::Misconfigured,
        if named.is_empty() {
            format!("no permission group is named {name}")
        } else {
            format!("several permission groups are named {name}, at no one scope of the resources")
        },
    ))
}

/// The claims of a token for another service, issued at `now` (seconds since
/// the epoch), and when it expires. It never outlives the token the caller
/// presented.
///
/// It has the claims the policy matched on, under the issuer's names, so the
/// service can match on the same ones. Nothing else: an issuer's other claims,
/// such as an email, stay behind. Signing adds its `jti`.
fn payload(
    issuer: &str,
    caller: &Caller,
    profile: &ProfileConfig,
    ttl: u64,
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

    let mut payload = caller.matched(Some(profile));
    let subject = match caller.identity.subject() {
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
    use super::*;
    use crate::service::config::{
        ACCOUNT_SCOPE, R2_SCOPE, ZONE_SCOPE,
        tests::{CACHE, ISSUER, NOW, claims, parse, policy},
    };

    fn caller<'p>(policy: &'p PolicyConfig, claims: Map<String, Value>) -> Caller<'p> {
        Caller {
            identity: Identity {
                issuer: ISSUER.into(),
                claims,
                claim_set: 0,
            },
            provider: &policy.providers[0],
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
    fn knows_a_caller_by_the_claims_the_policy_matches_on() {
        let policy = parse(&policy());
        let mut claims = claims();
        claims.insert("email".into(), "someone@example.com".into());
        let caller = caller(&policy, claims);
        assert_eq!(
            Value::Object(caller.matched(Some(&policy.profiles[0]))),
            json!({
                "ref": "refs/heads/main",
                "repository": "example-org/app",
                "repository_owner_id": "100000001",
            })
        );
        assert_eq!(
            Value::Object(caller.matched(None)),
            json!({ "repository_owner_id": "100000001" })
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
            })
        );

        let mut expired = claims();
        expired.insert("exp".into(), json!(NOW));
        let err = payload(
            "https://x.example.com",
            &caller(&policy, expired),
            &policy.profiles[1],
            60_000,
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.message, "the subject token has expired");
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
}
