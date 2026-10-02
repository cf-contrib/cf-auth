//! The broker's flows: exchanging a token for credentials, revoking a token,
//! publishing the metadata to verify its own tokens, and cleaning up.

use cf_oidc_exchange_sdk::v1::{
    BucketCredentials, Discovery, IssuedTokenType, Jwks, JwksKeysItem, TokenExchangeRequest,
    TokenExchangeRequestSubjectTokenType as SubjectTokenType, TokenExchangeResponse,
    TokenExchangeResponseTokenType as TokenType, TokenRevocationRequest,
};
use serde_json::Value;

use crate::{
    audit::Audit,
    cloudflare::{BucketGrant, MintedToken, rfc3339, token_name},
    config::Config,
    error::{ErrorCode, HttpError},
    github::{self, UserCheck},
    issuer::{self, ALGORITHM, IssueRequest},
    oidc::{self, Jwt, shown},
    policy::{
        CLOUDFLARE_AUDIENCE, Claims, Policy, Profile, Provider, ProviderType, clamp_ttl,
        r2_prefixes, select_profile,
    },
};

pub const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

fn now_ms() -> u64 {
    worker::Date::now().as_millis()
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

/// Checks what the generated validation can't: which audience, and what it can hand out.
fn read<'r>(request: &'r TokenExchangeRequest, policy: &Policy) -> Result<Exchange<'r>, HttpError> {
    let invalid_target = |audience: &str| {
        HttpError::new(ErrorCode::BadRequest, "invalid_target").with_detail(shown(audience))
    };
    let audience = request.audience.as_deref().unwrap_or(CLOUDFLARE_AUDIENCE);
    if audience.is_empty() {
        return Err(invalid_target(audience));
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
    if !issuable {
        let requested = request.requested_token_type.as_ref().map(|t| t.as_str());
        return Err(
            HttpError::new(ErrorCode::BadRequest, "unsupported_requested_token_type")
                .with_detail(requested.unwrap_or_default()),
        );
    }
    // Nothing is verified for an audience the policy doesn't know.
    if audience != CLOUDFLARE_AUDIENCE && !policy.profiles.iter().any(|p| p.audience == audience) {
        return Err(invalid_target(audience));
    }
    let kind = match request.subject_token_type {
        SubjectTokenType::UrnIetfParamsOauthTokenTypeIdToken
        | SubjectTokenType::UrnIetfParamsOauthTokenTypeJwt => ProviderType::Oidc,
        SubjectTokenType::UrnIetfParamsOauthTokenTypeAccessToken => ProviderType::GithubUser,
    };
    Ok(Exchange {
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

/// Authenticates the caller, whose token is in the body.
async fn authenticate<'p>(
    config: &Config,
    policy: &'p Policy,
    exchange: &Exchange<'_>,
) -> Result<Caller<'p>, HttpError> {
    if exchange.kind == ProviderType::Oidc {
        let jwt = Jwt::decode(exchange.token)?;
        let provider = oidc::provider_for(&jwt, &policy.providers)?;
        let claims = oidc::verify(jwt, provider, now_ms()).await?;
        return Ok(Caller { provider, claims });
    }

    // The provider for people, and its enabled profiles: none means a 404, so the
    // broker doesn't call GitHub for people it serves nothing.
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
        return Err(HttpError::new(ErrorCode::NotFound, "no_user_profiles"));
    };
    // Teams cost extra GitHub calls, so they're only looked up if a profile that could match needs them.
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

/// Serves `POST /oauth/token`, auditing the outcome.
pub async fn exchange_token(
    config: &Config,
    request: &TokenExchangeRequest,
) -> Result<TokenExchangeResponse, HttpError> {
    let policy = config.policy.clone();
    let mut caller: Option<Caller> = None;
    let mut profile: Option<String> = request.profile.clone();
    let result = async {
        let exchange = read(request, &policy)?;
        let verified = authenticate(config, &policy, &exchange).await?;
        let caller = caller.insert(verified);
        let selected = select_profile(
            &policy,
            &caller.provider.name,
            &caller.claims,
            exchange.profile,
            exchange.audience,
        )?;
        profile = Some(selected.name.clone());
        let ttl = clamp_ttl(exchange.ttl, selected)?;
        if selected.audience == CLOUDFLARE_AUDIENCE {
            cloudflare_credentials(config, caller, selected, ttl).await
        } else {
            service_token(config, caller, selected, ttl).await
        }
    }
    .await;

    if let Err(err) = &result {
        Audit::new("token.deny")
            .caller(
                caller.as_ref().map(|c| c.provider.name.as_str()),
                profile.as_deref(),
                caller.as_ref().map(|c| &c.claims),
            )
            .with("reason", err.reason)
            .with("detail", err.detail.clone())
            .emit();
    }
    result
}

/// The broker's own token, for a profile with another service's `audience`.
async fn service_token(
    config: &Config,
    caller: &Caller<'_>,
    profile: &Profile,
    ttl: u64,
) -> Result<TokenExchangeResponse, HttpError> {
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
) -> Result<TokenExchangeResponse, HttpError> {
    let Caller { provider, claims } = caller;
    let audit =
        |event| Audit::new(event).caller(Some(&provider.name), Some(&profile.name), Some(claims));

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
                // Half a profile isn't handed out. Credentials already issued can't
                // be revoked, but nobody has them.
                if let Some(token) = &token {
                    cloudflare.discard(&token.token_id).await;
                }
                return Err(err);
            }
        }
    }

    let expires_on = token
        .as_ref()
        .map(|t| t.expires_on.clone())
        .or_else(|| issued.first().map(|b| b.expires_on.clone()))
        .ok_or_else(|| {
            HttpError::new(ErrorCode::Internal, "internal").with_detail(format!(
                "profile {} has neither a token nor buckets",
                profile.name
            ))
        })?;
    let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_on)
        .map(|at| at.timestamp())
        .unwrap_or_default();
    let buckets = issued
        .into_iter()
        .map(|grant| -> Result<BucketCredentials, HttpError> {
            let bad = |what: &str| {
                HttpError::new(ErrorCode::Internal, "internal").with_detail(what.to_string())
            };
            Ok(BucketCredentials {
                access_key_id: grant.access_key_id,
                endpoint: grant.endpoint,
                expires_on: grant.expires_on.parse().map_err(|_| bad("expires_on"))?,
                name: grant.name,
                prefixes: grant.prefixes,
                secret_access_key: grant.secret_access_key,
                session_token: grant.session_token,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

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

/// Serves `POST /oauth/revoke`. Answers `Ok` whether the token was revoked or
/// already gone, as RFC 7009 has it.
pub async fn revoke_token(
    config: &Config,
    request: &TokenRevocationRequest,
) -> Result<(), HttpError> {
    let result = async {
        let cloudflare = config.cloudflare().await?;
        cloudflare
            .revoke(&config.cloudflare_api(), &request.token)
            .await
    }
    .await;
    let audit = Audit::new("token.revoke");
    match &result {
        Ok(Some(id)) => audit.with("token_id", id.as_str()).emit(),
        Ok(None) => audit.with("reason", "already_gone").emit(),
        Err(err) => audit
            .with("reason", err.reason)
            .with("detail", err.detail.clone())
            .emit(),
    }
    result.map(|_| ())
}

/// The broker's discovery document, so services can find its keys and endpoints.
/// It issues tokens by exchange only, so there's no authorization endpoint: it
/// isn't a login provider.
pub fn discovery(policy: &Policy) -> Result<Discovery, HttpError> {
    let issuer = &policy.issuer;
    let url = |path: &str| {
        format!("{issuer}{path}")
            .parse()
            .map_err(|_| HttpError::new(ErrorCode::Misconfigured, "invalid_policy"))
    };
    Ok(Discovery {
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
}

/// The broker's public key, or none when no signing key is bound.
pub async fn jwks(config: &Config) -> Result<Jwks, HttpError> {
    if !config.has_signing_key() {
        return Ok(Jwks { keys: vec![] });
    }
    let key = config.signing_key().await?;
    let jwk: JwksKeysItem = serde_json::from_value(key.public_jwk()).map_err(|err| {
        HttpError::new(ErrorCode::Internal, "internal").with_detail(err.to_string())
    })?;
    Ok(Jwks { keys: vec![jwk] })
}

/// The hourly cleanup of expired `cf-oidc:` tokens.
pub async fn cleanup(config: &Config) -> Result<usize, HttpError> {
    config.cloudflare().await?.cleanup(now_ms()).await
}

#[cfg(test)]
mod tests {
    use cf_oidc_exchange_sdk::v1::TokenExchangeRequestGrantType;
    use serde_json::json;

    use super::*;
    use crate::policy::load_policy;

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

    fn reason(request: &TokenExchangeRequest) -> Option<&'static str> {
        read(request, &policy()).err().map(|err| err.reason)
    }

    #[test]
    fn defaults_to_the_cloudflare_audience() {
        let policy = policy();
        let request = request(None, None);
        assert_eq!(
            read(&request, &policy).unwrap().audience,
            CLOUDFLARE_AUDIENCE
        );
    }

    #[test]
    fn refuses_an_audience_no_profile_is_for() {
        assert_eq!(
            reason(&request(Some("https://other.example.com"), None)),
            Some("invalid_target")
        );
        assert_eq!(reason(&request(Some(""), None)), Some("invalid_target"));
        assert_eq!(
            reason(&request(Some("https://cf-nix-cache.example.com"), None)),
            None
        );
    }

    #[test]
    fn refuses_token_types_the_audience_cant_have() {
        let jwt = Some(IssuedTokenType::UrnIetfParamsOauthTokenTypeJwt);
        let r2 = Some(IssuedTokenType::UrnCfOidcAuthParamsOauthTokenTypeR2Credentials);
        assert_eq!(
            reason(&request(None, jwt.clone())),
            Some("unsupported_requested_token_type")
        );
        assert_eq!(reason(&request(None, r2.clone())), None);
        let cache = Some("https://cf-nix-cache.example.com");
        assert_eq!(
            reason(&request(cache, r2)),
            Some("unsupported_requested_token_type")
        );
        assert_eq!(reason(&request(cache, jwt)), None);
    }

    #[test]
    fn publishes_the_endpoints() {
        let doc = serde_json::to_value(discovery(&policy()).unwrap()).unwrap();
        assert_eq!(doc["issuer"], "https://cf-oidc-exchange.example.com");
        assert_eq!(
            doc["jwks_uri"],
            "https://cf-oidc-exchange.example.com/.well-known/jwks"
        );
        assert_eq!(
            doc["token_endpoint"],
            "https://cf-oidc-exchange.example.com/oauth/token"
        );
        assert_eq!(
            doc["revocation_endpoint"],
            "https://cf-oidc-exchange.example.com/oauth/revoke"
        );
    }
}
