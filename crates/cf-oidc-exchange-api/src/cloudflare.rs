//! Cloudflare credentials: account API tokens, minted, revoked and cleaned up
//! with the broker token, and R2 temporary credentials, with the broker token as
//! their parent.

use std::{cell::RefCell, collections::HashMap};

use cf_oidc_exchange_sdk::v1::{Error, ErrorCode};
use chrono::{DateTime, SecondsFormat, Utc};
use cloudflare::v4::{
    ApiOpError, HttpClient, IamCreatePayload, IamEffect, IamPermissionGroup,
    IamPolicyWithPermissionGroupsAndResources, IamResources, IamResourcesTypeObjectNested,
    IamResourcesTypeObjectNestedAdditionalProperty, IamResourcesTypeObjectString,
    R2TempAccessCredsRequest, R2TempAccessCredsRequestPermission,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    audit::Audit,
    service::config::{
        Bucket, BucketPermission, Claims, Effect, ProviderConfig, ResourceValue, TokenPolicy,
    },
};

pub const API_URL: &str = "https://api.cloudflare.com/client/v4";

/// Every minted token's name starts with this. Revoke and cleanup never touch anything else.
pub const TOKEN_PREFIX: &str = "cf-oidc:";
const NAME_MAX: usize = 120;

/// Permission groups change rarely; a stale entry costs at most one failed mint.
const GROUPS_TTL_SECS: u64 = 3600;

const ACCOUNT_SCOPE: &str = "com.cloudflare.api.account";
const ZONE_SCOPE: &str = "com.cloudflare.api.account.zone";
const R2_SCOPE: &str = "com.cloudflare.edge.r2.bucket";

/// Tokens listed per page by the cleanup.
const PAGE_SIZE: usize = 50;

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

/// RFC 3339 without fractional seconds, which is what the tokens API accepts.
pub fn rfc3339(ms: u64) -> String {
    timestamp(ms).to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn timestamp(ms: u64) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(ms as i64).unwrap_or_default()
}

/// `cf-oidc:<provider>:<sub>`, whatever the issuer, cut to fit 120 characters.
pub fn token_name(claims: &Claims, provider: &ProviderConfig) -> String {
    let sub = match claims.get("sub").and_then(Value::as_str) {
        Some(sub) if !sub.is_empty() => sub,
        _ => "unknown",
    };
    let name = format!("{TOKEN_PREFIX}{}:{sub}", provider.name);
    name.chars().take(NAME_MAX).collect()
}

/// The Cloudflare API, as the broker token or another token.
pub struct Cloudflare {
    client: HttpClient,
    account_id: String,
    /// Kept to key the parent access key ID by.
    api_token: String,
}

/// A permission group, as the broker caches it.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Group {
    id: String,
    name: String,
    scopes: Vec<String>,
}

thread_local! {
    /// Permission groups by account, with when they expire (Unix ms).
    static GROUPS: RefCell<HashMap<String, (u64, Vec<Group>)>> = RefCell::new(HashMap::new());
    /// The broker token's ID, which is its R2 access key ID, keyed by the token, so
    /// a rotated broker token is looked up again.
    static PARENT: RefCell<Option<(String, String)>> = const { RefCell::new(None) };
}

/// A token the broker minted.
pub struct MintedToken {
    pub token: String,
    pub token_id: String,
    pub expires_on: String,
}

/// R2 credentials for one bucket.
pub struct BucketGrant {
    pub name: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub prefixes: Vec<String>,
    pub endpoint: String,
    pub expires_on: String,
}

impl Cloudflare {
    pub fn new(api_url: &str, account_id: &str, api_token: &str) -> Self {
        Self {
            client: HttpClient::new()
                .with_base_url(api_url)
                .with_api_key(api_token),
            account_id: account_id.into(),
            api_token: api_token.into(),
        }
    }

    /// Mints a token. Not retried: a create that failed midway leaves an orphan
    /// the cleanup removes.
    pub async fn mint(
        &self,
        policies: &[TokenPolicy],
        name: String,
        ttl: u64,
        now_ms: u64,
    ) -> Result<MintedToken, Error> {
        let policies = self.resolve(policies, now_ms).await?;
        let expires_on = timestamp(now_ms + ttl).with_nanosecond_zero();
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
        })
    }

    /// Deletes a token that was minted but won't be handed out. Best effort: the
    /// cleanup is the fallback.
    pub async fn discard(&self, token_id: &str) {
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
    /// authorization. Returns the deleted token's ID, or `None` if it was already gone.
    pub async fn revoke(&self, api_url: &str, presented: &str) -> Result<Option<String>, Error> {
        let presenter = HttpClient::new()
            .with_base_url(api_url)
            .with_api_key(presented);
        // The API's answer for a token it doesn't recognize: invalid, expired, deleted, another account's.
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
    pub async fn cleanup(&self, now_ms: u64) -> Result<usize, Error> {
        // Collect first: deleting while paginating would shift later pages and skip tokens.
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
                    Audit::new("token.cleanup")
                        .with("token_id", id)
                        .with("name", name)
                        .with(
                            "expires_on",
                            expires_on.to_rfc3339_opts(SecondsFormat::Secs, true),
                        )
                        .emit();
                }
                Err(err) if status(&err) == Some(404) => {}
                Err(err) => return Err(upstream("tokens.delete", err)),
            }
        }
        Ok(deleted)
    }

    /// Creates temporary S3 credentials for a bucket, limited to `prefixes`
    /// (already filled in), with the broker token as the parent.
    pub async fn issue_r2(
        &self,
        bucket: &Bucket,
        prefixes: Vec<String>,
        ttl: u64,
        now_ms: u64,
    ) -> Result<BucketGrant, Error> {
        let parent_access_key_id = self.parent_key_id().await?;
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
            prefixes: (!prefixes.is_empty()).then(|| prefixes.clone()),
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
        Ok(BucketGrant {
            name: bucket.name.clone(),
            access_key_id,
            secret_access_key,
            session_token,
            prefixes,
            endpoint: format!("https://{}.r2.cloudflarestorage.com", self.account_id),
            expires_on: rfc3339(now_ms + ttl),
        })
    }

    async fn parent_key_id(&self) -> Result<String, Error> {
        let cached = PARENT.with_borrow(|parent| {
            parent
                .as_ref()
                .filter(|(token, _)| *token == self.api_token)
                .map(|(_, id)| id.clone())
        });
        if let Some(id) = cached {
            return Ok(id);
        }
        let id = self
            .client
            .account_api_tokens_verify_token(&self.account_id)
            .await
            .map_err(|err| upstream("tokens.verify", err))?
            .result
            .ok_or_else(|| missing("tokens.verify"))?
            .id;
        PARENT.with_borrow_mut(|parent| *parent = Some((self.api_token.clone(), id.clone())));
        Ok(id)
    }

    /// Resolves permission-group names to IDs; resources are already in the
    /// API's shape. An unknown name is a configuration error, never a silent drop.
    async fn resolve(
        &self,
        policies: &[TokenPolicy],
        now_ms: u64,
    ) -> Result<Vec<IamPolicyWithPermissionGroupsAndResources>, Error> {
        let groups = self.permission_groups(now_ms).await?;
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
                    resources: resources(policy)?,
                })
            })
            .collect()
    }

    /// The account's permission groups: per isolate first, then the Cache API,
    /// which is shared per colo, then Cloudflare.
    async fn permission_groups(&self, now_ms: u64) -> Result<Vec<Group>, Error> {
        let key = format!("permission-groups/{}", self.account_id);
        let fresh = GROUPS.with_borrow(|groups| {
            groups
                .get(&key)
                .filter(|(expires, _)| *expires > now_ms)
                .map(|(_, groups)| groups.clone())
        });
        if let Some(groups) = fresh {
            return Ok(groups);
        }

        let url = format!("https://cf-oidc-exchange.internal/{key}");
        let cache = worker::Cache::default();
        let stored = match cache.get(url.as_str(), false).await {
            Ok(Some(mut response)) => response.json::<Vec<Group>>().await.ok(),
            _ => None,
        };
        let groups = match stored {
            Some(groups) => groups,
            None => {
                let groups: Vec<Group> = self
                    .client
                    .account_api_tokens_list_permission_groups(
                        &self.account_id,
                        None::<&str>,
                        None::<&str>,
                    )
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
                // Best effort: without the Cache API, the next isolate asks again.
                if let Ok(response) = worker::Response::from_json(&groups) {
                    let headers = response.headers();
                    let _ = headers.set("cache-control", &format!("max-age={GROUPS_TTL_SECS}"));
                    let _ = cache.put(url.as_str(), response).await;
                }
                groups
            }
        };
        let expires = now_ms + GROUPS_TTL_SECS * 1000;
        GROUPS.with_borrow_mut(|cached| cached.insert(key, (expires, groups.clone())));
        Ok(groups)
    }
}

trait WholeSeconds {
    fn with_nanosecond_zero(self) -> Self;
}

impl WholeSeconds for DateTime<Utc> {
    /// The tokens API takes no fractional seconds.
    fn with_nanosecond_zero(self) -> Self {
        use chrono::Timelike;
        self.with_nanosecond(0).unwrap_or(self)
    }
}

/// A policy's resources in the API's shape: all `"*"`-style values, or all nested maps.
fn resources(policy: &TokenPolicy) -> Result<IamResources, Error> {
    let flat: Option<_> = policy
        .resources
        .iter()
        .map(|(key, value)| match value {
            ResourceValue::Scope(scope) => Some((key.clone(), scope.clone())),
            ResourceValue::Nested(_) => None,
        })
        .collect();
    if let Some(additional_properties) = flat {
        return Ok(IamResources::IamResourcesTypeObjectString(
            IamResourcesTypeObjectString {
                additional_properties,
            },
        ));
    }
    let nested: Option<_> = policy
        .resources
        .iter()
        .map(|(key, value)| match value {
            ResourceValue::Nested(nested) => Some((
                key.clone(),
                IamResourcesTypeObjectNestedAdditionalProperty {
                    additional_properties: nested.clone(),
                },
            )),
            ResourceValue::Scope(_) => None,
        })
        .collect();
    nested
        .map(|additional_properties| {
            IamResources::IamResourcesTypeObjectNested(IamResourcesTypeObjectNested {
                additional_properties,
            })
        })
        .ok_or_else(|| {
            Error::new(
                ErrorCode::Misconfigured,
                "a token policy's resources mix \"*\" values and nested maps",
            )
        })
}

/// The scope a permission group needs for these resources, used to pick between
/// same-named groups.
fn scope_for(policy: &TokenPolicy) -> &'static str {
    let keys: Vec<&str> = policy.resources.keys().map(String::as_str).collect();
    if keys.iter().any(|k| k.starts_with(R2_SCOPE)) {
        return R2_SCOPE;
    }
    let zone = format!("{ZONE_SCOPE}.");
    if keys.iter().any(|k| k.starts_with(&zone)) {
        return ZONE_SCOPE;
    }
    // Nested form: `account.<id>: { "account.zone.*": "*" }` grants every zone in the account.
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
    let message = if named.is_empty() {
        format!("no permission group is named {name}")
    } else {
        format!("several permission groups are named {name}, at no one scope of the resources")
    };
    Err(Error::new(ErrorCode::Misconfigured, message))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn provider(name: &str) -> ProviderConfig {
        ProviderConfig {
            name: name.into(),
            issuer: "https://issuer.example.com".into(),
            audience: "https://cf-oidc-exchange.example.com".into(),
            jwks_uri: None,
            claims: vec![],
        }
    }

    fn claims(value: Value) -> Claims {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn names_tokens_after_the_provider_and_the_subject() {
        let job = claims(json!({ "sub": "repo:example-org/api:ref:refs/heads/main" }));
        assert_eq!(
            token_name(&job, &provider("github")),
            "cf-oidc:github:repo:example-org/api:ref:refs/heads/main"
        );
        assert_eq!(
            token_name(&Claims::new(), &provider("gitlab")),
            "cf-oidc:gitlab:unknown"
        );
    }

    #[test]
    fn fits_token_names_in_120_characters() {
        let long = claims(json!({ "sub": "x".repeat(200) }));
        let name = token_name(&long, &provider("github"));
        assert_eq!(name.chars().count(), 120);
        assert!(name.starts_with("cf-oidc:github:xxx"));
    }

    #[test]
    fn writes_rfc3339_without_fractions() {
        assert_eq!(rfc3339(1_800_000_000_123), "2027-01-15T08:00:00Z");
    }

    fn policy(resources: Value) -> TokenPolicy {
        TokenPolicy {
            effect: Effect::Allow,
            permissions: vec![],
            resources: serde_json::from_value(resources).unwrap(),
        }
    }

    fn groups() -> Vec<Group> {
        let group = |id: &str, name: &str, scope: &str| Group {
            id: id.into(),
            name: name.into(),
            scopes: vec![scope.into()],
        };
        vec![
            group(
                "pg-workers-scripts-write",
                "Workers Scripts Write",
                ACCOUNT_SCOPE,
            ),
            group("pg-dns-write", "DNS Write", ZONE_SCOPE),
            group("pg-lb-write-account", "Load Balancers Write", ACCOUNT_SCOPE),
            group("pg-lb-write-zone", "Load Balancers Write", ZONE_SCOPE),
        ]
    }

    #[test]
    fn picks_the_scope_from_the_resources() {
        let zone = "com.cloudflare.api.account.zone.fedcba9876543210fedcba9876543210";
        let account = "com.cloudflare.api.account.0123456789abcdef0123456789abcdef";
        assert_eq!(scope_for(&policy(json!({ zone: "*" }))), ZONE_SCOPE);
        assert_eq!(scope_for(&policy(json!({ account: "*" }))), ACCOUNT_SCOPE);
        assert_eq!(
            scope_for(&policy(
                json!({ account: { "com.cloudflare.api.account.zone.*": "*" } })
            )),
            ZONE_SCOPE
        );
        assert_eq!(
            scope_for(&policy(
                json!({ "com.cloudflare.edge.r2.bucket.x_default_y": "*" })
            )),
            R2_SCOPE
        );
    }

    #[test]
    fn picks_permission_groups_by_name_then_scope() {
        let groups = groups();
        assert_eq!(
            pick_group(&groups, "DNS Write", ACCOUNT_SCOPE).unwrap().id,
            "pg-dns-write"
        );
        assert_eq!(
            pick_group(&groups, "Load Balancers Write", ZONE_SCOPE)
                .unwrap()
                .id,
            "pg-lb-write-zone"
        );
        assert_eq!(
            pick_group(&groups, "Load Balancers Write", ACCOUNT_SCOPE)
                .unwrap()
                .id,
            "pg-lb-write-account"
        );
        assert_eq!(
            pick_group(&groups, "Load Balancers Write", R2_SCOPE)
                .unwrap_err()
                .message,
            "several permission groups are named Load Balancers Write, at no one scope of the resources"
        );
        assert_eq!(
            pick_group(&groups, "Nope", ACCOUNT_SCOPE)
                .unwrap_err()
                .message,
            "no permission group is named Nope"
        );
    }

    #[test]
    fn passes_resources_through_in_either_form() {
        let flat = resources(&policy(json!({ "com.cloudflare.api.account.zone.z": "*" }))).unwrap();
        let nested = resources(&policy(
            json!({ "com.cloudflare.api.account.a": { "com.cloudflare.api.account.zone.*": "*" } }),
        ))
        .unwrap();
        let json = |r: &IamResources| serde_json::to_value(r).unwrap();
        assert_eq!(
            json(&flat),
            json!({ "com.cloudflare.api.account.zone.z": "*" })
        );
        assert_eq!(
            json(&nested),
            json!({ "com.cloudflare.api.account.a": { "com.cloudflare.api.account.zone.*": "*" } })
        );
        let mixed = policy(
            json!({ "com.cloudflare.api.account.a": { "x": "*" }, "com.cloudflare.api.account.zone.z": "*" }),
        );
        assert_eq!(
            resources(&mixed).unwrap_err().error,
            ErrorCode::Misconfigured
        );
    }
}
