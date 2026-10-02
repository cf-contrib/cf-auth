//! The policy: which OIDC issuers the broker trusts (providers), and what each
//! caller may get (profiles). Loaded once per isolate, and refused with every
//! problem listed if any guardrail fails, so an unsafe policy never serves a
//! request.
//!
//! It knows no issuer by name: who may do what is in the claim sets, as in
//! cf-nix-cache.

mod claims;
mod matching;
mod prefix;
mod schema;
#[cfg(test)]
mod tests;

use std::{collections::BTreeMap, fmt, sync::LazyLock};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use self::{
    claims::{ClaimSet, Claims},
    matching::{clamp_ttl, select_profile},
    prefix::r2_prefixes,
};

/// The audience for Cloudflare API tokens and R2 credentials, and every profile's default.
pub const CLOUDFLARE_AUDIENCE: &str = "https://api.cloudflare.com";

const SECOND: u64 = 1000;
const MINUTE: u64 = 60 * SECOND;
const HOUR: u64 = 60 * MINUTE;

pub const MIN_TTL: u64 = MINUTE;
pub const MAX_TTL: u64 = 24 * HOUR;
const DEFAULT_TTL: u64 = 15 * MINUTE;
const DEFAULT_MAX_TTL: u64 = HOUR;

/// `ttlSeconds` range of R2 temporary credentials. Cloudflare documents a 7-day
/// maximum; the API accepts values down to 0, so the minimum is the broker's own.
const R2_MIN_TTL: u64 = MIN_TTL;
const R2_MAX_TTL: u64 = 7 * 24 * HOUR;

/// An account-level resource key; zone keys (`...account.zone.<id>`) don't match.
static ACCOUNT_RESOURCE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^com\.cloudflare\.api\.account\.([0-9a-f]{32})$").unwrap());

/// Parses `90s`, `15m`, `1h`, `1h30m` into milliseconds.
pub fn parse_duration(value: &str) -> Option<u64> {
    static DURATION: LazyLock<Regex> =
        LazyLock::new(|| Regex::new("^(?:([0-9]+)h)?(?:([0-9]+)m)?(?:([0-9]+)s)?$").unwrap());
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let caps = DURATION.captures(value)?;
    let part = |i: usize, unit: u64| -> Option<u64> {
        caps.get(i).map_or(Some(0), |m| {
            m.as_str().parse::<u64>().ok()?.checked_mul(unit)
        })
    };
    part(1, HOUR)?
        .checked_add(part(2, MINUTE)?)?
        .checked_add(part(3, SECOND)?)
}

/// An OIDC issuer the broker trusts, and which of its tokens.
#[derive(Clone, Debug, PartialEq)]
pub struct ProviderConfig {
    pub name: String,
    /// The tokens' `iss`, exactly.
    pub issuer: String,
    /// A value the tokens' `aud` must contain.
    pub audience: String,
    /// Where the keys are, if not in the issuer's discovery document.
    pub jwks_uri: Option<String>,
    /// Every token from this provider must match one of these, whichever profile
    /// it gets.
    pub claims: Vec<ClaimSet>,
}

impl ProviderConfig {
    /// Whether a token's claims are ones this provider takes.
    pub fn takes(&self, claims: &Claims) -> bool {
        self.claims.iter().any(|set| set.matches(claims))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BucketPermission {
    ObjectReadWrite,
    ObjectReadOnly,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Bucket {
    pub name: String,
    pub permission: BucketPermission,
    /// Templates with `{claim}` placeholders, filled in by `r2_prefixes`. Empty
    /// means the whole bucket.
    pub prefixes: Vec<String>,
}

/// A resource in Cloudflare's own token format: `"*"`, or a nested map.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResourceValue {
    Scope(String),
    Nested(BTreeMap<String, String>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TokenPolicy {
    pub effect: Effect,
    /// Permission-group names, resolved to IDs when a token is minted.
    pub permissions: Vec<String>,
    pub resources: BTreeMap<String, ResourceValue>,
}

/// What a caller may get, and who may get it.
#[derive(Clone, Debug, PartialEq)]
pub struct ProfileConfig {
    pub name: String,
    /// The provider whose tokens the profile is for.
    pub provider: String,
    /// A disabled profile never matches, even when a request names it.
    pub enabled: bool,
    /// What the profile issues for: Cloudflare credentials, or the broker's own
    /// token for this service.
    pub audience: String,
    /// A token must match one of these, as well as one of its provider's.
    pub claims: Vec<ClaimSet>,
    /// Milliseconds.
    pub ttl: u64,
    pub max_ttl: u64,
    /// The token's policies. `None` for a profile with only `buckets`.
    pub policies: Option<Vec<TokenPolicy>>,
    pub buckets: Option<Vec<Bucket>>,
}

impl ProfileConfig {
    /// Whether a token's claims match one of the profile's claim sets. Its
    /// provider's are checked apart, by [`ProviderConfig::takes`].
    pub fn matches(&self, claims: &Claims) -> bool {
        self.claims.iter().any(|set| set.matches(claims))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PolicyConfig {
    /// The broker's own URL.
    pub issuer: String,
    pub providers: Vec<ProviderConfig>,
    pub profiles: Vec<ProfileConfig>,
}

/// Every problem found in a policy, so an admin can fix them all in one go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError {
    pub issues: Vec<String>,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid policy:\n  - {}", self.issues.join("\n  - "))
    }
}

impl std::error::Error for PolicyError {}

/// `https://`, or plain `http://` on loopback, as cf-nix-cache allows for its issuers.
pub fn is_issuer_url(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    match url.scheme() {
        "https" => true,
        "http" => matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")),
        _ => false,
    }
}

/// Parses and validates a policy, from its JSON text or an already parsed value.
/// With `account_id`, account resources must name that account.
pub fn load_policy(input: &Value, account_id: Option<&str>) -> Result<PolicyConfig, PolicyError> {
    let fail = |issues: Vec<String>| Err(PolicyError { issues });
    let parsed;
    let raw = match input {
        Value::String(text) => match serde_json::from_str::<Value>(text) {
            Ok(value) => {
                parsed = value;
                &parsed
            }
            Err(err) => return fail(vec![format!("policy.json is not valid JSON: {err}")]),
        },
        other => other,
    };
    if let Some(version @ (1 | 2)) = raw.get("version").and_then(Value::as_u64) {
        return fail(vec![format!(
            "version {version} is no longer supported: claims are lists of claim sets, and providers are OIDC issuers only (see the README's policy section)"
        )]);
    }

    let policy: schema::Policy = match serde_path_to_error::deserialize(raw) {
        Ok(policy) => policy,
        Err(err) => return fail(vec![schema::shape_issue(err)]),
    };
    let issues = schema::check(&policy);
    if !issues.is_empty() {
        return fail(issues);
    }

    let mut loader = Loader {
        account_id,
        issues: Vec::new(),
    };
    let policy = loader.policy(policy);
    if loader.issues.is_empty() {
        Ok(policy)
    } else {
        fail(loader.issues)
    }
}

/// The guardrails, which need a well-formed policy. Collects every issue, by the
/// name of the provider or profile it's about.
struct Loader<'a> {
    account_id: Option<&'a str>,
    issues: Vec<String>,
}

impl Loader<'_> {
    fn issue(&mut self, issue: String) {
        self.issues.push(issue);
    }

    fn policy(&mut self, raw: schema::Policy) -> PolicyConfig {
        let mut providers: Vec<ProviderConfig> = Vec::new();
        for (i, provider) in raw.providers.into_iter().enumerate() {
            let at = format!("providers.{i} ({})", provider.name);
            if providers.iter().any(|p| p.name == provider.name) {
                self.issue(format!("{at}: duplicate provider name"));
            }
            if providers.iter().any(|p| p.issuer == provider.issuer) {
                self.issue(format!("{at}.issuer: another provider has the same issuer"));
            }
            providers.push(ProviderConfig {
                name: provider.name,
                issuer: provider.issuer,
                audience: provider.audience,
                jwks_uri: provider.jwks_uri,
                claims: provider.claims,
            });
        }

        let default_max = raw.defaults.max_ttl.as_deref().and_then(parse_duration);
        let default_max = default_max.unwrap_or(DEFAULT_MAX_TTL);
        let default_ttl = raw.defaults.ttl.as_deref().and_then(parse_duration);
        let default_ttl = default_ttl.unwrap_or(DEFAULT_TTL.min(default_max));
        self.check_ttls("defaults", default_ttl, default_max);

        let mut profiles: Vec<ProfileConfig> = Vec::new();
        for (i, profile) in raw.profiles.into_iter().enumerate() {
            let at = format!("profiles.{i} ({})", profile.name);
            if profiles.iter().any(|p| p.name == profile.name) {
                self.issue(format!("{at}: duplicate profile name"));
            }
            let defaults = (default_ttl, default_max);
            let profile = self.profile(&at, profile, &raw.issuer, &providers, defaults);
            profiles.push(profile);
        }

        PolicyConfig {
            issuer: raw.issuer,
            providers,
            profiles,
        }
    }

    fn profile(
        &mut self,
        at: &str,
        raw: schema::Profile,
        issuer: &str,
        providers: &[ProviderConfig],
        (default_ttl, default_max): (u64, u64),
    ) -> ProfileConfig {
        // With one provider, it's the only one a profile can be for.
        let named = match (&raw.provider, providers) {
            (Some(name), _) => Some(name.as_str()),
            (None, [only]) => Some(only.name.as_str()),
            (None, _) => None,
        };
        let provider = providers.iter().find(|p| Some(p.name.as_str()) == named);
        if raw.provider.is_none() && providers.len() > 1 {
            self.issue(format!(
                "{at}.provider: required when the policy has several providers"
            ));
        } else if provider.is_none() {
            let name = raw.provider.as_deref().unwrap_or_default();
            self.issue(format!("{at}.provider: no provider named {name}"));
        }

        // Guardrail 5: audiences are kept apart. The broker signs its own token
        // for another service; Cloudflare credentials are another profile's job.
        let has_credentials = raw.token.is_some() || raw.buckets.is_some();
        let audience = raw.audience.unwrap_or_else(|| CLOUDFLARE_AUDIENCE.into());
        if audience == CLOUDFLARE_AUDIENCE {
            if !has_credentials {
                self.issue(format!("{at}: must have a token, buckets or both"));
            }
        } else {
            if has_credentials {
                self.issue(format!(
                    "{at}: a profile for {audience} can't have a token or buckets"
                ));
            }
            if audience == issuer {
                self.issue(format!(
                    "{at}.audience: must be another service, not the broker itself"
                ));
            }
        }

        let policies = raw.token.map(|token| self.token(at, token));
        let buckets = raw.buckets.map(|buckets| self.buckets(at, buckets));

        // Guardrail 4: TTLs are capped.
        let max_ttl = raw.max_ttl.as_deref().and_then(parse_duration);
        let max_ttl = max_ttl.unwrap_or(default_max);
        let ttl = raw.ttl.as_deref().and_then(parse_duration);
        let ttl = ttl.unwrap_or(default_ttl.min(max_ttl));
        self.check_ttls(at, ttl, max_ttl);
        if buckets.is_some() && (ttl < R2_MIN_TTL || max_ttl > R2_MAX_TTL) {
            self.issue(format!(
                "{at}: ttl and max_ttl must be within the 1m to 7 days R2 credentials accept"
            ));
        }

        ProfileConfig {
            name: raw.name,
            provider: provider.map_or_else(String::new, |p| p.name.clone()),
            enabled: raw.enabled,
            audience,
            claims: raw.claims,
            ttl,
            max_ttl,
            policies,
            buckets,
        }
    }

    fn token(&mut self, at: &str, raw: schema::Token) -> Vec<TokenPolicy> {
        let mut policies = Vec::new();
        for (j, policy) in raw.policies.into_iter().enumerate() {
            // Tokens are minted in one account; another account's ID is a copy-paste mistake.
            for key in policy.resources.keys() {
                let id = ACCOUNT_RESOURCE
                    .captures(key)
                    .map(|caps| caps[1].to_string());
                if let (Some(account), Some(id)) = (self.account_id, id)
                    && id != account
                {
                    self.issue(format!(
                        "{at}.token.policies.{j}.resources: {key} is not the broker's account"
                    ));
                }
            }

            let effect = match policy.effect.as_deref() {
                Some("deny") => Effect::Deny,
                _ => Effect::Allow,
            };
            // Guardrail 3: no token-management permissions.
            if effect == Effect::Allow {
                for name in &policy.permissions {
                    if name.to_lowercase().contains("api tokens") {
                        self.issue(format!(
                            "{at}.token.policies.{j}: \"{name}\" is not grantable (token-management permission)"
                        ));
                    }
                }
            }
            policies.push(TokenPolicy {
                effect,
                permissions: policy.permissions,
                resources: policy.resources,
            });
        }
        policies
    }

    fn buckets(&mut self, at: &str, raw: Vec<schema::Bucket>) -> Vec<Bucket> {
        let mut buckets: Vec<Bucket> = Vec::new();
        for (j, bucket) in raw.into_iter().enumerate() {
            // The name is also the AWS profile's, so it can only appear once.
            if buckets.iter().any(|b| b.name == bucket.name) {
                self.issue(format!(
                    "{at}.buckets.{j}.name: duplicate bucket {}",
                    bucket.name
                ));
            }
            for (k, prefix) in bucket.prefixes.iter().enumerate() {
                if let Some(problem) = prefix::template_problem(prefix) {
                    self.issue(format!("{at}.buckets.{j}.prefixes.{k}: {problem}"));
                }
            }
            let permission = match bucket.permission.as_str() {
                "object-read-write" => BucketPermission::ObjectReadWrite,
                _ => BucketPermission::ObjectReadOnly,
            };
            buckets.push(Bucket {
                name: bucket.name,
                permission,
                prefixes: bucket.prefixes,
            });
        }
        buckets
    }

    fn check_ttls(&mut self, at: &str, ttl: u64, max: u64) {
        if max > MAX_TTL {
            self.issue(format!("{at}.max_ttl: must be at most 24h"));
        }
        if ttl < MIN_TTL {
            self.issue(format!("{at}.ttl: must be at least 1m"));
        }
        if ttl > max {
            self.issue(format!("{at}.ttl: must not exceed max_ttl"));
        }
    }
}
