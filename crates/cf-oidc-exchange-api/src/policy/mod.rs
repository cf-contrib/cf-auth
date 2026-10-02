//! The policy: who the broker trusts (providers), and what each caller may get
//! (profiles). Loaded once per isolate, and refused with every problem listed if
//! any guardrail fails, so an unsafe policy never serves a request.

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
    matching::{Claims, clamp_ttl, select_profile},
    prefix::r2_prefixes,
};

/// People's GitHub tokens: opaque, so the broker checks them with GitHub's API
/// instead of a signature.
pub const GITHUB_USERS_ISSUER: &str = "https://github.com";

/// GitHub Actions' OIDC issuer. GitHub Enterprise Cloud adds `/<enterprise>`.
pub const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";

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

/// Default `max_ttl` for profiles for people, unless the profile sets its own.
const USER_DEFAULT_MAX_TTL: u64 = HOUR;

/// GitHub's repo roles, least to most. `write` is GitHub's `push` and `read` its
/// `pull`. A profile's `repository_permission` is the least it accepts.
pub const REPOSITORY_PERMISSIONS: [&str; 5] = ["read", "triage", "write", "maintain", "admin"];

/// What a profile for people can match: what the broker looks up for a person,
/// nothing a job's token has.
const USER_MATCH: [&str; 6] = [
    "repository",
    "repository_id",
    "repository_owner_id",
    "actor_id",
    "team_id",
    "repository_permission",
];

/// Claims the broker checks against GitHub for a person, rather than compares with a value.
const USER_ONLY_MATCH: [&str; 2] = ["team_id", "repository_permission"];

/// Claims that only exist once a person names a repository, so they need a role on it.
const REPO_MATCH: [&str; 4] = [
    "repository",
    "repository_id",
    "repository_owner_id",
    "team_id",
];

/// What a provider for people can pin for every profile: the repo owner, and who.
const USER_PROVIDER_PINS: [&str; 2] = ["repository_owner_id", "actor_id"];

/// An account-level resource key; zone keys (`...account.zone.<id>`) don't match.
static ACCOUNT_RESOURCE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^com\.cloudflare\.api\.account\.([0-9a-f]{32})$").unwrap());

/// GitHub's default OIDC audience, `https://github.com/<owner>`, which tokens
/// requested for other clouds carry.
static GITHUB_DEFAULT_AUDIENCE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("^https://github\\.com(/|$)").unwrap());

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

/// Claim name to the values it may have: any of them.
pub type ClaimPatterns = BTreeMap<String, Vec<String>>;

/// How a provider's tokens are checked, which follows from its issuer: a person's
/// GitHub token with GitHub's API, any other issuer's as an OIDC token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderType {
    Oidc,
    GithubUser,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Provider {
    pub name: String,
    pub kind: ProviderType,
    /// The token's `iss`, exactly; `https://github.com` for people's GitHub tokens.
    pub issuer: String,
    /// OIDC only: a value the token's `aud` must contain.
    pub audience: Option<String>,
    /// OIDC only: where the keys are, if not in the issuer's discovery document.
    pub jwks_uri: Option<String>,
    /// Every token from this provider must have these.
    pub claims: ClaimPatterns,
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

#[derive(Clone, Debug, PartialEq)]
pub struct Profile {
    pub name: String,
    /// The provider whose tokens the profile is for.
    pub provider: String,
    /// That provider's type, kept here for the checks that depend on it.
    pub kind: ProviderType,
    /// A disabled profile never matches, even when a request names it.
    pub enabled: bool,
    /// What the profile issues for: Cloudflare credentials, or the broker's own
    /// token for this service.
    pub audience: String,
    /// All must match (AND), each any of its values: the profile's own claims and
    /// its provider's.
    pub claims: ClaimPatterns,
    /// Milliseconds.
    pub ttl: u64,
    pub max_ttl: u64,
    /// The token's policies. `None` for a profile with only `buckets`.
    pub policies: Option<Vec<TokenPolicy>>,
    pub buckets: Option<Vec<Bucket>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    /// The broker's own URL.
    pub issuer: String,
    pub providers: Vec<Provider>,
    pub profiles: Vec<Profile>,
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

/// Issuers that give a token to anyone's projects, and the claims that pin the
/// tenant: a provider for one of them must pin at least one, exactly.
fn tenant_claims(issuer: &str) -> Option<&'static [&'static str]> {
    let enterprise = issuer
        .strip_prefix(GITHUB_ACTIONS_ISSUER)
        .is_some_and(|rest| rest.starts_with('/'));
    if issuer == GITHUB_ACTIONS_ISSUER || enterprise {
        return Some(&["repository_owner_id"]);
    }
    match issuer {
        "https://gitlab.com" => Some(&["namespace_id", "project_id"]),
        "https://app.terraform.io" => Some(&["terraform_organization_id"]),
        _ => None,
    }
}

/// Parses and validates a policy, from its JSON text or an already parsed value.
/// With `account_id`, account resources must name that account.
pub fn load_policy(input: &Value, account_id: Option<&str>) -> Result<Policy, PolicyError> {
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
    if raw.get("version") == Some(&Value::from(1)) {
        return fail(vec![
            "version 1 is no longer supported: move github: to providers: and match: to claims: (see the broker README's migration table)".into(),
        ]);
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

    fn policy(&mut self, raw: schema::Policy) -> Policy {
        let mut providers: Vec<Provider> = Vec::new();
        for (i, provider) in raw.providers.into_iter().enumerate() {
            let at = format!("providers.{i} ({})", provider.name);
            if providers.iter().any(|p| p.name == provider.name) {
                self.issue(format!("{at}: duplicate provider name"));
            }
            if providers.iter().any(|p| p.issuer == provider.issuer) {
                self.issue(format!("{at}.issuer: another provider has the same issuer"));
            }
            let provider = self.provider(&at, provider);
            providers.push(provider);
        }

        let default_max = raw.defaults.max_ttl.as_deref().and_then(parse_duration);
        let default_max = default_max.unwrap_or(DEFAULT_MAX_TTL);
        let default_ttl = raw.defaults.ttl.as_deref().and_then(parse_duration);
        let default_ttl = default_ttl.unwrap_or(DEFAULT_TTL.min(default_max));
        self.check_ttls("defaults", default_ttl, default_max);

        let mut profiles: Vec<Profile> = Vec::new();
        for (i, profile) in raw.profiles.into_iter().enumerate() {
            let at = format!("profiles.{i} ({})", profile.name);
            if profiles.iter().any(|p| p.name == profile.name) {
                self.issue(format!("{at}: duplicate profile name"));
            }
            let defaults = (default_ttl, default_max);
            let profile = self.profile(&at, profile, &raw.issuer, &providers, defaults);
            profiles.push(profile);
        }

        Policy {
            issuer: raw.issuer,
            providers,
            profiles,
        }
    }

    fn provider(&mut self, at: &str, raw: schema::Provider) -> Provider {
        let claims = self.claims(&format!("{at}.claims"), raw.claims);

        if raw.issuer == GITHUB_USERS_ISSUER {
            // A person's GitHub token is checked with GitHub's API: it has no audience or keys.
            for (field, value) in [("audience", &raw.audience), ("jwks_uri", &raw.jwks_uri)] {
                if value.is_some() {
                    self.issue(format!(
                        "{at}.{field}: not for {GITHUB_USERS_ISSUER}, whose tokens aren't OIDC tokens"
                    ));
                }
            }
            for claim in claims.keys() {
                if !USER_PROVIDER_PINS.contains(&claim.as_str()) {
                    self.issue(format!(
                        "{at}.claims.{claim}: a provider for people pins {}; the rest go on profiles",
                        USER_PROVIDER_PINS.join(" or ")
                    ));
                }
            }
            return Provider {
                name: raw.name,
                kind: ProviderType::GithubUser,
                issuer: raw.issuer,
                audience: None,
                jwks_uri: None,
                claims,
            };
        }

        if raw.audience.is_none() {
            self.issue(format!("{at}.audience: required for an OIDC issuer"));
        }
        for claim in USER_ONLY_MATCH {
            if claims.contains_key(claim) {
                self.issue(format!(
                    "{at}.claims.{claim}: only for people ({GITHUB_USERS_ISSUER})"
                ));
            }
        }

        // Guardrail 1: an issuer that gives anyone's projects a token needs the tenant pinned.
        let tenant = tenant_claims(&raw.issuer);
        if let Some(tenant) = tenant
            && !tenant.iter().any(|claim| claims.contains_key(*claim))
        {
            self.issue(format!(
                "{at}.claims: must pin {}: {} issues tokens to anyone's projects",
                tenant.join(" or "),
                raw.issuer
            ));
        }
        // Guardrail 5: a custom audience, so a GitHub token requested for AWS or GCP
        // can't be replayed here.
        let audience = raw.audience.unwrap_or_default();
        if tenant.is_some_and(|tenant| tenant.contains(&"repository_owner_id"))
            && GITHUB_DEFAULT_AUDIENCE.is_match(&audience)
        {
            self.issue(format!(
                "{at}.audience: must not be GitHub's default audience; use the broker's URL"
            ));
        }
        Provider {
            name: raw.name,
            kind: ProviderType::Oidc,
            issuer: raw.issuer,
            audience: Some(audience),
            jwks_uri: raw.jwks_uri,
            claims,
        }
    }

    fn profile(
        &mut self,
        at: &str,
        raw: schema::Profile,
        issuer: &str,
        providers: &[Provider],
        (default_ttl, default_max): (u64, u64),
    ) -> Profile {
        // With one provider, it's the only one a profile can be for.
        let named = match (&raw.provider, providers) {
            (Some(name), _) => Some(name.as_str()),
            (None, [only]) => Some(only.name.as_str()),
            (None, _) => None,
        };
        let provider = providers.iter().find(|p| Some(p.name.as_str()) == named);
        let provider_name = provider.map_or("", |p| p.name.as_str());
        if raw.provider.is_none() && providers.len() > 1 {
            self.issue(format!(
                "{at}.provider: required when the policy has several providers"
            ));
        } else if provider.is_none() {
            let name = raw.provider.as_deref().unwrap_or_default();
            self.issue(format!("{at}.provider: no provider named {name}"));
        }
        let kind = provider.map_or(ProviderType::Oidc, |p| p.kind);
        let pinned = |claim: &str| provider.is_some_and(|p| p.claims.contains_key(claim));

        let claims = self.claims(&format!("{at}.claims"), raw.claims);
        // The provider's claims every token for this profile must also have.
        let mut inherited = provider.map(|p| p.claims.clone()).unwrap_or_default();
        // Guardrail 6: a person has no ref, environment or workflow, and picks the
        // repo, so a profile for people matches only what the broker looks up. It's
        // pinned either to a role on the repo they ask for, which must belong to the
        // provider's owner, or to who they are.
        if kind == ProviderType::GithubUser {
            self.check_user_claims(&format!("{at}.claims"), &claims);
            let repo_scoped = claims.contains_key("repository_permission");
            if repo_scoped && !pinned("repository_owner_id") {
                self.issue(format!(
                    "{at}.claims.repository_permission: needs provider {provider_name} to pin repository_owner_id, the owner the repo must belong to"
                ));
            }
            if !repo_scoped {
                if !claims.contains_key("actor_id") && !pinned("actor_id") {
                    self.issue(format!(
                        "{at}.claims: a profile for people needs repository_permission (a role on the repo they ask for) or actor_id (who may use it)"
                    ));
                }
                for claim in REPO_MATCH {
                    if claims.contains_key(claim) {
                        self.issue(format!("{at}.claims.{claim}: needs repository_permission"));
                    }
                }
                // Without a repo, the owner pin has nothing to bound: it applies to
                // repo-scoped profiles.
                inherited.remove("repository_owner_id");
            }
        } else {
            for claim in USER_ONLY_MATCH {
                if claims.contains_key(claim) {
                    self.issue(format!(
                        "{at}.claims.{claim}: only for people ({GITHUB_USERS_ISSUER})"
                    ));
                }
            }
        }

        // Guardrail 1: a provider's claims apply to every profile for it. A profile
        // can narrow them to some of their values, but not widen or change them.
        for (claim, values) in &inherited {
            if let Some(own) = claims.get(claim)
                && !own.iter().all(|value| values.contains(value))
            {
                self.issue(format!(
                    "{at}.claims.{claim}: conflicts with provider {provider_name}"
                ));
            }
        }

        let has_credentials = raw.token.is_some() || raw.buckets.is_some();
        let audience = raw.audience.unwrap_or_else(|| CLOUDFLARE_AUDIENCE.into());
        if audience == CLOUDFLARE_AUDIENCE {
            if !has_credentials {
                self.issue(format!("{at}: must have a token, buckets or both"));
            }
        } else {
            // The broker signs its own token for the service; Cloudflare credentials
            // are another profile's job.
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

        // Guardrail 4: TTL caps. A stolen gh token never expires, so what it can mint
        // for a person should.
        let fallback_max = match kind {
            ProviderType::GithubUser => default_max.min(USER_DEFAULT_MAX_TTL),
            ProviderType::Oidc => default_max,
        };
        let max_ttl = raw.max_ttl.as_deref().and_then(parse_duration);
        let max_ttl = max_ttl.unwrap_or(fallback_max);
        let ttl = raw.ttl.as_deref().and_then(parse_duration);
        let ttl = ttl.unwrap_or(default_ttl.min(max_ttl));
        self.check_ttls(at, ttl, max_ttl);
        if buckets.is_some() && (ttl < R2_MIN_TTL || max_ttl > R2_MAX_TTL) {
            self.issue(format!(
                "{at}: ttl and max_ttl must be within the 1m to 7 days R2 credentials accept"
            ));
        }

        let mut effective = inherited;
        effective.extend(claims);
        Profile {
            name: raw.name,
            provider: provider_name.into(),
            kind,
            enabled: raw.enabled,
            audience,
            claims: effective,
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

    /// Turns each claim's value into a list, and checks guardrail 2: patterns stay
    /// narrow, and IDs are exact.
    fn claims(&mut self, at: &str, raw: schema::ClaimSet) -> ClaimPatterns {
        let mut claims = ClaimPatterns::new();
        for (claim, values) in raw {
            let values = values.into_list();
            for value in &values {
                if claim.ends_with("_id") && value.contains('*') {
                    self.issue(format!(
                        "{at}.{claim}: ID claims must be exact, globs are not allowed"
                    ));
                } else if value.contains('*') && !matching::is_prefix_pattern(value) {
                    // A bare or leading `*` would match far more than intended; one in
                    // the middle needs a backtracking matcher.
                    self.issue(format!(
                        "{at}.{claim}: * is only allowed once, at the end, after a prefix (e.g. example-org/*)"
                    ));
                }
            }
            claims.insert(claim, values);
        }
        claims
    }

    /// Checks a claim set for people: only what the broker looks up for a person,
    /// with one valid role.
    fn check_user_claims(&mut self, at: &str, claims: &ClaimPatterns) {
        for claim in claims.keys() {
            if !USER_MATCH.contains(&claim.as_str()) {
                self.issue(format!(
                    "{at}.{claim}: not available for people; use {}",
                    USER_MATCH.join(", ")
                ));
            }
        }
        let Some(roles) = claims.get("repository_permission") else {
            return;
        };
        if roles.len() > 1 {
            self.issue(format!(
                "{at}.repository_permission: one role, the least the person must have"
            ));
        }
        if let Some(role) = roles.first()
            && !REPOSITORY_PERMISSIONS.contains(&role.as_str())
        {
            self.issue(format!(
                "{at}.repository_permission: must be one of {}",
                REPOSITORY_PERMISSIONS.join(", ")
            ));
        }
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
