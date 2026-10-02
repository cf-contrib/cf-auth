//! The policy as written: its shape, and the checks each field needs on its own.
//! Problems here are reported by their dot path (`profiles.1.claims.0`), and
//! stop the load before the guardrails, which need a well-formed policy.

use std::{collections::BTreeMap, sync::LazyLock};

use regex::Regex;
use serde::Deserialize;
use serde_path_to_error::Segment;

use super::{ClaimSet, ResourceValue, is_issuer_url, parse_duration};

static NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$").unwrap());

/// R2's bucket name rules: 3-63 lowercase letters, digits and hyphens, starting
/// and ending with a letter or digit.
static R2_BUCKET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$").unwrap());

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Policy {
    pub version: u64,
    /// The broker's own URL: the issuer of the tokens it signs for other services.
    pub issuer: String,
    pub providers: Vec<Provider>,
    #[serde(default)]
    pub defaults: Defaults,
    pub profiles: Vec<Profile>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Defaults {
    pub ttl: Option<String>,
    pub max_ttl: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Provider {
    pub name: String,
    /// The tokens' `iss`, exactly.
    pub issuer: String,
    /// A value the tokens' `aud` must contain.
    pub audience: String,
    pub jwks_uri: Option<String>,
    /// Every token from this provider must match one of these, whichever
    /// profile it gets.
    pub claims: Vec<ClaimSet>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    pub name: String,
    /// May be left out when the policy has exactly one provider.
    pub provider: Option<String>,
    /// Off switch for incidents: the profile stays in the policy but never matches.
    #[serde(default = "enabled")]
    pub enabled: bool,
    /// Another service the broker issues its own token for, instead of Cloudflare credentials.
    pub audience: Option<String>,
    /// A token must match one of these, as well as one of its provider's.
    pub claims: Vec<ClaimSet>,
    /// For everything the profile hands out: the token and the buckets' credentials.
    pub ttl: Option<String>,
    pub max_ttl: Option<String>,
    pub token: Option<Token>,
    /// Each bucket gets its own credentials, which the action exports as an AWS
    /// profile named after it.
    pub buckets: Option<Vec<Bucket>>,
}

fn enabled() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Token {
    pub policies: Vec<TokenPolicy>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TokenPolicy {
    pub effect: Option<String>,
    pub permissions: Vec<String>,
    /// Cloudflare's own token `resources`, e.g. `com.cloudflare.api.account.zone.<zone_id>: "*"`.
    pub resources: BTreeMap<String, ResourceValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Bucket {
    pub name: String,
    pub permission: String,
    #[serde(default)]
    pub prefixes: Vec<String>,
}

/// Reports a serde error by the dot path of the field it's about.
pub(super) fn shape_issue(err: serde_path_to_error::Error<serde_json::Error>) -> String {
    let mut path: Vec<String> = err
        .path()
        .iter()
        .map(|segment| match segment {
            Segment::Seq { index } => index.to_string(),
            Segment::Map { key } => key.clone(),
            Segment::Enum { variant } => variant.clone(),
            Segment::Unknown => "?".to_string(),
        })
        .collect();
    let mut message = err.into_inner().to_string();
    // serde names a missing field in the message, at its parent's path.
    if let Some(field) = message
        .strip_prefix("missing field `")
        .and_then(|rest| rest.split('`').next())
    {
        path.push(field.to_string());
        message = "required".to_string();
    }
    if message.starts_with("unknown field `") {
        message = "unknown key".to_string();
    }
    // serde_json adds the position in the input, which is meaningless for a value.
    if let Some(at) = message.find(" at line ") {
        message.truncate(at);
    }
    if path.is_empty() {
        message
    } else {
        format!("{}: {message}", path.join("."))
    }
}

/// Checks each field on its own: names, URLs, durations, picklists, non-empty lists.
pub(super) fn check(policy: &Policy) -> Vec<String> {
    let mut issues = Vec::new();
    let mut issue = |path: String, message: &str| issues.push(format!("{path}: {message}"));

    if policy.version != 3 {
        issue("version".into(), "must be 3");
    }
    if let Some(problem) = origin_problem(&policy.issuer) {
        issue("issuer".into(), problem);
    }
    if policy.providers.is_empty() {
        issue("providers".into(), "must list at least one provider");
    }
    for (i, provider) in policy.providers.iter().enumerate() {
        let at = format!("providers.{i}");
        if !NAME.is_match(&provider.name) {
            issue(format!("{at}.name"), "must be 1-64 of [A-Za-z0-9_.-]");
        }
        if let Some(problem) = issuer_url_problem(&provider.issuer) {
            issue(format!("{at}.issuer"), problem);
        }
        if provider.audience.is_empty() {
            issue(format!("{at}.audience"), "must not be empty");
        }
        if let Some(problem) = provider.jwks_uri.as_deref().and_then(issuer_url_problem) {
            issue(format!("{at}.jwks_uri"), problem);
        }
        // Guardrail 1: the provider is pinned. An issuer that gives anyone's
        // projects a token, such as GitHub Actions, would otherwise let them all in.
        if provider.claims.is_empty() {
            issue(format!("{at}.claims"), "must list at least one claim set");
        }
    }

    for (field, value) in [
        ("ttl", &policy.defaults.ttl),
        ("max_ttl", &policy.defaults.max_ttl),
    ] {
        if value
            .as_deref()
            .is_some_and(|v| parse_duration(v).is_none())
        {
            issue(
                format!("defaults.{field}"),
                "must be a duration such as 15m or 1h",
            );
        }
    }

    if policy.profiles.is_empty() {
        issue("profiles".into(), "must list at least one profile");
    }
    for (i, profile) in policy.profiles.iter().enumerate() {
        let at = format!("profiles.{i}");
        if !NAME.is_match(&profile.name) {
            issue(format!("{at}.name"), "must be 1-64 of [A-Za-z0-9_.-]");
        }
        if profile
            .provider
            .as_deref()
            .is_some_and(|name| !NAME.is_match(name))
        {
            issue(format!("{at}.provider"), "must be 1-64 of [A-Za-z0-9_.-]");
        }
        if let Some(problem) = profile.audience.as_deref().and_then(origin_problem) {
            issue(format!("{at}.audience"), problem);
        }
        if profile.claims.is_empty() {
            issue(format!("{at}.claims"), "must list at least one claim set");
        }
        for (field, value) in [("ttl", &profile.ttl), ("max_ttl", &profile.max_ttl)] {
            if value
                .as_deref()
                .is_some_and(|v| parse_duration(v).is_none())
            {
                issue(
                    format!("{at}.{field}"),
                    "must be a duration such as 15m or 1h",
                );
            }
        }

        if let Some(token) = &profile.token {
            if token.policies.is_empty() {
                issue(
                    format!("{at}.token.policies"),
                    "must list at least one policy",
                );
            }
            for (j, policy) in token.policies.iter().enumerate() {
                let at = format!("{at}.token.policies.{j}");
                if policy
                    .effect
                    .as_deref()
                    .is_some_and(|e| e != "allow" && e != "deny")
                {
                    issue(format!("{at}.effect"), "must be allow or deny");
                }
                if policy.permissions.is_empty() {
                    issue(
                        format!("{at}.permissions"),
                        "must list at least one permission",
                    );
                }
                for (k, permission) in policy.permissions.iter().enumerate() {
                    if permission.is_empty() {
                        issue(format!("{at}.permissions.{k}"), "must not be empty");
                    }
                }
                if policy.resources.is_empty() {
                    issue(format!("{at}.resources"), "must name at least one resource");
                }
                let nested = |value: &ResourceValue| matches!(value, ResourceValue::Nested(_));
                if policy.resources.values().any(nested) && !policy.resources.values().all(nested) {
                    issue(
                        format!("{at}.resources"),
                        "must be all \"*\" values or all nested maps, as Cloudflare takes them",
                    );
                }
                for key in policy.resources.keys() {
                    if !key.starts_with("com.cloudflare.") {
                        issue(
                            format!("{at}.resources.{key}"),
                            "must be a Cloudflare resource name",
                        );
                    }
                }
            }
        }

        if let Some(buckets) = &profile.buckets {
            if buckets.is_empty() {
                issue(format!("{at}.buckets"), "must list at least one bucket");
            }
            for (j, bucket) in buckets.iter().enumerate() {
                let at = format!("{at}.buckets.{j}");
                if !R2_BUCKET.is_match(&bucket.name) {
                    issue(format!("{at}.name"), "must be a valid R2 bucket name");
                }
                if !matches!(
                    bucket.permission.as_str(),
                    "object-read-write" | "object-read-only"
                ) {
                    issue(
                        format!("{at}.permission"),
                        "must be object-read-write or object-read-only",
                    );
                }
            }
        }
    }
    issues
}

fn origin_problem(value: &str) -> Option<&'static str> {
    match url::Url::parse(value) {
        Err(_) => Some("must be a URL"),
        Ok(url) if url.origin().ascii_serialization() != value => {
            Some("must be a bare origin such as https://cf-oidc-exchange.example.com")
        }
        Ok(_) => None,
    }
}

fn issuer_url_problem(value: &str) -> Option<&'static str> {
    match url::Url::parse(value) {
        Err(_) => Some("must be a URL"),
        Ok(_) if !is_issuer_url(value) => {
            Some("must be an https:// URL (http:// only on 127.0.0.1, localhost or [::1])")
        }
        Ok(_) => None,
    }
}
