//! Which profile a caller gets: their claims against each profile's.

use serde_json::{Map, Value};

use super::{MIN_TTL, Policy, Profile, REPOSITORY_PERMISSIONS, parse_duration};
use crate::error::{ErrorCode, HttpError};

/// A verified token's claims, or a person's as the broker looks them up.
pub type Claims = Map<String, Value>;

/// Whether a pattern is `<prefix>*`: one `*`, at the end, after a non-empty prefix.
pub(super) fn is_prefix_pattern(pattern: &str) -> bool {
    pattern.len() > 1 && pattern.find('*') == Some(pattern.len() - 1)
}

/// `<prefix>*` matches any value starting with the prefix, including across `/`.
/// Any other pattern must equal the value; the policy refuses other uses of `*`
/// when it loads.
pub fn glob(pattern: &str, value: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) if is_prefix_pattern(pattern) => value.starts_with(prefix),
        _ => pattern == value,
    }
}

/// Whether a person's role on the repo is at least `required`.
fn has_role(role: Option<&Value>, required: &str) -> bool {
    let rank = |role: &str| REPOSITORY_PERMISSIONS.iter().position(|r| *r == role);
    match (role.and_then(Value::as_str).and_then(rank), rank(required)) {
        (Some(role), Some(required)) => role >= required,
        _ => false,
    }
}

/// Whether one value of a token's claim matches one of the patterns.
fn matches_value(claim: &str, patterns: &[String], value: &Value) -> bool {
    let Some(value) = value.as_str() else {
        return false;
    };
    patterns.iter().any(|pattern| {
        if claim.ends_with("_id") {
            value == pattern
        } else {
            glob(pattern, value)
        }
    })
}

/// Whether every claim of the profile matches, each by any of its values.
pub fn matches(profile: &Profile, claims: &Claims) -> bool {
    profile.claims.iter().all(|(claim, patterns)| {
        match claim.as_str() {
            // Only a person's claims carry these: the teams they're in and their role on the repo.
            "team_id" => claims
                .get("team_ids")
                .and_then(Value::as_array)
                .is_some_and(|ids| {
                    ids.iter().any(|id| {
                        id.as_str()
                            .is_some_and(|id| patterns.iter().any(|p| p == id))
                    })
                }),
            "repository_permission" => patterns
                .first()
                .is_some_and(|required| has_role(claims.get(claim), required)),
            _ => match claims.get(claim) {
                // A claim that's a list in the token matches if any of its values does.
                Some(Value::Array(values)) => {
                    values.iter().any(|v| matches_value(claim, patterns, v))
                }
                Some(value) => matches_value(claim, patterns, value),
                None => false,
            },
        }
    })
}

/// Picks the profile to issue with, among those for `provider` and `audience`
/// only, or refuses with a `403` whose reason goes to the audit log.
pub fn select_profile<'a>(
    policy: &'a Policy,
    provider: &str,
    claims: &Claims,
    requested: Option<&str>,
    audience: &str,
) -> Result<&'a Profile, HttpError> {
    let mut profiles = policy
        .profiles
        .iter()
        .filter(|p| p.provider == provider && p.audience == audience);

    if let Some(requested) = requested {
        let profile = profiles.find(|p| p.name == requested);
        if let Some(profile) = profile
            && profile.enabled
            && matches(profile, claims)
        {
            return Ok(profile);
        }
        let named = policy.profiles.iter().find(|p| p.name == requested);
        let detail = match named {
            None => Some(format!("unknown profile {requested}")),
            Some(named) if named.provider != provider => {
                Some(format!("profile {requested} isn't for provider {provider}"))
            }
            Some(named) if named.audience != audience => {
                Some(format!("profile {requested} isn't for {audience}"))
            }
            Some(named) if !named.enabled => Some(format!("profile {requested} is disabled")),
            Some(_) => None,
        };
        let error = HttpError::new(ErrorCode::Forbidden, "profile_mismatch");
        return Err(match detail {
            Some(detail) => error.with_detail(detail),
            None => error,
        });
    }

    let candidates: Vec<&Profile> = profiles
        .filter(|p| p.enabled && matches(p, claims))
        .collect();
    match candidates.as_slice() {
        [] => Err(HttpError::new(ErrorCode::Forbidden, "no_match")),
        [profile] => Ok(profile),
        several => {
            let names: Vec<&str> = several.iter().map(|p| p.name.as_str()).collect();
            Err(HttpError::new(ErrorCode::Forbidden, "ambiguous").with_detail(names.join(",")))
        }
    }
}

/// Resolves the requested TTL against the profile, in milliseconds. Requests
/// above `max_ttl` are clamped, not refused.
pub fn clamp_ttl(requested: Option<&str>, profile: &Profile) -> Result<u64, HttpError> {
    let Some(requested) = requested else {
        return Ok(profile.ttl);
    };
    match parse_duration(requested) {
        Some(ttl) if ttl >= MIN_TTL => Ok(ttl.min(profile.max_ttl)),
        _ => Err(HttpError::new(ErrorCode::BadRequest, "invalid_ttl").with_detail(requested)),
    }
}
