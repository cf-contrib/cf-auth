//! R2 prefixes: bucket prefix templates filled in from the caller's claims.
//!
//! The prefix is the only thing keeping one repo out of another's keys, so these
//! checks run on the template when the policy loads and again on every
//! filled-in prefix.

use std::sync::LazyLock;

use regex::Regex;

use super::{Bucket, Claims};
use crate::error::{ErrorCode, HttpError};

/// A `{claim}` placeholder. Not `${claim}`, which Terraform's templatefile would try to fill in.
static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{([^{}]*)\}").unwrap());

static WHOLE_PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\{[^{}]*\}$").unwrap());

/// Claims a bucket prefix can be built from, and what a value must look like to be
/// used: the characters GitHub allows in owner and repo names, or a numeric ID.
static PREFIX_CLAIMS: LazyLock<[(&str, Regex); 4]> = LazyLock::new(|| {
    [
        (
            "repository",
            Regex::new("^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$").unwrap(),
        ),
        ("repository_owner", Regex::new("^[A-Za-z0-9._-]+$").unwrap()),
        ("repository_id", Regex::new("^[0-9]+$").unwrap()),
        ("repository_owner_id", Regex::new("^[0-9]+$").unwrap()),
    ]
});

fn prefix_claim(name: &str) -> Option<&'static Regex> {
    PREFIX_CLAIMS
        .iter()
        .find(|(claim, _)| *claim == name)
        .map(|(_, re)| re)
}

/// Checks a filled-in prefix. Returns what's wrong with it, if anything.
fn prefix_problem(prefix: &str) -> Option<&'static str> {
    if prefix.starts_with('/') {
        return Some("must not start with /");
    }
    // Without it, github.com/org/site would also cover github.com/org/site-old/.
    let Some(path) = prefix.strip_suffix('/') else {
        return Some("must end with /");
    };
    if prefix.contains('*') {
        return Some("must not contain *");
    }
    if prefix.contains("..") {
        return Some("must not contain ..");
    }
    if prefix.chars().any(char::is_control) {
        return Some("must not contain control characters");
    }
    if path
        .split('/')
        .any(|segment| segment.is_empty() || segment == ".")
    {
        return Some("must not contain empty or . path segments");
    }
    None
}

/// Checks a prefix template from the policy.
pub(super) fn template_problem(template: &str) -> Option<String> {
    if template.contains("${") {
        return Some("use {claim} placeholders, not ${claim}".into());
    }
    for caps in PLACEHOLDER.captures_iter(template) {
        if prefix_claim(&caps[1]).is_none() {
            let names: Vec<&str> = PREFIX_CLAIMS.iter().map(|(claim, _)| *claim).collect();
            return Some(format!(
                "unknown placeholder {}; use one of {}",
                &caps[0],
                names.join(", ")
            ));
        }
    }
    if PLACEHOLDER.replace_all(template, "").contains(['{', '}']) {
        return Some("has an unmatched { or }".into());
    }
    // A placeholder must fill whole path segments. Otherwise two repos could get the
    // same prefix: {repository_owner}{repository_id} is "a1"+"23" and "a"+"123" alike.
    if template
        .split('/')
        .any(|segment| segment.contains('{') && !WHOLE_PLACEHOLDER.is_match(segment))
    {
        return Some(
            "a placeholder must be a whole path segment, e.g. github.com/{repository}/".into(),
        );
    }
    prefix_problem(&PLACEHOLDER.replace_all(template, "x")).map(String::from)
}

/// Fills in a bucket's prefix templates from the verified token's claims, or
/// refuses with a `403` if a claim is missing or can't safely be used in a key.
pub fn r2_prefixes(bucket: &Bucket, claims: &Claims) -> Result<Vec<String>, HttpError> {
    let refuse = |detail: String| {
        HttpError::new(ErrorCode::Forbidden, "invalid_r2_prefix").with_detail(detail)
    };
    bucket
        .prefixes
        .iter()
        .map(|template| {
            let mut prefix = String::with_capacity(template.len());
            let mut rest = 0;
            for caps in PLACEHOLDER.captures_iter(template) {
                let (placeholder, name) = (caps.get(0).unwrap(), &caps[1]);
                let value = claims.get(name).and_then(|value| value.as_str());
                let value = match (value, prefix_claim(name)) {
                    (Some(value), Some(allowed)) if allowed.is_match(value) => value,
                    _ => {
                        return Err(refuse(format!(
                            "{name} claim is missing or not usable in a prefix"
                        )));
                    }
                };
                prefix.push_str(&template[rest..placeholder.start()]);
                prefix.push_str(value);
                rest = placeholder.end();
            }
            prefix.push_str(&template[rest..]);
            match prefix_problem(&prefix) {
                Some(problem) => Err(refuse(format!("{prefix}: {problem}"))),
                None => Ok(prefix),
            }
        })
        .collect()
}
