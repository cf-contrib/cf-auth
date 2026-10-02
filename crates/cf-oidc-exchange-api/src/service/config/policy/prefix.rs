//! R2 prefixes: bucket prefix templates filled in from the caller's claims.
//!
//! The prefix is the only thing keeping one caller out of another's keys, so
//! these checks run on the template when the policy loads and again on every
//! filled-in prefix.

use std::sync::LazyLock;

use cf_oidc_exchange_sdk::v1::{Error, ErrorCode};
use regex::Regex;
use serde_json::Value;

use super::{Bucket, Claims};

/// A `{claim}` placeholder. Not `${claim}`, which Terraform's templatefile would try to fill in.
static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{([^{}]*)\}").unwrap());

static WHOLE_PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\{[^{}]*\}$").unwrap());

/// What a placeholder can name: a claim, as issuers name them.
static CLAIM_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new("^[A-Za-z0-9_]{1,64}$").unwrap());

/// A value that can fill a placeholder: segments of letters, digits, `.`, `_`
/// and `-`, joined by `/`.
static SEGMENTS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$").unwrap());

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
        if !CLAIM_NAME.is_match(&caps[1]) {
            return Some(format!(
                "placeholder {} must name a claim: 1-64 of [A-Za-z0-9_]",
                &caps[0]
            ));
        }
    }
    if PLACEHOLDER.replace_all(template, "").contains(['{', '}']) {
        return Some("has an unmatched { or }".into());
    }
    // A placeholder must fill whole path segments. Otherwise two callers could get
    // the same prefix: {owner}{id} is "a1"+"23" and "a"+"123" alike.
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

/// A claim's value as it fills a placeholder: a string, or a number as written.
fn value(claims: &Claims, name: &str) -> Option<String> {
    match claims.get(name)? {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// Fills in a bucket's prefix templates from the verified token's claims, or
/// refuses with a `403` if a claim is missing or can't safely be used in a key.
///
/// A value can span several path segments, `owner/repo`, only when it's the
/// template's one placeholder. With several, each fills exactly one, so two
/// callers can never fill a template to the same prefix.
pub fn r2_prefixes(bucket: &Bucket, claims: &Claims) -> Result<Vec<String>, Error> {
    let refuse = |why: String| {
        Error::new(
            ErrorCode::Forbidden,
            format!("bucket {}: {why}", bucket.name),
        )
    };
    bucket
        .prefixes
        .iter()
        .map(|template| {
            let placeholders = PLACEHOLDER.captures_iter(template).count();
            let mut prefix = String::with_capacity(template.len());
            let mut rest = 0;
            for caps in PLACEHOLDER.captures_iter(template) {
                let (placeholder, name) = (caps.get(0).unwrap(), &caps[1]);
                let usable = |value: &String| {
                    SEGMENTS.is_match(value) && (placeholders == 1 || !value.contains('/'))
                };
                let Some(value) = value(claims, name).filter(usable) else {
                    return Err(refuse(format!(
                        "the {name} claim is missing or not usable in a prefix"
                    )));
                };
                prefix.push_str(&template[rest..placeholder.start()]);
                prefix.push_str(&value);
                rest = placeholder.end();
            }
            prefix.push_str(&template[rest..]);
            match prefix_problem(&prefix) {
                Some(problem) => Err(refuse(format!("prefix {prefix} {problem}"))),
                None => Ok(prefix),
            }
        })
        .collect()
}
