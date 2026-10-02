//! Claim sets, as cf-nix-cache has them: what a token's claims must be for a
//! provider to take it, or a profile to give it something.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{Map, Value};

/// A verified token's claims.
pub type Claims = Map<String, Value>;

/// Claim name to pattern. Matches when every claim matches.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(try_from = "Map<String, Value>")]
pub struct ClaimSet(BTreeMap<String, Pattern>);

impl TryFrom<Map<String, Value>> for ClaimSet {
    type Error = String;

    fn try_from(raw: Map<String, Value>) -> Result<Self, String> {
        if raw.is_empty() {
            return Err("a claim set must match at least one claim".to_string());
        }

        let mut claims = BTreeMap::new();
        for (claim, value) in raw {
            // IDs may be written as JSON numbers; most issuers send strings.
            let pattern = match value {
                Value::String(s) if !s.is_empty() => s,
                Value::Number(n) if n.is_u64() => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => {
                    return Err(format!(
                        "claim {claim} must be a non-empty string, a number or a boolean"
                    ));
                }
            };
            let pattern = Pattern::parse(&pattern)
                .filter(|pattern| !is_id_claim(&claim) || matches!(pattern, Pattern::Exact(_)))
                .ok_or_else(|| {
                    if is_id_claim(&claim) {
                        format!("claim {claim}: ID claims must match exactly")
                    } else {
                        format!("claim {claim}: * may only end a pattern, after a prefix")
                    }
                })?;
            claims.insert(claim, pattern);
        }
        Ok(Self(claims))
    }
}

impl ClaimSet {
    pub fn matches(&self, claims: &Claims) -> bool {
        self.0
            .iter()
            .all(|(claim, pattern)| match claims.get(claim) {
                // A list claim (`groups`, `amr`) matches if any entry does.
                Some(Value::Array(values)) => {
                    values.iter().any(|value| pattern.matches_value(value))
                }
                Some(value) => pattern.matches_value(value),
                None => false,
            })
    }

    /// The claims it matches on.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }
}

/// A claim's expected value: exact, or a prefix written with one trailing
/// `*` (`example-org/*`). `*_id` claims must be exact.
#[derive(Clone, Debug, PartialEq)]
enum Pattern {
    Exact(String),
    Prefix(String),
}

impl Pattern {
    /// `None` for a `*` anywhere but at the end of a non-empty prefix.
    fn parse(pattern: &str) -> Option<Self> {
        match pattern.strip_suffix('*') {
            Some(prefix) if !prefix.is_empty() && !prefix.contains('*') => {
                Some(Self::Prefix(prefix.to_string()))
            }
            Some(_) => None,
            None if pattern.contains('*') => None,
            None => Some(Self::Exact(pattern.to_string())),
        }
    }

    fn matches(&self, value: &str) -> bool {
        match self {
            Self::Exact(expected) => value == expected,
            Self::Prefix(prefix) => value.starts_with(prefix.as_str()),
        }
    }

    /// Numbers and booleans compare as they're written in JSON.
    fn matches_value(&self, value: &Value) -> bool {
        match value {
            Value::String(s) => self.matches(s),
            Value::Number(n) => self.matches(&n.to_string()),
            Value::Bool(b) => self.matches(if *b { "true" } else { "false" }),
            _ => false,
        }
    }
}

fn is_id_claim(claim: &str) -> bool {
    claim.ends_with("_id")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn set(value: Value) -> Result<ClaimSet, String> {
        serde_json::from_value(value).map_err(|err| err.to_string())
    }

    fn claims() -> Claims {
        json!({
            "sub": "repo:example-org/app:ref:refs/heads/main",
            "repository": "example-org/app",
            "repository_id": "200000002",
            "repository_owner_id": "100000001",
            "ref": "refs/heads/main",
            "groups": ["cache-readers", "cache-uploaders"],
            "email_verified": true,
        })
        .as_object()
        .unwrap()
        .clone()
    }

    #[test]
    fn rejects_bad_claim_sets() {
        let cases = [
            (json!({}), "a claim set must match at least one claim"),
            (
                json!({ "repository_id": "2000*" }),
                "claim repository_id: ID claims must match exactly",
            ),
            (json!({ "ref": "" }), "non-empty string"),
            (json!({ "ref": null }), "non-empty string"),
            (json!({ "ref": -1 }), "non-empty string"),
            (json!({ "ref": "*" }), "claim ref: * may only end a pattern"),
            (json!({ "ref": "*main" }), "may only end a pattern"),
            (json!({ "ref": "refs/*/main" }), "may only end a pattern"),
            (json!({ "ref": "refs/**" }), "may only end a pattern"),
        ];
        for (value, expected) in cases {
            let err = set(value.clone()).unwrap_err();
            assert!(err.contains(expected), "{value}: {err}");
        }
    }

    #[test]
    fn pattern_is_exact_or_a_trailing_prefix() {
        let parse = |p| Pattern::parse(p).unwrap();
        assert!(parse("example-org/*").matches("example-org/app"));
        assert!(parse("refs/heads/*").matches("refs/heads/feature/x"));
        assert!(parse("refs/heads/main").matches("refs/heads/main"));
        assert!(!parse("refs/heads/main").matches("refs/heads/main2"));
        assert!(!parse("example-org/*").matches("other-org/app"));
        // Regex metacharacters are literal.
        assert!(parse("a.b*").matches("a.bc"));
        assert!(!parse("a.b*").matches("axbc"));
        for pattern in ["*", "*x", "a*b", "a**"] {
            assert_eq!(Pattern::parse(pattern), None, "{pattern}");
        }
    }

    #[test]
    fn needs_every_claim_to_match() {
        let set = set(json!({ "repository": "example-org/*", "ref": "refs/heads/main" })).unwrap();
        assert!(set.matches(&claims()));

        let mut other_ref = claims();
        other_ref.insert("ref".into(), "refs/heads/dev".into());
        assert!(!set.matches(&other_ref));
        other_ref.remove("ref");
        assert!(!set.matches(&other_ref), "a missing claim never matches");
    }

    #[test]
    fn matches_lists_numbers_and_booleans() {
        let matches = |value: Value| set(value).unwrap().matches(&claims());
        assert!(
            matches(json!({ "groups": "cache-uploaders" })),
            "a list matches if any entry does"
        );
        assert!(
            matches(json!({ "email_verified": true })),
            "booleans compare as written"
        );
        assert!(
            matches(json!({ "repository_id": 200000002 })),
            "numbers compare as written"
        );
        assert!(!matches(json!({ "groups": "admins" })));
        assert!(
            !matches(json!({ "repository_id": "2000000021" })),
            "IDs compare exactly"
        );
    }
}
