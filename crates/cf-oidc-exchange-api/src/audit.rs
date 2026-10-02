//! The audit log: one JSON line per event, in Workers Logs. Never token values,
//! R2 secrets or raw JWTs.

use std::collections::BTreeSet;

use serde::ser::{Serialize, SerializeMap, Serializer};
use serde_json::Value;

use crate::service::config::Claims;

/// An audit line under construction: the event, then who it's about, then the rest.
#[must_use]
pub struct Audit {
    /// In the order they were added, which is the order they're written in.
    fields: Vec<(String, Value)>,
}

impl Serialize for Audit {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.fields.len()))?;
        for (key, value) in &self.fields {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

/// Whether a claim's value is one to write down: a string, number or boolean.
fn scalar(value: &Value) -> bool {
    match value {
        Value::String(text) => !text.is_empty(),
        Value::Number(_) | Value::Bool(_) => true,
        _ => false,
    }
}

impl Audit {
    pub fn new(event: &'static str) -> Self {
        Self {
            fields: vec![("event".into(), event.into())],
        }
    }

    /// Adds a field, unless it's absent or already there.
    pub fn with(mut self, key: &str, value: impl Into<Value>) -> Self {
        let value = value.into();
        if !value.is_null() && !self.fields.iter().any(|(k, _)| k == key) {
            self.fields.push((key.into(), value));
        }
        self
    }

    /// Adds the provider and profile, and who the caller is: their token's
    /// `sub`, and the claims in `names`, the ones the policy matches on, which
    /// are never secret.
    pub fn caller<'n>(
        mut self,
        provider: Option<&str>,
        profile: Option<&str>,
        claims: Option<&Claims>,
        names: impl IntoIterator<Item = &'n str>,
    ) -> Self {
        self = self.with("provider", provider).with("profile", profile);
        let names: BTreeSet<&str> = names.into_iter().collect();
        for key in std::iter::once("sub").chain(names) {
            let value = claims.and_then(|claims| claims.get(key));
            if let Some(value) = value.filter(|value| scalar(value)) {
                self = self.with(key, value.clone());
            }
        }
        self
    }

    /// The line, as written.
    pub fn line(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Writes the line: a warning for denials and an invalid policy.
    pub fn emit(self) {
        let line = self.line();
        if matches!(
            self.fields[0].1.as_str(),
            Some("token.deny" | "policy.invalid")
        ) {
            worker::console_warn!("{line}");
        } else {
            worker::console_log!("{line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn writes_the_event_who_and_then_the_rest() {
        let claims = json!({
            "sub": "repo:example-org/api:ref:refs/heads/main",
            "repository": "example-org/api",
            "repository_id": 200000003,
            "email": "someone@example.com",
            "ref": "",
        });
        let audit = Audit::new("token.mint")
            .caller(
                Some("github"),
                Some("workers-deploy"),
                claims.as_object(),
                ["repository_id", "repository", "ref", "repository"],
            )
            .with("token_id", "tok-1")
            .with("detail", None::<String>);
        assert_eq!(
            audit.line(),
            r#"{"event":"token.mint","provider":"github","profile":"workers-deploy","sub":"repo:example-org/api:ref:refs/heads/main","repository":"example-org/api","repository_id":200000003,"token_id":"tok-1"}"#
        );
    }

    #[test]
    fn never_overwrites_a_field() {
        let audit = Audit::new("token.deny")
            .with("reason", "first")
            .with("reason", "second");
        assert_eq!(audit.line(), r#"{"event":"token.deny","reason":"first"}"#);
    }
}
