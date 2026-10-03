//! Companions for the generated models: constructors, and what makes [`Error`]
//! an error the Worker can return with `?`.

use std::fmt;

use crate::v1::{Error, ErrorCode};

impl Error {
    /// An OAuth error response (RFC 6749 §5.2):
    /// `{ "error": "<code>", "error_description": "<what went wrong>" }`.
    pub fn new(code: ErrorCode, description: impl Into<String>) -> Self {
        Self {
            error: code,
            error_description: description.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error, self.error_description)
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_its_code_and_message() {
        let err = Error::new(ErrorCode::InvalidRequest, "no profile matches the token");
        assert_eq!(
            err.to_string(),
            "invalid_request: no profile matches the token"
        );
    }
}
