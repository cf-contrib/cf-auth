//! Companions for the generated models: constructors, and what makes [`Error`]
//! an error the Worker can return with `?`.

use std::fmt;

use crate::v1::{Error, ErrorCode};

impl Error {
    /// An error in the shape shared with cf-nix-cache:
    /// `{ "error": "<code>", "message": "<what went wrong>" }`.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            error: code,
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error, self.message)
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_its_code_and_message() {
        let err = Error::new(ErrorCode::Forbidden, "no profile matches the token");
        assert_eq!(err.to_string(), "forbidden: no profile matches the token");
    }
}
