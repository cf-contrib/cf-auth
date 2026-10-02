//! An error that maps to an HTTP response: the code callers see, and the reason
//! and detail only the audit log gets.

use std::fmt;

/// The `error` of every non-2xx response. Deliberately generic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Misconfigured,
    UpstreamError,
    Internal,
}

impl ErrorCode {
    pub fn status(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::Misconfigured | Self::Internal => 500,
            Self::UpstreamError => 502,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Misconfigured => "misconfigured",
            Self::UpstreamError => "upstream_error",
            Self::Internal => "internal",
        }
    }
}

/// `reason` and `detail` are for the audit log only; callers just see `{ "error": code }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpError {
    pub code: ErrorCode,
    pub reason: &'static str,
    pub detail: Option<String>,
}

impl HttpError {
    pub fn new(code: ErrorCode, reason: &'static str) -> Self {
        Self {
            code,
            reason,
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.detail {
            Some(detail) => write!(f, "{}: {detail}", self.reason),
            None => f.write_str(self.reason),
        }
    }
}

impl std::error::Error for HttpError {}
