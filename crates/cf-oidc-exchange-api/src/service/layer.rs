//! What runs around the API's routes, as layers: exchange auth, and the
//! contract every response keeps.
//!
//! [`AuthenticateLayer`] is layered over the API's routes in the crate root.
//! Every token exchange needs an OIDC token from a provider the policy names,
//! as its `subject_token`. The layer verifies it with [`cf_oidc_core`] before
//! the request reaches the handler, and refuses the exchange if it isn't
//! valid, or none of its provider's claim sets matches. Everything else
//! passes straight through.
//!
//! The handler takes the caller's verified token from
//! [`cf_oidc_core::verified`], by the token as sent: never by decoding it
//! itself, so a token the layer didn't verify gets nothing.
//!
//! [`respond`] is layered over everything: it gives the generated validation's
//! refusals the `Error` body every error has, and every response its
//! `Cache-Control`.

use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    Json,
    body::{Body, to_bytes},
    extract::Request,
    http::{HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use cf_oidc_exchange_sdk::v1::{self, ErrorCode};
use serde_json::Value;
use tower_layer::Layer;
use tower_service::Service;
use tracing::warn;
use worker::send::SendFuture;

use super::config::{Config, PolicyConfig};

/// Where the token exchange is.
const TOKEN_PATH: &str = "/oauth/token";

/// The most of a request body read: the generated router's limit.
const MAX_BODY_BYTES: usize = 16 * 1024;

/// Authenticates every token exchange before the routes it's layered over,
/// against the providers in the Worker's policy. Every other request passes
/// through.
#[derive(Clone)]
pub struct AuthenticateLayer {
    config: Arc<Config>,
}

impl AuthenticateLayer {
    /// A layer that takes the providers from `config`.
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for AuthenticateLayer {
    type Service = Authenticate<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Authenticate {
            inner,
            config: self.config.clone(),
        }
    }
}

/// [`AuthenticateLayer`]'s service: authenticates an exchange, then hands the
/// request to the service it wraps.
#[derive(Clone)]
pub struct Authenticate<S> {
    inner: S,
    config: Arc<Config>,
}

impl<S> Service<Request> for Authenticate<S>
where
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        // The service polled ready is the one to call: a clone takes its
        // place for the next request.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let config = self.config.clone();

        Box::pin(async move {
            if req.method() != Method::POST || req.uri().path() != TOKEN_PATH {
                return inner.call(req).await;
            }

            // The token is in the form body, which the handler reads again.
            let (parts, body) = req.into_parts();
            let Ok(body) = to_bytes(body, MAX_BODY_BYTES).await else {
                let err = v1::Error::new(ErrorCode::BadRequest, "the body is over 16 KiB");
                return Ok((StatusCode::BAD_REQUEST, Json(err)).into_response());
            };
            let token = subject_token(&body);
            let req = Request::from_parts(parts, Body::from(body));

            // Without one, there's nothing to verify: the generated validation
            // refuses the request, and the handler would find no identity.
            let Some(token) = token else {
                return inner.call(req).await;
            };

            // Verifying fetches the issuer's keys, and fetch futures aren't
            // `Send`, which the router wants; a Worker is single-threaded, so
            // it runs in a `SendFuture`.
            let policy = config.policy();
            let accepted = SendFuture::new(async {
                let (provider, jwt) = cf_oidc_core::verify(&token, &policy.providers).await?;
                cf_oidc_core::authorize(&jwt.claims, &provider.claims)
            });
            match accepted.await {
                Ok(_) => inner.call(req).await,
                Err(err) => Ok(refuse(policy, err)),
            }
        })
    }
}

/// The `subject_token` of a form body, if it has one.
fn subject_token(body: &[u8]) -> Option<String> {
    let fields: Vec<(String, String)> = serde_urlencoded::from_bytes(body).ok()?;
    fields
        .into_iter()
        .find(|(name, value)| name == "subject_token" && !value.is_empty())
        .map(|(_, token)| token)
}

/// Refuses an exchange whose token `cf_oidc_core` didn't accept, with why
/// logged, and returned unless it's an issuer's fault.
fn refuse(policy: &PolicyConfig, err: cf_oidc_core::Error) -> Response {
    let (status, body) = match err {
        cf_oidc_core::Error::InvalidToken(message) => {
            warn!(event = "token.deny", error = "unauthorized", %message);
            let body = v1::Error::new(ErrorCode::Unauthorized, message);
            (StatusCode::UNAUTHORIZED, body)
        }
        cf_oidc_core::Error::InsufficientScope { issuer, subject } => {
            // Named as the policy names it.
            let provider = policy
                .providers
                .iter()
                .find(|provider| provider.issuer == issuer)
                .map_or(issuer.as_str(), |provider| provider.name.as_str());
            let message = format!("the token matches none of provider {provider}'s claim sets");
            warn!(
                event = "token.deny",
                provider,
                sub = subject,
                error = "forbidden",
                %message,
            );
            let body = v1::Error::new(ErrorCode::Forbidden, message);
            (StatusCode::FORBIDDEN, body)
        }
        cf_oidc_core::Error::TemporarilyUnavailable(message) => {
            warn!(event = "token.deny", error = "upstream_error", %message);
            let body = v1::Error::new(
                ErrorCode::UpstreamError,
                "the subject token's issuer couldn't be reached",
            );
            (StatusCode::BAD_GATEWAY, body)
        }
    };
    (status, Json(body)).into_response()
}

/// The contract's error body for requests the generated validation refuses,
/// and every response's `Cache-Control`.
///
/// The generated validation answers `application/problem+json` with `400`,
/// `413`, `415` or `422`; the contract has `400` with the `Error` body every
/// error has.
pub async fn respond(req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    let response = next.run(req).await;

    let problem = response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|value| value == "application/problem+json");
    let mut response = if problem {
        let body = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap_or_default();
        let err = v1::Error::new(ErrorCode::BadRequest, rejection(&body));
        // Logged like any refusal, with what was wrong, which never includes
        // the values sent.
        let event = if path == TOKEN_PATH {
            "token.deny"
        } else {
            "token.revoke"
        };
        warn!(event, error = err.error.as_str(), message = %err.message);
        (StatusCode::BAD_REQUEST, Json(err)).into_response()
    } else {
        response
    };

    // What verifying the broker's tokens takes is public and cacheable;
    // nothing else is.
    let cache_control = if path.starts_with("/.well-known/") && response.status() == StatusCode::OK
    {
        "public, max-age=300"
    } else {
        "no-store"
    };
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );
    response
}

/// What the generated validation found wrong, from its problem details: each
/// violation's place and what's wrong there, or the problem itself.
fn rejection(body: &[u8]) -> String {
    let problem: Value = serde_json::from_slice(body).unwrap_or_default();
    let violations: Vec<String> = problem["errors"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|violation| {
            let location = violation["location"].as_str().unwrap_or_default();
            let message = violation["message"].as_str().unwrap_or_default();
            format!("{location} {message}")
        })
        .collect();
    if !violations.is_empty() {
        return violations.join("; ");
    }
    match problem["code"].as_str() {
        Some("unsupported_media_type") => {
            "the body must be form-encoded (application/x-www-form-urlencoded)".into()
        }
        _ => problem["title"]
            .as_str()
            .unwrap_or("the request doesn't fit the API")
            .to_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn finds_the_subject_token_in_the_form() {
        let form = |body: &str| subject_token(body.as_bytes());
        assert_eq!(
            form("grant_type=x&subject_token=a.b.c").as_deref(),
            Some("a.b.c")
        );
        assert_eq!(form("subject_token=a%2Bb").as_deref(), Some("a+b"));
        assert_eq!(form("subject_token="), None);
        assert_eq!(form("grant_type=x"), None);
        assert_eq!(form("{\"subject_token\":\"a\"}"), None);
    }

    #[test]
    fn says_what_the_validation_found_wrong() {
        let problem = json!({
            "type": "x", "title": "Request validation failed", "status": 422, "code": "request_validation_failed",
            "errors": [
                { "code": "min_length", "location": "/body/token", "message": "does not meet the length constraint" },
                { "code": "required", "location": "/body/grant_type", "message": "is required" },
            ],
        });
        assert_eq!(
            rejection(problem.to_string().as_bytes()),
            "/body/token does not meet the length constraint; /body/grant_type is required"
        );
        let media = json!({ "type": "x", "title": "Unsupported media type", "status": 415, "code": "unsupported_media_type" });
        assert_eq!(
            rejection(media.to_string().as_bytes()),
            "the body must be form-encoded (application/x-www-form-urlencoded)"
        );
    }
}
