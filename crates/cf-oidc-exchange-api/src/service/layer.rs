//! What every response gets, around the generated router: the contract's error
//! body for requests the generated validation rejects or no route serves, and
//! its `Cache-Control`.

use axum::{
    Json,
    body::to_bytes,
    extract::Request,
    http::{HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use cf_oidc_exchange_sdk::v1::{Error, ErrorCode};
use serde_json::Value;

use crate::audit::Audit;

/// The most of a rejected request's problem details read, to audit it.
const MAX_PROBLEM_BYTES: usize = 16 * 1024;

/// The generated validation answers `application/problem+json` with `400`,
/// `413`, `415` or `422`; the contract has `400` with the `Error` body every
/// error has. A path no route serves, or a method it doesn't, is a `404`.
pub async fn respond(req: Request, next: Next) -> Response {
    let (method, path) = (req.method().clone(), req.uri().path().to_owned());
    let response = next.run(req).await;
    let mut response = contract(&method, &path, response).await;

    // The metadata to verify the broker's tokens is public and cacheable; nothing else is.
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

async fn contract(method: &Method, path: &str, response: Response) -> Response {
    let problem = response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|value| value == "application/problem+json");
    if problem {
        let body = to_bytes(response.into_body(), MAX_PROBLEM_BYTES)
            .await
            .unwrap_or_default();
        let err = Error::new(ErrorCode::BadRequest, rejection(&body));
        // Audited like any refusal, with what was wrong, which never includes the values sent.
        let event = if path == "/oauth/revoke" {
            "token.revoke"
        } else {
            "token.deny"
        };
        Audit::new(event)
            .with("error", err.error.as_str())
            .with("message", err.message.as_str())
            .emit();
        return (StatusCode::BAD_REQUEST, Json(err)).into_response();
    }
    // The generated router's own 404 and 405 have no body.
    if matches!(
        response.status(),
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
    ) && response.headers().get(header::CONTENT_TYPE).is_none()
    {
        let err = Error::new(ErrorCode::NotFound, format!("no route for {method} {path}"));
        return (StatusCode::NOT_FOUND, Json(err)).into_response();
    }
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
