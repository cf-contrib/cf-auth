//! What every response gets, around the generated router: the contract's error
//! body for requests the generated validation rejects or no route serves, and
//! its `Cache-Control`.

use axum::{
    body::to_bytes,
    extract::Request,
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use crate::audit::Audit;

/// The most of a rejected request's problem details read, to audit it.
const MAX_PROBLEM_BYTES: usize = 16 * 1024;

/// The generated validation answers `application/problem+json` with `400`,
/// `413`, `415` or `422`; the contract has `400 {"error":"bad_request"}`. A path
/// no route serves, or a method it doesn't, is `404 {"error":"not_found"}`.
pub async fn respond(req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    let response = next.run(req).await;
    let mut response = contract(&path, response).await;

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

async fn contract(path: &str, response: Response) -> Response {
    let problem = response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|value| value == "application/problem+json");
    if problem {
        let body = to_bytes(response.into_body(), MAX_PROBLEM_BYTES)
            .await
            .unwrap_or_default();
        audit_rejection(path, &body);
        return error(StatusCode::BAD_REQUEST, "bad_request");
    }
    // The generated router's own 404 and 405 have no body.
    if matches!(
        response.status(),
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
    ) && response.headers().get(header::CONTENT_TYPE).is_none()
    {
        return error(StatusCode::NOT_FOUND, "not_found");
    }
    response
}

fn error(status: StatusCode, code: &str) -> Response {
    (status, axum::Json(json!({ "error": code }))).into_response()
}

/// Audits a request the generated validation rejected, with what was wrong,
/// which never includes the values sent.
fn audit_rejection(path: &str, body: &[u8]) {
    let problem: Value = serde_json::from_slice(body).unwrap_or_default();
    let mut detail = problem["code"]
        .as_str()
        .unwrap_or("invalid_request")
        .to_string();
    for violation in problem["errors"].as_array().into_iter().flatten() {
        let location = violation["location"].as_str().unwrap_or_default();
        let message = violation["message"].as_str().unwrap_or_default();
        detail.push_str(&format!("; {location} {message}"));
    }
    let event = if path == "/oauth/revoke" {
        "token.revoke"
    } else {
        "token.deny"
    };
    Audit::new(event)
        .with("reason", "invalid_request")
        .with("detail", detail)
        .emit();
}
