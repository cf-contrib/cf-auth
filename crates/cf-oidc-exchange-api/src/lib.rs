//! The Worker half of cf-oidc-exchange: a broker that exchanges OIDC tokens
//! for short-lived Cloudflare credentials, or its own tokens for other
//! services.
//!
//! Each request reads the Worker's configuration from its bindings, then
//! serves the SDK's router over it: the exchange API, with the auth layer
//! authenticating every exchange before its handler, and the health endpoints
//! beside it, with OAuth's rules for responses over all of it. A
//! configuration that can't be read, an unset account, a Cloudflare token
//! that isn't a Secrets Store binding or an invalid policy, fails every
//! request instead, with a `server_error`.
//!
//! The hourly cron deletes the expired tokens the broker minted.

mod service;

use std::sync::Arc;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response as HttpResponse},
};
use cf_oidc_exchange_sdk::v1::{self, ErrorCode};
use tower_service::Service;
use tracing::{error, info};
use tracing_web::MakeWebConsoleWriter;
use worker::*;

use crate::service::{
    config::Config,
    handler::ExchangeServiceHandler,
    layer::{AuthenticateLayer, OAuthResponseLayer},
};

/// Logs as JSON lines, one per event with its fields at the top level, which
/// Workers Logs indexes. The time is left to Workers Logs.
#[event(start)]
fn start() {
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_target(false)
        .without_time()
        .with_writer(MakeWebConsoleWriter::new())
        .init();
}

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, _ctx: Context) -> Result<HttpResponse> {
    let mut router = match Config::from_env(&env) {
        // The router checks each request against the spec, form bodies
        // included, before it reaches a handler; the auth layer
        // authenticates every exchange first.
        Ok(config) => {
            let config = Arc::new(config);
            v1::exchange_service_api_router(ExchangeServiceHandler::new(config.clone()))
                .layer(AuthenticateLayer::new(config))
                // Merged after the layer, so outside it. Not in the spec:
                // they're for whoever deploys the Worker, not its clients.
                .merge(v1::HealthHandler::new().into_router())
                // Over everything, the health endpoints too.
                .layer(OAuthResponseLayer)
        }
        // Misconfigured, the Worker serves nothing: every request, the health
        // endpoints' too, is refused, with why logged.
        Err(err) => {
            let msg = err.to_string();
            axum::Router::new().fallback(move || async move {
                error!(event = "misconfigured", message = %msg);
                let body = v1::Error::new(ErrorCode::ServerError, "the broker is misconfigured");
                (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
            })
        }
    };
    Ok(router.call(req).await?)
}

/// The hourly cleanup of expired `cf-oidc:` tokens.
#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    let deleted = match Config::from_env(&env) {
        Ok(config) => {
            ExchangeServiceHandler::new(Arc::new(config))
                .cleanup()
                .await
        }
        Err(err) => Err(v1::Error::new(ErrorCode::ServerError, err.to_string())),
    };
    match deleted {
        Ok(deleted) => info!(event = "cleanup.done", deleted),
        Err(err) => error!(
            event = "cleanup.failed",
            error = err.error.as_str(),
            message = %err.error_description,
        ),
    }
}
