//! The broker as a Rust Worker: the `oidc.exchange.v1` API, generated from the
//! spec in `cf-oidc-exchange-sdk`, served over the Workers runtime.

mod audit;
mod cloudflare;
mod github;
mod issuer;
mod oidc;
mod policy;
mod service;
mod webcrypto;

use std::sync::Arc;

use axum::{
    Json,
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response as HttpResponse},
};
use cf_oidc_exchange_sdk::v1::{self, ErrorCode};
use serde_json::json;
use tower_service::Service;
use worker::*;

use crate::service::{config::Config, handler::ExchangeServiceHandler, layer};

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, _ctx: Context) -> Result<HttpResponse> {
    let mut router = match Config::from_env(&env).await {
        // The router checks each request against the spec, form bodies
        // included, before it reaches a handler. The layer gives every
        // response the contract's error body and its Cache-Control.
        Ok(config) => {
            v1::exchange_service_api_router(ExchangeServiceHandler::new(Arc::new(config)))
                // Not in the spec: they're for whoever deploys the Worker, not its clients.
                .merge(v1::HealthHandler::new().into_router())
                .layer(middleware::from_fn(layer::respond))
        }
        // Misconfigured, the Worker serves nothing: every request, the health
        // endpoints' too, is refused, with why logged.
        Err(err) => {
            let msg = err.to_string();
            axum::Router::new().fallback(move || async move {
                console_error!("{msg}");
                let body = v1::Error::new(
                    ErrorCode::Misconfigured,
                    "the broker is misconfigured; its logs say why",
                );
                (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
            })
        }
    };
    Ok(router.call(req).await?)
}

/// The hourly cleanup of expired `cf-oidc:` tokens.
#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    let deleted = match Config::from_env(&env).await {
        Ok(config) => {
            ExchangeServiceHandler::new(Arc::new(config))
                .cleanup()
                .await
        }
        Err(err) => Err(err),
    };
    match deleted {
        Ok(deleted) => console_log!("{}", json!({ "event": "cleanup.done", "deleted": deleted })),
        Err(err) => console_error!(
            "{}",
            json!({ "event": "cleanup.failed", "error": err.error.as_str(), "message": err.message })
        ),
    }
}
