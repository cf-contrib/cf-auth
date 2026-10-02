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

use axum::{middleware, response::Response as HttpResponse};
use cf_oidc_exchange_sdk::v1;
use serde_json::json;
use tower_service::Service;
use worker::*;

use crate::service::{handler::ExchangeServiceHandler, layer};

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, _ctx: Context) -> Result<HttpResponse> {
    // The router checks each request against the spec, form bodies included,
    // before it reaches a handler. The layer gives every response the
    // contract's error body and its Cache-Control.
    let mut router = v1::exchange_service_api_router(ExchangeServiceHandler::new(env))
        // Not in the spec: they're for whoever deploys the Worker, not its clients.
        .merge(v1::HealthHandler::new().into_router())
        .layer(middleware::from_fn(layer::respond));
    Ok(router.call(req).await?)
}

/// The hourly cleanup of expired `cf-oidc:` tokens.
#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    match ExchangeServiceHandler::new(env).cleanup().await {
        Ok(deleted) => console_log!("{}", json!({ "event": "cleanup.done", "deleted": deleted })),
        Err(err) => console_error!(
            "{}",
            json!({ "event": "cleanup.failed", "error": err.error.as_str(), "message": err.message })
        ),
    }
}
