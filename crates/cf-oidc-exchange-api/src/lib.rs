//! The broker as a Rust Worker: the `oidc.exchange.v1` API, generated from the
//! spec in `cf-oidc-exchange-sdk`, served over the Workers runtime.

pub mod audit;
pub mod cloudflare;
pub mod config;
pub mod error;
pub mod exchange;
pub mod github;
pub mod issuer;
pub mod oidc;
pub mod policy;
mod service;
pub mod webcrypto;

use axum::{middleware, response::Response as HttpResponse};
use cf_oidc_exchange_sdk::v1;
use tower_service::Service;
use worker::*;

use crate::{config::Config, service::handler::ExchangeServiceHandler};

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, _ctx: Context) -> Result<HttpResponse> {
    // The router checks each request against the spec, form bodies included,
    // before it reaches a handler.
    let mut router = v1::exchange_service_api_router(ExchangeServiceHandler::new(env))
        .merge(v1::HealthHandler::new().into_router())
        .layer(middleware::from_fn(service::layer::respond));
    Ok(router.call(req).await?)
}

/// The hourly cleanup of expired `cf-oidc:` tokens.
#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    let deleted = match Config::load(&env).await {
        Ok(config) => exchange::cleanup(&config).await,
        Err(err) => Err(err),
    };
    match deleted {
        Ok(deleted) => console_log!(
            "{}",
            serde_json::json!({ "event": "cleanup.done", "deleted": deleted })
        ),
        Err(err) => console_error!(
            "{}",
            serde_json::json!({ "event": "cleanup.failed", "reason": err.reason, "detail": err.detail })
        ),
    }
}
