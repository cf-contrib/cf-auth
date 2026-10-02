//! The broker as a Rust Worker: the `oidc.exchange.v1` API, generated from the
//! spec in `cf-oidc-exchange-sdk`, served over the Workers runtime.
//!
//! It replaces `packages/cf-oidc-broker` once it passes the same tests.

mod service;

use axum::response::Response as HttpResponse;
use cf_oidc_exchange_sdk::v1;
use tower_service::Service;
use worker::*;

use crate::service::handler::ExchangeServiceHandler;

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, _ctx: Context) -> Result<HttpResponse> {
    // The router checks each request against the spec, form bodies included,
    // before it reaches a handler.
    let mut router = v1::exchange_service_api_router(ExchangeServiceHandler::new(env));
    Ok(router.call(req).await?)
}
