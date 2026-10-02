//! The Rust SDK for the cf-oidc-exchange HTTP API: its types, a client, and the
//! traits a server of it implements, generated from the OpenAPI document.
//!
//! Everything is under [`v1`]:
//!
//! ```
//! use cf_oidc_exchange_sdk::v1::*;
//! ```
//!
//! # What is in it
//!
//! - **Types**: [`v1::TokenExchangeRequest`] and [`v1::TokenExchangeResponse`],
//!   [`v1::TokenRevocationRequest`], the discovery document and JWKS, and
//!   [`v1::ErrorResponse`], the body of every error.
//! - **Server** (`server` feature): `ExchangeServiceApi`, a response enum per
//!   operation, and `exchange_service_api_router`, an axum router over it that
//!   checks requests against the spec before they reach a handler.
//! - **Client** (`client` feature): `HttpClient`, a method per operation.
//! - **Health**: the endpoints a server answers beside the API,
//!   [`v1::HEALTH_LIVE_PATH`] and [`v1::HEALTH_READY_PATH`]; `HealthHandler`,
//!   which answers them (`server` feature), and `HealthClient`, which asks
//!   (`client` feature).
//!
//! # Generated code
//!
//! `openapi/oidc/exchange/v1/exchangev1.yaml` is the source. `build.rs` runs
//! [openapi-to-rust](https://github.com/gpu-cli/openapi-to-rust) over it into
//! `OUT_DIR`, so none of it is checked in or edited by hand. What is
//! hand-written is `src/oidc.exchange.v1.extra.rs`, included into `v1` beside
//! it: the health endpoints.

/// Everything for `oidc.exchange.v1`: the types, and the server and client the
/// crate's features enable.
pub mod v1 {
    // The generated module root opens with `unused_imports`, which `include!`
    // can't take: build.rs strips it, and it's restated here. The clippy lints
    // are the generator's style, not ours to fix.
    #![allow(
        unused_imports,
        clippy::collapsible_if,
        clippy::double_must_use,
        clippy::match_single_binding,
        clippy::redundant_field_names,
        clippy::result_large_err
    )]

    // The generated code, and its hand-written companion: each `.extra.rs` is
    // included into the module of the code it goes with.
    include!(concat!(env!("OUT_DIR"), "/exchangev1/mod.rs"));
    include!("oidc.exchange.v1.extra.rs");
}
