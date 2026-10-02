//! `ExchangeServiceApi`, the trait the SDK's router calls.
//!
//! Still a skeleton: every operation answers `500 internal` until the
//! TypeScript broker's policy, verification and minting are ported.

use cf_oidc_exchange_sdk::v1::{
    DiscoveryResponse, ErrorResponse, ErrorResponseError, ExchangeServiceApi,
    ExchangeTokenResponse, JwksResponse, RevokeTokenResponse, TokenExchangeRequest,
    TokenRevocationRequest,
};
use worker::Env;

/// The broker's service, holding the Worker's bindings.
#[derive(Clone)]
pub struct ExchangeServiceHandler {
    // Read by the operations once they're ported.
    #[allow(dead_code)]
    env: Env,
}

impl ExchangeServiceHandler {
    pub fn new(env: Env) -> Self {
        Self { env }
    }
}

/// The body every error has: only the code; the reason goes to the audit log.
fn internal() -> ErrorResponse {
    ErrorResponse {
        error: ErrorResponseError::Internal,
    }
}

#[async_trait::async_trait]
impl ExchangeServiceApi for ExchangeServiceHandler {
    async fn exchange_token(&self, _body: TokenExchangeRequest) -> ExchangeTokenResponse {
        ExchangeTokenResponse::InternalServerError(internal())
    }

    async fn revoke_token(&self, _body: TokenRevocationRequest) -> RevokeTokenResponse {
        RevokeTokenResponse::InternalServerError(internal())
    }

    async fn discovery(&self) -> DiscoveryResponse {
        DiscoveryResponse::InternalServerError(internal())
    }

    async fn jwks(&self) -> JwksResponse {
        JwksResponse::InternalServerError(internal())
    }
}
