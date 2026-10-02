//! The generated `ExchangeServiceApi`, over the broker's flows in [`crate::exchange`].

use std::future::Future;

use async_trait::async_trait;
use cf_oidc_exchange_sdk::v1::{
    DiscoveryResponse, ErrorResponse, ErrorResponseError, ExchangeServiceApi,
    ExchangeTokenResponse, Health, HealthResponse, HealthStatus, JwksResponse, RevokeTokenResponse,
    TokenExchangeRequest, TokenRevocationRequest,
};
use worker::{Env, console_error, send::SendFuture};

use crate::{
    config::Config,
    error::{ErrorCode, HttpError},
    exchange,
};

/// Serves the API over the Worker's bindings.
#[derive(Clone)]
pub struct ExchangeServiceHandler {
    env: Env,
}

impl ExchangeServiceHandler {
    pub fn new(env: Env) -> Self {
        Self { env }
    }

    /// Runs a flow with the loaded configuration. Fetch and WebCrypto futures
    /// aren't `Send`, which the router wants; a Worker is single-threaded, so the
    /// flow runs in a `SendFuture`.
    async fn run<T, F, Fut>(&self, flow: F) -> Result<T, HttpError>
    where
        F: FnOnce(Config) -> Fut,
        Fut: Future<Output = Result<T, HttpError>>,
    {
        let env = self.env.clone();
        SendFuture::new(async move { flow(Config::load(&env)?).await }).await
    }
}

/// The body of an error response: only the code. The reason and detail are for
/// the audit log, and failures nobody audited go to the error log.
fn body(err: &HttpError) -> ErrorResponse {
    if matches!(
        err.code,
        ErrorCode::Misconfigured | ErrorCode::Internal | ErrorCode::UpstreamError
    ) {
        console_error!("{}: {err}", err.code.as_str());
    }
    let error = match err.code {
        ErrorCode::BadRequest => ErrorResponseError::BadRequest,
        ErrorCode::Unauthorized => ErrorResponseError::Unauthorized,
        ErrorCode::Forbidden => ErrorResponseError::Forbidden,
        ErrorCode::NotFound => ErrorResponseError::NotFound,
        ErrorCode::Misconfigured => ErrorResponseError::Misconfigured,
        ErrorCode::UpstreamError => ErrorResponseError::UpstreamError,
        ErrorCode::Internal => ErrorResponseError::Internal,
    };
    ErrorResponse { error }
}

/// For responses that only document a `500`.
fn internal(err: &HttpError) -> ErrorResponse {
    let mut body = body(err);
    if !matches!(body.error, ErrorResponseError::Misconfigured) {
        body.error = ErrorResponseError::Internal;
    }
    body
}

#[async_trait]
impl ExchangeServiceApi for ExchangeServiceHandler {
    async fn exchange_token(&self, request: TokenExchangeRequest) -> ExchangeTokenResponse {
        let result = self
            .run(|config| async move { exchange::exchange_token(&config, &request).await })
            .await;
        match result {
            Ok(response) => ExchangeTokenResponse::Ok(response),
            Err(err) => {
                let body = body(&err);
                match err.code {
                    ErrorCode::BadRequest => ExchangeTokenResponse::BadRequest(body),
                    ErrorCode::Unauthorized => ExchangeTokenResponse::Unauthorized(body),
                    ErrorCode::Forbidden => ExchangeTokenResponse::Forbidden(body),
                    ErrorCode::NotFound => ExchangeTokenResponse::NotFound(body),
                    ErrorCode::UpstreamError => ExchangeTokenResponse::BadGateway(body),
                    ErrorCode::Misconfigured | ErrorCode::Internal => {
                        ExchangeTokenResponse::InternalServerError(body)
                    }
                }
            }
        }
    }

    async fn revoke_token(&self, request: TokenRevocationRequest) -> RevokeTokenResponse {
        let result = self
            .run(|config| async move { exchange::revoke_token(&config, &request).await })
            .await;
        match result {
            Ok(()) => RevokeTokenResponse::Ok,
            Err(err) => {
                let body = body(&err);
                match err.code {
                    ErrorCode::BadRequest => RevokeTokenResponse::BadRequest(body),
                    ErrorCode::Forbidden => RevokeTokenResponse::Forbidden(body),
                    ErrorCode::UpstreamError => RevokeTokenResponse::BadGateway(body),
                    _ => RevokeTokenResponse::InternalServerError(internal(&err)),
                }
            }
        }
    }

    async fn discovery(&self) -> DiscoveryResponse {
        match self
            .run(|config| async move { exchange::discovery(&config.policy) })
            .await
        {
            Ok(document) => DiscoveryResponse::Ok(document),
            Err(err) => DiscoveryResponse::InternalServerError(internal(&err)),
        }
    }

    async fn jwks(&self) -> JwksResponse {
        match self
            .run(|config| async move { exchange::jwks(&config).await })
            .await
        {
            Ok(jwks) => JwksResponse::Ok(jwks),
            Err(err) => JwksResponse::InternalServerError(internal(&err)),
        }
    }

    async fn health(&self) -> HealthResponse {
        match self
            .run(|config| async move { exchange::health(&config).await })
            .await
        {
            Ok(()) => HealthResponse::Ok(Health {
                status: HealthStatus::Ok,
            }),
            Err(err) => HealthResponse::InternalServerError(internal(&err)),
        }
    }
}
