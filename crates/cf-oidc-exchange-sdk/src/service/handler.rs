//! The health endpoints a server of the API answers beside it, and a client
//! for them. Hand-written, not generated: they're plain HTTP, not part of the
//! API's OpenAPI document.

/// The liveness endpoint: the server is up and serving HTTP. Shared by the
/// server that answers it, `HealthHandler`, and the client that asks,
/// `HealthClient`, so the two can't drift apart.
pub const HEALTH_LIVE_PATH: &str = "/health/live";

/// The readiness endpoint: the server can serve. Shared as
/// [`HEALTH_LIVE_PATH`] is.
pub const HEALTH_READY_PATH: &str = "/health/ready";

#[cfg(feature = "client")]
pub use client::HealthClient;
#[cfg(feature = "server")]
pub use server::{HealthCheck, HealthCheckError, HealthHandler};

#[cfg(feature = "client")]
mod client {
    use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};

    use super::{HEALTH_LIVE_PATH, HEALTH_READY_PATH};
    use crate::v1::HttpResult;

    /// Checks a server's health endpoints, [`HEALTH_LIVE_PATH`] and
    /// [`HEALTH_READY_PATH`].
    ///
    /// Hand-written, not generated: the endpoints are plain HTTP beside the
    /// API, not in its OpenAPI document. Built like the generated
    /// `HttpClient`, over a reqwest-middleware client, so it reaches the
    /// server exactly as that does.
    #[derive(Clone)]
    pub struct HealthClient {
        base_url: String,
        http: ClientWithMiddleware,
    }

    impl HealthClient {
        /// A client for the server at `base_url`, e.g.
        /// `https://cf-oidc-exchange.example.workers.dev`, over a plain reqwest
        /// client.
        #[must_use]
        pub fn new(base_url: impl Into<String>) -> Self {
            Self::with_client(ClientBuilder::new(reqwest::Client::new()).build(), base_url)
        }

        /// Over any client: one with middleware, retries, a test double.
        #[must_use]
        pub fn with_client(http: ClientWithMiddleware, base_url: impl Into<String>) -> Self {
            Self {
                base_url: base_url.into(),
                http,
            }
        }

        /// Whether the server is up: `GET /health/live` answered 2xx.
        ///
        /// # Errors
        ///
        /// `HttpError::Middleware` when the server couldn't be reached at all.
        pub async fn is_live(&self) -> HttpResult<bool> {
            self.check(HEALTH_LIVE_PATH).await
        }

        /// Whether the server can serve: `GET /health/ready` answered 2xx.
        /// `Ok(false)` for the 503 it answers when a check fails.
        ///
        /// # Errors
        ///
        /// `HttpError::Middleware` when the server couldn't be reached at all.
        pub async fn is_ready(&self) -> HttpResult<bool> {
            self.check(HEALTH_READY_PATH).await
        }

        /// `GET path` against the base URL, answered 2xx or not.
        async fn check(&self, path: &str) -> HttpResult<bool> {
            let url = format!("{}{path}", self.base_url.trim_end_matches('/'));
            Ok(self.http.get(url).send().await?.status().is_success())
        }
    }
}

#[cfg(feature = "server")]
mod server {
    use std::{future::Future, pin::Pin, sync::Arc};

    use axum::{http::StatusCode, routing::get};

    use super::{HEALTH_LIVE_PATH, HEALTH_READY_PATH};

    /// What a failed [`HealthCheck::check`] carries: why.
    pub type HealthCheckError = Box<dyn std::error::Error + Send + Sync>;

    /// A check of something the server depends on, the policy or a secret, for
    /// a health endpoint to ask. `/health/ready` asks every one given to
    /// [`HealthHandler::readiness`].
    pub trait HealthCheck: Send + Sync + 'static {
        /// `Ok` when what it checks is healthy; the error says why not.
        fn check(&self) -> impl Future<Output = Result<(), HealthCheckError>> + Send;
    }

    /// [`HealthCheck`] with its future boxed, which is what lets a
    /// [`HealthHandler`] hold checks of any type without being generic over
    /// them, while an implementor still writes a plain `async fn check`.
    trait DynHealthCheck: Send + Sync {
        fn check(&self) -> Pin<Box<dyn Future<Output = Result<(), HealthCheckError>> + Send + '_>>;
    }

    impl<R: HealthCheck> DynHealthCheck for R {
        fn check(&self) -> Pin<Box<dyn Future<Output = Result<(), HealthCheckError>> + Send + '_>> {
            Box::pin(HealthCheck::check(self))
        }
    }

    /// Answers the health endpoints, [`HEALTH_LIVE_PATH`] and
    /// [`HEALTH_READY_PATH`].
    ///
    /// Liveness says the server is up and serving HTTP, and never asks
    /// anything: an outage behind it should take the server out of rotation,
    /// not have it restarted. Readiness asks every check given with
    /// [`readiness`](Self::readiness), and is ready only while all of them
    /// pass: with none, whenever it is live.
    #[derive(Clone, Default)]
    pub struct HealthHandler {
        checks: Vec<Arc<dyn DynHealthCheck>>,
    }

    impl HealthHandler {
        /// Create a new [`HealthHandler`] with no readiness checks yet.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Ask `check` too before answering ready: one per thing the server
        /// can't serve without.
        #[must_use]
        pub fn readiness(mut self, check: impl HealthCheck) -> Self {
            self.checks.push(Arc::new(check));
            self
        }

        /// Both endpoints, as a router to merge beside the API's.
        pub fn into_router(self) -> axum::Router {
            axum::Router::new()
                .route(HEALTH_LIVE_PATH, get(Self::live))
                .route(
                    HEALTH_READY_PATH,
                    get(move || async move { self.ready().await }),
                )
        }

        /// Liveness: serving HTTP at all is the whole of it.
        pub async fn live() -> StatusCode {
            StatusCode::OK
        }

        /// Readiness: 200 when every check passes, all of them together, and
        /// 503 otherwise. The probe's caller sees only the code. Unlike a
        /// server with a runtime to time out on, this waits for the checks
        /// however long they take: a Worker has no timer of its own here, and
        /// the platform bounds the request.
        pub async fn ready(&self) -> StatusCode {
            for check in &self.checks {
                if check.check().await.is_err() {
                    return StatusCode::SERVICE_UNAVAILABLE;
                }
            }
            StatusCode::OK
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A check that answers at once, as told.
        struct Answers(bool);

        impl HealthCheck for Answers {
            async fn check(&self) -> Result<(), HealthCheckError> {
                if self.0 {
                    Ok(())
                } else {
                    Err("the Cloudflare token can't be read".into())
                }
            }
        }

        #[tokio::test]
        async fn live_is_always_ok() {
            assert_eq!(HealthHandler::live().await, StatusCode::OK);
        }

        #[tokio::test]
        async fn ready_follows_the_check() {
            let ready = |answer| HealthHandler::new().readiness(Answers(answer));

            assert_eq!(ready(true).ready().await, StatusCode::OK);
            assert_eq!(ready(false).ready().await, StatusCode::SERVICE_UNAVAILABLE);
        }

        /// Every check has to pass, and with none there is nothing to fail.
        #[tokio::test]
        async fn ready_needs_every_check() {
            let both = HealthHandler::new()
                .readiness(Answers(true))
                .readiness(Answers(false));

            assert_eq!(both.ready().await, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(HealthHandler::new().ready().await, StatusCode::OK);
        }
    }
}
