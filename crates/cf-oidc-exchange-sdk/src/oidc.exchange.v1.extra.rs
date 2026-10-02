// Hand-written companion to the generated `oidc.exchange.v1` code.
//
// Same convention as grpc-rust-template: the generated module is machine-written,
// from the OpenAPI document into OUT_DIR, `oidc.exchange.v1.extra.rs` beside
// lib.rs is not, and `v1` includes both into the one module. `//` rather than
// `//!` because an `include!`d file cannot carry inner attributes; the module
// documentation lives in lib.rs.
//
// What's here: the health endpoints a server of the API answers beside it, and
// a client for them. They're plain HTTP, not operations in the OpenAPI document.
// The private modules are `health_*` because the generated code already has
// `client` and `server`.

/// The liveness endpoint: the server is up and serving HTTP. Shared by the
/// server that answers it and the [`HealthClient`] that asks, so the two
/// cannot drift apart.
pub const HEALTH_LIVE_PATH: &str = "/health/live";

/// The readiness endpoint: the server can serve, with the policy and secrets it
/// needs. Shared as [`HEALTH_LIVE_PATH`] is.
pub const HEALTH_READY_PATH: &str = "/health/ready";

#[cfg(feature = "client")]
pub use health_client::HealthClient;
#[cfg(feature = "server")]
pub use health_server::{HealthCheck, HealthCheckError, HealthHandler, READY_TIMEOUT};

// -- Client ----------------------------------------------------------------

#[cfg(feature = "client")]
mod health_client {
    use super::{HEALTH_LIVE_PATH, HEALTH_READY_PATH};

    /// Checks a server's health endpoints, [`HEALTH_LIVE_PATH`] and
    /// [`HEALTH_READY_PATH`].
    ///
    /// Hand-written, not generated: the endpoints are plain HTTP beside the API,
    /// not operations in its document.
    #[derive(Clone)]
    pub struct HealthClient {
        base_url: String,
        http: reqwest::Client,
    }

    impl HealthClient {
        /// A client for the server at `base_url`, e.g.
        /// `https://cf-oidc-exchange.example.workers.dev`.
        pub fn new(base_url: impl Into<String>) -> Self {
            Self::with_client(base_url, reqwest::Client::new())
        }

        /// A client for the server at `base_url`, over `http`.
        pub fn with_client(base_url: impl Into<String>, http: reqwest::Client) -> Self {
            Self {
                base_url: base_url.into(),
                http,
            }
        }

        /// Whether the server is up: `GET /health/live` answered 2xx.
        pub async fn is_live(&self) -> Result<bool, reqwest::Error> {
            self.check(HEALTH_LIVE_PATH).await
        }

        /// Whether the server can serve: `GET /health/ready` answered 2xx -- up,
        /// and every readiness check passing.
        pub async fn is_ready(&self) -> Result<bool, reqwest::Error> {
            self.check(HEALTH_READY_PATH).await
        }

        async fn check(&self, path: &str) -> Result<bool, reqwest::Error> {
            let url = format!("{}{path}", self.base_url.trim_end_matches('/'));
            Ok(self.http.get(url).send().await?.status().is_success())
        }
    }
}

// -- Server ----------------------------------------------------------------

// The plain-HTTP endpoints a server of this API answers beside it, behind the
// `server` feature. What only the server knows reaches them through
// `HealthCheck`.
#[cfg(feature = "server")]
mod health_server {
    use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

    use axum::{http::StatusCode, routing::get};
    use futures_util::future::{Either, select};

    use super::{HEALTH_LIVE_PATH, HEALTH_READY_PATH};

    /// What a failed [`HealthCheck::check`] carries: why, for the log.
    pub type HealthCheckError = Box<dyn std::error::Error + Send + Sync>;

    /// A check of something the server depends on -- for the broker, its policy
    /// and secrets -- for a health endpoint to ask. `/health/ready` asks every
    /// one given to [`HealthHandler::readiness`].
    pub trait HealthCheck: Send + Sync + 'static {
        /// `Ok` when what it checks is healthy; the error says why not.
        fn check(&self) -> impl Future<Output = Result<(), HealthCheckError>> + Send;
    }

    /// [`HealthCheck`] with its future boxed, which is what lets a
    /// [`HealthHandler`] hold checks of any type without being generic over
    /// them -- while an implementor still writes a plain `async fn check`.
    trait DynHealthCheck: Send + Sync {
        fn check(&self) -> Pin<Box<dyn Future<Output = Result<(), HealthCheckError>> + Send + '_>>;
    }

    impl<R: HealthCheck> DynHealthCheck for R {
        fn check(&self) -> Pin<Box<dyn Future<Output = Result<(), HealthCheckError>> + Send + '_>> {
            Box::pin(HealthCheck::check(self))
        }
    }

    /// How long readiness waits for the checks. Well inside a probe's own
    /// timeout, so a check that hangs -- a secret store that doesn't answer --
    /// answers 503 in time rather than not at all.
    pub const READY_TIMEOUT: Duration = Duration::from_secs(2);

    /// Answers the health endpoints, [`HEALTH_LIVE_PATH`] and
    /// [`HEALTH_READY_PATH`].
    ///
    /// Liveness says the server is up and serving HTTP, and never asks
    /// anything: an outage behind it should take the server out of rotation,
    /// not have it restarted. Readiness asks every check given with
    /// [`readiness`](Self::readiness), and is ready only while all of them
    /// pass -- with none, whenever it is live.
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
        /// cannot serve without.
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

        /// Readiness: 200 when every check passes within [`READY_TIMEOUT`],
        /// all of them together, and 503 otherwise, with why logged -- the
        /// probe's caller sees only the code.
        ///
        /// The timeout is futures-timer's rather than tokio's, so it also runs
        /// in a Worker, which has no tokio runtime.
        pub async fn ready(&self) -> StatusCode {
            let checks = async {
                for check in &self.checks {
                    check.check().await?;
                }
                Ok::<(), HealthCheckError>(())
            };

            let timeout = futures_timer::Delay::new(READY_TIMEOUT);
            match select(std::pin::pin!(checks), timeout).await {
                Either::Left((Ok(()), _)) => StatusCode::OK,
                Either::Left((Err(error), _)) => {
                    tracing::warn!(%error, "not ready");
                    StatusCode::SERVICE_UNAVAILABLE
                }
                Either::Right(_) => {
                    tracing::warn!(timeout = ?READY_TIMEOUT, "not ready: no answer in time");
                    StatusCode::SERVICE_UNAVAILABLE
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::time::Instant;

        use super::*;

        /// A check that answers at once, as told.
        struct Answers(bool);

        impl HealthCheck for Answers {
            async fn check(&self) -> Result<(), HealthCheckError> {
                if self.0 {
                    Ok(())
                } else {
                    Err("the broker token can't be read".into())
                }
            }
        }

        /// A check that never answers.
        struct Hangs;

        impl HealthCheck for Hangs {
            async fn check(&self) -> Result<(), HealthCheckError> {
                std::future::pending().await
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

        /// A check that hangs is cut off at [`READY_TIMEOUT`], not waited on.
        #[tokio::test]
        async fn ready_is_unavailable_in_time_when_the_check_hangs() {
            let started = Instant::now();

            assert_eq!(
                HealthHandler::new().readiness(Hangs).ready().await,
                StatusCode::SERVICE_UNAVAILABLE
            );
            assert!(started.elapsed() < READY_TIMEOUT + Duration::from_secs(1));
        }
    }
}
