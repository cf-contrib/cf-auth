//! Service implementations for the generated API trait.
//!
//! The service type, the bindings it reads, and the trait impl are in
//! [`handler`]. What every response gets around the generated router, the
//! contract's error body and its `Cache-Control`, is in [`layer`], which the
//! crate root layers over the routes.
//!
//! The health endpoints are the SDK's `HealthHandler`, merged beside them in
//! the crate root: they're a deployment check, not part of the API, so the
//! spec doesn't declare them.

pub mod handler;
pub mod layer;
