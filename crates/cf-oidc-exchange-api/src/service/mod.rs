//! Service implementations for the generated API trait.
//!
//! The Worker's configuration, the one place its bindings are read, is in
//! [`config`]. The service type and the trait impl are in [`handler`].
//! Exchange auth is in [`layer`], which the crate root layers over the API's
//! routes, so no handler authenticates.
//!
//! The health endpoints are the SDK's `HealthHandler`, merged beside them in
//! the crate root: they're a deployment check, not part of the API, so the
//! spec doesn't declare them.

pub mod config;
pub mod handler;
pub mod layer;
