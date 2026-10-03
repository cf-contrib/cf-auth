//! OIDC tokens in Cloudflare Workers: verifying them, for any issuer (GitHub
//! Actions, GitLab, Cloudflare Access, or a broker that issues its own), and
//! signing them, for a Worker that is an issuer.
//!
//! Accepting a token takes two steps:
//!
//! 1. [`Providers::verify`] validates it as RFC 7519 §7.2 and RFC 8725 say.
//!    It picks its [`Provider`] by its `iss` claim, which must be one a
//!    provider names exactly, and checks its JOSE [`Header`]. Its RS256
//!    signature is checked with the runtime's WebCrypto against that issuer's
//!    keys, found through its metadata (or a configured `jwks_uri`) and never
//!    through anything in the token. Then its registered [`Claims`] are
//!    validated: `iss`, `aud`, `exp` and `nbf`.
//! 2. [`ClaimRules::authorize`] matches its claims against the policy, which
//!    no RFC says anything about.
//!
//! Keys are cached per isolate, and so is each verified token until it
//! expires: [`verified`] reads it back, so whoever verified a token can hand
//! it to whatever runs next without verifying it again.
//!
//! A Worker that issues its own tokens signs them with a [`SigningKey`], an RSA
//! key imported into WebCrypto, and publishes its [`SigningKey::public_jwk`].
//!
//! The futures aren't `Send`: they hold JavaScript values. A Worker is
//! single-threaded, so a caller that needs `Send`, such as an axum handler,
//! wraps them in `worker::send::SendFuture`.
//!
//! # Modules
//!
//! Each holds one layer, as the RFCs draw them:
//!
//! - `jwt`: the token format (RFC 7515, RFC 7519, RFC 9068), which knows
//!   nothing of providers;
//! - `jwk` and `metadata`: an issuer's keys (RFC 7517) and where they are
//!   (OpenID Connect Discovery, RFC 8414), fetched by `fetch`;
//! - `provider`: verifying, with what's cached in `cache`;
//! - `policy`: the claim rules;
//! - `signing`: issuing, with `webcrypto` doing the RS256 for both sides;
//! - `error`: what goes wrong.

mod cache;
mod error;
mod fetch;
mod jwk;
mod jwt;
mod metadata;
mod policy;
mod provider;
mod signing;
mod webcrypto;

pub use crate::{
    cache::verified,
    error::{Error, KeyError},
    fetch::check_url,
    jwt::{ALGORITHM, AT_JWT, AccessTokenClaims, Claims, Header, JWT, Jwt},
    policy::{ClaimRule, ClaimRules},
    provider::{Provider, Providers},
    signing::{SignedToken, SigningKey},
};
