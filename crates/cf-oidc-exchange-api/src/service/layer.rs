//! What runs around the API's routes, as layers: exchange auth, and the
//! contract every response keeps.
//!
//! [`AuthenticateLayer`] is layered over the API's routes in the crate root.
//! Every token exchange needs an OIDC token from a provider the policy names,
//! as its `subject_token`. The layer verifies it before the request reaches
//! the handler, and refuses the exchange if it isn't valid, or none of its
//! provider's claim sets matches. Everything else passes straight through.
//!
//! A token picks its provider by its `iss` claim, which must be one the policy
//! names exactly. Its signature is checked against that issuer's keys, found
//! through its discovery document (or a configured `jwks_uri`) and never
//! through anything in the token. Then the standard claims are checked, and
//! the token is accepted if any of the provider's claim sets matches.
//!
//! The handler takes the caller's [`Identity`] from the layer, by the token,
//! with [`identity`]: never from the token itself, so a token the layer didn't
//! verify gets nothing.
//!
//! [`respond`] is layered over everything: it gives the generated validation's
//! refusals the `Error` body every error has, and every response its
//! `Cache-Control`.

use std::{
    cell::RefCell,
    collections::HashMap,
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    Json,
    body::{Body, to_bytes},
    extract::Request,
    http::{HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cf_oidc_exchange_sdk::v1::{self, ErrorCode};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tower_layer::Layer;
use tower_service::Service;
use web_sys::{CryptoKey, WorkerGlobalScope};
use worker::{
    Date, console_error,
    js_sys::{self, Uint8Array},
    send::SendFuture,
    wasm_bindgen::{JsCast, JsValue},
    wasm_bindgen_futures::JsFuture,
};

use super::{
    config::{Config, PolicyConfig, ProviderConfig, check_url},
    handler::Audit,
};

/// Where the token exchange is.
const TOKEN_PATH: &str = "/oauth/token";

/// The most of a request body read: the generated router's limit.
const MAX_BODY_BYTES: usize = 16 * 1024;

/// Clock tolerance for `exp` and `nbf`.
const LEEWAY_SECS: u64 = 30;

/// How long a fetched JWKS is trusted before it's fetched again.
const JWKS_TTL_MS: u64 = 10 * 60 * 1000;

/// An unknown `kid` refetches an issuer's JWKS at most this often, so tokens
/// with made-up key IDs can't make the Worker hammer the issuer.
const JWKS_MIN_REFETCH_MS: u64 = 30 * 1000;

/// How long an issuer has to answer.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

thread_local! {
    /// Each issuer's signing keys, by issuer.
    static JWKS: RefCell<HashMap<String, KeySet>> = RefCell::new(HashMap::new());
    static CACHE: RefCell<IdentityCache> = RefCell::new(IdentityCache::new());
}

/// Authenticates every token exchange before the routes it's layered over,
/// against the providers in the Worker's policy. Every other request passes
/// through.
#[derive(Clone)]
pub struct AuthenticateLayer {
    config: Arc<Config>,
}

impl AuthenticateLayer {
    /// A layer that takes the providers from `config`.
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for AuthenticateLayer {
    type Service = Authenticate<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Authenticate {
            inner,
            config: self.config.clone(),
        }
    }
}

/// [`AuthenticateLayer`]'s service: authenticates an exchange, then hands the
/// request to the service it wraps.
#[derive(Clone)]
pub struct Authenticate<S> {
    inner: S,
    config: Arc<Config>,
}

impl<S> Service<Request> for Authenticate<S>
where
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        // The service polled ready is the one to call: a clone takes its
        // place for the next request.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let config = self.config.clone();

        Box::pin(async move {
            if req.method() != Method::POST || req.uri().path() != TOKEN_PATH {
                return inner.call(req).await;
            }

            // The token is in the form body, which the handler reads again.
            let (parts, body) = req.into_parts();
            let Ok(body) = to_bytes(body, MAX_BODY_BYTES).await else {
                let err = v1::Error::new(ErrorCode::BadRequest, "the body is over 16 KiB");
                return Ok((StatusCode::BAD_REQUEST, Json(err)).into_response());
            };
            let token = subject_token(&body);
            let req = Request::from_parts(parts, Body::from(body));

            // Without one, there's nothing to verify: the generated validation
            // refuses the request, and the handler would find no identity.
            let Some(token) = token else {
                return inner.call(req).await;
            };

            // Verifying fetches the issuer's keys, and fetch futures aren't
            // `Send`, which the router wants; a Worker is single-threaded, so
            // it runs in a `SendFuture`.
            match SendFuture::new(verify(&token, config.policy())).await {
                Ok(_) => inner.call(req).await,
                Err(err) => Ok(err.into_response()),
            }
        })
    }
}

/// The `subject_token` of a form body, if it has one.
fn subject_token(body: &[u8]) -> Option<String> {
    let fields: Vec<(String, String)> = serde_urlencoded::from_bytes(body).ok()?;
    fields
        .into_iter()
        .find(|(name, value)| name == "subject_token" && !value.is_empty())
        .map(|(_, token)| token)
}

/// The caller of an exchange: the provider its token is from, and the token's
/// claims.
#[derive(Clone, Debug, PartialEq)]
pub struct Identity {
    /// The provider's name.
    pub provider: String,
    pub claims: Map<String, Value>,
}

/// The identity of `token`, which the layer verified before the request
/// reached the handler.
///
/// # Errors
///
/// When the layer didn't verify it: never, short of a bug, since the layer
/// is over every exchange.
pub fn identity(token: &str) -> Result<Identity, v1::Error> {
    let key = IdentityCache::key(token);
    match CACHE.with_borrow(|cache| cache.get(&key, Date::now().as_millis())) {
        Some(Ok(identity)) => Ok(identity),
        _ => Err(v1::Error::new(
            ErrorCode::Unauthorized,
            "the subject token wasn't verified",
        )),
    }
}

/// Verifies `token`, against the provider its `iss` names, and keeps the
/// outcome for [`identity`] until the token expires.
async fn verify(token: &str, policy: &PolicyConfig) -> Result<Identity, AuthError> {
    let now_ms = Date::now().as_millis();
    let key = IdentityCache::key(token);
    if let Some(result) = CACHE.with_borrow(|cache| cache.get(&key, now_ms)) {
        return result.inspect_err(AuthError::audit);
    }

    let jwt = Jwt::decode(token).inspect_err(AuthError::audit)?;
    let provider = policy
        .provider_for(&jwt.claims)
        .inspect_err(AuthError::audit)?;
    let result = provider.verify_token(&jwt, now_ms).await;
    // A verified token's identity can't change, so both outcomes hold until
    // it expires. Expiry and other time-based failures are not cached.
    if matches!(result, Ok(_) | Err(AuthError::Forbidden(..)))
        && let Some(exp) = jwt.claims.get("exp").and_then(Value::as_u64)
    {
        let expires_at = (exp + LEEWAY_SECS) * 1000;
        CACHE.with_borrow_mut(|cache| cache.insert(key, result.clone(), expires_at, now_ms));
    }
    result.inspect_err(AuthError::audit)
}

/// Why an exchange was not authenticated.
#[derive(Clone, Debug, PartialEq)]
pub enum AuthError {
    /// A missing or invalid token (`401`).
    Unauthorized(String),
    /// A valid token none of its provider's claim sets matches (`403`): its
    /// identity, and why.
    Forbidden(Identity, String),
    /// An issuer's discovery document or keys couldn't be had (`502`). Not the
    /// caller's fault.
    Upstream(String),
}

impl AuthError {
    fn audit(&self) {
        let (code, message) = match self {
            Self::Unauthorized(msg) => (ErrorCode::Unauthorized, msg),
            Self::Forbidden(_, msg) => (ErrorCode::Forbidden, msg),
            Self::Upstream(msg) => (ErrorCode::UpstreamError, msg),
        };
        let audit = match self {
            Self::Forbidden(identity, _) => Audit::new("token.deny").caller(
                Some(&identity.provider),
                None,
                Some(&identity.claims),
                [],
            ),
            _ => Audit::new("token.deny"),
        };
        audit
            .with("error", code.as_str())
            .with("message", message.as_str())
            .emit();
    }
}

/// The error, as the JSON every error has. Upstream details are logged, not
/// returned.
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            AuthError::Unauthorized(msg) => (
                StatusCode::UNAUTHORIZED,
                v1::Error::new(ErrorCode::Unauthorized, msg),
            ),
            AuthError::Forbidden(_, msg) => (
                StatusCode::FORBIDDEN,
                v1::Error::new(ErrorCode::Forbidden, msg),
            ),
            AuthError::Upstream(msg) => {
                console_error!("auth upstream failure: {msg}");
                (
                    StatusCode::BAD_GATEWAY,
                    v1::Error::new(
                        ErrorCode::UpstreamError,
                        "the subject token's issuer couldn't be reached",
                    ),
                )
            }
        };
        (status, Json(body)).into_response()
    }
}

fn invalid(what: &str) -> AuthError {
    AuthError::Unauthorized(format!("the subject token isn't valid: {what}"))
}

impl PolicyConfig {
    /// The provider a token's claims say it comes from, by its `iss`, read
    /// unverified only to pick the keys to verify it with.
    fn provider_for(&self, claims: &Map<String, Value>) -> Result<&ProviderConfig, AuthError> {
        let iss = claims
            .get("iss")
            .and_then(Value::as_str)
            .unwrap_or_default();
        self.providers
            .iter()
            .find(|provider| provider.issuer == iss)
            .ok_or_else(|| {
                let shown: String = iss.chars().take(200).collect();
                AuthError::Unauthorized(format!("no provider is for issuer {shown}"))
            })
    }
}

impl ProviderConfig {
    /// Verifies `jwt`, a token that claims to come from this provider, and
    /// matches it against the provider's claim sets.
    async fn verify_token(&self, jwt: &Jwt<'_>, now_ms: u64) -> Result<Identity, AuthError> {
        let jwk = self.find_key(jwt.kid.as_deref(), now_ms).await?;
        if !jwk
            .verify_rs256(jwt.signing_input.as_bytes(), &jwt.signature)
            .await?
        {
            return Err(invalid("bad signature"));
        }
        self.check_claims(&jwt.claims, now_ms / 1000)
    }

    /// Checks the claims of a token whose signature the provider's keys
    /// verified.
    fn check_claims(
        &self,
        claims: &Map<String, Value>,
        now_secs: u64,
    ) -> Result<Identity, AuthError> {
        let claim = |name| claims.get(name);

        if claim("iss").and_then(Value::as_str) != Some(self.issuer.as_str()) {
            return Err(invalid("wrong issuer"));
        }

        // A trailing `/` is ignored, here and in the token.
        let ours = |aud: &Value| {
            aud.as_str()
                .is_some_and(|aud| aud.trim_end_matches('/') == self.audience.trim_end_matches('/'))
        };
        let audience_ok = match claim("aud") {
            Some(Value::Array(auds)) => auds.iter().any(ours),
            Some(aud) => ours(aud),
            None => false,
        };
        if !audience_ok {
            return Err(invalid("wrong audience"));
        }

        let Some(exp) = claim("exp").and_then(Value::as_u64) else {
            return Err(invalid("missing exp"));
        };
        if now_secs >= exp + LEEWAY_SECS {
            return Err(invalid("expired"));
        }
        if let Some(nbf) = claim("nbf").and_then(Value::as_u64)
            && nbf > now_secs + LEEWAY_SECS
        {
            return Err(invalid("not yet valid"));
        }

        let identity = Identity {
            provider: self.name.clone(),
            claims: claims.clone(),
        };
        // Guardrail 1: every token is held to its provider's claim sets,
        // whichever profile it gets. Which would have matched isn't said:
        // that's the policy, not the caller's to probe.
        if !self.claims.iter().any(|set| set.matches(claims)) {
            let message = format!(
                "the token matches none of provider {}'s claim sets",
                self.name
            );
            return Err(AuthError::Forbidden(identity, message));
        }
        Ok(identity)
    }

    async fn find_key(&self, kid: Option<&str>, now_ms: u64) -> Result<Jwk, AuthError> {
        let unknown = || invalid("no matching key");

        match JWKS.with_borrow(|sets| KeySet::lookup(sets.get(&self.issuer), kid, now_ms)) {
            Lookup::Hit(key) => return Ok(key),
            Lookup::Unknown => return Err(unknown()),
            Lookup::Fetch => {}
        }

        let set = self.fetch_jwks(now_ms).await?;
        let key = set.find(kid).cloned();
        JWKS.with_borrow_mut(|sets| sets.insert(self.issuer.clone(), set));
        key.ok_or_else(unknown)
    }

    async fn fetch_jwks(&self, now_ms: u64) -> Result<KeySet, AuthError> {
        let jwks_uri = match &self.jwks_uri {
            Some(jwks_uri) => jwks_uri.clone(),
            None => {
                let url = format!(
                    "{}/.well-known/openid-configuration",
                    self.issuer.trim_end_matches('/')
                );
                let discovery: Discovery = fetch_json(&url).await?;
                // OIDC Discovery requires the document to name its own issuer, so
                // one issuer can't hand out another's keys.
                if discovery.issuer != self.issuer {
                    return Err(AuthError::Upstream(format!(
                        "{url} is for issuer {}, not {}",
                        discovery.issuer, self.issuer
                    )));
                }
                check_url(&discovery.jwks_uri)
                    .map_err(|why| AuthError::Upstream(format!("{url}: jwks_uri {why}")))?;
                discovery.jwks_uri
            }
        };
        let jwks: Jwks = fetch_json(&jwks_uri).await?;
        Ok(KeySet::parse(jwks, now_ms))
    }
}

/// A decoded, not yet verified, JWT.
struct Jwt<'a> {
    kid: Option<String>,
    claims: Map<String, Value>,
    /// `<header>.<payload>`, the bytes the signature covers.
    signing_input: &'a str,
    signature: Vec<u8>,
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    kid: Option<String>,
}

impl<'a> Jwt<'a> {
    fn decode(jwt: &'a str) -> Result<Self, AuthError> {
        let not_a_jwt = || invalid("not a JWT");
        let segment = |s: &str| URL_SAFE_NO_PAD.decode(s).map_err(|_| not_a_jwt());

        let parts: Vec<&str> = jwt.split('.').collect();
        let [header, payload, signature] = parts[..] else {
            return Err(not_a_jwt());
        };

        let header: JwtHeader =
            serde_json::from_slice(&segment(header)?).map_err(|_| not_a_jwt())?;
        let claims = serde_json::from_slice(&segment(payload)?).map_err(|_| not_a_jwt())?;
        if header.alg != "RS256" {
            return Err(invalid("alg must be RS256"));
        }

        Ok(Jwt {
            kid: header.kid,
            claims,
            signing_input: &jwt[..jwt.len() - signature.len() - 1],
            signature: segment(signature)?,
        })
    }
}

/// The part of an issuer's discovery document the Worker reads.
#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<RawJwk>,
}

#[derive(Deserialize)]
struct RawJwk {
    kty: String,
    kid: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
struct Jwk {
    kid: Option<String>,
    n: String,
    e: String,
}

impl Jwk {
    /// Verifies an RS256 (RSASSA-PKCS1-v1_5 with SHA-256) signature with WebCrypto.
    async fn verify_rs256(
        &self,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<bool, AuthError> {
        let webcrypto = |err: JsValue| AuthError::Upstream(format!("WebCrypto: {err:?}"));
        let object = |value: Value| -> Result<js_sys::Object, AuthError> {
            js_sys::JSON::parse(&value.to_string())
                .map(JsCast::unchecked_into)
                .map_err(webcrypto)
        };

        let subtle = js_sys::global()
            .unchecked_into::<WorkerGlobalScope>()
            .crypto()
            .map_err(webcrypto)?
            .subtle();
        let algorithm = object(json!({ "name": "RSASSA-PKCS1-v1_5", "hash": "SHA-256" }))?;
        let key_data = object(json!({ "kty": "RSA", "n": self.n, "e": self.e, "alg": "RS256" }))?;
        let usages = js_sys::Array::of1(&JsValue::from_str("verify"));

        let key: CryptoKey = JsFuture::from(
            subtle
                .import_key_with_object("jwk", &key_data, &algorithm, false, &usages)
                .map_err(webcrypto)?,
        )
        .await
        .map_err(webcrypto)?
        .unchecked_into();

        // A signature WebCrypto refuses to check (e.g. wrong length) is the
        // caller's problem, not an upstream failure.
        let verified = subtle
            .verify_with_object_and_buffer_source_and_buffer_source(
                &algorithm,
                &key,
                &Uint8Array::from(signature),
                &Uint8Array::from(signing_input),
            )
            .map(JsFuture::from);
        match verified {
            Ok(future) => Ok(future.await.ok().and_then(|v| v.as_bool()) == Some(true)),
            Err(_) => Ok(false),
        }
    }
}

/// An issuer's signing keys, cached per isolate.
struct KeySet {
    keys: Vec<Jwk>,
    fetched_at: u64,
}

#[derive(Debug, PartialEq)]
enum Lookup {
    Hit(Jwk),
    Fetch,
    /// Unknown `kid`, and the JWKS was fetched too recently to try again.
    Unknown,
}

impl KeySet {
    fn parse(jwks: Jwks, fetched_at: u64) -> Self {
        let keys = jwks
            .keys
            .into_iter()
            .filter(|key| key.kty == "RSA")
            .filter_map(|key| {
                Some(Jwk {
                    kid: key.kid,
                    n: key.n?,
                    e: key.e?,
                })
            })
            .collect();
        Self { keys, fetched_at }
    }

    /// The key with this `kid`; without one, the only key there is.
    fn find(&self, kid: Option<&str>) -> Option<&Jwk> {
        match kid {
            Some(kid) => self.keys.iter().find(|key| key.kid.as_deref() == Some(kid)),
            None => match self.keys.as_slice() {
                [only] => Some(only),
                _ => None,
            },
        }
    }

    fn lookup(set: Option<&KeySet>, kid: Option<&str>, now_ms: u64) -> Lookup {
        let Some(set) = set else {
            return Lookup::Fetch;
        };
        let age = now_ms.saturating_sub(set.fetched_at);
        match set.find(kid) {
            Some(key) if age < JWKS_TTL_MS => Lookup::Hit(key.clone()),
            Some(_) => Lookup::Fetch,
            None if age < JWKS_MIN_REFETCH_MS => Lookup::Unknown,
            None => Lookup::Fetch,
        }
    }
}

async fn fetch_json<T: DeserializeOwned>(url: &str) -> Result<T, AuthError> {
    let upstream = |err: reqwest::Error| AuthError::Upstream(format!("fetching {url}: {err}"));
    let resp = reqwest::Client::new()
        .get(url)
        .timeout(FETCH_TIMEOUT)
        .send()
        .await
        .map_err(upstream)?;
    if !resp.status().is_success() {
        return Err(AuthError::Upstream(format!(
            "fetching {url} returned {}",
            resp.status().as_u16()
        )));
    }
    resp.json().await.map_err(upstream)
}

/// Per-isolate cache of auth results, keyed by the SHA-256 of the token so raw
/// tokens are never stored.
///
/// Holds refusals (`403`) as well as identities, so a token no claim set
/// allows isn't verified again on every request either. The handler takes its
/// caller's identity from here.
struct IdentityCache {
    entries: HashMap<[u8; 32], (u64, Result<Identity, AuthError>)>,
}

impl IdentityCache {
    /// Upper bound on entries, so a flood of distinct tokens can't grow the
    /// isolate's memory without limit.
    const MAX_ENTRIES: usize = 1024;

    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn key(token: &str) -> [u8; 32] {
        Sha256::digest(token.as_bytes()).into()
    }

    fn get(&self, key: &[u8; 32], now_ms: u64) -> Option<Result<Identity, AuthError>> {
        self.entries
            .get(key)
            .filter(|(expires_at, _)| now_ms < *expires_at)
            .map(|(_, result)| result.clone())
    }

    fn insert(
        &mut self,
        key: [u8; 32],
        result: Result<Identity, AuthError>,
        expires_at: u64,
        now_ms: u64,
    ) {
        if self.entries.len() >= Self::MAX_ENTRIES {
            self.entries
                .retain(|_, (expires_at, _)| now_ms < *expires_at);
        }
        if self.entries.len() >= Self::MAX_ENTRIES {
            self.entries.clear();
        }
        self.entries.insert(key, (expires_at, result));
    }
}

/// The contract's error body for requests the generated validation refuses,
/// and every response's `Cache-Control`.
///
/// The generated validation answers `application/problem+json` with `400`,
/// `413`, `415` or `422`; the contract has `400` with the `Error` body every
/// error has.
pub async fn respond(req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    let response = next.run(req).await;

    let problem = response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|value| value == "application/problem+json");
    let mut response = if problem {
        let body = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap_or_default();
        let err = v1::Error::new(ErrorCode::BadRequest, rejection(&body));
        // Audited like any refusal, with what was wrong, which never includes
        // the values sent.
        let event = if path == TOKEN_PATH {
            "token.deny"
        } else {
            "token.revoke"
        };
        Audit::new(event)
            .with("error", err.error.as_str())
            .with("message", err.message.as_str())
            .emit();
        (StatusCode::BAD_REQUEST, Json(err)).into_response()
    } else {
        response
    };

    // What verifying the broker's tokens takes is public and cacheable;
    // nothing else is.
    let cache_control = if path.starts_with("/.well-known/") && response.status() == StatusCode::OK
    {
        "public, max-age=300"
    } else {
        "no-store"
    };
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );
    response
}

/// What the generated validation found wrong, from its problem details: each
/// violation's place and what's wrong there, or the problem itself.
fn rejection(body: &[u8]) -> String {
    let problem: Value = serde_json::from_slice(body).unwrap_or_default();
    let violations: Vec<String> = problem["errors"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|violation| {
            let location = violation["location"].as_str().unwrap_or_default();
            let message = violation["message"].as_str().unwrap_or_default();
            format!("{location} {message}")
        })
        .collect();
    if !violations.is_empty() {
        return violations.join("; ");
    }
    match problem["code"].as_str() {
        Some("unsupported_media_type") => {
            "the body must be form-encoded (application/x-www-form-urlencoded)".into()
        }
        _ => problem["title"]
            .as_str()
            .unwrap_or("the request doesn't fit the API")
            .to_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::config::tests::{BROKER, ISSUER, NOW, claims, parse, policy};

    fn provider() -> ProviderConfig {
        parse(&policy()).providers.remove(0)
    }

    fn identity() -> Result<Identity, AuthError> {
        Ok(Identity {
            provider: "github".to_string(),
            claims: claims(),
        })
    }

    #[test]
    fn identity_cache_expires_entries() {
        let mut cache = IdentityCache::new();
        let key = IdentityCache::key("token");
        cache.insert(key, identity(), 100, 0);
        assert_eq!(cache.get(&key, 99), Some(identity()));
        assert_eq!(cache.get(&key, 100), None);
    }

    #[test]
    fn identity_cache_holds_refusals() {
        let mut cache = IdentityCache::new();
        let key = IdentityCache::key("token");
        let refused = Err(AuthError::Forbidden(identity().unwrap(), "no".to_string()));
        cache.insert(key, refused.clone(), 100, 0);
        assert_eq!(cache.get(&key, 0), Some(refused));
    }

    #[test]
    fn identity_cache_is_bounded() {
        let mut cache = IdentityCache::new();
        for i in 0..=IdentityCache::MAX_ENTRIES {
            cache.insert(IdentityCache::key(&i.to_string()), identity(), 100, 0);
        }
        assert!(cache.entries.len() <= IdentityCache::MAX_ENTRIES);
    }

    #[test]
    fn finds_the_subject_token_in_the_form() {
        let form = |body: &str| subject_token(body.as_bytes());
        assert_eq!(
            form("grant_type=x&subject_token=a.b.c").as_deref(),
            Some("a.b.c")
        );
        assert_eq!(form("subject_token=a%2Bb").as_deref(), Some("a+b"));
        assert_eq!(form("subject_token="), None);
        assert_eq!(form("grant_type=x"), None);
        assert_eq!(form("{\"subject_token\":\"a\"}"), None);
    }

    #[test]
    fn picks_the_provider_by_the_tokens_issuer() {
        let policy = parse(&policy());
        assert_eq!(policy.provider_for(&claims()).unwrap().name, "github");

        let mut other = claims();
        other.insert("iss".into(), "https://other.example.com".into());
        assert_eq!(
            policy.provider_for(&other).unwrap_err(),
            AuthError::Unauthorized("no provider is for issuer https://other.example.com".into())
        );
    }

    #[test]
    fn check_claims_returns_the_identity() {
        let identity = provider().check_claims(&claims(), NOW).unwrap();
        assert_eq!(identity.provider, "github");
        assert_eq!(identity.claims, claims());
    }

    #[test]
    fn check_claims_accepts_an_audience_array_and_a_trailing_slash() {
        for aud in [
            json!(["https://other.example.com", BROKER]),
            json!(format!("{BROKER}/")),
        ] {
            let mut claims = claims();
            claims.insert("aud".into(), aud.clone());
            assert!(provider().check_claims(&claims, NOW).is_ok(), "{aud}");
        }
    }

    #[test]
    fn check_claims_says_what_is_wrong() {
        let cases: [(&str, Value, &str); 6] = [
            ("iss", json!("https://other.example.com"), "wrong issuer"),
            // A token requested for AWS, or GitHub's default audience.
            ("aud", json!("sts.amazonaws.com"), "wrong audience"),
            ("aud", Value::Null, "wrong audience"),
            ("exp", json!(NOW - LEEWAY_SECS), "expired"),
            ("nbf", json!(NOW + LEEWAY_SECS + 1), "not yet valid"),
            ("exp", Value::Null, "missing exp"),
        ];
        for (claim, value, expected) in cases {
            let mut claims = claims();
            claims.insert(claim.into(), value);
            assert_eq!(
                provider().check_claims(&claims, NOW),
                Err(invalid(expected)),
                "{claim}"
            );
        }
    }

    #[test]
    fn check_claims_tolerates_clock_skew() {
        let mut claims = claims();
        claims.insert("nbf".into(), json!(NOW + LEEWAY_SECS));
        assert!(provider().check_claims(&claims, NOW).is_ok());
        assert!(
            provider()
                .check_claims(&claims, NOW + 300 + LEEWAY_SECS - 1)
                .is_ok()
        );
    }

    #[test]
    fn check_claims_holds_every_token_to_its_providers_claim_sets() {
        let mut claims = claims();
        claims.insert("repository_owner_id".into(), "999999".into());
        assert!(matches!(
            provider().check_claims(&claims, NOW),
            Err(AuthError::Forbidden(_, message)) if message == "the token matches none of provider github's claim sets"
        ));
    }

    fn segment(value: Value) -> String {
        URL_SAFE_NO_PAD.encode(value.to_string())
    }

    #[test]
    fn decode_splits_a_jwt() {
        let header = segment(json!({ "alg": "RS256", "kid": "key-1" }));
        let payload = segment(Value::Object(claims()));
        let jwt = format!("{header}.{payload}.c2ln");

        let token = Jwt::decode(&jwt).expect("should decode");
        assert_eq!(token.kid.as_deref(), Some("key-1"));
        assert_eq!(token.signing_input, format!("{header}.{payload}"));
        assert_eq!(token.signature, b"sig");
        assert_eq!(token.claims, claims());
    }

    #[test]
    fn decode_rejects_anything_else() {
        let payload = segment(json!({ "iss": ISSUER }));
        let cases = [
            ("gho_notAJwt".to_string(), "not a JWT"),
            ("not.a.jwt".to_string(), "not a JWT"),
            ("a.b.c.d".to_string(), "not a JWT"),
            (
                format!("{}.{payload}.c2ln", segment(json!({ "alg": "none" }))),
                "alg must be RS256",
            ),
            (
                format!("{}.{payload}.c2ln", segment(json!({ "alg": "HS256" }))),
                "alg must be RS256",
            ),
        ];
        for (jwt, expected) in cases {
            assert_eq!(Jwt::decode(&jwt).err(), Some(invalid(expected)), "{jwt}");
        }
    }

    #[test]
    fn keyset_keeps_rsa_keys_and_refetches_sparingly() {
        let jwks: Jwks = serde_json::from_value(json!({ "keys": [
            { "kty": "RSA", "kid": "key-1", "n": "AQAB", "e": "AQAB" },
            { "kty": "EC", "kid": "key-2", "x": "AA", "y": "AA" },
        ]}))
        .unwrap();
        let set = KeySet::parse(jwks, 0);
        assert_eq!(set.keys.len(), 1);

        assert_eq!(KeySet::lookup(None, Some("key-1"), 0), Lookup::Fetch);
        assert!(matches!(
            KeySet::lookup(Some(&set), Some("key-1"), 1),
            Lookup::Hit(_)
        ));
        // Without a kid, the only key.
        assert!(matches!(
            KeySet::lookup(Some(&set), None, 1),
            Lookup::Hit(_)
        ));
        assert_eq!(
            KeySet::lookup(Some(&set), Some("key-1"), JWKS_TTL_MS),
            Lookup::Fetch
        );
        assert_eq!(
            KeySet::lookup(Some(&set), Some("key-2"), 1),
            Lookup::Unknown
        );
        assert_eq!(
            KeySet::lookup(Some(&set), Some("key-2"), JWKS_MIN_REFETCH_MS),
            Lookup::Fetch
        );
    }

    #[test]
    fn says_what_the_validation_found_wrong() {
        let problem = json!({
            "type": "x", "title": "Request validation failed", "status": 422, "code": "request_validation_failed",
            "errors": [
                { "code": "min_length", "location": "/body/token", "message": "does not meet the length constraint" },
                { "code": "required", "location": "/body/grant_type", "message": "is required" },
            ],
        });
        assert_eq!(
            rejection(problem.to_string().as_bytes()),
            "/body/token does not meet the length constraint; /body/grant_type is required"
        );
        let media = json!({ "type": "x", "title": "Unsupported media type", "status": 415, "code": "unsupported_media_type" });
        assert_eq!(
            rejection(media.to_string().as_bytes()),
            "the body must be form-encoded (application/x-www-form-urlencoded)"
        );
    }
}
