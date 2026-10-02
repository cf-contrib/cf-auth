//! The integration tests' world: stand-ins for the OIDC issuers, GitHub's API
//! and Cloudflare's, served from the test process, and the scenario the Worker
//! reads on every request. All IDs, tokens and keys are made up.

#![allow(dead_code)]

use std::{
    collections::{BTreeMap, HashMap},
    sync::{LazyLock, Mutex, MutexGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{Path, Query, Request},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, get},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng};
use rsa::{
    BigUint, RsaPrivateKey, RsaPublicKey,
    pkcs1v15::{Signature, SigningKey, VerifyingKey},
    sha2::Sha256,
    signature::{SignatureEncoding, Signer, Verifier},
    traits::PublicKeyParts,
};
use serde_json::{Map, Value, json};

/// Where `tests/run.sh` serves the Worker. It's also the broker's own URL in the
/// test policy, and the audience of the stand-in issuers' tokens.
pub const BROKER: &str = "http://127.0.0.1:8790";
pub const AUDIENCE: &str = BROKER;

/// Where the stand-ins listen; `wrangler.test.toml` points the Worker here.
const STAND_INS: &str = "http://127.0.0.1:8791";
const STAND_INS_ADDR: &str = "127.0.0.1:8791";

pub const ACCOUNT_ID: &str = "0123456789abcdef0123456789abcdef";
pub const ZONE_ID: &str = "fedcba9876543210fedcba9876543210";
pub const OWNER_ID: &str = "100000001";
pub const USER_ID: &str = "300000004";
pub const TEAM_ID: &str = "400000005";
pub const USER_TOKEN: &str = "gho_exampleUserToken0000000000000000000";
pub const CACHE: &str = "https://cf-nix-cache.example.com";

/// The broker tokens `tests/run.sh` puts in the local Secrets Store.
pub const BROKER_TOKEN: &str = "test-broker-token";
pub const BROKER_TOKEN_ID: &str = "tok-broker";
pub const ROTATED_TOKEN: &str = "test-broker-token-rotated";

pub const GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub const ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
pub const ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
pub const JWT_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";
pub const R2_CREDENTIALS: &str = "urn:cf-oidc-auth:params:oauth:token-type:r2-credentials";

const KID: &str = "test-key";

/// The stand-in issuers' signing key, from a fixed seed.
static KEY: LazyLock<RsaPrivateKey> = LazyLock::new(|| {
    RsaPrivateKey::new(&mut ChaCha8Rng::seed_from_u64(11), 2048).expect("the key generates")
});

/// An issuer the stand-ins serve: `http://127.0.0.1:8791/issuers/<name>`.
pub fn issuer(name: &str) -> String {
    format!("{STAND_INS}/issuers/{name}")
}

/// A fresh issuer, so the Worker hasn't cached its keys or discovery document.
pub fn fresh_issuer(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    issuer(&format!("{prefix}-{nanos}"))
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

/// What the Worker sees: the scenario it reads, and the stand-ins' state.
pub struct World {
    /// The policy, the account, and which bindings hold the broker token and signing key.
    pub scenario: Value,
    /// Discovery documents that differ from the issuer's own, by issuer name.
    pub discovery: HashMap<String, Value>,
    pub cloudflare: FakeCloudflare,
    pub github: FakeGitHub,
}

impl World {
    fn new() -> Self {
        Self {
            scenario: json!({
                "policy": test_policy(),
                "account_id": ACCOUNT_ID,
                "broker_token": "CF_OIDC_EXCHANGE_API_BROKER_TOKEN",
                "signing_key": "CF_OIDC_EXCHANGE_API_SIGNING_KEY",
            }),
            discovery: HashMap::new(),
            cloudflare: FakeCloudflare::new(),
            github: FakeGitHub::new(),
        }
    }

    /// The policy, to change.
    pub fn policy(&mut self) -> &mut Value {
        &mut self.scenario["policy"]
    }
}

static WORLD: LazyLock<Mutex<World>> = LazyLock::new(|| Mutex::new(World::new()));

/// One test at a time: they share the stand-ins, and the Worker's log.
static TEST: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The world, to look at or change.
pub fn world() -> MutexGuard<'static, World> {
    WORLD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A test's hold on the world, fresh: the default scenario and stand-ins.
pub struct Test {
    _guard: tokio::sync::MutexGuard<'static, ()>,
    /// Where the Worker's log was when the test began.
    log_from: u64,
}

/// Starts a test: waits for the one before it, then resets the world.
pub async fn start() -> Test {
    LazyLock::force(&SERVER);
    let guard = TEST.lock().await;
    *world() = World::new();
    Test {
        _guard: guard,
        log_from: log_len(),
    }
}

// ---------------------------------------------------------------------------
// The Worker's log
// ---------------------------------------------------------------------------

fn log_path() -> String {
    std::env::var("CF_OIDC_EXCHANGE_API_LOG").unwrap_or_else(|_| ".wrangler/integration.log".into())
}

fn log_len() -> u64 {
    std::fs::metadata(log_path()).map(|m| m.len()).unwrap_or(0)
}

impl Test {
    /// The Worker's log since the test began.
    pub fn log(&self) -> String {
        let bytes = std::fs::read(log_path()).unwrap_or_default();
        String::from_utf8_lossy(&bytes[(self.log_from as usize).min(bytes.len())..]).into_owned()
    }

    /// The audit lines since the test began.
    pub fn audit_lines(&self) -> Vec<Value> {
        self.log()
            .lines()
            .filter_map(|line| line.find(r#"{"event":"#).map(|at| &line[at..]))
            .filter_map(|line| {
                // Warnings come with a colour reset after the JSON.
                let end = line.rfind('}')?;
                serde_json::from_str(&line[..=end]).ok()
            })
            .collect()
    }

    /// The first audit line for `event`, waiting a moment for wrangler to print it.
    pub async fn audit(&self, event: &str) -> Option<Value> {
        for _ in 0..20 {
            if let Some(line) = self.audit_lines().into_iter().find(|l| l["event"] == event) {
                return Some(line);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        None
    }

    /// Every audit line for `event`, after giving wrangler a moment.
    pub async fn audits(&self, event: &str) -> Vec<Value> {
        tokio::time::sleep(Duration::from_millis(300)).await;
        self.audit_lines()
            .into_iter()
            .filter(|l| l["event"] == event)
            .collect()
    }

    pub async fn deny(&self) -> Value {
        self.audit("token.deny").await.expect("a token.deny line")
    }
}

/// That an audit line records a refusal with `error`, saying `message` (or
/// something that contains it).
#[track_caller]
pub fn assert_refused(line: &Value, error: &str, message: &str) {
    assert_eq!(line["error"], error, "{line}");
    let said = line["message"].as_str().unwrap_or_default();
    assert!(
        said.contains(message),
        "{said:?} doesn't say {message:?}: {line}"
    );
}

/// That a response is the error every error is: `error`, with a message.
#[track_caller]
pub fn assert_error(reply: &Reply, error: &str) {
    let body = reply.json();
    assert_eq!(body["error"], error, "{body}");
    assert!(
        body["message"].as_str().is_some_and(|m| !m.is_empty()),
        "{body}"
    );
}

/// Whether `actual` has every field of `expected`, as `toMatchObject` checks.
#[track_caller]
pub fn assert_matches(actual: &Value, expected: Value) {
    for (key, value) in expected.as_object().unwrap() {
        assert_eq!(&actual[key], value, "{key} in {actual}");
    }
}

// ---------------------------------------------------------------------------
// Tokens and calls
// ---------------------------------------------------------------------------

/// A GitHub Actions job's claims.
pub fn github_claims(overrides: Value) -> Value {
    let mut claims = json!({
        "repository": "example-org/api",
        "repository_id": "200000003",
        "repository_owner": "example-org",
        "repository_owner_id": OWNER_ID,
        "ref": "refs/heads/main",
        "ref_type": "branch",
        "environment": "prod",
        "event_name": "push",
        "workflow_ref": "example-org/api/.github/workflows/deploy.yml@refs/heads/main",
        "job_workflow_ref": "example-org/api/.github/workflows/deploy.yml@refs/heads/main",
        "run_id": "1234567890",
        "run_attempt": "1",
        "actor_id": USER_ID,
        "runner_environment": "github-hosted",
    });
    merge(&mut claims, overrides);
    claims
}

/// Sets each of `overrides`' fields in `target`; `null` removes one.
pub fn merge(target: &mut Value, overrides: Value) {
    let target = target.as_object_mut().unwrap();
    for (key, value) in overrides.as_object().cloned().unwrap_or_default() {
        if value.is_null() {
            target.remove(&key);
        } else {
            target.insert(key, value);
        }
    }
}

/// A token from the `actions` stand-in issuer.
pub fn sign(claims: Value) -> String {
    sign_with(&issuer("actions"), claims, AUDIENCE, 300)
}

/// A token from `iss` for `aud`, expiring in `ttl` seconds, with `claims`.
pub fn sign_with(iss: &str, claims: Value, aud: &str, ttl: i64) -> String {
    let now = now() as i64;
    let mut payload = json!({ "iss": iss, "aud": aud, "iat": now, "exp": now + ttl });
    merge(&mut payload, claims);
    let header = json!({ "alg": "RS256", "kid": KID });
    let encode = |value: &Value| URL_SAFE_NO_PAD.encode(value.to_string());
    let input = format!("{}.{}", encode(&header), encode(&payload));
    let signature = SigningKey::<Sha256>::new(KEY.clone()).sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_vec()))
}

pub struct Reply {
    pub status: u16,
    pub cache_control: Option<String>,
    pub text: String,
}

impl Reply {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or_else(|_| panic!("not JSON: {}", self.text))
    }
}

async fn reply(response: reqwest::Response) -> Reply {
    Reply {
        status: response.status().as_u16(),
        cache_control: response
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .map(String::from),
        text: response.text().await.unwrap(),
    }
}

/// POSTs a form to the Worker.
pub async fn post_form(path: &str, form: &[(&str, &str)]) -> Reply {
    let response = reqwest::Client::new()
        .post(format!("{BROKER}{path}"))
        .form(form)
        .send()
        .await
        .expect("the Worker answers");
    reply(response).await
}

/// POSTs a body of any content type to the Worker.
pub async fn post_raw(path: &str, content_type: &str, body: String) -> Reply {
    let response = reqwest::Client::new()
        .post(format!("{BROKER}{path}"))
        .header("content-type", content_type)
        .body(body)
        .send()
        .await
        .expect("the Worker answers");
    reply(response).await
}

pub async fn call(method: Method, path: &str) -> Reply {
    let response = reqwest::Client::new()
        .request(method, format!("{BROKER}{path}"))
        .send()
        .await
        .expect("the Worker answers");
    reply(response).await
}

/// Exchanges a job's OIDC token at `POST /oauth/token`, with the broker's own fields.
pub async fn job_token(jwt: &str, fields: &[(&str, &str)]) -> Reply {
    let mut form = vec![
        ("grant_type", GRANT),
        ("subject_token", jwt),
        ("subject_token_type", ID_TOKEN),
    ];
    form.extend_from_slice(fields);
    post_form("/oauth/token", &form).await
}

/// Exchanges a person's GitHub token, with the broker's own fields.
pub async fn user_token(token: &str, fields: &[(&str, &str)]) -> Reply {
    let mut form = vec![
        ("grant_type", GRANT),
        ("subject_token", token),
        ("subject_token_type", ACCESS_TOKEN),
    ];
    form.extend_from_slice(fields);
    post_form("/oauth/token", &form).await
}

/// Revokes `token` at `POST /oauth/revoke`, form-encoded as RFC 7009 has it.
pub async fn revoke(token: Option<&str>) -> Reply {
    match token {
        Some(token) => {
            post_form(
                "/oauth/revoke",
                &[("token", token), ("token_type_hint", "access_token")],
            )
            .await
        }
        None => post_form("/oauth/revoke", &[]).await,
    }
}

/// Verifies a token the broker signed with the keys it publishes, and returns
/// its header and claims.
pub async fn verify_broker_token(jwt: &str) -> (Value, Value) {
    let jwks = call(Method::GET, "/.well-known/jwks").await.json();
    let [header, payload, signature] = jwt.split('.').collect::<Vec<_>>()[..] else {
        panic!("not a JWT: {jwt}");
    };
    let decode =
        |s: &str| -> Value { serde_json::from_slice(&URL_SAFE_NO_PAD.decode(s).unwrap()).unwrap() };
    let (header_json, claims) = (decode(header), decode(payload));
    let key = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kid"] == header_json["kid"])
        .expect("the token's kid is published");
    let number = |name: &str| {
        BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(key[name].as_str().unwrap()).unwrap())
    };
    let public = RsaPublicKey::new(number("n"), number("e")).unwrap();
    let signature =
        Signature::try_from(URL_SAFE_NO_PAD.decode(signature).unwrap().as_slice()).unwrap();
    VerifyingKey::<Sha256>::new(public)
        .verify(format!("{header}.{payload}").as_bytes(), &signature)
        .expect("the broker's signature verifies");
    (header_json, claims)
}

// ---------------------------------------------------------------------------
// The test policy
// ---------------------------------------------------------------------------

/// A version 2 policy: one GitHub Actions provider, `github`, for the `actions`
/// stand-in issuer, and three profiles for it.
pub fn test_policy() -> Value {
    json!({
        "version": 2,
        "issuer": AUDIENCE,
        "providers": [{ "name": "github", "issuer": issuer("actions"), "audience": AUDIENCE, "claims": { "repository_owner_id": OWNER_ID } }],
        "defaults": { "ttl": "15m", "max_ttl": "1h" },
        "profiles": [
            {
                "name": "infra-cloudflare",
                "provider": "github",
                "claims": { "repository_id": "200000002", "ref": "refs/heads/main", "environment": "prod" },
                "ttl": "15m",
                "token": { "policies": [{
                    "effect": "allow",
                    "permissions": ["Zone Write", "DNS Write"],
                    "resources": { (format!("com.cloudflare.api.account.zone.{ZONE_ID}")): "*" },
                }]},
            },
            {
                "name": "workers-deploy",
                "provider": "github",
                "claims": { "repository": "example-org/*", "ref": "refs/heads/main", "environment": "prod" },
                "token": { "policies": [{
                    "effect": "allow",
                    "permissions": ["Workers Scripts Write"],
                    "resources": { (format!("com.cloudflare.api.account.{ACCOUNT_ID}")): "*" },
                }]},
            },
            {
                "name": "service-dns",
                "provider": "github",
                "claims": { "job_workflow_ref": "example-org/workflows/.github/workflows/deploy.yml@refs/heads/main" },
                "ttl": "5m",
                "token": { "policies": [{
                    "effect": "allow",
                    "permissions": ["DNS Write"],
                    "resources": { (format!("com.cloudflare.api.account.zone.{ZONE_ID}")): "*" },
                }]},
            },
        ],
    })
}

/// The provider for people's GitHub tokens, pinned to the test org.
pub fn people() -> Value {
    json!({ "name": "people", "issuer": "https://github.com", "claims": { "repository_owner_id": OWNER_ID } })
}

/// workers-deploy's token, for profiles that need one.
pub fn deploy_token() -> Value {
    test_policy()["profiles"][1]["token"].clone()
}

// ---------------------------------------------------------------------------
// The stand-in server
// ---------------------------------------------------------------------------

static SERVER: LazyLock<()> = LazyLock::new(|| {
    let listener = std::net::TcpListener::bind(STAND_INS_ADDR)
        .unwrap_or_else(|err| panic!("the stand-ins can't listen on {STAND_INS_ADDR}: {err}"));
    listener.set_nonblocking(true).unwrap();
    let app = Router::new()
        .route(
            "/scenario",
            get(|| async { Json(world().scenario.clone()) }),
        )
        .route(
            "/issuers/{name}/.well-known/openid-configuration",
            get(discovery),
        )
        .route("/issuers/{name}/.well-known/jwks", get(jwks))
        .route("/github/{*path}", any(github))
        .route("/cloudflare/client/v4/{*path}", any(cloudflare));
    // Each test has its own runtime, so the server gets a thread of its own.
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                axum::serve(listener, app).await.unwrap();
            });
    });
});

async fn discovery(Path(name): Path<String>) -> Json<Value> {
    let issuer = issuer(&name);
    let own = json!({ "issuer": issuer, "jwks_uri": format!("{issuer}/.well-known/jwks") });
    Json(world().discovery.get(&name).cloned().unwrap_or(own))
}

async fn jwks() -> Json<Value> {
    Json(json!({ "keys": [{
        "kty": "RSA",
        "kid": KID,
        "alg": "RS256",
        "use": "sig",
        "n": URL_SAFE_NO_PAD.encode(KEY.n().to_bytes_be()),
        "e": URL_SAFE_NO_PAD.encode(KEY.e().to_bytes_be()),
    }]}))
}

async fn github(
    method: Method,
    Path(path): Path<String>,
    Query(query): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    world()
        .github
        .handle(method, &format!("/{path}"), &query, &auth)
}

async fn cloudflare(
    Path(path): Path<String>,
    Query(query): Query<BTreeMap<String, String>>,
    req: Request,
) -> Response {
    let method = req.method().clone();
    let auth = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .trim_start_matches("Bearer ")
        .to_string();
    let bytes = axum::body::to_bytes(req.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    let body = serde_json::from_slice(&bytes).ok();
    world()
        .cloudflare
        .handle(method, &format!("/{path}"), &query, &auth, body)
}

fn json_reply(status: u16, body: Value) -> Response {
    (StatusCode::from_u16(status).unwrap(), Json(body)).into_response()
}

// ---------------------------------------------------------------------------
// Cloudflare
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct StoredToken {
    pub id: String,
    pub name: String,
    pub value: String,
    pub status: String,
    pub expires_on: Option<String>,
    pub policies: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CloudflareRequest {
    pub method: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub body: Option<Value>,
}

/// Cloudflare's account tokens API, permission groups and R2 temporary credentials, in memory.
pub struct FakeCloudflare {
    pub tokens: BTreeMap<String, StoredToken>,
    pub requests: Vec<CloudflareRequest>,
    pub fail_create: bool,
    pub fail_r2: bool,
    /// Fails temp-access-credentials for this bucket only.
    pub fail_r2_bucket: Option<String>,
    seq: u32,
}

pub fn permission_groups() -> Value {
    json!([
        { "id": "pg-workers-scripts-write", "name": "Workers Scripts Write", "scopes": ["com.cloudflare.api.account"] },
        { "id": "pg-dns-write", "name": "DNS Write", "scopes": ["com.cloudflare.api.account.zone"] },
        { "id": "pg-zone-write", "name": "Zone Write", "scopes": ["com.cloudflare.api.account.zone"] },
        // Same name at two scopes, to exercise disambiguation.
        { "id": "pg-lb-write-account", "name": "Load Balancers Write", "scopes": ["com.cloudflare.api.account"] },
        { "id": "pg-lb-write-zone", "name": "Load Balancers Write", "scopes": ["com.cloudflare.api.account.zone"] },
    ])
}

fn envelope(result: Value) -> Response {
    json_reply(
        200,
        json!({ "success": true, "errors": [], "messages": [], "result": result }),
    )
}

fn api_error(status: u16, message: &str) -> Response {
    json_reply(
        status,
        json!({ "success": false, "errors": [{ "code": 1000, "message": message }], "messages": [], "result": null }),
    )
}

impl FakeCloudflare {
    fn new() -> Self {
        let mut fake = Self {
            tokens: BTreeMap::new(),
            requests: Vec::new(),
            fail_create: false,
            fail_r2: false,
            fail_r2_bucket: None,
            seq: 0,
        };
        fake.add(
            Some(BROKER_TOKEN_ID),
            "cf-oidc broker token",
            Some(BROKER_TOKEN),
            None,
            "active",
        );
        fake
    }

    /// Adds a token, and returns it.
    pub fn add(
        &mut self,
        id: Option<&str>,
        name: &str,
        value: Option<&str>,
        expires_on: Option<String>,
        status: &str,
    ) -> StoredToken {
        self.seq += 1;
        let id = id
            .map(String::from)
            .unwrap_or_else(|| format!("tok-{}", self.seq));
        let token = StoredToken {
            value: value
                .map(String::from)
                .unwrap_or_else(|| format!("value-{id}")),
            id: id.clone(),
            name: name.into(),
            status: status.into(),
            expires_on,
            policies: json!([]),
        };
        self.tokens.insert(id, token.clone());
        token
    }

    /// Requests other than the permission-group list, which the Worker caches.
    pub fn calls(&self) -> Vec<&CloudflareRequest> {
        self.requests
            .iter()
            .filter(|r| !r.path.ends_with("/tokens/permission_groups"))
            .collect()
    }

    fn view(token: &StoredToken) -> Value {
        json!({ "id": token.id, "name": token.name, "status": token.status, "expires_on": token.expires_on, "policies": token.policies })
    }

    fn handle(
        &mut self,
        method: Method,
        path: &str,
        query: &BTreeMap<String, String>,
        auth: &str,
        body: Option<Value>,
    ) -> Response {
        self.requests.push(CloudflareRequest {
            method: method.to_string(),
            path: path.into(),
            query: query.clone(),
            body: body.clone(),
        });
        let acct = format!("/accounts/{ACCOUNT_ID}");

        if method == Method::GET && path == format!("{acct}/tokens/permission_groups") {
            return envelope(permission_groups());
        }
        // Everything below takes the broker token, except verify, which takes the presented one.
        if method == Method::GET && path == format!("{acct}/tokens/verify") {
            return match self.tokens.values().find(|t| t.value == auth) {
                Some(t) => {
                    envelope(json!({ "id": t.id, "status": t.status, "expires_on": t.expires_on }))
                }
                None => api_error(401, "Invalid API Token"),
            };
        }
        if auth != BROKER_TOKEN {
            return api_error(403, "Unauthorized");
        }

        if method == Method::POST && path == format!("{acct}/tokens") {
            if self.fail_create {
                return api_error(500, "Internal Server Error");
            }
            let body = body.unwrap_or_default();
            let expires_on = body["expires_on"].as_str().map(String::from);
            let mut token = self.add(
                None,
                body["name"].as_str().unwrap_or_default(),
                None,
                expires_on,
                "active",
            );
            token.policies = body["policies"].clone();
            self.tokens.insert(token.id.clone(), token.clone());
            let mut created = Self::view(&token);
            created["value"] = json!(token.value);
            return envelope(created);
        }
        if method == Method::POST && path == format!("{acct}/r2/temp-access-credentials") {
            let body = body.unwrap_or_default();
            let bucket = body["bucket"].as_str().unwrap_or_default();
            if self.fail_r2 || self.fail_r2_bucket.as_deref() == Some(bucket) {
                return api_error(403, "Unauthorized to access requested resource");
            }
            return envelope(json!({
                "accessKeyId": body["parentAccessKeyId"],
                "secretAccessKey": "r2-secret-value",
                "sessionToken": "r2-session-token-value",
            }));
        }
        if method == Method::GET && path == format!("{acct}/tokens") {
            let page = query
                .get("page")
                .and_then(|p| p.parse::<f64>().ok())
                .unwrap_or(1.0);
            let include_expired = query.get("include_expired").is_some_and(|v| v == "true");
            let all: Vec<Value> = self
                .tokens
                .values()
                .filter(|t| include_expired || t.status != "expired")
                .map(Self::view)
                .collect();
            return envelope(if page > 1.0 { json!([]) } else { json!(all) });
        }
        if let Some(id) = path.strip_prefix(&format!("{acct}/tokens/")) {
            let Some(token) = self.tokens.get(id).cloned() else {
                return api_error(404, "Not found");
            };
            if method == Method::GET {
                return envelope(Self::view(&token));
            }
            if method == Method::DELETE {
                self.tokens.remove(id);
                return envelope(json!({ "id": token.id }));
            }
        }
        api_error(404, &format!("unhandled {method} {path}"))
    }
}

// ---------------------------------------------------------------------------
// GitHub
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct FakeRepo {
    pub id: u64,
    pub full_name: &'static str,
    pub owner_id: u64,
    /// The test user's role; `None` means the repo is visible without access.
    pub role: Option<&'static str>,
}

pub struct GitHubFailure {
    pub path: &'static str,
    pub status: u16,
    pub headers: Vec<(&'static str, &'static str)>,
}

/// GitHub's REST API for one user: `/user`, repos and `/user/teams`.
pub struct FakeGitHub {
    pub requests: Vec<String>,
    pub repos: Vec<FakeRepo>,
    pub teams: Vec<(u64, u64)>,
    /// Replies with this to every request whose path starts with its `path`.
    pub fail: Option<GitHubFailure>,
}

impl FakeGitHub {
    fn new() -> Self {
        let owner: u64 = OWNER_ID.parse().unwrap();
        Self {
            requests: Vec::new(),
            repos: vec![
                FakeRepo {
                    id: 200000002,
                    full_name: "example-org/infra",
                    owner_id: owner,
                    role: Some("write"),
                },
                FakeRepo {
                    id: 200000003,
                    full_name: "example-org/api",
                    owner_id: owner,
                    role: Some("read"),
                },
                FakeRepo {
                    id: 200000009,
                    full_name: "other-org/infra",
                    owner_id: 999999,
                    role: Some("admin"),
                },
            ],
            teams: vec![(TEAM_ID.parse().unwrap(), owner), (400000099, 999999)],
            fail: None,
        }
    }

    fn handle(
        &mut self,
        _method: Method,
        path: &str,
        query: &BTreeMap<String, String>,
        auth: &str,
    ) -> Response {
        let search: Vec<String> = query.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let shown = if search.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{}", search.join("&"))
        };
        self.requests.push(shown);
        if let Some(fail) = self.fail.as_ref().filter(|f| path.starts_with(f.path)) {
            let mut response = json_reply(fail.status, json!({ "message": "fail" }));
            for (name, value) in &fail.headers {
                response.headers_mut().insert(*name, value.parse().unwrap());
            }
            return response;
        }
        if auth != format!("Bearer {USER_TOKEN}") {
            return json_reply(401, json!({ "message": "Bad credentials" }));
        }
        if path == "/user" {
            return json_reply(
                200,
                json!({ "id": USER_ID.parse::<u64>().unwrap(), "login": "octocat" }),
            );
        }
        if path == "/user/teams" {
            let teams: Vec<Value> = self
                .teams
                .iter()
                .map(|(id, org)| json!({ "id": id, "organization": { "id": org } }))
                .collect();
            return json_reply(
                200,
                if query.get("page").map(String::as_str) == Some("1") {
                    json!(teams)
                } else {
                    json!([])
                },
            );
        }
        let by_name = path.strip_prefix("/repos/");
        let by_id = path.strip_prefix("/repositories/");
        let repo = self
            .repos
            .iter()
            .find(|r| Some(r.full_name) == by_name || Some(r.id.to_string().as_str()) == by_id);
        let Some(repo) = repo else {
            return json_reply(404, json!({ "message": "Not Found" }));
        };
        let order = ["read", "triage", "write", "maintain", "admin"];
        let at = repo
            .role
            .and_then(|role| order.iter().position(|r| *r == role));
        let has = |level: usize| at.is_some_and(|at| at >= level);
        json_reply(
            200,
            json!({
                "id": repo.id,
                "full_name": repo.full_name,
                "owner": { "id": repo.owner_id, "login": repo.full_name.split('/').next().unwrap() },
                "permissions": { "pull": has(0), "triage": has(1), "push": has(2), "maintain": has(3), "admin": has(4) },
            }),
        )
    }
}

/// Merges `extra` into `value`'s map; for building policies.
pub fn with(mut value: Value, extra: Value) -> Value {
    merge(&mut value, extra);
    value
}

pub fn obj(value: &Value) -> &Map<String, Value> {
    value.as_object().unwrap()
}
