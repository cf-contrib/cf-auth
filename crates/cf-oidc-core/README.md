# cf-oidc-core

OIDC tokens in Cloudflare Workers: verifying them, for any issuer (GitHub
Actions, GitLab CI, Cloudflare Access, or a broker that issues its own), and
signing them, for a Worker that is an issuer. cf-oidc-exchange verifies the
tokens exchanges present with it and signs its own, and
[cf-nix-cache](https://github.com/cf-contrib/cf-nix-cache) verifies the tokens
uploads present.

Accepting a token takes two steps. `verify` validates it as a JWT, as RFC 7519
§7.2 and RFC 8725 say:

- It picks its provider by its `iss`, which must be one a provider names
  exactly.
- Its JOSE Header must have `alg` RS256 and no `crit`, and the `typ` the
  provider names, if it names one.
- Its RS256 signature is checked with the runtime's WebCrypto, so no RSA crate
  ends up in the wasm. The keys are that issuer's, found through its OpenID
  Provider Metadata, its Authorization Server Metadata (RFC 8414) if it has
  none, or a configured `jwks_uri`: never through anything in the token. Keys whose `use`, `key_ops` or `alg` say they aren't for RS256
  signatures are skipped.
- Its registered claims are validated: `iss`, `aud` (a trailing `/` ignored),
  `exp` and `nbf`, with 60 seconds of clock tolerance. Any registered claim of
  the wrong type refuses it.

Then `authorize` matches its claims against claim rules: the policy, which no
RFC covers.

```rust
use cf_oidc_core::{ClaimRule, Provider};

impl Provider for MyProviderConfig {
    fn issuer(&self) -> &str { &self.issuer }
    fn audience(&self) -> &str { &self.audience }
    // Optional: where its keys are, and the typ its tokens must have.
    fn jwks_uri(&self) -> Option<&str> { self.jwks_uri.as_deref() }
}

// In a Worker, before the handler. The future isn't Send: wrap it in
// worker::send::SendFuture where axum wants one.
let (provider, jwt) = cf_oidc_core::verify(&token, &providers).await?;
let rule = cf_oidc_core::authorize(&jwt.claims, &provider.rules)?;
let sub = jwt.claims.sub();                // the registered claims, typed
let repo = jwt.claims.get("repository");  // any other, by name

// Later, for the same token, without verifying it again.
let jwt = cf_oidc_core::verified(&token);

// A Worker that issues tokens: sign them, and publish the key's public half.
let key = cf_oidc_core::SigningKey::import(&pkcs8_pem).await?;
let signed = key.sign_access_token(AccessTokenClaims { iss, sub, aud, client_id, iat, exp, other }).await?;
let signed = key.sign(claims).await?;      // any other JWT; signed.jwt, signed.jti
let jwk = key.public_jwk();

// A resource server that takes only access tokens from that Worker names
// typ: Some(cf_oidc_core::AT_JWT) for it.
```

| | |
|---|---|
| `Provider` | An OpenID Provider whose tokens are accepted: its issuer, the audience its tokens must be for, and optionally its `jwks_uri` and the `typ` its tokens must have. Implement it on your configuration's type. |
| `verify` | Validates a token against the provider its `iss` names, and keeps it until it expires. Returns the provider and the `Jwt`. |
| `authorize` | The index of the first `ClaimRule` a token's claims match. |
| `verified` | A token `verify` accepted in this isolate, if it hasn't expired. |
| `Jwt` | A verified token: its `Header` and its `Claims`. |
| `Header` | The JOSE Header parameters it was verified by: `alg`, `kid` and `typ`. |
| `Claims` | The JWT Claims Set. `iss()`, `sub()`, `aud()`, `exp()`, `nbf()`, `iat()`, `jti()`, and RFC 8693's `client_id()` and `scope()`, read the registered claims; it derefs to the JSON object, so any claim reads by name. |
| `AccessTokenClaims` | The claims RFC 9068 requires of a JWT access token (`iss`, `sub`, `aud`, `client_id`, `iat`, `exp`), and any others. |
| `ClaimRule` | Claim name to pattern, deserialized from a JSON object. A pattern is exact, or a prefix ending in one `*`; `*_id` claims must be exact. Numbers and booleans compare as written, and a list claim matches if any entry does. |
| `Error` | RFC 6750's codes: `InvalidToken` (an invalid token, or an issuer no provider is for), `InsufficientScope` (no claim rule matches), or `TemporarilyUnavailable` (the issuer's keys couldn't be had). |
| `SigningKey` | An RSA private key (PKCS#8 PEM, at least 2048 bits) imported into WebCrypto. Its `kid` is the public key's RFC 7638 thumbprint, so a new key gets a new one. `sign_access_token` signs `AccessTokenClaims` as an RFC 9068 access token (`typ` `at+jwt`), and `sign` any `Claims` as a JWT (`typ` `JWT`), both with RS256 and a fresh `jti`; `public_jwk` is what a JWK Set publishes. |
| `JWT`, `AT_JWT` | The `typ`s `sign` and `sign_access_token` give tokens, for `Provider::typ`. |
| `SignedToken` | The signed JWT, and its `jti`. |
| `KeyError` | Why a key can't be imported, or a token signed. |
| `check_url` | Whether a URL is HTTPS, or plain HTTP on loopback: for checking issuers and `jwks_uri`s in your configuration. |

Each issuer's keys are cached per isolate for 10 minutes, and a `kid` the
cache doesn't know refetches them at most every 30 seconds. A token without a
`kid` takes the issuer's only key. Verified tokens are cached per isolate by
the token's SHA-256, at most 1024 of them.
