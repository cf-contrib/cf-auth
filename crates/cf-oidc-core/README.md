# cf-oidc-core

OIDC tokens in Cloudflare Workers: verifying them, for any issuer (GitHub
Actions, GitLab CI, Cloudflare Access, or a broker that issues its own), and
signing them, for a Worker that is an issuer. cf-oidc-exchange verifies the
tokens exchanges present with it and signs its own, and
[cf-nix-cache](https://github.com/cf-contrib/cf-nix-cache) verifies the tokens
uploads present.

A token picks its provider by its `iss`, which must be one a provider names
exactly. Its RS256 signature is checked with the runtime's WebCrypto, so no RSA
crate ends up in the wasm, against that issuer's keys: found through its
discovery document, or a configured `jwks_uri`, never through anything in the
token. Then `iss`, `aud` (a trailing `/` ignored), `exp` and `nbf` are checked
with 60 seconds of clock tolerance, and the token is accepted if one of the
provider's claim sets matches.

```rust
use cf_oidc_core::{ClaimSet, Provider};

impl Provider for MyProviderConfig {
    fn issuer(&self) -> &str { &self.issuer }
    fn audience(&self) -> &str { &self.audience }
    fn jwks_uri(&self) -> Option<&str> { self.jwks_uri.as_deref() }
    fn claims(&self) -> &[ClaimSet] { &self.claims }
}

// In a Worker, before the handler. The future isn't Send: wrap it in
// worker::send::SendFuture where axum wants one.
let identity = cf_oidc_core::verify(&token, &providers).await?;

// Later, for the same token, without verifying it again.
let identity = cf_oidc_core::verified(&token);

// A Worker that issues tokens: sign them, and publish the key's public half.
let key = cf_oidc_core::SigningKey::import(&pkcs8_pem).await?;
let signed = key.sign(claims).await?;      // signed.jwt, signed.jti
let jwk = key.public_jwk();
```

| | |
|---|---|
| `Provider` | What a token is checked against: the issuer, the audience, where the keys are, and the claim sets. Implement it on your configuration's type. |
| `ClaimSet` | Claim name to pattern, deserialized from a JSON object. A pattern is exact, or a prefix ending in one `*`; `*_id` claims must be exact. Numbers and booleans compare as written, and a list claim matches if any entry does. |
| `verify` | Verifies a token, and keeps the outcome until it expires. |
| `verified` | The identity of a token `verify` accepted in this isolate. |
| `Identity` | The token's issuer and claims, and which claim set matched. |
| `Error` | `Unauthorized` (an invalid token, or an issuer no provider is for), `Forbidden` (no claim set matches) or `Upstream` (the issuer's keys couldn't be had). |
| `SigningKey` | An RSA private key (PKCS#8 PEM, at least 2048 bits) imported into WebCrypto. Its `kid` is the public key's RFC 7638 thumbprint, so a new key gets a new one. `sign` signs claims with RS256 and gives them a fresh `jti`; `public_jwk` is what a JWKS publishes. |
| `SignedToken` | The signed JWT, and its `jti`. |
| `KeyError` | Why a key can't be imported, or a token signed. |
| `check_url` | Whether a URL is HTTPS, or plain HTTP on loopback: for checking issuers and `jwks_uri`s in your configuration. |

Each issuer's keys are cached per isolate for 10 minutes, and a `kid` the
cache doesn't know refetches them at most every 30 seconds. A token without a
`kid` takes the issuer's only key. Outcomes are cached per isolate by the
token's SHA-256, refusals by claim set too, at most 1024 of them.
