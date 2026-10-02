# cf-oidc-exchange-api

The broker as a Rust Worker: the `oidc.exchange.v1` API that
[`cf-oidc-exchange-sdk`](../cf-oidc-exchange-sdk) generates from its OpenAPI
document, served over the Workers runtime with workers-rs. It replaces
[`packages/cf-oidc-broker`](../../packages/cf-oidc-broker).

| | |
|---|---|
| `src/policy` | The policy: loading, guardrails, matching, bucket prefixes. |
| `src/oidc.rs` | OIDC tokens: the provider by `iss`, RS256 against the issuer's keys, the standard claims. |
| `src/github.rs` | People's GitHub tokens, checked with GitHub's API. |
| `src/issuer.rs` | The broker's own RS256 tokens, for profiles with another service's `audience`. |
| `src/cloudflare.rs` | Account API tokens and R2 temporary credentials, through [cloudflare-rs](https://github.com/cf-contrib/cloudflare-rs). |
| `src/exchange.rs` | The flows: exchange, revocation, discovery, JWKS, health, cleanup. |
| `src/service` | The generated API's implementation, and the layer around its router. |
| `src/webcrypto.rs` | RS256 and SHA-256 through the runtime's WebCrypto: no RSA crate in the wasm. |
| `worker/entry.js` | The entry module: hands the Worker `policy.json`, a module beside it. |

## Development

`nix develop` at the repository root has the toolchain.

```sh
cp policy.example.json policy.json
wrangler dev
```

`cargo test` runs the unit tests. The integration tests run the Worker under
`wrangler dev`, built with the `stand-ins` feature, against stand-ins for the
OIDC issuers, GitHub and Cloudflare that the tests serve and control:

```sh
tests/run.sh
```

It creates made-up secrets in a local Secrets Store, starts `wrangler dev` with
`wrangler.test.toml` on port 8790, serves the stand-ins on 8791, and runs the
tests one at a time. A `stand-ins` build takes, on every request, the scenario
the running test sets: the policy, the account, and which bindings hold the
broker token and the signing key. A release build never reads it.
