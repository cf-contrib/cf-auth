# cf-oidc-exchange

> Keyless Cloudflare API access from GitHub Actions: a job trades its GitHub
> OIDC token for a short-lived, least-privilege Cloudflare API token, so no
> workflow stores a `CLOUDFLARE_API_TOKEN` secret.

[![CI](https://github.com/cf-contrib/cf-oidc-exchange/actions/workflows/ci.yml/badge.svg)](https://github.com/cf-contrib/cf-oidc-exchange/actions/workflows/ci.yml)
[![Rust (edition 2024)](https://img.shields.io/badge/Rust-2024-black?logo=rust)](https://www.rust-lang.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Nix Flake](https://img.shields.io/badge/Nix-Flake-5277C3?logo=nixos&logoColor=white)](https://nixos.wiki/wiki/Flakes)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> [!NOTE]
> **Pre-1.0.** The policy format and the broker API may still change between
> minor versions. cf-oidc-exchange fills a gap until Cloudflare trusts GitHub's OIDC
> issuer natively. When it does, swap the action and delete the broker.

```yaml
permissions:
  id-token: write

steps:
  - uses: cf-contrib/cf-oidc-exchange@v0.9.0 # x-release-please-version
    with:
      url: https://cf-oidc-exchange.example.com
      profile: workers-deploy
  - run: npx wrangler deploy # CLOUDFLARE_API_TOKEN + CLOUDFLARE_ACCOUNT_ID are set
```

| | Ships as | What it is |
|---|---|---|
| [`action`](action) | `uses: cf-contrib/cf-oidc-exchange@<version>` | The GitHub Action, in JavaScript with no runtime dependencies. Gets the job's OIDC token, exports the minted Cloudflare token, and revokes it at job end. |
| [`crates/cf-oidc-exchange-api`](crates/cf-oidc-exchange-api) | `index.js` + `index_bg.wasm.base64` in [Releases](https://github.com/cf-contrib/cf-oidc-exchange/releases) | The broker, a Cloudflare Worker written in Rust, in your account. Checks the OIDC token against your policy, and mints the Cloudflare token or R2 credentials, or signs a token for another service. |
| [`crates/cf-oidc-exchange-sdk`](crates/cf-oidc-exchange-sdk) | A Rust crate in this workspace; not published | The broker's HTTP API: its [OpenAPI document](crates/cf-oidc-exchange-sdk/openapi/oidc/exchange/v1/exchangev1.yaml), and the types, server traits and client generated from it; hand-written beside them, the health endpoints. The Worker builds on it. |
| [`crates/cf-oidc-core`](crates/cf-oidc-core) | A Rust crate in this workspace; not published | OIDC tokens in Workers, verified and signed. The Worker builds on it, and cf-nix-cache can too. |
| [`deployment/terraform`](deployment/terraform) | `//deployment/terraform?ref=<version>` | Deploys the released Worker with your policy, its bindings and its cron. |

The action and the broker, with its Terraform module, are released together from one tag, so deploy the broker from the release whose action you use. The action talks only to the broker, never to the Cloudflare API.

The broker takes OIDC tokens from any issuer you list: GitHub Actions, GitLab CI, HCP Terraform, or, for people, an identity provider such as [Cloudflare Access](crates/cf-oidc-exchange-api#people). Who gets what is in the policy's claim sets, the same rules [cf-nix-cache](https://github.com/cf-contrib/cf-nix-cache) uses.

Other services can trust the broker too. A profile with an `audience` gets the caller a short-lived token the broker signs itself, for that service, which verifies it with the broker's published keys. [cf-nix-cache](https://github.com/cf-contrib/cf-nix-cache) is the first such service. See [Tokens for other services](crates/cf-oidc-exchange-api#tokens-for-other-services).

## How it works

```mermaid
sequenceDiagram
    participant Job as GitHub Actions job
    participant OIDC as GitHub's OIDC issuer
    participant Broker as cf-oidc-exchange (Worker)
    participant CF as Cloudflare API

    Job->>OIDC: 1. request an OIDC token (aud = the action's url)
    OIDC-->>Job: JWT
    Job->>Broker: 2. POST /oauth/token (RFC 8693, the JWT as subject_token)
    Broker->>OIDC: metadata and keys (cached)
    Broker->>Broker: 3. verify the JWT, match the policy's claim sets, pick the profile
    Broker->>CF: 4. look up permission groups, create the token (expires_on)
    CF-->>Broker: token
    Broker-->>Job: access_token, token_id, account_id
    Note over Job: 5. mask and export CLOUDFLARE_API_TOKEN<br/>and CLOUDFLARE_ACCOUNT_ID for later steps
    Job->>Broker: 6. POST /oauth/revoke (RFC 7009, the post step)
    Broker->>CF: verify it, check it's a cf-oidc token, delete it
    Note over Broker,CF: an hourly cron deletes expired cf-oidc:* tokens
```

The only long-lived credential is the broker's **Cloudflare token**: an account-owned token with **Account API Tokens Write**, plus R2 permissions if profiles hand out [prefix-limited R2 credentials](crates/cf-oidc-exchange-api#buckets) (e.g. one shared Terraform-state bucket, each repo limited to its own prefix). It lives in Cloudflare Secrets Store, bound to the Worker, so it never passes through Terraform or CI and never leaves the Worker.

## Do you need it?

A stored `CLOUDFLARE_API_TOKEN` never expires unless someone rotates it. It's usually over-scoped, anyone who can run a workflow that reads it can exfiltrate it, and nothing links a job to what the token did.

| Approach | Secret in GitHub | Token lifetime | Notes |
|---|---|---|---|
| API token as a GitHub secret | yes | long-lived | The status quo |
| Token in AWS/GCP Secret Manager, read via their OIDC | no | long-lived | Fine if you already use AWS/GCP; the Cloudflare token is still long-lived |
| [bounded-systems/cf-oidc-token-broker](https://github.com/bounded-systems/cf-oidc-token-broker) | no | short-lived | Same idea. The policy is code you edit and redeploy |
| **cf-oidc-exchange** | **no** | **short-lived** | Declarative policy, prebuilt release, automatic revoke |

If a stored secret is acceptable to you, it's less to run.

## Quick start

1. **Create the Cloudflare token.** In the Cloudflare dashboard, create an account-owned API token with **Account API Tokens Write** (plus R2 permissions for [buckets](crates/cf-oidc-exchange-api#buckets)), and store it in Secrets Store.
2. **Write a policy** that says which repos, branches and environments get which permissions. See the [broker's README](crates/cf-oidc-exchange-api#policy).
3. **Deploy the broker** with the [Terraform module](deployment/terraform), on workers.dev (a custom domain is optional), then check that `<url>/.well-known/oauth-authorization-server` returns `200`.
4. **Add the action** to a job with `permissions: id-token: write`. See the [action's README](action).

## Development

Everything runs inside the dev shell: `nix develop`, or the Dev Container.

```sh
pnpm install && pnpm lint && pnpm typecheck && pnpm test   # the action
cargo test                                                  # the crates' unit tests
crates/cf-oidc-exchange-api/tests/run.sh                    # the broker end to end, under wrangler dev
(cd deployment/terraform && tofu test)                      # the Terraform module
```

Releases are cut by release-please from Conventional Commits. Each release is tagged `vX.Y.Z` and attaches the broker's `index.js`, `index_bg.wasm.base64` and their `SHA256SUMS`. Pin the action to a release tag or its commit SHA: before 1.0 there is no floating major tag, because minor releases may break.

## License

[MIT](LICENSE)
