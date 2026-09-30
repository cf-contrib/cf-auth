# cf-oidc-auth broker

> The Worker half of [cf-oidc-auth](../..): verifies a GitHub Actions OIDC token,
> matches it against your policy, and mints a short-lived Cloudflare API token
> with exactly that profile's permissions.

[![CI](https://github.com/cf-contrib/cf-oidc-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/cf-contrib/cf-oidc-auth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

> [!NOTE]
> **Pre-1.0.** The policy format and the `/v1` API may still change between
> minor versions.

```yaml
version: 1

github:
  audience: https://cf-auth.example.com # the broker's URL
  owner_id: "100000001"                 # your org's numeric ID, applied to every profile

profiles:
  - name: workers-deploy
    match:
      repository_id: "200000002"
      ref: refs/heads/main
      environment: prod
    token:
      ttl: 15m
      policies:
        - permissions: ["Workers Scripts Write"]
          resources:
            com.cloudflare.api.account.0123456789abcdef0123456789abcdef: "*"
```

A job in repo `200000002`, on `main`, in the `prod` environment, gets a 15-minute token that can deploy Workers in the account. Any other job gets a `403`.

## Deploy

1. **Create the broker token.** In the Cloudflare dashboard, create an **account-owned** API token with only **Account API Tokens Write**. It's the broker's only long-lived credential. This is the one manual step: automating it would need a token that can create tokens. Store it in [Secrets Store](https://developers.cloudflare.com/secrets-store/) so it never passes through your deploy tooling:
   ```sh
   wrangler secrets-store secret create <store-id> --name cf-auth-broker-token --scopes workers --remote
   ```
2. **Look up numeric IDs.** Pin IDs, not names, because a deleted repo or org name can be re-registered by someone else:
   ```sh
   gh api orgs/<org> --jq .id           # github.owner_id
   gh api repos/<org>/<repo> --jq .id   # match.repository_id
   ```
3. **Deploy** the released `broker.js` with the [Terraform module](terraform) (`//packages/cf-oidc-broker/terraform?ref=<version>`). It downloads the release (optionally pinned to a checksum) and sets up the bindings, the workers.dev URL (or an optional custom domain) and the cron. To build from source instead:
   ```sh
   wrangler deploy   # after setting CF_AUTH_BROKER_ACCOUNT_ID, CF_AUTH_BROKER_POLICY and [[secrets_store_secrets]] in wrangler.toml
   ```
4. **Check** that `<broker-url>/healthz` returns `200` (`https://cf-auth.<subdomain>.workers.dev`, or your custom domain). A `500` means the policy was rejected or the broker token can't be read; the reasons are in Workers Logs.

## Bindings

| Binding | Type | Required | Description |
|---|---|---|---|
| `CF_AUTH_BROKER_ACCOUNT_ID` | plain text | yes | Account the broker token belongs to and tokens are minted in. |
| `CF_AUTH_BROKER_POLICY` | plain text (JSON) | yes | The policy. Terraform: `jsonencode(yamldecode(templatefile("policy.yaml", …)))`. A Wrangler `[vars]` table also works. |
| `CF_AUTH_BROKER_TOKEN` | Secrets Store secret | yes | Account-owned token with only Account API Tokens Write. Read on every request, so rotating the secret takes effect without a redeploy. Anything else, such as a plain `wrangler secret`, is refused with `500`. |

The hourly cron (`17 * * * *` in the examples) deletes expired `cf-auth:*` tokens.

## Policy

```yaml
version: 1

github:
  issuer: https://token.actions.githubusercontent.com # default. GHE: .../<enterprise>
  audience: https://cf-auth.example.com               # REQUIRED: the broker's origin
  owner_id: "100000001"                               # REQUIRED: numeric org/user ID

defaults:
  ttl: 15m     # default 15m
  max_ttl: 1h  # default 1h, at most 24h

profiles:
  - name: infra-cloudflare
    match:
      repository_id: "200000002"
      ref: refs/heads/main
      environment: prod                 # pair with required reviewers on the environment
    token:
      policies:
        - permissions: ["Zone Write", "Zone WAF Write", "DNS Write"]
          resources:
            com.cloudflare.api.account.zone.fedcba9876543210fedcba9876543210: "*" # example.com

  - name: workers-deploy
    match:
      repository: "example-org/*"       # globs are allowed on non-ID claims
      ref: refs/heads/main
      environment: prod
    token:
      policies:
        - permissions: ["Workers Scripts Write"]
          resources:
            com.cloudflare.api.account.0123456789abcdef0123456789abcdef: "*"

  - name: service-dns
    match:
      job_workflow_ref: "example-org/workflows/.github/workflows/deploy.yml@refs/heads/main"
    token:
      ttl: 5m
      policies:
        - effect: allow                 # the default; "deny" carves out exceptions
          permissions: ["DNS Write"]
          resources:
            com.cloudflare.api.account.zone.fedcba9876543210fedcba9876543210: "*"
```

The broker validates the policy on the first request. If it's invalid, the broker fails closed and every request gets `500`.

### Matching

- A profile matches when **all** its `match` keys equal the JWT's claims. There's no OR inside a profile; write two profiles.
- `github.owner_id` is added to every profile as `repository_owner_id`. A profile can't override it.
- Any string claim GitHub issues can be matched: `repository`, `repository_id`, `ref`, `ref_type`, `environment`, `event_name`, `workflow_ref`, `job_workflow_ref`, `actor_id`, `runner_environment`, and so on. A claim missing from the JWT never matches.
- `*` matches any run of characters, including `/`. ID claims (`*_id`) must be exact.
- If the request names a `profile`, that profile must match. Otherwise exactly one profile must match. Both failures are a `403`.
- Unquoted YAML numbers are accepted for IDs and compared as strings.

### Permissions

`permissions` are permission-group names as the [permission groups API](https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/subresources/permission_groups/) returns them, e.g. `"DNS Write"` or `"Workers Scripts Write"`. The broker looks up their IDs with the broker token and caches them for an hour. To see the full list:

```sh
curl -H "Authorization: Bearer <token>" \
  "https://api.cloudflare.com/client/v4/accounts/<account_id>/tokens/permission_groups"
```

- An unknown name fails the mint with `500` (`unknown_permission`). It's never silently dropped.
- If a name exists at several scopes, the broker uses the one matching the resources' scope (account, zone or R2 bucket).

### Resources

`resources` is Cloudflare's own token resources format, passed through as written. Common forms:

| Grants | `resources` |
|---|---|
| The whole account | `com.cloudflare.api.account.<account_id>: "*"` |
| One zone | `com.cloudflare.api.account.zone.<zone_id>: "*"` |
| Every zone in the account | `com.cloudflare.api.account.<account_id>: { com.cloudflare.api.account.zone.*: "*" }` |

Keys must start with `com.cloudflare.`, and account keys must name `CF_AUTH_BROKER_ACCOUNT_ID`. Add a comment with the zone's name next to each zone ID so reviewers can tell them apart. With the Terraform module, write `${account_id}` and it's filled in from `var.account_id`.

### TTL and names

- Durations look like `90s`, `15m`, `1h`, `1h30m`.
- A requested `ttl` above the profile's `max_ttl` is clamped. Below `1m`, or unparseable, is a `400`.
- Minted tokens are named `cf-auth:<repository>:<run_id>:<run_attempt>`, at most 120 characters.

### Guardrails

These are enforced when the policy loads, so an unsafe policy never serves a request:

1. **The owner pin is mandatory.** GitHub issues OIDC tokens to every repository on github.com, and the broker URL is public.
2. **ID claims can't be globbed.**
3. **No token-management permissions.** Granting any permission group matching `API Tokens` is rejected, so a job can't turn its short-lived token into a long-lived one.
4. **TTLs are capped.** `max_ttl` is at most 24h, and `ttl` can't exceed it.
5. **The audience must be custom.** `github.audience` is required and can't be GitHub's default (`https://github.com/<owner>`), so a JWT requested for AWS or GCP can't be replayed here.

## HTTP API

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/token` | `Bearer <github-oidc-jwt>` | Mint a token. Body: `{ "profile"?, "ttl"? }`. Returns `{ token, token_id, account_id, expires_on, profile }`. |
| `POST` | `/v1/revoke` | `Bearer <minted-token>` | Revoke a token. Holding it is the proof. Returns `204`, also when it's already gone, and `403` for tokens not named `cf-auth:*`. |
| `GET` | `/healthz` | public | `200` if the policy and bindings are valid, else `500`. Never shows the policy. |

**Errors:** `{ "error": "<code>" }` with one of these statuses:

- `400 bad_request`
- `401 unauthorized`
- `403 forbidden`
- `500 misconfigured`
- `502 upstream_error`

Bodies are deliberately generic; the reason goes to the audit log.

**Contract:** the types live in [`src/api.ts`](src/api.ts). The action type-checks against them, so a change here breaks the action's typecheck in the same PR.

## Security

| Threat | Mitigation |
|---|---|
| Forged or tampered JWT | Signature checked against the issuer's JWKS (RS256 only), plus `iss`, `aud`, `exp` and `nbf` with 30s tolerance |
| A repo outside your org asks for a token | Mandatory `owner_id` pin |
| Deleted repo or org re-registered by an attacker | Pin numeric IDs, not names |
| Malicious PR code gets a prod token | Match `ref: refs/heads/main` and `environment: prod`, with required reviewers on the environment. Fork PRs don't get `id-token: write` on `pull_request`. Don't write profiles that match `event_name: pull_request_target`. |
| Stolen minted token | 15m default TTL, revoked at job end, expired tokens deleted hourly |
| Stolen JWT replayed | Short JWT lifetime and a custom audience |
| Broker token exfiltrated | Kept in Secrets Store, so it isn't in Terraform state or CI. Only code running in the Worker can read it. Restrict who can deploy Workers in the broker's account, rotate the broker token, and consider a dedicated account per trust domain. |
| Token flooding | Only workflows the policy allows can mint. Tokens are short-lived, revoked at job end, and cleaned up hourly. There's no rate limit yet (see [Limitations](#limitations)). |

### Audit log

Every mint, denial and revoke emits one JSON line to Workers Logs. Token values and JWTs are never logged:

```json
{"event":"token.mint","profile":"workers-deploy","repository":"example-org/api","repository_id":"200000003","ref":"refs/heads/main","environment":"prod","run_id":"1234567890","run_attempt":"1","actor_id":"300000004","token_id":"<token-id>","expires_on":"2026-09-28T12:15:00Z"}
```

When an isolate first loads the policy, it logs `policy.loaded` with the profile count, e.g. `{"event":"policy.loaded","profiles":3}`. Check this line after deploying.

Denials are `token.deny` with a `reason`:

- **Request problems:** `invalid_jwt`, `invalid_body`, `invalid_ttl`
- **Policy didn't allow it:** `no_match`, `ambiguous`, `profile_mismatch`
- **Configuration or upstream errors:** `broker_token_unavailable`, `unknown_permission`, `ambiguous_permission`, `jwks_unavailable`, `cloudflare_error`

## Limitations

- **The policy must fit in 5 KB.** `CF_AUTH_BROKER_POLICY` is a Worker binding, and Cloudflare caps each at 5 KB, which is roughly 15–20 profiles. The Terraform module fails the plan if it's larger. Split large policies across brokers per team or trust domain.
- **One account per broker.** Tokens are minted in `CF_AUTH_BROKER_ACCOUNT_ID` only. Deploy one broker per account.
- **GitHub Actions only.** Other OIDC issuers (GitLab CI, Buildkite, …) aren't supported yet.
- **No JWT replay cache.** A stolen JWT can be exchanged again until it expires. The custom audience and its short lifetime limit this.
- **Resource IDs aren't checked up front.** Apart from the account check, a wrong zone ID is only caught when Cloudflare rejects the mint (`502`).
- **Permission names can change.** Cloudflare can rename a permission group. Profiles using the old name fail closed (`500`) until the policy is updated, and the one-hour cache can delay a fix by up to an hour per isolate.
- **Secrets Store is required, and in open beta.** The broker token is only accepted from Secrets Store, so a plain Worker secret can't end up in Terraform state or deploy tooling. Accounts without Secrets Store can't run the broker yet.
- **No rate limit.** A workflow the policy allows can mint as often as it runs. Each token expires within minutes, is revoked at job end and cleaned up hourly, but a compromised workflow could still create many tokens at once. Cloudflare's rate-limit binding was tried and didn't enforce a 30-per-minute limit against ~85 requests a minute, so it was left out. An exact per-repository limit (e.g. a Durable Object) may come later.

## Development

```sh
pnpm test           # unit + integration tests in workerd, Cloudflare API and JWKS faked
pnpm build          # dist/broker.js
pnpm check:bundle   # boot dist/broker.js in workerd, check its gzipped size
wrangler dev        # local broker; create the token in the local store first:
                    #   wrangler secrets-store secret create <store-id> --name cf-auth-broker-token --scopes workers
```

`wrangler.toml` is for local testing and build-from-source deploys. Production normally uses the released `broker.js`.

## License

[MIT](../../LICENSE)
