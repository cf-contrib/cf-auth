# cf-oidc-auth broker

> The Worker half of [cf-oidc-auth](../..): verifies a GitHub Actions OIDC token,
> matches it against your policy, and mints a short-lived Cloudflare API token
> with exactly that profile's permissions, R2 credentials limited to the repo's
> key prefix, or both.

[![CI](https://github.com/cf-contrib/cf-oidc-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/cf-contrib/cf-oidc-auth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

> [!NOTE]
> **Pre-1.0.** The policy format and the `/v1` API may still change between
> minor versions.

```yaml
version: 1

github:
  audience: https://cf-oidc-broker.example.com # the broker's URL
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

1. **Create the broker token.** In the Cloudflare dashboard, create an **account-owned** API token with **Account API Tokens Write**. If any profile has an [`r2` grant](#r2-grants), also give it **Admin Read & Write** on R2 (the account-level **Workers R2 Storage Write** permission). It's the broker's only long-lived credential. This is the one manual step: automating it would need a token that can create tokens. Store it in [Secrets Store](https://developers.cloudflare.com/secrets-store/) so it never passes through your deploy tooling:
   ```sh
   wrangler secrets-store secret create <store-id> --name cf-auth-broker-token --scopes workers --remote
   ```
2. **Look up numeric IDs.** Pin IDs, not names, because a deleted repo or org name can be re-registered by someone else:
   ```sh
   gh api orgs/<org> --jq .id           # github.owner_id
   gh api repos/<org>/<repo> --jq .id   # match.repository_id
   ```
3. **Deploy** the released `broker.js` with the [Terraform module](terraform) (`//packages/cf-oidc-broker/terraform?ref=<version>`). It downloads the release (optionally pinned to a checksum), uploads your policy next to it, and sets up the bindings, the workers.dev URL (or an optional custom domain) and the cron. To build from source instead:
   ```sh
   cp src/policy.example.json src/policy.json   # then edit it; it isn't committed
   wrangler deploy   # after setting CF_OIDC_BROKER_ACCOUNT_ID and [[secrets_store_secrets]] in wrangler.toml
   ```
4. **Check** that `<broker-url>/healthz` returns `200` (`https://cf-auth.<subdomain>.workers.dev`, or your custom domain). A `500` means the policy was rejected or the broker token can't be read; the reasons are in Workers Logs.

## Bindings

| Binding | Type | Required | Description |
|---|---|---|---|
| `CF_OIDC_BROKER_ACCOUNT_ID` | plain text | yes | Account the broker token belongs to and tokens are minted in. |
| `CF_OIDC_BROKER_TOKEN` | Secrets Store secret | yes | Account-owned token with Account API Tokens Write, plus R2 Admin Read & Write (Workers R2 Storage Write) if any profile has an `r2` grant. Read on every request, so rotating the secret takes effect without a redeploy. Anything else, such as a plain `wrangler secret`, is refused with `500`. |

The hourly cron (`17 * * * *` in the examples) deletes expired `cf-oidc:*` tokens.

The policy isn't a binding. `broker.js` imports it from `policy.json`, a second
file in the same Worker version, so it changes only with a deploy and rolls back
with it:

- The Terraform module renders your `policy.yaml` to JSON and uploads it as a
  text module next to the release `broker.js`.
- A `wrangler` build bundles `src/policy.json`. The build fails if it's missing.

The policy is checked when an isolate first serves a request. An invalid one is a
`500` on every route, with the reasons in the `policy.invalid` log line.

## Policy

```yaml
version: 1

github:
  issuer: https://token.actions.githubusercontent.com # default. GHE: .../<enterprise>
  audience: https://cf-oidc-broker.example.com        # REQUIRED: the broker's origin
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

  - name: terraform-state               # no token: only R2 credentials
    match:
      ref: refs/heads/main
    r2:
      bucket: org-terraform-state
      permission: object-read-write
      prefixes: ["{repository_owner_id}/{repository_id}/"]
      ttl: 15m                          # only in a profile without token
```

A profile has a `token`, an `r2` grant, or both.

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

Keys must start with `com.cloudflare.`, and account keys must name `CF_OIDC_BROKER_ACCOUNT_ID`. Add a comment with the zone's name next to each zone ID so reviewers can tell them apart. With the Terraform module, write `${account_id}` and it's filled in from `var.account_id`.

### R2 grants

An `r2` grant gets the job [temporary R2 credentials](https://developers.cloudflare.com/r2/api/s3/temporary-credentials/) for one bucket, optionally limited to key prefixes built from the job's claims. One shared bucket can then hold every repo's Terraform state, with each repo limited to its own prefix:

```yaml
    r2:
      bucket: org-terraform-state         # a valid R2 bucket name
      permission: object-read-write       # or object-read-only; admin levels aren't allowed
      prefixes: ["github.com/{repository}/"]
```

- **Placeholders** are `{claim}`, not `${claim}`, so Terraform's `templatefile` leaves them alone. Only `{repository}`, `{repository_owner}`, `{repository_id}` and `{repository_owner_id}` are allowed. They're filled in from the verified JWT, never from the request.
- **Prefixes** must end in `/`, so `github.com/org/site/` doesn't also cover `github.com/org/site-old/`. They can't start with `/` or contain `*`, `..`, empty or `.` segments, or control characters, and each placeholder must be a whole path segment (`tfstate/{repository_id}/`, not `tfstate-{repository_id}/`), so two repos can never end up with the same prefix. These are checked when the policy loads.
- **Claims** filling a placeholder must be non-empty and use only the characters GitHub allows in owner and repo names (`A-Z`, `a-z`, `0-9`, `.`, `_`, `-`, plus the one `/` in `repository`); IDs must be numeric. The filled-in prefix is checked again. Otherwise the request is a `403` (`invalid_r2_prefix`), before anything is minted.
- **Without `prefixes`** the credentials cover the whole bucket.
- **Lifetime:** as long as the token would last: the profile's `ttl`, capped at `max_ttl`, with the request's `ttl` still honoured. In a profile without `token`, set `ttl` and `max_ttl` in `r2`. The credentials **can't be revoked early**, so keep TTLs short.
- **Parent token:** the broker token calls `temp-access-credentials` and is the credentials' parent, which can't exceed its permissions. Calling the endpoint takes **Admin Read & Write** on R2 (the account-level **Workers R2 Storage Write** permission); object-level or bucket-scoped tokens are refused with a `403`, which the broker reports as `502` (`cloudflare_error` in the audit log). That's account-wide, but it doesn't widen what a leaked broker token can do: with Account API Tokens Write it could already mint itself a token with any R2 permission. The policy still only hands out `object-*` permissions. Revoking or rolling the broker token cuts off every credential issued from it immediately, including those of jobs running at that moment. That's the emergency switch.
- **With both** `token` and `r2`, the broker mints the token first. If the credentials then can't be created, it deletes the token and replies `502`.

> [!WARNING]
> **The policy decides when a job's `AWS_*` variables are replaced.** The action exports the credentials as `AWS_*` whenever the matched profile has an `r2` grant, including for workflows that don't set `profile`. Set `profile` for R2 in every workflow, and give a job that also talks to AWS its R2 access in a separate job.

**Renamed and reused repo names.** A prefix built from `{repository}` moves when the repo is renamed, and a deleted repo's name can be taken by a new repo in the org, which would then get the old repo's state. `{repository_owner_id}/{repository_id}/` doesn't change on a rename and is never reused.

**What a grant doesn't cover:** several buckets in one job, and admin operations such as creating or listing buckets. For those, grant R2 permissions in the profile's `token` and derive S3 credentials from `CLOUDFLARE_API_TOKEN` in a step: the access key ID is the token's ID, and the secret is the SHA-256 of the token value. Buckets in a jurisdiction (`eu`, `fedramp`) need a different endpoint than the one the broker returns.

### TTL and names

- Durations look like `90s`, `15m`, `1h`, `1h30m`.
- A requested `ttl` above the profile's `max_ttl` is clamped. Below `1m`, or unparseable, is a `400`.
- Minted tokens are named `cf-oidc:<repository>:<run_id>:<run_attempt>`, at most 120 characters.

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
| `POST` | `/v1/token` | `Bearer <github-oidc-jwt>` | Mint a token, R2 credentials, or both. Body: `{ "profile"?, "ttl"? }`. Returns `{ token?, token_id?, account_id, expires_on, profile, r2? }`: `token` and `token_id` when the profile has a `token`, and `r2: { access_key_id, secret_access_key, session_token, bucket, prefixes, endpoint, expires_on }` when it has an `r2` grant. |
| `POST` | `/v1/revoke` | `Bearer <minted-token>` | Revoke a token. Holding it is the proof. Returns `204`, also when it's already gone, and `403` for tokens not named `cf-oidc:*`. |
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
| Stolen R2 credentials | Limited to one bucket and the repo's prefixes, and short-lived. They can't be revoked one by one; rolling the broker token revokes all of them |
| One repo reaches another's R2 keys | Prefixes must end in `/`, placeholders fill whole segments from verified claims with a fixed character set, and both the template and the result are checked. Prefer ID-based prefixes |
| Stolen JWT replayed | Short JWT lifetime and a custom audience |
| Broker token exfiltrated | Kept in Secrets Store, so it isn't in Terraform state or CI. Only code running in the Worker can read it. Restrict who can deploy Workers in the broker's account, rotate the broker token, and consider a dedicated account per trust domain. |
| Token flooding | Only workflows the policy allows can mint. Tokens are short-lived, revoked at job end, and cleaned up hourly. There's no rate limit yet (see [Limitations](#limitations)). |

### Audit log

Every mint, denial and revoke emits one JSON line to Workers Logs. Token values, R2 secrets and JWTs are never logged:

```json
{"event":"token.mint","profile":"workers-deploy","repository":"example-org/api","repository_id":"200000003","ref":"refs/heads/main","environment":"prod","run_id":"1234567890","run_attempt":"1","actor_id":"300000004","token_id":"<token-id>","expires_on":"2026-09-28T12:15:00Z"}
```

R2 credentials are `r2.issued`, with the bucket, the filled-in prefixes and the permission:

```json
{"event":"r2.issued","profile":"terraform-state","repository":"example-org/api","repository_id":"200000003","ref":"refs/heads/main","run_id":"1234567890","run_attempt":"1","actor_id":"300000004","bucket":"org-terraform-state","prefixes":["100000001/200000003/"],"permission":"object-read-write","expires_on":"2026-09-28T12:15:00Z"}
```

When an isolate first loads the policy, it logs `policy.loaded` with the profile count, e.g. `{"event":"policy.loaded","profiles":3}`. Check this line after deploying.

Denials are `token.deny` with a `reason`:

- **Request problems:** `invalid_jwt`, `invalid_body`, `invalid_ttl`
- **Policy didn't allow it:** `no_match`, `ambiguous`, `profile_mismatch`, `invalid_r2_prefix`
- **Configuration or upstream errors:** `broker_token_unavailable`, `unknown_permission`, `ambiguous_permission`, `jwks_unavailable`, `cloudflare_error`

## Limitations

- **One account per broker.** Tokens are minted in `CF_OIDC_BROKER_ACCOUNT_ID` only. Deploy one broker per account.
- **GitHub Actions only.** Other OIDC issuers (GitLab CI, Buildkite, …) aren't supported yet.
- **No JWT replay cache.** A stolen JWT can be exchanged again until it expires. The custom audience and its short lifetime limit this.
- **Resource IDs aren't checked up front.** Apart from the account check, a wrong zone ID is only caught when Cloudflare rejects the mint (`502`).
- **Permission names can change.** Cloudflare can rename a permission group. Profiles using the old name fail closed (`500`) until the policy is updated, and the one-hour cache can delay a fix by up to an hour per isolate.
- **Secrets Store is required, and in open beta.** The broker token is only accepted from Secrets Store, so a plain Worker secret can't end up in Terraform state or deploy tooling. Accounts without Secrets Store can't run the broker yet.
- **R2 credentials can't be revoked early.** They last their TTL; only rolling the broker token cuts them all off. One bucket per grant, and only buckets outside a jurisdiction.
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
