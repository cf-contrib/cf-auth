# cf-oidc-auth broker

> The Worker half of [cf-oidc-auth](../..): verifies a GitHub Actions OIDC token,
> matches it against your policy, and mints a short-lived Cloudflare API token
> with exactly that profile's permissions, R2 credentials limited to the repo's
> key prefix, or both. People can get the same from their GitHub token, through
> [`subject: users` profiles](#people).

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
    ttl: 15m
    token:
      policies:
        - permissions: ["Workers Scripts Write"]
          resources:
            com.cloudflare.api.account.0123456789abcdef0123456789abcdef: "*"
```

A job in repo `200000002`, on `main`, in the `prod` environment, gets a 15-minute token that can deploy Workers in the account. Any other job gets a `403`.

## Deploy

1. **Create the broker token.** In the Cloudflare dashboard, create an **account-owned** API token with **Account API Tokens Write**. If any profile has [`buckets`](#buckets), also give it R2 permissions covering what they delegate. It's the broker's only long-lived credential. This is the one manual step: automating it would need a token that can create tokens. Store it in [Secrets Store](https://developers.cloudflare.com/secrets-store/) so it never passes through your deploy tooling:
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
| `CF_OIDC_BROKER_TOKEN` | Secrets Store secret | yes | Account-owned token with Account API Tokens Write, plus R2 permissions covering what profiles' `buckets` delegate. Read on every request, so rotating the secret takes effect without a redeploy. Anything else, such as a plain `wrangler secret`, is refused with `500`. |
| `CF_OIDC_BROKER_SIGNING_KEY` | Secrets Store secret | for profiles with an `audience` | RSA private key (at least 2048 bits), as a PKCS#8 PEM, the broker signs [its own tokens](#tokens-for-other-services) with. Without it the broker issues none, publishes no keys, and those profiles fail closed with `500`. |

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
      repository: "example-org/*"       # a trailing * is allowed on non-ID claims
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
    ttl: 5m                             # for everything the profile hands out
    token:
      policies:
        - effect: allow                 # the default; "deny" carves out exceptions
          permissions: ["DNS Write"]
          resources:
            com.cloudflare.api.account.zone.fedcba9876543210fedcba9876543210: "*"

  - name: terraform-state               # no token: only R2 credentials
    match:
      ref: refs/heads/main
    buckets:
      - name: org-terraform-state
        permission: object-read-write
        prefixes: ["{repository_owner_id}/{repository_id}/"]

  - name: tofu-plan                     # for people, with gh-cloudflare
    subject: users
    match:
      team_id: "400000005"              # infra team
      repository_permission: write      # at least write on the requested repo
    buckets:
      - name: org-terraform-state
        permission: object-read-only
        prefixes: ["{repository_owner_id}/{repository_id}/"]
```

A profile has a `token`, `buckets`, or both. It's for GitHub Actions jobs unless it says `subject: users`. A profile with an `audience` instead issues the broker's own token for that service: see [Tokens for other services](#tokens-for-other-services).

To switch a profile off, for example during an incident, set `enabled: false`. It stays in the policy but never matches, and a request naming it is a `403`.

The broker validates the policy on the first request. If it's invalid, the broker fails closed and every request gets `500`.

### Matching

- A profile matches when **all** its `match` keys equal the JWT's claims. There's no OR inside a profile; write two profiles.
- `github.owner_id` is added to every profile as `repository_owner_id`. A profile can't override it.
- Any string claim GitHub issues can be matched: `repository`, `repository_id`, `ref`, `ref_type`, `environment`, `event_name`, `workflow_ref`, `job_workflow_ref`, `actor_id`, `runner_environment`, and so on. A claim missing from the JWT never matches.
- A pattern can end in one `*` after a prefix, such as `example-org/*` or `refs/heads/release/*`, and then matches any value starting with that prefix, including across `/`. A `*` anywhere else, or on its own, is refused when the policy loads. ID claims (`*_id`) must be exact.
- If the request names a `profile`, that profile must match. Otherwise exactly one profile must match. Both failures are a `403`.
- Unquoted YAML numbers are accepted for IDs and compared as strings.
- A job is only matched against profiles for `actions` (the default), and a person only against `subject: users` profiles. Naming a profile for the other subject is a `403`. `subject_token_type` on [`/oauth/token`](#token-exchange) says which: a job sends its OIDC token and a person their GitHub token.

### People

A `subject: users` profile gives people credentials for a repo, from their GitHub user token. The client is [gh-cloudflare](https://github.com/gh-extensions/gh-cloudflare), which sends `gh auth token` to [`POST /oauth/token`](#token-exchange) with the repo to act for:

```sh
gh cloudflare exec --profile tofu-plan -- tofu plan
```

The broker asks GitHub, with the person's token, who they are, what the repo's IDs are, what their role on it is and, if a profile needs it, which teams they're in. It builds the claims from those answers. Nothing in them comes from the request except which repo to look up.

| Match key | Matches when |
|---|---|
| `repository_permission` | **Required.** The person's role on the repo is at least this: `read`, `triage`, `write`, `maintain` or `admin`. |
| `team_id` | The person is a member of this team. GitHub answers for a token with the `repo`, `read:org` or `user` scope; gh's token has `repo`. |
| `repository`, `repository_id` | The repo, as for jobs. |
| `actor_id` | The person's numeric user ID. |

- The repo must belong to `github.owner_id`.
- Claims only jobs have (`ref`, `environment`, `workflow_ref`, …) can't be used in a user profile, and `team_id` and `repository_permission` can't be used in an Actions profile.
- Bucket prefixes are filled in from the repo GitHub returned, so `{repository_owner_id}/{repository_id}/` gives a person the same prefix the repo's jobs get.
- `max_ttl` defaults to `1h` for user profiles, even if `defaults.max_ttl` is higher. A profile can set its own.
- GitHub App installation tokens (`ghs_…`, including `GITHUB_TOKEN`) are refused: they identify a repo, not a person. Jobs send their OIDC token instead.
- A token that isn't authorized for an org's SAML SSO is refused with `sso_required` in the audit log.

> [!WARNING]
> **A gh token works across all of GitHub and doesn't expire.** Anyone who steals one can mint whatever the user profiles give its owner. Keep user profiles to what `tofu plan` needs, such as read-only tokens and `object-read-only` state, and keep `apply` in CI behind `environment: prod` with required reviewers. Otherwise anyone who can run it locally can skip those reviewers.

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

### Buckets

Each entry in `buckets` gets the job [temporary R2 credentials](https://developers.cloudflare.com/r2/api/s3/temporary-credentials/) for that bucket, optionally limited to key prefixes built from the job's claims. One shared bucket can then hold every repo's Terraform state, with each repo limited to its own prefix:

```yaml
    buckets:
      - name: org-terraform-state         # a valid R2 bucket name
        permission: object-read-write     # or object-read-only; admin levels aren't allowed
        prefixes: ["github.com/{repository}/"]
```

- **Several buckets** each get their own credentials, and the action exports each one as an AWS profile named after the bucket. A bucket can appear only once per profile.

- **Placeholders** are `{claim}`, not `${claim}`, so Terraform's `templatefile` leaves them alone. Only `{repository}`, `{repository_owner}`, `{repository_id}` and `{repository_owner_id}` are allowed. They're filled in from the verified JWT, never from the request.
- **Prefixes** must end in `/`, so `github.com/org/site/` doesn't also cover `github.com/org/site-old/`. They can't start with `/` or contain `*`, `..`, empty or `.` segments, or control characters, and each placeholder must be a whole path segment (`tfstate/{repository_id}/`, not `tfstate-{repository_id}/`), so two repos can never end up with the same prefix. These are checked when the policy loads.
- **Claims** filling a placeholder must be non-empty and use only the characters GitHub allows in owner and repo names (`A-Z`, `a-z`, `0-9`, `.`, `_`, `-`, plus the one `/` in `repository`); IDs must be numeric. The filled-in prefix is checked again. Otherwise the request is a `403` (`invalid_r2_prefix`), before anything is minted.
- **Without `prefixes`** the credentials cover the whole bucket.
- **Lifetime:** the profile's `ttl`, capped at its `max_ttl`, with the request's `ttl` still honoured. That's the same as the token's, in a profile with both. The credentials **can't be revoked early**, so keep TTLs short.
- **Parent token:** the broker token calls `temp-access-credentials` with its own ID as the parent, as in [Cloudflare's example](https://developers.cloudflare.com/r2/examples/authenticate-r2-temp-credentials/), and the credentials can't exceed its permissions. Give it **Workers R2 Storage Write** (R2's "Admin Read & Write"), which is known to work. Cloudflare asks for "at least the permissions you plan to delegate", so an R2 permission limited to the profiles' buckets may be enough, but that hasn't been tried. Without an R2 permission the endpoint refuses the token with code `10000`, which the broker reports as `502` (`cloudflare_error` in the audit log). Admin Read & Write is account-wide, but it doesn't widen what a leaked broker token can do: with Account API Tokens Write it could already mint itself a token with any R2 permission. The policy still only hands out `object-*` permissions. Revoking or rolling the broker token cuts off every credential issued from it within seconds, including those of jobs running at that moment. That's the emergency switch.
- **With both** `token` and `buckets`, the broker mints the token first. If the credentials then can't be created, it deletes the token and replies `502`.

> [!WARNING]
> **The policy decides when a job's `AWS_*` variables are replaced.** The action exports the credentials, and replaces or clears `AWS_*`, whenever the matched profile has `buckets`, including for workflows that don't set `profile`. Set `profile` for R2 in every workflow, and give a job that also talks to AWS its R2 access in a separate job.

**Renamed and reused repo names.** A prefix built from `{repository}` moves when the repo is renamed, and a deleted repo's name can be taken by a new repo in the org, which would then get the old repo's state. `{repository_owner_id}/{repository_id}/` doesn't change on a rename and is never reused.

**What `buckets` doesn't cover:** admin operations such as creating or listing buckets. For those, grant R2 permissions in the profile's `token` and derive S3 credentials from `CLOUDFLARE_API_TOKEN` in a step: the access key ID is the token's ID, and the secret is the SHA-256 of the token value. Buckets in a jurisdiction (`eu`, `fedramp`) need a different endpoint than the one the broker returns.

### Tokens for other services

A profile with `audience: <service URL>` gives the caller a token the broker signs itself, for another service that trusts the broker, such as [cf-nix-cache](https://github.com/cf-contrib/cf-nix-cache). It has no `token` or `buckets`: who may use the service is decided by the profile's `match`, like any other.

```yaml
  - name: nix-push
    audience: https://cf-nix-cache.example.com
    match:
      repository_id: "200000003"
      ref: refs/heads/main
    ttl: 15m
```

The caller asks for it with [`audience`](#token-exchange) set to the service's URL, and gets a JWT the broker signed (`alg: RS256`, which OIDC verifiers support by default):

- `iss` is the broker's URL (`github.audience`), `aud` the service, and `sub` GitHub's `sub` for a job or `user:<actor_id>` for a person.
- The verified claims are copied under GitHub's names, so a service can keep matching on them: `repository`, `repository_id`, `repository_owner`, `repository_owner_id`, `ref`, `ref_type`, `environment`, `event_name`, `workflow_ref`, `job_workflow_ref`, `run_id`, `run_attempt`, `runner_environment`, `actor`, `actor_id` and, for a person, `repository_permission`. Plus `profile` and a unique `jti`.
- It lasts the profile's `ttl`, but never past the job's OIDC token, which lasts minutes. Exchange again for a fresh one: there are no refresh tokens.

Services find the public key at [`/.well-known/jwks`](#http-api), or through [`/.well-known/openid-configuration`](#http-api), and should check `iss`, `aud`, `exp` and the `RS256` algorithm.

The key is an RSA private key, at least 2048 bits, in Secrets Store, bound as `CF_OIDC_BROKER_SIGNING_KEY` (`signing_key_secret` in the [Terraform module](terraform)):

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out signing-key.pem
wrangler secrets-store secret create <store-id> --name cf-auth-signing-key --scopes workers   # paste the PEM
rm signing-key.pem
```

Its `kid` is the public key's thumbprint, so replacing the secret rotates the key. Tokens signed with the old key stop verifying once services refetch the JWKS, and they're short-lived anyway.

### TTL and names

- Durations look like `90s`, `15m`, `1h`, `1h30m`.
- `ttl` and `max_ttl` go on the profile, and apply to its token and buckets alike. `token.ttl` and `token.max_ttl`, where they used to go, still work, but a profile can't use both places.
- A requested `ttl` above the profile's `max_ttl` is clamped. Below `1m`, or unparseable, is a `400`.
- Minted tokens are named `cf-oidc:<repository>:<run_id>:<run_attempt>` for jobs and `cf-oidc:user:<login>:<repository>` for people, at most 120 characters.

### Guardrails

These are enforced when the policy loads, so an unsafe policy never serves a request:

1. **The owner pin is mandatory.** GitHub issues OIDC tokens to every repository on github.com, and the broker URL is public.
2. **Patterns stay narrow.** ID claims can't use `*`, and other claims only as a single trailing `*` after a prefix, so a pattern can't match everything (`*`) or anything ending in a value (`*main`).
3. **No token-management permissions.** Granting any permission group matching `API Tokens` is rejected, so a job can't turn its short-lived token into a long-lived one.
4. **TTLs are capped.** `max_ttl` is at most 24h, and `ttl` can't exceed it.
5. **The audience must be custom.** `github.audience` is required and can't be GitHub's default (`https://github.com/<owner>`), so a JWT requested for AWS or GCP can't be replayed here.
6. **People and jobs are kept apart.** Each only matches profiles for its own subject. A user profile must require a role on the repo, since the person picks the repo, and can't match claims only jobs have.
7. **Audiences are kept apart.** A request only matches profiles for its `audience`. A profile for another service can't hand out Cloudflare credentials, and its audience must be a bare origin other than the broker's own.

## HTTP API

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/oauth/token` | `subject_token` in the body | [Token exchange](#token-exchange) (RFC 8693) for jobs and people alike. What the action uses. |
| `POST` | `/oauth/revoke` | `token` in the body | [Revoke](#revocation) (RFC 7009) a token the broker minted. What the action's post step uses. |
| `GET` | `/.well-known/openid-configuration` | public | The broker's issuer, key and endpoint URLs, for services that verify [its tokens](#tokens-for-other-services). |
| `GET` | `/.well-known/jwks` | public | The public key the broker signs its own tokens with. Empty without `CF_OIDC_BROKER_SIGNING_KEY`. |
| `GET` | `/healthz` | public | `200` if the policy and bindings are valid, else `500`. Never shows the policy. |

### Token exchange

`POST /oauth/token` is an [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) token exchange, form-encoded or JSON. The token goes in the body, and `subject_token_type` says whose it is. [`openapi.yaml`](openapi.yaml) is the contract.

```sh
curl -sS https://cf-oidc-broker.example.com/oauth/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$GITHUB_OIDC_TOKEN" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:id_token \
  -d profile=workers-deploy
```

| Parameter | |
|---|---|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | A GitHub Actions OIDC token, or a person's GitHub user token |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:id_token` or `…:jwt` for a job, `urn:ietf:params:oauth:token-type:access_token` for a person |
| `audience` | Optional. `https://api.cloudflare.com`, the default, for Cloudflare credentials; or a service's URL for [the broker's own token](#tokens-for-other-services) |
| `requested_token_type` | Optional. For Cloudflare, `urn:ietf:params:oauth:token-type:access_token` or `urn:cf-oidc-auth:params:oauth:token-type:r2-credentials`; for a service, `urn:ietf:params:oauth:token-type:jwt` or `…:access_token` |
| `profile` | Optional. Profile to use; if omitted, exactly one profile must match |
| `ttl` | Optional. Requested lifetime such as `10m` or `1h`, clamped to the profile's `max_ttl` |
| `repository` | Required for a person: `owner/name` or the repo's numeric ID |

Delegation (`actor_token`), audiences no profile is for, and other token types are refused with `400`, not ignored. A person gets `404` when no enabled profile is for people.

The response has the standard fields plus the broker's own:

```json
{
  "access_token": "…",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 900,
  "expires_at": 1790597700,
  "token_id": "…",
  "account_id": "0123456789abcdef0123456789abcdef",
  "profile": "workers-deploy",
  "buckets": [{ "name": "…", "access_key_id": "…", "secret_access_key": "…", "session_token": "…", "prefixes": ["…"], "endpoint": "…", "expires_on": "…" }]
}
```

`buckets` is there when the profile has buckets. A profile with only buckets has no single bearer token, so it returns no `access_token` or `token_id`, with `issued_token_type` `urn:cf-oidc-auth:params:oauth:token-type:r2-credentials` and `token_type` `N_A`. For a service's audience, `access_token` is the broker's JWT, `issued_token_type` is `urn:ietf:params:oauth:token-type:jwt`, and there's no `token_id`, `account_id` or `buckets`.

Errors are the same as on every route.

### Revocation

`POST /oauth/revoke` is an [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) revocation, form-encoded or JSON, with the token in `token` (`token_type_hint` is ignored). Holding the token is the proof. It answers `200` with no body whether the token was revoked, was already gone or was never valid, and `403` for a token the broker didn't mint (one not named `cf-oidc:*`, including the broker token), which it never deletes.

```sh
curl -sS https://cf-oidc-broker.example.com/oauth/revoke -d token="$CLOUDFLARE_API_TOKEN"
```

**Errors:** `{ "error": "<code>" }` with one of these statuses:

- `400 bad_request`
- `401 unauthorized`
- `403 forbidden`
- `404 not_found`
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
| Stolen broker-issued token | Valid for one service (`aud`), and never longer than the job's OIDC token it came from |
| Signing key exfiltrated | Kept in Secrets Store like the broker token. Replace the secret to rotate it: the new key gets a new `kid`, and services stop accepting the old one once they refetch the JWKS |
| Stolen gh token | Only gets what user profiles give its owner, for repos they can access. Keep those profiles read-only, with short TTLs (`1h` cap by default). Revoking the token on GitHub cuts it off at the next mint |
| A person picks a repo they shouldn't reach | The broker looks up their role on it with GitHub, and user profiles must require one. Prefixes come from GitHub's answer, not the request |
| Broker token exfiltrated | Kept in Secrets Store, so it isn't in Terraform state or CI. Only code running in the Worker can read it. Restrict who can deploy Workers in the broker's account, rotate the broker token, and consider a dedicated account per trust domain. |
| Token flooding | Only workflows and people the policy allows can mint. Tokens are short-lived, revoked at job end, and cleaned up hourly. There's no rate limit yet (see [Limitations](#limitations)). |

### Audit log

Every mint, issue, denial and revoke emits one JSON line to Workers Logs, with `subject` (`actions` or `users`) for mints and denials. Token values, R2 secrets, JWTs and gh tokens are never logged:

```json
{"event":"token.mint","subject":"actions","profile":"workers-deploy","repository":"example-org/api","repository_id":"200000003","ref":"refs/heads/main","environment":"prod","run_id":"1234567890","run_attempt":"1","actor_id":"300000004","token_id":"<token-id>","expires_on":"2026-09-28T12:15:00Z"}
```

R2 credentials are `r2.issued`, with the bucket, the filled-in prefixes and the permission:

```json
{"event":"r2.issued","subject":"actions","profile":"terraform-state","repository":"example-org/api","repository_id":"200000003","ref":"refs/heads/main","run_id":"1234567890","run_attempt":"1","actor_id":"300000004","bucket":"org-terraform-state","prefixes":["100000001/200000003/"],"permission":"object-read-write","expires_on":"2026-09-28T12:15:00Z"}
```

A token for another service is `token.issue`, with the audience and the token's `jti`, never the token:

```json
{"event":"token.issue","subject":"actions","profile":"nix-push","repository":"example-org/api","repository_id":"200000003","ref":"refs/heads/main","run_id":"1234567890","run_attempt":"1","actor_id":"300000004","audience":"https://cf-nix-cache.example.com","jti":"<uuid>","expires_on":"2026-09-28T12:05:00Z"}
```

When an isolate first loads the policy, it logs `policy.loaded` with the profile count, e.g. `{"event":"policy.loaded","profiles":3}`. Check this line after deploying.

Denials are `token.deny` with a `reason`:

- **Request problems:** `invalid_jwt`, `invalid_user_token`, `installation_token`, `invalid_body`, `invalid_ttl`, `no_user_profiles`, `unsupported_grant_type`, `unsupported_subject_token_type`, `unsupported_requested_token_type`, `actor_token_unsupported`, `invalid_target`
- **Policy or GitHub didn't allow it:** `no_match`, `ambiguous`, `profile_mismatch`, `invalid_r2_prefix`, `repository_forbidden`, `teams_forbidden`, `sso_required`
- **Configuration or upstream errors:** `broker_token_unavailable`, `signing_key_unavailable`, `unknown_permission`, `ambiguous_permission`, `jwks_unavailable`, `github_unavailable`, `cloudflare_error`

## Limitations

- **One account per broker.** Tokens are minted in `CF_OIDC_BROKER_ACCOUNT_ID` only. Deploy one broker per account.
- **GitHub only.** Other OIDC issuers (GitLab CI, Buildkite, …) aren't supported yet, and people need a github.com account: GitHub Enterprise Server's API isn't supported for user profiles.
- **People use their gh token.** It's sent to the broker as is. A GitHub App, whose short-lived tokens only it accepts, may come later.
- **A person's role and teams are checked on every mint.** Each mint makes two or three GitHub API calls with their token, which counts against their rate limit. Teams past the first 1000 aren't seen.
- **One signing key at a time.** Rotating it can't publish the old and new keys side by side, so a token signed just before the rotation fails at a service that has already refetched the JWKS. They're short-lived, and the caller can exchange again.
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
