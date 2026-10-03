# cf-oidc-exchange Terraform module

> The Terraform / OpenTofu half of [cf-oidc-exchange](../..): deploys the released
> broker, a Rust Worker, to Cloudflare, with its bindings, hourly cleanup cron, and
> a workers.dev URL (or, optionally, a custom domain). No `wrangler` or local
> build is needed.

```hcl
module "cf_oidc_broker" {
  source = "git::https://github.com/cf-contrib/cf-oidc-exchange.git//deployment/terraform?ref=v0.8.0" # x-release-please-version

  account_id          = var.account_id
  hostname            = "cf-oidc-exchange.example.workers.dev"
  cloudflare_token_secret = { secret_store_id = var.secret_store_id, secret_name = "cf-oidc-exchange-cloudflare-token" }
  policy_file         = "${path.root}/policy.yaml"
}

output "broker_url" {
  value = module.cf_oidc_broker.url
}
```

The module is released with the action and the broker from the same tag, and
by default deploys the broker of the release its `ref` points to.

## Prerequisites

- Terraform or OpenTofu >= 1.9.
- The **Cloudflare token**, an account-owned API token with
  **Account API Tokens Write** (see the [broker's README](../../crates/cf-oidc-exchange-api#deploy)),
  stored in [Secrets Store](https://developers.cloudflare.com/secrets-store/) (open beta).
  If any profile has `buckets`, the token also needs R2 permissions
  covering what they delegate: it creates their credentials and is
  their parent (see [Buckets](../../crates/cf-oidc-exchange-api#buckets)).
- A separate API token for *deploying*, exported as `CLOUDFLARE_API_TOKEN`, with:
  - **Account → Workers Scripts: Edit**
  - **Account → Secrets Store: Edit**, to bind the Cloudflare token's secret
  - **Zone → Workers Routes: Edit** on the broker's zone, only for a custom domain (not tested yet)

  The first two were enough for a workers.dev deploy in testing.
- (Optional) `GITHUB_TOKEN` if you hit anonymous GitHub API rate limits.

## Usage

```sh
# Store the Cloudflare token once. Wrangler prompts for the value.
wrangler secrets-store store list --remote     # note the store ID
wrangler secrets-store secret create <store-id> --name cf-oidc-exchange-cloudflare-token --scopes workers --remote

$EDITOR policy.yaml                            # providers, profiles; see Policy below

export CLOUDFLARE_API_TOKEN=...                # deploy token, not the broker's Cloudflare token
tofu init
tofu apply
curl -fsS "$(tofu output -raw broker_url)/.well-known/oauth-authorization-server"   # 500 if the policy is wrong
```

Terraform only references the secret by store ID and name. The token's value
never enters Terraform state or the plan. Rotate it by replacing the secret in
Secrets Store; the broker reads it on every request.


## URL

`hostname` decides where the broker is served:

- A `*.workers.dev` hostname serves it on workers.dev. It must be
  `<worker_name>.<subdomain>.workers.dev`, with your account's subdomain: find it
  in the dashboard under Workers & Pages, or with
  `GET /accounts/<account_id>/workers/subdomain`. Leave `zone_id` unset.
- Any other hostname is a custom domain and needs `zone_id`. The broker is then
  served on that domain only, and workers.dev is disabled.

Either way the broker is reachable on exactly one URL, the `url` output, which is also the OIDC audience.

## Policy

`policy_file` is rendered with `templatefile`. The module fills in:

- `${broker_url}`: use it for the top-level `issuer` and for each provider's `audience`, so both always match the deployed URL.
- `${account_id}`: use it for account resources.
- Anything in `policy_vars`, e.g. repository IDs looked up with the `github` provider, so no IDs are hard-coded.

Bucket prefixes use the broker's own `{claim}` placeholders, which `templatefile` leaves alone. Don't write `${repository}`: Terraform would try to fill it in and fail the plan.

```yaml
version: 3
issuer: ${broker_url}

providers:
  - name: github
    issuer: https://token.actions.githubusercontent.com
    audience: ${broker_url}
    claims:
      - repository_owner_id: "${owner_id}"  # policy_vars = { owner_id = data.github_organization.org.id }

profiles:
  - name: deploy
    claims:
      - repository_id: "${repo_id}"  # policy_vars = { repo_id = data.github_repository.app.repo_id }
    token:
      policies:
        - permissions: ["Workers Scripts Write"]
          resources:
            "com.cloudflare.api.account.${account_id}": "*"
  - name: terraform-state          # every repo gets its own prefix in one shared bucket
    claims:
      - ref: refs/heads/main
    buckets:
      - name: org-terraform-state
        permission: object-read-write
        prefixes: ["{repository_owner_id}/{repository_id}/"]  # filled in by the broker, per job
```

The format is documented in the [broker's README](../../crates/cf-oidc-exchange-api#policy). A
fuller sample is in [`tests/fixtures/policy.yaml`](tests/fixtures/policy.yaml).

The rendered policy is bound as `CF_OIDC_EXCHANGE_API_POLICY`, compact JSON. A
Worker variable holds at most 5 KB, and the plan fails on a policy over that.
Every policy change creates a new Worker version.

## Upgrading and pinning

The module's `ref` pins the broker too: `?ref=vX.Y.Z` deploys that release's
Worker. To upgrade, bump the `ref`, run `tofu init -upgrade`, then `apply` to
upload a new Worker version and shift all traffic to it. Keep the action's
version in your workflows on the same release.

A release has the Worker's two modules, `index.js` and the wasm (as base64 text,
`index_bg.wasm.base64`), and a `SHA256SUMS` of them. The plan
fails if a download doesn't match `SHA256SUMS`. To pin the artifacts too, set
`checksums_sha256` to the SHA-256 of the release's `SHA256SUMS`:

```sh
curl -fsSL https://github.com/cf-contrib/cf-oidc-exchange/releases/download/v0.8.0/SHA256SUMS | sha256sum # x-release-please-version
```

Set `release_tag = "latest"` to track the newest release instead.

To deploy a build of your own (an unreleased branch, a fork), build the Worker
and set `worker_dir` to the result. Nothing is downloaded then:

```sh
cd crates/cf-oidc-exchange-api
worker-build --release   # worker_dir = ".../crates/cf-oidc-exchange-api/build"
```

## Inputs

| Variable | Required | Default | Description |
|---|---|---|---|
| `account_id` | yes | | Cloudflare account ID. The broker runs here and mints tokens for it. |
| `hostname` | yes | | `<worker_name>.<subdomain>.workers.dev`, or a custom domain. |
| `zone_id` | for a custom domain | `null` | Zone ID of the zone holding a custom-domain `hostname`. |
| `cloudflare_token_secret` | yes | | `{ secret_store_id, secret_name }` of the Secrets Store secret holding the Cloudflare token. With `buckets`, the token also needs R2 permissions covering what they delegate. |
| `signing_key_secret` | for profiles with an `audience` | `null` | `{ secret_store_id, secret_name }` of the Secrets Store secret holding the RSA key the broker signs its own tokens with. See [Tokens for other services](../../crates/cf-oidc-exchange-api#tokens-for-other-services). |
| `policy_file` | yes | | Policy YAML path, rendered as a template. |
| `policy_vars` | no | `{}` | Extra template variables for the policy. |
| `worker_dir` | no | `null` | A local build (`index.js`, `index_bg.wasm`) to deploy instead of a release. |
| `release_tag` | no | the module's release | Release to deploy, or `latest`. |
| `checksums_sha256` | no | `null` | Expected SHA-256 of the release's `SHA256SUMS`. |
| `worker_name` | no | `cf-oidc-exchange` | Worker script name. |
| `worker_compatibility_date` | no | `2026-08-15` | Workers compatibility date. |

## Notes

- Workers Logs is enabled so the audit log is kept. Add Logpush if you need it
  for longer.
- Worker bindings are reset on every version upload, so every binding the broker
  needs is declared here.
- `tofu test` plans the module with mocked providers (no credentials needed) and
  checks the Cloudflare token binding, both URL modes, local artifacts, checksums, the
  policy template (including bucket prefix placeholders) and its size.
