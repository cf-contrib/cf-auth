# cf-oidc-auth Terraform module

> The Terraform / OpenTofu half of [cf-oidc-auth](../../..): deploys the released
> `broker.js` as a Cloudflare Worker, with its bindings, hourly cleanup cron, and
> a workers.dev URL (or, optionally, a custom domain). No `wrangler` or local
> build is needed.

```hcl
module "cf_auth" {
  source = "git::https://github.com/cf-contrib/cf-oidc-auth.git//packages/cf-oidc-broker/terraform?ref=v0.4.0" # x-release-please-version

  account_id          = var.account_id
  hostname            = "cf-auth.example.workers.dev"
  broker_token_secret = { store_id = var.store_id, secret_name = "cf-auth-broker-token" }
  policy_file         = "${path.root}/policy.yaml"
}

output "broker_url" {
  value = module.cf_auth.broker_url
}
```

The module is released with the action and the broker from the same tag, and
by default deploys the `broker.js` of the release its `ref` points to.

## Prerequisites

- Terraform or OpenTofu >= 1.9.
- The **broker token**, an account-owned API token with only
  **Account API Tokens Write** (see the [broker's README](..#deploy)),
  stored in [Secrets Store](https://developers.cloudflare.com/secrets-store/) (open beta).
- A separate API token for *deploying*, exported as `CLOUDFLARE_API_TOKEN`, with:
  - **Account → Workers Scripts: Edit**
  - **Account → Secrets Store: Edit**, to bind the broker token's secret
  - **Zone → Workers Routes: Edit** on the broker's zone, only for a custom domain (not tested yet)

  The first two were enough for a workers.dev deploy in testing.
- (Optional) `GITHUB_TOKEN` if you hit anonymous GitHub API rate limits.

## Usage

```sh
# Store the broker token once. Wrangler prompts for the value.
wrangler secrets-store store list --remote     # note the store ID
wrangler secrets-store secret create <store-id> --name cf-auth-broker-token --scopes workers --remote

$EDITOR policy.yaml                            # owner_id, profiles; see Policy below

export CLOUDFLARE_API_TOKEN=...                # deploy token, not the broker token
tofu init
tofu apply
curl -fsS "$(tofu output -raw broker_url)/healthz"   # 500 if the policy or the secret is wrong
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

Either way the broker is reachable on exactly one URL, `broker_url`, which is also the OIDC audience.

## Policy

`policy_file` is rendered with `templatefile`. The module fills in:

- `${broker_url}`: use it for `github.audience`, so the audience always matches the deployed URL.
- `${account_id}`: use it for account resources.
- Anything in `policy_vars`, e.g. repository IDs looked up with the `github` provider, so no IDs are hard-coded.

```yaml
version: 1

github:
  audience: ${broker_url}
  owner_id: "${owner_id}"          # policy_vars = { owner_id = data.github_organization.org.id }
profiles:
  - name: deploy
    match:
      repository_id: "${repo_id}"  # policy_vars = { repo_id = data.github_repository.app.repo_id }
    token:
      policies:
        - permissions: ["Workers Scripts Write"]
          resources:
            "com.cloudflare.api.account.${account_id}": "*"
```

The format is documented in the [broker's README](..#policy). A
fuller sample is in [`tests/fixtures/policy.yaml`](tests/fixtures/policy.yaml).

The rendered policy must fit in one Worker binding: Cloudflare allows 5 KB per
variable, which is roughly 15–20 profiles. The plan fails with the policy's size if
it's larger. Past that, run a broker per team or trust domain.

## Upgrading and pinning

The module's `ref` pins the broker too: `?ref=vX.Y.Z` deploys that release's
`broker.js`. To upgrade, bump the `ref`, run `tofu init -upgrade`, then `apply` to
upload a new Worker version and shift all traffic to it. Keep the action's
version in your workflows on the same release.

To pin the artifact itself, also set `broker_sha256` to the value in the
release's `broker.js.sha256`. The plan fails if the download doesn't match. Set
`release_tag = "latest"` to track the newest release instead.

To deploy a build of your own (an unreleased branch, a fork), run `pnpm build`
and set `broker_file` to the resulting `packages/cf-oidc-broker/dist/broker.js`.
Nothing is downloaded then.

## Inputs

| Variable | Required | Default | Description |
|---|---|---|---|
| `account_id` | yes | | Cloudflare account ID. The broker runs here and mints tokens for it. |
| `hostname` | yes | | `<worker_name>.<subdomain>.workers.dev`, or a custom domain. |
| `zone_id` | for a custom domain | `null` | Zone ID of the zone holding a custom-domain `hostname`. |
| `broker_token_secret` | yes | | `{ store_id, secret_name }` of the Secrets Store secret holding the broker token. Recommended. |
| `policy_file` | yes | | Policy YAML path, rendered as a template. |
| `policy_vars` | no | `{}` | Extra template variables for the policy. |
| `broker_file` | no | `null` | Local `broker.js` to deploy instead of a release. |
| `release_tag` | no | the module's release | Release to deploy, or `latest`. |
| `broker_sha256` | no | `null` | Expected SHA-256 of `broker.js`. |
| `worker_name` | no | `cf-auth` | Worker script name. |
| `worker_compatibility_date` | no | `2026-08-15` | Workers compatibility date. |

## Notes

- Workers Logs is enabled so the audit log is kept. Add Logpush if you need it
  for longer.
- Worker bindings are reset on every version upload, so every binding the broker
  needs is declared here.
- `tofu test` plans the module with mocked providers (no credentials needed) and
  checks the broker token binding, both URL modes, local artifacts, checksums, the
  policy template and the policy size limit.
