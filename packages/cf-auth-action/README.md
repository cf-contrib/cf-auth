# cf-auth action

> The GitHub Action half of [cf-auth](../..): exchange the job's OIDC token for
> a short-lived Cloudflare API token, export it, and revoke it when the job ends.

[![CI](https://github.com/cf-contrib/cf-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/cf-contrib/cf-auth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

> [!NOTE]
> **Pre-1.0.** Inputs may still change between minor versions.

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: prod
    permissions:
      contents: read
      id-token: write # required: lets the job request an OIDC token
    steps:
      - uses: actions/checkout@v6
      - uses: cf-contrib/cf-auth@v0.1.0 # x-release-please-version
        with:
          broker-url: https://cf-auth.example.com
          rule: workers-deploy
      - run: npx wrangler deploy
```

It needs a deployed [broker](../cf-auth-broker) whose policy allows this workflow.

## Versions

Pin a release. Before 1.0 there's no floating `v0` tag, because a minor release may contain breaking changes:

```yaml
- uses: cf-contrib/cf-auth@v0.1.0 # x-release-please-version
```

For the strictest setup, pin the commit SHA the tag points to, and let Dependabot's `github-actions` updates keep it current:

```yaml
- uses: cf-contrib/cf-auth@<commit-sha> # v0.1.0
```

A floating `v1` tag will follow each release from 1.0 on.

## Inputs

| Input | Required | Description |
|---|---|---|
| `broker-url` | yes | Broker base URL, e.g. `https://cf-auth.example.com`. Its origin is the OIDC audience and must equal `github.audience` in the policy. |
| `rule` | no | Rule to request. Recommended when more than one rule could match. |
| `ttl` | no | Requested lifetime such as `5m` or `1h`. Defaults to the rule's `ttl`, capped at its `max_ttl`. |
| `s3-credentials` | no | `true` to also export R2 S3 API credentials derived from the token. Default `false`. See [R2 over the S3 API](#r2-over-the-s3-api). |

## What it does

- **Main step:**
  - requests an OIDC token for the broker's origin, retrying brief runner failures;
  - asks the broker for a Cloudflare token (not retried, because minting isn't idempotent);
  - masks the token and the OIDC token;
  - exports `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` for the rest of the job;
  - with `s3-credentials: true`, also masks and exports `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_ENDPOINT_URL_S3` and `AWS_REGION`;
  - logs the token ID, rule and expiry (none of them secret), so a run can be matched to the broker's audit log:
    ```
    cf-auth: minted token 3f2a… (rule workers-deploy, expires 2026-09-28T12:15:00Z)
    ```
- **Post step:** revokes the token. It runs even when the job fails. A failed revoke is a warning, not an error: the token expires on its own and the broker's cron deletes it.

Apart from `s3-credentials`, none of this can be switched off. Exported values are also in the `env` context, so actions that take credentials as inputs can use `${{ env.CLOUDFLARE_API_TOKEN }}`.

## Examples

### With `cloudflare/wrangler-action`

`wrangler-action` sets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` from its own inputs. If you omit them it overwrites the exported values with empty strings, so pass them explicitly:

```yaml
      - uses: cf-contrib/cf-auth@v0.1.0 # x-release-please-version
        with:
          broker-url: https://cf-auth.example.com
          rule: workers-deploy
      - uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ env.CLOUDFLARE_API_TOKEN }}
          accountId: ${{ env.CLOUDFLARE_ACCOUNT_ID }}
```

### Terraform / OpenTofu apply

```yaml
      - uses: cf-contrib/cf-auth@v0.1.0 # x-release-please-version
        with:
          broker-url: https://cf-auth.example.com
          rule: infra-cloudflare
          ttl: 30m
      - run: tofu apply -auto-approve # the cloudflare provider reads CLOUDFLARE_API_TOKEN
```

### R2 over the S3 API

Tools that speak S3 (`aws s3`, `rclone`, the OpenTofu/Terraform `s3` backend) need an access key pair, not an API token. R2 derives one from any token with R2 permissions: the access key ID is the token's ID and the secret is the SHA-256 of its value. With `s3-credentials: true` the action exports that pair along with the account's R2 endpoint:

| Variable | Value |
|---|---|
| `AWS_ACCESS_KEY_ID` | the token's ID |
| `AWS_SECRET_ACCESS_KEY` | SHA-256 (hex) of the token, masked |
| `AWS_ENDPOINT_URL_S3` | `https://<account_id>.r2.cloudflarestorage.com` |
| `AWS_REGION` | `auto` |

```yaml
      - uses: cf-contrib/cf-auth@v0.1.0 # x-release-please-version
        with:
          broker-url: https://cf-auth.example.com
          rule: infra-cloudflare
          ttl: 30m
          s3-credentials: true
      - run: tofu init && tofu apply -auto-approve # s3 backend on R2, cloudflare provider
```

- The rule must grant R2 permissions, e.g. `Workers R2 Storage Bucket Item Read`/`Write` on `com.cloudflare.edge.r2.bucket.<account_id>_default_<bucket>`. Without them the credentials are rejected.
- The pair lives and dies with the token: the post step's revoke invalidates it too.
- It's opt-in because it overwrites any `AWS_*` credentials already set in the job. A job that also talks to AWS should get R2 access in a separate job.
- Buckets in a jurisdiction (`eu`, `fedramp`) use a different endpoint, e.g. `https://<account_id>.eu.r2.cloudflarestorage.com`. Set it in the tool's config, which takes precedence over `AWS_ENDPOINT_URL_S3`.

### Two scopes: two jobs

```yaml
jobs:
  dns:
    runs-on: ubuntu-latest
    environment: prod
    permissions: { contents: read, id-token: write }
    steps:
      - uses: actions/checkout@v6
      - uses: cf-contrib/cf-auth@v0.1.0 # x-release-please-version
        with: { broker-url: https://cf-auth.example.com, rule: service-dns }
      - run: ./scripts/update-dns.sh

  deploy:
    needs: dns
    runs-on: ubuntu-latest
    environment: prod
    permissions: { contents: read, id-token: write }
    steps:
      - uses: actions/checkout@v6
      - uses: cf-contrib/cf-auth@v0.1.0 # x-release-please-version
        with: { broker-url: https://cf-auth.example.com, rule: workers-deploy }
      - run: npx wrangler deploy
```

## Troubleshooting

| Error | Cause |
|---|---|
| `OIDC unavailable: add permissions: id-token: write to the job` | The job can't request an OIDC token. Add the permission. Fork PRs on `pull_request` never get it. |
| `broker returned 401 (unauthorized)` | The broker rejected the OIDC token, usually because `broker-url` doesn't match `github.audience` in the policy. |
| `broker returned 403 (forbidden)` | No rule allows this workflow, or the named `rule` doesn't match. The broker's audit log (`token.deny`) has the reason. |
| `broker returned 500 (misconfigured)` | The broker's policy or bindings are invalid. Check `/healthz` and its logs. |
| `broker-url must use https` | Plain `http` is only accepted for `localhost` and `127.0.0.1`. |

## Limitations

- **One token per job.** Every step in a job can read the runner, so a second scope in the same job wouldn't be isolated. Use two jobs.
- **No outputs.** The values are in `env`; outputs would just be a second name for them.
- **Masking isn't isolation.** The token is hidden in logs, but any step in the job, including third-party actions and PR code, can use it until the post step revokes it. Keep rules for prod behind `environment` protection.
- **Needs a `node24` runner.** The action runs straight from the tag's checkout, with no build step and nothing installed.

## License

[MIT](../../LICENSE)
