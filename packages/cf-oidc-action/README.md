# cf-oidc-auth action

> The GitHub Action half of [cf-oidc-auth](../..): exchange the job's OIDC token for
> a short-lived Cloudflare API token and/or R2 credentials, export them, and revoke
> the token when the job ends.

[![CI](https://github.com/cf-contrib/cf-oidc-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/cf-contrib/cf-oidc-auth/actions/workflows/ci.yml)
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
      - uses: cf-contrib/cf-oidc-auth@v0.7.0 # x-release-please-version
        with:
          broker-url: https://cf-oidc-broker.example.com
          profile: workers-deploy
      - run: npx wrangler deploy
```

It needs a deployed [broker](../cf-oidc-broker) whose policy allows this workflow.

## Versions

Pin a release. Before 1.0 there's no floating `v0` tag, because a minor release may contain breaking changes:

```yaml
- uses: cf-contrib/cf-oidc-auth@v0.7.0 # x-release-please-version
```

For the strictest setup, pin the commit SHA the tag points to, and let Dependabot's `github-actions` updates keep it current:

```yaml
- uses: cf-contrib/cf-oidc-auth@<commit-sha> # v0.1.0
```

A floating `v1` tag will follow each release from 1.0 on.

## Inputs

| Input | Required | Description |
|---|---|---|
| `broker-url` | yes | Broker base URL, e.g. `https://cf-oidc-broker.example.com`. Its origin is the OIDC audience and must equal `github.audience` in the policy. |
| `profile` | no | Policy profile to request (not an AWS profile). Recommended when more than one profile could match. |
| `ttl` | no | Requested lifetime such as `5m` or `1h`. Defaults to the profile's `ttl`, capped at its `max_ttl`. |

## What it does

- **Main step:**
  - requests an OIDC token for the broker's origin, retrying brief runner failures;
  - asks the broker for a Cloudflare token (not retried, because minting isn't idempotent);
  - masks the token and the OIDC token;
  - exports `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` for the rest of the job. For a profile with only `buckets` there's no token, and only `CLOUDFLARE_ACCOUNT_ID` is exported;
  - when the profile has `buckets`, also writes [S3 credentials](#r2-over-the-s3-api) as one AWS profile per bucket, exports them, and masks the secrets and session tokens;
  - logs the token ID, profile and expiry (none of them secret), so a run can be matched to the broker's audit log:
    ```
    cf-oidc: minted token 3f2a… (profile workers-deploy, expires 2026-09-28T12:15:00Z)
    cf-oidc: issued R2 credentials for bucket org-terraform-state under 100000001/200000003/ (profile terraform-state, expires 2026-09-28T12:15:00Z)
    ```
- **Post step:** revokes the token, if there is one, and deletes the R2 credentials file. It runs even when the job fails. A failed revoke is a warning, not an error: the token expires on its own and the broker's cron deletes it. R2 credentials can't be revoked; the post step logs when they expire.

None of this can be switched off: what's exported is decided by the profile. Exported values are also in the `env` context, so actions that take credentials as inputs can use `${{ env.CLOUDFLARE_API_TOKEN }}`.

## Examples

### With `cloudflare/wrangler-action`

`wrangler-action` sets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` from its own inputs. If you omit them it overwrites the exported values with empty strings, so pass them explicitly:

```yaml
      - uses: cf-contrib/cf-oidc-auth@v0.7.0 # x-release-please-version
        with:
          broker-url: https://cf-oidc-broker.example.com
          profile: workers-deploy
      - uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ env.CLOUDFLARE_API_TOKEN }}
          accountId: ${{ env.CLOUDFLARE_ACCOUNT_ID }}
```

### Terraform / OpenTofu apply

```yaml
      - uses: cf-contrib/cf-oidc-auth@v0.7.0 # x-release-please-version
        with:
          broker-url: https://cf-oidc-broker.example.com
          profile: infra-cloudflare
          ttl: 30m
      - run: tofu apply -auto-approve # the cloudflare provider reads CLOUDFLARE_API_TOKEN
```

### R2 over the S3 API

When the matched profile has [`buckets`](../cf-oidc-broker#buckets), the broker returns temporary R2 credentials for each bucket, limited to its key prefixes. The action writes them to a credentials file, `$RUNNER_TEMP/cf-oidc/credentials` (mode `0600`), with one AWS profile per bucket, named after it. It exports:

| Variable | One bucket | Several buckets |
|---|---|---|
| `AWS_SHARED_CREDENTIALS_FILE` | the credentials file | the same |
| `AWS_ENDPOINT_URL_S3` | `https://<account_id>.r2.cloudflarestorage.com` | the same |
| `AWS_REGION`, `AWS_DEFAULT_REGION` | `auto` | the same |
| `CLOUDFLARE_R2_BUCKETS` | JSON mapping each bucket to its filled-in prefixes, e.g. `{"org-terraform-state":["100000001/200000003/"]}` | the same |
| `AWS_ACCESS_KEY_ID` | the bucket's access key ID (not secret, not masked) | empty |
| `AWS_SECRET_ACCESS_KEY` | the bucket's secret access key, masked | empty |
| `AWS_SESSION_TOKEN`, `AWS_SECURITY_TOKEN` | the bucket's session token, masked. botocore still reads the legacy name | empty |
| `CLOUDFLARE_R2_BUCKET` | the bucket's name | empty |
| `CLOUDFLARE_R2_PREFIX` | the filled-in prefix, e.g. `100000001/200000003/`, if the bucket has exactly one | empty |

- **One bucket:** S3 tools work without a profile. The bucket's profile works too.
- **Several buckets:** there are no default credentials, so every step names its bucket's profile: `aws --profile org-artifacts …`, `AWS_PROFILE` on the step, or the s3 backend's `profile` argument. A step that forgets fails with "Unable to locate credentials", not with credentials left by an earlier step. A workflow that names its profile keeps working when a bucket is added to the profile later.
- **The policy decides when `AWS_*` is replaced.** The credentials overwrite any `AWS_*` credentials already set in the job, for every workflow matching a profile with `buckets`, including one that doesn't set `profile`. Always set `profile` for R2, and give a job that also talks to AWS its R2 access in a separate job.
- **No revocation.** The credentials last as long as the profile's `ttl` (or the requested `ttl`, capped at `max_ttl`), so keep it short. The post step deletes the credentials file.

### Two scopes: two jobs

```yaml
jobs:
  dns:
    runs-on: ubuntu-latest
    environment: prod
    permissions: { contents: read, id-token: write }
    steps:
      - uses: actions/checkout@v6
      - uses: cf-contrib/cf-oidc-auth@v0.7.0 # x-release-please-version
        with: { broker-url: https://cf-oidc-broker.example.com, profile: service-dns }
      - run: ./scripts/update-dns.sh

  deploy:
    needs: dns
    runs-on: ubuntu-latest
    environment: prod
    permissions: { contents: read, id-token: write }
    steps:
      - uses: actions/checkout@v6
      - uses: cf-contrib/cf-oidc-auth@v0.7.0 # x-release-please-version
        with: { broker-url: https://cf-oidc-broker.example.com, profile: workers-deploy }
      - run: npx wrangler deploy
```

## Troubleshooting

| Error | Cause |
|---|---|
| `OIDC unavailable: add permissions: id-token: write to the job` | The job can't request an OIDC token. Add the permission. Fork PRs on `pull_request` never get it. |
| `broker returned 401 (unauthorized)` | The broker rejected the OIDC token, usually because `broker-url` doesn't match `github.audience` in the policy. |
| `broker returned 403 (forbidden)` | No profile allows this workflow, or the named `profile` doesn't match. The broker's audit log (`token.deny`) has the reason. |
| `broker returned 502 (upstream_error)` | The Cloudflare API refused a call; the audit log has the message. For a profile with `buckets`, it's usually a broker token without enough R2 permissions on the bucket. |
| `broker returned 500 (misconfigured)` | The broker's policy or bindings are invalid. Check `/healthz` and its logs. |
| `broker-url must use https` | Plain `http` is only accepted for `localhost` and `127.0.0.1`. |
| `AccessDenied` from S3 on some keys | The credentials only cover the bucket's prefixes: keep every key under `$CLOUDFLARE_R2_PREFIX`. |

## Limitations

- **R2 credentials can't be revoked.** They expire at the end of their TTL.
- **One token per job.** Every step in a job can read the runner, so a second scope in the same job wouldn't be isolated. Use two jobs.
- **No outputs.** The values are in `env`; outputs would just be a second name for them.
- **Masking isn't isolation.** The token is hidden in logs, but any step in the job, including third-party actions and PR code, can use it until the post step revokes it. Keep profiles for prod behind `environment` protection.
- **Needs a `node24` runner.** The action runs straight from the tag's checkout, with no build step and nothing installed.

## License

[MIT](../../LICENSE)
