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
      - uses: cf-contrib/cf-oidc-auth@v0.4.2 # x-release-please-version
        with:
          broker-url: https://cf-oidc-broker.example.com
          profile: workers-deploy
      - run: npx wrangler deploy
```

It needs a deployed [broker](../cf-oidc-broker) whose policy allows this workflow.

## Versions

Pin a release. Before 1.0 there's no floating `v0` tag, because a minor release may contain breaking changes:

```yaml
- uses: cf-contrib/cf-oidc-auth@v0.4.2 # x-release-please-version
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
  - exports `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` for the rest of the job. For a profile with only an `r2` grant there's no token, and only `CLOUDFLARE_ACCOUNT_ID` is exported;
  - when the profile has an `r2` grant, also exports [S3 credentials](#r2-over-the-s3-api) (`AWS_*`) and masks the secret and the session token;
  - logs the token ID, profile and expiry (none of them secret), so a run can be matched to the broker's audit log:
    ```
    cf-oidc: minted token 3f2a… (profile workers-deploy, expires 2026-09-28T12:15:00Z)
    cf-oidc: issued R2 credentials for bucket org-terraform-state under 100000001/200000003/ (profile terraform-state, expires 2026-09-28T12:15:00Z)
    ```
- **Post step:** revokes the token, if there is one. It runs even when the job fails. A failed revoke is a warning, not an error: the token expires on its own and the broker's cron deletes it. R2 credentials can't be revoked; the post step logs when they expire.

None of this can be switched off: what's exported is decided by the profile. Exported values are also in the `env` context, so actions that take credentials as inputs can use `${{ env.CLOUDFLARE_API_TOKEN }}`.

## Examples

### With `cloudflare/wrangler-action`

`wrangler-action` sets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` from its own inputs. If you omit them it overwrites the exported values with empty strings, so pass them explicitly:

```yaml
      - uses: cf-contrib/cf-oidc-auth@v0.4.2 # x-release-please-version
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
      - uses: cf-contrib/cf-oidc-auth@v0.4.2 # x-release-please-version
        with:
          broker-url: https://cf-oidc-broker.example.com
          profile: infra-cloudflare
          ttl: 30m
      - run: tofu apply -auto-approve # the cloudflare provider reads CLOUDFLARE_API_TOKEN
```

### R2 over the S3 API

When the matched profile has an [`r2` grant](../cf-oidc-broker#r2-grants), the broker returns temporary R2 credentials for one bucket, limited to the grant's key prefixes, and the action exports them:

| Variable | Value |
|---|---|
| `AWS_ACCESS_KEY_ID` | the access key ID (not secret, not masked) |
| `AWS_SECRET_ACCESS_KEY` | the secret access key, masked |
| `AWS_SESSION_TOKEN`, `AWS_SECURITY_TOKEN` | the session token, masked. botocore still reads the legacy name |
| `AWS_ENDPOINT_URL_S3` | `https://<account_id>.r2.cloudflarestorage.com` |
| `AWS_REGION`, `AWS_DEFAULT_REGION` | `auto` |
| `CLOUDFLARE_R2_BUCKET` | the grant's bucket |
| `CLOUDFLARE_R2_PREFIX` | the filled-in prefix, e.g. `100000001/200000003/`. Only when the grant has exactly one |

These replace any `AWS_*` credentials already set in the job, and the **policy** decides when that happens: every workflow matching a profile with an `r2` grant gets them, including one that doesn't set `profile`. Always set `profile` for R2, and give a job that also talks to AWS its R2 access in a separate job.

The credentials can't be revoked. They last as long as the profile's `ttl` (or the requested `ttl`, capped at `max_ttl`), so keep it short.

**OpenTofu / Terraform `s3` backend** takes the credentials from the environment. It can't read `bucket` or `key` from it, so pass them at init. Non-default workspaces are stored under `workspace_key_prefix` (default `env:`), which is outside the repo's prefix, so move it inside or `tofu workspace` commands are denied:

```yaml
    permissions: { contents: read, id-token: write }
    steps:
      - uses: actions/checkout@v6
      - uses: cf-contrib/cf-oidc-auth@v0.4.2 # x-release-please-version
        with:
          broker-url: https://cf-oidc-broker.example.com
          profile: terraform-state
      - run: |
          tofu init \
            -backend-config="bucket=$CLOUDFLARE_R2_BUCKET" \
            -backend-config="key=${CLOUDFLARE_R2_PREFIX}terraform.tfstate" \
            -backend-config="workspace_key_prefix=${CLOUDFLARE_R2_PREFIX}env:"
          tofu apply -auto-approve
```

```hcl
terraform {
  backend "s3" {
    # bucket, key and workspace_key_prefix come from -backend-config.
    region       = "auto"
    use_lockfile = true # writes <key>.tflock, inside the prefix

    skip_credentials_validation = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_metadata_api_check     = true
    skip_s3_checksum            = true
    use_path_style              = true
  }
}
```

The backend reads the endpoint from `AWS_ENDPOINT_URL_S3`. R2 isn't AWS, so the backend's AWS-only checks are switched off.

With a policy like this in the broker, every repo in the org gets read and write access to its own state, and to nothing else in the bucket:

```yaml
  - name: terraform-state
    match:
      ref: refs/heads/main
    r2:
      bucket: org-terraform-state
      permission: object-read-write
      prefixes: ["{repository_owner_id}/{repository_id}/"] # survives renames, unlike {repository}
```

**AWS CLI and SDKs** read all of these. `AWS_ENDPOINT_URL_S3` needs a version with service-specific endpoint support (added in 2023). With an older one, pass the endpoint yourself:

```yaml
      - run: aws s3 sync ./dist "s3://$CLOUDFLARE_R2_BUCKET/$CLOUDFLARE_R2_PREFIX" --endpoint-url "$AWS_ENDPOINT_URL_S3"
```

**rclone** doesn't read `AWS_ENDPOINT_URL_S3`. Point it at R2 and tell it to use the environment's keys:

```yaml
      - run: rclone copy ./dist "r2:$CLOUDFLARE_R2_BUCKET/$CLOUDFLARE_R2_PREFIX"
        env:
          RCLONE_CONFIG_R2_TYPE: s3
          RCLONE_CONFIG_R2_PROVIDER: Cloudflare
          RCLONE_CONFIG_R2_ENV_AUTH: "true"
          RCLONE_CONFIG_R2_ENDPOINT: ${{ env.AWS_ENDPOINT_URL_S3 }}
```

**Several buckets, or admin operations** such as creating or listing buckets, aren't covered by a grant. Grant R2 permissions in the profile's `token` instead, e.g. `Workers R2 Storage Bucket Item Write` on `com.cloudflare.edge.r2.bucket.<account_id>_default_<bucket>`, and derive S3 credentials from the token in a step. The access key ID is the token's ID, the secret is the SHA-256 of its value, and both die with the token when the post step revokes it:

```yaml
      - run: |
          secret=$(printf %s "$CLOUDFLARE_API_TOKEN" | sha256sum | cut -d' ' -f1)
          echo "::add-mask::$secret"
          id=$(curl -fsS -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
            "https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/tokens/verify" | jq -r .result.id)
          {
            echo "AWS_ACCESS_KEY_ID=$id"
            echo "AWS_SECRET_ACCESS_KEY=$secret"
            echo "AWS_ENDPOINT_URL_S3=https://$CLOUDFLARE_ACCOUNT_ID.r2.cloudflarestorage.com"
            echo "AWS_REGION=auto"
            echo "AWS_SESSION_TOKEN="   # clears one left by an earlier AWS step
          } >> "$GITHUB_ENV"
```

**Jurisdictions:** buckets in a jurisdiction (`eu`, `fedramp`) use a different endpoint, e.g. `https://<account_id>.eu.r2.cloudflarestorage.com`, and aren't supported by grants yet.

### Two scopes: two jobs

```yaml
jobs:
  dns:
    runs-on: ubuntu-latest
    environment: prod
    permissions: { contents: read, id-token: write }
    steps:
      - uses: actions/checkout@v6
      - uses: cf-contrib/cf-oidc-auth@v0.4.2 # x-release-please-version
        with: { broker-url: https://cf-oidc-broker.example.com, profile: service-dns }
      - run: ./scripts/update-dns.sh

  deploy:
    needs: dns
    runs-on: ubuntu-latest
    environment: prod
    permissions: { contents: read, id-token: write }
    steps:
      - uses: actions/checkout@v6
      - uses: cf-contrib/cf-oidc-auth@v0.4.2 # x-release-please-version
        with: { broker-url: https://cf-oidc-broker.example.com, profile: workers-deploy }
      - run: npx wrangler deploy
```

## Troubleshooting

| Error | Cause |
|---|---|
| `OIDC unavailable: add permissions: id-token: write to the job` | The job can't request an OIDC token. Add the permission. Fork PRs on `pull_request` never get it. |
| `broker returned 401 (unauthorized)` | The broker rejected the OIDC token, usually because `broker-url` doesn't match `github.audience` in the policy. |
| `broker returned 403 (forbidden)` | No profile allows this workflow, or the named `profile` doesn't match. The broker's audit log (`token.deny`) has the reason. |
| `broker returned 502 (upstream_error)` | The Cloudflare API refused a call; the audit log has the message. For a profile with an `r2` grant, it's usually a broker token without enough R2 permissions on the grant's bucket. |
| `broker returned 500 (misconfigured)` | The broker's policy or bindings are invalid. Check `/healthz` and its logs. |
| `broker-url must use https` | Plain `http` is only accepted for `localhost` and `127.0.0.1`. |
| `AccessDenied` from S3 on some keys | The credentials only cover the grant's prefixes. Check `key` and `workspace_key_prefix` start with `$CLOUDFLARE_R2_PREFIX`. |

## Limitations

- **R2 credentials can't be revoked.** They expire at the end of their TTL.
- **One token per job.** Every step in a job can read the runner, so a second scope in the same job wouldn't be isolated. Use two jobs.
- **No outputs.** The values are in `env`; outputs would just be a second name for them.
- **Masking isn't isolation.** The token is hidden in logs, but any step in the job, including third-party actions and PR code, can use it until the post step revokes it. Keep profiles for prod behind `environment` protection.
- **Needs a `node24` runner.** The action runs straight from the tag's checkout, with no build step and nothing installed.

## License

[MIT](../../LICENSE)
