locals {
  custom_domain = !endswith(var.hostname, ".workers.dev")

  # The OIDC audience. The policy gets it as $${broker_url}, so the two can't drift.
  broker_url = "https://${var.hostname}"
}

# Worker script. It's reachable on exactly one URL, the OIDC audience: its
# workers.dev URL, or the custom domain if hostname is one.
resource "cloudflare_worker" "this" {
  account_id = var.account_id
  name       = var.worker_name

  subdomain = {
    enabled = !local.custom_domain
  }

  # The audit log goes to Workers Logs.
  observability = {
    enabled = true
    logs = {
      enabled         = true
      invocation_logs = false
    }
  }
}

locals {
  policy_json = jsonencode(yamldecode(templatefile(var.policy_file, merge(var.policy_vars, {
    account_id = var.account_id
    broker_url = local.broker_url
  }))))
}

# Upload a new version on every artifact, policy or binding change.
resource "cloudflare_worker_version" "this" {
  account_id         = var.account_id
  worker_id          = cloudflare_worker.this.id
  compatibility_date = var.worker_compatibility_date
  main_module        = "entry.js"

  lifecycle {
    precondition {
      condition     = local.release_ok
      error_message = "The release's files don't match its SHA256SUMS, or SHA256SUMS doesn't match checksums_sha256."
    }
  }

  modules = [
    {
      # Hands the Worker policy.json, then is the Worker.
      name           = "entry.js"
      content_type   = "application/javascript+module"
      content_base64 = base64encode(local.entry_js)
    },
    {
      name           = "index.js"
      content_type   = "application/javascript+module"
      content_base64 = base64encode(local.index_js)
    },
    {
      name           = "index_bg.wasm"
      content_type   = "application/wasm"
      content_base64 = local.wasm_base64
    },
    {
      # Imported by entry.js. Uploaded as text, which the Worker parses, since
      # Workers has no JSON module type.
      name           = "policy.json"
      content_type   = "text/plain"
      content_base64 = base64encode(local.policy_json)
    },
  ]

  bindings = concat([
    {
      name = "CF_OIDC_EXCHANGE_API_ACCOUNT_ID"
      type = "plain_text"
      text = var.account_id
    },
    {
      # Only ever from Secrets Store, so the token never enters Terraform state.
      name        = "CF_OIDC_EXCHANGE_API_CLOUDFLARE_TOKEN"
      type        = "secrets_store_secret"
      store_id    = var.cloudflare_token_secret.secret_store_id
      secret_name = var.cloudflare_token_secret.secret_name
    },
    ], var.signing_key_secret == null ? [] : [
    {
      # The key the broker signs its own tokens with, for profiles with an audience.
      name        = "CF_OIDC_EXCHANGE_API_SIGNING_KEY"
      type        = "secrets_store_secret"
      store_id    = var.signing_key_secret.secret_store_id
      secret_name = var.signing_key_secret.secret_name
    },
  ])
}

# Promote the new version to 100% of traffic.
resource "cloudflare_workers_deployment" "this" {
  account_id  = var.account_id
  script_name = cloudflare_worker.this.name
  strategy    = "percentage"

  versions = [
    {
      percentage = 100
      version_id = cloudflare_worker_version.this.id
    },
  ]
}

resource "cloudflare_workers_custom_domain" "this" {
  count = local.custom_domain ? 1 : 0

  account_id = var.account_id
  zone_id    = var.zone_id
  hostname   = var.hostname
  service    = cloudflare_worker.this.name

  depends_on = [cloudflare_workers_deployment.this]
}

# Hourly cleanup of expired cf-oidc:* tokens.
resource "cloudflare_workers_cron_trigger" "this" {
  account_id  = var.account_id
  script_name = cloudflare_worker.this.name
  schedules   = [{ cron = "17 * * * *" }]

  depends_on = [cloudflare_workers_deployment.this]
}
