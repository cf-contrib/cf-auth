locals {
  custom_domain = !endswith(var.hostname, ".workers.dev")

  # The OIDC audience. The policy gets it as $${broker_url}, so the two can't drift.
  broker_url = "https://${var.hostname}"
}

# Worker script. It's reachable on exactly one URL, the OIDC audience: its
# workers.dev URL, or the custom domain if hostname is one.
resource "cloudflare_worker" "cf_auth" {
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

  # Cloudflare caps each Worker environment variable at 5 KB. Counted
  # conservatively as 5,000 characters; the JSON is ASCII in practice.
  policy_max_length = 5000
}

# Upload a new version on every artifact, policy or binding change.
resource "cloudflare_worker_version" "cf_auth" {
  account_id         = var.account_id
  worker_id          = cloudflare_worker.cf_auth.id
  compatibility_date = var.worker_compatibility_date
  main_module        = "broker.js"

  lifecycle {
    precondition {
      condition     = var.broker_sha256 == null || sha256(local.broker_js) == var.broker_sha256
      error_message = "broker.js does not match broker_sha256."
    }

    precondition {
      condition     = length(local.policy_json) <= local.policy_max_length
      error_message = "The policy is ${length(local.policy_json)} characters as JSON; Cloudflare allows ${local.policy_max_length} per binding. Split it across brokers or trim it."
    }
  }

  modules = [
    {
      name           = "broker.js"
      content_type   = "application/javascript+module"
      content_base64 = base64encode(local.broker_js)
    },
  ]

  bindings = [
    {
      name = "CF_AUTH_BROKER_ACCOUNT_ID"
      type = "plain_text"
      text = var.account_id
    },
    {
      name = "CF_AUTH_BROKER_POLICY"
      type = "plain_text"
      text = local.policy_json
    },
    {
      # Only ever from Secrets Store, so the token never enters Terraform state.
      name        = "CF_AUTH_BROKER_TOKEN"
      type        = "secrets_store_secret"
      store_id    = var.broker_token_secret.store_id
      secret_name = var.broker_token_secret.secret_name
    },
  ]
}

# Promote the new version to 100% of traffic.
resource "cloudflare_workers_deployment" "cf_auth" {
  account_id  = var.account_id
  script_name = cloudflare_worker.cf_auth.name
  strategy    = "percentage"

  versions = [
    {
      percentage = 100
      version_id = cloudflare_worker_version.cf_auth.id
    },
  ]
}

resource "cloudflare_workers_custom_domain" "cf_auth" {
  count = local.custom_domain ? 1 : 0

  account_id = var.account_id
  zone_id    = var.zone_id
  hostname   = var.hostname
  service    = cloudflare_worker.cf_auth.name

  depends_on = [cloudflare_workers_deployment.cf_auth]
}

# Hourly cleanup of expired cf-auth:* tokens.
resource "cloudflare_workers_cron_trigger" "cf_auth" {
  account_id  = var.account_id
  script_name = cloudflare_worker.cf_auth.name
  schedules   = [{ cron = "17 * * * *" }]

  depends_on = [cloudflare_workers_deployment.cf_auth]
}
