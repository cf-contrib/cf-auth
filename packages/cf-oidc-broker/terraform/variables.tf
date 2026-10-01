variable "account_id" {
  type        = string
  description = "Cloudflare account ID. The broker runs here and mints tokens for this account."
}

variable "hostname" {
  type        = string
  description = "The broker's hostname, which is also the OIDC audience: <worker_name>.<subdomain>.workers.dev, or a custom domain such as cf-oidc-broker.example.com (needs zone_id)."

  validation {
    condition     = can(regex("^[a-z0-9-]+(\\.[a-z0-9-]+)+$", var.hostname))
    error_message = "hostname must be a bare lowercase hostname, without a scheme, port or path."
  }

  validation {
    condition     = !endswith(var.hostname, ".workers.dev") || (startswith(var.hostname, "${var.worker_name}.") && length(split(".", var.hostname)) == 4)
    error_message = "A workers.dev hostname must be ${var.worker_name}.<subdomain>.workers.dev: Cloudflare serves the Worker under its name."
  }
}

variable "zone_id" {
  type        = string
  description = "Zone ID of the zone that holds a custom-domain hostname. Not used for workers.dev."
  default     = null

  validation {
    condition     = (var.zone_id == null) == endswith(var.hostname, ".workers.dev")
    error_message = "Set zone_id for a custom domain, and not for a workers.dev hostname."
  }
}

variable "broker_token_secret" {
  type = object({
    secret_store_id = string
    secret_name     = string
  })
  description = "Secrets Store secret holding the broker token: an account-owned token with \"Account API Tokens Write\", plus R2 permissions covering what profiles' buckets delegate (it creates those credentials and is their parent). Terraform only references it; the value never enters state."
}

variable "policy_file" {
  type        = string
  description = "Path to the policy YAML, rendered as a template with $${account_id}, $${broker_url} and policy_vars. Use an absolute path such as \"$${path.root}/policy.yaml\"."
}

variable "policy_vars" {
  type        = map(string)
  description = "Extra template variables for the policy, e.g. repository IDs looked up with the github provider."
  default     = {}
}

variable "release_tag" {
  type        = string
  description = "cf-oidc-auth release to deploy, e.g. v1.2.3, or \"latest\". Defaults to the release this module comes from."
  default     = "v0.7.0" # x-release-please-version
}

variable "broker_file" {
  type        = string
  description = "Path to a locally built broker.js (pnpm build). Deploys it instead of downloading a release."
  default     = null
}

variable "broker_sha256" {
  type        = string
  description = "Expected SHA-256 of broker.js (from the release's broker.js.sha256). Set it to pin the artifact."
  default     = null
}

variable "worker_name" {
  type        = string
  description = "Cloudflare Worker script name."
  default     = "cf-auth"
}

variable "worker_compatibility_date" {
  type        = string
  description = "Workers runtime compatibility date."
  default     = "2026-08-15"
}
