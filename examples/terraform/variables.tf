variable "account_id" {
  type        = string
  description = "Cloudflare account ID. The broker runs here and mints tokens for this account."
}

variable "hostname" {
  type        = string
  description = "Custom domain for the broker, e.g. cf-auth.example.com. Set this and zone_id, or workers_dev_subdomain."
  default     = null
}

variable "zone_id" {
  type        = string
  description = "Zone ID of the zone that holds hostname."
  default     = null
}

variable "workers_dev_subdomain" {
  type        = string
  description = "Your account's workers.dev subdomain. Serves the broker at https://<worker_name>.<subdomain>.workers.dev instead of a custom domain."
  default     = null
}

variable "broker_token_secret" {
  type = object({
    store_id    = string
    secret_name = string
  })
  description = "Secrets Store secret holding the broker token (an account-owned token with only \"Account API Tokens Write\"). Terraform only references it; the value never enters state."
}

variable "policy_file" {
  type        = string
  description = "Path to the policy YAML, rendered as a template with $${account_id}, $${broker_url} and policy_vars."
  default     = "policy.yaml"
}

variable "policy_vars" {
  type        = map(string)
  description = "Extra template variables for the policy, e.g. repository IDs looked up with the github provider."
  default     = {}
}

variable "release_tag" {
  type        = string
  description = "cf-auth release to deploy, e.g. v1.2.3, or \"latest\"."
  default     = "latest"
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
