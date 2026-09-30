output "url" {
  value       = local.broker_url
  description = "Use as the action's broker-url. The policy gets it as $${broker_url}."
}

output "worker_name" {
  value       = cloudflare_worker.this.name
  description = "Deployed Worker script name."
}

output "release_tag" {
  value       = var.broker_file != null ? "local" : data.github_release.this[0].release_tag
  description = "cf-oidc-auth release that was deployed, or \"local\" for broker_file."
}
