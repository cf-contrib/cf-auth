output "url" {
  value       = local.broker_url
  description = "Use as the action's url. The policy gets it as $${broker_url}."
}

output "worker_name" {
  value       = cloudflare_worker.this.name
  description = "Deployed Worker script name."
}

output "release_tag" {
  value       = var.worker_dir != null ? "local" : data.github_release.this[0].release_tag
  description = "cf-oidc-exchange release that was deployed, or \"local\" for worker_dir."
}
