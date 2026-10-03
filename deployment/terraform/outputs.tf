output "url" {
  value       = local.broker_url
  description = "The broker's URL: use it as the action's url. It's the policy's issuer, and providers' audience unless they name another."
}

output "worker_name" {
  value       = cloudflare_worker.this.name
  description = "Deployed Worker script name."
}

output "release_tag" {
  value       = var.worker_dir != null ? "local" : data.github_release.this[0].release_tag
  description = "cf-oidc-exchange release that was deployed, or \"local\" for worker_dir."
}
