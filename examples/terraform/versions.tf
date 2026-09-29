# Providers are configured by the caller, or by default when used as a root
# module: cloudflare reads CLOUDFLARE_API_TOKEN, github GITHUB_TOKEN (optional).
terraform {
  required_version = ">= 1.9.0"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.10"
    }
    github = {
      source  = "integrations/github"
      version = "~> 6.6"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.5"
    }
  }
}
