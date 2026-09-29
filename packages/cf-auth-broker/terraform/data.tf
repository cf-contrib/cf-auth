# The release is only downloaded when no local broker_file is given.
data "github_release" "cf_auth" {
  count = var.broker_file == null ? 1 : 0

  owner       = "cf-contrib"
  repository  = "cf-auth"
  retrieve_by = var.release_tag == "latest" ? "latest" : "tag"
  release_tag = var.release_tag == "latest" ? null : var.release_tag
}

locals {
  release_assets = var.broker_file != null ? {} : {
    for asset in data.github_release.cf_auth[0].assets : asset.name => asset.browser_download_url
  }
}

data "http" "broker_js" {
  count = var.broker_file == null ? 1 : 0

  url = local.release_assets["broker.js"]
}

locals {
  broker_js = var.broker_file != null ? file(var.broker_file) : data.http.broker_js[0].response_body
}
