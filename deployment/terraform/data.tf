# The release is only downloaded when no local worker_dir is given.
data "github_release" "this" {
  count = var.worker_dir == null ? 1 : 0

  owner       = "cf-contrib"
  repository  = "cf-oidc-auth"
  retrieve_by = var.release_tag == "latest" ? "latest" : "tag"
  release_tag = var.release_tag == "latest" ? null : var.release_tag
}

locals {
  release_assets = var.worker_dir != null ? {} : {
    for asset in data.github_release.this[0].assets : asset.name => asset.browser_download_url
  }
}

# The Worker's modules: entry.js imports index.js, worker-build's output, which
# imports the wasm. The release has the wasm as base64 text, so its checksum can
# be checked here: Terraform only hashes strings.
data "http" "entry_js" {
  count = var.worker_dir == null ? 1 : 0
  url   = local.release_assets["entry.js"]
}

data "http" "index_js" {
  count = var.worker_dir == null ? 1 : 0
  url   = local.release_assets["index.js"]
}

data "http" "index_bg_wasm" {
  count = var.worker_dir == null ? 1 : 0
  url   = local.release_assets["index_bg.wasm.base64"]
}

data "http" "sha256sums" {
  count = var.worker_dir == null ? 1 : 0
  url   = local.release_assets["SHA256SUMS"]
}

locals {
  entry_js      = var.worker_dir != null ? file("${var.worker_dir}/entry.js") : data.http.entry_js[0].response_body
  index_js      = var.worker_dir != null ? file("${var.worker_dir}/index.js") : data.http.index_js[0].response_body
  wasm_download = var.worker_dir != null ? "" : data.http.index_bg_wasm[0].response_body
  wasm_base64   = var.worker_dir != null ? filebase64("${var.worker_dir}/index_bg.wasm") : trimspace(local.wasm_download)

  # SHA256SUMS, as sha256sum writes it: "<hash>  <name>" on each line.
  sha256sums = var.worker_dir != null ? "" : data.http.sha256sums[0].response_body
  checksums = {
    for line in split("\n", trimspace(local.sha256sums)) :
    trimprefix(regex("  .*$", line), "  ") => regex("^[0-9a-f]{64}", line)
    if length(regexall("^[0-9a-f]{64}  ", line)) > 0
  }

  # Every downloaded file must match SHA256SUMS, and SHA256SUMS must match checksums_sha256 if it's set.
  release_ok = var.worker_dir != null || (
    lookup(local.checksums, "entry.js", "") == sha256(local.entry_js) &&
    lookup(local.checksums, "index.js", "") == sha256(local.index_js) &&
    lookup(local.checksums, "index_bg.wasm.base64", "") == sha256(local.wasm_download) &&
    (var.checksums_sha256 == null || sha256(local.sha256sums) == var.checksums_sha256)
  )
}
