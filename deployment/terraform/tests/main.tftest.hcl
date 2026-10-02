# Plans the module with mocked providers: no credentials or network needed.
# Covers the broker token binding, URL modes, the release and local artifacts, their
# checksums, the policy template and its size,
# and bucket prefix placeholders.
mock_provider "cloudflare" {}
mock_provider "github" {}
mock_provider "http" {}

override_data {
  target = data.github_release.this
  values = {
    assets = [
      {
        name                 = "index.js"
        browser_download_url = "https://example.com/index.js"
        content_type         = "application/octet-stream"
        created_at           = "2026-10-02T00:00:00Z"
        id                   = 2
        label                = ""
        node_id              = "RA_test2"
        size                 = 1
        updated_at           = "2026-10-02T00:00:00Z"
        url                  = "https://api.github.com/repos/cf-contrib/cf-oidc-exchange/releases/assets/2"
      },
      {
        name                 = "index_bg.wasm.base64"
        browser_download_url = "https://example.com/index_bg.wasm.base64"
        content_type         = "application/octet-stream"
        created_at           = "2026-10-02T00:00:00Z"
        id                   = 3
        label                = ""
        node_id              = "RA_test3"
        size                 = 1
        updated_at           = "2026-10-02T00:00:00Z"
        url                  = "https://api.github.com/repos/cf-contrib/cf-oidc-exchange/releases/assets/3"
      },
      {
        name                 = "SHA256SUMS"
        browser_download_url = "https://example.com/SHA256SUMS"
        content_type         = "application/octet-stream"
        created_at           = "2026-10-02T00:00:00Z"
        id                   = 4
        label                = ""
        node_id              = "RA_test4"
        size                 = 1
        updated_at           = "2026-10-02T00:00:00Z"
        url                  = "https://api.github.com/repos/cf-contrib/cf-oidc-exchange/releases/assets/4"
      },
    ]
  }
}

# A release whose files match its SHA256SUMS.
override_data {
  target = data.http.index_js
  values = { response_body = "export default {};" }
}

override_data {
  target = data.http.index_bg_wasm
  values = { response_body = "AGFzbQEAAAA=" }
}

override_data {
  target = data.http.sha256sums
  values = {
    response_body = <<-EOT
      9f085b1079ab38f776bbb3930dfd067a838ca3e0483aff8625f88837e8ed964c  index.js
      037e64cdc23d28f2d300b10174f8398968910e7520c8e68ad5eaa581f05a0137  index_bg.wasm.base64
    EOT
  }
}

variables {
  cloudflare_token_secret = { secret_store_id = "00000000000000000000000000000000", secret_name = "cf-oidc-exchange-cloudflare-token" }
  account_id              = "0123456789abcdef0123456789abcdef"
  hostname                = "cf-oidc-exchange.example.workers.dev"
  policy_file             = "tests/fixtures/policy.yaml"
}

run "secrets_store_binding" {
  command = plan


  assert {
    condition = anytrue([
      for b in cloudflare_worker_version.this.bindings :
      b.name == "CF_OIDC_EXCHANGE_API_CLOUDFLARE_TOKEN" && b.type == "secrets_store_secret" && b.secret_name == "cf-oidc-exchange-cloudflare-token"
    ])
    error_message = "the broker token should be a Secrets Store binding"
  }

  assert {
    condition     = length([for b in cloudflare_worker_version.this.bindings : b if b.type == "secret_text"]) == 0
    error_message = "no secret_text binding should be created"
  }
}

run "no_signing_key_by_default" {
  command = plan

  assert {
    condition     = length([for b in cloudflare_worker_version.this.bindings : b if b.name == "CF_OIDC_EXCHANGE_API_SIGNING_KEY"]) == 0
    error_message = "the signing key should only be bound when signing_key_secret is set"
  }
}

run "signing_key_binding" {
  command = plan

  variables {
    signing_key_secret = { secret_store_id = "00000000000000000000000000000000", secret_name = "cf-oidc-exchange-signing-key" }
  }

  assert {
    condition = anytrue([
      for b in cloudflare_worker_version.this.bindings :
      b.name == "CF_OIDC_EXCHANGE_API_SIGNING_KEY" && b.type == "secrets_store_secret" && b.secret_name == "cf-oidc-exchange-signing-key"
    ])
    error_message = "the signing key should be a Secrets Store binding"
  }
}

run "policy_is_templated" {
  command = plan

  assert {
    condition = anytrue([
      for b in cloudflare_worker_version.this.bindings :
      b.name == "CF_OIDC_EXCHANGE_API_POLICY" && b.type == "plain_text" && strcontains(b.text, "com.cloudflare.api.account.0123456789abcdef0123456789abcdef")
    ])
    error_message = "the policy should be a plain_text binding with account_id filled in"
  }
}

run "rejects_a_policy_over_5_kb" {
  command = plan

  variables {
    policy_file = "tests/fixtures/large-policy.yaml"
  }

  expect_failures = [cloudflare_worker_version.this]
}

run "workers_dev" {
  command = plan

  assert {
    condition     = length(cloudflare_workers_custom_domain.this) == 0 && cloudflare_worker.this.subdomain.enabled
    error_message = "a workers.dev deploy should have no custom domain"
  }

  assert {
    condition     = output.url == "https://cf-oidc-exchange.example.workers.dev"
    error_message = "url should be the workers.dev URL"
  }

  assert {
    condition     = jsondecode(local.policy_json).issuer == "https://cf-oidc-exchange.example.workers.dev" && jsondecode(local.policy_json).providers[0].audience == "https://cf-oidc-exchange.example.workers.dev"
    error_message = "the policy audience should be filled in with broker_url"
  }
}

run "custom_domain" {
  command = plan

  variables {
    hostname = "cf-oidc-exchange.example.com"
    zone_id  = "fedcba9876543210fedcba9876543210"
  }

  assert {
    condition     = length(cloudflare_workers_custom_domain.this) == 1 && !cloudflare_worker.this.subdomain.enabled
    error_message = "a custom domain deploy should disable workers.dev"
  }

  assert {
    condition     = output.url == "https://cf-oidc-exchange.example.com"
    error_message = "url should be the custom domain"
  }
}

run "workers_dev_follows_worker_name" {
  command = plan

  variables {
    worker_name = "auth"
    hostname    = "auth.example.workers.dev"
  }

  assert {
    condition     = output.url == "https://auth.example.workers.dev"
    error_message = "a workers.dev hostname matching worker_name should be accepted"
  }
}

run "rejects_a_workers_dev_name_mismatch" {
  command = plan

  variables {
    hostname = "auth.example.workers.dev"
  }

  expect_failures = [var.hostname]
}

run "rejects_a_url" {
  command = plan

  variables {
    hostname = "https://cf-oidc-exchange.example.workers.dev"
  }

  expect_failures = [var.hostname]
}

run "rejects_a_custom_domain_without_zone_id" {
  command = plan

  variables {
    hostname = "cf-oidc-exchange.example.com"
  }

  expect_failures = [var.zone_id]
}

run "rejects_zone_id_on_workers_dev" {
  command = plan

  variables {
    zone_id = "fedcba9876543210fedcba9876543210"
  }

  expect_failures = [var.zone_id]
}

run "uploads_the_release" {
  command = plan

  assert {
    condition     = cloudflare_worker_version.this.main_module == "index.js"
    error_message = "index.js should be the main module"
  }

  assert {
    condition = alltrue([
      for name, type in {
        "index.js"      = "application/javascript+module"
        "index_bg.wasm" = "application/wasm"
      } : anytrue([for m in cloudflare_worker_version.this.modules : m.name == name && m.content_type == type])
    ])
    error_message = "index.js and index_bg.wasm should be uploaded"
  }

  assert {
    condition     = anytrue([for m in cloudflare_worker_version.this.modules : m.name == "index_bg.wasm" && m.content_base64 == "AGFzbQEAAAA="])
    error_message = "the release's base64 wasm should be uploaded as the wasm module"
  }
}

run "pins_the_release" {
  command = plan

  variables {
    checksums_sha256 = "c153336c0d57f29adad2594f0d9203287fc5ba40a8649cfe54fb4120f09fa797"
  }
}

run "rejects_a_checksum_mismatch" {
  command = plan

  variables {
    checksums_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
  }

  expect_failures = [cloudflare_worker_version.this]
}

run "rejects_a_file_that_doesnt_match_sha256sums" {
  command = plan

  override_data {
    target = data.http.index_js
    values = { response_body = "export default { tampered: true };" }
  }

  expect_failures = [cloudflare_worker_version.this]
}

run "local_worker_dir" {
  command = plan

  variables {
    worker_dir = "tests/fixtures/worker"
  }

  assert {
    condition     = length(data.github_release.this) == 0 && length(data.http.index_js) == 0
    error_message = "a local worker_dir should skip the release download"
  }

  assert {
    condition     = anytrue([for m in cloudflare_worker_version.this.modules : m.name == "index_bg.wasm" && m.content_base64 == filebase64("tests/fixtures/worker/index_bg.wasm")])
    error_message = "the local wasm should be uploaded"
  }

  assert {
    condition     = output.release_tag == "local"
    error_message = "release_tag should say local"
  }
}

run "policy_vars" {
  command = plan

  variables {
    policy_file = "tests/fixtures/vars-policy.yaml"
    policy_vars = { owner_id = "100000001", repository_id = "200000002" }
  }

  assert {
    condition     = jsondecode(local.policy_json).profiles[0].claims[0].repository_id == "200000002" && jsondecode(local.policy_json).providers[0].claims[0].repository_owner_id == "100000001"
    error_message = "policy_vars should be filled into the policy"
  }
}

run "bucket_prefix_placeholders" {
  command = plan

  variables {
    policy_file = "tests/fixtures/buckets-policy.yaml"
  }

  # templatefile fills in $${…} but must leave the broker's {claim} placeholders alone.
  assert {
    condition     = jsondecode(local.policy_json).profiles[0].buckets[0].prefixes == ["github.com/{repository}/"]
    error_message = "{repository} should reach the broker unchanged"
  }

  assert {
    condition     = jsondecode(local.policy_json).profiles[1].buckets[0].prefixes == ["{repository_owner_id}/{repository_id}/"]
    error_message = "{repository_owner_id} and {repository_id} should reach the broker unchanged"
  }

  assert {
    condition     = jsondecode(local.policy_json).profiles[1].token.policies[0].resources["com.cloudflare.api.account.0123456789abcdef0123456789abcdef"] == "*"
    error_message = "$${account_id} should still be filled in next to buckets"
  }
}
