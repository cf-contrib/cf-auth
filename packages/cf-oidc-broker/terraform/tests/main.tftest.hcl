# Plans the module with mocked providers: no credentials or network needed.
# Covers the broker token binding, URL modes, local artifacts, the policy template,
# bucket prefix placeholders and the policy module.
mock_provider "cloudflare" {}
mock_provider "github" {}
mock_provider "http" {}

override_data {
  target = data.github_release.this
  values = {
    assets = [{
      name                 = "broker.js"
      browser_download_url = "https://example.com/broker.js"
      content_type         = "application/javascript"
      created_at           = "2026-09-29T00:00:00Z"
      id                   = 1
      label                = ""
      node_id              = "RA_test"
      size                 = 18
      updated_at           = "2026-09-29T00:00:00Z"
      url                  = "https://api.github.com/repos/cf-contrib/cf-oidc-auth/releases/assets/1"
    }]
  }
}

override_data {
  target = data.http.broker_js
  values = { response_body = "export default {};" }
}

variables {
  broker_token_secret = { secret_store_id = "00000000000000000000000000000000", secret_name = "cf-auth-broker-token" }
  account_id          = "0123456789abcdef0123456789abcdef"
  hostname            = "cf-auth.example.workers.dev"
  policy_file         = "tests/fixtures/policy.yaml"
}

run "secrets_store_binding" {
  command = plan


  assert {
    condition = anytrue([
      for b in cloudflare_worker_version.this.bindings :
      b.name == "CF_OIDC_BROKER_TOKEN" && b.type == "secrets_store_secret" && b.secret_name == "cf-auth-broker-token"
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
    condition     = length([for b in cloudflare_worker_version.this.bindings : b if b.name == "CF_OIDC_BROKER_SIGNING_KEY"]) == 0
    error_message = "the signing key should only be bound when signing_key_secret is set"
  }
}

run "signing_key_binding" {
  command = plan

  variables {
    signing_key_secret = { secret_store_id = "00000000000000000000000000000000", secret_name = "cf-auth-signing-key" }
  }

  assert {
    condition = anytrue([
      for b in cloudflare_worker_version.this.bindings :
      b.name == "CF_OIDC_BROKER_SIGNING_KEY" && b.type == "secrets_store_secret" && b.secret_name == "cf-auth-signing-key"
    ])
    error_message = "the signing key should be a Secrets Store binding"
  }
}

run "policy_is_templated" {
  command = plan


  assert {
    condition = anytrue([
      for m in cloudflare_worker_version.this.modules :
      m.name == "policy.json" && m.content_type == "text/plain" && strcontains(base64decode(m.content_base64), "com.cloudflare.api.account.0123456789abcdef0123456789abcdef")
    ])
    error_message = "the policy should be a policy.json text module with account_id filled in"
  }

  assert {
    condition     = length([for b in cloudflare_worker_version.this.bindings : b if b.name == "CF_AUTH_BROKER_POLICY"]) == 0
    error_message = "the policy should not be a binding"
  }
}

run "accepts_a_large_policy" {
  command = plan

  variables {
    policy_file = "tests/fixtures/large-policy.yaml"
  }

  assert {
    condition     = length(local.policy_json) > 5000
    error_message = "the fixture should be over the old 5 KB binding limit"
  }
}

run "workers_dev" {
  command = plan

  assert {
    condition     = length(cloudflare_workers_custom_domain.this) == 0 && cloudflare_worker.this.subdomain.enabled
    error_message = "a workers.dev deploy should have no custom domain"
  }

  assert {
    condition     = output.url == "https://cf-auth.example.workers.dev"
    error_message = "url should be the workers.dev URL"
  }

  assert {
    condition     = jsondecode(local.policy_json).github.audience == "https://cf-auth.example.workers.dev"
    error_message = "the policy audience should be filled in with broker_url"
  }
}

run "custom_domain" {
  command = plan

  variables {
    hostname = "cf-auth.example.com"
    zone_id  = "fedcba9876543210fedcba9876543210"
  }

  assert {
    condition     = length(cloudflare_workers_custom_domain.this) == 1 && !cloudflare_worker.this.subdomain.enabled
    error_message = "a custom domain deploy should disable workers.dev"
  }

  assert {
    condition     = output.url == "https://cf-auth.example.com"
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
    hostname = "https://cf-auth.example.workers.dev"
  }

  expect_failures = [var.hostname]
}

run "rejects_a_custom_domain_without_zone_id" {
  command = plan

  variables {
    hostname = "cf-auth.example.com"
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

run "local_broker_file" {
  command = plan

  variables {
    broker_file = "tests/fixtures/broker.js"
  }

  assert {
    condition     = length(data.github_release.this) == 0 && length(data.http.broker_js) == 0
    error_message = "a local broker_file should skip the release download"
  }

  assert {
    condition     = anytrue([for m in cloudflare_worker_version.this.modules : m.content_base64 == filebase64("tests/fixtures/broker.js")])
    error_message = "the local broker_file should be uploaded"
  }

  assert {
    condition     = output.release_tag == "local"
    error_message = "release_tag should say local"
  }
}

run "rejects_a_checksum_mismatch" {
  command = plan

  variables {
    broker_file   = "tests/fixtures/broker.js"
    broker_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
  }

  expect_failures = [cloudflare_worker_version.this]
}

run "policy_vars" {
  command = plan

  variables {
    policy_file = "tests/fixtures/vars-policy.yaml"
    policy_vars = { owner_id = "100000001", repository_id = "200000002" }
  }

  assert {
    condition     = jsondecode(local.policy_json).profiles[0].match.repository_id == "200000002" && jsondecode(local.policy_json).github.owner_id == "100000001"
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
