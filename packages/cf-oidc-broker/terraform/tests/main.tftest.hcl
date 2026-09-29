# Plans the module with mocked providers: no credentials or network needed.
# Covers the broker token binding, URL modes, local artifacts, the policy template and
# the policy size limit.
mock_provider "cloudflare" {}
mock_provider "github" {}
mock_provider "http" {}

override_data {
  target = data.github_release.cf_auth
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
  broker_token_secret = { store_id = "00000000000000000000000000000000", secret_name = "cf-auth-broker-token" }
  account_id          = "0123456789abcdef0123456789abcdef"
  zone_id             = "fedcba9876543210fedcba9876543210"
  hostname            = "cf-auth.example.com"
  policy_file         = "tests/fixtures/policy.yaml"
}

run "secrets_store_binding" {
  command = plan


  assert {
    condition = anytrue([
      for b in cloudflare_worker_version.cf_auth.bindings :
      b.name == "CF_AUTH_BROKER_TOKEN" && b.type == "secrets_store_secret" && b.secret_name == "cf-auth-broker-token"
    ])
    error_message = "the broker token should be a Secrets Store binding"
  }

  assert {
    condition     = length([for b in cloudflare_worker_version.cf_auth.bindings : b if b.type == "secret_text"]) == 0
    error_message = "no secret_text binding should be created"
  }
}

run "policy_is_templated" {
  command = plan


  assert {
    condition = anytrue([
      for b in cloudflare_worker_version.cf_auth.bindings :
      b.name == "CF_AUTH_BROKER_POLICY" && strcontains(b.text, "com.cloudflare.api.account.0123456789abcdef0123456789abcdef")
    ])
    error_message = "the policy should have account_id filled in"
  }
}

run "rejects_an_oversized_policy" {
  command = plan

  variables {
    policy_file = "tests/fixtures/large-policy.yaml"
  }

  expect_failures = [cloudflare_worker_version.cf_auth]
}

run "sample_policy_fits" {
  command = plan


  assert {
    condition     = length(local.policy_json) < local.policy_max_length
    error_message = "the sample policy should fit in one binding"
  }
}

run "custom_domain" {
  command = plan


  assert {
    condition     = length(cloudflare_workers_custom_domain.cf_auth) == 1 && !cloudflare_worker.cf_auth.subdomain.enabled
    error_message = "a custom domain deploy should disable workers.dev"
  }

  assert {
    condition     = output.broker_url == "https://cf-auth.example.com"
    error_message = "broker_url should be the custom domain"
  }
}

run "workers_dev" {
  command = plan

  variables {
    hostname              = null
    zone_id               = null
    workers_dev_subdomain = "example"
  }

  assert {
    condition     = length(cloudflare_workers_custom_domain.cf_auth) == 0 && cloudflare_worker.cf_auth.subdomain.enabled
    error_message = "a workers.dev deploy should have no custom domain"
  }

  assert {
    condition     = output.broker_url == "https://cf-auth.example.workers.dev"
    error_message = "broker_url should be the workers.dev URL"
  }

  assert {
    condition     = jsondecode(local.policy_json).github.audience == "https://cf-auth.example.workers.dev"
    error_message = "the policy audience should be filled in with broker_url"
  }
}

run "rejects_both_url_modes" {
  command = plan

  variables {
    workers_dev_subdomain = "example"
  }

  expect_failures = [cloudflare_worker_version.cf_auth]
}

run "local_broker_file" {
  command = plan

  variables {
    broker_file = "tests/fixtures/broker.js"
  }

  assert {
    condition     = length(data.github_release.cf_auth) == 0 && length(data.http.broker_js) == 0
    error_message = "a local broker_file should skip the release download"
  }

  assert {
    condition     = anytrue([for m in cloudflare_worker_version.cf_auth.modules : m.content_base64 == filebase64("tests/fixtures/broker.js")])
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

  expect_failures = [cloudflare_worker_version.cf_auth]
}

run "policy_vars" {
  command = plan

  variables {
    policy_file = "tests/fixtures/vars-policy.yaml"
    policy_vars = { owner_id = "100000001", repository_id = "200000002" }
  }

  assert {
    condition     = jsondecode(local.policy_json).rules[0].match.repository_id == "200000002" && jsondecode(local.policy_json).github.owner_id == "100000001"
    error_message = "policy_vars should be filled into the policy"
  }
}
