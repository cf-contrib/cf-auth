//! The policy's loading, guardrails, matching and bucket prefixes. All IDs are made up.

use cf_oidc_exchange_sdk::v1::Error;
use serde_json::{Value, json};

use super::*;

const ACCOUNT_ID: &str = "0123456789abcdef0123456789abcdef";
const ZONE_ID: &str = "fedcba9876543210fedcba9876543210";
const OWNER_ID: &str = "100000001";
const AUDIENCE: &str = "https://cf-oidc-exchange.example.com";
const CACHE: &str = "https://cf-nix-cache.example.com";
const GITHUB_ACTIONS: &str = "https://token.actions.githubusercontent.com";

/// A version 3 policy: one GitHub Actions provider, `github`, pinned to the test
/// org, and three profiles for it.
fn policy() -> Value {
    json!({
        "version": 3,
        "issuer": AUDIENCE,
        "providers": [{
            "name": "github",
            "issuer": GITHUB_ACTIONS,
            "audience": AUDIENCE,
            "claims": [{ "repository_owner_id": OWNER_ID }],
        }],
        "defaults": { "ttl": "15m", "max_ttl": "1h" },
        "profiles": [
            {
                "name": "infra-cloudflare",
                "provider": "github",
                "claims": [{ "repository_id": "200000002", "ref": "refs/heads/main", "environment": "prod" }],
                "ttl": "15m",
                "token": { "policies": [{
                    "effect": "allow",
                    "permissions": ["Zone Write", "DNS Write"],
                    "resources": { (format!("com.cloudflare.api.account.zone.{ZONE_ID}")): "*" },
                }]},
            },
            {
                "name": "workers-deploy",
                "provider": "github",
                "claims": [{ "repository": "example-org/*", "ref": "refs/heads/main", "environment": "prod" }],
                "token": { "policies": [{
                    "effect": "allow",
                    "permissions": ["Workers Scripts Write"],
                    "resources": { (format!("com.cloudflare.api.account.{ACCOUNT_ID}")): "*" },
                }]},
            },
            {
                "name": "service-dns",
                "provider": "github",
                "claims": [{ "job_workflow_ref": "example-org/workflows/.github/workflows/deploy.yml@refs/heads/main" }],
                "ttl": "5m",
                "token": { "policies": [{
                    "effect": "allow",
                    "permissions": ["DNS Write"],
                    "resources": { (format!("com.cloudflare.api.account.zone.{ZONE_ID}")): "*" },
                }]},
            },
        ],
    })
}

/// A GitLab provider, for tests about several providers.
fn gitlab() -> Value {
    json!({ "name": "gitlab", "issuer": "https://gitlab.com", "audience": AUDIENCE, "claims": [{ "namespace_id": "4000001" }] })
}

/// Sets the value at a JSON pointer, adding the key if it's not there. `null` removes it.
fn set(target: &mut Value, pointer: &str, value: Value) {
    let (parent, key) = pointer.rsplit_once('/').unwrap();
    let parent = target.pointer_mut(parent).unwrap();
    match parent {
        Value::Object(map) if value.is_null() => {
            map.remove(key);
        }
        Value::Object(map) => {
            map.insert(key.to_string(), value);
        }
        Value::Array(list) => list[key.parse::<usize>().unwrap()] = value,
        _ => panic!("{pointer} is not in an object or array"),
    }
}

fn push(target: &mut Value, pointer: &str, value: Value) {
    target
        .pointer_mut(pointer)
        .unwrap()
        .as_array_mut()
        .unwrap()
        .push(value);
}

/// `base` with `overrides` applied; a `null` override removes the claim.
fn with(base: Value, overrides: Value) -> Claims {
    let Value::Object(mut claims) = base else {
        unreachable!()
    };
    for (key, value) in overrides.as_object().unwrap() {
        if value.is_null() {
            claims.remove(key);
        } else {
            claims.insert(key.clone(), value.clone());
        }
    }
    claims
}

/// A GitHub Actions job's claims.
fn github_claims(overrides: Value) -> Claims {
    let base = json!({
        "iss": GITHUB_ACTIONS,
        "sub": "repo:example-org/api:environment:prod",
        "repository": "example-org/api",
        "repository_id": "200000003",
        "repository_owner": "example-org",
        "repository_owner_id": OWNER_ID,
        "ref": "refs/heads/main",
        "environment": "prod",
        "run_id": "1234567890",
    });
    with(base, overrides)
}

fn load(input: &Value) -> PolicyConfig {
    load_policy(input, None).unwrap_or_else(|err| panic!("{err}"))
}

/// Loads a policy and returns its issues, or none if it's valid.
fn issues(input: &Value) -> Vec<String> {
    load_policy(input, None)
        .err()
        .map(|err| err.issues)
        .unwrap_or_default()
}

/// The one issue a policy has, which must start with `at` and contain `says`.
#[track_caller]
fn assert_issue(input: &Value, at: &str, says: &str) {
    let found = issues(input);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].starts_with(at) && found[0].contains(says),
        "{found:?}"
    );
}

fn profile<'a>(policy: &'a PolicyConfig, name: &str) -> &'a ProfileConfig {
    policy.profiles.iter().find(|p| p.name == name).unwrap()
}

/// What a refusal says, if it was one.
fn denial<T>(result: Result<T, Error>) -> Option<String> {
    result.err().map(|err| err.message)
}

/// Selects a Cloudflare profile for a token from `provider`.
fn select<'a>(
    policy: &'a PolicyConfig,
    provider: &str,
    claims: &Claims,
    requested: Option<&str>,
) -> Result<&'a ProfileConfig, Error> {
    select_profile(
        policy,
        provider_of(policy, provider),
        claims,
        requested,
        CLOUDFLARE_AUDIENCE,
    )
}

fn provider_of<'a>(policy: &'a PolicyConfig, name: &str) -> &'a ProviderConfig {
    policy.providers.iter().find(|p| p.name == name).unwrap()
}

fn set_of(value: Value) -> ClaimSet {
    serde_json::from_value(value).unwrap()
}

mod parse_duration {
    use super::*;

    #[test]
    fn parses() {
        for (input, ms) in [
            ("30s", 30_000),
            ("15m", 900_000),
            ("1h", 3_600_000),
            ("1h30m", 5_400_000),
        ] {
            assert_eq!(parse_duration(input), Some(ms), "{input}");
        }
    }

    #[test]
    fn rejects() {
        for input in ["", "15", "m", "1d", "-5m", "1.5h", "15 m"] {
            assert_eq!(parse_duration(input), None, "{input:?}");
        }
    }
}

mod load_policy {
    use super::*;

    #[test]
    fn accepts_the_example_policy_and_applies_defaults() {
        let p = load(&Value::String(policy().to_string()));
        assert_eq!(p.issuer, AUDIENCE);
        assert_eq!(
            p.providers,
            vec![ProviderConfig {
                name: "github".into(),
                issuer: GITHUB_ACTIONS.into(),
                audience: AUDIENCE.into(),
                jwks_uri: None,
                claims: vec![set_of(json!({ "repository_owner_id": OWNER_ID }))],
            }]
        );
        let deploy = profile(&p, "workers-deploy");
        assert_eq!(deploy.provider, "github");
        assert_eq!(deploy.audience, CLOUDFLARE_AUDIENCE);
        assert_eq!(deploy.ttl, 15 * 60_000);
        assert_eq!(deploy.max_ttl, 60 * 60_000);
        assert_eq!(deploy.policies.as_ref().unwrap()[0].effect, Effect::Allow);
    }

    #[test]
    fn accepts_the_example_policy_file() {
        let example = include_str!("../../../../policy.example.json");
        load(&Value::String(example.into()));
    }

    #[test]
    fn lets_profiles_leave_the_provider_out_when_theres_only_one() {
        let mut p = policy();
        for i in 0..3 {
            set(&mut p, &format!("/profiles/{i}/provider"), Value::Null);
        }
        assert!(load(&p).profiles.iter().all(|r| r.provider == "github"));
    }

    #[test]
    fn refuses_older_versions_with_a_pointer_to_what_changed() {
        for version in [1, 2] {
            let found = issues(&json!({ "version": version, "providers": [], "profiles": [] }));
            assert_eq!(found.len(), 1);
            assert!(
                found[0].starts_with(&format!("version {version} is no longer supported")),
                "{found:?}"
            );
        }
        let mut p = policy();
        set(&mut p, "/version", json!(4));
        assert_eq!(issues(&p), ["version: must be 3"]);
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(issues(&Value::String("{".into()))[0].contains("not valid JSON"));
    }

    #[test]
    fn rejects_unknown_keys() {
        let mut p = policy();
        set(&mut p, "/extra", json!(true));
        assert_eq!(issues(&p), ["extra: unknown key"]);
        let mut p = policy();
        set(&mut p, "/profiles/1/token/ttl", json!("10m"));
        assert_eq!(issues(&p), ["profiles.1.token.ttl: unknown key"]);
    }

    mod providers {
        use super::*;

        #[test]
        fn rejects_duplicate_names_and_issuers() {
            let mut p = policy();
            let first = p["providers"][0].clone();
            push(&mut p, "/providers", first);
            assert_eq!(
                issues(&p),
                [
                    "providers.1 (github): duplicate provider name",
                    "providers.1 (github).issuer: another provider has the same issuer",
                ]
            );
        }

        #[test]
        fn requires_an_issuer_an_audience_and_claims() {
            for field in ["issuer", "audience", "claims"] {
                let mut p = policy();
                set(&mut p, &format!("/providers/0/{field}"), Value::Null);
                assert_eq!(
                    issues(&p),
                    [format!("providers.0.{field}: required")],
                    "{field}"
                );
            }
            let mut p = policy();
            set(&mut p, "/providers/0/audience", json!(""));
            assert_eq!(issues(&p), ["providers.0.audience: must not be empty"]);
        }

        #[test]
        fn one_requires_every_provider_to_be_pinned() {
            let mut p = policy();
            set(&mut p, "/providers/0/claims", json!([]));
            assert_eq!(
                issues(&p),
                ["providers.0.claims: must list at least one claim set"]
            );
            set(&mut p, "/providers/0/claims", json!([{}]));
            assert_issue(
                &p,
                "providers.0.claims.0",
                "a claim set must match at least one claim",
            );
        }

        #[test]
        fn takes_any_issuer_by_its_claims() {
            let mut p = policy();
            push(&mut p, "/providers", gitlab());
            let loaded = load(&p);
            assert_eq!(loaded.providers[1].issuer, "https://gitlab.com");
        }

        #[test]
        fn only_allows_plain_http_on_loopback() {
            for (issuer, ok) in [
                ("http://127.0.0.1:8788", true),
                ("http://localhost", true),
                ("http://[::1]:9000", true),
                ("https://issuer.example.com", true),
                ("http://issuer.example.com", false),
            ] {
                let mut p = policy();
                let mut local = gitlab();
                set(&mut local, "/issuer", json!(issuer));
                push(&mut p, "/providers", local);
                let refused = issues(&p).join(",").contains("must be an https:// URL");
                assert_eq!(refused, !ok, "{issuer}");
            }
            let mut p = policy();
            set(
                &mut p,
                "/providers/0/jwks_uri",
                json!("http://keys.example.com"),
            );
            assert_issue(&p, "providers.0.jwks_uri", "must be an https:// URL");
        }
    }

    mod claim_sets {
        use super::*;

        #[test]
        fn two_keeps_patterns_narrow_and_ids_exact() {
            let mut p = policy();
            set(&mut p, "/profiles/0/claims/0/repository_id", json!("2000*"));
            assert_issue(
                &p,
                "profiles.0.claims.0",
                "claim repository_id: ID claims must match exactly",
            );

            for pattern in ["*", "*/api", "example-org/*/api", "example-org/**"] {
                let mut p = policy();
                set(&mut p, "/profiles/1/claims/0/repository", json!(pattern));
                assert_issue(
                    &p,
                    "profiles.1.claims.0",
                    "claim repository: * may only end a pattern, after a prefix",
                );
            }
        }

        #[test]
        fn checks_provider_claim_sets_the_same_way() {
            let mut p = policy();
            set(
                &mut p,
                "/providers/0/claims/0/repository_owner_id",
                json!("1000*"),
            );
            assert_issue(&p, "providers.0.claims.0", "ID claims must match exactly");
        }

        #[test]
        fn takes_numbers_and_booleans_as_written() {
            let mut p = policy();
            set(
                &mut p,
                "/providers/0/claims/0/repository_owner_id",
                json!(100000001),
            );
            set(
                &mut p,
                "/profiles/1/claims/0/runner_environment_trusted",
                json!(true),
            );
            let loaded = load(&p);
            let deploy = profile(&loaded, "workers-deploy");
            assert!(loaded.providers[0].takes(&github_claims(json!({}))));
            assert!(deploy.matches(&github_claims(
                json!({ "runner_environment_trusted": true })
            )));
            assert!(!deploy.matches(&github_claims(
                json!({ "runner_environment_trusted": false })
            )));
        }

        #[test]
        fn rejects_values_that_arent_patterns() {
            for value in [json!(""), json!(-1), json!(1.5), json!(["a"])] {
                let mut p = policy();
                set(&mut p, "/profiles/0/claims/0/ref", value.clone());
                assert_issue(
                    &p,
                    "profiles.0.claims.0",
                    "claim ref must be a non-empty string, a number or a boolean",
                );
            }
        }

        #[test]
        fn requires_profiles_to_list_claim_sets() {
            let mut p = policy();
            set(&mut p, "/profiles/0/claims", json!([]));
            assert_eq!(
                issues(&p),
                ["profiles.0.claims: must list at least one claim set"]
            );
            set(&mut p, "/profiles/0/claims", Value::Null);
            assert_eq!(issues(&p), ["profiles.0.claims: required"]);
        }
    }

    mod guardrails {
        use super::*;

        #[test]
        fn three_rejects_granting_token_management() {
            for permission in [
                "API Tokens Write",
                "Account API Tokens Write",
                "API Tokens Read",
            ] {
                let mut p = policy();
                push(
                    &mut p,
                    "/profiles/1/token/policies/0/permissions",
                    json!(permission),
                );
                assert!(
                    issues(&p).join(",").contains("not grantable"),
                    "{permission}"
                );
            }
        }

        #[test]
        fn three_allows_denying_token_management() {
            let mut p = policy();
            let deny = json!({
                "effect": "deny",
                "permissions": ["API Tokens Write"],
                "resources": { (format!("com.cloudflare.api.account.{ACCOUNT_ID}")): "*" },
            });
            push(&mut p, "/profiles/1/token/policies", deny);
            assert!(issues(&p).is_empty());
        }

        #[test]
        fn four_caps_ttls() {
            let mut p = policy();
            set(&mut p, "/profiles/1/max_ttl", json!("25h"));
            assert!(
                issues(&p)
                    .join(",")
                    .contains("max_ttl: must be at most 24h")
            );
            let mut p = policy();
            set(&mut p, "/defaults", json!({ "ttl": "2h", "max_ttl": "1h" }));
            assert!(
                issues(&p)
                    .join(",")
                    .contains("defaults.ttl: must not exceed max_ttl")
            );
            let mut p = policy();
            set(&mut p, "/profiles/1/ttl", json!("2h"));
            assert!(
                issues(&p)
                    .join(",")
                    .contains("ttl: must not exceed max_ttl")
            );
            let mut p = policy();
            set(&mut p, "/profiles/1/ttl", json!("forever"));
            assert_eq!(
                issues(&p),
                ["profiles.1.ttl: must be a duration such as 15m or 1h"]
            );
        }

        #[test]
        fn requires_the_brokers_issuer_to_be_a_bare_origin() {
            let mut p = policy();
            set(&mut p, "/issuer", json!(format!("{AUDIENCE}/")));
            assert!(
                issues(&p)
                    .join(",")
                    .contains("issuer: must be a bare origin")
            );
        }
    }

    #[test]
    fn rejects_duplicate_profile_names() {
        let mut p = policy();
        let deploy = p["profiles"][1].clone();
        push(&mut p, "/profiles", deploy);
        assert!(issues(&p).join(",").contains("duplicate profile name"));
    }

    #[test]
    fn requires_a_profiles_provider_when_there_are_several() {
        let mut p = policy();
        push(&mut p, "/providers", gitlab());
        set(&mut p, "/profiles/0/provider", Value::Null);
        assert_eq!(
            issues(&p),
            [
                "profiles.0 (infra-cloudflare).provider: required when the policy has several providers"
            ]
        );
    }

    #[test]
    fn rejects_a_provider_that_doesnt_exist() {
        let mut p = policy();
        set(&mut p, "/profiles/0/provider", json!("gitlab"));
        assert_eq!(
            issues(&p),
            ["profiles.0 (infra-cloudflare).provider: no provider named gitlab"]
        );
    }

    mod resources {
        use super::*;

        fn with_resources(resources: Value) -> Value {
            let mut p = policy();
            set(&mut p, "/profiles/1/token/policies/0/resources", resources);
            p
        }

        #[test]
        fn accepts_cloudflares_flat_and_nested_forms() {
            let flat = json!({ (format!("com.cloudflare.api.account.zone.{ZONE_ID}")): "*" });
            assert!(issues(&with_resources(flat)).is_empty());
            let nested = json!({
                (format!("com.cloudflare.api.account.{ACCOUNT_ID}")): { "com.cloudflare.api.account.zone.*": "*" },
            });
            assert!(issues(&with_resources(nested)).is_empty());
        }

        #[test]
        fn rejects_bad_resources() {
            assert!(
                issues(&with_resources(json!({})))
                    .join(",")
                    .contains("must name at least one resource")
            );
            assert!(
                issues(&with_resources(json!({ "example.com": "*" })))
                    .join(",")
                    .contains("must be a Cloudflare resource name")
            );
            let mixed = json!({
                (format!("com.cloudflare.api.account.{ACCOUNT_ID}")): { "com.cloudflare.api.account.zone.*": "*" },
                (format!("com.cloudflare.api.account.zone.{ZONE_ID}")): "*",
            });
            assert!(
                issues(&with_resources(mixed))
                    .join(",")
                    .contains("must be all")
            );
        }

        #[test]
        fn rejects_another_accounts_id_when_the_brokers_account_is_known() {
            let other = with_resources(
                json!({ "com.cloudflare.api.account.ffffffffffffffffffffffffffffffff": "*" }),
            );
            assert!(issues(&other).is_empty());
            let err = load_policy(&other, Some(ACCOUNT_ID)).unwrap_err();
            assert!(err.issues.join(",").contains("is not the broker's account"));
            assert!(load_policy(&policy(), Some(ACCOUNT_ID)).is_ok());
        }
    }

    #[test]
    fn reports_every_problem_at_once() {
        let mut p = policy();
        set(
            &mut p,
            "/defaults",
            json!({ "ttl": "2h", "max_ttl": "30h" }),
        );
        set(&mut p, "/profiles/0/provider", json!("gitlab"));
        assert!(issues(&p).len() >= 3);
    }
}

mod matching {
    use super::*;

    #[test]
    fn ands_every_claim_of_a_set() {
        let loaded = load(&policy());
        let deploy = profile(&loaded, "workers-deploy");
        assert!(deploy.matches(&github_claims(json!({}))));
        assert!(!deploy.matches(&github_claims(json!({ "environment": "staging" }))));
        assert!(!deploy.matches(&github_claims(json!({ "environment": null }))));
    }

    #[test]
    fn ors_the_sets() {
        let mut p = policy();
        push(
            &mut p,
            "/profiles/1/claims",
            json!({ "repository": "example-org/*", "ref": "refs/heads/release/*", "environment": "prod" }),
        );
        let loaded = load(&p);
        let deploy = profile(&loaded, "workers-deploy");
        assert!(deploy.matches(&github_claims(json!({ "ref": "refs/heads/main" }))));
        assert!(deploy.matches(&github_claims(json!({ "ref": "refs/heads/release/2026" }))));
        assert!(!deploy.matches(&github_claims(json!({ "ref": "refs/heads/dev" }))));
    }

    #[test]
    fn holds_every_token_to_its_providers_claim_sets() {
        let loaded = load(&policy());
        let outsider = github_claims(json!({ "repository_owner_id": "999" }));
        assert_eq!(
            denial(select(&loaded, "github", &outsider, None)).as_deref(),
            Some("the token matches none of provider github's claim sets")
        );
    }

    #[test]
    fn selects_the_single_matching_profile() {
        let loaded = load(&policy());
        let claims = github_claims(json!({}));
        assert_eq!(
            select(&loaded, "github", &claims, None).unwrap().name,
            "workers-deploy"
        );
    }

    #[test]
    fn denies_when_nothing_matches() {
        let loaded = load(&policy());
        let claims = github_claims(json!({ "ref": "refs/heads/dev" }));
        assert_eq!(
            denial(select(&loaded, "github", &claims, None)).as_deref(),
            Some("no profile matches the token")
        );
    }

    #[test]
    fn denies_when_several_profiles_match_and_none_is_named() {
        let loaded = load(&policy());
        let claims = github_claims(
            json!({ "repository": "example-org/infra", "repository_id": "200000002" }),
        );
        assert_eq!(
            denial(select(&loaded, "github", &claims, None)).as_deref(),
            Some("profiles infra-cloudflare, workers-deploy all match the token: name one")
        );
        let named = select(&loaded, "github", &claims, Some("infra-cloudflare")).unwrap();
        assert_eq!(named.name, "infra-cloudflare");
    }

    #[test]
    fn denies_a_named_profile_that_doesnt_match() {
        let loaded = load(&policy());
        let claims = github_claims(json!({}));
        assert_eq!(
            denial(select(&loaded, "github", &claims, Some("infra-cloudflare"))).as_deref(),
            Some("profile infra-cloudflare doesn't match the token")
        );
        assert_eq!(
            denial(select(&loaded, "github", &claims, Some("nope"))).as_deref(),
            Some("unknown profile nope")
        );
    }

    #[test]
    fn never_gives_one_providers_token_anothers_profile() {
        let mut p = policy();
        push(&mut p, "/providers", gitlab());
        let token = p["profiles"][1]["token"].clone();
        push(
            &mut p,
            "/profiles",
            json!({ "name": "gitlab-deploy", "provider": "gitlab", "claims": [{ "project_path": "group/*" }], "token": token }),
        );
        let loaded = load(&p);
        let job = github_claims(json!({}));
        assert_eq!(
            denial(select(&loaded, "github", &job, Some("gitlab-deploy"))).as_deref(),
            Some("profile gitlab-deploy isn't for provider github")
        );
        let gitlab_job = with(
            json!({ "namespace_id": "4000001", "project_path": "group/app" }),
            json!({}),
        );
        assert_eq!(
            select(&loaded, "gitlab", &gitlab_job, None).unwrap().name,
            "gitlab-deploy"
        );
    }

    #[test]
    fn enables_profiles_unless_they_say_otherwise() {
        assert!(load(&policy()).profiles.iter().all(|p| p.enabled));
        let mut p = policy();
        set(&mut p, "/profiles/1/enabled", json!("no"));
        assert_issue(&p, "profiles.1.enabled: ", "expected a boolean");
    }

    #[test]
    fn never_matches_a_disabled_profile_even_by_name() {
        let mut p = policy();
        set(&mut p, "/profiles/1/enabled", json!(false));
        let disabled = load(&p);
        let claims = github_claims(json!({}));
        assert_eq!(
            denial(select(&disabled, "github", &claims, None)).as_deref(),
            Some("no profile matches the token")
        );
        assert_eq!(
            denial(select(&disabled, "github", &claims, Some("workers-deploy"))).as_deref(),
            Some("profile workers-deploy is disabled")
        );
    }

    #[test]
    fn clamps_ttl_to_max_ttl_and_rejects_nonsense() {
        let loaded = load(&policy());
        let deploy = profile(&loaded, "workers-deploy");
        assert_eq!(clamp_ttl(None, deploy).ok(), Some(15 * 60_000));
        assert_eq!(clamp_ttl(Some("5m"), deploy).ok(), Some(5 * 60_000));
        assert_eq!(clamp_ttl(Some("10h"), deploy).ok(), Some(60 * 60_000));
        for ttl in ["forever", "30s"] {
            assert_eq!(
                denial(clamp_ttl(Some(ttl), deploy)),
                Some(format!("ttl {ttl} isn't a duration of at least 1m"))
            );
        }
    }
}

mod service_audiences {
    use super::*;

    /// The test policy plus a profile issuing the broker's own token for the cache.
    fn with_service(extra: Value) -> Value {
        let mut p = policy();
        let mut service = json!({
            "name": "nix-push",
            "provider": "github",
            "audience": CACHE,
            "claims": [{ "ref": "refs/heads/main" }],
        });
        for (key, value) in extra.as_object().unwrap() {
            set(&mut service, &format!("/{key}"), value.clone());
        }
        push(&mut p, "/profiles", service);
        p
    }

    #[test]
    fn gives_every_other_profile_the_cloudflare_audience() {
        let loaded = load(&with_service(json!({})));
        assert_eq!(profile(&loaded, "nix-push").audience, CACHE);
        let cloudflare = loaded
            .profiles
            .iter()
            .filter(|p| p.audience == CLOUDFLARE_AUDIENCE);
        assert_eq!(cloudflare.count(), loaded.profiles.len() - 1);
    }

    #[test]
    fn five_keeps_audiences_apart() {
        let buckets =
            json!({ "buckets": [{ "name": "org-artifacts", "permission": "object-read-only" }] });
        assert_eq!(
            issues(&with_service(buckets)),
            [format!(
                "profiles.3 (nix-push): a profile for {CACHE} can't have a token or buckets"
            )]
        );
        assert_eq!(
            issues(&with_service(json!({ "audience": AUDIENCE }))),
            ["profiles.3 (nix-push).audience: must be another service, not the broker itself"]
        );
        let path = with_service(json!({ "audience": format!("{CACHE}/upload") }));
        assert!(
            issues(&path)
                .join(",")
                .contains("profiles.3.audience: must be a bare origin")
        );
    }

    #[test]
    fn only_selects_profiles_for_the_requested_audience() {
        let loaded = load(&with_service(json!({})));
        let github = provider_of(&loaded, "github");
        let claims = github_claims(json!({}));
        assert_eq!(
            select(&loaded, "github", &claims, None).unwrap().name,
            "workers-deploy"
        );
        assert_eq!(
            select_profile(&loaded, github, &claims, None, CACHE)
                .unwrap()
                .name,
            "nix-push"
        );
        assert_eq!(
            denial(select_profile(
                &loaded,
                github,
                &claims,
                Some("workers-deploy"),
                CACHE
            )),
            Some(format!("profile workers-deploy isn't for {CACHE}"))
        );
    }
}

mod buckets {
    use super::*;

    /// workers-deploy with one bucket, plus profile-level fields such as ttl, and
    /// without its token unless `token` is true.
    fn with_bucket(bucket: Value, profile: Value, token: bool) -> Value {
        let mut p = policy();
        if !token {
            set(&mut p, "/profiles/1/token", Value::Null);
        }
        for (key, value) in profile.as_object().unwrap() {
            set(&mut p, &format!("/profiles/1/{key}"), value.clone());
        }
        let mut full = json!({ "name": "org-terraform-state", "permission": "object-read-write" });
        for (key, value) in bucket.as_object().unwrap() {
            set(&mut full, &format!("/{key}"), value.clone());
        }
        set(&mut p, "/profiles/1/buckets", json!([full]));
        p
    }

    fn bucket(prefixes: Value) -> Value {
        with_bucket(json!({ "prefixes": prefixes }), json!({}), false)
    }

    fn loaded(p: &Value) -> ProfileConfig {
        load(p).profiles[1].clone()
    }

    #[test]
    fn accepts_a_profile_with_only_buckets_using_the_default_ttls() {
        let profile = loaded(&bucket(json!(["github.com/{repository}/"])));
        assert_eq!(profile.policies, None);
        assert_eq!(
            profile.buckets,
            Some(vec![Bucket {
                name: "org-terraform-state".into(),
                permission: BucketPermission::ObjectReadWrite,
                prefixes: vec!["github.com/{repository}/".into()],
            }])
        );
        assert_eq!((profile.ttl, profile.max_ttl), (15 * 60_000, 60 * 60_000));
    }

    #[test]
    fn takes_ttl_and_max_ttl_from_the_profile_within_r2s_range() {
        let profile = loaded(&with_bucket(
            json!({}),
            json!({ "ttl": "5m", "max_ttl": "10m" }),
            false,
        ));
        assert_eq!((profile.ttl, profile.max_ttl), (5 * 60_000, 10 * 60_000));
        let p = with_bucket(json!({}), json!({ "ttl": "20m", "max_ttl": "10m" }), false);
        assert!(
            issues(&p)
                .join(",")
                .contains("(workers-deploy).ttl: must not exceed max_ttl")
        );
    }

    #[test]
    fn accepts_a_token_and_buckets_and_requires_one_of_them() {
        let profile = loaded(&with_bucket(json!({}), json!({}), true));
        assert_eq!(profile.policies.map(|p| p.len()), Some(1));
        let mut p = policy();
        set(&mut p, "/profiles/1/token", Value::Null);
        assert!(
            issues(&p)
                .join(",")
                .contains("must have a token, buckets or both")
        );
    }

    #[test]
    fn accepts_several_buckets_each_once() {
        let mut p = with_bucket(json!({}), json!({}), false);
        push(
            &mut p,
            "/profiles/1/buckets",
            json!({ "name": "org-artifacts", "permission": "object-read-only", "prefixes": ["{repository_id}/"] }),
        );
        let names: Vec<String> = loaded(&p)
            .buckets
            .unwrap()
            .into_iter()
            .map(|b| b.name)
            .collect();
        assert_eq!(names, ["org-terraform-state", "org-artifacts"]);

        push(
            &mut p,
            "/profiles/1/buckets",
            json!({ "name": "org-terraform-state", "permission": "object-read-only" }),
        );
        assert_eq!(
            issues(&p),
            ["profiles.1 (workers-deploy).buckets.2.name: duplicate bucket org-terraform-state"]
        );
        set(&mut p, "/profiles/1/buckets", json!([]));
        assert!(issues(&p).join(",").contains("buckets: "));
    }

    #[test]
    fn rejects_bad_bucket_names_and_permissions() {
        let long = "x".repeat(64);
        for name in [
            "ab",
            "Org-State",
            "org_state",
            "-org-state",
            "org-state-",
            long.as_str(),
        ] {
            let p = with_bucket(json!({ "name": name }), json!({}), false);
            assert!(
                issues(&p)
                    .join(",")
                    .contains("buckets.0.name: must be a valid R2 bucket name"),
                "{name}"
            );
        }
        for permission in ["admin-read-write", "admin-read-only", "read-write"] {
            let p = with_bucket(json!({ "permission": permission }), json!({}), false);
            assert!(
                issues(&p).join(",").contains(
                    "buckets.0.permission: must be object-read-write or object-read-only"
                ),
                "{permission}"
            );
        }
    }

    #[test]
    fn accepts_prefixes_from_any_claim() {
        for prefix in [
            "github.com/{repository}/",
            "{repository_owner_id}/{repository_id}/",
            "gitlab.com/{namespace_id}/{project_id}/",
            "{project_path}/state/",
            "shared/",
        ] {
            assert!(issues(&bucket(json!([prefix]))).is_empty(), "{prefix}");
        }
    }

    #[test]
    fn rejects_bad_prefixes() {
        for (prefix, message) in [
            ("github.com/{repository}", "must end with /"),
            ("/github.com/{repository}/", "must not start with /"),
            ("github.com/*/", "must not contain *"),
            ("github.com/../{repository}/", "must not contain .."),
            ("github.com//{repository}/", "empty or . path segments"),
            ("./{repository}/", "empty or . path segments"),
            ("", "must end with /"),
            ("github.com/${repository}/", "not ${claim}"),
            ("github.com/{}/", "placeholder {} must name a claim"),
            (
                "github.com/{repo-name}/",
                "placeholder {repo-name} must name a claim",
            ),
            ("github.com/{repository/", "unmatched"),
            ("github.com/repository}/", "unmatched"),
            ("state-{repository_id}/", "whole path segment"),
            ("{repository_owner}{repository_id}/", "whole path segment"),
            ("github.com\t/{repository}/", "control characters"),
        ] {
            let found = issues(&bucket(json!([prefix])));
            assert_eq!(found.len(), 1, "{prefix:?}: {found:?}");
            assert!(
                found[0].starts_with("profiles.1 (workers-deploy).buckets.0.prefixes.0: "),
                "{prefix:?}: {found:?}"
            );
            assert!(found[0].contains(message), "{prefix:?}: {found:?}");
        }
    }

    mod r2_prefixes {
        use super::*;

        fn fill(prefixes: &[&str], claims: &Claims) -> Result<Vec<String>, Error> {
            let bucket = Bucket {
                name: "org-terraform-state".into(),
                permission: BucketPermission::ObjectReadWrite,
                prefixes: prefixes.iter().map(|p| p.to_string()).collect(),
            };
            r2_prefixes(&bucket, claims)
        }

        #[test]
        fn fills_placeholders_from_the_claims() {
            let templates = [
                "github.com/{repository}/",
                "{repository_owner_id}/{repository_id}/",
                "{repository_owner}/",
            ];
            assert_eq!(
                fill(&templates, &github_claims(json!({}))).unwrap(),
                [
                    "github.com/example-org/api/".to_string(),
                    format!("{OWNER_ID}/200000003/"),
                    "example-org/".to_string(),
                ]
            );
            assert!(fill(&[], &github_claims(json!({}))).unwrap().is_empty());
        }

        #[test]
        fn takes_numbers_and_any_issuers_claims() {
            let gitlab = with(
                json!({ "namespace_id": 4000001, "project_path": "group/sub/app" }),
                json!({}),
            );
            assert_eq!(
                fill(&["gitlab.com/{namespace_id}/", "{project_path}/"], &gitlab).unwrap(),
                ["gitlab.com/4000001/", "group/sub/app/"]
            );
        }

        #[test]
        fn keeps_a_repo_whose_name_starts_with_anothers_out_of_it() {
            let template = ["github.com/{repository}/"];
            let site = &fill(
                &template,
                &github_claims(json!({ "repository": "example-org/site" })),
            )
            .unwrap()[0];
            let old = &fill(
                &template,
                &github_claims(json!({ "repository": "example-org/site-old" })),
            )
            .unwrap()[0];
            assert!(!old.starts_with(site.as_str()));
        }

        /// With several placeholders, one value spanning segments could make two
        /// callers' prefixes the same: a="x/y", b="z" and a="x", b="y/z".
        #[test]
        fn spans_segments_only_with_one_placeholder() {
            let claims = github_claims(json!({}));
            assert!(fill(&["{repository_owner}/{repository}/"], &claims).is_err());
            assert!(fill(&["{repository}/"], &claims).is_ok());
        }

        #[test]
        fn refuses_unusable_claims() {
            for (case, repository) in [
                ("missing", Value::Null),
                ("empty", json!("")),
                ("a boolean", json!(true)),
                ("a list", json!(["example-org/api"])),
                ("a leading slash", json!("/example-org/api")),
                ("a trailing slash", json!("example-org/api/")),
                ("..", json!("example-org/..")),
                (". as a segment", json!("example-org/.")),
                ("a space", json!("example-org/my api")),
                ("a percent escape", json!("example-org/%2e%2e")),
                ("a backslash", json!("example-org\\api")),
                ("a non-ASCII character", json!("example-org/\u{0430}pi")),
                ("a newline", json!("example-org/api\n")),
                ("a *", json!("example-org/*")),
            ] {
                let claims = github_claims(json!({ "repository": repository }));
                let refused =
                    denial(fill(&["github.com/{repository}/"], &claims)).unwrap_or_default();
                assert!(
                    refused.starts_with("bucket org-terraform-state: "),
                    "{case}: {refused}"
                );
            }
        }
    }
}
