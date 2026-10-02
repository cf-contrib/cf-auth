//! Ported from the TypeScript broker's `test/policy.test.ts`. All IDs are made up.

use cf_oidc_exchange_sdk::v1::Error;
use serde_json::{Value, json};

use super::{
    matching::{glob, matches},
    *,
};

const ACCOUNT_ID: &str = "0123456789abcdef0123456789abcdef";
const ZONE_ID: &str = "fedcba9876543210fedcba9876543210";
const OWNER_ID: &str = "100000001";
const USER_ID: &str = "300000004";
const TEAM_ID: &str = "400000005";
const AUDIENCE: &str = "https://cf-oidc-exchange.example.com";
const CACHE: &str = "https://cf-nix-cache.example.com";

/// A version 2 policy: one GitHub Actions provider, `github`, and three profiles for it.
fn policy() -> Value {
    json!({
        "version": 2,
        "issuer": AUDIENCE,
        "providers": [{
            "name": "github",
            "issuer": GITHUB_ACTIONS_ISSUER,
            "audience": AUDIENCE,
            "claims": { "repository_owner_id": OWNER_ID },
        }],
        "defaults": { "ttl": "15m", "max_ttl": "1h" },
        "profiles": [
            {
                "name": "infra-cloudflare",
                "provider": "github",
                "claims": { "repository_id": "200000002", "ref": "refs/heads/main", "environment": "prod" },
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
                "claims": { "repository": "example-org/*", "ref": "refs/heads/main", "environment": "prod" },
                "token": { "policies": [{
                    "effect": "allow",
                    "permissions": ["Workers Scripts Write"],
                    "resources": { (format!("com.cloudflare.api.account.{ACCOUNT_ID}")): "*" },
                }]},
            },
            {
                "name": "service-dns",
                "provider": "github",
                "claims": { "job_workflow_ref": "example-org/workflows/.github/workflows/deploy.yml@refs/heads/main" },
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

/// The provider for people's GitHub tokens, pinned to the test org.
fn people() -> Value {
    json!({ "name": "people", "issuer": "https://github.com", "claims": { "repository_owner_id": OWNER_ID } })
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

fn get(target: &Value, pointer: &str) -> Value {
    target.pointer(pointer).unwrap().clone()
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

fn github_claims(overrides: Value) -> Claims {
    let base = json!({
        "repository": "example-org/api",
        "repository_id": "200000003",
        "repository_owner": "example-org",
        "repository_owner_id": OWNER_ID,
        "ref": "refs/heads/main",
        "ref_type": "branch",
        "environment": "prod",
        "event_name": "push",
        "workflow_ref": "example-org/api/.github/workflows/deploy.yml@refs/heads/main",
        "job_workflow_ref": "example-org/api/.github/workflows/deploy.yml@refs/heads/main",
        "run_id": "1234567890",
        "run_attempt": "1",
        "actor_id": USER_ID,
        "runner_environment": "github-hosted",
    });
    with(base, overrides)
}

fn load(input: &Value) -> Policy {
    load_policy(input, None).unwrap_or_else(|err| panic!("{err}"))
}

/// Loads a policy and returns its issues, or none if it's valid.
fn issues(input: &Value) -> Vec<String> {
    load_policy(input, None)
        .err()
        .map(|err| err.issues)
        .unwrap_or_default()
}

fn profile<'a>(policy: &'a Policy, name: &str) -> &'a Profile {
    policy.profiles.iter().find(|p| p.name == name).unwrap()
}

/// What a refusal says, if it was one.
fn denial<T>(result: Result<T, Error>) -> Option<String> {
    result.err().map(|err| err.message)
}

fn select<'a>(
    policy: &'a Policy,
    provider: &str,
    claims: &Claims,
    requested: Option<&str>,
) -> Result<&'a Profile, Error> {
    select_profile(policy, provider, claims, requested, CLOUDFLARE_AUDIENCE)
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| v.to_string()).collect()
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

mod glob {
    use super::*;

    #[test]
    fn matches_exact_strings_without_star() {
        assert!(glob("refs/heads/main", "refs/heads/main"));
        assert!(!glob("refs/heads/main", "refs/heads/main2"));
    }

    #[test]
    fn lets_star_span_any_characters_including_slash() {
        assert!(glob("example-org/*", "example-org/api"));
        assert!(glob("refs/heads/release/*", "refs/heads/release/2026/09"));
        assert!(!glob("example-org/*", "other-org/api"));
    }

    #[test]
    fn treats_regex_metacharacters_literally() {
        assert!(glob("a.b*", "a.bc"));
        assert!(!glob("a.b*", "axbc"));
    }

    #[test]
    fn only_treats_a_trailing_star_after_a_prefix_as_a_wildcard() {
        assert!(glob("example-org/*", "example-org/"));
        assert!(!glob("*", "anything"));
        assert!(!glob("a*b", "axb"));
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
            vec![Provider {
                name: "github".into(),
                kind: ProviderType::Oidc,
                issuer: GITHUB_ACTIONS_ISSUER.into(),
                audience: Some(AUDIENCE.into()),
                jwks_uri: None,
                claims: [("repository_owner_id".to_string(), strings(&[OWNER_ID]))].into(),
            }]
        );
        let deploy = profile(&p, "workers-deploy");
        assert_eq!(deploy.provider, "github");
        assert_eq!(deploy.ttl, 15 * 60_000);
        assert_eq!(deploy.max_ttl, 60 * 60_000);
        assert_eq!(deploy.policies.as_ref().unwrap()[0].effect, Effect::Allow);
    }

    #[test]
    fn accepts_the_example_policy_file() {
        let example = include_str!("../../policy.example.json");
        load(&Value::String(example.into()));
    }

    #[test]
    fn adds_the_providers_claims_to_every_profile() {
        for profile in load(&policy()).profiles {
            assert_eq!(profile.claims["repository_owner_id"], strings(&[OWNER_ID]));
        }
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
    fn accepts_unquoted_numeric_ids_from_yaml() {
        let mut p = policy();
        set(
            &mut p,
            "/providers/0/claims/repository_owner_id",
            json!(100000001),
        );
        set(&mut p, "/profiles/0/claims/repository_id", json!(200000002));
        let loaded = load(&p);
        assert_eq!(
            loaded.providers[0].claims["repository_owner_id"],
            strings(&[OWNER_ID])
        );
        assert_eq!(
            loaded.profiles[0].claims["repository_id"],
            strings(&["200000002"])
        );
    }

    #[test]
    fn rejects_negative_and_fractional_numbers() {
        for value in [json!(-1), json!(1.5), json!(true)] {
            let mut p = policy();
            set(&mut p, "/profiles/0/claims/repository_id", value);
            let found = issues(&p);
            assert_eq!(found.len(), 1);
            assert!(
                found[0].starts_with("profiles.0.claims.repository_id: "),
                "{found:?}"
            );
        }
    }

    #[test]
    fn takes_one_value_or_a_list_and_loads_both_as_a_list() {
        let mut p = policy();
        set(
            &mut p,
            "/profiles/1/claims/ref",
            json!(["refs/heads/main", "refs/heads/release/*"]),
        );
        set(
            &mut p,
            "/providers/0/claims/repository_owner_id",
            json!([100000001, "100000002"]),
        );
        let loaded = load(&p);
        assert_eq!(
            loaded.profiles[1].claims["ref"],
            strings(&["refs/heads/main", "refs/heads/release/*"])
        );
        assert_eq!(
            loaded.profiles[1].claims["repository_owner_id"],
            strings(&[OWNER_ID, "100000002"])
        );
    }

    #[test]
    fn rejects_an_empty_list() {
        let mut p = policy();
        set(&mut p, "/profiles/1/claims/ref", json!([]));
        assert!(issues(&p).join(",").contains("profiles.1.claims.ref"));
    }

    #[test]
    fn rejects_an_empty_value() {
        let mut p = policy();
        set(&mut p, "/profiles/1/claims/ref", json!(""));
        assert_eq!(issues(&p), ["profiles.1.claims.ref: must not be empty"]);
    }

    #[test]
    fn refuses_version_1_with_a_pointer_to_the_migration() {
        assert_eq!(
            issues(&json!({ "version": 1, "github": {}, "profiles": [] })),
            [
                "version 1 is no longer supported: move github: to providers: and match: to claims: (see the broker README's migration table)"
            ]
        );
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
    }

    #[test]
    fn rejects_the_old_token_ttl() {
        let mut p = policy();
        set(&mut p, "/profiles/1/token/ttl", json!("10m"));
        assert_eq!(issues(&p), ["profiles.1.token.ttl: unknown key"]);
    }

    mod providers {
        use super::*;

        #[test]
        fn rejects_duplicate_names_and_issuers() {
            let mut p = policy();
            let first = get(&p, "/providers/0");
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
        fn requires_an_issuer() {
            let mut p = policy();
            push(
                &mut p,
                "/providers",
                json!({ "name": "other", "claims": {} }),
            );
            assert_eq!(issues(&p), ["providers.1.issuer: required"]);
        }

        #[test]
        fn requires_an_audience_for_an_oidc_issuer() {
            let mut p = policy();
            let other =
                json!({ "name": "other", "issuer": "https://issuer.example.com", "claims": {} });
            push(&mut p, "/providers", other);
            assert_eq!(
                issues(&p),
                ["providers.1 (other).audience: required for an OIDC issuer"]
            );
        }

        #[test]
        fn treats_github_com_as_peoples_tokens_and_any_other_issuer_as_oidc() {
            let mut p = policy();
            push(&mut p, "/providers", people());
            let kinds: Vec<_> = load(&p)
                .providers
                .into_iter()
                .map(|r| (r.name, r.kind))
                .collect();
            assert_eq!(
                kinds,
                [
                    ("github".to_string(), ProviderType::Oidc),
                    ("people".to_string(), ProviderType::GithubUser),
                ]
            );
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
                let local = json!({ "name": "local", "issuer": issuer, "audience": AUDIENCE, "claims": {} });
                push(&mut p, "/providers", local);
                let refused = issues(&p).join(",").contains("must be an https:// URL");
                assert_eq!(refused, !ok, "{issuer}");
            }
        }

        #[test]
        fn refuses_an_audience_on_the_provider_for_people() {
            let mut p = policy();
            let mut provider = people();
            set(&mut provider, "/audience", json!(AUDIENCE));
            push(&mut p, "/providers", provider);
            assert_eq!(
                issues(&p),
                [
                    "providers.1 (people).audience: not for https://github.com, whose tokens aren't OIDC tokens"
                ]
            );
        }

        #[test]
        fn allows_one_provider_for_people_like_any_issuer() {
            let mut p = policy();
            let mut more = people();
            set(&mut more, "/name", json!("more-people"));
            push(&mut p, "/providers", people());
            push(&mut p, "/providers", more);
            assert_eq!(
                issues(&p),
                ["providers.2 (more-people).issuer: another provider has the same issuer"]
            );
        }

        #[test]
        fn only_lets_the_provider_for_people_pin_the_owner_and_who() {
            let mut p = policy();
            let mut provider = people();
            set(&mut provider, "/claims/team_id", json!(TEAM_ID));
            push(&mut p, "/providers", provider);
            assert_eq!(
                issues(&p),
                [
                    "providers.1 (people).claims.team_id: a provider for people pins repository_owner_id or actor_id; the rest go on profiles"
                ]
            );
        }
    }

    mod guardrails {
        use super::*;

        #[test]
        fn one_requires_github_actions_providers_to_pin_the_owner() {
            let mut p = policy();
            set(&mut p, "/providers/0/claims", json!({}));
            assert_eq!(
                issues(&p),
                [format!(
                    "providers.0 (github).claims: must pin repository_owner_id: {GITHUB_ACTIONS_ISSUER} issues tokens to anyone's projects"
                )]
            );
        }

        #[test]
        fn one_requires_multi_tenant_issuers_to_pin_the_tenant() {
            let enterprise = format!("{GITHUB_ACTIONS_ISSUER}/example-enterprise");
            for (issuer, pin) in [
                ("https://gitlab.com", "namespace_id or project_id"),
                ("https://app.terraform.io", "terraform_organization_id"),
                (enterprise.as_str(), "repository_owner_id"),
            ] {
                let mut p = policy();
                let other = json!({ "name": "other", "issuer": issuer, "audience": AUDIENCE, "claims": {} });
                push(&mut p, "/providers", other);
                assert_eq!(
                    issues(&p),
                    [format!(
                        "providers.1 (other).claims: must pin {pin}: {issuer} issues tokens to anyone's projects"
                    )]
                );
            }
        }

        #[test]
        fn one_lets_a_single_tenant_issuer_go_without_a_pin() {
            let mut p = policy();
            let own = json!({
                "name": "gitlab-self",
                "issuer": "https://gitlab.example.com",
                "audience": AUDIENCE,
                "claims": {},
            });
            push(&mut p, "/providers", own);
            assert!(issues(&p).is_empty());
        }

        #[test]
        fn one_lets_a_profile_narrow_its_providers_list_but_not_widen_it() {
            let mut p = policy();
            set(
                &mut p,
                "/providers/0/claims/repository_owner_id",
                json!([OWNER_ID, "100000002"]),
            );
            set(
                &mut p,
                "/profiles/1/claims/repository_owner_id",
                json!(OWNER_ID),
            );
            assert_eq!(
                load(&p).profiles[1].claims["repository_owner_id"],
                strings(&[OWNER_ID])
            );
            set(
                &mut p,
                "/profiles/1/claims/repository_owner_id",
                json!([OWNER_ID, "999"]),
            );
            assert_eq!(
                issues(&p),
                [
                    "profiles.1 (workers-deploy).claims.repository_owner_id: conflicts with provider github"
                ]
            );
        }

        #[test]
        fn one_rejects_a_profile_that_overrides_its_providers_claims() {
            let mut p = policy();
            set(
                &mut p,
                "/profiles/1/claims/repository_owner_id",
                json!("999"),
            );
            assert_eq!(
                issues(&p),
                [
                    "profiles.1 (workers-deploy).claims.repository_owner_id: conflicts with provider github"
                ]
            );
        }

        #[test]
        fn two_rejects_globs_on_id_claims() {
            let mut p = policy();
            set(&mut p, "/profiles/0/claims/repository_id", json!("2000*"));
            assert!(
                issues(&p)
                    .join(",")
                    .contains("repository_id: ID claims must be exact")
            );
        }

        #[test]
        fn two_checks_provider_claims_the_same_way() {
            let mut p = policy();
            set(
                &mut p,
                "/providers/0/claims/repository_owner_id",
                json!("1000*"),
            );
            assert!(issues(&p).join(",").contains(
                "providers.0 (github).claims.repository_owner_id: ID claims must be exact"
            ));
        }

        #[test]
        fn two_rejects_broad_patterns() {
            for pattern in ["*", "*/api", "example-org/*/api", "example-org/**"] {
                let mut p = policy();
                set(&mut p, "/profiles/1/claims/repository", json!(pattern));
                assert_eq!(
                    issues(&p),
                    [
                        "profiles.1 (workers-deploy).claims.repository: * is only allowed once, at the end, after a prefix (e.g. example-org/*)"
                    ],
                    "{pattern}"
                );
            }
        }

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
        fn four_caps_max_ttl_at_24h() {
            let mut p = policy();
            set(&mut p, "/profiles/1/max_ttl", json!("25h"));
            assert!(
                issues(&p)
                    .join(",")
                    .contains("max_ttl: must be at most 24h")
            );
        }

        #[test]
        fn four_rejects_ttl_above_max_ttl() {
            let mut p = policy();
            set(&mut p, "/defaults", json!({ "ttl": "2h", "max_ttl": "1h" }));
            assert!(
                issues(&p)
                    .join(",")
                    .contains("defaults.ttl: must not exceed max_ttl")
            );
        }

        #[test]
        fn four_rejects_a_profile_ttl_above_the_default_max_ttl() {
            let mut p = policy();
            set(&mut p, "/profiles/1/ttl", json!("2h"));
            assert!(
                issues(&p)
                    .join(",")
                    .contains("ttl: must not exceed max_ttl")
            );
        }

        #[test]
        fn four_rejects_a_duration_it_cant_parse() {
            let mut p = policy();
            set(&mut p, "/profiles/1/ttl", json!("forever"));
            assert_eq!(
                issues(&p),
                ["profiles.1.ttl: must be a duration such as 15m or 1h"]
            );
        }

        #[test]
        fn five_rejects_githubs_audience() {
            for aud in ["https://github.com/example-org", "https://github.com"] {
                let mut p = policy();
                set(&mut p, "/providers/0/audience", json!(aud));
                assert_eq!(
                    issues(&p),
                    [
                        "providers.0 (github).audience: must not be GitHub's default audience; use the broker's URL"
                    ]
                );
            }
        }

        #[test]
        fn requires_the_brokers_issuer_to_be_a_bare_origin() {
            let mut p = policy();
            set(
                &mut p,
                "/issuer",
                json!("https://cf-oidc-exchange.example.com/"),
            );
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
        let deploy = get(&p, "/profiles/1");
        push(&mut p, "/profiles", deploy);
        assert!(issues(&p).join(",").contains("duplicate profile name"));
    }

    #[test]
    fn requires_a_profiles_provider_when_there_are_several() {
        let mut p = policy();
        push(&mut p, "/providers", people());
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
        fn rejects_mixing_flat_and_nested_resources() {
            let mixed = json!({
                (format!("com.cloudflare.api.account.{ACCOUNT_ID}")): { "com.cloudflare.api.account.zone.*": "*" },
                (format!("com.cloudflare.api.account.zone.{ZONE_ID}")): "*",
            });
            let found = issues(&with_resources(mixed)).join(",");
            assert!(
                found.contains("profiles.1.token.policies.0.resources: must be all"),
                "{found}"
            );
        }

        #[test]
        fn rejects_an_empty_resources_map() {
            let found = issues(&with_resources(json!({}))).join(",");
            assert!(found.contains("must name at least one resource"));
        }

        #[test]
        fn rejects_keys_that_arent_cloudflare_resource_names() {
            let found = issues(&with_resources(json!({ "example.com": "*" }))).join(",");
            assert!(found.contains("must be a Cloudflare resource name"));
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
        set(&mut p, "/profiles/0/claims/repository_id", json!("*"));
        assert!(issues(&p).len() >= 3);
    }
}

mod matching {
    use super::*;

    #[test]
    fn ands_every_claim() {
        let loaded = load(&policy());
        let deploy = profile(&loaded, "workers-deploy");
        assert!(matches(deploy, &github_claims(json!({}))));
        assert!(!matches(
            deploy,
            &github_claims(json!({ "environment": "staging" }))
        ));
    }

    #[test]
    fn requires_the_owner_pin() {
        let loaded = load(&policy());
        let claims = github_claims(json!({ "repository_owner_id": "999" }));
        assert!(!matches(profile(&loaded, "workers-deploy"), &claims));
    }

    #[test]
    fn fails_when_a_matched_claim_is_missing() {
        let loaded = load(&policy());
        let claims = github_claims(json!({ "environment": null }));
        assert!(!matches(profile(&loaded, "workers-deploy"), &claims));
    }

    #[test]
    fn matches_any_value_of_a_list() {
        let mut p = policy();
        set(
            &mut p,
            "/profiles/1/claims/ref",
            json!(["refs/heads/main", "refs/heads/release/*"]),
        );
        let loaded = load(&p);
        let deploy = &loaded.profiles[1];
        assert!(matches(
            deploy,
            &github_claims(json!({ "ref": "refs/heads/main" }))
        ));
        assert!(matches(
            deploy,
            &github_claims(json!({ "ref": "refs/heads/release/2026" }))
        ));
        assert!(!matches(
            deploy,
            &github_claims(json!({ "ref": "refs/heads/dev" }))
        ));
    }

    #[test]
    fn matches_a_claim_thats_a_list_in_the_token_if_any_of_its_values_does() {
        let mut p = policy();
        set(
            &mut p,
            "/profiles/1/claims",
            json!({ "groups": ["deployers", "admins"] }),
        );
        let loaded = load(&p);
        let deploy = &loaded.profiles[1];
        assert!(matches(
            deploy,
            &github_claims(json!({ "groups": ["readers", "deployers"] }))
        ));
        assert!(!matches(
            deploy,
            &github_claims(json!({ "groups": ["readers"] }))
        ));
    }

    #[test]
    fn compares_id_claims_exactly() {
        let loaded = load(&policy());
        let infra = profile(&loaded, "infra-cloudflare");
        assert!(matches(
            infra,
            &github_claims(json!({ "repository_id": "200000002" }))
        ));
        assert!(!matches(
            infra,
            &github_claims(json!({ "repository_id": "2000000021" }))
        ));
    }

    #[test]
    fn selects_the_single_matching_profile() {
        let loaded = load(&policy());
        let selected = select(&loaded, "github", &github_claims(json!({})), None).unwrap();
        assert_eq!(selected.name, "workers-deploy");
    }

    #[test]
    fn denies_when_nothing_matches() {
        let loaded = load(&policy());
        let claims = github_claims(json!({ "ref": "refs/heads/dev" }));
        assert_eq!(
            denial(select(&loaded, "github", &claims, None)),
            Some("no profile matches the token".to_string())
        );
    }

    #[test]
    fn denies_when_several_profiles_match_and_none_is_named() {
        let loaded = load(&policy());
        let claims = github_claims(
            json!({ "repository": "example-org/infra", "repository_id": "200000002" }),
        );
        let err = select(&loaded, "github", &claims, None).unwrap_err();
        assert_eq!(
            err.message,
            "profiles infra-cloudflare, workers-deploy all match the token: name one"
        );
        let named = select(&loaded, "github", &claims, Some("infra-cloudflare")).unwrap();
        assert_eq!(named.name, "infra-cloudflare");
    }

    #[test]
    fn denies_a_named_profile_that_doesnt_match() {
        let loaded = load(&policy());
        let claims = github_claims(json!({}));
        let err = select(&loaded, "github", &claims, Some("infra-cloudflare")).unwrap_err();
        assert_eq!(
            err.message,
            "profile infra-cloudflare doesn't match the token"
        );
        let err = select(&loaded, "github", &claims, Some("nope")).unwrap_err();
        assert_eq!(err.message, "unknown profile nope");
    }

    #[test]
    fn enables_profiles_unless_they_say_otherwise() {
        assert!(load(&policy()).profiles.iter().all(|p| p.enabled));
        let mut p = policy();
        set(&mut p, "/profiles/1/enabled", json!("no"));
        let found = issues(&p);
        assert_eq!(found.len(), 1);
        assert!(found[0].starts_with("profiles.1.enabled: "), "{found:?}");
        assert!(found[0].contains("expected a boolean"), "{found:?}");
    }

    #[test]
    fn never_matches_a_disabled_profile_even_by_name() {
        let mut p = policy();
        set(&mut p, "/profiles/1/enabled", json!(false));
        let disabled = load(&p);
        let claims = github_claims(json!({}));
        assert_eq!(
            denial(select(&disabled, "github", &claims, None)),
            Some("no profile matches the token".to_string())
        );
        let err = select(&disabled, "github", &claims, Some("workers-deploy")).unwrap_err();
        assert_eq!(err.message, "profile workers-deploy is disabled");
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
            "claims": { "ref": "refs/heads/main" },
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
    fn refuses_a_token_or_buckets_on_a_service_profile() {
        let buckets =
            json!({ "buckets": [{ "name": "org-artifacts", "permission": "object-read-only" }] });
        assert_eq!(
            issues(&with_service(buckets)),
            [format!(
                "profiles.3 (nix-push): a profile for {CACHE} can't have a token or buckets"
            )]
        );
    }

    #[test]
    fn refuses_the_broker_itself_as_an_audience() {
        let p = with_service(json!({ "audience": AUDIENCE }));
        assert_eq!(
            issues(&p),
            ["profiles.3 (nix-push).audience: must be another service, not the broker itself"]
        );
    }

    #[test]
    fn refuses_an_audience_that_isnt_a_bare_origin() {
        let p = with_service(json!({ "audience": format!("{CACHE}/upload") }));
        assert!(
            issues(&p)
                .join(",")
                .contains("profiles.3.audience: must be a bare origin")
        );
    }

    #[test]
    fn only_selects_profiles_for_the_requested_audience() {
        let loaded = load(&with_service(json!({})));
        let claims = github_claims(json!({}));
        assert_eq!(
            select(&loaded, "github", &claims, None).unwrap().name,
            "workers-deploy"
        );
        let service = select_profile(&loaded, "github", &claims, None, CACHE).unwrap();
        assert_eq!(service.name, "nix-push");
        let err =
            select_profile(&loaded, "github", &claims, Some("workers-deploy"), CACHE).unwrap_err();
        assert_eq!(
            err.message,
            format!("profile workers-deploy isn't for {CACHE}")
        );
    }
}

mod people {
    use super::*;

    /// The test policy plus the people provider and one profile for it, with
    /// workers-deploy's token.
    fn with_user(claims: Value, extra: Value) -> Value {
        let mut p = policy();
        push(&mut p, "/providers", people());
        let token = get(&p, "/profiles/1/token");
        let mut user =
            json!({ "name": "tofu-plan", "provider": "people", "claims": claims, "token": token });
        for (key, value) in extra.as_object().unwrap() {
            set(&mut user, &format!("/{key}"), value.clone());
        }
        push(&mut p, "/profiles", user);
        p
    }

    /// A person's claims as the broker builds them.
    fn person(overrides: Value) -> Claims {
        let base = json!({
            "actor": "octocat",
            "actor_id": USER_ID,
            "repository": "example-org/infra",
            "repository_id": "200000002",
            "repository_owner": "example-org",
            "repository_owner_id": OWNER_ID,
            "repository_permission": "write",
            "team_ids": [TEAM_ID],
        });
        with(base, overrides)
    }

    #[test]
    fn gives_profiles_their_providers_type() {
        let claims = json!({ "team_id": TEAM_ID, "repository_permission": "write" });
        let p = load(&with_user(claims, json!({})));
        assert_eq!(profile(&p, "workers-deploy").kind, ProviderType::Oidc);
        let user = profile(&p, "tofu-plan");
        assert_eq!(
            (user.provider.as_str(), user.kind),
            ("people", ProviderType::GithubUser)
        );
    }

    #[test]
    fn adds_the_people_providers_owner_pin() {
        let p = load(&with_user(
            json!({ "repository_permission": "write" }),
            json!({}),
        ));
        assert_eq!(
            profile(&p, "tofu-plan").claims["repository_owner_id"],
            strings(&[OWNER_ID])
        );
    }

    #[test]
    fn six_needs_a_role_on_the_repo_or_a_list_of_who() {
        assert_eq!(
            issues(&with_user(json!({ "team_id": TEAM_ID }), json!({}))),
            [
                "profiles.3 (tofu-plan).claims: a profile for people needs repository_permission (a role on the repo they ask for) or actor_id (who may use it)",
                "profiles.3 (tofu-plan).claims.team_id: needs repository_permission",
            ]
        );
    }

    #[test]
    fn six_accepts_a_list_of_who_may_use_it_without_the_owner_pin() {
        let p = load(&with_user(
            json!({ "actor_id": [USER_ID, "300000005"] }),
            json!({}),
        ));
        let user = profile(&p, "tofu-plan");
        // The owner pin bounds the repos people ask for; a list of who has no repo.
        assert_eq!(
            user.claims,
            [("actor_id".to_string(), strings(&[USER_ID, "300000005"]))].into()
        );
        let someone = json!({ "actor": "someone", "actor_id": "300000099" });
        assert!(matches(
            user,
            &with(
                json!({ "actor": "octocat", "actor_id": USER_ID }),
                json!({})
            )
        ));
        assert!(!matches(user, &with(someone, json!({}))));
    }

    #[test]
    fn six_needs_the_providers_owner_pin_for_a_role_on_the_repo() {
        let mut p = with_user(json!({ "repository_permission": "write" }), json!({}));
        set(&mut p, "/providers/1/claims", json!({}));
        assert_eq!(
            issues(&p),
            [
                "profiles.3 (tofu-plan).claims.repository_permission: needs provider people to pin repository_owner_id, the owner the repo must belong to"
            ]
        );
    }

    #[test]
    fn takes_one_role_the_least() {
        let p = with_user(
            json!({ "repository_permission": ["read", "write"] }),
            json!({}),
        );
        assert_eq!(
            issues(&p),
            [
                "profiles.3 (tofu-plan).claims.repository_permission: one role, the least the person must have"
            ]
        );
    }

    #[test]
    fn six_rejects_claims_only_jobs_have() {
        let claims = json!({ "repository_permission": "write", "ref": "refs/heads/main", "environment": "prod" });
        let found = issues(&with_user(claims, json!({})));
        // In claim-name order, which is how the loaded claims are kept.
        assert_eq!(found.len(), 2);
        assert!(
            found[0]
                .starts_with("profiles.3 (tofu-plan).claims.environment: not available for people")
        );
        assert!(
            found[1].starts_with("profiles.3 (tofu-plan).claims.ref: not available for people")
        );
    }

    #[test]
    fn six_rejects_person_only_claims_in_an_oidc_profile() {
        let mut p = policy();
        set(&mut p, "/profiles/0/claims/team_id", json!(TEAM_ID));
        set(
            &mut p,
            "/profiles/0/claims/repository_permission",
            json!("write"),
        );
        assert_eq!(
            issues(&p),
            [
                "profiles.0 (infra-cloudflare).claims.team_id: only for people (https://github.com)",
                "profiles.0 (infra-cloudflare).claims.repository_permission: only for people (https://github.com)",
            ]
        );
    }

    #[test]
    fn rejects_an_unknown_repository_permission() {
        let p = with_user(json!({ "repository_permission": "push" }), json!({}));
        assert_eq!(
            issues(&p),
            [
                "profiles.3 (tofu-plan).claims.repository_permission: must be one of read, triage, write, maintain, admin"
            ]
        );
    }

    #[test]
    fn two_rejects_a_globbed_team_id() {
        let p = with_user(
            json!({ "team_id": "4000*", "repository_permission": "write" }),
            json!({}),
        );
        assert_eq!(
            issues(&p),
            [
                "profiles.3 (tofu-plan).claims.team_id: ID claims must be exact, globs are not allowed"
            ]
        );
    }

    #[test]
    fn caps_the_default_max_ttl_at_1h_unless_the_profile_sets_its_own() {
        let defaults = json!({ "ttl": "15m", "max_ttl": "24h" });
        let mut p = with_user(json!({ "repository_permission": "write" }), json!({}));
        set(&mut p, "/defaults", defaults.clone());
        let loaded = load(&p);
        assert_eq!(profile(&loaded, "tofu-plan").max_ttl, 60 * 60_000);
        assert_eq!(profile(&loaded, "workers-deploy").max_ttl, 24 * 60 * 60_000);

        let mut own = with_user(
            json!({ "repository_permission": "write" }),
            json!({ "max_ttl": "8h" }),
        );
        set(&mut own, "/defaults", defaults);
        assert_eq!(profile(&load(&own), "tofu-plan").max_ttl, 8 * 60 * 60_000);
    }

    mod matching {
        use super::*;

        fn loaded() -> Policy {
            let claims = json!({ "team_id": TEAM_ID, "repository_permission": "write" });
            load(&with_user(claims, json!({})))
        }

        #[test]
        fn requires_at_least_the_role() {
            let loaded = loaded();
            let user = profile(&loaded, "tofu-plan");
            assert!(matches(user, &person(json!({}))));
            assert!(matches(
                user,
                &person(json!({ "repository_permission": "admin" }))
            ));
            assert!(!matches(
                user,
                &person(json!({ "repository_permission": "triage" }))
            ));
            assert!(!matches(
                user,
                &person(json!({ "repository_permission": null }))
            ));
            assert!(!matches(
                user,
                &person(json!({ "repository_permission": "push" }))
            ));
        }

        #[test]
        fn requires_membership_of_the_team() {
            let loaded = loaded();
            let user = profile(&loaded, "tofu-plan");
            assert!(matches(
                user,
                &person(json!({ "team_ids": ["400000099", TEAM_ID] }))
            ));
            assert!(!matches(user, &person(json!({ "team_ids": [] }))));
            assert!(!matches(user, &person(json!({ "team_ids": null }))));
            assert!(!matches(user, &person(json!({ "team_ids": TEAM_ID }))));
        }

        #[test]
        fn keeps_the_owner_pin() {
            let loaded = loaded();
            let claims = person(json!({ "repository_owner_id": "999999" }));
            assert!(!matches(profile(&loaded, "tofu-plan"), &claims));
        }

        #[test]
        fn never_picks_a_jobs_profile_for_a_person() {
            let loaded = loaded();
            // workers-deploy matches repository example-org/*, which a person's claims have too.
            let me = person(json!({}));
            assert_eq!(
                select(&loaded, "people", &me, None).unwrap().name,
                "tofu-plan"
            );
            let named = select(&loaded, "people", &me, Some("workers-deploy"));
            assert_eq!(
                denial(named).as_deref(),
                Some("profile workers-deploy isn't for provider people")
            );
            let no_teams = person(json!({ "team_ids": [] }));
            assert_eq!(
                denial(select(&loaded, "people", &no_teams, None)),
                Some("no profile matches the token".to_string())
            );
        }

        #[test]
        fn never_picks_a_persons_profile_for_a_job() {
            let loaded = loaded();
            let mut job = github_claims(json!({}));
            job.extend(person(json!({ "ref": "refs/heads/dev" })));
            assert_eq!(
                denial(select(&loaded, "github", &job, None)),
                Some("no profile matches the token".to_string())
            );
            let named = select(&loaded, "github", &job, Some("tofu-plan"));
            assert_eq!(
                denial(named).as_deref(),
                Some("profile tofu-plan isn't for provider github")
            );
        }
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

    fn loaded(p: &Value) -> Profile {
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
                prefixes: strings(&["github.com/{repository}/"]),
            }])
        );
        assert_eq!(profile.ttl, 15 * 60_000);
        assert_eq!(profile.max_ttl, 60 * 60_000);
    }

    #[test]
    fn takes_ttl_and_max_ttl_from_the_profile() {
        let profile = loaded(&with_bucket(
            json!({}),
            json!({ "ttl": "5m", "max_ttl": "10m" }),
            false,
        ));
        assert_eq!(profile.ttl, 5 * 60_000);
        assert_eq!(profile.max_ttl, 10 * 60_000);
        let p = with_bucket(json!({}), json!({ "ttl": "20m", "max_ttl": "10m" }), false);
        assert!(
            issues(&p)
                .join(",")
                .contains("(workers-deploy).ttl: must not exceed max_ttl")
        );
        let p = with_bucket(json!({}), json!({ "max_ttl": "25h" }), false);
        assert!(
            issues(&p)
                .join(",")
                .contains("(workers-deploy).max_ttl: must be at most 24h")
        );
    }

    #[test]
    fn applies_the_profiles_ttl_to_the_token_too() {
        let mut p = policy();
        set(&mut p, "/profiles/1/ttl", json!("5m"));
        assert_eq!(loaded(&p).ttl, 5 * 60_000);
    }

    #[test]
    fn accepts_a_profile_with_a_token_and_buckets() {
        let profile = loaded(&with_bucket(json!({}), json!({}), true));
        assert_eq!(profile.policies.map(|p| p.len()), Some(1));
        assert_eq!(profile.buckets.unwrap()[0].prefixes, Vec::<String>::new());
    }

    #[test]
    fn requires_a_token_buckets_or_both() {
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
        let artifacts = json!({ "name": "org-artifacts", "permission": "object-read-only", "prefixes": ["{repository_id}/"] });
        push(&mut p, "/profiles/1/buckets", artifacts);
        let names: Vec<String> = loaded(&p)
            .buckets
            .unwrap()
            .into_iter()
            .map(|b| b.name)
            .collect();
        assert_eq!(names, ["org-terraform-state", "org-artifacts"]);

        let again = json!({ "name": "org-terraform-state", "permission": "object-read-only" });
        push(&mut p, "/profiles/1/buckets", again);
        assert_eq!(
            issues(&p),
            ["profiles.1 (workers-deploy).buckets.2.name: duplicate bucket org-terraform-state"]
        );

        set(&mut p, "/profiles/1/buckets", json!([]));
        assert!(issues(&p).join(",").contains("buckets: "));
    }

    #[test]
    fn rejects_bad_bucket_names() {
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
            let found = issues(&p).join(",");
            assert!(
                found.contains("buckets.0.name: must be a valid R2 bucket name"),
                "{name}"
            );
        }
    }

    #[test]
    fn rejects_bad_permissions() {
        for permission in ["admin-read-write", "admin-read-only", "read-write"] {
            let p = with_bucket(json!({ "permission": permission }), json!({}), false);
            let found = issues(&p).join(",");
            assert!(
                found.contains(
                    "buckets.0.permission: must be object-read-write or object-read-only"
                ),
                "{permission}"
            );
        }
    }

    #[test]
    fn accepts_good_prefixes() {
        for prefix in [
            "github.com/{repository}/",
            "{repository_owner_id}/{repository_id}/",
            "{repository_owner}/shared/",
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
            ("/", "must not start with /"),
            ("", "must end with /"),
            ("github.com/${repository}/", "not ${claim}"),
            ("github.com/{ref}/", "unknown placeholder {ref}"),
            ("github.com/{}/", "unknown placeholder {}"),
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
                prefixes: strings(prefixes),
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
            assert_eq!(
                fill(&[], &github_claims(json!({}))).unwrap(),
                Vec::<String>::new()
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
            assert!(!format!("{old}terraform.tfstate").starts_with(site.as_str()));
        }

        #[test]
        fn refuses_an_unusable_repository() {
            for (case, repository) in [
                ("missing", Value::Null),
                ("empty", json!("")),
                ("a number", json!(42)),
                ("without an owner", json!("api")),
                ("with two slashes", json!("example-org/api/../other")),
                ("a leading slash", json!("/example-org/api")),
                ("a space", json!("example-org/my api")),
                ("a percent escape", json!("example-org/%2e%2e")),
                ("a backslash", json!("example-org\\api")),
                ("a non-ASCII character", json!("example-org/\u{0430}pi")),
                ("a newline", json!("example-org/api\n")),
                ("a *", json!("example-org/*")),
            ] {
                let claims = github_claims(json!({ "repository": repository }));
                let filled = fill(&["github.com/{repository}/"], &claims);
                let refused = denial(filled).unwrap_or_default();
                assert!(
                    refused.starts_with("bucket org-terraform-state: "),
                    "{case}: {refused}"
                );
            }
        }

        #[test]
        fn refuses_unusable_claims() {
            let templates = [
                "github.com/{repository}/",
                "{repository_owner}/",
                "{repository_owner_id}/{repository_id}/",
            ];
            for (case, overrides) in [
                ("..", json!({ "repository": "example-org/.." })),
                (". as the repo", json!({ "repository": "example-org/." })),
                (".. as the owner", json!({ "repository_owner": ".." })),
                (
                    "a slash in the owner",
                    json!({ "repository_owner": "example-org/api" }),
                ),
                ("a non-numeric ID", json!({ "repository_id": "200000003a" })),
                ("an empty ID", json!({ "repository_owner_id": "" })),
            ] {
                let filled = fill(&templates, &github_claims(overrides));
                let refused = denial(filled).unwrap_or_default();
                assert!(
                    refused.starts_with("bucket org-terraform-state: "),
                    "{case}: {refused}"
                );
            }
        }
    }
}
