//! End-to-end tests of the Worker under `wrangler dev`, with the OIDC issuers,
//! GitHub and Cloudflare replaced by the stand-ins in `helper`. Ported from the
//! TypeScript broker's `test/worker.test.ts`. Run with `tests/run.sh`.

#![cfg(feature = "integration")]

mod helper;

use axum::http::Method;
use helper::*;
use serde_json::{Value, json};

fn token_id(reply: &Reply) -> String {
    reply.json()["token_id"]
        .as_str()
        .expect("a token_id")
        .to_string()
}

fn minted_policies(id: &str) -> Value {
    world().cloudflare.tokens[id].policies.clone()
}

fn r2_bodies() -> Vec<Value> {
    world()
        .cloudflare
        .requests
        .iter()
        .filter(|r| r.path.ends_with("/r2/temp-access-credentials"))
        .map(|r| r.body.clone().unwrap())
        .collect()
}

fn token_count() -> usize {
    world().cloudflare.tokens.len()
}

mod token_exchange_for_jobs {
    use super::*;

    #[tokio::test]
    async fn mints_a_scoped_expiring_token() {
        let _t = start().await;
        let before = now();
        let res = job_token(
            &sign(github_claims(json!({}))),
            &[("profile", "workers-deploy")],
        )
        .await;
        assert_eq!(res.status, 200, "{}", res.text);
        assert_eq!(res.cache_control.as_deref(), Some("no-store"));

        let body = res.json();
        assert_eq!(body["profile"], "workers-deploy");
        assert_eq!(body["account_id"], ACCOUNT_ID);
        assert!(body["access_token"].as_str().unwrap().starts_with("value-"));
        assert_matches(
            &body,
            json!({ "issued_token_type": ACCESS_TOKEN, "token_type": "Bearer" }),
        );

        let created = world().cloudflare.tokens[&token_id(&res)].clone();
        assert_eq!(created.name, "cf-oidc:example-org/api:1234567890:1");
        assert_eq!(
            created.policies,
            json!([{
                "effect": "allow",
                "permission_groups": [{ "id": "pg-workers-scripts-write" }],
                "resources": { (format!("com.cloudflare.api.account.{ACCOUNT_ID}")): "*" },
            }])
        );
        // The default ttl is 15m, sent to Cloudflare without fractional seconds.
        let expires_on = created.expires_on.unwrap();
        assert_eq!(expires_on.len(), 20, "{expires_on}");
        assert!(expires_on.ends_with('Z'));
        let expires_at = body["expires_at"].as_u64().unwrap();
        assert!(expires_at - before > 14 * 60 && expires_at - before <= 15 * 60 + 1);
    }

    #[tokio::test]
    async fn uses_the_single_matching_profile_when_none_is_named() {
        let _t = start().await;
        let res = job_token(&sign(github_claims(json!({}))), &[]).await;
        assert_eq!(res.status, 200);
        assert_eq!(res.json()["profile"], "workers-deploy");
    }

    #[tokio::test]
    async fn resolves_permission_names_to_ids_and_passes_resources_through() {
        let _t = start().await;
        let claims = github_claims(
            json!({ "repository": "example-org/infra", "repository_id": "200000002" }),
        );
        let res = job_token(&sign(claims), &[("profile", "infra-cloudflare")]).await;
        assert_eq!(res.status, 200);
        assert_eq!(
            minted_policies(&token_id(&res)),
            json!([{
                "effect": "allow",
                "permission_groups": [{ "id": "pg-zone-write" }, { "id": "pg-dns-write" }],
                "resources": { (format!("com.cloudflare.api.account.zone.{ZONE_ID}")): "*" },
            }])
        );
    }

    #[tokio::test]
    async fn clamps_the_requested_ttl_to_max_ttl() {
        let _t = start().await;
        let res = job_token(&sign(github_claims(json!({}))), &[("ttl", "12h")]).await;
        let body = res.json();
        assert!(body["expires_at"].as_u64().unwrap() - now() <= 60 * 60 + 1);
        assert!(body["expires_in"].as_u64().unwrap() <= 60 * 60);
    }

    #[tokio::test]
    async fn writes_an_audit_line_without_secrets() {
        let t = start().await;
        let res = job_token(&sign(github_claims(json!({}))), &[]).await;
        let body = res.json();
        let mint = t.audit("token.mint").await.expect("a token.mint line");
        assert_matches(
            &mint,
            json!({
                "profile": "workers-deploy",
                "repository": "example-org/api",
                "repository_id": "200000003",
                "ref": "refs/heads/main",
                "environment": "prod",
                "run_id": "1234567890",
                "run_attempt": "1",
                "actor_id": USER_ID,
                "token_id": body["token_id"],
            }),
        );
        assert!(!t.log().contains(body["access_token"].as_str().unwrap()));
    }

    #[tokio::test]
    async fn rejects_a_request_without_a_subject_token() {
        let t = start().await;
        let res = post_form(
            "/oauth/token",
            &[("grant_type", GRANT), ("subject_token_type", ID_TOKEN)],
        )
        .await;
        assert_eq!(res.status, 400);
        assert_error(&res, "bad_request");
        assert_refused(&t.deny().await, "bad_request", "");
    }

    #[tokio::test]
    async fn refuses_a_jwt_for_another_audience() {
        let _t = start().await;
        let jwt = sign_with(
            &issuer("actions"),
            github_claims(json!({})),
            "sts.amazonaws.com",
            300,
        );
        assert_eq!(job_token(&jwt, &[]).await.status, 401);
    }

    #[tokio::test]
    async fn refuses_a_repo_outside_the_pinned_owner_with_a_generic_body() {
        let t = start().await;
        let claims = github_claims(json!({ "repository_owner_id": "999999" }));
        let res = job_token(&sign(claims), &[]).await;
        assert_eq!(res.status, 403);
        assert_error(&res, "forbidden");
        assert_refused(&t.deny().await, "forbidden", "no profile matches the token");
        assert_eq!(token_count(), 1); // only the broker token
    }

    #[tokio::test]
    async fn refuses_when_several_profiles_match_and_none_is_named() {
        let t = start().await;
        let claims = github_claims(
            json!({ "repository": "example-org/infra", "repository_id": "200000002" }),
        );
        assert_eq!(job_token(&sign(claims), &[]).await.status, 403);
        assert_refused(&t.deny().await, "forbidden", "all match the token");
    }

    #[tokio::test]
    async fn refuses_a_named_profile_that_doesnt_match() {
        let t = start().await;
        let res = job_token(
            &sign(github_claims(json!({}))),
            &[("profile", "infra-cloudflare")],
        )
        .await;
        assert_eq!(res.status, 403);
        let deny = t.deny().await;
        assert_matches(&deny, json!({ "profile": "infra-cloudflare" }));
        assert_refused(&deny, "forbidden", "profile ");
    }

    #[tokio::test]
    async fn rejects_bad_fields() {
        let _t = start().await;
        let long = "x".repeat(65);
        let jwt = sign(github_claims(json!({})));
        let cases: [&[(&str, &str)]; 4] = [
            &[("ttl", "forever")],
            &[("ttl", "600")],
            &[("profile", "a"), ("profile", "b")],
            &[("profile", &long)],
        ];
        for fields in cases {
            assert_eq!(job_token(&jwt, fields).await.status, 400, "{fields:?}");
        }
    }

    #[tokio::test]
    async fn logs_the_profile_count_when_the_policy_loads() {
        let t = start().await;
        world().policy()["defaults"] = json!({ "ttl": "10m" }); // a policy the Worker hasn't loaded
        call(Method::GET, "/.well-known/openid-configuration").await;
        assert_eq!(
            t.audit("policy.loaded").await,
            Some(json!({ "event": "policy.loaded", "profiles": 3 }))
        );
    }

    #[tokio::test]
    async fn fails_closed_when_the_policy_is_invalid() {
        let t = start().await;
        world().policy()["github"] = json!({ "audience": "https://x.example.com" });
        let res = job_token(&sign(github_claims(json!({}))), &[]).await;
        assert_eq!(res.status, 500);
        assert_error(&res, "misconfigured");
        assert!(t.audit("policy.invalid").await.is_some());
    }

    #[tokio::test]
    async fn fails_when_a_permission_name_is_unknown() {
        let t = start().await;
        world().policy()["profiles"][1]["token"]["policies"][0]["permissions"] =
            json!(["Workers Scrpts Write"]);
        let res = job_token(&sign(github_claims(json!({}))), &[]).await;
        assert_eq!(res.status, 500);
        assert_refused(
            &t.deny().await,
            "misconfigured",
            "no permission group is named Workers Scrpts Write",
        );
    }

    #[tokio::test]
    async fn picks_the_right_scope_for_a_permission_name_shared_by_two_groups() {
        let _t = start().await;
        world().policy()["profiles"][1]["token"]["policies"][0]["permissions"] =
            json!(["Load Balancers Write"]);
        let res = job_token(&sign(github_claims(json!({}))), &[]).await;
        assert_eq!(res.status, 200, "{}", res.text);
        assert_eq!(
            minted_policies(&token_id(&res))[0]["permission_groups"],
            json!([{ "id": "pg-lb-write-account" }])
        );
    }

    #[tokio::test]
    async fn picks_the_zone_scoped_group_for_zone_resources() {
        let _t = start().await;
        world().policy()["profiles"][0]["token"]["policies"][0]["permissions"] =
            json!(["Load Balancers Write"]);
        let claims = github_claims(
            json!({ "repository": "example-org/infra", "repository_id": "200000002" }),
        );
        let res = job_token(&sign(claims), &[("profile", "infra-cloudflare")]).await;
        assert_eq!(res.status, 200, "{}", res.text);
        assert_eq!(
            minted_policies(&token_id(&res))[0]["permission_groups"],
            json!([{ "id": "pg-lb-write-zone" }])
        );
    }

    #[tokio::test]
    async fn fails_closed_when_the_policy_names_another_account() {
        let _t = start().await;
        world().scenario["account_id"] = json!("ffffffffffffffffffffffffffffffff");
        let res = job_token(&sign(github_claims(json!({}))), &[]).await;
        assert_eq!(res.status, 500);
        assert_error(&res, "misconfigured");
    }

    #[tokio::test]
    async fn fails_when_the_cloudflare_api_does_without_retrying_the_create() {
        let t = start().await;
        world().cloudflare.fail_create = true;
        let res = job_token(&sign(github_claims(json!({}))), &[]).await;
        assert_eq!(res.status, 502);
        // The caller is told it's upstream, not what failed; the audit log says.
        assert_error(&res, "upstream_error");
        assert!(
            !res.json()["message"]
                .as_str()
                .unwrap()
                .contains("tokens.create"),
            "{}",
            res.text
        );
        assert_refused(
            &t.deny().await,
            "upstream_error",
            "Cloudflare: tokens.create: returned 500",
        );
        let creates = world()
            .cloudflare
            .requests
            .iter()
            .filter(|r| r.method == "POST")
            .count();
        assert_eq!(creates, 1);
    }
}

mod token_exchange_for_jobs_with_buckets {
    use super::*;

    /// Adds profiles for the state environment, which no other test profile matches.
    fn with_profiles(profiles: Value) {
        let mut world = world();
        let list = world.policy()["profiles"].as_array_mut().unwrap();
        list.extend(profiles.as_array().unwrap().iter().cloned());
    }

    fn state() -> Value {
        json!({ "repository": "example-org/state-*", "environment": "state" })
    }

    fn state_repo(overrides: Value) -> String {
        let mut claims =
            github_claims(json!({ "repository": "example-org/state-app", "environment": "state" }));
        merge(&mut claims, overrides);
        sign(claims)
    }

    fn deploy_policies() -> Value {
        json!({ "policies": [{ "permissions": ["Workers Scripts Write"], "resources": { (format!("com.cloudflare.api.account.{ACCOUNT_ID}")): "*" } }] })
    }

    #[tokio::test]
    async fn issues_prefix_limited_credentials_for_a_profile_with_only_buckets() {
        let _t = start().await;
        with_profiles(json!([{
            "name": "terraform-state",
            "claims": state(),
            "buckets": [{ "name": "org-terraform-state", "permission": "object-read-write", "prefixes": ["github.com/{repository}/"] }],
        }]));
        let before = now();
        let res = job_token(&state_repo(json!({})), &[("profile", "terraform-state")]).await;
        assert_eq!(res.status, 200, "{}", res.text);
        let body = res.json();
        let expires_on = body["buckets"][0]["expires_on"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            body,
            json!({
                "issued_token_type": R2_CREDENTIALS,
                "token_type": "N_A",
                "expires_in": body["expires_in"],
                "expires_at": body["expires_at"],
                "account_id": ACCOUNT_ID,
                "profile": "terraform-state",
                "buckets": [{
                    "name": "org-terraform-state",
                    "access_key_id": BROKER_TOKEN_ID,
                    "secret_access_key": "r2-secret-value",
                    "session_token": "r2-session-token-value",
                    "prefixes": ["github.com/example-org/state-app/"],
                    "endpoint": format!("https://{ACCOUNT_ID}.r2.cloudflarestorage.com"),
                    "expires_on": expires_on,
                }],
            })
        );
        assert_eq!(expires_on.len(), 20, "{expires_on}");
        let expires_at = body["expires_at"].as_u64().unwrap();
        assert!(expires_at - before > 14 * 60 && expires_at - before <= 15 * 60 + 1);
        assert_eq!(
            r2_bodies(),
            [json!({
                "bucket": "org-terraform-state",
                "parentAccessKeyId": BROKER_TOKEN_ID,
                "permission": "object-read-write",
                "ttlSeconds": 900.0,
                "prefixes": ["github.com/example-org/state-app/"],
            })]
        );
        assert_eq!(token_count(), 1); // no API token minted
    }

    #[tokio::test]
    async fn covers_the_whole_bucket_without_prefixes_and_honours_the_requested_ttl() {
        let _t = start().await;
        with_profiles(json!([{
            "name": "terraform-state",
            "claims": state(),
            "max_ttl": "30m",
            "buckets": [{ "name": "org-terraform-state", "permission": "object-read-only" }],
        }]));
        let res = job_token(&state_repo(json!({})), &[("ttl", "2h")]).await;
        assert_eq!(res.json()["buckets"][0]["prefixes"], json!([]));
        assert_eq!(
            r2_bodies()[0],
            json!({ "bucket": "org-terraform-state", "parentAccessKeyId": BROKER_TOKEN_ID, "permission": "object-read-only", "ttlSeconds": 1800.0 })
        );
    }

    #[tokio::test]
    async fn mints_a_token_and_credentials_that_expire_together_for_a_profile_with_both() {
        let _t = start().await;
        with_profiles(json!([{
            "name": "state-and-deploy",
            "claims": state(),
            "ttl": "10m",
            "token": deploy_policies(),
            "buckets": [{ "name": "org-terraform-state", "permission": "object-read-write", "prefixes": ["{repository_id}/"] }],
        }]));
        let res = job_token(&state_repo(json!({})), &[]).await;
        assert_eq!(res.status, 200, "{}", res.text);
        let body = res.json();
        assert!(
            world()
                .cloudflare
                .tokens
                .contains_key(body["token_id"].as_str().unwrap())
        );
        assert_eq!(body["buckets"][0]["prefixes"], json!(["200000003/"]));
        assert_eq!(r2_bodies()[0]["ttlSeconds"], json!(600.0));
        let bucket_expiry = chrono_secs(body["buckets"][0]["expires_on"].as_str().unwrap());
        assert!((bucket_expiry - body["expires_at"].as_i64().unwrap()).abs() <= 1);
    }

    #[tokio::test]
    async fn issues_credentials_for_each_bucket_in_the_policys_order() {
        let t = start().await;
        with_profiles(json!([{
            "name": "state-and-artifacts",
            "claims": state(),
            "buckets": [
                { "name": "org-terraform-state", "permission": "object-read-write", "prefixes": ["github.com/{repository}/"] },
                { "name": "org-artifacts", "permission": "object-read-only" },
            ],
        }]));
        let res = job_token(&state_repo(json!({})), &[]).await;
        assert_eq!(res.status, 200, "{}", res.text);
        let buckets: Vec<Value> = res.json()["buckets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| json!([b["name"], b["prefixes"]]))
            .collect();
        assert_eq!(
            buckets,
            [
                json!(["org-terraform-state", ["github.com/example-org/state-app/"]]),
                json!(["org-artifacts", []])
            ]
        );
        let names: Vec<Value> = r2_bodies().iter().map(|b| b["bucket"].clone()).collect();
        assert_eq!(
            names,
            [json!("org-terraform-state"), json!("org-artifacts")]
        );
        let issued: Vec<Value> = t
            .audits("r2.issued")
            .await
            .iter()
            .map(|l| l["bucket"].clone())
            .collect();
        assert_eq!(
            issued,
            [json!("org-terraform-state"), json!("org-artifacts")]
        );
    }

    #[tokio::test]
    async fn deletes_the_token_when_a_later_buckets_credentials_cant_be_created() {
        let t = start().await;
        with_profiles(json!([{
            "name": "state-and-artifacts",
            "claims": state(),
            "token": deploy_policies(),
            "buckets": [
                { "name": "org-terraform-state", "permission": "object-read-write" },
                { "name": "org-artifacts", "permission": "object-read-only" },
            ],
        }]));
        world().cloudflare.fail_r2_bucket = Some("org-artifacts".into());
        assert_eq!(job_token(&state_repo(json!({})), &[]).await.status, 502);
        assert_eq!(token_count(), 1); // only the broker token
        let issued: Vec<Value> = t
            .audits("r2.issued")
            .await
            .iter()
            .map(|l| l["bucket"].clone())
            .collect();
        assert_eq!(issued, [json!("org-terraform-state")]);
    }

    #[tokio::test]
    async fn deletes_the_token_when_the_credentials_cant_be_created() {
        let t = start().await;
        with_profiles(json!([{
            "name": "state-and-deploy",
            "claims": state(),
            "token": deploy_policies(),
            "buckets": [{ "name": "org-terraform-state", "permission": "object-read-write" }],
        }]));
        world().cloudflare.fail_r2 = true;
        let res = job_token(&state_repo(json!({})), &[]).await;
        assert_eq!(res.status, 502);
        assert_error(&res, "upstream_error");
        assert_eq!(token_count(), 1); // the minted token was deleted
        assert_matches(
            &t.audit("token.revoke").await.unwrap(),
            json!({ "reason": "discarded" }),
        );
        assert!(t.audits("r2.issued").await.is_empty());
    }

    #[tokio::test]
    async fn refuses_without_calling_cloudflare_when_a_claim_cant_be_used_in_the_prefix() {
        let t = start().await;
        with_profiles(json!([{
            "name": "terraform-state",
            "claims": state(),
            "buckets": [{ "name": "org-terraform-state", "permission": "object-read-write", "prefixes": ["{repository_owner}/"] }],
        }]));
        let res = job_token(
            &state_repo(json!({ "repository_owner": "../example-org" })),
            &[],
        )
        .await;
        assert_eq!(res.status, 403);
        assert_error(&res, "forbidden");
        let deny = t.deny().await;
        assert_matches(&deny, json!({ "profile": "terraform-state" }));
        assert_refused(&deny, "forbidden", "bucket org-terraform-state: ");
        assert!(world().cloudflare.calls().is_empty());
    }

    #[tokio::test]
    async fn writes_an_r2_issued_audit_line_without_secrets() {
        let t = start().await;
        with_profiles(json!([{
            "name": "terraform-state",
            "claims": state(),
            "buckets": [{ "name": "org-terraform-state", "permission": "object-read-write", "prefixes": ["github.com/{repository}/"] }],
        }]));
        let res = job_token(&state_repo(json!({})), &[]).await;
        let expires_on = res.json()["buckets"][0]["expires_on"].clone();
        assert_eq!(
            t.audit("r2.issued").await.unwrap(),
            json!({
                "event": "r2.issued",
                "provider": "github",
                "profile": "terraform-state",
                "repository": "example-org/state-app",
                "repository_id": "200000003",
                "ref": "refs/heads/main",
                "environment": "state",
                "event_name": "push",
                "workflow_ref": "example-org/api/.github/workflows/deploy.yml@refs/heads/main",
                "job_workflow_ref": "example-org/api/.github/workflows/deploy.yml@refs/heads/main",
                "run_id": "1234567890",
                "run_attempt": "1",
                "actor_id": USER_ID,
                "bucket": "org-terraform-state",
                "prefixes": ["github.com/example-org/state-app/"],
                "permission": "object-read-write",
                "expires_on": expires_on,
            })
        );
        assert!(!t.log().contains("r2-secret-value"));
        assert!(!t.log().contains("r2-session-token-value"));
    }

    #[tokio::test]
    async fn looks_up_the_parent_access_key_id_once_and_again_after_the_broker_token_rotates() {
        let _t = start().await;
        with_profiles(json!([{
            "name": "terraform-state",
            "claims": state(),
            "buckets": [{ "name": "org-terraform-state", "permission": "object-read-write" }],
        }]));
        let verifies = || {
            world()
                .cloudflare
                .requests
                .iter()
                .filter(|r| r.path.ends_with("/tokens/verify"))
                .count()
        };
        // An earlier test may have looked it up already: once at most, then never again.
        job_token(&state_repo(json!({})), &[]).await;
        let first = verifies();
        assert!(first <= 1);
        job_token(&state_repo(json!({})), &[]).await;
        assert_eq!(verifies(), first);

        {
            let mut world = world();
            world.cloudflare.add(
                Some("tok-rotated"),
                "cf-oidc broker token (rotated)",
                Some(ROTATED_TOKEN),
                None,
                "active",
            );
            world.scenario["broker_token"] = json!("BROKER_TOKEN_ROTATED");
        }
        // The stand-in only takes the original broker token for everything but verify, so stop here.
        job_token(&state_repo(json!({})), &[]).await;
        assert_eq!(verifies(), first + 1);
    }
}

/// Seconds since the epoch of an RFC 3339 timestamp.
fn chrono_secs(rfc3339: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .unwrap()
        .timestamp()
}

mod token_exchange_for_people {
    use super::*;

    /// A person's profiles: a team's read-only state, and a token for one repo's writers.
    fn with_user_profiles(extra: Value) {
        let mut world = world();
        let policy = world.policy();
        policy["providers"].as_array_mut().unwrap().push(people());
        let profiles = policy["profiles"].as_array_mut().unwrap();
        profiles.push(json!({
            "name": "tofu-plan",
            "provider": "people",
            "claims": { "team_id": TEAM_ID, "repository_permission": "read" },
            "ttl": "30m",
            "buckets": [{ "name": "org-terraform-state", "permission": "object-read-only", "prefixes": ["{repository_owner_id}/{repository_id}/"] }],
        }));
        profiles.push(json!({
            "name": "infra-dns",
            "provider": "people",
            "claims": { "repository_id": "200000002", "repository_permission": "write" },
            "token": { "policies": [{ "permissions": ["DNS Write"], "resources": { (format!("com.cloudflare.api.account.zone.{ZONE_ID}")): "*" } }] },
        }));
        profiles.extend(extra.as_array().unwrap().iter().cloned());
    }

    async fn setup() -> Test {
        let t = start().await;
        with_user_profiles(json!([]));
        t
    }

    fn github_requests() -> Vec<String> {
        world().github.requests.clone()
    }

    #[tokio::test]
    async fn issues_state_credentials_under_the_prefix_githubs_ids_give() {
        let _t = setup().await;
        let res = user_token(
            USER_TOKEN,
            &[("profile", "tofu-plan"), ("repository", "example-org/api")],
        )
        .await;
        assert_eq!(res.status, 200, "{}", res.text);
        let body = res.json();
        assert!(body.get("access_token").is_none());
        assert_matches(
            &body["buckets"][0],
            json!({ "name": "org-terraform-state", "prefixes": [format!("{OWNER_ID}/200000003/")] }),
        );
        assert!(body["expires_at"].as_u64().unwrap() - now() <= 30 * 60 + 1);
    }

    #[tokio::test]
    async fn accepts_a_numeric_repository_id() {
        let _t = setup().await;
        let res = user_token(
            USER_TOKEN,
            &[("profile", "tofu-plan"), ("repository", "200000003")],
        )
        .await;
        assert_eq!(res.status, 200, "{}", res.text);
        assert!(github_requests().contains(&"/repositories/200000003".to_string()));
    }

    #[tokio::test]
    async fn mints_a_token_named_after_the_person_and_the_repo() {
        let _t = setup().await;
        let res = user_token(
            USER_TOKEN,
            &[
                ("profile", "infra-dns"),
                ("repository", "example-org/infra"),
            ],
        )
        .await;
        assert_eq!(res.status, 200, "{}", res.text);
        assert_eq!(
            world().cloudflare.tokens[&token_id(&res)].name,
            "cf-oidc:user:octocat:example-org/infra"
        );
    }

    #[tokio::test]
    async fn writes_audit_lines_with_the_person_without_the_gh_token() {
        let t = setup().await;
        user_token(
            USER_TOKEN,
            &[
                ("profile", "infra-dns"),
                ("repository", "example-org/infra"),
            ],
        )
        .await;
        assert_matches(
            &t.audit("token.mint").await.unwrap(),
            json!({
                "provider": "people",
                "profile": "infra-dns",
                "actor": "octocat",
                "actor_id": USER_ID,
                "repository": "example-org/infra",
                "repository_id": "200000002",
            }),
        );
        assert!(!t.log().contains(USER_TOKEN));
    }

    #[tokio::test]
    async fn refuses_when_several_user_profiles_match_and_none_is_named() {
        let t = setup().await;
        // tofu-plan (team, read) and infra-dns (repo, write) both match example-org/infra.
        assert_eq!(
            user_token(USER_TOKEN, &[("repository", "example-org/infra")])
                .await
                .status,
            403
        );
        let deny = t.deny().await;
        assert_matches(&deny, json!({ "provider": "people" }));
        assert_refused(&deny, "forbidden", "all match the token");
    }

    #[tokio::test]
    async fn never_uses_a_jobs_profile_for_a_person() {
        let t = setup().await;
        // workers-deploy matches repository example-org/*, as this person's claims would.
        let res = user_token(
            USER_TOKEN,
            &[
                ("profile", "workers-deploy"),
                ("repository", "example-org/api"),
            ],
        )
        .await;
        assert_eq!(res.status, 403);
        assert_refused(
            &t.deny().await,
            "forbidden",
            "profile workers-deploy isn't for provider people",
        );
    }

    #[tokio::test]
    async fn never_uses_a_persons_profile_for_a_job() {
        let t = setup().await;
        let res = job_token(&sign(github_claims(json!({}))), &[("profile", "tofu-plan")]).await;
        assert_eq!(res.status, 403);
        let deny = t.deny().await;
        assert_matches(&deny, json!({ "provider": "github" }));
        assert_refused(&deny, "forbidden", "profile ");
    }

    #[tokio::test]
    async fn refuses_without_enough_access_to_the_repo() {
        let t = setup().await;
        // The person can only read example-org/infra; infra-dns needs write on 200000002.
        world().github.repos[0].role = Some("read");
        let res = user_token(
            USER_TOKEN,
            &[
                ("profile", "infra-dns"),
                ("repository", "example-org/infra"),
            ],
        )
        .await;
        assert_eq!(res.status, 403);
        assert_refused(&t.deny().await, "forbidden", "profile ");
        assert_eq!(token_count(), 1);
    }

    #[tokio::test]
    async fn refuses_outside_the_team() {
        let t = setup().await;
        world().github.teams.clear();
        let res = user_token(
            USER_TOKEN,
            &[("profile", "tofu-plan"), ("repository", "example-org/api")],
        )
        .await;
        assert_eq!(res.status, 403);
        assert_refused(&t.deny().await, "forbidden", "profile ");
    }

    #[tokio::test]
    async fn refuses_a_repo_outside_the_pinned_owner_without_looking_up_teams() {
        let t = setup().await;
        let res = user_token(
            USER_TOKEN,
            &[("profile", "tofu-plan"), ("repository", "other-org/infra")],
        )
        .await;
        assert_eq!(res.status, 403);
        assert_error(&res, "forbidden");
        assert_refused(
            &t.deny().await,
            "forbidden",
            "other-org/infra doesn't belong to the owner the provider pins",
        );
        assert!(
            !github_requests()
                .iter()
                .any(|r| r.starts_with("/user/teams"))
        );
    }

    #[tokio::test]
    async fn refuses_a_repo_the_person_cant_see() {
        let t = setup().await;
        assert_eq!(
            user_token(USER_TOKEN, &[("repository", "example-org/secret")])
                .await
                .status,
            403
        );
        assert_refused(
            &t.deny().await,
            "forbidden",
            "the repository doesn't exist, or the token can't see it",
        );
    }

    #[tokio::test]
    async fn looks_up_teams_only_when_a_profile_that_could_match_needs_them() {
        let _t = setup().await;
        user_token(
            USER_TOKEN,
            &[
                ("profile", "infra-dns"),
                ("repository", "example-org/infra"),
            ],
        )
        .await;
        assert!(
            !github_requests()
                .iter()
                .any(|r| r.starts_with("/user/teams"))
        );
    }

    #[tokio::test]
    async fn refuses_a_github_app_installation_token_without_calling_github() {
        let t = setup().await;
        let res = user_token(
            "ghs_exampleInstallationToken000000000000",
            &[("repository", "example-org/api")],
        )
        .await;
        assert_eq!(res.status, 401);
        assert_refused(&t.deny().await, "unauthorized", "installation token");
        assert!(github_requests().is_empty());
    }

    #[tokio::test]
    async fn refuses_a_token_github_rejects() {
        let t = setup().await;
        assert_eq!(
            user_token("gho_revoked", &[("repository", "example-org/api")])
                .await
                .status,
            401
        );
        assert_refused(&t.deny().await, "unauthorized", "GitHub rejected the token");
    }

    #[tokio::test]
    async fn rejects_a_request_without_a_token_without_calling_github() {
        let t = setup().await;
        let res = user_token("", &[("repository", "example-org/api")]).await;
        assert_eq!(res.status, 400);
        assert_refused(&t.deny().await, "bad_request", "");
        assert!(github_requests().is_empty());
    }

    #[tokio::test]
    async fn rejects_a_bad_repository_without_calling_github() {
        let _t = setup().await;
        for repository in ["example-org", "a/b/c", "example org/api"] {
            assert_eq!(
                user_token(USER_TOKEN, &[("repository", repository)])
                    .await
                    .status,
                400,
                "{repository}"
            );
        }
        assert!(github_requests().is_empty());
    }

    #[tokio::test]
    async fn without_a_repository_only_asks_github_who_the_person_is() {
        let t = setup().await;
        // Every profile here needs a role on a repo, so none matches.
        assert_eq!(user_token(USER_TOKEN, &[]).await.status, 403);
        let deny = t.deny().await;
        assert_matches(&deny, json!({ "provider": "people", "actor_id": USER_ID }));
        assert_refused(&deny, "forbidden", "no profile matches the token");
        assert_eq!(github_requests(), ["/user"]);
    }

    #[tokio::test]
    async fn issues_to_a_person_on_a_profiles_list_with_one_github_call() {
        let _t = start().await;
        with_user_profiles(json!([{
            "name": "on-call",
            "provider": "people",
            "claims": { "actor_id": [USER_ID, "300000099"] },
            "buckets": [{ "name": "org-terraform-state", "permission": "object-read-only", "prefixes": ["shared/"] }],
        }]));
        let res = user_token(USER_TOKEN, &[("profile", "on-call")]).await;
        assert_eq!(res.status, 200, "{}", res.text);
        assert_eq!(res.json()["buckets"][0]["prefixes"], json!(["shared/"]));
        assert_eq!(github_requests(), ["/user"]);
    }

    #[tokio::test]
    async fn refuses_a_person_who_isnt_on_the_list() {
        let t = start().await;
        with_user_profiles(json!([{
            "name": "on-call",
            "provider": "people",
            "claims": { "actor_id": "300000099" },
            "buckets": [{ "name": "org-terraform-state", "permission": "object-read-only", "prefixes": ["shared/"] }],
        }]));
        assert_eq!(
            user_token(USER_TOKEN, &[("profile", "on-call")])
                .await
                .status,
            403
        );
        assert_refused(&t.deny().await, "forbidden", "profile ");
    }

    #[tokio::test]
    async fn answers_not_found_when_no_profile_is_for_people_without_calling_github() {
        let _t = start().await;
        assert_eq!(
            user_token(USER_TOKEN, &[("repository", "example-org/api")])
                .await
                .status,
            404
        );
        assert!(github_requests().is_empty());
    }

    #[tokio::test]
    async fn answers_not_found_when_every_profile_for_people_is_disabled() {
        let _t = setup().await;
        for profile in world().policy()["profiles"].as_array_mut().unwrap() {
            if profile["provider"] == "people" {
                profile["enabled"] = json!(false);
            }
        }
        assert_eq!(
            user_token(USER_TOKEN, &[("repository", "example-org/api")])
                .await
                .status,
            404
        );
        assert!(github_requests().is_empty());
    }

    #[tokio::test]
    async fn refuses_when_the_token_cant_list_teams() {
        let t = setup().await;
        // What GitHub answers a classic token without the repo, read:org or user scope.
        world().github.fail = Some(GitHubFailure {
            path: "/user/teams",
            status: 404,
            headers: vec![],
        });
        let res = user_token(
            USER_TOKEN,
            &[("profile", "tofu-plan"), ("repository", "example-org/api")],
        )
        .await;
        assert_eq!(res.status, 403);
        assert_refused(&t.deny().await, "forbidden", "can't list its user's teams");
        assert_eq!(token_count(), 1);
    }

    #[tokio::test]
    async fn refuses_when_the_token_isnt_authorized_for_saml_sso() {
        let t = setup().await;
        world().github.fail = Some(GitHubFailure {
            path: "/repos/",
            status: 403,
            headers: vec![(
                "x-github-sso",
                "required; url=https://github.com/orgs/x/sso",
            )],
        });
        assert_eq!(
            user_token(USER_TOKEN, &[("repository", "example-org/api")])
                .await
                .status,
            403
        );
        assert_refused(&t.deny().await, "forbidden", "SAML SSO");
    }

    #[tokio::test]
    async fn fails_when_github_does() {
        let failures = [
            (403, vec![("x-ratelimit-remaining", "0")]),
            (429, vec![]),
            (503, vec![]),
        ];
        for (status, headers) in failures {
            let t = setup().await;
            world().github.fail = Some(GitHubFailure {
                path: "/user",
                status,
                headers,
            });
            let res = user_token(
                USER_TOKEN,
                &[
                    ("profile", "infra-dns"),
                    ("repository", "example-org/infra"),
                ],
            )
            .await;
            assert_eq!(res.status, 502, "{status}");
            assert_refused(&t.deny().await, "upstream_error", "GitHub: /user");
            drop(t);
        }
    }
}

mod revocation {
    use super::*;

    async fn minted() -> Value {
        job_token(&sign(github_claims(json!({}))), &[]).await.json()
    }

    #[tokio::test]
    async fn deletes_a_token_the_broker_minted() {
        let t = start().await;
        let token = minted().await;
        let res = revoke(token["access_token"].as_str()).await;
        assert_eq!(res.status, 200);
        assert_eq!(res.text, "");
        assert!(
            !world()
                .cloudflare
                .tokens
                .contains_key(token["token_id"].as_str().unwrap())
        );
        assert_matches(
            &t.audit("token.revoke").await.unwrap(),
            json!({ "token_id": token["token_id"] }),
        );
    }

    #[tokio::test]
    async fn succeeds_when_the_token_is_already_gone_or_never_existed() {
        let _t = start().await;
        let token = minted().await;
        revoke(token["access_token"].as_str()).await;
        assert_eq!(revoke(token["access_token"].as_str()).await.status, 200);
        assert_eq!(revoke(Some("never-existed")).await.status, 200);
    }

    #[tokio::test]
    async fn refuses_to_delete_tokens_the_broker_didnt_mint() {
        let _t = start().await;
        let foreign = world()
            .cloudflare
            .add(None, "ci deploy (manual)", None, None, "active");
        assert_eq!(revoke(Some(&foreign.value)).await.status, 403);
        assert!(world().cloudflare.tokens.contains_key(&foreign.id));
    }

    #[tokio::test]
    async fn refuses_to_delete_the_broker_token() {
        let _t = start().await;
        assert_eq!(revoke(Some(BROKER_TOKEN)).await.status, 403);
    }

    #[tokio::test]
    async fn rejects_a_request_without_a_token() {
        let _t = start().await;
        assert_eq!(revoke(None).await.status, 400);
    }

    #[tokio::test]
    async fn rejects_json() {
        let _t = start().await;
        let res = post_raw(
            "/oauth/revoke",
            "application/json",
            json!({ "token": "x" }).to_string(),
        )
        .await;
        assert_eq!(res.status, 400);
    }
}

mod broker_token {
    use super::*;

    #[tokio::test]
    async fn is_read_on_every_use() {
        let _t = start().await;
        let res = job_token(&sign(github_claims(json!({}))), &[]).await;
        assert_eq!(res.status, 200);
        // A rotated secret takes effect on the next request, without a redeploy:
        // the stand-in takes only the original token for anything but verify.
        world().scenario["broker_token"] = json!("BROKER_TOKEN_ROTATED");
        world().cloudflare.add(
            Some("tok-rotated"),
            "cf-oidc broker token (rotated)",
            Some(ROTATED_TOKEN),
            None,
            "active",
        );
        let res = job_token(&sign(github_claims(json!({}))), &[]).await;
        assert_eq!(res.status, 502);
    }

    #[tokio::test]
    async fn fails_closed_when_the_secret_cant_be_read() {
        let t = start().await;
        world().scenario["broker_token"] = json!("BROKER_TOKEN_MISSING");
        let res = job_token(&sign(github_claims(json!({}))), &[]).await;
        assert_eq!(res.status, 500);
        assert_error(&res, "misconfigured");
        assert_refused(
            &t.deny().await,
            "misconfigured",
            "BROKER_TOKEN_MISSING can't be read",
        );
        assert_eq!(token_count(), 1); // nothing minted
    }

    #[tokio::test]
    async fn refuses_a_plain_worker_secret() {
        let t = start().await;
        world().scenario["broker_token"] = json!("BROKER_TOKEN_PLAIN");
        let res = job_token(&sign(github_claims(json!({}))), &[]).await;
        assert_eq!(res.status, 500);
        assert_error(&res, "misconfigured");
        assert!(!res.text.contains("BROKER_TOKEN_PLAIN"), "{}", res.text);
        // Refused with the configuration, before any route: the log says why.
        assert!(
            t.log()
                .contains("misconfigured: BROKER_TOKEN_PLAIN must be a Secrets Store binding"),
            "{}",
            t.log()
        );
        assert!(world().cloudflare.calls().is_empty());
    }
}

mod health {
    use cf_oidc_exchange_sdk::v1::HealthClient;

    use super::*;

    #[tokio::test]
    async fn is_live_and_ready() {
        let _t = start().await;
        let health = HealthClient::new(BROKER);
        assert!(health.is_live().await.expect("the request failed"));
        assert!(health.is_ready().await.expect("the request failed"));
        assert_eq!(
            call(Method::GET, "/health/ready")
                .await
                .cache_control
                .as_deref(),
            Some("no-store")
        );
    }

    /// Misconfigured, the Worker serves nothing, the health endpoints
    /// included, so a broken deploy shows on its probes.
    #[tokio::test]
    async fn is_neither_live_nor_ready_when_misconfigured() {
        let _t = start().await;
        world().scenario["policy"] = json!("{");
        let health = HealthClient::new(BROKER);
        assert!(!health.is_live().await.expect("the request failed"));
        assert!(!health.is_ready().await.expect("the request failed"));
        let res = call(Method::GET, "/health/ready").await;
        assert_eq!(res.status, 500);
        assert_error(&res, "misconfigured");
    }
}

mod exchange_requests {
    use super::*;

    #[tokio::test]
    async fn exchanges_a_jobs_oidc_token_for_a_cloudflare_api_token() {
        let t = start().await;
        let before = now();
        let res = job_token(
            &sign(github_claims(json!({}))),
            &[("profile", "workers-deploy")],
        )
        .await;
        assert_eq!(res.status, 200);
        let body = res.json();
        assert_eq!(
            body,
            json!({
                "access_token": body["access_token"],
                "issued_token_type": ACCESS_TOKEN,
                "token_type": "Bearer",
                "expires_in": body["expires_in"],
                "expires_at": body["expires_at"],
                "token_id": body["token_id"],
                "account_id": ACCOUNT_ID,
                "profile": "workers-deploy",
            })
        );
        let expires_in = body["expires_in"].as_u64().unwrap();
        assert!(expires_in > 14 * 60 && expires_in <= 15 * 60);
        assert!(body["expires_at"].as_u64().unwrap() - before <= 15 * 60 + 1);
        assert_matches(
            &t.audit("token.mint").await.unwrap(),
            json!({ "provider": "github", "profile": "workers-deploy", "token_id": body["token_id"] }),
        );
    }

    #[tokio::test]
    async fn accepts_the_jwt_token_type_and_the_cloudflare_audience() {
        let _t = start().await;
        let jwt = sign(github_claims(json!({})));
        let res = post_form(
            "/oauth/token",
            &[
                ("grant_type", GRANT),
                ("subject_token", &jwt),
                ("subject_token_type", JWT_TYPE),
                ("audience", "https://api.cloudflare.com"),
            ],
        )
        .await;
        assert_eq!(res.status, 200, "{}", res.text);
        assert_eq!(res.json()["profile"], "workers-deploy");
    }

    #[tokio::test]
    async fn rejects_what_it_doesnt_support_without_calling_anyone() {
        type Case<'a> = (&'a str, &'a [(&'a str, &'a str)], &'a str);
        let cases: [Case; 6] = [
            (
                "another grant type",
                &[("grant_type", "client_credentials")],
                "",
            ),
            ("no subject token", &[("subject_token", "")], ""),
            (
                "an unsupported subject token type",
                &[(
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:saml2",
                )],
                "",
            ),
            (
                "another audience",
                &[("audience", "https://cache.example.com")],
                "no profile is for audience",
            ),
            (
                "an actor token",
                &[("actor_token", "x"), ("actor_token_type", ID_TOKEN)],
                "",
            ),
            (
                "an unsupported requested token type",
                &[(
                    "requested_token_type",
                    "urn:ietf:params:oauth:token-type:refresh_token",
                )],
                "",
            ),
        ];
        for (case, overrides, says) in cases {
            let t = start().await;
            let mut form: Vec<(&str, &str)> = vec![
                ("grant_type", GRANT),
                ("subject_token", "not-checked"),
                ("subject_token_type", ID_TOKEN),
            ];
            for (key, value) in overrides {
                form.retain(|(k, _)| k != key);
                form.push((key, value));
            }
            let res = post_form("/oauth/token", &form).await;
            assert_eq!(res.status, 400, "{case}");
            assert_error(&res, "bad_request");
            let deny = t.deny().await;
            assert_eq!(deny["error"], "bad_request", "{case}: {deny}");
            assert!(
                deny["message"].as_str().unwrap_or_default().contains(says),
                "{case}: {deny}"
            );
            assert!(world().github.requests.is_empty(), "{case}");
            assert!(world().cloudflare.calls().is_empty(), "{case}");
            drop(t);
        }
    }

    #[tokio::test]
    async fn rejects_a_body_thats_not_form_encoded() {
        for content_type in ["application/json", "text/plain"] {
            let t = start().await;
            let res = post_raw(
                "/oauth/token",
                content_type,
                json!({ "grant_type": GRANT }).to_string(),
            )
            .await;
            assert_eq!(res.status, 400, "{content_type}");
            assert_refused(
                &t.deny().await,
                "bad_request",
                "the body must be form-encoded",
            );
            drop(t);
        }
    }

    #[tokio::test]
    async fn refuses_a_token_that_isnt_a_valid_oidc_token() {
        let t = start().await;
        let res = job_token("not-a-jwt", &[]).await;
        assert_eq!(res.status, 401);
        assert_refused(
            &t.deny().await,
            "unauthorized",
            "the subject token isn't valid: not a JWT",
        );
        assert!(world().cloudflare.calls().is_empty());
    }
}

mod providers {
    use super::*;

    /// A GitLab CI job's claims, in GitLab's names.
    fn gitlab_claims(overrides: Value) -> Value {
        let mut claims = json!({
            "sub": "project_path:group/app:ref_type:branch:ref:main",
            "namespace_id": "4000001",
            "project_id": "500000001",
            "project_path": "group/app",
            "ref": "main",
            "ref_protected": "true",
        });
        merge(&mut claims, overrides);
        claims
    }

    /// A GitLab stand-in at a fresh issuer, with a profile for Cloudflare and one for the cache.
    async fn setup() -> (Test, String) {
        let t = start().await;
        let gitlab = fresh_issuer("gitlab");
        {
            let mut world = world();
            let policy = world.policy();
            policy["providers"].as_array_mut().unwrap().push(json!({
                "name": "gitlab", "issuer": gitlab, "audience": AUDIENCE, "claims": { "namespace_id": "4000001" },
            }));
            let profiles = policy["profiles"].as_array_mut().unwrap();
            profiles.push(json!({ "name": "gitlab-deploy", "provider": "gitlab", "claims": { "project_path": "group/app", "ref_protected": "true" }, "token": deploy_token() }));
            profiles.push(json!({ "name": "gitlab-cache", "provider": "gitlab", "audience": CACHE, "claims": { "project_path": "group/*" } }));
        }
        (t, gitlab)
    }

    fn gitlab_token(gitlab: &str, claims: Value) -> String {
        sign_with(gitlab, claims, AUDIENCE, 300)
    }

    #[tokio::test]
    async fn exchanges_another_issuers_token_found_by_its_iss_and_checked_with_its_keys() {
        let (t, gitlab) = setup().await;
        let res = job_token(&gitlab_token(&gitlab, gitlab_claims(json!({}))), &[]).await;
        assert_eq!(res.status, 200, "{}", res.text);
        assert_eq!(res.json()["profile"], "gitlab-deploy");
        // Named after the provider and the token's subject: GitLab's has no repo or run.
        assert_eq!(
            world().cloudflare.tokens[&token_id(&res)].name,
            "cf-oidc:gitlab:project_path:group/app:ref_type:branch:ref:main"
        );
        assert_matches(
            &t.audit("token.mint").await.unwrap(),
            json!({ "provider": "gitlab", "profile": "gitlab-deploy", "sub": "project_path:group/app:ref_type:branch:ref:main" }),
        );
    }

    #[tokio::test]
    async fn holds_every_token_to_its_providers_claims() {
        let (t, gitlab) = setup().await;
        let res = job_token(
            &gitlab_token(&gitlab, gitlab_claims(json!({ "namespace_id": "4000002" }))),
            &[],
        )
        .await;
        assert_eq!(res.status, 403);
        let deny = t.deny().await;
        assert_matches(&deny, json!({ "provider": "gitlab" }));
        assert_refused(&deny, "forbidden", "no profile matches the token");
    }

    #[tokio::test]
    async fn never_gives_a_token_from_one_provider_anothers_profile() {
        let (t, gitlab) = setup().await;
        let res = job_token(
            &gitlab_token(&gitlab, gitlab_claims(json!({}))),
            &[("profile", "workers-deploy")],
        )
        .await;
        assert_eq!(res.status, 403);
        assert_refused(
            &t.deny().await,
            "forbidden",
            "profile workers-deploy isn't for provider gitlab",
        );
    }

    #[tokio::test]
    async fn refuses_a_token_from_an_issuer_no_provider_is_for() {
        let (t, _) = setup().await;
        let jwt = sign_with(
            "https://other.example.com",
            github_claims(json!({})),
            AUDIENCE,
            300,
        );
        assert_eq!(job_token(&jwt, &[]).await.status, 401);
        assert_refused(
            &t.deny().await,
            "unauthorized",
            "no provider is for issuer https://other.example.com",
        );
    }

    #[tokio::test]
    async fn fails_when_the_discovery_document_names_another_issuer() {
        let (t, gitlab) = setup().await;
        let name = gitlab.rsplit('/').next().unwrap().to_string();
        world().discovery.insert(name, json!({ "issuer": "https://evil.example.com", "jwks_uri": format!("{gitlab}/.well-known/jwks") }));
        assert_eq!(
            job_token(&gitlab_token(&gitlab, gitlab_claims(json!({}))), &[])
                .await
                .status,
            502
        );
        let deny = t.deny().await;
        assert_refused(
            &deny,
            "upstream_error",
            "is for issuer https://evil.example.com",
        );
    }

    #[tokio::test]
    async fn takes_the_keys_from_jwks_uri_when_its_set_not_from_discovery() {
        let (_t, gitlab) = setup().await;
        let name = gitlab.rsplit('/').next().unwrap().to_string();
        {
            let mut world = world();
            // Discovery would fail; jwks_uri never reads it.
            world
                .discovery
                .insert(name, json!({ "issuer": "https://evil.example.com" }));
            world.policy()["providers"][1]["jwks_uri"] =
                json!(format!("{gitlab}/.well-known/jwks"));
        }
        let res = job_token(&gitlab_token(&gitlab, gitlab_claims(json!({}))), &[]).await;
        assert_eq!(res.status, 200, "{}", res.text);
    }

    #[tokio::test]
    async fn issues_another_providers_caller_a_service_token_with_the_matched_claims() {
        let (_t, gitlab) = setup().await;
        let res = job_token(
            &gitlab_token(&gitlab, gitlab_claims(json!({}))),
            &[("audience", CACHE)],
        )
        .await;
        assert_eq!(res.status, 200, "{}", res.text);
        let (_, claims) = verify_broker_token(res.json()["access_token"].as_str().unwrap()).await;
        assert_matches(
            &claims,
            json!({
                "iss": AUDIENCE,
                "aud": CACHE,
                "sub": "project_path:group/app:ref_type:branch:ref:main",
                "provider": "gitlab",
                "profile": "gitlab-cache",
                // What the policy matched on, so the service can match on it too.
                "project_path": "group/app",
                "namespace_id": "4000001",
            }),
        );
        // Claims nobody matched on stay behind.
        assert!(claims.get("project_id").is_none());
    }
}

mod tokens_for_other_services {
    use super::*;

    async fn setup() -> Test {
        let t = start().await;
        let mut world = world();
        let policy = world.policy();
        policy["providers"].as_array_mut().unwrap().push(people());
        let profiles = policy["profiles"].as_array_mut().unwrap();
        profiles.push(json!({ "name": "nix-push", "provider": "github", "audience": CACHE, "claims": { "ref": "refs/heads/main" }, "ttl": "15m" }));
        profiles.push(json!({ "name": "nix-push-people", "provider": "people", "audience": CACHE, "claims": { "repository_permission": "write" }, "ttl": "30m" }));
        drop(world);
        t
    }

    async fn for_cache(subject_token: &str, token_type: &str, extra: &[(&str, &str)]) -> Reply {
        let mut form = vec![
            ("grant_type", GRANT),
            ("subject_token", subject_token),
            ("subject_token_type", token_type),
            ("audience", CACHE),
        ];
        form.extend_from_slice(extra);
        post_form("/oauth/token", &form).await
    }

    #[tokio::test]
    async fn issues_a_job_a_token_the_service_can_verify_with_the_brokers_keys() {
        let t = setup().await;
        let sub = "repo:example-org/api:environment:prod";
        let res = for_cache(&sign(github_claims(json!({ "sub": sub }))), ID_TOKEN, &[]).await;
        assert_eq!(res.status, 200, "{}", res.text);
        let body = res.json();
        assert_eq!(
            body,
            json!({
                "access_token": body["access_token"],
                "issued_token_type": JWT_TYPE,
                "token_type": "Bearer",
                "expires_in": body["expires_in"],
                "expires_at": body["expires_at"],
                "profile": "nix-push",
            })
        );
        let (header, claims) = verify_broker_token(body["access_token"].as_str().unwrap()).await;
        assert_matches(&header, json!({ "alg": "RS256", "typ": "JWT" }));
        assert_matches(
            &claims,
            json!({
                "iss": AUDIENCE,
                "aud": CACHE,
                "sub": sub,
                "provider": "github",
                "profile": "nix-push",
                "repository": "example-org/api",
                "repository_owner_id": OWNER_ID,
                "ref": "refs/heads/main",
                "run_id": "1234567890",
            }),
        );
        assert!(claims["jti"].is_string());
        // Only the identity: no API token, no R2 credentials.
        assert!(world().cloudflare.calls().is_empty());
        assert_matches(
            &t.audit("token.issue").await.unwrap(),
            json!({ "provider": "github", "profile": "nix-push", "audience": CACHE, "jti": claims["jti"] }),
        );
    }

    #[tokio::test]
    async fn never_outlives_the_jobs_oidc_token() {
        let _t = setup().await;
        let before = now();
        let jwt = sign_with(&issuer("actions"), github_claims(json!({})), AUDIENCE, 120);
        let body = for_cache(&jwt, ID_TOKEN, &[]).await.json();
        // The profile's ttl is 15m; the GitHub token's 2m wins.
        let lives = body["expires_at"].as_u64().unwrap() - before;
        assert!(lives > 60 && lives <= 2 * 60 + 1, "{lives}");
    }

    #[tokio::test]
    async fn issues_a_person_a_token_named_after_their_github_user() {
        let _t = setup().await;
        let before = now();
        let res = for_cache(
            USER_TOKEN,
            ACCESS_TOKEN,
            &[("repository", "example-org/infra")],
        )
        .await;
        assert_eq!(res.status, 200, "{}", res.text);
        let body = res.json();
        let (_, claims) = verify_broker_token(body["access_token"].as_str().unwrap()).await;
        assert_matches(
            &claims,
            json!({
                "sub": format!("user:{USER_ID}"),
                "actor": "octocat",
                "repository": "example-org/infra",
                "repository_permission": "write",
                "profile": "nix-push-people",
            }),
        );
        // A GitHub user token doesn't expire, so the profile's 30m applies.
        let lives = body["expires_at"].as_u64().unwrap() - before;
        assert!(lives > 29 * 60 && lives <= 30 * 60 + 1, "{lives}");
    }

    #[tokio::test]
    async fn publishes_a_discovery_document_and_only_the_public_key() {
        let _t = setup().await;
        let res = call(Method::GET, "/.well-known/openid-configuration").await;
        assert_eq!(res.status, 200);
        assert_eq!(res.cache_control.as_deref(), Some("public, max-age=300"));
        assert_matches(
            &res.json(),
            json!({
                "issuer": AUDIENCE,
                "jwks_uri": format!("{AUDIENCE}/.well-known/jwks"),
                "token_endpoint": format!("{AUDIENCE}/oauth/token"),
                "revocation_endpoint": format!("{AUDIENCE}/oauth/revoke"),
                "grant_types_supported": [GRANT],
                "id_token_signing_alg_values_supported": ["RS256"],
            }),
        );

        let jwks = call(Method::GET, "/.well-known/jwks").await.json();
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        // Only the public members: no d, p, q or the CRT values.
        let mut members: Vec<&String> = keys[0].as_object().unwrap().keys().collect();
        members.sort();
        assert_eq!(members, ["alg", "e", "kid", "kty", "n", "use"]);
        let res = for_cache(&sign(github_claims(json!({}))), ID_TOKEN, &[]).await;
        let (header, _) = verify_broker_token(res.json()["access_token"].as_str().unwrap()).await;
        assert_eq!(header["kid"], keys[0]["kid"]);
    }

    #[tokio::test]
    async fn rejects_an_audience_no_profile_is_for_without_verifying_anything() {
        let t = setup().await;
        let res = post_form(
            "/oauth/token",
            &[
                ("grant_type", GRANT),
                ("subject_token", "not-checked"),
                ("subject_token_type", ID_TOKEN),
                ("audience", "https://other.example.com"),
            ],
        )
        .await;
        assert_eq!(res.status, 400);
        assert_refused(&t.deny().await, "bad_request", "no profile is for audience");
        assert!(world().github.requests.is_empty());
    }

    #[tokio::test]
    async fn refuses_a_cloudflare_profile_named_for_the_service() {
        let t = setup().await;
        let res = for_cache(
            &sign(github_claims(json!({}))),
            ID_TOKEN,
            &[("profile", "workers-deploy")],
        )
        .await;
        assert_eq!(res.status, 403);
        assert_refused(
            &t.deny().await,
            "forbidden",
            &format!("profile workers-deploy isn't for {CACHE}"),
        );
    }

    #[tokio::test]
    async fn rejects_a_cloudflare_token_type_requested_for_the_service() {
        let _t = setup().await;
        let res = for_cache(
            &sign(github_claims(json!({}))),
            ID_TOKEN,
            &[("requested_token_type", R2_CREDENTIALS)],
        )
        .await;
        assert_eq!(res.status, 400);
    }

    #[tokio::test]
    async fn fails_closed_without_a_signing_key_and_leaves_cloudflare_profiles_working() {
        let t = setup().await;
        world().scenario["signing_key"] = json!("SIGNING_KEY_UNBOUND");
        let res = for_cache(&sign(github_claims(json!({}))), ID_TOKEN, &[]).await;
        assert_eq!(res.status, 500);
        assert_error(&res, "misconfigured");
        assert_refused(
            &t.deny().await,
            "misconfigured",
            "SIGNING_KEY_UNBOUND isn't bound",
        );

        assert_eq!(
            job_token(&sign(github_claims(json!({}))), &[]).await.status,
            200
        );
        // Nothing to publish without a key.
        assert_eq!(
            call(Method::GET, "/.well-known/jwks").await.json(),
            json!({ "keys": [] })
        );
    }

    #[tokio::test]
    async fn fails_closed_on_a_signing_key_that_isnt_an_rsa_pkcs8_pem() {
        let t = setup().await;
        world().scenario["signing_key"] = json!("SIGNING_KEY_NOT_PEM");
        assert_eq!(
            for_cache(&sign(github_claims(json!({}))), ID_TOKEN, &[])
                .await
                .status,
            500
        );
        assert_refused(
            &t.deny().await,
            "misconfigured",
            "the signing key: not an RSA private key in PKCS#8 PEM",
        );
    }

    #[tokio::test]
    async fn fails_closed_on_an_rsa_key_under_2048_bits() {
        let t = setup().await;
        world().scenario["signing_key"] = json!("SIGNING_KEY_SMALL");
        assert_eq!(
            for_cache(&sign(github_claims(json!({}))), ID_TOKEN, &[])
                .await
                .status,
            500
        );
        assert_refused(
            &t.deny().await,
            "misconfigured",
            "the signing key: RSA key is 1024 bits, at least 2048 needed",
        );
    }
}

#[tokio::test]
async fn answers_not_found_on_unknown_routes_including_the_removed_v1_routes() {
    let _t = start().await;
    for path in [
        "/v1/token",
        "/v1/actions/token",
        "/v1/users/token",
        "/v1/user/token",
        "/v1/revoke",
    ] {
        let res = post_form(path, &[]).await;
        assert_eq!(res.status, 404, "{path}");
        assert_error(&res, "not_found");
    }
    assert_eq!(call(Method::GET, "/oauth/token").await.status, 404);
    assert_eq!(call(Method::GET, "/").await.status, 404);
}

#[tokio::test]
async fn the_scheduled_cleanup_deletes_only_expired_broker_tokens() {
    let _t = start().await;
    let at = |offset: i64| {
        chrono::DateTime::from_timestamp(now() as i64 + offset, 0)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    };
    let (expired, live, foreign) = {
        let mut world = world();
        let cf = &mut world.cloudflare;
        (
            cf.add(
                None,
                "cf-oidc:example-org/api:1:1",
                None,
                Some(at(-60)),
                "expired",
            ),
            cf.add(
                None,
                "cf-oidc:example-org/api:2:1",
                None,
                Some(at(60)),
                "active",
            ),
            cf.add(None, "someone else's", None, Some(at(-60)), "expired"),
        )
    };
    let res = call(Method::GET, "/__scheduled?cron=17+*+*+*+*").await;
    assert_eq!(res.status, 200, "{}", res.text);
    let world = world();
    assert!(!world.cloudflare.tokens.contains_key(&expired.id));
    assert!(world.cloudflare.tokens.contains_key(&live.id));
    assert!(world.cloudflare.tokens.contains_key(&foreign.id));
    assert!(
        world
            .cloudflare
            .requests
            .iter()
            .any(|r| r.method == "GET" && r.path.ends_with("/tokens"))
    );
}
