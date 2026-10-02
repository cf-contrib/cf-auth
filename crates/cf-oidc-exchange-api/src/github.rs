//! People's GitHub tokens (`gh auth token`): opaque, so they're checked with
//! GitHub's API, which also says who the person is and what they can do.

use std::time::Duration;

use cf_oidc_exchange_sdk::v1::{Error, ErrorCode};
use futures_util::future::join;
use reqwest::{StatusCode, header::HeaderMap};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;

use crate::service::config::Claims;

pub const API_URL: &str = "https://api.github.com";

/// `/user/teams` pages of 100 to read at most. Past this, teams further down never match.
const MAX_TEAM_PAGES: u32 = 10;

const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// What a `403` or `404` from GitHub means for each lookup.
const USER_DENIED: &str = "GitHub won't say whose the token is";
const REPOSITORY_DENIED: &str = "the repository doesn't exist, or the token can't see it";
const TEAMS_DENIED: &str =
    "the token can't list its user's teams: it needs the repo, read:org or user scope";

/// GitHub's permission flags, most to least, under the policy's names for them.
const ROLES: [(&str, &str); 5] = [
    ("admin", "admin"),
    ("maintain", "maintain"),
    ("push", "write"),
    ("triage", "triage"),
    ("pull", "read"),
];

#[derive(Deserialize)]
struct User {
    id: u64,
    login: String,
}

#[derive(Deserialize)]
struct Owner {
    id: u64,
    login: String,
}

#[derive(Deserialize)]
struct Repository {
    id: u64,
    full_name: String,
    owner: Owner,
    #[serde(default)]
    permissions: Option<serde_json::Map<String, Value>>,
}

#[derive(Deserialize)]
struct Organization {
    id: u64,
}

#[derive(Deserialize)]
struct Team {
    id: u64,
    organization: Option<Organization>,
}

/// What to check besides the token.
pub struct UserCheck<'a> {
    /// The owners a requested repo must belong to: the provider's `repository_owner_id` pin.
    pub owner_ids: &'a [String],
    /// Whether a profile could match on `team_id`. Otherwise the teams aren't looked up.
    pub teams: bool,
}

/// Checks a person's GitHub token and returns their claims, as GitHub reports
/// them: who they are and, for a `repository`, the repo's IDs, their role on it
/// and, if asked, the IDs of their teams in the pinned owners. Nothing in the
/// claims comes from the request except which repo to look up.
pub async fn verify_user(
    api: &str,
    token: &str,
    repository: Option<&str>,
    check: UserCheck<'_>,
) -> Result<Claims, Error> {
    let github = GitHub { api, token };
    // GITHUB_TOKEN and other installation tokens identify a repo, not a person.
    if token.starts_with("ghs_") {
        return Err(Error::new(
            ErrorCode::Unauthorized,
            "a GitHub App installation token identifies a repo, not a person: GitHub Actions jobs exchange their OIDC token instead",
        ));
    }

    let mut claims = Claims::new();
    // Without a repo, only who the person is: one call, for profiles that list who may use them.
    let Some(repository) = repository else {
        let user: User = github.get("/user", USER_DENIED).await?;
        claims.insert("actor".into(), user.login.into());
        claims.insert("actor_id".into(), user.id.to_string().into());
        return Ok(claims);
    };
    if check.owner_ids.is_empty() {
        return Err(Error::new(
            ErrorCode::Forbidden,
            "the provider for people pins no repository_owner_id, so it takes no repository",
        ));
    }

    let path = if repository.bytes().all(|b| b.is_ascii_digit()) {
        format!("/repositories/{repository}")
    } else {
        format!("/repos/{repository}")
    };
    // Both at once, but a bad token is reported as that, not as whatever the repo lookup said.
    let (user, repo) = join(
        github.get::<User>("/user", USER_DENIED),
        github.get::<Repository>(&path, REPOSITORY_DENIED),
    )
    .await;
    let (user, repo) = (user?, repo?);

    // Checked here rather than left to the owner pin, so another org's repo costs no team lookups.
    let owner_id = repo.owner.id.to_string();
    if !check.owner_ids.contains(&owner_id) {
        return Err(Error::new(
            ErrorCode::Forbidden,
            format!(
                "{} doesn't belong to the owner the provider pins",
                repo.full_name
            ),
        ));
    }

    claims.insert("actor".into(), user.login.into());
    claims.insert("actor_id".into(), user.id.to_string().into());
    claims.insert("repository".into(), repo.full_name.into());
    claims.insert("repository_id".into(), repo.id.to_string().into());
    claims.insert("repository_owner".into(), repo.owner.login.into());
    claims.insert("repository_owner_id".into(), owner_id.into());
    if let Some(role) = role(repo.permissions.as_ref()) {
        claims.insert("repository_permission".into(), role.into());
    }
    if check.teams {
        let ids = github.team_ids(check.owner_ids).await?;
        claims.insert("team_ids".into(), ids.into());
    }
    Ok(claims)
}

/// A person's role on a repo: the highest of GitHub's permission flags they have.
fn role(permissions: Option<&serde_json::Map<String, Value>>) -> Option<&'static str> {
    let permissions = permissions?;
    ROLES
        .iter()
        .find(|(flag, _)| permissions.get(*flag) == Some(&Value::Bool(true)))
        .map(|(_, role)| *role)
}

struct GitHub<'a> {
    api: &'a str,
    token: &'a str,
}

impl GitHub<'_> {
    /// IDs of the caller's teams in the pinned owners. GitHub accepts `repo`,
    /// `read:org` or `user` for it, and gh's token has `repo`.
    async fn team_ids(&self, owner_ids: &[String]) -> Result<Vec<String>, Error> {
        let mut ids = Vec::new();
        for page in 1..=MAX_TEAM_PAGES {
            let path = format!("/user/teams?per_page=100&page={page}");
            let teams: Vec<Team> = self.get(&path, TEAMS_DENIED).await?;
            for team in &teams {
                let org = team.organization.as_ref().map(|org| org.id.to_string());
                if org.is_some_and(|org| owner_ids.contains(&org)) {
                    ids.push(team.id.to_string());
                }
            }
            if teams.len() < 100 {
                break;
            }
        }
        Ok(ids)
    }

    /// GETs a GitHub API path with the caller's token. `denied` is what a `403`
    /// or `404` means.
    async fn get<T: DeserializeOwned>(&self, path: &str, denied: &'static str) -> Result<T, Error> {
        let unavailable =
            |why: String| Error::new(ErrorCode::UpstreamError, format!("GitHub: {why}"));
        let response = reqwest::Client::new()
            .get(format!("{}{path}", self.api))
            .bearer_auth(self.token)
            .header("accept", "application/vnd.github+json")
            .header("user-agent", "cf-oidc-exchange")
            .header("x-github-api-version", "2022-11-28")
            .timeout(FETCH_TIMEOUT)
            .send()
            .await
            .map_err(|err| unavailable(format!("{path}: {err}")))?;
        let status = response.status();
        if !status.is_success() {
            return Err(failure(status, response.headers(), path, denied));
        }
        response
            .json()
            .await
            .map_err(|_| unavailable(format!("{path}: response isn't JSON")))
    }
}

/// Maps a GitHub API error status to the broker's.
fn failure(status: StatusCode, headers: &HeaderMap, path: &str, denied: &'static str) -> Error {
    let rate_limited = status == StatusCode::TOO_MANY_REQUESTS
        || (status == StatusCode::FORBIDDEN
            && headers
                .get("x-ratelimit-remaining")
                .is_some_and(|v| v == "0"));
    if status == StatusCode::UNAUTHORIZED {
        return Error::new(ErrorCode::Unauthorized, "GitHub rejected the token");
    }
    if rate_limited {
        return Error::new(
            ErrorCode::UpstreamError,
            format!("GitHub: {path}: rate limited"),
        );
    }
    if status == StatusCode::FORBIDDEN && headers.contains_key("x-github-sso") {
        return Error::new(
            ErrorCode::Forbidden,
            "the token isn't authorized for the organization's SAML SSO: authorize it on GitHub",
        );
    }
    if status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND {
        return Error::new(ErrorCode::Forbidden, denied);
    }
    Error::new(
        ErrorCode::UpstreamError,
        format!("GitHub: {path}: returned {}", status.as_u16()),
    )
}

#[cfg(test)]
mod tests {
    use reqwest::header::HeaderValue;
    use serde_json::json;

    use super::*;

    #[test]
    fn takes_the_highest_role() {
        let flags = |value: Value| value.as_object().cloned();
        let all = flags(
            json!({ "admin": false, "maintain": false, "push": true, "triage": true, "pull": true }),
        );
        assert_eq!(role(all.as_ref()), Some("write"));
        assert_eq!(role(flags(json!({ "pull": true })).as_ref()), Some("read"));
        assert_eq!(role(flags(json!({ "pull": false })).as_ref()), None);
        assert_eq!(role(None), None);
    }

    #[test]
    fn maps_githubs_errors() {
        let failed = |status: u16, headers: &[(&'static str, &'static str)]| {
            let mut map = HeaderMap::new();
            for (name, value) in headers {
                map.insert(*name, HeaderValue::from_static(value));
            }
            failure(
                StatusCode::from_u16(status).unwrap(),
                &map,
                "/user",
                "denied",
            )
        };
        let rejected = failed(401, &[]);
        assert_eq!(
            (rejected.error, rejected.message.as_str()),
            (ErrorCode::Unauthorized, "GitHub rejected the token")
        );
        for (status, headers) in [(403, vec![("x-ratelimit-remaining", "0")]), (429, vec![])] {
            let limited = failed(status, &headers);
            assert_eq!(
                (limited.error, limited.message.as_str()),
                (ErrorCode::UpstreamError, "GitHub: /user: rate limited")
            );
        }
        let sso = failed(403, &[("x-github-sso", "required; url=x")]);
        assert_eq!(sso.error, ErrorCode::Forbidden);
        assert!(sso.message.contains("SAML SSO"), "{}", sso.message);
        for status in [403, 404] {
            let denied = failed(status, &[]);
            assert_eq!(
                (denied.error, denied.message.as_str()),
                (ErrorCode::Forbidden, "denied")
            );
        }
        let down = failed(503, &[]);
        assert_eq!(
            (down.error, down.message.as_str()),
            (ErrorCode::UpstreamError, "GitHub: /user: returned 503")
        );
    }
}
