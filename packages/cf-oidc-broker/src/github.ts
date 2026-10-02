import type { components } from "@octokit/openapi-types";
import { HttpError } from "./errors.js";
import type { Claims, RepositoryPermission } from "./policy.js";

const API_URL = "https://api.github.com";

/** `/user/teams` pages of 100 to read at most. Past this, teams further down never match. */
const MAX_TEAM_PAGES = 10;

/** A repository as a person's request names it: `owner/name` or its numeric ID. */
export const REPOSITORY = /^(?:[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+|\d+)$/;

type Team = components["schemas"]["team-full"];
// GET /user returns the private shape for the token's own user; both have id and login.
type User = components["schemas"]["public-user"];
type Repository = components["schemas"]["full-repository"];

/** GitHub's permission flags, most to least, under the policy's names for them. */
const ROLES: [keyof NonNullable<Repository["permissions"]>, RepositoryPermission][] = [
  ["admin", "admin"],
  ["maintain", "maintain"],
  ["push", "write"],
  ["triage", "triage"],
  ["pull", "read"],
];

export interface UserCheck {
  /** `github.owner_id`: the repo must belong to it. */
  ownerId: string;
  /** Whether a profile could match on `team_id`. Otherwise the teams aren't looked up. */
  teams: boolean;
}

/**
 * Checks a person's GitHub user token (`gh auth token`) and returns their claims for
 * `repository`, as GitHub reports them: who they are, the repo's IDs, their role on
 * it and, if asked, the IDs of their teams in the pinned owner. Nothing in the claims
 * comes from the request except which repo to look up.
 */
export async function verifyGitHubUser(token: string, repository: string, check: UserCheck): Promise<Claims> {
  // GITHUB_TOKEN and other installation tokens identify a repo, not a person.
  if (token.startsWith("ghs_")) {
    throw new HttpError("unauthorized", "installation_token", "GitHub Actions jobs exchange their OIDC token instead");
  }

  const repoPath = /^\d+$/.test(repository) ? `/repositories/${repository}` : `/repos/${repository}`;
  // Both at once, but a bad token is reported as that, not as whatever the repo lookup said.
  const [userResult, repoResult] = await Promise.allSettled([
    get<User>("/user", token, "invalid_user_token"),
    get<Repository>(repoPath, token, "repository_forbidden"),
  ]);
  if (userResult.status === "rejected") throw userResult.reason;
  if (repoResult.status === "rejected") throw repoResult.reason;
  const user = userResult.value;
  const repo = repoResult.value;

  // Checked here rather than left to the owner pin, so another org's repo costs no team lookups.
  if (String(repo.owner.id) !== check.ownerId) {
    throw new HttpError("forbidden", "repository_forbidden", `${repo.full_name} is outside the pinned owner`);
  }

  const role = ROLES.find(([flag]) => repo.permissions?.[flag] === true)?.[1];
  const claims: Claims = {
    actor: user.login,
    actor_id: String(user.id),
    repository: repo.full_name,
    repository_id: String(repo.id),
    repository_owner: repo.owner.login,
    repository_owner_id: String(repo.owner.id),
  };
  if (role) claims.repository_permission = role;
  if (check.teams) claims.team_ids = await teamIds(token, check.ownerId);
  return claims;
}

/** IDs of the caller's teams in the owner. GitHub accepts `repo`, `read:org` or `user` for it, and gh's token has `repo`. */
async function teamIds(token: string, ownerId: string): Promise<string[]> {
  const ids: string[] = [];
  for (let page = 1; page <= MAX_TEAM_PAGES; page++) {
    const teams = await get<Team[]>(`/user/teams?per_page=100&page=${page}`, token, "teams_forbidden");
    for (const team of teams) {
      if (String(team.organization?.id) === ownerId) ids.push(String(team.id));
    }
    if (teams.length < 100) break;
  }
  return ids;
}

/** GETs a GitHub API path with the caller's token. `denied` is the reason for a `403` or `404`. */
async function get<T>(path: string, token: string, denied: string): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, {
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${token}`,
        "user-agent": "cf-oidc-broker",
        "x-github-api-version": "2022-11-28",
      },
      signal: AbortSignal.timeout(10_000),
    });
  } catch (err) {
    throw new HttpError("upstream_error", "github_unavailable", `${path}: ${(err as Error).message}`);
  }
  if (!res.ok) throw failure(res, path, denied);
  try {
    return (await res.json()) as T;
  } catch {
    throw new HttpError("upstream_error", "github_unavailable", `${path}: response isn't JSON`);
  }
}

/** Maps a GitHub API error status to the broker's. */
function failure(res: Response, path: string, denied: string): HttpError {
  const rateLimited = res.status === 429 || (res.status === 403 && res.headers.get("x-ratelimit-remaining") === "0");
  if (res.status === 401) return new HttpError("unauthorized", "invalid_user_token", path);
  if (rateLimited) return new HttpError("upstream_error", "github_unavailable", `${path}: rate limited`);
  if (res.status === 403 && res.headers.has("x-github-sso")) {
    return new HttpError("forbidden", "sso_required", `${path}: authorize the token for SAML SSO`);
  }
  if (res.status === 403 || res.status === 404) return new HttpError("forbidden", denied, path);
  return new HttpError("upstream_error", "github_unavailable", `${path}: GitHub returned ${res.status}`);
}
