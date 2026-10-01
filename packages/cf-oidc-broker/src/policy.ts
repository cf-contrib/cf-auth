import * as v from "valibot";
import { HttpError } from "./errors.js";

export const DEFAULT_ISSUER = "https://token.actions.githubusercontent.com";

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;

export const MIN_TTL = MINUTE;
export const MAX_TTL = 24 * HOUR;
const DEFAULT_TTL = 15 * MINUTE;
const DEFAULT_MAX_TTL = HOUR;

/** Permission groups that could mint further tokens. Never grantable (§7 guardrail 3). */
const TOKEN_MANAGEMENT = /api tokens/i;

/** An account-level resource key; zone keys (`...account.zone.<id>`) don't match. */
const ACCOUNT_RESOURCE = /^com\.cloudflare\.api\.account\.([0-9a-f]{32})$/;

/** R2's bucket name rules: 3-63 lowercase letters, digits and hyphens, starting and ending with a letter or digit. */
const R2_BUCKET = /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/;

/**
 * `ttlSeconds` range of R2 temporary credentials. Cloudflare documents a 7-day maximum;
 * the API accepts values down to 0, so the minimum is the broker's own.
 */
const R2_MIN_TTL = MIN_TTL;
const R2_MAX_TTL = 7 * 24 * HOUR;

/**
 * Claims a bucket prefix can be built from, and what a value must look like to be used:
 * the characters GitHub allows in owner and repo names, or a numeric ID.
 */
const PREFIX_CLAIMS = {
  repository: /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/,
  repository_owner: /^[A-Za-z0-9._-]+$/,
  repository_id: /^\d+$/,
  repository_owner_id: /^\d+$/,
} as const;
type PrefixClaim = keyof typeof PREFIX_CLAIMS;

/** Who a profile is for: GitHub Actions jobs (OIDC JWT) or people (GitHub user token). */
export type Subject = "actions" | "users";

/**
 * GitHub's repo roles, least to most. `write` is GitHub's `push` and `read` its `pull`.
 * A user profile's `repository_permission` is the least it accepts.
 */
export const REPOSITORY_PERMISSIONS = ["read", "triage", "write", "maintain", "admin"] as const;
export type RepositoryPermission = (typeof REPOSITORY_PERMISSIONS)[number];

/** What a user profile can match: what the broker looks up for a person, nothing Actions-specific. */
const USER_MATCH = [
  "repository",
  "repository_id",
  "repository_owner_id",
  "actor_id",
  "team_id",
  "repository_permission",
];

/** Match keys the broker checks against GitHub for a person, rather than compares with a claim. */
const USER_ONLY_MATCH = ["team_id", "repository_permission"];

/** Default `max_ttl` for user profiles, unless the profile sets its own. */
const USER_DEFAULT_MAX_TTL = HOUR;

/** A `{claim}` placeholder. Not `${claim}`, which Terraform's templatefile would try to fill in. */
const PLACEHOLDER = /\{([^{}]*)\}/g;

/** Host of GitHub's default OIDC audience (`https://github.com/<owner>`), which other clouds' JWTs carry. */
const GITHUB_DEFAULT_AUDIENCE_HOST = "github.com";

/** Parses `90s`, `15m`, `1h`, `1h30m` into milliseconds. */
export function parseDuration(value: string): number | undefined {
  const m = /^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/.exec(value.trim());
  if (!m || value.trim() === "") return undefined;
  const [, h = "0", min = "0", s = "0"] = m;
  return Number(h) * HOUR + Number(min) * MINUTE + Number(s) * SECOND;
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

// YAML turns unquoted IDs into numbers, so accept both and normalize to strings,
// which is what GitHub puts in its claims.
const ClaimValue = v.union([
  v.pipe(v.string(), v.nonEmpty()),
  v.pipe(v.number(), v.integer(), v.minValue(0), v.transform(String)),
]);

const NumericId = v.pipe(ClaimValue, v.regex(/^\d+$/, "must be a numeric ID"));

const Duration = v.pipe(
  v.string(),
  v.check((s) => parseDuration(s) !== undefined, "must be a duration such as 15m or 1h"),
  v.transform((s) => parseDuration(s) as number),
);

const Origin = v.pipe(
  v.string(),
  v.url(),
  v.check((s) => new URL(s).origin === s, "must be a bare origin such as https://cf-oidc-broker.example.com"),
);

/** Cloudflare's native token `resources`, e.g. `com.cloudflare.api.account.zone.<zone_id>: "*"`. */
const Resources = v.pipe(
  v.record(
    v.pipe(v.string(), v.startsWith("com.cloudflare.", "must be a Cloudflare resource name")),
    v.union([v.string(), v.record(v.string(), v.string())]),
  ),
  v.check((r) => Object.keys(r).length > 0, "must name at least one resource"),
);

const TokenPolicy = v.strictObject({
  effect: v.optional(v.picklist(["allow", "deny"]), "allow"),
  permissions: v.pipe(v.array(v.pipe(v.string(), v.nonEmpty())), v.minLength(1)),
  resources: Resources,
});

const Bucket = v.strictObject({
  name: v.pipe(v.string(), v.regex(R2_BUCKET, "must be a valid R2 bucket name")),
  permission: v.picklist(["object-read-write", "object-read-only"], "must be object-read-write or object-read-only"),
  prefixes: v.optional(v.array(v.string()), []),
});

const Profile = v.strictObject({
  name: v.pipe(v.string(), v.regex(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/, "must be 1-64 of [A-Za-z0-9_.-]")),
  subject: v.optional(v.picklist(["actions", "users"], "must be actions or users"), "actions"),
  match: v.optional(v.record(v.pipe(v.string(), v.regex(/^[a-z_]+$/, "must be a claim name")), ClaimValue), {}),
  // For everything the profile hands out: the token and the buckets' credentials.
  ttl: v.optional(Duration),
  max_ttl: v.optional(Duration),
  token: v.optional(
    v.strictObject({
      // Where ttl and max_ttl went before they moved up to the profile. Still accepted.
      ttl: v.optional(Duration),
      max_ttl: v.optional(Duration),
      policies: v.pipe(v.array(TokenPolicy), v.minLength(1)),
    }),
  ),
  // Each bucket gets its own credentials, which the action exports as an AWS profile named after it.
  buckets: v.optional(v.pipe(v.array(Bucket), v.minLength(1))),
});

const PolicySchema = v.strictObject({
  version: v.literal(1),
  github: v.strictObject({
    issuer: v.optional(v.pipe(v.string(), v.url(), v.startsWith("https://")), DEFAULT_ISSUER),
    audience: Origin,
    owner_id: NumericId,
  }),
  defaults: v.optional(
    v.strictObject({
      ttl: v.optional(Duration),
      max_ttl: v.optional(Duration),
    }),
    {},
  ),
  profiles: v.pipe(v.array(Profile), v.minLength(1)),
});

export type TokenPolicy = v.InferOutput<typeof TokenPolicy>;
export type Resources = TokenPolicy["resources"];

export interface Bucket {
  name: string;
  permission: "object-read-write" | "object-read-only";
  /** Templates with `{claim}` placeholders, filled in by `r2Prefixes`. Empty means the whole bucket. */
  prefixes: string[];
}

export interface Profile {
  name: string;
  /** Only callers of this subject can use the profile. */
  subject: Subject;
  /** All keys must match (AND). Always includes `repository_owner_id`. */
  match: Record<string, string>;
  ttl: number;
  max_ttl: number;
  /** The token's policies. Absent for a profile with only `buckets`. */
  policies?: TokenPolicy[];
  buckets?: Bucket[];
}

export interface Policy {
  github: { issuer: string; audience: string; owner_id: string };
  profiles: Profile[];
}

export class PolicyError extends Error {
  constructor(readonly issues: string[]) {
    super(`invalid policy:\n  - ${issues.join("\n  - ")}`);
    this.name = "PolicyError";
  }
}

// ---------------------------------------------------------------------------
// Loading and guardrails
// ---------------------------------------------------------------------------

/**
 * Parses and validates a policy. Throws `PolicyError` listing every problem found,
 * so an admin can fix them all in one go. With `accountId`, account resources must
 * name that account.
 */
export function loadPolicy(input: unknown, accountId?: string): Policy {
  let raw = input;
  if (typeof raw === "string") {
    try {
      raw = JSON.parse(raw);
    } catch (err) {
      throw new PolicyError([`policy.json is not valid JSON: ${(err as Error).message}`]);
    }
  }

  const parsed = v.safeParse(PolicySchema, raw);
  if (!parsed.success) {
    throw new PolicyError(
      parsed.issues.map((i) => {
        const path = v.getDotPath(i);
        return path ? `${path}: ${i.message}` : i.message;
      }),
    );
  }

  const { github, defaults, profiles } = parsed.output;
  const issues: string[] = [];

  // Guardrail 5: custom audience, so JWTs minted for AWS/GCP can't be replayed here.
  if (new URL(github.audience).hostname === GITHUB_DEFAULT_AUDIENCE_HOST) {
    issues.push("github.audience: must not be GitHub's default audience; use the broker's URL");
  }

  const defaultMax = defaults.max_ttl ?? DEFAULT_MAX_TTL;
  const defaultTTL = defaults.ttl ?? Math.min(DEFAULT_TTL, defaultMax);
  checkTTLs("defaults", defaultTTL, defaultMax, issues);

  const names = new Set<string>();
  const out: Profile[] = profiles.map((profile, i) => {
    const at = `profiles.${i} (${profile.name})`;
    if (names.has(profile.name)) issues.push(`${at}: duplicate profile name`);
    names.add(profile.name);

    for (const [claim, value] of Object.entries(profile.match)) {
      // Guardrail 2: IDs are exact, never globbed.
      if (claim.endsWith("_id") && value.includes("*")) {
        issues.push(`${at}.match.${claim}: ID claims must be exact, globs are not allowed`);
      }
    }

    // Guardrail 6: a person has no ref, environment or workflow, and the client picks the
    // repo, so a user profile matches only what the broker looks up, and must require a
    // role on that repo. Actions profiles can't use the keys only a person has.
    if (profile.subject === "users") {
      for (const claim of Object.keys(profile.match)) {
        if (!USER_MATCH.includes(claim)) {
          issues.push(`${at}.match.${claim}: not available for people; use ${USER_MATCH.join(", ")}`);
        }
      }
      if (profile.match.repository_permission === undefined) {
        issues.push(`${at}.match.repository_permission: required for a user profile`);
      }
    } else {
      for (const claim of USER_ONLY_MATCH) {
        if (claim in profile.match) issues.push(`${at}.match.${claim}: only for user profiles (subject: users)`);
      }
    }
    const role = profile.match.repository_permission;
    if (role !== undefined && !(REPOSITORY_PERMISSIONS as readonly string[]).includes(role)) {
      issues.push(`${at}.match.repository_permission: must be one of ${REPOSITORY_PERMISSIONS.join(", ")}`);
    }

    // Guardrail 1: the owner pin applies to every profile and can't be overridden.
    const owner = profile.match.repository_owner_id;
    if (owner !== undefined && owner !== github.owner_id) {
      issues.push(`${at}.match.repository_owner_id: conflicts with github.owner_id`);
    }

    const { token, buckets } = profile;
    if (!token && !buckets) issues.push(`${at}: must have a token, buckets or both`);

    token?.policies.forEach((p, j) => {
      // Tokens are minted in one account; another account's ID is a copy-paste mistake.
      for (const key of Object.keys(p.resources)) {
        const id = ACCOUNT_RESOURCE.exec(key)?.[1];
        if (accountId && id && id !== accountId) {
          issues.push(`${at}.token.policies.${j}.resources: ${key} is not the broker's account`);
        }
      }

      // Guardrail 3: no token-management permissions.
      if (p.effect !== "allow") return;
      for (const name of p.permissions) {
        if (TOKEN_MANAGEMENT.test(name)) {
          issues.push(`${at}.token.policies.${j}: "${name}" is not grantable (token-management permission)`);
        }
      }
    });

    const bucketNames = new Set<string>();
    buckets?.forEach((bucket, j) => {
      // The name is also the AWS profile's, so it can only appear once.
      if (bucketNames.has(bucket.name)) issues.push(`${at}.buckets.${j}.name: duplicate bucket ${bucket.name}`);
      bucketNames.add(bucket.name);
      bucket.prefixes.forEach((prefix, k) => {
        const problem = templateProblem(prefix);
        if (problem) issues.push(`${at}.buckets.${j}.prefixes.${k}: ${problem}`);
      });
    });

    // Guardrail 4: TTL caps.
    const legacy = token?.ttl !== undefined || token?.max_ttl !== undefined;
    if (legacy && (profile.ttl !== undefined || profile.max_ttl !== undefined)) {
      issues.push(`${at}: set ttl and max_ttl on the profile or on its token, not both`);
    }
    const lifetime = legacy ? token : profile;
    // A stolen gh token never expires, so what it can mint for a person should.
    const fallbackMax = profile.subject === "users" ? Math.min(defaultMax, USER_DEFAULT_MAX_TTL) : defaultMax;
    const max_ttl = lifetime?.max_ttl ?? fallbackMax;
    const ttl = lifetime?.ttl ?? Math.min(defaultTTL, max_ttl);
    checkTTLs(legacy ? `${at}.token` : at, ttl, max_ttl, issues);
    if (buckets && (ttl < R2_MIN_TTL || max_ttl > R2_MAX_TTL)) {
      issues.push(`${at}: ttl and max_ttl must be within the 1m to 7 days R2 credentials accept`);
    }

    return {
      name: profile.name,
      subject: profile.subject,
      match: { ...profile.match, repository_owner_id: github.owner_id },
      ttl,
      max_ttl,
      ...(token ? { policies: token.policies } : {}),
      ...(buckets ? { buckets } : {}),
    };
  });

  if (issues.length > 0) throw new PolicyError(issues);
  return { github, profiles: out };
}

function checkTTLs(at: string, ttl: number, max: number, issues: string[]) {
  if (max > MAX_TTL) issues.push(`${at}.max_ttl: must be at most 24h`);
  if (ttl < MIN_TTL) issues.push(`${at}.ttl: must be at least 1m`);
  if (ttl > max) issues.push(`${at}.ttl: must not exceed max_ttl`);
}

// ---------------------------------------------------------------------------
// R2 prefixes
// ---------------------------------------------------------------------------

// The prefix is the only thing keeping one repo out of another's keys, so these
// checks run on the template when the policy loads and again on every filled-in prefix.

/** Checks a filled-in prefix. Returns what's wrong with it, if anything. */
function prefixProblem(prefix: string): string | undefined {
  if (prefix.startsWith("/")) return "must not start with /";
  // Without it, github.com/org/site would also cover github.com/org/site-old/.
  if (!prefix.endsWith("/")) return "must end with /";
  if (prefix.includes("*")) return "must not contain *";
  if (prefix.includes("..")) return "must not contain ..";
  if (/\p{Cc}/u.test(prefix)) return "must not contain control characters";
  if (
    prefix
      .slice(0, -1)
      .split("/")
      .some((segment) => segment === "" || segment === ".")
  ) {
    return "must not contain empty or . path segments";
  }
  return undefined;
}

/** Checks a prefix template from the policy. */
function templateProblem(template: string): string | undefined {
  // biome-ignore lint/suspicious/noTemplateCurlyInString: names the syntax to avoid
  if (template.includes("${")) return "use {claim} placeholders, not ${claim}";
  for (const [placeholder, name = ""] of template.matchAll(PLACEHOLDER)) {
    if (!Object.hasOwn(PREFIX_CLAIMS, name)) {
      return `unknown placeholder ${placeholder}; use one of ${Object.keys(PREFIX_CLAIMS).join(", ")}`;
    }
  }
  if (/[{}]/.test(template.replace(PLACEHOLDER, ""))) return "has an unmatched { or }";
  // A placeholder must fill whole path segments. Otherwise two repos could get the same
  // prefix: {repository_owner}{repository_id} is "a1"+"23" and "a"+"123" alike.
  const segments = template.split("/");
  if (segments.some((s) => s.includes("{") && !/^\{[^{}]*\}$/.test(s))) {
    return "a placeholder must be a whole path segment, e.g. github.com/{repository}/";
  }
  return prefixProblem(template.replace(PLACEHOLDER, "x"));
}

/**
 * Fills in a bucket's prefix templates from the verified JWT's claims, or throws a
 * `403` if a claim is missing or can't safely be used in a key.
 */
export function r2Prefixes(bucket: Bucket, claims: Claims): string[] {
  return bucket.prefixes.map((template) => {
    const prefix = template.replace(PLACEHOLDER, (_, name: PrefixClaim) => {
      const value = claims[name];
      if (typeof value !== "string" || !PREFIX_CLAIMS[name].test(value)) {
        throw new HttpError("forbidden", "invalid_r2_prefix", `${name} claim is missing or not usable in a prefix`);
      }
      return value;
    });
    const problem = prefixProblem(prefix);
    if (problem) throw new HttpError("forbidden", "invalid_r2_prefix", `${prefix}: ${problem}`);
    return prefix;
  });
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

export type Claims = Record<string, unknown>;

/** `*` matches any run of characters, including `/`. Everything else is literal. */
export function glob(pattern: string, value: string): boolean {
  if (!pattern.includes("*")) return pattern === value;
  const re = pattern
    .split("*")
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${re}$`, "s").test(value);
}

/** Whether a person's role on the repo is at least `required`. */
function hasRole(role: unknown, required: string): boolean {
  const roles: readonly unknown[] = REPOSITORY_PERMISSIONS;
  return roles.includes(role) && roles.indexOf(role) >= roles.indexOf(required);
}

export function matches(profile: Profile, claims: Claims): boolean {
  return Object.entries(profile.match).every(([claim, pattern]) => {
    // Only a person's claims carry these: the teams they're in and their role on the repo.
    if (claim === "team_id") return Array.isArray(claims.team_ids) && claims.team_ids.includes(pattern);
    if (claim === "repository_permission") return hasRole(claims.repository_permission, pattern);
    const value = claims[claim];
    if (typeof value !== "string") return false;
    return claim.endsWith("_id") ? value === pattern : glob(pattern, value);
  });
}

/**
 * Picks the profile to mint with, among those for `subject` only, or throws a `403`
 * whose reason goes to the audit log.
 */
export function selectProfile(policy: Policy, subject: Subject, claims: Claims, requested?: string): Profile {
  const profiles = policy.profiles.filter((p) => p.subject === subject);
  if (requested !== undefined) {
    const profile = profiles.find((p) => p.name === requested);
    if (!profile || !matches(profile, claims)) {
      const known = policy.profiles.some((p) => p.name === requested);
      const detail = profile
        ? undefined
        : known
          ? `profile ${requested} isn't for ${subject}`
          : `unknown profile ${requested}`;
      throw new HttpError("forbidden", "profile_mismatch", detail);
    }
    return profile;
  }

  const candidates = profiles.filter((p) => matches(p, claims));
  if (candidates.length === 0) throw new HttpError("forbidden", "no_match");
  if (candidates.length > 1) {
    throw new HttpError("forbidden", "ambiguous", candidates.map((p) => p.name).join(","));
  }
  return candidates[0] as Profile;
}

/** Resolves the requested TTL against the profile. Requests above `max_ttl` are clamped, not refused. */
export function clampTTL(requested: string | undefined, profile: Profile): number {
  if (requested === undefined) return profile.ttl;
  const ttl = parseDuration(requested);
  if (ttl === undefined || ttl < MIN_TTL) {
    throw new HttpError("bad_request", "invalid_ttl", requested);
  }
  return Math.min(ttl, profile.max_ttl);
}
