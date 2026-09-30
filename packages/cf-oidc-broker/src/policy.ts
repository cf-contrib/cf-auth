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
  v.check((s) => new URL(s).origin === s, "must be a bare origin such as https://cf-auth.example.com"),
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

const Profile = v.strictObject({
  name: v.pipe(v.string(), v.regex(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/, "must be 1-64 of [A-Za-z0-9_.-]")),
  match: v.optional(v.record(v.pipe(v.string(), v.regex(/^[a-z_]+$/, "must be a claim name")), ClaimValue), {}),
  token: v.strictObject({
    ttl: v.optional(Duration),
    max_ttl: v.optional(Duration),
    policies: v.pipe(v.array(TokenPolicy), v.minLength(1)),
  }),
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

export interface Profile {
  name: string;
  /** All keys must match (AND). Always includes `repository_owner_id`. */
  match: Record<string, string>;
  ttl: number;
  max_ttl: number;
  policies: TokenPolicy[];
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

    // Guardrail 1: the owner pin applies to every profile and can't be overridden.
    const owner = profile.match.repository_owner_id;
    if (owner !== undefined && owner !== github.owner_id) {
      issues.push(`${at}.match.repository_owner_id: conflicts with github.owner_id`);
    }

    profile.token.policies.forEach((p, j) => {
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

    // Guardrail 4: TTL caps.
    const max_ttl = profile.token.max_ttl ?? defaultMax;
    const ttl = profile.token.ttl ?? Math.min(defaultTTL, max_ttl);
    checkTTLs(`${at}.token`, ttl, max_ttl, issues);

    return {
      name: profile.name,
      match: { ...profile.match, repository_owner_id: github.owner_id },
      ttl,
      max_ttl,
      policies: profile.token.policies,
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

export function matches(profile: Profile, claims: Claims): boolean {
  return Object.entries(profile.match).every(([claim, pattern]) => {
    const value = claims[claim];
    if (typeof value !== "string") return false;
    return claim.endsWith("_id") ? value === pattern : glob(pattern, value);
  });
}

/** Picks the profile to mint with, or throws a `403` whose reason goes to the audit log. */
export function selectProfile(policy: Policy, claims: Claims, requested?: string): Profile {
  if (requested !== undefined) {
    const profile = policy.profiles.find((p) => p.name === requested);
    if (!profile || !matches(profile, claims)) {
      throw new HttpError("forbidden", "profile_mismatch", profile ? undefined : `unknown profile ${requested}`);
    }
    return profile;
  }

  const candidates = policy.profiles.filter((p) => matches(p, claims));
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
