import * as v from "valibot";
import { HttpError } from "./errors.js";

/** People's GitHub tokens: opaque, so the broker checks them with GitHub's API instead of a signature. */
export const GITHUB_USERS_ISSUER = "https://github.com";

/** GitHub Actions' OIDC issuer. GitHub Enterprise Cloud adds `/<enterprise>`. */
export const GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com";

/** The audience for Cloudflare API tokens and R2 credentials, and every profile's default. */
export const CLOUDFLARE_AUDIENCE = "https://api.cloudflare.com";

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

/**
 * GitHub's repo roles, least to most. `write` is GitHub's `push` and `read` its `pull`.
 * A user profile's `repository_permission` is the least it accepts.
 */
export const REPOSITORY_PERMISSIONS = ["read", "triage", "write", "maintain", "admin"] as const;
export type RepositoryPermission = (typeof REPOSITORY_PERMISSIONS)[number];

/** What a profile for people can match: what the broker looks up for a person, nothing a job's token has. */
const USER_MATCH = [
  "repository",
  "repository_id",
  "repository_owner_id",
  "actor_id",
  "team_id",
  "repository_permission",
];

/** Claims the broker checks against GitHub for a person, rather than compares with a value. */
const USER_ONLY_MATCH = ["team_id", "repository_permission"];

/** Claims that only exist once a person names a repository, so they need a role on it. */
const REPO_MATCH = ["repository", "repository_id", "repository_owner_id", "team_id"];

/** What a provider for people can pin for every profile: the repo owner, and who. */
const USER_PROVIDER_PINS = ["repository_owner_id", "actor_id"];

/** Default `max_ttl` for profiles for people, unless the profile sets its own. */
const USER_DEFAULT_MAX_TTL = HOUR;

/** A `{claim}` placeholder. Not `${claim}`, which Terraform's templatefile would try to fill in. */
const PLACEHOLDER = /\{([^{}]*)\}/g;

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
// which is what issuers put in their claims.
const ClaimValue = v.union([
  v.pipe(v.string(), v.nonEmpty()),
  v.pipe(v.number(), v.integer(), v.minValue(0), v.transform(String)),
]);

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

/** An issuer or key URL: `https://`, or plain `http://` on loopback for local development. */
const IssuerUrl = v.pipe(
  v.string(),
  v.url(),
  v.check(isIssuerUrl, "must be an https:// URL (http:// only on 127.0.0.1, localhost or [::1])"),
);

const Name = v.pipe(v.string(), v.regex(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/, "must be 1-64 of [A-Za-z0-9_.-]"));

// One value, or a list meaning any of them. Either way it's a list once loaded.
const ClaimValues = v.pipe(
  v.union([ClaimValue, v.pipe(v.array(ClaimValue), v.minLength(1, "must list at least one value"))]),
  v.transform((value) => (Array.isArray(value) ? value : [value])),
);

const ClaimSet = v.optional(
  v.record(v.pipe(v.string(), v.regex(/^[a-z_]+$/, "must be a claim name")), ClaimValues),
  {},
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

const ProviderSchema = v.strictObject({
  name: Name,
  // https://github.com for people's GitHub tokens; any other issuer's tokens are OIDC tokens.
  issuer: IssuerUrl,
  audience: v.optional(v.pipe(v.string(), v.nonEmpty())),
  jwks_uri: v.optional(IssuerUrl),
  // Every token from this provider must have these, whichever profile it gets.
  claims: ClaimSet,
});

const ProfileSchema = v.strictObject({
  name: Name,
  // May be left out when the policy has exactly one provider.
  provider: v.optional(Name),
  // Off switch for incidents: the profile stays in the policy but never matches.
  enabled: v.optional(v.boolean("must be true or false"), true),
  // Another service the broker issues its own token for, instead of Cloudflare credentials.
  audience: v.optional(Origin),
  claims: ClaimSet,
  // For everything the profile hands out: the token and the buckets' credentials.
  ttl: v.optional(Duration),
  max_ttl: v.optional(Duration),
  token: v.optional(v.strictObject({ policies: v.pipe(v.array(TokenPolicy), v.minLength(1)) })),
  // Each bucket gets its own credentials, which the action exports as an AWS profile named after it.
  buckets: v.optional(v.pipe(v.array(Bucket), v.minLength(1))),
});

const PolicySchema = v.strictObject({
  version: v.literal(2),
  // The broker's own URL: the issuer of the tokens it signs for other services.
  issuer: Origin,
  providers: v.pipe(v.array(ProviderSchema), v.minLength(1)),
  defaults: v.optional(
    v.strictObject({
      ttl: v.optional(Duration),
      max_ttl: v.optional(Duration),
    }),
    {},
  ),
  profiles: v.pipe(v.array(ProfileSchema), v.minLength(1)),
});

export type TokenPolicy = v.InferOutput<typeof TokenPolicy>;
export type Resources = TokenPolicy["resources"];

export interface Bucket {
  name: string;
  permission: "object-read-write" | "object-read-only";
  /** Templates with `{claim}` placeholders, filled in by `r2Prefixes`. Empty means the whole bucket. */
  prefixes: string[];
}

/**
 * How a provider's tokens are checked, which follows from its issuer: a person's GitHub token
 * with GitHub's API, any other issuer's as an OIDC token.
 */
export type ProviderType = "oidc" | "github-user";

/** Claim name to the values it may have: any of them. */
export type ClaimPatterns = Record<string, string[]>;

export interface Provider {
  name: string;
  type: ProviderType;
  /** The token's `iss`, exactly; `https://github.com` for people's GitHub tokens. */
  issuer: string;
  /** OIDC only: a value the token's `aud` must contain. */
  audience?: string;
  /** OIDC only: where the keys are, if not in the issuer's discovery document. */
  jwks_uri?: string;
  /** Every token from this provider must have these. */
  claims: ClaimPatterns;
}

export interface Profile {
  name: string;
  /** The provider whose tokens the profile is for. */
  provider: string;
  /** That provider's type, kept here for the checks that depend on it. */
  type: ProviderType;
  /** A disabled profile never matches, even when a request names it. */
  enabled: boolean;
  /** What the profile issues for: Cloudflare credentials, or the broker's own token for this service. */
  audience: string;
  /** All must match (AND), each any of its values: the profile's own claims and its provider's. */
  claims: ClaimPatterns;
  ttl: number;
  max_ttl: number;
  /** The token's policies. Absent for a profile with only `buckets`. */
  policies?: TokenPolicy[];
  buckets?: Bucket[];
}

export interface Policy {
  /** The broker's own URL. */
  issuer: string;
  providers: Provider[];
  profiles: Profile[];
}

export class PolicyError extends Error {
  constructor(readonly issues: string[]) {
    super(`invalid policy:\n  - ${issues.join("\n  - ")}`);
    this.name = "PolicyError";
  }
}

/** `https://`, or plain `http://` on loopback, as cf-nix-cache allows for its issuers. */
export function isIssuerUrl(value: string): boolean {
  const url = new URL(value);
  if (url.protocol === "https:") return true;
  return url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname);
}

/**
 * Issuers that give a token to anyone's projects, and the claims that pin the tenant: a
 * provider for one of them must pin at least one, exactly.
 */
function tenantClaims(issuer: string): string[] | undefined {
  if (issuer === GITHUB_ACTIONS_ISSUER || issuer.startsWith(`${GITHUB_ACTIONS_ISSUER}/`)) {
    return ["repository_owner_id"];
  }
  if (issuer === "https://gitlab.com") return ["namespace_id", "project_id"];
  if (issuer === "https://app.terraform.io") return ["terraform_organization_id"];
  return undefined;
}

/** Guardrail 2 for a claim set: patterns stay narrow, and IDs are exact. */
function checkPatterns(at: string, claims: ClaimPatterns, issues: string[]) {
  for (const [claim, values] of Object.entries(claims)) {
    for (const value of values) {
      if (claim.endsWith("_id") && value.includes("*")) {
        issues.push(`${at}.${claim}: ID claims must be exact, globs are not allowed`);
      } else if (value.includes("*") && !isPrefixPattern(value)) {
        // A bare or leading `*` would match far more than intended; one in the middle needs a backtracking matcher.
        issues.push(`${at}.${claim}: * is only allowed once, at the end, after a prefix (e.g. example-org/*)`);
      }
    }
  }
}

/** Checks a claim set for people: only what the broker looks up for a person, with one valid role. */
function checkUserClaims(at: string, claims: ClaimPatterns, issues: string[]) {
  for (const claim of Object.keys(claims)) {
    if (!USER_MATCH.includes(claim)) {
      issues.push(`${at}.${claim}: not available for people; use ${USER_MATCH.join(", ")}`);
    }
  }
  const roles = claims.repository_permission;
  if (roles !== undefined && roles.length > 1) {
    issues.push(`${at}.repository_permission: one role, the least the person must have`);
  }
  const role = roles?.[0];
  if (role !== undefined && !(REPOSITORY_PERMISSIONS as readonly string[]).includes(role)) {
    issues.push(`${at}.repository_permission: must be one of ${REPOSITORY_PERMISSIONS.join(", ")}`);
  }
}

// ---------------------------------------------------------------------------
// Loading and guardrails
// ---------------------------------------------------------------------------

/** Loads and checks the providers. Their issues go to `issues`. */
function loadProviders(raw: v.InferOutput<typeof ProviderSchema>[], issues: string[]): Provider[] {
  const names = new Set<string>();
  const issuers = new Set<string>();
  return raw.map((provider, i) => {
    const at = `providers.${i} (${provider.name})`;
    if (names.has(provider.name)) issues.push(`${at}: duplicate provider name`);
    names.add(provider.name);
    if (issuers.has(provider.issuer)) issues.push(`${at}.issuer: another provider has the same issuer`);
    issuers.add(provider.issuer);
    checkPatterns(`${at}.claims`, provider.claims, issues);

    if (provider.issuer === GITHUB_USERS_ISSUER) {
      // A person's GitHub token is checked with GitHub's API: it has no audience or keys.
      for (const field of ["audience", "jwks_uri"] as const) {
        if (provider[field] !== undefined)
          issues.push(`${at}.${field}: not for ${GITHUB_USERS_ISSUER}, whose tokens aren't OIDC tokens`);
      }
      for (const claim of Object.keys(provider.claims)) {
        if (!USER_PROVIDER_PINS.includes(claim)) {
          issues.push(
            `${at}.claims.${claim}: a provider for people pins ${USER_PROVIDER_PINS.join(" or ")}; the rest go on profiles`,
          );
        }
      }
      return { name: provider.name, type: "github-user", issuer: provider.issuer, claims: provider.claims };
    }

    if (provider.audience === undefined) issues.push(`${at}.audience: required for an OIDC issuer`);
    for (const claim of USER_ONLY_MATCH) {
      if (claim in provider.claims) issues.push(`${at}.claims.${claim}: only for people (${GITHUB_USERS_ISSUER})`);
    }

    // Guardrail 1: an issuer that gives anyone's projects a token needs the tenant pinned.
    const tenant = tenantClaims(provider.issuer);
    if (tenant && !tenant.some((claim) => provider.claims[claim] !== undefined)) {
      issues.push(
        `${at}.claims: must pin ${tenant.join(" or ")}: ${provider.issuer} issues tokens to anyone's projects`,
      );
    }
    // Guardrail 5: a custom audience, so a GitHub token requested for AWS or GCP can't be replayed here.
    const audience = provider.audience ?? "";
    if (tenant?.includes("repository_owner_id") && /^https:\/\/github\.com(\/|$)/.test(audience)) {
      issues.push(`${at}.audience: must not be GitHub's default audience; use the broker's URL`);
    }
    return {
      name: provider.name,
      type: "oidc",
      issuer: provider.issuer,
      audience,
      ...(provider.jwks_uri ? { jwks_uri: provider.jwks_uri } : {}),
      claims: provider.claims,
    };
  });
}

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
  if ((raw as { version?: unknown } | null)?.version === 1) {
    throw new PolicyError([
      "version 1 is no longer supported: move github: to providers: and match: to claims: (see the broker README's migration table)",
    ]);
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

  const { issuer, defaults, profiles } = parsed.output;
  const issues: string[] = [];
  const providers = loadProviders(parsed.output.providers, issues);

  const defaultMax = defaults.max_ttl ?? DEFAULT_MAX_TTL;
  const defaultTTL = defaults.ttl ?? Math.min(DEFAULT_TTL, defaultMax);
  checkTTLs("defaults", defaultTTL, defaultMax, issues);

  const names = new Set<string>();
  const out: Profile[] = profiles.map((profile, i) => {
    const at = `profiles.${i} (${profile.name})`;
    if (names.has(profile.name)) issues.push(`${at}: duplicate profile name`);
    names.add(profile.name);

    // With one provider, it's the only one a profile can be for.
    const named = profile.provider ?? (providers.length === 1 ? providers[0]?.name : undefined);
    const provider = providers.find((p) => p.name === named);
    if (profile.provider === undefined && providers.length > 1) {
      issues.push(`${at}.provider: required when the policy has several providers`);
    } else if (!provider) {
      issues.push(`${at}.provider: no provider named ${profile.provider}`);
    }
    const type = provider?.type ?? "oidc";

    checkPatterns(`${at}.claims`, profile.claims, issues);
    // The provider's claims every token for this profile must also have.
    let inherited: ClaimPatterns = provider?.claims ?? {};
    // Guardrail 6: a person has no ref, environment or workflow, and picks the repo, so a
    // profile for people matches only what the broker looks up. It's pinned either to a role
    // on the repo they ask for, which must belong to the provider's owner, or to who they are.
    if (type === "github-user") {
      checkUserClaims(`${at}.claims`, profile.claims, issues);
      const repoScoped = profile.claims.repository_permission !== undefined;
      if (repoScoped && provider?.claims.repository_owner_id === undefined) {
        issues.push(
          `${at}.claims.repository_permission: needs provider ${provider?.name} to pin repository_owner_id, the owner the repo must belong to`,
        );
      }
      if (!repoScoped) {
        if (profile.claims.actor_id === undefined && provider?.claims.actor_id === undefined) {
          issues.push(
            `${at}.claims: a profile for people needs repository_permission (a role on the repo they ask for) or actor_id (who may use it)`,
          );
        }
        for (const claim of REPO_MATCH) {
          if (claim in profile.claims) issues.push(`${at}.claims.${claim}: needs repository_permission`);
        }
        // Without a repo, the owner pin has nothing to bound: it applies to repo-scoped profiles.
        const { repository_owner_id: _, ...rest } = inherited;
        inherited = rest;
      }
    } else {
      for (const claim of USER_ONLY_MATCH) {
        if (claim in profile.claims) issues.push(`${at}.claims.${claim}: only for people (${GITHUB_USERS_ISSUER})`);
      }
    }

    // Guardrail 1: a provider's claims apply to every profile for it. A profile can narrow
    // them to some of their values, but not widen or change them.
    for (const [claim, values] of Object.entries(inherited)) {
      const own = profile.claims[claim];
      if (own !== undefined && !own.every((value) => values.includes(value))) {
        issues.push(`${at}.claims.${claim}: conflicts with provider ${provider?.name}`);
      }
    }

    const { token, buckets } = profile;
    const audience = profile.audience ?? CLOUDFLARE_AUDIENCE;
    if (audience === CLOUDFLARE_AUDIENCE) {
      if (!token && !buckets) issues.push(`${at}: must have a token, buckets or both`);
    } else {
      // The broker signs its own token for the service; Cloudflare credentials are another profile's job.
      if (token || buckets) issues.push(`${at}: a profile for ${audience} can't have a token or buckets`);
      if (audience === issuer) issues.push(`${at}.audience: must be another service, not the broker itself`);
    }

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

    // Guardrail 4: TTL caps. A stolen gh token never expires, so what it can mint for a person should.
    const fallbackMax = type === "github-user" ? Math.min(defaultMax, USER_DEFAULT_MAX_TTL) : defaultMax;
    const max_ttl = profile.max_ttl ?? fallbackMax;
    const ttl = profile.ttl ?? Math.min(defaultTTL, max_ttl);
    checkTTLs(at, ttl, max_ttl, issues);
    if (buckets && (ttl < R2_MIN_TTL || max_ttl > R2_MAX_TTL)) {
      issues.push(`${at}: ttl and max_ttl must be within the 1m to 7 days R2 credentials accept`);
    }

    return {
      name: profile.name,
      provider: provider?.name ?? "",
      type,
      enabled: profile.enabled,
      audience,
      claims: { ...inherited, ...profile.claims },
      ttl,
      max_ttl,
      ...(token ? { policies: token.policies } : {}),
      ...(buckets ? { buckets } : {}),
    };
  });

  if (issues.length > 0) throw new PolicyError(issues);
  return { issuer, providers, profiles: out };
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

/** Whether a pattern is `<prefix>*`: one `*`, at the end, after a non-empty prefix. */
function isPrefixPattern(pattern: string): boolean {
  return pattern.length > 1 && pattern.indexOf("*") === pattern.length - 1;
}

/**
 * `<prefix>*` matches any value starting with the prefix, including across `/`. Any other
 * pattern must equal the value; the policy refuses other uses of `*` when it loads.
 */
export function glob(pattern: string, value: string): boolean {
  return isPrefixPattern(pattern) ? value.startsWith(pattern.slice(0, -1)) : pattern === value;
}

/** Whether a person's role on the repo is at least `required`. */
function hasRole(role: unknown, required: string): boolean {
  const roles: readonly unknown[] = REPOSITORY_PERMISSIONS;
  return roles.includes(role) && roles.indexOf(role) >= roles.indexOf(required);
}

/** Whether one value of a token's claim matches one of the patterns. */
function matchesValue(claim: string, patterns: string[], value: unknown): boolean {
  if (typeof value !== "string") return false;
  return patterns.some((pattern) => (claim.endsWith("_id") ? value === pattern : glob(pattern, value)));
}

/** Whether every claim of the profile matches, each by any of its values. */
export function matches(profile: Profile, claims: Claims): boolean {
  return Object.entries(profile.claims).every(([claim, patterns]) => {
    // Only a person's claims carry these: the teams they're in and their role on the repo.
    if (claim === "team_id")
      return Array.isArray(claims.team_ids) && claims.team_ids.some((id) => patterns.includes(id));
    if (claim === "repository_permission") return hasRole(claims.repository_permission, patterns[0] as string);
    const value = claims[claim];
    // A claim that's a list in the token matches if any of its values does.
    return Array.isArray(value)
      ? value.some((v) => matchesValue(claim, patterns, v))
      : matchesValue(claim, patterns, value);
  });
}

/**
 * Picks the profile to issue with, among those for `provider` and `audience` only, or throws
 * a `403` whose reason goes to the audit log.
 */
export function selectProfile(
  policy: Policy,
  provider: string,
  claims: Claims,
  requested?: string,
  audience = CLOUDFLARE_AUDIENCE,
): Profile {
  const profiles = policy.profiles.filter((p) => p.provider === provider && p.audience === audience);
  if (requested !== undefined) {
    const named = policy.profiles.find((p) => p.name === requested);
    const profile = profiles.find((p) => p.name === requested);
    if (!profile?.enabled || !matches(profile, claims)) {
      const detail = !named
        ? `unknown profile ${requested}`
        : named.provider !== provider
          ? `profile ${requested} isn't for provider ${provider}`
          : named.audience !== audience
            ? `profile ${requested} isn't for ${audience}`
            : named.enabled
              ? undefined
              : `profile ${requested} is disabled`;
      throw new HttpError("forbidden", "profile_mismatch", detail);
    }
    return profile;
  }

  const candidates = profiles.filter((p) => p.enabled && matches(p, claims));
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
