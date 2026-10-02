import Cloudflare, { AuthenticationError, BadRequestError, NotFoundError, PermissionDeniedError } from "cloudflare";
import { audit } from "./audit.js";
import { HttpError } from "./errors.js";
import type { Claims, Provider, TokenPolicy } from "./policy.js";
import { resolvePolicies } from "./resolve.js";

/** Every minted token's name starts with this. Revoke and cleanup never touch anything else. */
export const TOKEN_PREFIX = "cf-oidc:";
const NAME_MAX = 120;

/**
 * `cf-oidc:<repo>:<run_id>:<attempt>` for a GitHub Actions job, `cf-oidc:user:<login>:<repo>`
 * for a person, and `cf-oidc:<provider>:<sub>` for any other issuer's caller, cut to fit 120
 * characters. A repo name can't contain `:`, so the GitHub forms never collide.
 */
export function tokenName(claims: Claims, provider: Pick<Provider, "name" | "type">): string {
  const str = (key: string) => (typeof claims[key] === "string" ? (claims[key] as string) : "");
  const named = (head: string, tail: string, body: string) =>
    `${TOKEN_PREFIX}${head}${body.slice(0, NAME_MAX - TOKEN_PREFIX.length - head.length - tail.length)}${tail}`;
  const repo = str("repository");
  if (provider.type === "github-user") return named(`user:${str("actor") || "unknown"}:`, "", repo || "unknown");
  // A GitHub Actions token names its repo and run; other issuers don't.
  if (repo && str("run_id")) return named("", `:${str("run_id")}:${str("run_attempt") || "0"}`, repo);
  return named(`${provider.name}:`, "", str("sub") || "unknown");
}

/** RFC 3339 without fractional seconds, which is what the tokens API accepts. */
export function rfc3339(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
}

export interface MintedToken {
  token: string;
  token_id: string;
  expires_on: string;
}

/** Mints a token. Not retried: a create that failed midway leaves an orphan the cron job removes. */
export async function mint(
  cf: Cloudflare,
  accountId: string,
  policies: TokenPolicy[],
  name: string,
  ttl: number,
): Promise<MintedToken> {
  const resolved = await resolvePolicies(cf, accountId, policies);
  const expires_on = rfc3339(Date.now() + ttl);

  const token = await cf.accounts.tokens.create(
    { account_id: accountId, name, policies: resolved, expires_on },
    { maxRetries: 0 },
  );
  if (!token.id || !token.value) {
    throw new HttpError("upstream_error", "cloudflare_error", "tokens.create returned no token");
  }

  return { token: token.value, token_id: token.id, expires_on: token.expires_on ?? expires_on };
}

/** Deletes a token that was minted but won't be handed out. Best effort: the cron job is the fallback. */
export async function discard(cf: Cloudflare, accountId: string, id: string): Promise<void> {
  try {
    await cf.accounts.tokens.delete(id, { account_id: accountId });
    audit("token.revoke", { token_id: id, reason: "discarded" });
  } catch (err) {
    audit("token.revoke", { token_id: id, reason: "discard_failed", detail: String(err) });
  }
}

/** The API's answer for a token it doesn't recognize (invalid, expired, deleted, other account). */
function isGone(err: unknown): boolean {
  return (
    err instanceof AuthenticationError ||
    err instanceof PermissionDeniedError ||
    err instanceof NotFoundError ||
    err instanceof BadRequestError
  );
}

/**
 * Revokes a token the caller presents. Holding it is the proof of authorization.
 * Returns the deleted token's ID, or `undefined` if it was already gone.
 */
export async function revoke(cf: Cloudflare, accountId: string, presented: string): Promise<string | undefined> {
  let id: string;
  try {
    const self = new Cloudflare({ apiToken: presented, maxRetries: 1 });
    ({ id } = await self.accounts.tokens.verify({ account_id: accountId }));
  } catch (err) {
    if (isGone(err)) return undefined;
    throw err;
  }

  let name: string | undefined;
  try {
    ({ name } = await cf.accounts.tokens.get(id, { account_id: accountId }));
  } catch (err) {
    if (err instanceof NotFoundError) return undefined;
    throw err;
  }
  if (!name?.startsWith(TOKEN_PREFIX)) {
    throw new HttpError("forbidden", "foreign_token", id);
  }

  try {
    await cf.accounts.tokens.delete(id, { account_id: accountId });
  } catch (err) {
    if (!(err instanceof NotFoundError)) throw err;
  }
  return id;
}

/** Deletes expired `cf-oidc:` tokens. Returns how many were removed. */
export async function cleanup(cf: Cloudflare, accountId: string, now = Date.now()): Promise<number> {
  // Collect first: deleting while paginating would shift later pages and skip tokens.
  const expired: { id: string; name: string; expires_on: string }[] = [];
  for await (const t of cf.accounts.tokens.list({ account_id: accountId, include_expired: true })) {
    if (!t.id || !t.name?.startsWith(TOKEN_PREFIX) || !t.expires_on) continue;
    if (t.status === "expired" || Date.parse(t.expires_on) <= now) {
      expired.push({ id: t.id, name: t.name, expires_on: t.expires_on });
    }
  }

  let deleted = 0;
  for (const t of expired) {
    try {
      await cf.accounts.tokens.delete(t.id, { account_id: accountId });
      deleted++;
      audit("token.cleanup", { token_id: t.id, name: t.name, expires_on: t.expires_on });
    } catch (err) {
      if (!(err instanceof NotFoundError)) throw err;
    }
  }
  return deleted;
}
