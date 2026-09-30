import Cloudflare, { AuthenticationError, BadRequestError, NotFoundError, PermissionDeniedError } from "cloudflare";
import { audit } from "./audit.js";
import { HttpError } from "./errors.js";
import type { Claims, TokenPolicy } from "./policy.js";
import { resolvePolicies } from "./resolve.js";

/** Every minted token's name starts with this. Revoke and cleanup never touch anything else. */
export const TOKEN_PREFIX = "cf-oidc:";
const NAME_MAX = 120;

/** `cf-oidc:<repo>:<run_id>:<attempt>`, truncating the repo so the name fits in 120 chars. */
export function tokenName(claims: Claims): string {
  const str = (key: string) => (typeof claims[key] === "string" ? (claims[key] as string) : "");
  const run = `:${str("run_id") || "0"}:${str("run_attempt") || "0"}`;
  const room = NAME_MAX - TOKEN_PREFIX.length - run.length;
  return `${TOKEN_PREFIX}${(str("repository") || "unknown").slice(0, room)}${run}`;
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
  claims: Claims,
  ttl: number,
): Promise<MintedToken> {
  const resolved = await resolvePolicies(cf, accountId, policies);
  const expires_on = rfc3339(Date.now() + ttl);

  const token = await cf.accounts.tokens.create(
    { account_id: accountId, name: tokenName(claims), policies: resolved, expires_on },
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
