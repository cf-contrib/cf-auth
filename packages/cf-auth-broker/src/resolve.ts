import type Cloudflare from "cloudflare";
import type { TokenPolicyParam } from "cloudflare/resources/shared";
import { HttpError } from "./errors.js";
import type { Resources, TokenPolicy } from "./policy.js";

/** Permission groups change rarely; a stale entry costs at most one failed mint. */
const TTL_SECONDS = 3600;

const ACCOUNT_SCOPE = "com.cloudflare.api.account";
const ZONE_SCOPE = "com.cloudflare.api.account.zone";
const R2_SCOPE = "com.cloudflare.edge.r2.bucket";

interface PermissionGroup {
  id: string;
  name: string;
  scopes: string[];
}

const memory = new Map<string, { value: unknown; expires: number }>();

/** Two-level cache: per-isolate memory first, then the Cache API (shared per colo). */
async function cached<T>(key: string, load: () => Promise<T>): Promise<T> {
  const hit = memory.get(key);
  if (hit && hit.expires > Date.now()) return hit.value as T;

  const cache = typeof caches === "undefined" ? undefined : caches.default;
  const url = `https://cf-auth.internal/${encodeURIComponent(key)}`;

  let value: T;
  const stored = await cache?.match(url);
  if (stored) {
    value = await stored.json();
  } else {
    value = await load();
    await cache?.put(
      url,
      new Response(JSON.stringify(value), { headers: { "cache-control": `max-age=${TTL_SECONDS}` } }),
    );
  }

  memory.set(key, { value, expires: Date.now() + TTL_SECONDS * 1000 });
  return value;
}

/** Test hook: forget everything cached in this isolate. */
export function clearCache() {
  memory.clear();
}

async function permissionGroups(cf: Cloudflare, accountId: string): Promise<PermissionGroup[]> {
  return cached(`permission-groups/${accountId}`, async () => {
    const groups: PermissionGroup[] = [];
    for await (const g of cf.accounts.tokens.permissionGroups.list({ account_id: accountId })) {
      if (g.id && g.name) groups.push({ id: g.id, name: g.name, scopes: g.scopes ?? [] });
    }
    return groups;
  });
}

/** The scope a permission group needs for these resources, used to pick between same-named groups. */
function scopeFor(resources: Resources): string {
  const keys = Object.keys(resources);
  if (keys.some((k) => k.startsWith(R2_SCOPE))) return R2_SCOPE;
  if (keys.some((k) => k.startsWith(`${ZONE_SCOPE}.`))) return ZONE_SCOPE;
  // Nested form: `account.<id>: { "account.zone.*": "*" }` grants every zone in the account.
  const nested = Object.values(resources).flatMap((v) => (typeof v === "object" ? Object.keys(v) : []));
  if (nested.some((k) => k.startsWith(`${ZONE_SCOPE}.`))) return ZONE_SCOPE;
  return ACCOUNT_SCOPE;
}

function pickGroup(groups: PermissionGroup[], name: string, scope: string): PermissionGroup {
  const named = groups.filter((g) => g.name === name);
  if (named.length === 1) return named[0] as PermissionGroup;
  const scoped = named.filter((g) => g.scopes.includes(scope));
  if (scoped.length === 1) return scoped[0] as PermissionGroup;
  throw new HttpError("misconfigured", named.length === 0 ? "unknown_permission" : "ambiguous_permission", name);
}

/**
 * Resolves permission-group names to IDs; resources are already in the API's shape.
 * An unknown name is a configuration error, never a silent drop.
 */
export async function resolvePolicies(
  cf: Cloudflare,
  accountId: string,
  policies: TokenPolicy[],
): Promise<TokenPolicyParam[]> {
  const groups = await permissionGroups(cf, accountId);
  return policies.map((p) => {
    const scope = scopeFor(p.resources);
    return {
      effect: p.effect,
      permission_groups: p.permissions.map((name) => ({ id: pickGroup(groups, name, scope).id })),
      // Passed through as written; the SDK types it more narrowly than the policy schema.
      resources: p.resources as TokenPolicyParam["resources"],
    };
  });
}
