import type Cloudflare from "cloudflare";
import type { R2Credentials } from "./api.js";
import { HttpError } from "./errors.js";
import type { R2Grant } from "./policy.js";
import { rfc3339 } from "./tokens.js";

// The broker token's ID, which is its R2 access key ID. Kept per isolate and keyed by
// the token value, so a rotated broker token is looked up again.
let parent: { apiToken: string; id: string } | undefined;

/** Test hook: forget the cached parent access key ID. */
export function clearParent() {
  parent = undefined;
}

async function parentKeyId(cf: Cloudflare, accountId: string): Promise<string> {
  const apiToken = cf.apiToken ?? "";
  if (parent?.apiToken !== apiToken) {
    const { id } = await cf.accounts.tokens.verify({ account_id: accountId });
    if (!id) throw new HttpError("upstream_error", "cloudflare_error", "tokens.verify returned no id");
    parent = { apiToken, id };
  }
  return parent.id;
}

/**
 * Creates temporary S3 credentials for the grant's bucket, limited to `prefixes`
 * (already filled in), with the broker token as the parent.
 */
export async function issueR2(
  cf: Cloudflare,
  accountId: string,
  grant: R2Grant,
  prefixes: string[],
  ttl: number,
): Promise<R2Credentials> {
  const parentAccessKeyId = await parentKeyId(cf, accountId);
  const expires_on = rfc3339(Date.now() + ttl);

  const creds = await cf.r2.temporaryCredentials.create({
    account_id: accountId,
    bucket: grant.bucket,
    parentAccessKeyId,
    permission: grant.permission,
    ttlSeconds: Math.floor(ttl / 1000),
    ...(prefixes.length > 0 ? { prefixes } : {}),
  });
  if (!creds.accessKeyId || !creds.secretAccessKey || !creds.sessionToken) {
    throw new HttpError("upstream_error", "cloudflare_error", "temporaryCredentials.create returned no credentials");
  }

  return {
    access_key_id: creds.accessKeyId,
    secret_access_key: creds.secretAccessKey,
    session_token: creds.sessionToken,
    bucket: grant.bucket,
    prefixes,
    endpoint: `https://${accountId}.r2.cloudflarestorage.com`,
    expires_on,
  };
}
