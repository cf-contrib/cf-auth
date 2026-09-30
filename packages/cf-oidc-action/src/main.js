// @ts-check
/** @typedef {import("../../cf-oidc-broker/src/api.js").TokenRequest} TokenRequest */
/** @typedef {import("../../cf-oidc-broker/src/api.js").TokenResponse} TokenResponse */
/** @typedef {import("../../cf-oidc-broker/src/api.js").ErrorResponse} ErrorResponse */
import { brokerURL, fail, idToken, input, mask, write } from "./runner.js";

/** Hints for the statuses a misconfigured workflow or policy usually produces. */
const HINTS = /** @type {Record<number, string>} */ ({
  401: "the broker rejected the OIDC token; check that broker-url matches github.audience in the policy",
  403: "no profile allows this workflow; the broker's audit log has the reason",
  500: "the broker is misconfigured; check its /healthz and logs",
});

/**
 * Fails unless every field is a non-empty string, rather than export "undefined".
 * @param {object} obj @param {readonly string[]} fields @param {string} [at]
 */
function requireStrings(obj, fields, at = "") {
  for (const field of fields) {
    const value = /** @type {Record<string, unknown>} */ (obj)[field];
    if (typeof value !== "string" || value === "") {
      throw new Error(`cf-oidc broker returned an invalid response: missing ${at}${field}`);
    }
  }
}

try {
  const broker = brokerURL(input("broker-url"));
  const jwt = await idToken(broker.origin);
  mask(jwt);

  /** @type {TokenRequest} */
  const body = { profile: input("profile") || undefined, ttl: input("ttl") || undefined };

  // No retry: minting isn't idempotent. A token orphaned by a failed request is removed by the broker's cron cleanup.
  const response = await fetch(new URL("/v1/token", broker), {
    method: "POST",
    headers: { authorization: `Bearer ${jwt}`, "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) {
    const { error } = /** @type {Partial<ErrorResponse>} */ (await response.json().catch(() => ({})));
    const hint = HINTS[response.status];
    throw new Error(
      `cf-oidc broker returned ${response.status}${error ? ` (${error})` : ""}${hint ? `: ${hint}` : ""}`,
    );
  }

  const t = /** @type {TokenResponse} */ (await response.json());
  requireStrings(t, ["account_id"]);
  // A profile with only buckets has no token.
  if (t.token !== undefined || t.token_id !== undefined) requireStrings(t, ["token", "token_id"]);
  const buckets = t.buckets ?? [];
  if (!Array.isArray(buckets)) throw new Error("cf-oidc broker returned an invalid response: buckets is not a list");
  buckets.forEach((b, i) => {
    requireStrings(
      b,
      ["name", "access_key_id", "secret_access_key", "session_token", "endpoint", "expires_on"],
      `buckets.${i}.`,
    );
    if (!Array.isArray(b.prefixes)) {
      throw new Error(`cf-oidc broker returned an invalid response: missing buckets.${i}.prefixes`);
    }
  });
  // AWS_* holds one set of credentials. Checked before exporting anything.
  if (buckets.length > 1) {
    throw new Error(`profile ${t.profile} has ${buckets.length} buckets; this version of the action exports one`);
  }
  if (t.token === undefined && buckets.length === 0) {
    throw new Error("cf-oidc broker returned an invalid response: missing token and buckets");
  }

  write("GITHUB_ENV", "CLOUDFLARE_ACCOUNT_ID", t.account_id);
  if (t.token !== undefined && t.token_id !== undefined) {
    mask(t.token);
    write("GITHUB_ENV", "CLOUDFLARE_API_TOKEN", t.token);
    write("GITHUB_STATE", "token", t.token); // read by post.js as STATE_token
    write("GITHUB_STATE", "token_id", t.token_id);
    console.log(`cf-oidc: minted token ${t.token_id} (profile ${t.profile}, expires ${t.expires_on})`);
  }

  const bucket = buckets[0];
  if (bucket !== undefined) {
    mask(bucket.secret_access_key);
    mask(bucket.session_token);
    // These replace any AWS credentials an earlier step left in the job.
    write("GITHUB_ENV", "AWS_ACCESS_KEY_ID", bucket.access_key_id);
    write("GITHUB_ENV", "AWS_SECRET_ACCESS_KEY", bucket.secret_access_key);
    // botocore still reads the legacy name.
    write("GITHUB_ENV", "AWS_SESSION_TOKEN", bucket.session_token);
    write("GITHUB_ENV", "AWS_SECURITY_TOKEN", bucket.session_token);
    write("GITHUB_ENV", "AWS_ENDPOINT_URL_S3", bucket.endpoint);
    write("GITHUB_ENV", "AWS_REGION", "auto");
    write("GITHUB_ENV", "AWS_DEFAULT_REGION", "auto");
    write("GITHUB_ENV", "CLOUDFLARE_R2_BUCKET", bucket.name);
    if (bucket.prefixes.length === 1) {
      write("GITHUB_ENV", "CLOUDFLARE_R2_PREFIX", /** @type {string} */ (bucket.prefixes[0]));
    }
    write("GITHUB_STATE", "r2_expires_on", bucket.expires_on);
    const scope = bucket.prefixes.length > 0 ? ` under ${bucket.prefixes.join(", ")}` : "";
    console.log(
      `cf-oidc: issued R2 credentials for bucket ${bucket.name}${scope} (profile ${t.profile}, expires ${bucket.expires_on})`,
    );
  }
} catch (err) {
  fail(err);
}
