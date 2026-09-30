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
  // A profile with only an r2 grant has no token.
  if (t.token !== undefined || t.token_id !== undefined) requireStrings(t, ["token", "token_id"]);
  if (t.r2 !== undefined) {
    requireStrings(
      t.r2,
      ["access_key_id", "secret_access_key", "session_token", "bucket", "endpoint", "expires_on"],
      "r2.",
    );
    if (!Array.isArray(t.r2.prefixes)) {
      throw new Error("cf-oidc broker returned an invalid response: missing r2.prefixes");
    }
  }
  if (t.token === undefined && t.r2 === undefined) {
    throw new Error("cf-oidc broker returned an invalid response: missing token and r2");
  }

  write("GITHUB_ENV", "CLOUDFLARE_ACCOUNT_ID", t.account_id);
  if (t.token !== undefined && t.token_id !== undefined) {
    mask(t.token);
    write("GITHUB_ENV", "CLOUDFLARE_API_TOKEN", t.token);
    write("GITHUB_STATE", "token", t.token); // read by post.js as STATE_token
    write("GITHUB_STATE", "token_id", t.token_id);
    console.log(`cf-oidc: minted token ${t.token_id} (profile ${t.profile}, expires ${t.expires_on})`);
  }

  if (t.r2 !== undefined) {
    const r2 = t.r2;
    mask(r2.secret_access_key);
    mask(r2.session_token);
    // These replace any AWS credentials an earlier step left in the job.
    write("GITHUB_ENV", "AWS_ACCESS_KEY_ID", r2.access_key_id);
    write("GITHUB_ENV", "AWS_SECRET_ACCESS_KEY", r2.secret_access_key);
    // botocore still reads the legacy name.
    write("GITHUB_ENV", "AWS_SESSION_TOKEN", r2.session_token);
    write("GITHUB_ENV", "AWS_SECURITY_TOKEN", r2.session_token);
    write("GITHUB_ENV", "AWS_ENDPOINT_URL_S3", r2.endpoint);
    write("GITHUB_ENV", "AWS_REGION", "auto");
    write("GITHUB_ENV", "AWS_DEFAULT_REGION", "auto");
    write("GITHUB_ENV", "CLOUDFLARE_R2_BUCKET", r2.bucket);
    if (r2.prefixes.length === 1) write("GITHUB_ENV", "CLOUDFLARE_R2_PREFIX", /** @type {string} */ (r2.prefixes[0]));
    write("GITHUB_STATE", "r2_expires_on", r2.expires_on);
    const scope = r2.prefixes.length > 0 ? ` under ${r2.prefixes.join(", ")}` : "";
    console.log(
      `cf-oidc: issued R2 credentials for bucket ${r2.bucket}${scope} (profile ${t.profile}, expires ${r2.expires_on})`,
    );
  }
} catch (err) {
  fail(err);
}
