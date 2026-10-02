// @ts-check
/** @typedef {import("../../cf-oidc-broker/src/api.js").TokenExchangeRequest} TokenExchangeRequest */
/** @typedef {import("../../cf-oidc-broker/src/api.js").TokenExchangeResponse} TokenExchangeResponse */
/** @typedef {import("../../cf-oidc-broker/src/api.js").ErrorResponse} ErrorResponse */
/** @typedef {import("../../cf-oidc-broker/src/api.js").BucketCredentials} BucketCredentials */
import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { brokerURL, fail, idToken, input, mask, write } from "./runner.js";

/** Hints for the statuses a misconfigured workflow or policy usually produces. */
const HINTS = /** @type {Record<number, string>} */ ({
  401: "the broker rejected the OIDC token; check that broker-url matches github.audience in the policy",
  403: "no profile allows this workflow; the broker's audit log has the reason",
  404: "the broker doesn't serve /oauth/token; deploy the broker from the same release as the action",
  500: "the broker is misconfigured; check its /healthz and logs",
});

/** Formats a Unix time in seconds like the broker's RFC 3339 timestamps, e.g. `2026-09-28T12:15:00Z`. */
const rfc3339 = (/** @type {number} */ seconds) => new Date(seconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");

/** R2's bucket name rules. The name becomes a section header in the credentials file. */
const BUCKET_NAME = /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/;

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

  /** @type {TokenExchangeRequest} */
  const body = {
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    subject_token: jwt,
    subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
    profile: input("profile") || undefined,
    ttl: input("ttl") || undefined,
  };

  // No retry: minting isn't idempotent. A token orphaned by a failed request is removed by the broker's cron cleanup.
  const response = await fetch(new URL("/oauth/token", broker), {
    method: "POST",
    headers: { "content-type": "application/json" },
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

  // The action asks for Cloudflare credentials, whose response always names the account.
  const t = /** @type {TokenExchangeResponse & { account_id: string }} */ (await response.json());
  requireStrings(t, ["account_id"]);
  // A profile with only buckets has no token.
  if (t.access_token !== undefined || t.token_id !== undefined) {
    requireStrings(t, ["access_token", "token_id"]);
    if (!Number.isFinite(t.expires_at))
      throw new Error("cf-oidc broker returned an invalid response: missing expires_at");
  }
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
    // Written into an INI file, so nothing may break out of its line or section.
    const secrets = [b.access_key_id, b.secret_access_key, b.session_token];
    if (!BUCKET_NAME.test(b.name) || secrets.some((v) => /\s/.test(v))) {
      throw new Error(`cf-oidc broker returned an invalid response: malformed buckets.${i}`);
    }
  });
  if (t.access_token === undefined && buckets.length === 0) {
    throw new Error("cf-oidc broker returned an invalid response: missing token and buckets");
  }

  write("GITHUB_ENV", "CLOUDFLARE_ACCOUNT_ID", t.account_id);
  if (t.access_token !== undefined && t.token_id !== undefined) {
    mask(t.access_token);
    write("GITHUB_ENV", "CLOUDFLARE_API_TOKEN", t.access_token);
    write("GITHUB_STATE", "token", t.access_token); // read by post.js as STATE_token
    write("GITHUB_STATE", "token_id", t.token_id);
    console.log(`cf-oidc: minted token ${t.token_id} (profile ${t.profile}, expires ${rfc3339(t.expires_at)})`);
  }

  if (buckets.length > 0) {
    for (const b of buckets) {
      mask(b.secret_access_key);
      mask(b.session_token);
    }
    // One profile per bucket, named after it. Region and endpoint stay in the environment:
    // every bucket in the account has the same endpoint.
    const runnerTemp = process.env.RUNNER_TEMP;
    if (!runnerTemp) throw new Error("RUNNER_TEMP is not set; is this running in GitHub Actions?");
    const dir = join(runnerTemp, "cf-oidc");
    const file = join(dir, "credentials");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const profiles = buckets.map(
      (b) =>
        `[${b.name}]\naws_access_key_id = ${b.access_key_id}\naws_secret_access_key = ${b.secret_access_key}\naws_session_token = ${b.session_token}\n`,
    );
    writeFileSync(file, profiles.join("\n"), { mode: 0o600 });
    chmodSync(file, 0o600); // an existing file keeps its old mode otherwise
    write("GITHUB_STATE", "credentials_file", file); // deleted by post.js

    write("GITHUB_ENV", "AWS_SHARED_CREDENTIALS_FILE", file);
    write("GITHUB_ENV", "AWS_ENDPOINT_URL_S3", /** @type {BucketCredentials} */ (buckets[0]).endpoint);
    write("GITHUB_ENV", "AWS_REGION", "auto");
    write("GITHUB_ENV", "AWS_DEFAULT_REGION", "auto");
    const prefixes = Object.fromEntries(buckets.map((b) => [b.name, b.prefixes]));
    write("GITHUB_ENV", "CLOUDFLARE_R2_BUCKETS", JSON.stringify(prefixes));

    // With one bucket, its credentials are also the default, so tools work without a
    // profile. With several there's no sensible default: clear the credentials, so a step
    // that forgets its profile fails instead of using ones an earlier step left behind.
    // Empty means unset to the AWS CLI and SDKs; botocore still reads the legacy name.
    const only = buckets.length === 1 ? buckets[0] : undefined;
    write("GITHUB_ENV", "AWS_ACCESS_KEY_ID", only?.access_key_id ?? "");
    write("GITHUB_ENV", "AWS_SECRET_ACCESS_KEY", only?.secret_access_key ?? "");
    write("GITHUB_ENV", "AWS_SESSION_TOKEN", only?.session_token ?? "");
    write("GITHUB_ENV", "AWS_SECURITY_TOKEN", only?.session_token ?? "");
    write("GITHUB_ENV", "CLOUDFLARE_R2_BUCKET", only?.name ?? "");
    // Only meaningful for exactly one prefix; CLOUDFLARE_R2_BUCKETS has them all.
    write("GITHUB_ENV", "CLOUDFLARE_R2_PREFIX", only?.prefixes.length === 1 ? (only.prefixes[0] ?? "") : "");

    // Every bucket is issued with the same TTL; the post step reports the earliest expiry.
    const expires = buckets.map((b) => b.expires_on).sort()[0];
    write("GITHUB_STATE", "r2_expires_on", /** @type {string} */ (expires));
    for (const b of buckets) {
      const scope = b.prefixes.length > 0 ? ` under ${b.prefixes.join(", ")}` : "";
      console.log(
        `cf-oidc: issued R2 credentials for bucket ${b.name}${scope} as AWS profile ${b.name} (profile ${t.profile}, expires ${b.expires_on})`,
      );
    }
  }
} catch (err) {
  fail(err);
}
