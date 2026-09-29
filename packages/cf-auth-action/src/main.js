// @ts-check
/** @typedef {import("../../cf-auth-broker/src/api.js").TokenRequest} TokenRequest */
/** @typedef {import("../../cf-auth-broker/src/api.js").TokenResponse} TokenResponse */
/** @typedef {import("../../cf-auth-broker/src/api.js").ErrorResponse} ErrorResponse */
import { createHash } from "node:crypto";
import { booleanInput, brokerURL, fail, idToken, input, mask, write } from "./runner.js";

/** Hints for the statuses a misconfigured workflow or policy usually produces. */
const HINTS = /** @type {Record<number, string>} */ ({
  401: "the broker rejected the OIDC token; check that broker-url matches github.audience in the policy",
  403: "no policy rule allows this workflow; the broker's audit log has the reason",
  500: "the broker is misconfigured; check its /healthz and logs",
});

try {
  const broker = brokerURL(input("broker-url"));
  // Parsed before minting, so a typo doesn't leave a token behind.
  const s3 = booleanInput("s3-credentials");
  const jwt = await idToken(broker.origin);
  mask(jwt);

  /** @type {TokenRequest} */
  const body = { rule: input("rule") || undefined, ttl: input("ttl") || undefined };

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
      `cf-auth broker returned ${response.status}${error ? ` (${error})` : ""}${hint ? `: ${hint}` : ""}`,
    );
  }

  const t = /** @type {TokenResponse} */ (await response.json());

  mask(t.token);
  write("GITHUB_ENV", "CLOUDFLARE_API_TOKEN", t.token);
  write("GITHUB_ENV", "CLOUDFLARE_ACCOUNT_ID", t.account_id);
  write("GITHUB_STATE", "token", t.token); // read by post.js as STATE_token
  write("GITHUB_STATE", "token_id", t.token_id);

  if (s3) {
    // R2 accepts any token with R2 permissions as S3 credentials: the token ID is the
    // access key and the SHA-256 of its value the secret. Revoking the token revokes both.
    const secret = createHash("sha256").update(t.token).digest("hex");
    mask(secret);
    write("GITHUB_ENV", "AWS_ACCESS_KEY_ID", t.token_id);
    write("GITHUB_ENV", "AWS_SECRET_ACCESS_KEY", secret);
    write("GITHUB_ENV", "AWS_ENDPOINT_URL_S3", `https://${t.account_id}.r2.cloudflarestorage.com`);
    write("GITHUB_ENV", "AWS_REGION", "auto");
  }

  console.log(`cf-auth: minted token ${t.token_id} (rule ${t.rule}, expires ${t.expires_on})`);
} catch (err) {
  fail(err);
}
