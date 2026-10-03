// @ts-check
/** @typedef {import("./api.js").TokenRevocationRequest} TokenRevocationRequest */
// Revokes the token and deletes the R2 credentials file at job end. Never fails the
// job: the token expires on its own anyway.
import { rmSync } from "node:fs";
import { brokerURL, input, state, warning } from "./runner.js";

const token = state("token");
const id = state("token_id");
const r2ExpiresOn = state("r2_expires_on");
const credentialsFile = state("credentials_file");

if (credentialsFile) {
  try {
    rmSync(credentialsFile, { force: true });
    console.log(`cf-oidc: deleted ${credentialsFile}`);
  } catch (err) {
    warning(`cf-oidc: deleting ${credentialsFile} failed (${err instanceof Error ? err.message : err})`);
  }
}

if (r2ExpiresOn) {
  console.log(`cf-oidc: R2 temporary credentials can't be revoked; they expire at ${r2ExpiresOn}`);
}

if (token) {
  try {
    const broker = brokerURL(input("broker-url"));
    /** @satisfies {TokenRevocationRequest} */
    const body = { token, token_type_hint: "access_token" };
    // RFC 7009: form-encoded, and 200 whether revoked now or already gone.
    const response = await fetch(new URL("/oauth/revoke", broker), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body),
      signal: AbortSignal.timeout(30_000),
    });
    if (response.status === 200) {
      console.log(`cf-oidc: revoked token ${id}`);
    } else {
      warning(`cf-oidc: revoking token ${id} returned ${response.status}; it expires on its own`);
    }
  } catch (err) {
    warning(
      `cf-oidc: revoking token ${id} failed (${err instanceof Error ? err.message : err}); it expires on its own`,
    );
  }
}
