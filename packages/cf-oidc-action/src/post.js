// @ts-check
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
    const response = await fetch(new URL("/v1/revoke", broker), {
      method: "POST",
      headers: { authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(30_000),
    });
    if (response.status === 204) {
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
