// @ts-check
// Revokes the token at job end. Never fails the job: the token expires on its own anyway.
import { brokerURL, input, state, warning } from "./runner.js";

const token = state("token");
const id = state("token_id");

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
