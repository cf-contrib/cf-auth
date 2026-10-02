import { adminSecretsStore, env, SELF } from "cloudflare:test";
import { expect, it } from "vitest";

declare global {
  namespace Cloudflare {
    interface Env {
      CF_OIDC_BROKER_TOKEN: SecretsStoreSecret;
    }
  }
}

// A missing secret is covered in worker.test.ts; here it would only make
// Miniflare's local Secrets Store log a noisy uncaught error.
it("reads the broker token from Secrets Store and serves /healthz", async () => {
  await adminSecretsStore(env.CF_OIDC_BROKER_TOKEN).create("unused-broker-token-value");
  const res = await SELF.fetch("https://cf-auth.example.com/healthz");
  expect(res.status).toBe(200);
});

const form = { "content-type": "application/x-www-form-urlencoded" };

it("refuses a token exchange without a subject token", async () => {
  const res = await SELF.fetch("https://cf-auth.example.com/oauth/token", {
    method: "POST",
    headers: form,
    body: "grant_type=urn:ietf:params:oauth:grant-type:token-exchange",
  });
  expect(res.status).toBe(400);
  expect(await res.json()).toEqual({ error: "bad_request" });
});

it("refuses to revoke without a token", async () => {
  const res = await SELF.fetch("https://cf-auth.example.com/oauth/revoke", { method: "POST", headers: form, body: "" });
  expect(res.status).toBe(400);
});
