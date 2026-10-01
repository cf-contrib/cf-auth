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

it("rejects a mint without a JWT", async () => {
  const res = await SELF.fetch("https://cf-auth.example.com/v1/actions/token", { method: "POST" });
  expect(res.status).toBe(401);
  expect(await res.json()).toEqual({ error: "unauthorized" });
});

it("refuses to revoke without a token", async () => {
  const res = await SELF.fetch("https://cf-auth.example.com/v1/revoke", { method: "POST" });
  expect(res.status).toBe(401);
});
