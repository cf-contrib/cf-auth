// Boots the release artifact (dist/broker.js) in workerd, to catch bundling
// problems the source-level tests can't see. Run `pnpm build` first.
import { writeFileSync } from "node:fs";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

// dist/broker.js imports ./policy.json, which a deploy puts next to it.
const policy = {
  version: 1,
  github: { audience: "https://cf-auth.example.com", owner_id: "100000001" },
  profiles: [
    {
      name: "workers-deploy",
      match: { repository_id: "200000002" },
      token: {
        policies: [
          {
            permissions: ["Workers Scripts Write"],
            resources: { "com.cloudflare.api.account.0123456789abcdef0123456789abcdef": "*" },
          },
        ],
      },
    },
  ],
};
writeFileSync("dist/policy.json", JSON.stringify(policy));

export default defineConfig({
  plugins: [
    cloudflareTest({
      main: "./dist/broker.js",
      miniflare: {
        compatibilityDate: "2026-08-15",
        // The broker token comes from a real (local) Secrets Store binding, seeded by the test.
        secretsStoreSecrets: {
          CF_OIDC_BROKER_TOKEN: { store_id: "test-store", secret_name: "cf-auth-broker-token" },
        },
        bindings: {
          CF_OIDC_BROKER_ACCOUNT_ID: "0123456789abcdef0123456789abcdef",
        },
      },
    }),
  ],
  test: {
    include: ["test/bundle/*.test.ts"],
  },
});
