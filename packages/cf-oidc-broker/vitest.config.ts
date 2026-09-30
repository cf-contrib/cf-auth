import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    // No main: the tests build brokers with createBroker, since src/index.ts
    // imports a policy.json that isn't in the repo.
    cloudflareTest({
      miniflare: {
        compatibilityDate: "2026-08-15",
      },
    }),
  ],
  test: {
    include: ["test/*.test.ts"],
  },
});
