// End-to-end tests of the Worker's handlers inside workerd, with GitHub and the
// Cloudflare API replaced by in-memory fakes.
import { createExecutionContext, createScheduledController, waitOnExecutionContext } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { TokenResponse } from "../src/api.js";
import worker, { type Env } from "../src/index.js";
import { clearCache } from "../src/resolve.js";
import { tokenName } from "../src/tokens.js";
import {
  ACCOUNT_ID,
  BROKER_TOKEN,
  createIssuer,
  FakeCloudflare,
  githubClaims,
  installFetch,
  testPolicy,
  ZONE_ID,
} from "./helpers.js";

// A unique issuer keeps this file's JWKS out of any other file's per-isolate cache.
const ISSUER = `https://token.actions.githubusercontent.com/worker-test-${crypto.randomUUID()}`;

let issuer: Awaited<ReturnType<typeof createIssuer>>;
let cf: FakeCloudflare;
let env: Env;
let logs: string[];

beforeAll(async () => {
  issuer = await createIssuer(ISSUER);
});

beforeEach(() => {
  clearCache();
  cf = new FakeCloudflare();
  installFetch(issuer, cf);
  env = {
    CF_AUTH_BROKER_ACCOUNT_ID: ACCOUNT_ID,
    CF_AUTH_BROKER_POLICY: JSON.stringify(testPolicy(ISSUER)),
    CF_AUTH_BROKER_TOKEN: { get: async () => BROKER_TOKEN },
  };
  logs = [];
  const capture = (...args: unknown[]) => void logs.push(args.join(" "));
  vi.spyOn(console, "log").mockImplementation(capture);
  vi.spyOn(console, "warn").mockImplementation(capture);
  vi.spyOn(console, "error").mockImplementation(capture);
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function call(method: string, path: string, init: { token?: string; body?: unknown } = {}) {
  const headers: Record<string, string> = {};
  if (init.token) headers.authorization = `Bearer ${init.token}`;
  if (init.body !== undefined) headers["content-type"] = "application/json";
  const request = new Request(`https://cf-auth.example.com${path}`, {
    method,
    headers,
    ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
  });
  return worker.fetch(request as Parameters<typeof worker.fetch>[0], env);
}

const auditLines = () => logs.map((l) => JSON.parse(l) as Record<string, unknown>);

describe("POST /v1/token", () => {
  it("mints a scoped, expiring token", async () => {
    const before = Date.now();
    const res = await call("POST", "/v1/token", { token: await issuer.sign(), body: { rule: "workers-deploy" } });
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");

    const body = (await res.json()) as TokenResponse;
    expect(body.rule).toBe("workers-deploy");
    expect(body.account_id).toBe(ACCOUNT_ID);
    expect(body.token).toMatch(/^value-/);

    const created = cf.tokens.get(body.token_id);
    expect(created?.name).toBe("cf-auth:example-org/api:1234567890:1");
    expect(created?.policies).toEqual([
      {
        effect: "allow",
        permission_groups: [{ id: "pg-workers-scripts-write" }],
        resources: { [`com.cloudflare.api.account.${ACCOUNT_ID}`]: "*" },
      },
    ]);

    // Default ttl is 15m, sent without fractional seconds.
    expect(body.expires_on).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
    const ttl = Date.parse(body.expires_on) - before;
    expect(ttl).toBeGreaterThan(14 * 60_000);
    expect(ttl).toBeLessThanOrEqual(15 * 60_000 + 1000);
  });

  it("uses the single matching rule when none is named", async () => {
    const res = await call("POST", "/v1/token", { token: await issuer.sign() });
    expect(res.status).toBe(200);
    expect(((await res.json()) as TokenResponse).rule).toBe("workers-deploy");
  });

  it("resolves permission names to IDs and passes resources through", async () => {
    const claims = githubClaims({ repository: "example-org/infra", repository_id: "200000002" });
    const res = await call("POST", "/v1/token", {
      token: await issuer.sign(claims),
      body: { rule: "infra-cloudflare" },
    });
    expect(res.status).toBe(200);
    const { token_id } = (await res.json()) as TokenResponse;
    expect(cf.tokens.get(token_id)?.policies).toEqual([
      {
        effect: "allow",
        permission_groups: [{ id: "pg-zone-write" }, { id: "pg-dns-write" }],
        resources: { [`com.cloudflare.api.account.zone.${ZONE_ID}`]: "*" },
      },
    ]);
  });

  it("clamps the requested ttl to max_ttl", async () => {
    const res = await call("POST", "/v1/token", { token: await issuer.sign(), body: { ttl: "12h" } });
    const { expires_on } = (await res.json()) as TokenResponse;
    expect(Date.parse(expires_on) - Date.now()).toBeLessThanOrEqual(60 * 60_000 + 1000);
  });

  it("writes an audit line without secrets", async () => {
    const res = await call("POST", "/v1/token", { token: await issuer.sign() });
    const { token, token_id } = (await res.json()) as TokenResponse;
    const mint = auditLines().find((l) => l.event === "token.mint");
    expect(mint).toMatchObject({
      rule: "workers-deploy",
      repository: "example-org/api",
      repository_id: "200000003",
      ref: "refs/heads/main",
      environment: "prod",
      run_id: "1234567890",
      run_attempt: "1",
      actor_id: "300000004",
      token_id,
    });
    expect(logs.join("\n")).not.toContain(token);
  });

  it("401s without a JWT", async () => {
    const res = await call("POST", "/v1/token", {});
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
  });

  it("401s on a JWT for another audience", async () => {
    const jwt = await issuer.sign(undefined, { audience: "sts.amazonaws.com" });
    expect((await call("POST", "/v1/token", { token: jwt })).status).toBe(401);
  });

  it("403s for a repo outside the pinned owner, with a generic body", async () => {
    const claims = githubClaims({ repository: "example-org/api", repository_owner_id: "999999" });
    const res = await call("POST", "/v1/token", { token: await issuer.sign(claims) });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });
    expect(auditLines().find((l) => l.event === "token.deny")).toMatchObject({ reason: "no_match" });
    expect(cf.tokens.size).toBe(1); // only the broker token
  });

  it("403s when several rules match and none is named", async () => {
    const claims = githubClaims({ repository: "example-org/infra", repository_id: "200000002" });
    const res = await call("POST", "/v1/token", { token: await issuer.sign(claims) });
    expect(res.status).toBe(403);
    expect(auditLines().find((l) => l.event === "token.deny")).toMatchObject({ reason: "ambiguous" });
  });

  it("403s when the named rule doesn't match", async () => {
    const res = await call("POST", "/v1/token", { token: await issuer.sign(), body: { rule: "infra-cloudflare" } });
    expect(res.status).toBe(403);
    expect(auditLines().find((l) => l.event === "token.deny")).toMatchObject({
      reason: "rule_mismatch",
      rule: "infra-cloudflare",
    });
  });

  it.each([[{ ttl: "forever" }], [{ ttl: 600 }], [[1, 2]], [{ rule: "x".repeat(65) }]])(
    "400s on body %j",
    async (body) => {
      expect((await call("POST", "/v1/token", { token: await issuer.sign(), body })).status).toBe(400);
    },
  );

  it("logs the rule count when the policy loads", async () => {
    env.CF_AUTH_BROKER_POLICY = JSON.stringify({ ...testPolicy(ISSUER), defaults: { ttl: "10m" } }); // force a reload
    await call("GET", "/healthz");
    expect(auditLines().find((l) => l.event === "policy.loaded")).toEqual({ event: "policy.loaded", rules: 3 });
  });

  it("500s, failing closed, when the policy is invalid", async () => {
    env.CF_AUTH_BROKER_POLICY = JSON.stringify({
      ...testPolicy(ISSUER),
      github: { audience: "https://x.example.com" },
    });
    const res = await call("POST", "/v1/token", { token: await issuer.sign() });
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "misconfigured" });
  });

  it("500s when a permission name is unknown", async () => {
    const policy = testPolicy(ISSUER);
    (policy.rules[1]?.token.policies[0] as { permissions: string[] }).permissions = ["Workers Scrpts Write"];
    env.CF_AUTH_BROKER_POLICY = JSON.stringify(policy);
    const res = await call("POST", "/v1/token", { token: await issuer.sign() });
    expect(res.status).toBe(500);
    expect(auditLines().find((l) => l.event === "token.deny")).toMatchObject({ reason: "unknown_permission" });
  });

  it("picks the right scope for a permission name shared by two groups", async () => {
    const policy = testPolicy(ISSUER);
    (policy.rules[1]?.token.policies[0] as { permissions: string[] }).permissions = ["Load Balancers Write"];
    env.CF_AUTH_BROKER_POLICY = JSON.stringify(policy);
    const res = await call("POST", "/v1/token", { token: await issuer.sign() });
    const { token_id } = (await res.json()) as TokenResponse;
    expect(cf.tokens.get(token_id)?.policies[0]).toMatchObject({
      permission_groups: [{ id: "pg-lb-write-account" }],
    });
  });

  it("picks the zone-scoped group for zone resources", async () => {
    const policy = testPolicy(ISSUER);
    (policy.rules[0]?.token.policies[0] as { permissions: string[] }).permissions = ["Load Balancers Write"];
    env.CF_AUTH_BROKER_POLICY = JSON.stringify(policy);
    const claims = githubClaims({ repository: "example-org/infra", repository_id: "200000002" });
    const res = await call("POST", "/v1/token", {
      token: await issuer.sign(claims),
      body: { rule: "infra-cloudflare" },
    });
    const { token_id } = (await res.json()) as TokenResponse;
    expect(cf.tokens.get(token_id)?.policies[0]).toMatchObject({
      permission_groups: [{ id: "pg-lb-write-zone" }],
    });
  });

  it("500s when the policy names another account", async () => {
    env.CF_AUTH_BROKER_ACCOUNT_ID = "ffffffffffffffffffffffffffffffff";
    const res = await call("POST", "/v1/token", { token: await issuer.sign() });
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "misconfigured" });
  });

  it("502s when the Cloudflare API fails, without retrying the create", async () => {
    cf.failCreate = true;
    const res = await call("POST", "/v1/token", { token: await issuer.sign() });
    expect(res.status).toBe(502);
    expect(cf.requests.filter((r) => r.method === "POST").length).toBe(1);
  });
});

describe("POST /v1/revoke", () => {
  async function minted(): Promise<TokenResponse> {
    const res = await call("POST", "/v1/token", { token: await issuer.sign() });
    return (await res.json()) as TokenResponse;
  }

  it("deletes a cf-auth token", async () => {
    const t = await minted();
    const res = await call("POST", "/v1/revoke", { token: t.token });
    expect(res.status).toBe(204);
    expect(cf.tokens.has(t.token_id)).toBe(false);
    expect(auditLines().find((l) => l.event === "token.revoke")).toMatchObject({ token_id: t.token_id });
  });

  it("204s when the token is already gone", async () => {
    const t = await minted();
    await call("POST", "/v1/revoke", { token: t.token });
    expect((await call("POST", "/v1/revoke", { token: t.token })).status).toBe(204);
    expect((await call("POST", "/v1/revoke", { token: "never-existed" })).status).toBe(204);
  });

  it("refuses to delete tokens cf-auth didn't mint", async () => {
    const foreign = cf.add({ name: "ci deploy (manual)" });
    const res = await call("POST", "/v1/revoke", { token: foreign.value });
    expect(res.status).toBe(403);
    expect(cf.tokens.has(foreign.id)).toBe(true);
  });

  it("refuses to delete the broker token", async () => {
    expect((await call("POST", "/v1/revoke", { token: BROKER_TOKEN })).status).toBe(403);
  });

  it("401s without a token", async () => {
    expect((await call("POST", "/v1/revoke")).status).toBe(401);
  });
});

describe("broker token", () => {
  const store = (get: () => Promise<string>) => ({ get: vi.fn(get) });

  it("is read from Secrets Store on every use", async () => {
    const secret = store(async () => BROKER_TOKEN);
    env.CF_AUTH_BROKER_TOKEN = secret;
    const res = await call("POST", "/v1/token", { token: await issuer.sign() });
    expect(res.status).toBe(200);
    const { token } = (await res.json()) as TokenResponse;
    expect((await call("POST", "/v1/revoke", { token })).status).toBe(204);
    // Read on every use, so a rotated secret takes effect without a redeploy.
    expect(secret.get).toHaveBeenCalledTimes(2);
  });

  it("500s, failing closed, when the secret can't be read", async () => {
    env.CF_AUTH_BROKER_TOKEN = store(async () => {
      throw new Error("secret not found");
    });
    const res = await call("POST", "/v1/token", { token: await issuer.sign() });
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "misconfigured" });
    expect(auditLines().find((l) => l.event === "token.deny")).toMatchObject({ reason: "broker_token_unavailable" });
    expect(cf.tokens.size).toBe(1); // nothing minted
  });

  it("reports an unreadable secret on /healthz", async () => {
    env.CF_AUTH_BROKER_TOKEN = store(async () => {
      throw new Error("secret not found");
    });
    expect((await call("GET", "/healthz")).status).toBe(500);
  });

  it("refuses a plain Worker secret, failing closed", async () => {
    env.CF_AUTH_BROKER_TOKEN = BROKER_TOKEN as unknown as SecretsStoreSecret;
    const res = await call("POST", "/v1/token", { token: await issuer.sign() });
    expect(res.status).toBe(500);
    expect(auditLines().find((l) => l.event === "token.deny")).toMatchObject({
      reason: "broker_token_unavailable",
      detail: "CF_AUTH_BROKER_TOKEN must be a Secrets Store binding",
    });
    expect(cf.tokens.size).toBe(1); // nothing minted
    expect((await call("GET", "/healthz")).status).toBe(500);
  });
});

describe("GET /healthz", () => {
  it("200s when the policy is valid", async () => {
    const res = await call("GET", "/healthz");
    expect(res.status).toBe(200);
    expect(await res.text()).not.toContain("owner_id");
  });

  it("500s when the policy is invalid, without revealing it", async () => {
    env.CF_AUTH_BROKER_POLICY = "{";
    const res = await call("GET", "/healthz");
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "misconfigured" });
  });

  it("accepts a policy passed as an object (wrangler [vars] table)", async () => {
    env.CF_AUTH_BROKER_POLICY = testPolicy(ISSUER);
    expect((await call("GET", "/healthz")).status).toBe(200);
  });
});

it("404s on unknown routes", async () => {
  expect((await call("GET", "/v1/token")).status).toBe(404);
  expect((await call("GET", "/")).status).toBe(404);
});

describe("scheduled cleanup", () => {
  it("deletes only expired cf-auth tokens", async () => {
    const past = new Date(Date.now() - 60_000).toISOString();
    const future = new Date(Date.now() + 60_000).toISOString();
    const expired = cf.add({ name: "cf-auth:example-org/api:1:1", expires_on: past, status: "expired" });
    const live = cf.add({ name: "cf-auth:example-org/api:2:1", expires_on: future });
    const foreign = cf.add({ name: "someone else's", expires_on: past, status: "expired" });

    const ctx = createExecutionContext();
    await worker.scheduled(createScheduledController(), env, ctx);
    await waitOnExecutionContext(ctx);

    expect(cf.tokens.has(expired.id)).toBe(false);
    expect(cf.tokens.has(live.id)).toBe(true);
    expect(cf.tokens.has(foreign.id)).toBe(true);
    expect(cf.requests.some((r) => r.path.endsWith("/tokens") && r.method === "GET")).toBe(true);
  });
});

describe("tokenName", () => {
  it("fits in 120 characters", () => {
    const name = tokenName(githubClaims({ repository: `example-org/${"x".repeat(200)}` }));
    expect(name.length).toBe(120);
    expect(name).toMatch(/^cf-auth:example-org\/x+:1234567890:1$/);
  });
});
