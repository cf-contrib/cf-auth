// End-to-end tests of the Worker's handlers inside workerd, with GitHub and the
// Cloudflare API replaced by in-memory fakes.
import { createExecutionContext, createScheduledController, waitOnExecutionContext } from "cloudflare:test";
import { createLocalJWKSet, decodeProtectedHeader, exportPKCS8, generateKeyPair, type JWK, jwtVerify } from "jose";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { TokenExchangeResponse } from "../src/api.js";
import { createBroker, type Env } from "../src/broker.js";
import { clearSigningKey } from "../src/issuer.js";
import { clearParent } from "../src/r2.js";
import { clearCache } from "../src/resolve.js";
import { tokenName } from "../src/tokens.js";
import {
  ACCOUNT_ID,
  AUDIENCE,
  BROKER_TOKEN,
  BROKER_TOKEN_ID,
  createIssuer,
  FakeCloudflare,
  FakeGitHub,
  githubClaims,
  installFetch,
  OWNER_ID,
  TEAM_ID,
  type TestPolicy,
  testPolicy,
  USER_ID,
  USER_TOKEN,
  ZONE_ID,
} from "./helpers.js";

type TestProfile = TestPolicy["profiles"][number];

/** A response for a profile with a token. */
type WithToken = TokenExchangeResponse & { access_token: string; token_id: string };

// A unique issuer keeps this file's JWKS out of any other file's per-isolate cache.
const ISSUER = `https://token.actions.githubusercontent.com/worker-test-${crypto.randomUUID()}`;

let issuer: Awaited<ReturnType<typeof createIssuer>>;
let cf: FakeCloudflare;
let github: FakeGitHub;
let env: Env;
let policyFile: unknown;
let logs: string[];

beforeAll(async () => {
  issuer = await createIssuer(ISSUER);
});

beforeEach(() => {
  clearCache();
  clearParent();
  cf = new FakeCloudflare();
  github = new FakeGitHub();
  installFetch(issuer, cf, github);
  env = {
    CF_OIDC_BROKER_ACCOUNT_ID: ACCOUNT_ID,
    CF_OIDC_BROKER_TOKEN: { get: async () => BROKER_TOKEN },
  };
  // policy.json as the Terraform module uploads it: JSON text.
  policyFile = JSON.stringify(testPolicy(ISSUER));
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
  const worker = createBroker(policyFile);
  return worker.fetch(request as Parameters<typeof worker.fetch>[0], env);
}

const GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
const ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token";
const ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";

/** Exchanges a job's OIDC token at `POST /oauth/token`, with the broker's own `fields`, as JSON. */
function jobToken(jwt: string, fields: Record<string, unknown> = {}) {
  return call("POST", "/oauth/token", {
    body: { grant_type: GRANT, subject_token: jwt, subject_token_type: ID_TOKEN, ...fields },
  });
}

/** Revokes `token` at `POST /oauth/revoke`, form-encoded as RFC 7009 has it. */
function revokeToken(token?: string) {
  const request = new Request("https://cf-auth.example.com/oauth/revoke", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(token === undefined ? {} : { token, token_type_hint: "access_token" }).toString(),
  });
  const worker = createBroker(policyFile);
  return worker.fetch(request as Parameters<typeof worker.fetch>[0], env);
}

const auditLines = () => logs.map((l) => JSON.parse(l) as Record<string, unknown>);

describe("token exchange for jobs", () => {
  it("mints a scoped, expiring token", async () => {
    const before = Date.now();
    const res = await jobToken(await issuer.sign(), { profile: "workers-deploy" });
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");

    const body = (await res.json()) as WithToken;
    expect(body.profile).toBe("workers-deploy");
    expect(body.account_id).toBe(ACCOUNT_ID);
    expect(body.access_token).toMatch(/^value-/);
    expect(body).toMatchObject({ issued_token_type: ACCESS_TOKEN, token_type: "Bearer" });

    const created = cf.tokens.get(body.token_id);
    expect(created?.name).toBe("cf-oidc:example-org/api:1234567890:1");
    expect(created?.policies).toEqual([
      {
        effect: "allow",
        permission_groups: [{ id: "pg-workers-scripts-write" }],
        resources: { [`com.cloudflare.api.account.${ACCOUNT_ID}`]: "*" },
      },
    ]);

    // Default ttl is 15m, sent to Cloudflare without fractional seconds.
    expect(created?.expires_on).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
    expect(body.expires_at).toBe(Date.parse(created?.expires_on ?? "") / 1000);
    const ttl = body.expires_at * 1000 - before;
    expect(ttl).toBeGreaterThan(14 * 60_000);
    expect(ttl).toBeLessThanOrEqual(15 * 60_000 + 1000);
  });

  it("uses the single matching profile when none is named", async () => {
    const res = await jobToken(await issuer.sign());
    expect(res.status).toBe(200);
    expect(((await res.json()) as WithToken).profile).toBe("workers-deploy");
  });

  it("resolves permission names to IDs and passes resources through", async () => {
    const claims = githubClaims({ repository: "example-org/infra", repository_id: "200000002" });
    const res = await jobToken(await issuer.sign(claims), { profile: "infra-cloudflare" });
    expect(res.status).toBe(200);
    const { token_id } = (await res.json()) as WithToken;
    expect(cf.tokens.get(token_id)?.policies).toEqual([
      {
        effect: "allow",
        permission_groups: [{ id: "pg-zone-write" }, { id: "pg-dns-write" }],
        resources: { [`com.cloudflare.api.account.zone.${ZONE_ID}`]: "*" },
      },
    ]);
  });

  it("clamps the requested ttl to max_ttl", async () => {
    const res = await jobToken(await issuer.sign(), { ttl: "12h" });
    const { expires_at, expires_in } = (await res.json()) as WithToken;
    expect(expires_at * 1000 - Date.now()).toBeLessThanOrEqual(60 * 60_000 + 1000);
    expect(expires_in).toBeLessThanOrEqual(60 * 60);
  });

  it("writes an audit line without secrets", async () => {
    const res = await jobToken(await issuer.sign());
    const { access_token: token, token_id } = (await res.json()) as WithToken;
    const mint = auditLines().find((l) => l.event === "token.mint");
    expect(mint).toMatchObject({
      profile: "workers-deploy",
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

  it("400s without a subject token", async () => {
    const res = await call("POST", "/oauth/token", { body: { grant_type: GRANT, subject_token_type: ID_TOKEN } });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "bad_request" });
  });

  it("401s on a JWT for another audience", async () => {
    const jwt = await issuer.sign(undefined, { audience: "sts.amazonaws.com" });
    expect((await jobToken(jwt)).status).toBe(401);
  });

  it("403s for a repo outside the pinned owner, with a generic body", async () => {
    const claims = githubClaims({ repository: "example-org/api", repository_owner_id: "999999" });
    const res = await jobToken(await issuer.sign(claims));
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });
    expect(auditLines().find((l) => l.event === "token.deny")).toMatchObject({ reason: "no_match" });
    expect(cf.tokens.size).toBe(1); // only the broker token
  });

  it("403s when several profiles match and none is named", async () => {
    const claims = githubClaims({ repository: "example-org/infra", repository_id: "200000002" });
    const res = await jobToken(await issuer.sign(claims));
    expect(res.status).toBe(403);
    expect(auditLines().find((l) => l.event === "token.deny")).toMatchObject({ reason: "ambiguous" });
  });

  it("403s when the named profile doesn't match", async () => {
    const res = await jobToken(await issuer.sign(), { profile: "infra-cloudflare" });
    expect(res.status).toBe(403);
    expect(auditLines().find((l) => l.event === "token.deny")).toMatchObject({
      reason: "profile_mismatch",
      profile: "infra-cloudflare",
    });
  });

  it.each([[{ ttl: "forever" }], [{ ttl: 600 }], [{ profile: ["a"] }], [{ profile: "x".repeat(65) }]])(
    "400s on body %j",
    async (body) => {
      expect((await jobToken(await issuer.sign(), body)).status).toBe(400);
    },
  );

  it("logs the profile count when the policy loads", async () => {
    policyFile = JSON.stringify({ ...testPolicy(ISSUER), defaults: { ttl: "10m" } }); // force a reload
    await call("GET", "/healthz");
    expect(auditLines().find((l) => l.event === "policy.loaded")).toEqual({ event: "policy.loaded", profiles: 3 });
  });

  it("500s, failing closed, when the policy is invalid", async () => {
    policyFile = JSON.stringify({
      ...testPolicy(ISSUER),
      github: { audience: "https://x.example.com" },
    });
    const res = await jobToken(await issuer.sign());
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "misconfigured" });
  });

  it("500s when a permission name is unknown", async () => {
    const policy = testPolicy(ISSUER);
    (policy.profiles[1]?.token.policies[0] as { permissions: string[] }).permissions = ["Workers Scrpts Write"];
    policyFile = JSON.stringify(policy);
    const res = await jobToken(await issuer.sign());
    expect(res.status).toBe(500);
    expect(auditLines().find((l) => l.event === "token.deny")).toMatchObject({ reason: "unknown_permission" });
  });

  it("picks the right scope for a permission name shared by two groups", async () => {
    const policy = testPolicy(ISSUER);
    (policy.profiles[1]?.token.policies[0] as { permissions: string[] }).permissions = ["Load Balancers Write"];
    policyFile = JSON.stringify(policy);
    const res = await jobToken(await issuer.sign());
    const { token_id } = (await res.json()) as WithToken;
    expect(cf.tokens.get(token_id)?.policies[0]).toMatchObject({
      permission_groups: [{ id: "pg-lb-write-account" }],
    });
  });

  it("picks the zone-scoped group for zone resources", async () => {
    const policy = testPolicy(ISSUER);
    (policy.profiles[0]?.token.policies[0] as { permissions: string[] }).permissions = ["Load Balancers Write"];
    policyFile = JSON.stringify(policy);
    const claims = githubClaims({ repository: "example-org/infra", repository_id: "200000002" });
    const res = await jobToken(await issuer.sign(claims), { profile: "infra-cloudflare" });
    const { token_id } = (await res.json()) as WithToken;
    expect(cf.tokens.get(token_id)?.policies[0]).toMatchObject({
      permission_groups: [{ id: "pg-lb-write-zone" }],
    });
  });

  it("500s when the policy names another account", async () => {
    env.CF_OIDC_BROKER_ACCOUNT_ID = "ffffffffffffffffffffffffffffffff";
    const res = await jobToken(await issuer.sign());
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "misconfigured" });
  });

  it("502s when the Cloudflare API fails, without retrying the create", async () => {
    cf.failCreate = true;
    const res = await jobToken(await issuer.sign());
    expect(res.status).toBe(502);
    expect(cf.requests.filter((r) => r.method === "POST").length).toBe(1);
  });
});

describe("token exchange for jobs, with buckets", () => {
  const STATE = { repository: "example-org/state-*", environment: "state" };

  /** Adds profiles for the state environment, which no other test profile matches. */
  function withProfiles(...profiles: (Omit<TestProfile, "token"> & Partial<Pick<TestProfile, "token">>)[]) {
    const policy = testPolicy(ISSUER);
    policy.profiles.push(...(profiles as TestProfile[]));
    policyFile = JSON.stringify(policy);
  }

  const stateRepo = (repo = "state-app", overrides: Record<string, unknown> = {}) =>
    issuer.sign(githubClaims({ repository: `example-org/${repo}`, environment: "state", ...overrides }));

  const r2Requests = () => cf.requests.filter((r) => r.path.endsWith("/r2/temp-access-credentials"));

  it("issues prefix-limited credentials for a profile with only buckets", async () => {
    withProfiles({
      name: "terraform-state",
      match: STATE,
      buckets: [
        { name: "org-terraform-state", permission: "object-read-write", prefixes: ["github.com/{repository}/"] },
      ],
    });
    const before = Date.now();
    const res = await jobToken(await stateRepo(), { profile: "terraform-state" });
    expect(res.status).toBe(200);

    const body = (await res.json()) as TokenExchangeResponse;
    expect(body).toEqual({
      issued_token_type: "urn:cf-oidc-auth:params:oauth:token-type:r2-credentials",
      token_type: "N_A",
      expires_in: expect.any(Number),
      expires_at: Math.floor(Date.parse(body.buckets?.[0]?.expires_on ?? "") / 1000),
      account_id: ACCOUNT_ID,
      profile: "terraform-state",
      buckets: [
        {
          name: "org-terraform-state",
          access_key_id: BROKER_TOKEN_ID,
          secret_access_key: "r2-secret-value",
          session_token: "r2-session-token-value",
          prefixes: ["github.com/example-org/state-app/"],
          endpoint: `https://${ACCOUNT_ID}.r2.cloudflarestorage.com`,
          expires_on: expect.stringMatching(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/),
        },
      ],
    });
    const ttl = body.expires_at * 1000 - before;
    expect(ttl).toBeGreaterThan(14 * 60_000);
    expect(ttl).toBeLessThanOrEqual(15 * 60_000 + 1000);

    expect(r2Requests()).toEqual([
      {
        method: "POST",
        path: `/accounts/${ACCOUNT_ID}/r2/temp-access-credentials`,
        body: {
          bucket: "org-terraform-state",
          parentAccessKeyId: BROKER_TOKEN_ID,
          permission: "object-read-write",
          ttlSeconds: 900,
          prefixes: ["github.com/example-org/state-app/"],
        },
      },
    ]);
    expect(cf.tokens.size).toBe(1); // no API token minted
  });

  it("covers the whole bucket without prefixes, and honours the requested ttl", async () => {
    withProfiles({
      name: "terraform-state",
      match: STATE,
      max_ttl: "30m",
      buckets: [{ name: "org-terraform-state", permission: "object-read-only" }],
    });
    const res = await jobToken(await stateRepo(), { ttl: "2h" });
    const body = (await res.json()) as TokenExchangeResponse;
    expect(body.buckets?.[0]?.prefixes).toEqual([]);
    expect(r2Requests()[0]?.body).toEqual({
      bucket: "org-terraform-state",
      parentAccessKeyId: BROKER_TOKEN_ID,
      permission: "object-read-only",
      ttlSeconds: 1800,
    });
  });

  it("mints a token and credentials that expire together for a profile with both", async () => {
    withProfiles({
      name: "state-and-deploy",
      match: STATE,
      ttl: "10m",
      token: {
        policies: [
          {
            permissions: ["Workers Scripts Write"],
            resources: { [`com.cloudflare.api.account.${ACCOUNT_ID}`]: "*" },
          },
        ],
      },
      buckets: [{ name: "org-terraform-state", permission: "object-read-write", prefixes: ["{repository_id}/"] }],
    });
    const res = await jobToken(await stateRepo());
    expect(res.status).toBe(200);
    const body = (await res.json()) as WithToken;
    expect(cf.tokens.has(body.token_id)).toBe(true);
    expect(body.buckets?.[0]?.prefixes).toEqual(["200000003/"]);
    // The token's expiry, which the bucket's matches to the second.
    expect(Math.abs(Date.parse(body.buckets?.[0]?.expires_on ?? "") - body.expires_at * 1000)).toBeLessThanOrEqual(
      1000,
    );
    expect(r2Requests()[0]?.body).toMatchObject({ ttlSeconds: 600 });
  });

  it("issues credentials for each bucket, in the policy's order", async () => {
    withProfiles({
      name: "state-and-artifacts",
      match: STATE,
      buckets: [
        { name: "org-terraform-state", permission: "object-read-write", prefixes: ["github.com/{repository}/"] },
        { name: "org-artifacts", permission: "object-read-only" },
      ],
    });
    const res = await jobToken(await stateRepo());
    expect(res.status).toBe(200);
    const body = (await res.json()) as TokenExchangeResponse;
    expect(body.buckets?.map((b) => [b.name, b.prefixes])).toEqual([
      ["org-terraform-state", ["github.com/example-org/state-app/"]],
      ["org-artifacts", []],
    ]);
    expect(r2Requests().map((r) => r.body)).toEqual([
      {
        bucket: "org-terraform-state",
        parentAccessKeyId: BROKER_TOKEN_ID,
        permission: "object-read-write",
        ttlSeconds: 900,
        prefixes: ["github.com/example-org/state-app/"],
      },
      { bucket: "org-artifacts", parentAccessKeyId: BROKER_TOKEN_ID, permission: "object-read-only", ttlSeconds: 900 },
    ]);
    expect(
      auditLines()
        .filter((l) => l.event === "r2.issued")
        .map((l) => l.bucket),
    ).toEqual(["org-terraform-state", "org-artifacts"]);
  });

  it("deletes the token and 502s when a later bucket's credentials can't be created", async () => {
    withProfiles({
      name: "state-and-artifacts",
      match: STATE,
      token: {
        policies: [
          { permissions: ["Workers Scripts Write"], resources: { [`com.cloudflare.api.account.${ACCOUNT_ID}`]: "*" } },
        ],
      },
      buckets: [
        { name: "org-terraform-state", permission: "object-read-write" },
        { name: "org-artifacts", permission: "object-read-only" },
      ],
    });
    cf.failR2Bucket = "org-artifacts";
    const res = await jobToken(await stateRepo());
    expect(res.status).toBe(502);
    expect(cf.tokens.size).toBe(1); // only the broker token
    expect(
      auditLines()
        .filter((l) => l.event === "r2.issued")
        .map((l) => l.bucket),
    ).toEqual(["org-terraform-state"]);
  });

  it("deletes the token and 502s when the credentials can't be created", async () => {
    withProfiles({
      name: "state-and-deploy",
      match: STATE,
      token: {
        policies: [
          { permissions: ["Workers Scripts Write"], resources: { [`com.cloudflare.api.account.${ACCOUNT_ID}`]: "*" } },
        ],
      },
      buckets: [{ name: "org-terraform-state", permission: "object-read-write" }],
    });
    cf.failR2 = true;
    const res = await jobToken(await stateRepo());
    expect(res.status).toBe(502);
    expect(await res.json()).toEqual({ error: "upstream_error" });
    expect(cf.tokens.size).toBe(1); // only the broker token: the minted one was deleted
    expect(auditLines().find((l) => l.event === "token.revoke")).toMatchObject({ reason: "discarded" });
    expect(auditLines().some((l) => l.event === "r2.issued")).toBe(false);
  });

  it("403s without calling Cloudflare when a claim can't be used in the prefix", async () => {
    withProfiles({
      name: "terraform-state",
      match: STATE,
      buckets: [{ name: "org-terraform-state", permission: "object-read-write", prefixes: ["{repository_owner}/"] }],
    });
    const res = await jobToken(await stateRepo("state-app", { repository_owner: "../example-org" }));
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });
    expect(auditLines().find((l) => l.event === "token.deny")).toMatchObject({
      profile: "terraform-state",
      reason: "invalid_r2_prefix",
    });
    expect(cf.requests).toEqual([]);
  });

  it("writes an r2.issued audit line without secrets", async () => {
    withProfiles({
      name: "terraform-state",
      match: STATE,
      buckets: [
        { name: "org-terraform-state", permission: "object-read-write", prefixes: ["github.com/{repository}/"] },
      ],
    });
    const res = await jobToken(await stateRepo());
    const { buckets } = (await res.json()) as TokenExchangeResponse;
    expect(auditLines().find((l) => l.event === "r2.issued")).toEqual({
      event: "r2.issued",
      subject: "actions",
      profile: "terraform-state",
      repository: "example-org/state-app",
      repository_id: "200000003",
      ref: "refs/heads/main",
      environment: "state",
      event_name: "push",
      workflow_ref: "example-org/api/.github/workflows/deploy.yml@refs/heads/main",
      job_workflow_ref: "example-org/api/.github/workflows/deploy.yml@refs/heads/main",
      run_id: "1234567890",
      run_attempt: "1",
      actor_id: "300000004",
      bucket: "org-terraform-state",
      prefixes: ["github.com/example-org/state-app/"],
      permission: "object-read-write",
      expires_on: buckets?.[0]?.expires_on,
    });
    expect(logs.join("\n")).not.toContain("r2-secret-value");
    expect(logs.join("\n")).not.toContain("r2-session-token-value");
  });

  it("looks up the parent access key ID once, and again after the broker token rotates", async () => {
    withProfiles({
      name: "terraform-state",
      match: STATE,
      buckets: [{ name: "org-terraform-state", permission: "object-read-write" }],
    });
    const verifies = () => cf.requests.filter((r) => r.path.endsWith("/tokens/verify")).length;
    await jobToken(await stateRepo());
    await jobToken(await stateRepo());
    expect(verifies()).toBe(1);

    const rotated = cf.add({
      id: "tok-rotated",
      name: "cf-oidc broker token (rotated)",
      value: "rotated-broker-token",
    });
    env.CF_OIDC_BROKER_TOKEN = { get: async () => rotated.value };
    // The fake only accepts the original broker token for everything but verify, so stop here.
    await jobToken(await stateRepo());
    expect(verifies()).toBe(2);
  });
});

describe("token exchange for people", () => {
  /** A person's profiles: a team's read-only state, and a token for one repo's writers. */
  function withUserProfiles(...extra: Partial<TestProfile>[]) {
    const policy = testPolicy(ISSUER);
    const profiles = [
      {
        name: "tofu-plan",
        subject: "users",
        match: { team_id: TEAM_ID, repository_permission: "read" },
        ttl: "30m",
        buckets: [
          {
            name: "org-terraform-state",
            permission: "object-read-only",
            prefixes: ["{repository_owner_id}/{repository_id}/"],
          },
        ],
      },
      {
        name: "infra-dns",
        subject: "users",
        match: { repository_id: "200000002", repository_permission: "write" },
        token: {
          policies: [
            { permissions: ["DNS Write"], resources: { [`com.cloudflare.api.account.zone.${ZONE_ID}`]: "*" } },
          ],
        },
      },
      ...extra,
    ];
    policy.profiles.push(...(profiles as TestProfile[]));
    policyFile = JSON.stringify(policy);
  }

  /** Exchanges a person's GitHub token, with the broker's own `fields`. */
  const mintFor = (fields: Record<string, unknown> | undefined, token = USER_TOKEN) =>
    call("POST", "/oauth/token", {
      body: { grant_type: GRANT, subject_token: token, subject_token_type: ACCESS_TOKEN, ...fields },
    });
  const deny = () => auditLines().find((l) => l.event === "token.deny");

  beforeEach(() => withUserProfiles());

  it("issues state credentials under the prefix GitHub's IDs give", async () => {
    const res = await mintFor({ profile: "tofu-plan", repository: "example-org/api" });
    expect(res.status).toBe(200);
    const body = (await res.json()) as TokenExchangeResponse;
    expect(body.access_token).toBeUndefined();
    expect(body.buckets?.[0]).toMatchObject({
      name: "org-terraform-state",
      prefixes: [`${OWNER_ID}/200000003/`],
    });
    expect(body.expires_at * 1000 - Date.now()).toBeLessThanOrEqual(30 * 60_000 + 1000);
  });

  it("accepts a numeric repository ID", async () => {
    const res = await mintFor({ profile: "tofu-plan", repository: "200000003" });
    expect(res.status).toBe(200);
    expect(github.requests).toContain("/repositories/200000003");
  });

  it("mints a token named after the person and the repo", async () => {
    const res = await mintFor({ profile: "infra-dns", repository: "example-org/infra" });
    expect(res.status).toBe(200);
    const { token_id } = (await res.json()) as WithToken;
    expect(cf.tokens.get(token_id)?.name).toBe("cf-oidc:user:octocat:example-org/infra");
  });

  it("writes audit lines with the person, without the gh token", async () => {
    await mintFor({ profile: "infra-dns", repository: "example-org/infra" });
    expect(auditLines().find((l) => l.event === "token.mint")).toMatchObject({
      subject: "users",
      profile: "infra-dns",
      actor: "octocat",
      actor_id: USER_ID,
      repository: "example-org/infra",
      repository_id: "200000002",
    });
    expect(logs.join("\n")).not.toContain(USER_TOKEN);
  });

  it("403s when several user profiles match and none is named", async () => {
    // tofu-plan (team, read) and infra-dns (repo, write) both match example-org/infra.
    expect((await mintFor({ repository: "example-org/infra" })).status).toBe(403);
    expect(deny()).toMatchObject({ subject: "users", reason: "ambiguous" });
  });

  it("never uses an Actions profile for a person", async () => {
    // workers-deploy matches repository example-org/*, as this person's claims would.
    const res = await mintFor({ profile: "workers-deploy", repository: "example-org/api" });
    expect(res.status).toBe(403);
    expect(deny()).toMatchObject({ reason: "profile_mismatch", detail: "profile workers-deploy isn't for users" });
  });

  it("never uses a user profile for a job", async () => {
    const res = await jobToken(await issuer.sign(), { profile: "tofu-plan" });
    expect(res.status).toBe(403);
    expect(deny()).toMatchObject({ subject: "actions", reason: "profile_mismatch" });
  });

  it("403s without enough access to the repo", async () => {
    // The person can only read example-org/api; infra-dns needs write on 200000002.
    github.repos.push({ id: 200000002, full_name: "example-org/infra", owner_id: Number(OWNER_ID), role: "read" });
    github.repos.shift();
    expect((await mintFor({ profile: "infra-dns", repository: "example-org/infra" })).status).toBe(403);
    expect(deny()).toMatchObject({ reason: "profile_mismatch" });
    expect(cf.tokens.size).toBe(1);
  });

  it("403s outside the team", async () => {
    github.teams = [];
    expect((await mintFor({ profile: "tofu-plan", repository: "example-org/api" })).status).toBe(403);
    expect(deny()).toMatchObject({ reason: "profile_mismatch" });
  });

  it("403s for a repo outside the pinned owner, without looking up teams", async () => {
    const res = await mintFor({ profile: "tofu-plan", repository: "other-org/infra" });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });
    expect(deny()).toMatchObject({ reason: "repository_forbidden" });
    expect(github.requests.some((r) => r.startsWith("/user/teams"))).toBe(false);
  });

  it("403s for a repo the person can't see", async () => {
    expect((await mintFor({ repository: "example-org/secret" })).status).toBe(403);
    expect(deny()).toMatchObject({ reason: "repository_forbidden" });
  });

  it("looks up teams only when a profile that could match needs them", async () => {
    await mintFor({ profile: "infra-dns", repository: "example-org/infra" });
    expect(github.requests.some((r) => r.startsWith("/user/teams"))).toBe(false);
  });

  it("401s on a GitHub App installation token, without calling GitHub", async () => {
    const res = await mintFor({ repository: "example-org/api" }, "ghs_exampleInstallationToken000000000000");
    expect(res.status).toBe(401);
    expect(deny()).toMatchObject({ reason: "installation_token" });
    expect(github.requests).toEqual([]);
  });

  it("401s on a token GitHub rejects", async () => {
    expect((await mintFor({ repository: "example-org/api" }, "gho_revoked")).status).toBe(401);
    expect(deny()).toMatchObject({ reason: "invalid_user_token" });
  });

  it("400s without a token, without calling GitHub", async () => {
    const res = await mintFor({ repository: "example-org/api" }, "");
    expect(res.status).toBe(400);
    expect(deny()).toMatchObject({ reason: "invalid_body" });
    expect(github.requests).toEqual([]);
  });

  it.each([[undefined], [{}], [{ repository: "example-org" }], [{ repository: "a/b/c" }], [{ repository: 200000003 }]])(
    "400s on body %j, without calling GitHub",
    async (body) => {
      expect((await mintFor(body)).status).toBe(400);
      expect(github.requests).toEqual([]);
    },
  );

  it("404s when no profile is for people, without calling GitHub", async () => {
    policyFile = JSON.stringify(testPolicy(ISSUER));
    expect((await mintFor({ repository: "example-org/api" })).status).toBe(404);
    expect(github.requests).toEqual([]);
  });

  it("404s when every profile for people is disabled, without calling GitHub", async () => {
    const policy = JSON.parse(policyFile as string) as TestPolicy;
    for (const p of policy.profiles) if (p.subject === "users") (p as Record<string, unknown>).enabled = false;
    policyFile = JSON.stringify(policy);
    expect((await mintFor({ repository: "example-org/api" })).status).toBe(404);
    expect(github.requests).toEqual([]);
  });

  it("403s when the token can't list teams", async () => {
    // What GitHub answers a classic token without the repo, read:org or user scope.
    github.fail = { path: "/user/teams", status: 404 };
    expect((await mintFor({ profile: "tofu-plan", repository: "example-org/api" })).status).toBe(403);
    expect(deny()).toMatchObject({ reason: "teams_forbidden" });
    expect(cf.tokens.size).toBe(1);
  });

  it("403s when the token isn't authorized for SAML SSO", async () => {
    github.fail = {
      path: "/repos/",
      status: 403,
      headers: { "x-github-sso": "required; url=https://github.com/orgs/x/sso" },
    };
    expect((await mintFor({ repository: "example-org/api" })).status).toBe(403);
    expect(deny()).toMatchObject({ reason: "sso_required" });
  });

  it.each([[{ status: 403, headers: { "x-ratelimit-remaining": "0" } }], [{ status: 429 }], [{ status: 503 }]])(
    "502s when GitHub fails with %j",
    async (failure) => {
      github.fail = { path: "/user", ...failure };
      expect((await mintFor({ profile: "infra-dns", repository: "example-org/infra" })).status).toBe(502);
      expect(deny()).toMatchObject({ reason: "github_unavailable" });
    },
  );
});

describe("POST /oauth/revoke", () => {
  async function minted(): Promise<WithToken> {
    const res = await jobToken(await issuer.sign());
    return (await res.json()) as WithToken;
  }

  it("deletes a cf-auth token", async () => {
    const t = await minted();
    const res = await revokeToken(t.access_token);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("");
    expect(cf.tokens.has(t.token_id)).toBe(false);
    expect(auditLines().find((l) => l.event === "token.revoke")).toMatchObject({ token_id: t.token_id });
  });

  it("200s when the token is already gone or never existed", async () => {
    const t = await minted();
    await revokeToken(t.access_token);
    expect((await revokeToken(t.access_token)).status).toBe(200);
    expect((await revokeToken("never-existed")).status).toBe(200);
  });

  it("refuses to delete tokens cf-auth didn't mint", async () => {
    const foreign = cf.add({ name: "ci deploy (manual)" });
    const res = await revokeToken(foreign.value);
    expect(res.status).toBe(403);
    expect(cf.tokens.has(foreign.id)).toBe(true);
  });

  it("refuses to delete the broker token", async () => {
    expect((await revokeToken(BROKER_TOKEN)).status).toBe(403);
  });

  it("400s without a token", async () => {
    expect((await revokeToken()).status).toBe(400);
  });

  it("accepts JSON too", async () => {
    const t = await minted();
    expect((await call("POST", "/oauth/revoke", { body: { token: t.access_token } })).status).toBe(200);
    expect(cf.tokens.has(t.token_id)).toBe(false);
  });
});

describe("broker token", () => {
  const store = (get: () => Promise<string>) => ({ get: vi.fn(get) });

  it("is read from Secrets Store on every use", async () => {
    const secret = store(async () => BROKER_TOKEN);
    env.CF_OIDC_BROKER_TOKEN = secret;
    const res = await jobToken(await issuer.sign());
    expect(res.status).toBe(200);
    const { access_token: token } = (await res.json()) as WithToken;
    expect((await revokeToken(token)).status).toBe(200);
    // Read on every use, so a rotated secret takes effect without a redeploy.
    expect(secret.get).toHaveBeenCalledTimes(2);
  });

  it("500s, failing closed, when the secret can't be read", async () => {
    env.CF_OIDC_BROKER_TOKEN = store(async () => {
      throw new Error("secret not found");
    });
    const res = await jobToken(await issuer.sign());
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "misconfigured" });
    expect(auditLines().find((l) => l.event === "token.deny")).toMatchObject({ reason: "broker_token_unavailable" });
    expect(cf.tokens.size).toBe(1); // nothing minted
  });

  it("reports an unreadable secret on /healthz", async () => {
    env.CF_OIDC_BROKER_TOKEN = store(async () => {
      throw new Error("secret not found");
    });
    expect((await call("GET", "/healthz")).status).toBe(500);
  });

  it("refuses a plain Worker secret, failing closed", async () => {
    env.CF_OIDC_BROKER_TOKEN = BROKER_TOKEN as unknown as SecretsStoreSecret;
    const res = await jobToken(await issuer.sign());
    expect(res.status).toBe(500);
    expect(auditLines().find((l) => l.event === "token.deny")).toMatchObject({
      reason: "broker_token_unavailable",
      detail: "CF_OIDC_BROKER_TOKEN must be a Secrets Store binding",
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
    policyFile = "{";
    const res = await call("GET", "/healthz");
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "misconfigured" });
  });

  it("accepts an already-parsed policy (policy.json inlined by a bundler)", async () => {
    policyFile = testPolicy(ISSUER);
    expect((await call("GET", "/healthz")).status).toBe(200);
  });
});

describe("POST /oauth/token", () => {
  /** Posts a token exchange, form-encoded as RFC 8693 has it, or as JSON. */
  async function exchange(params: Record<string, string>, contentType = "application/x-www-form-urlencoded") {
    const json = contentType === "application/json";
    const request = new Request("https://cf-auth.example.com/oauth/token", {
      method: "POST",
      headers: { "content-type": contentType },
      body: json ? JSON.stringify(params) : new URLSearchParams(params).toString(),
    });
    const worker = createBroker(policyFile);
    return worker.fetch(request as Parameters<typeof worker.fetch>[0], env);
  }

  const forJob = async (extra: Record<string, string> = {}) => ({
    grant_type: GRANT,
    subject_token: await issuer.sign(),
    subject_token_type: ID_TOKEN,
    ...extra,
  });
  const deny = () => auditLines().find((l) => l.event === "token.deny");

  /** Adds `profiles` to the test policy. */
  function withProfiles(...profiles: Record<string, unknown>[]) {
    const policy = testPolicy(ISSUER);
    policy.profiles.push(...(profiles as TestProfile[]));
    policyFile = JSON.stringify(policy);
  }

  it("exchanges a job's OIDC token for a Cloudflare API token", async () => {
    const before = Math.floor(Date.now() / 1000);
    const res = await exchange(await forJob({ profile: "workers-deploy" }));
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");

    const body = (await res.json()) as TokenExchangeResponse;
    expect(body).toEqual({
      access_token: expect.stringMatching(/^value-/),
      issued_token_type: ACCESS_TOKEN,
      token_type: "Bearer",
      expires_in: expect.any(Number),
      expires_at: expect.any(Number),
      token_id: expect.any(String),
      account_id: ACCOUNT_ID,
      profile: "workers-deploy",
    });
    expect(cf.tokens.get(body.token_id as string)?.name).toBe("cf-oidc:example-org/api:1234567890:1");
    // Default ttl is 15m.
    expect(body.expires_at - before).toBeGreaterThan(14 * 60);
    expect(body.expires_at - before).toBeLessThanOrEqual(15 * 60 + 1);
    expect(body.expires_in).toBeGreaterThan(14 * 60);
    expect(body.expires_in).toBeLessThanOrEqual(15 * 60);
    expect(auditLines().find((l) => l.event === "token.mint")).toMatchObject({
      subject: "actions",
      profile: "workers-deploy",
      token_id: body.token_id,
    });
  });

  it("accepts JSON, the jwt token type and the Cloudflare audience", async () => {
    const res = await exchange(
      await forJob({
        subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
        audience: "https://api.cloudflare.com",
      }),
      "application/json",
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as TokenExchangeResponse).profile).toBe("workers-deploy");
  });

  it("returns only R2 credentials for a profile without a token", async () => {
    withProfiles({
      name: "terraform-state",
      match: { environment: "state" },
      buckets: [{ name: "org-terraform-state", permission: "object-read-write", prefixes: ["{repository_id}/"] }],
    });
    const res = await exchange({
      grant_type: GRANT,
      subject_token: await issuer.sign(githubClaims({ environment: "state" })),
      subject_token_type: ID_TOKEN,
      profile: "terraform-state",
    });
    expect(res.status).toBe(200);

    const body = (await res.json()) as TokenExchangeResponse;
    expect(body.access_token).toBeUndefined();
    expect(body.token_id).toBeUndefined();
    expect(body).toMatchObject({
      issued_token_type: "urn:cf-oidc-auth:params:oauth:token-type:r2-credentials",
      token_type: "N_A",
      account_id: ACCOUNT_ID,
      profile: "terraform-state",
    });
    expect(body.buckets?.map((b) => [b.name, b.prefixes])).toEqual([["org-terraform-state", ["200000003/"]]]);
    expect(body.expires_at).toBe(Math.floor(Date.parse(body.buckets?.[0]?.expires_on as string) / 1000));
  });

  it("exchanges a person's GitHub token for the requested repo", async () => {
    withProfiles({
      name: "tofu-plan",
      subject: "users",
      match: { team_id: TEAM_ID, repository_permission: "read" },
      buckets: [{ name: "org-terraform-state", permission: "object-read-only", prefixes: ["{repository_id}/"] }],
    });
    const res = await exchange({
      grant_type: GRANT,
      subject_token: USER_TOKEN,
      subject_token_type: ACCESS_TOKEN,
      repository: "example-org/api",
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as TokenExchangeResponse;
    expect(body.profile).toBe("tofu-plan");
    expect(body.buckets?.[0]?.prefixes).toEqual(["200000003/"]);
    expect(auditLines().find((l) => l.event === "r2.issued")).toMatchObject({ subject: "users", actor_id: USER_ID });
  });

  it.each([
    ["another grant type", { grant_type: "client_credentials" }, "unsupported_grant_type"],
    ["no subject token", { subject_token: "" }, "invalid_body"],
    [
      "an unsupported subject token type",
      { subject_token_type: "urn:ietf:params:oauth:token-type:saml2" },
      "unsupported_subject_token_type",
    ],
    ["another audience", { audience: "https://cache.example.com" }, "invalid_target"],
    ["an actor token", { actor_token: "x", actor_token_type: ID_TOKEN }, "actor_token_unsupported"],
    [
      "an unsupported requested token type",
      { requested_token_type: "urn:ietf:params:oauth:token-type:refresh_token" },
      "unsupported_requested_token_type",
    ],
    ["a person without a repository", { subject_token_type: ACCESS_TOKEN }, "invalid_body"],
  ])("400s on %s, without calling anyone", async (_, override, reason) => {
    const res = await exchange({
      grant_type: GRANT,
      subject_token: "not-checked",
      subject_token_type: ID_TOKEN,
      ...override,
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "bad_request" });
    expect(deny()?.reason).toBe(reason);
    expect(github.requests).toEqual([]);
    expect(cf.requests).toEqual([]);
  });

  it("400s on a JSON body that isn't an object", async () => {
    const res = await call("POST", "/oauth/token", { body: [GRANT] });
    expect(res.status).toBe(400);
    expect(deny()?.detail).toBe("not an object");
  });

  it("400s on a body that's neither form-encoded nor JSON", async () => {
    const res = await exchange(await forJob(), "text/plain");
    expect(res.status).toBe(400);
    expect(deny()?.detail).toMatch(/content-type/);
  });

  it("401s on a token that isn't a valid OIDC token", async () => {
    const res = await exchange({ grant_type: GRANT, subject_token: "not-a-jwt", subject_token_type: ID_TOKEN });
    expect(res.status).toBe(401);
    expect(deny()?.reason).toBe("invalid_jwt");
    expect(cf.requests).toEqual([]);
  });

  it("403s on a profile that doesn't match the job", async () => {
    const res = await exchange(await forJob({ profile: "infra-cloudflare" }));
    expect(res.status).toBe(403);
    expect(deny()).toMatchObject({ subject: "actions", reason: "profile_mismatch" });
  });
});

describe("tokens for other services", () => {
  const CACHE = "https://cf-nix-cache.example.com";
  const JWT_TYPE = "urn:ietf:params:oauth:token-type:jwt";
  let signingPem: string;

  beforeAll(async () => {
    const { privateKey } = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
    signingPem = await exportPKCS8(privateKey);
  });

  beforeEach(() => {
    clearSigningKey();
    env.CF_OIDC_BROKER_SIGNING_KEY = { get: async () => signingPem };
    const policy = testPolicy(ISSUER);
    const services = [
      { name: "nix-push", audience: CACHE, match: { ref: "refs/heads/main" }, ttl: "15m" },
      {
        name: "nix-push-people",
        subject: "users",
        audience: CACHE,
        match: { repository_permission: "write" },
        ttl: "30m",
      },
    ];
    policy.profiles.push(...(services as unknown as TestProfile[]));
    policyFile = JSON.stringify(policy);
  });

  /** The broker's published keys, as a service would fetch them. */
  async function brokerKeys() {
    const res = await call("GET", "/.well-known/jwks");
    expect(res.status).toBe(200);
    return createLocalJWKSet((await res.json()) as { keys: JWK[] });
  }

  const forCache = (subjectToken: string, type = ID_TOKEN, extra: Record<string, unknown> = {}) =>
    call("POST", "/oauth/token", {
      body: { grant_type: GRANT, subject_token: subjectToken, subject_token_type: type, audience: CACHE, ...extra },
    });

  it("issues a job a token the service can verify with the broker's keys", async () => {
    const sub = "repo:example-org/api:environment:prod";
    const res = await forCache(await issuer.sign(githubClaims({ sub })));
    expect(res.status).toBe(200);
    const body = (await res.json()) as TokenExchangeResponse;
    expect(body).toEqual({
      access_token: expect.any(String),
      issued_token_type: JWT_TYPE,
      token_type: "Bearer",
      expires_in: expect.any(Number),
      expires_at: expect.any(Number),
      profile: "nix-push",
    });

    const { payload, protectedHeader } = await jwtVerify(body.access_token as string, await brokerKeys(), {
      issuer: AUDIENCE,
      audience: CACHE,
      algorithms: ["EdDSA"],
    });
    expect(protectedHeader).toMatchObject({ alg: "EdDSA", typ: "JWT" });
    expect(payload).toMatchObject({
      sub,
      profile: "nix-push",
      repository: "example-org/api",
      repository_owner_id: OWNER_ID,
      ref: "refs/heads/main",
      run_id: "1234567890",
    });
    expect(payload.jti).toEqual(expect.any(String));
    // Only the identity goes to Cloudflare's side: no API token, no R2 credentials.
    expect(cf.requests).toEqual([]);
    expect(auditLines().find((l) => l.event === "token.issue")).toMatchObject({
      subject: "actions",
      profile: "nix-push",
      audience: CACHE,
      jti: payload.jti,
    });
  });

  it("never outlives the job's OIDC token", async () => {
    const before = Math.floor(Date.now() / 1000);
    const res = await forCache(await issuer.sign(githubClaims(), { expiresIn: "2m" }));
    const body = (await res.json()) as TokenExchangeResponse;
    // The profile's ttl is 15m; the GitHub token's 2m wins.
    expect(body.expires_at - before).toBeLessThanOrEqual(2 * 60 + 1);
    expect(body.expires_at - before).toBeGreaterThan(60);
  });

  it("issues a person a token named after their GitHub user", async () => {
    const before = Math.floor(Date.now() / 1000);
    const res = await forCache(USER_TOKEN, ACCESS_TOKEN, { repository: "example-org/infra" });
    expect(res.status).toBe(200);
    const body = (await res.json()) as TokenExchangeResponse;
    const { payload } = await jwtVerify(body.access_token as string, await brokerKeys(), { audience: CACHE });
    expect(payload).toMatchObject({
      sub: `user:${USER_ID}`,
      actor: "octocat",
      repository: "example-org/infra",
      repository_permission: "write",
      profile: "nix-push-people",
    });
    // A GitHub user token doesn't expire, so the profile's 30m applies.
    expect(body.expires_at - before).toBeGreaterThan(29 * 60);
    expect(body.expires_at - before).toBeLessThanOrEqual(30 * 60 + 1);
  });

  it("publishes a discovery document and only the public key", async () => {
    const res = await call("GET", "/.well-known/openid-configuration");
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("public, max-age=300");
    expect(await res.json()).toMatchObject({
      issuer: AUDIENCE,
      jwks_uri: `${AUDIENCE}/.well-known/jwks`,
      token_endpoint: `${AUDIENCE}/oauth/token`,
      revocation_endpoint: `${AUDIENCE}/oauth/revoke`,
      grant_types_supported: [GRANT],
      id_token_signing_alg_values_supported: ["EdDSA"],
    });

    const { keys } = (await (await call("GET", "/.well-known/jwks")).json()) as { keys: JWK[] };
    expect(keys).toEqual([
      { kty: "OKP", crv: "Ed25519", x: expect.any(String), kid: expect.any(String), alg: "EdDSA", use: "sig" },
    ]);
    const res2 = await forCache(await issuer.sign());
    const { access_token } = (await res2.json()) as TokenExchangeResponse;
    expect(decodeProtectedHeader(access_token as string).kid).toBe(keys[0]?.kid);
  });

  it("400s on an audience no profile is for, without verifying anything", async () => {
    const res = await call("POST", "/oauth/token", {
      body: {
        grant_type: GRANT,
        subject_token: "not-checked",
        subject_token_type: ID_TOKEN,
        audience: "https://other.example.com",
      },
    });
    expect(res.status).toBe(400);
    expect(auditLines().find((l) => l.event === "token.deny")).toMatchObject({ reason: "invalid_target" });
    expect(github.requests).toEqual([]);
  });

  it("403s on a Cloudflare profile named for the service", async () => {
    const res = await forCache(await issuer.sign(), ID_TOKEN, { profile: "workers-deploy" });
    expect(res.status).toBe(403);
    expect(auditLines().find((l) => l.event === "token.deny")).toMatchObject({
      reason: "profile_mismatch",
      detail: `profile workers-deploy isn't for ${CACHE}`,
    });
  });

  it("400s on a Cloudflare token type requested for the service", async () => {
    const res = await forCache(await issuer.sign(), ID_TOKEN, {
      requested_token_type: "urn:cf-oidc-auth:params:oauth:token-type:r2-credentials",
    });
    expect(res.status).toBe(400);
  });

  it("fails closed without a signing key, and leaves Cloudflare profiles working", async () => {
    delete env.CF_OIDC_BROKER_SIGNING_KEY;
    const res = await forCache(await issuer.sign());
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "misconfigured" });
    expect(auditLines().find((l) => l.event === "token.deny")).toMatchObject({ reason: "signing_key_unavailable" });

    expect((await jobToken(await issuer.sign())).status).toBe(200);
    expect((await call("GET", "/healthz")).status).toBe(500);
    // Nothing to publish without a key.
    expect(await (await call("GET", "/.well-known/jwks")).json()).toEqual({ keys: [] });
  });

  it("fails closed on a signing key that isn't an Ed25519 PKCS#8 PEM", async () => {
    env.CF_OIDC_BROKER_SIGNING_KEY = { get: async () => "not a key" };
    expect((await forCache(await issuer.sign())).status).toBe(500);
    expect(auditLines().find((l) => l.event === "token.deny")).toMatchObject({
      reason: "signing_key_unavailable",
      detail: "not an Ed25519 private key in PKCS#8 PEM",
    });
  });

  it("reports healthy when the signing key loads", async () => {
    expect((await call("GET", "/healthz")).status).toBe(200);
  });
});

it("404s on unknown routes, including the removed /v1 token routes", async () => {
  const jwt = await issuer.sign();
  for (const path of ["/v1/token", "/v1/actions/token", "/v1/users/token", "/v1/user/token", "/v1/revoke"]) {
    expect((await call("POST", path, { token: jwt, body: {} })).status).toBe(404);
  }
  expect((await call("GET", "/oauth/token")).status).toBe(404);
  expect((await call("GET", "/")).status).toBe(404);
});

describe("scheduled cleanup", () => {
  it("deletes only expired cf-auth tokens", async () => {
    const past = new Date(Date.now() - 60_000).toISOString();
    const future = new Date(Date.now() + 60_000).toISOString();
    const expired = cf.add({ name: "cf-oidc:example-org/api:1:1", expires_on: past, status: "expired" });
    const live = cf.add({ name: "cf-oidc:example-org/api:2:1", expires_on: future });
    const foreign = cf.add({ name: "someone else's", expires_on: past, status: "expired" });

    const ctx = createExecutionContext();
    await createBroker(policyFile).scheduled(createScheduledController(), env, ctx);
    await waitOnExecutionContext(ctx);

    expect(cf.tokens.has(expired.id)).toBe(false);
    expect(cf.tokens.has(live.id)).toBe(true);
    expect(cf.tokens.has(foreign.id)).toBe(true);
    expect(cf.requests.some((r) => r.path.endsWith("/tokens") && r.method === "GET")).toBe(true);
  });
});

describe("tokenName", () => {
  it("fits in 120 characters", () => {
    const name = tokenName(githubClaims({ repository: `example-org/${"x".repeat(200)}` }), "actions");
    expect(name.length).toBe(120);
    expect(name).toMatch(/^cf-oidc:example-org\/x+:1234567890:1$/);
  });

  it("names a person's token after them, also within 120 characters", () => {
    const claims = { actor: "octocat", repository: `example-org/${"x".repeat(200)}` };
    const name = tokenName(claims, "users");
    expect(name.length).toBe(120);
    expect(name).toMatch(/^cf-oidc:user:octocat:example-org\/x+$/);
  });
});
