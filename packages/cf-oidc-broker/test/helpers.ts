// Test doubles for GitHub's OIDC issuer and the Cloudflare API. All IDs are made up.
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { vi } from "vitest";

export const ACCOUNT_ID = "0123456789abcdef0123456789abcdef";
export const OWNER_ID = "100000001";
export const AUDIENCE = "https://cf-auth.example.com";
export const BROKER_TOKEN = "broker-token-value";
export const ZONE_ID = "fedcba9876543210fedcba9876543210";

export const PERMISSION_GROUPS = [
  { id: "pg-workers-scripts-write", name: "Workers Scripts Write", scopes: ["com.cloudflare.api.account"] },
  { id: "pg-dns-write", name: "DNS Write", scopes: ["com.cloudflare.api.account.zone"] },
  { id: "pg-zone-write", name: "Zone Write", scopes: ["com.cloudflare.api.account.zone"] },
  // Same name at two scopes, to exercise disambiguation.
  { id: "pg-lb-write-account", name: "Load Balancers Write", scopes: ["com.cloudflare.api.account"] },
  { id: "pg-lb-write-zone", name: "Load Balancers Write", scopes: ["com.cloudflare.api.account.zone"] },
];

export function githubClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    repository: "example-org/api",
    repository_id: "200000003",
    repository_owner: "example-org",
    repository_owner_id: OWNER_ID,
    ref: "refs/heads/main",
    ref_type: "branch",
    environment: "prod",
    event_name: "push",
    workflow_ref: "example-org/api/.github/workflows/deploy.yml@refs/heads/main",
    job_workflow_ref: "example-org/api/.github/workflows/deploy.yml@refs/heads/main",
    run_id: "1234567890",
    run_attempt: "1",
    actor_id: "300000004",
    runner_environment: "github-hosted",
    ...overrides,
  };
}

/** Loosely typed so tests can break it in any way they like. */
export interface TestPolicy {
  version: number;
  github: { issuer?: string; audience?: string; owner_id?: string };
  defaults?: { ttl?: string; max_ttl?: string };
  profiles: {
    name: string;
    match: Record<string, unknown>;
    token: {
      ttl?: string;
      max_ttl?: string;
      policies: { effect?: string; permissions: string[]; resources: Record<string, unknown> }[];
    };
  }[];
  [key: string]: unknown;
}

export function testPolicy(issuer: string): TestPolicy {
  return {
    version: 1,
    github: { issuer, audience: AUDIENCE, owner_id: OWNER_ID },
    defaults: { ttl: "15m", max_ttl: "1h" },
    profiles: [
      {
        name: "infra-cloudflare",
        match: { repository_id: "200000002", ref: "refs/heads/main", environment: "prod" },
        token: {
          ttl: "15m",
          policies: [
            {
              effect: "allow",
              permissions: ["Zone Write", "DNS Write"],
              resources: { [`com.cloudflare.api.account.zone.${ZONE_ID}`]: "*" },
            },
          ],
        },
      },
      {
        name: "workers-deploy",
        match: { repository: "example-org/*", ref: "refs/heads/main", environment: "prod" },
        token: {
          policies: [
            {
              effect: "allow",
              permissions: ["Workers Scripts Write"],
              resources: { [`com.cloudflare.api.account.${ACCOUNT_ID}`]: "*" },
            },
          ],
        },
      },
      {
        name: "service-dns",
        match: { job_workflow_ref: "example-org/workflows/.github/workflows/deploy.yml@refs/heads/main" },
        token: {
          ttl: "5m",
          policies: [
            {
              effect: "allow",
              permissions: ["DNS Write"],
              resources: { [`com.cloudflare.api.account.zone.${ZONE_ID}`]: "*" },
            },
          ],
        },
      },
    ],
  };
}

/** A signing key and JWKS standing in for `token.actions.githubusercontent.com`. */
export async function createIssuer(issuer: string) {
  const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
  const jwks = { keys: [{ ...(await exportJWK(publicKey)), kid: "test-key", alg: "RS256", use: "sig" }] };

  async function sign(
    claims: Record<string, unknown> = githubClaims(),
    opts: { issuer?: string; audience?: string; expiresIn?: string | number } = {},
  ) {
    return new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid: "test-key" })
      .setIssuer(opts.issuer ?? issuer)
      .setAudience(opts.audience ?? AUDIENCE)
      .setIssuedAt()
      .setExpirationTime(opts.expiresIn ?? "5m")
      .sign(privateKey);
  }

  return { issuer, jwks, sign };
}

interface StoredToken {
  id: string;
  name: string;
  value: string;
  status: "active" | "expired";
  expires_on?: string;
  policies: unknown[];
}

const API = "https://api.cloudflare.com/client/v4";

function envelope(result: unknown, status = 200) {
  return Response.json({ success: true, errors: [], messages: [], result }, { status });
}

function apiError(status: number, message: string) {
  return Response.json({ success: false, errors: [{ code: 1000, message }], messages: [], result: null }, { status });
}

/** In-memory Cloudflare account tokens API and permission groups. */
export class FakeCloudflare {
  tokens = new Map<string, StoredToken>();
  requests: { method: string; path: string; body?: unknown }[] = [];
  failCreate = false;
  private seq = 0;

  constructor() {
    this.add({ name: "cf-oidc broker token", value: BROKER_TOKEN });
  }

  add(t: Partial<StoredToken> & { name: string }): StoredToken {
    const id = t.id ?? `tok-${++this.seq}`;
    const token: StoredToken = { id, value: `value-${id}`, status: "active", policies: [], ...t };
    this.tokens.set(id, token);
    return token;
  }

  async handle(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname.replace("/client/v4", "");
    const body = req.method === "POST" ? await req.json() : undefined;
    this.requests.push({ method: req.method, path, body });

    const auth = req.headers.get("authorization")?.replace(/^Bearer /, "");
    const acct = `/accounts/${ACCOUNT_ID}`;

    if (req.method === "GET" && path === `${acct}/tokens/permission_groups`) {
      return envelope(PERMISSION_GROUPS);
    }

    // Everything below requires the broker token, except verify which uses the presented one.
    if (req.method === "GET" && path === `${acct}/tokens/verify`) {
      const token = [...this.tokens.values()].find((t) => t.value === auth);
      if (!token) return apiError(401, "Invalid API Token");
      return envelope({ id: token.id, status: token.status, expires_on: token.expires_on });
    }
    if (auth !== BROKER_TOKEN) return apiError(403, "Unauthorized");

    if (req.method === "POST" && path === `${acct}/tokens`) {
      if (this.failCreate) return apiError(500, "Internal Server Error");
      const b = body as { name: string; policies: unknown[]; expires_on?: string };
      const token = this.add({
        name: b.name,
        policies: b.policies,
        ...(b.expires_on ? { expires_on: b.expires_on } : {}),
      });
      const { value, ...rest } = token;
      return envelope({ ...rest, value });
    }
    if (req.method === "GET" && path === `${acct}/tokens`) {
      const page = Number(url.searchParams.get("page") ?? "1");
      const includeExpired = url.searchParams.get("include_expired") === "true";
      const all = [...this.tokens.values()].filter((t) => includeExpired || t.status !== "expired");
      return envelope(page > 1 ? [] : all.map(({ value: _, ...t }) => t));
    }

    const m = new RegExp(`^${acct}/tokens/([^/]+)$`).exec(path);
    if (m) {
      const token = this.tokens.get(m[1] as string);
      if (!token) return apiError(404, "Not found");
      if (req.method === "GET") {
        const { value: _, ...rest } = token;
        return envelope(rest);
      }
      if (req.method === "DELETE") {
        this.tokens.delete(token.id);
        return envelope({ id: token.id });
      }
    }

    return apiError(404, `unhandled ${req.method} ${path}`);
  }
}

/** Routes the Worker's outbound `fetch` to the fake issuer and fake Cloudflare API. */
export function installFetch(issuer: { issuer: string; jwks: unknown }, cf: FakeCloudflare) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const req = new Request(input as RequestInfo, init as RequestInit);
    if (req.url === `${issuer.issuer}/.well-known/jwks`) return Response.json(issuer.jwks);
    if (req.url.startsWith(API)) return cf.handle(req);
    throw new TypeError(`unexpected fetch ${req.url}`);
  });
}
