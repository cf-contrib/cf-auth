// Test doubles for GitHub's OIDC issuer, GitHub's REST API and the Cloudflare API. All IDs
// and tokens are made up.
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { vi } from "vitest";

export const ACCOUNT_ID = "0123456789abcdef0123456789abcdef";
export const OWNER_ID = "100000001";
export const AUDIENCE = "https://cf-auth.example.com";
export const BROKER_TOKEN = "broker-token-value";
export const BROKER_TOKEN_ID = "tok-broker";
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
  issuer?: string;
  providers: {
    name: string;
    issuer?: string;
    audience?: string;
    jwks_uri?: string;
    claims?: Record<string, unknown>;
  }[];
  defaults?: { ttl?: string; max_ttl?: string };
  profiles: {
    name: string;
    provider?: string;
    claims: Record<string, unknown>;
    /** Always there in testPolicy's profiles; tests delete it to leave only `buckets`. */
    token: {
      policies: { effect?: string; permissions: string[]; resources: Record<string, unknown> }[];
    };
    ttl?: string;
    max_ttl?: string;
    buckets?: { name?: string; permission?: string; prefixes?: string[] }[];
  }[];
  [key: string]: unknown;
}

/** The provider for people's GitHub tokens, pinned to the test org. */
export const PEOPLE = { name: "people", issuer: "https://github.com", claims: { repository_owner_id: OWNER_ID } };

/** A version 2 policy: one GitHub Actions provider, `github`, and three profiles for it. */
export function testPolicy(issuer: string): TestPolicy {
  return {
    version: 2,
    issuer: AUDIENCE,
    providers: [{ name: "github", issuer, audience: AUDIENCE, claims: { repository_owner_id: OWNER_ID } }],
    defaults: { ttl: "15m", max_ttl: "1h" },
    profiles: [
      {
        name: "infra-cloudflare",
        provider: "github",
        claims: { repository_id: "200000002", ref: "refs/heads/main", environment: "prod" },
        ttl: "15m",
        token: {
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
        provider: "github",
        claims: { repository: "example-org/*", ref: "refs/heads/main", environment: "prod" },
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
        provider: "github",
        claims: { job_workflow_ref: "example-org/workflows/.github/workflows/deploy.yml@refs/heads/main" },
        ttl: "5m",
        token: {
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

  // What the broker reads first, to find the keys.
  const discovery = { issuer, jwks_uri: `${issuer}/.well-known/jwks` };
  return { issuer, jwks, discovery, sign };
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

/** In-memory Cloudflare account tokens API, permission groups and R2 temporary credentials. */
export class FakeCloudflare {
  tokens = new Map<string, StoredToken>();
  requests: { method: string; path: string; body?: unknown }[] = [];
  failCreate = false;
  failR2 = false;
  /** Fails temp-access-credentials for this bucket only. */
  failR2Bucket: string | undefined;
  private seq = 0;

  constructor() {
    this.add({ id: BROKER_TOKEN_ID, name: "cf-oidc broker token", value: BROKER_TOKEN });
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
    if (req.method === "POST" && path === `${acct}/r2/temp-access-credentials`) {
      const b = body as { bucket: string; parentAccessKeyId: string };
      if (this.failR2 || b.bucket === this.failR2Bucket) {
        return apiError(403, "Unauthorized to access requested resource");
      }
      return envelope({
        accessKeyId: b.parentAccessKeyId,
        secretAccessKey: "r2-secret-value",
        sessionToken: "r2-session-token-value",
      });
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

export const USER_TOKEN = "gho_exampleUserToken0000000000000000000";
export const USER_ID = "300000004";
export const TEAM_ID = "400000005";

type Role = "read" | "triage" | "write" | "maintain" | "admin";

/** GitHub's permission flags for a role: each role includes the ones below it. */
function flags(role: Role | undefined) {
  const order: Role[] = ["read", "triage", "write", "maintain", "admin"];
  const at = role ? order.indexOf(role) : -1;
  return { pull: at >= 0, triage: at >= 1, push: at >= 2, maintain: at >= 3, admin: at >= 4 };
}

interface FakeRepo {
  id: number;
  full_name: string;
  owner_id: number;
  /** The test user's role; absent means the repo is visible (public) without access. */
  role?: Role;
}

/** In-memory GitHub REST API for one user: `/user`, repos and `/user/teams`. */
export class FakeGitHub {
  requests: string[] = [];
  repos: FakeRepo[] = [
    { id: 200000002, full_name: "example-org/infra", owner_id: Number(OWNER_ID), role: "write" },
    { id: 200000003, full_name: "example-org/api", owner_id: Number(OWNER_ID), role: "read" },
    { id: 200000009, full_name: "other-org/infra", owner_id: 999999, role: "admin" },
  ];
  teams = [
    { id: Number(TEAM_ID), organization: { id: Number(OWNER_ID) } },
    { id: 400000099, organization: { id: 999999 } },
  ];
  /** Replies with this to every request whose path starts with `path`. */
  fail: { path: string; status: number; headers?: Record<string, string> } | undefined;

  handle(req: Request): Response {
    const url = new URL(req.url);
    this.requests.push(`${url.pathname}${url.search}`);
    if (this.fail && url.pathname.startsWith(this.fail.path)) {
      return Response.json({ message: "fail" }, { status: this.fail.status, headers: this.fail.headers ?? {} });
    }
    if (req.headers.get("authorization") !== `Bearer ${USER_TOKEN}`) {
      return Response.json({ message: "Bad credentials" }, { status: 401 });
    }

    if (url.pathname === "/user") return Response.json({ id: Number(USER_ID), login: "octocat" });
    if (url.pathname === "/user/teams") return Response.json(url.searchParams.get("page") === "1" ? this.teams : []);

    const byName = /^\/repos\/([^/]+\/[^/]+)$/.exec(url.pathname)?.[1];
    const byId = /^\/repositories\/(\d+)$/.exec(url.pathname)?.[1];
    const repo = this.repos.find((r) => r.full_name === byName || String(r.id) === byId);
    if (!repo) return Response.json({ message: "Not Found" }, { status: 404 });
    const [owner] = repo.full_name.split("/");
    return Response.json({
      id: repo.id,
      full_name: repo.full_name,
      owner: { id: repo.owner_id, login: owner },
      permissions: flags(repo.role),
    });
  }
}

/** Routes the Worker's outbound `fetch` to the fake issuer, GitHub API and Cloudflare API. */
/** An issuer as the fake fetch serves it: its discovery document and its JWKS. */
interface FakeIssuer {
  issuer: string;
  jwks: unknown;
  discovery: unknown;
}

export function installFetch(issuers: FakeIssuer | FakeIssuer[], cf: FakeCloudflare, github?: FakeGitHub) {
  const all = Array.isArray(issuers) ? issuers : [issuers];
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const req = new Request(input as RequestInfo, init as RequestInit);
    for (const issuer of all) {
      if (req.url === `${issuer.issuer}/.well-known/openid-configuration`) return Response.json(issuer.discovery);
      if (req.url === `${issuer.issuer}/.well-known/jwks`) return Response.json(issuer.jwks);
    }
    if (req.url.startsWith(API)) return cf.handle(req);
    if (github && req.url.startsWith("https://api.github.com/")) return github.handle(req);
    throw new TypeError(`unexpected fetch ${req.url}`);
  });
}
