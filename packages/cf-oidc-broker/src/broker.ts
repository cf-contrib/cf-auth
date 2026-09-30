import Cloudflare, { CloudflareError } from "cloudflare";
import type { ErrorResponse, R2Credentials, TokenRequest, TokenResponse } from "./api.js";
import { audit } from "./audit.js";
import { HttpError } from "./errors.js";
import { bearer, verifyGitHubJWT } from "./jwt.js";
import { type Claims, clampTTL, loadPolicy, type Policy, PolicyError, r2Prefixes, selectProfile } from "./policy.js";
import { issueR2 } from "./r2.js";
import { cleanup, discard, type MintedToken, mint, revoke } from "./tokens.js";

export interface Env {
  /** Account the broker token belongs to and tokens are minted in. */
  CF_OIDC_BROKER_ACCOUNT_ID: string;
  /**
   * Account-owned token with "Account API Tokens Write", plus R2 Admin Read & Write
   * ("Workers R2 Storage Write") for `r2` grants: it creates their credentials and is
   * their parent. Must be a Secrets Store binding: a plain Worker secret is refused,
   * not used.
   */
  CF_OIDC_BROKER_TOKEN: SecretsStoreSecret;
}

// Parsed once per isolate. The policy and env are fixed for the lifetime of a deployment.
let loaded: { raw: unknown; accountId: string; result: Policy | PolicyError } | undefined;

/** Loads the policy and checks required bindings. Fails closed: any problem is a `500`. */
export function config(raw: unknown, env: Env): Policy {
  if (loaded === undefined || loaded.raw !== raw || loaded.accountId !== env.CF_OIDC_BROKER_ACCOUNT_ID) {
    let result: Policy | PolicyError;
    try {
      result = loadPolicy(raw, env.CF_OIDC_BROKER_ACCOUNT_ID);
    } catch (err) {
      result = err instanceof PolicyError ? err : new PolicyError([String(err)]);
    }
    loaded = { raw, accountId: env.CF_OIDC_BROKER_ACCOUNT_ID, result };
    if (result instanceof PolicyError) {
      audit("policy.invalid", { issues: result.issues });
    } else {
      audit("policy.loaded", { profiles: result.profiles.length });
    }
  }
  if (loaded.result instanceof PolicyError) throw loaded.result;
  if (!env.CF_OIDC_BROKER_ACCOUNT_ID || !env.CF_OIDC_BROKER_TOKEN) {
    throw new PolicyError(["CF_OIDC_BROKER_ACCOUNT_ID and CF_OIDC_BROKER_TOKEN must be set"]);
  }
  return loaded.result;
}

/** A client authenticated with the broker token. A Secrets Store value is read on every call, never cached here. */
async function brokerClient(env: Env): Promise<Cloudflare> {
  const secret: unknown = env.CF_OIDC_BROKER_TOKEN;
  // Fail closed rather than accept a weaker setup: the token lives only in Secrets Store.
  if (typeof (secret as Partial<SecretsStoreSecret> | undefined)?.get !== "function") {
    throw new HttpError(
      "misconfigured",
      "broker_token_unavailable",
      "CF_OIDC_BROKER_TOKEN must be a Secrets Store binding",
    );
  }
  let apiToken: string;
  try {
    apiToken = await (secret as SecretsStoreSecret).get();
  } catch (err) {
    throw new HttpError("misconfigured", "broker_token_unavailable", (err as Error).message);
  }
  if (!apiToken) throw new HttpError("misconfigured", "broker_token_unavailable", "empty value");
  return new Cloudflare({ apiToken });
}

function json(status: number, body: unknown): Response {
  return Response.json(body, { status, headers: { "cache-control": "no-store" } });
}

function failure(err: unknown): Response {
  if (err instanceof HttpError) return json(err.status, { error: err.code } satisfies ErrorResponse);
  if (err instanceof PolicyError) return json(500, { error: "misconfigured" } satisfies ErrorResponse);
  if (err instanceof CloudflareError) {
    console.error(JSON.stringify({ event: "cloudflare.error", message: err.message }));
    return json(502, { error: "upstream_error" } satisfies ErrorResponse);
  }
  console.error(JSON.stringify({ event: "internal.error", message: String(err) }));
  return json(500, { error: "internal" } satisfies ErrorResponse);
}

async function readTokenRequest(request: Request): Promise<TokenRequest> {
  const text = await request.text();
  if (text.trim() === "") return {};
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new HttpError("bad_request", "invalid_body", "not JSON");
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new HttpError("bad_request", "invalid_body", "not an object");
  }
  const { profile, ttl } = body as Record<string, unknown>;
  if ((profile !== undefined && typeof profile !== "string") || (ttl !== undefined && typeof ttl !== "string")) {
    throw new HttpError("bad_request", "invalid_body", "profile and ttl must be strings");
  }
  // Both end up in the audit log; profile names are at most 64 characters anyway.
  if ((profile?.length ?? 0) > 64 || (ttl?.length ?? 0) > 16) {
    throw new HttpError("bad_request", "invalid_body", "profile or ttl too long");
  }
  return { profile, ttl };
}

async function handleToken(request: Request, env: Env, raw: unknown): Promise<Response> {
  let claims: Claims | undefined;
  let profile: string | undefined;
  try {
    const policy = config(raw, env);
    claims = await verifyGitHubJWT(bearer(request), policy.github);

    const req = await readTokenRequest(request);
    profile = req.profile;
    const selected = selectProfile(policy, claims, req.profile);
    profile = selected.name;
    const ttl = clampTTL(req.ttl, selected);
    // Filled in before anything is minted, so an unusable claim leaves nothing behind.
    const prefixes = selected.r2 ? r2Prefixes(selected.r2, claims) : [];

    const cf = await brokerClient(env);
    const accountId = env.CF_OIDC_BROKER_ACCOUNT_ID;
    let token: MintedToken | undefined;
    if (selected.policies) {
      token = await mint(cf, accountId, selected.policies, claims, ttl);
      audit("token.mint", { profile, claims, token_id: token.token_id, expires_on: token.expires_on });
    }

    let r2: R2Credentials | undefined;
    if (selected.r2) {
      try {
        r2 = await issueR2(cf, accountId, selected.r2, prefixes, ttl);
      } catch (err) {
        // Half a grant isn't handed out.
        if (token) await discard(cf, accountId, token.token_id);
        throw err;
      }
      audit("r2.issued", {
        profile,
        claims,
        bucket: r2.bucket,
        prefixes: r2.prefixes,
        permission: selected.r2.permission,
        expires_on: r2.expires_on,
      });
    }

    const expires_on = token?.expires_on ?? r2?.expires_on;
    if (expires_on === undefined) throw new Error(`profile ${profile} has neither a token nor an r2 grant`);
    return json(200, {
      ...token,
      account_id: accountId,
      expires_on,
      profile: selected.name,
      ...(r2 ? { r2 } : {}),
    } satisfies TokenResponse);
  } catch (err) {
    if (err instanceof HttpError) {
      audit("token.deny", { profile, claims, reason: err.reason, detail: err.detail });
    } else if (err instanceof CloudflareError) {
      audit("token.deny", { profile, claims, reason: "cloudflare_error", detail: err.message });
    }
    return failure(err);
  }
}

async function handleRevoke(request: Request, env: Env, raw: unknown): Promise<Response> {
  try {
    config(raw, env);
    const presented = bearer(request);
    const cf = await brokerClient(env);
    const id = await revoke(cf, env.CF_OIDC_BROKER_ACCOUNT_ID, presented);
    audit("token.revoke", id ? { token_id: id } : { reason: "already_gone" });
    return new Response(null, { status: 204 });
  } catch (err) {
    if (err instanceof HttpError) audit("token.revoke", { reason: err.reason, detail: err.detail });
    return failure(err);
  }
}

/**
 * The Worker, serving `policy`: the policy file's JSON text, or the parsed
 * object when a bundler has already inlined it.
 */
export function createBroker(policy: unknown) {
  return {
    async fetch(request, env): Promise<Response> {
      const { pathname } = new URL(request.url);
      const route = `${request.method} ${pathname}`;
      switch (route) {
        case "POST /v1/token":
          return handleToken(request, env, policy);
        case "POST /v1/revoke":
          return handleRevoke(request, env, policy);
        case "GET /healthz":
          try {
            config(policy, env);
            await brokerClient(env); // a missing Secrets Store secret shows up here, not on the first mint
            return json(200, { status: "ok" });
          } catch (err) {
            return failure(err);
          }
        default:
          return json(404, { error: "not_found" } satisfies ErrorResponse);
      }
    },

    async scheduled(_controller, env, ctx): Promise<void> {
      if (!env.CF_OIDC_BROKER_ACCOUNT_ID || !env.CF_OIDC_BROKER_TOKEN) return;
      ctx.waitUntil(
        brokerClient(env)
          .then((cf) => cleanup(cf, env.CF_OIDC_BROKER_ACCOUNT_ID))
          .then((deleted) => {
            console.log(JSON.stringify({ event: "cleanup.done", deleted }));
          }),
      );
    },
  } satisfies ExportedHandler<Env>;
}
