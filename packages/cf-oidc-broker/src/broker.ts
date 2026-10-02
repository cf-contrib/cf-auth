import Cloudflare, { CloudflareError } from "cloudflare";
import type { BucketCredentials, ErrorResponse, TokenExchangeResponse } from "./api.js";
import { audit } from "./audit.js";
import { HttpError } from "./errors.js";
import { verifyGitHubUser } from "./github.js";
import { verifyGitHubJWT } from "./jwt.js";
import {
  type Claims,
  clampTTL,
  loadPolicy,
  type Policy,
  PolicyError,
  r2Prefixes,
  type Subject,
  selectProfile,
} from "./policy.js";
import { issueR2 } from "./r2.js";
import { ACCESS_TOKEN, R2_CREDENTIALS, readExchangeRequest, readRevokeRequest, type TokenFields } from "./requests.js";
import { cleanup, discard, type MintedToken, mint, revoke, tokenName } from "./tokens.js";

export interface Env {
  /** Account the broker token belongs to and tokens are minted in. */
  CF_OIDC_BROKER_ACCOUNT_ID: string;
  /**
   * Account-owned token with "Account API Tokens Write", plus R2 permissions covering
   * what profiles' `buckets` delegate: it creates their credentials and is their parent. Must be a Secrets Store binding: a plain Worker secret is refused,
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

/** Ends with a `404` when no enabled profile is for people, so the broker doesn't call GitHub for them. */
function userProfiles(policy: Policy) {
  const users = policy.profiles.filter((p) => p.subject === "users" && p.enabled);
  if (users.length === 0) throw new HttpError("not_found", "no_user_profiles");
  return users;
}

/** Checks a person's GitHub token for the requested repo. */
async function verifyUser(policy: Policy, token: string, fields: TokenFields): Promise<Claims> {
  // Teams cost extra GitHub calls, so they're only looked up if a profile that could match needs them.
  const users = userProfiles(policy);
  const candidates = fields.profile === undefined ? users : users.filter((p) => p.name === fields.profile);
  const teams = candidates.some((p) => p.match.team_id !== undefined);
  return verifyGitHubUser(token, fields.repository as string, { ownerId: policy.github.owner_id, teams });
}

/** A verified caller of a token route. */
interface Caller {
  subject: Subject;
  claims: Claims;
  fields: TokenFields;
}

/** Authenticates the caller, whose token is in the body. Nothing is verified before the body parses. */
async function authenticate(request: Request, policy: Policy): Promise<Caller> {
  const { subject, token, fields } = await readExchangeRequest(request);
  const claims =
    subject === "actions" ? await verifyGitHubJWT(token, policy.github) : await verifyUser(policy, token, fields);
  return { subject, claims, fields };
}

/** What a token exchange hands out. */
interface Grant {
  profile: string;
  accountId: string;
  token?: MintedToken | undefined;
  buckets: BucketCredentials[];
  expiresOn: string;
}

/** The RFC 8693 response of `/oauth/token`, with the broker's own fields as extensions. */
function exchangeResponse(grant: Grant): TokenExchangeResponse {
  const expiresAt = Math.floor(Date.parse(grant.expiresOn) / 1000);
  const { token } = grant;
  return {
    ...(token
      ? { access_token: token.token, issued_token_type: ACCESS_TOKEN, token_type: "Bearer", token_id: token.token_id }
      : { issued_token_type: R2_CREDENTIALS, token_type: "N_A" }),
    expires_in: Math.max(0, expiresAt - Math.floor(Date.now() / 1000)),
    expires_at: expiresAt,
    account_id: grant.accountId,
    profile: grant.profile,
    ...(grant.buckets.length > 0 ? { buckets: grant.buckets } : {}),
  };
}

/** Serves `POST /oauth/token`. */
async function handleToken(request: Request, env: Env, raw: unknown): Promise<Response> {
  let subject: Subject | undefined;
  let claims: Claims | undefined;
  let profile: string | undefined;
  try {
    const policy = config(raw, env);
    const caller = await authenticate(request, policy);
    ({ subject, claims } = caller);
    const { fields } = caller;
    profile = fields.profile;
    const selected = selectProfile(policy, caller.subject, caller.claims, fields.profile);
    profile = selected.name;
    const ttl = clampTTL(fields.ttl, selected);
    // Filled in before anything is minted, so an unusable claim leaves nothing behind.
    const verified = caller.claims;
    const buckets = (selected.buckets ?? []).map((bucket) => ({ bucket, prefixes: r2Prefixes(bucket, verified) }));

    const cf = await brokerClient(env);
    const accountId = env.CF_OIDC_BROKER_ACCOUNT_ID;
    let token: MintedToken | undefined;
    if (selected.policies) {
      token = await mint(cf, accountId, selected.policies, tokenName(verified, caller.subject), ttl);
      audit("token.mint", { subject, profile, claims, token_id: token.token_id, expires_on: token.expires_on });
    }

    const issued: BucketCredentials[] = [];
    for (const { bucket, prefixes } of buckets) {
      let creds: BucketCredentials;
      try {
        creds = await issueR2(cf, accountId, bucket, prefixes, ttl);
      } catch (err) {
        // Half a profile isn't handed out. Credentials already issued can't be revoked,
        // but nobody has them.
        if (token) await discard(cf, accountId, token.token_id);
        throw err;
      }
      audit("r2.issued", {
        subject,
        profile,
        claims,
        bucket: creds.name,
        prefixes: creds.prefixes,
        permission: bucket.permission,
        expires_on: creds.expires_on,
      });
      issued.push(creds);
    }

    const expiresOn = token?.expires_on ?? issued[0]?.expires_on;
    if (expiresOn === undefined) throw new Error(`profile ${profile} has neither a token nor buckets`);
    const grant: Grant = { profile: selected.name, accountId, token, buckets: issued, expiresOn };
    return json(200, exchangeResponse(grant));
  } catch (err) {
    if (err instanceof HttpError) {
      audit("token.deny", { subject, profile, claims, reason: err.reason, detail: err.detail });
    } else if (err instanceof CloudflareError) {
      audit("token.deny", { subject, profile, claims, reason: "cloudflare_error", detail: err.message });
    }
    return failure(err);
  }
}

/** Serves `POST /oauth/revoke`. Answers `200` whether the token was revoked or already gone, as RFC 7009 has it. */
async function handleRevoke(request: Request, env: Env, raw: unknown): Promise<Response> {
  try {
    config(raw, env);
    const presented = await readRevokeRequest(request);
    const cf = await brokerClient(env);
    const id = await revoke(cf, env.CF_OIDC_BROKER_ACCOUNT_ID, presented);
    audit("token.revoke", id ? { token_id: id } : { reason: "already_gone" });
    return new Response(null, { status: 200, headers: { "cache-control": "no-store" } });
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
        case "POST /oauth/token":
          return handleToken(request, env, policy);
        case "POST /oauth/revoke":
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
