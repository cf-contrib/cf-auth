import type { IssuedTokenType, SubjectTokenType, TokenExchangeRequest } from "./api.js";
import { HttpError } from "./errors.js";
import { REPOSITORY } from "./github.js";
import { CLOUDFLARE_AUDIENCE, type ProviderType } from "./policy.js";

export const TOKEN_EXCHANGE =
  "urn:ietf:params:oauth:grant-type:token-exchange" satisfies TokenExchangeRequest["grant_type"];
export const ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token" satisfies IssuedTokenType;
export const R2_CREDENTIALS = "urn:cf-oidc-auth:params:oauth:token-type:r2-credentials" satisfies IssuedTokenType;
export const JWT = "urn:ietf:params:oauth:token-type:jwt" satisfies IssuedTokenType;

/** Which kind of provider each kind of subject token is checked against. */
const PROVIDER_TYPES: Record<SubjectTokenType, ProviderType> = {
  "urn:ietf:params:oauth:token-type:id_token": "oidc",
  "urn:ietf:params:oauth:token-type:jwt": "oidc",
  "urn:ietf:params:oauth:token-type:access_token": "github-user",
};

/** An OIDC token is a few KB at most, and a GitHub user token far less. */
const MAX_SUBJECT_TOKEN = 8192;

/** The broker's own exchange parameters, once checked. */
export type TokenFields = Pick<TokenExchangeRequest, "profile" | "ttl" | "repository">;

const invalid = (detail: string) => new HttpError("bad_request", "invalid_body", detail);

/** Checks `profile`, `ttl` and, for people, `repository`. They end up in the audit log, so they're bounded. */
function checkFields(type: ProviderType, fields: Record<string, unknown>): TokenFields {
  const { profile, ttl } = fields;
  if ((profile !== undefined && typeof profile !== "string") || (ttl !== undefined && typeof ttl !== "string")) {
    throw invalid("profile and ttl must be strings");
  }
  // Profile names are at most 64 characters anyway.
  if ((profile?.length ?? 0) > 64 || (ttl?.length ?? 0) > 16) throw invalid("profile or ttl too long");
  if (type === "oidc") return { profile, ttl };

  // Optional: without one, only who the person is counts.
  const { repository } = fields;
  if (repository === undefined) return { profile, ttl };
  if (typeof repository !== "string" || repository.length > 200 || !REPOSITORY.test(repository)) {
    throw invalid("repository must be owner/name or a numeric ID");
  }
  return { profile, ttl, repository };
}

/** Parses a JSON object body, or throws a `400`. */
function parseObject(text: string): Record<string, unknown> {
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw invalid("not JSON");
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) throw invalid("not an object");
  return body as Record<string, unknown>;
}

/** Reads an `/oauth/*` body: form-encoded as the RFCs have it, or JSON. */
async function readBody(request: Request): Promise<Record<string, unknown>> {
  const type = request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();
  const text = await request.text();
  if (type === "application/x-www-form-urlencoded") return Object.fromEntries(new URLSearchParams(text));
  if (type === "application/json") return parseObject(text);
  throw invalid("content-type must be application/x-www-form-urlencoded or application/json");
}

/** A parsed `POST /oauth/token`: what kind of token, which token, for what. */
export interface Exchange {
  type: ProviderType;
  token: string;
  /** Cloudflare, or a service the policy issues the broker's own tokens for. Checked against the policy later. */
  audience: string;
  fields: TokenFields;
}

/** What each audience can hand out: Cloudflare credentials, or a JWT for any other service. */
const ISSUABLE = {
  cloudflare: [ACCESS_TOKEN, R2_CREDENTIALS] as unknown[],
  service: [JWT, ACCESS_TOKEN] as unknown[],
};

/**
 * Reads an RFC 8693 token exchange, form-encoded or JSON. Anything it doesn't support, such
 * as delegation with `actor_token`, is refused rather than ignored.
 */
export async function readExchangeRequest(request: Request): Promise<Exchange> {
  const body = await readBody(request);

  const { grant_type, subject_token, subject_token_type, audience, requested_token_type } = body;
  // The audit log gets what was asked for, cut short.
  const shown = (value: unknown) => String(value).slice(0, 200);
  if (grant_type !== TOKEN_EXCHANGE) throw new HttpError("bad_request", "unsupported_grant_type", shown(grant_type));
  if (body.actor_token !== undefined || body.actor_token_type !== undefined) {
    throw new HttpError("bad_request", "actor_token_unsupported");
  }
  if (typeof subject_token !== "string" || subject_token === "") throw invalid("subject_token is required");
  if (subject_token.length > MAX_SUBJECT_TOKEN) throw invalid("subject_token too long");
  const type =
    typeof subject_token_type === "string" && Object.hasOwn(PROVIDER_TYPES, subject_token_type)
      ? PROVIDER_TYPES[subject_token_type as SubjectTokenType]
      : undefined;
  if (type === undefined) {
    throw new HttpError("bad_request", "unsupported_subject_token_type", shown(subject_token_type));
  }
  if (audience !== undefined && (typeof audience !== "string" || audience === "" || audience.length > 200)) {
    throw new HttpError("bad_request", "invalid_target", shown(audience));
  }
  const target = audience ?? CLOUDFLARE_AUDIENCE;
  const issuable = target === CLOUDFLARE_AUDIENCE ? ISSUABLE.cloudflare : ISSUABLE.service;
  if (requested_token_type !== undefined && !issuable.includes(requested_token_type)) {
    throw new HttpError("bad_request", "unsupported_requested_token_type", shown(requested_token_type));
  }
  return { type, token: subject_token, audience: target, fields: checkFields(type, body) };
}

/**
 * Reads an RFC 7009 revocation: the token to revoke, form-encoded or JSON. `token_type_hint`
 * is ignored, as the RFC allows: only Cloudflare API tokens the broker minted can be revoked.
 */
export async function readRevokeRequest(request: Request): Promise<string> {
  const { token } = await readBody(request);
  if (typeof token !== "string" || token === "") throw invalid("token is required");
  if (token.length > MAX_SUBJECT_TOKEN) throw invalid("token too long");
  return token;
}
