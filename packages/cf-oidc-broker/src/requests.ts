import type { IssuedTokenType, SubjectTokenType, TokenExchangeRequest, UserTokenRequest } from "./api.js";
import { HttpError } from "./errors.js";
import { REPOSITORY } from "./github.js";
import type { Subject } from "./policy.js";

export const TOKEN_EXCHANGE =
  "urn:ietf:params:oauth:grant-type:token-exchange" satisfies TokenExchangeRequest["grant_type"];
export const ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token" satisfies IssuedTokenType;
export const R2_CREDENTIALS = "urn:cf-oidc-auth:params:oauth:token-type:r2-credentials" satisfies IssuedTokenType;
/** The audience for Cloudflare API tokens and R2 credentials, and the default. */
export const CLOUDFLARE_AUDIENCE = "https://api.cloudflare.com";

/** Who presents each kind of subject token. */
const SUBJECTS: Record<SubjectTokenType, Subject> = {
  "urn:ietf:params:oauth:token-type:id_token": "actions",
  "urn:ietf:params:oauth:token-type:jwt": "actions",
  "urn:ietf:params:oauth:token-type:access_token": "users",
};

/** A GitHub OIDC token is a few KB at most, and a GitHub user token far less. */
const MAX_SUBJECT_TOKEN = 8192;

/** A token request, whichever route it came in on. */
export type TokenFields = Partial<UserTokenRequest>;

const invalid = (detail: string) => new HttpError("bad_request", "invalid_body", detail);

/** Checks `profile`, `ttl` and, for people, `repository`. They end up in the audit log, so they're bounded. */
function checkFields(subject: Subject, fields: Record<string, unknown>): TokenFields {
  const { profile, ttl } = fields;
  if ((profile !== undefined && typeof profile !== "string") || (ttl !== undefined && typeof ttl !== "string")) {
    throw invalid("profile and ttl must be strings");
  }
  // Profile names are at most 64 characters anyway.
  if ((profile?.length ?? 0) > 64 || (ttl?.length ?? 0) > 16) throw invalid("profile or ttl too long");
  if (subject === "actions") return { profile, ttl };

  const { repository } = fields;
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

/** Reads the body of `/v1/actions/token` or `/v1/users/token`. `repository` is only read, and then required, for people. */
export async function readTokenRequest(request: Request, subject: Subject): Promise<TokenFields> {
  const text = await request.text();
  if (text.trim() === "") {
    if (subject === "users") throw invalid("repository is required");
    return {};
  }
  return checkFields(subject, parseObject(text));
}

/** A parsed `POST /oauth/token`: who's asking, with what token, for what. */
export interface Exchange {
  subject: Subject;
  token: string;
  fields: TokenFields;
}

/**
 * Reads an RFC 8693 token exchange, form-encoded or JSON. Anything it doesn't support, such
 * as delegation with `actor_token` or another audience, is refused rather than ignored.
 */
export async function readExchangeRequest(request: Request): Promise<Exchange> {
  const type = request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();
  const text = await request.text();
  let body: Record<string, unknown>;
  if (type === "application/x-www-form-urlencoded") {
    body = Object.fromEntries(new URLSearchParams(text));
  } else if (type === "application/json") {
    body = parseObject(text);
  } else {
    throw invalid("content-type must be application/x-www-form-urlencoded or application/json");
  }

  const { grant_type, subject_token, subject_token_type, audience, requested_token_type } = body;
  // The audit log gets what was asked for, cut short.
  const shown = (value: unknown) => String(value).slice(0, 200);
  if (grant_type !== TOKEN_EXCHANGE) throw new HttpError("bad_request", "unsupported_grant_type", shown(grant_type));
  if (body.actor_token !== undefined || body.actor_token_type !== undefined) {
    throw new HttpError("bad_request", "actor_token_unsupported");
  }
  if (typeof subject_token !== "string" || subject_token === "") throw invalid("subject_token is required");
  if (subject_token.length > MAX_SUBJECT_TOKEN) throw invalid("subject_token too long");
  const subject =
    typeof subject_token_type === "string" && Object.hasOwn(SUBJECTS, subject_token_type)
      ? SUBJECTS[subject_token_type as SubjectTokenType]
      : undefined;
  if (subject === undefined) {
    throw new HttpError("bad_request", "unsupported_subject_token_type", shown(subject_token_type));
  }
  if (audience !== undefined && audience !== CLOUDFLARE_AUDIENCE) {
    throw new HttpError("bad_request", "invalid_target", shown(audience));
  }
  if (
    requested_token_type !== undefined &&
    requested_token_type !== ACCESS_TOKEN &&
    requested_token_type !== R2_CREDENTIALS
  ) {
    throw new HttpError("bad_request", "unsupported_requested_token_type", shown(requested_token_type));
  }
  return { subject, token: subject_token, fields: checkFields(subject, body) };
}
