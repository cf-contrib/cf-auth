// The broker's HTTP contract. The action type-checks against this file, so it
// must stay free of runtime code and Workers-specific types.

/** What the presented `subject_token` is: a GitHub Actions OIDC token (`id_token` or `jwt`), or a GitHub user token (`access_token`). */
export type SubjectTokenType =
  | "urn:ietf:params:oauth:token-type:id_token"
  | "urn:ietf:params:oauth:token-type:jwt"
  | "urn:ietf:params:oauth:token-type:access_token";

/** What comes back: a Cloudflare API token, or only R2 credentials for a profile without a `token`. */
export type IssuedTokenType =
  | "urn:ietf:params:oauth:token-type:access_token"
  | "urn:cf-oidc-auth:params:oauth:token-type:r2-credentials";

/**
 * Body of `POST /oauth/token`, an RFC 8693 token exchange, form-encoded or JSON. `profile`,
 * `ttl` and `repository` are the broker's own extension parameters.
 */
export interface TokenExchangeRequest {
  grant_type: "urn:ietf:params:oauth:grant-type:token-exchange";
  subject_token: string;
  subject_token_type: SubjectTokenType;
  /** Defaults to Cloudflare, the only audience so far: `https://api.cloudflare.com`. */
  audience?: string | undefined;
  requested_token_type?: IssuedTokenType | undefined;
  profile?: string | undefined;
  ttl?: string | undefined;
  /** Required for a GitHub user token: the repo to get credentials for. */
  repository?: string | undefined;
}

/**
 * `200` response of `POST /oauth/token`. A profile with only `buckets` has no single bearer
 * token, so it returns no `access_token` and `token_type: "N_A"`, with the credentials in `buckets`.
 */
export interface TokenExchangeResponse {
  access_token?: string;
  issued_token_type: IssuedTokenType;
  token_type: "Bearer" | "N_A";
  /** Seconds until the token, or the R2 credentials, expire. */
  expires_in: number;
  /** Unix time in seconds. */
  expires_at: number;
  /** The Cloudflare API token's ID, present with `access_token`. */
  token_id?: string;
  account_id: string;
  profile: string;
  buckets?: BucketCredentials[];
}

/**
 * Body of `POST /oauth/revoke`, an RFC 7009 revocation, form-encoded or JSON. Answers `200`
 * whether the token was revoked, already gone or never valid; `403` for tokens the broker didn't mint.
 */
export interface TokenRevocationRequest {
  token: string;
  /** Ignored, as RFC 7009 allows: only Cloudflare API tokens the broker minted can be revoked. */
  token_type_hint?: "access_token" | undefined;
}

/** S3 credentials for one R2 bucket, limited to `prefixes`. They can't be revoked; they expire. */
export interface BucketCredentials {
  /** The bucket's name. */
  name: string;
  access_key_id: string;
  secret_access_key: string;
  session_token: string;
  /** Filled in from the caller's claims. Empty means the whole bucket. */
  prefixes: string[];
  /** `https://<account_id>.r2.cloudflarestorage.com` */
  endpoint: string;
  /** RFC 3339 timestamp. */
  expires_on: string;
}

export type ErrorCode =
  | "bad_request"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "misconfigured"
  | "upstream_error"
  | "internal";

/** Body of every non-2xx response. Deliberately generic: details only go to the audit log. */
export interface ErrorResponse {
  error: ErrorCode;
}
