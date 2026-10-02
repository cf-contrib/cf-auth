// The broker's /v1 HTTP contract. The action type-checks against this file, so it
// must stay free of runtime code and Workers-specific types.

/** Body of `POST /v1/actions/token`, which a GitHub Actions job calls with its OIDC token. */
export interface TokenRequest {
  /** Profile to use. If omitted, exactly one profile must match the caller's claims. */
  profile?: string | undefined;
  /** Requested lifetime such as `10m` or `1h`. Capped at the profile's `max_ttl`. */
  ttl?: string | undefined;
}

/** Body of `POST /v1/users/token`, which a person calls with their GitHub user token. */
export interface UserTokenRequest extends TokenRequest {
  /**
   * Repo to get credentials for: `owner/name` or its numeric ID. The broker checks the
   * caller's role on it, and fills in bucket prefixes from what GitHub returns for it.
   */
  repository: string;
}

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
 * `ttl` and `repository` are extension parameters with the same meaning as on the `/v1` routes.
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

/** `200` response of `POST /v1/actions/token` and `POST /v1/users/token`. */
export interface TokenResponse {
  /** Absent for a profile with only `buckets`, like `token_id`. */
  token?: string;
  token_id?: string;
  account_id: string;
  /** RFC 3339 timestamp, e.g. `2026-09-28T12:15:00Z`. */
  expires_on: string;
  profile: string;
  /** One entry per bucket in the profile's `buckets`, in the same order. */
  buckets?: BucketCredentials[];
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
