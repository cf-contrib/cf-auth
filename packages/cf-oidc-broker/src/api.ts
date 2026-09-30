// The broker's /v1 HTTP contract. The action type-checks against this file, so it
// must stay free of runtime code and Workers-specific types.

/** Body of `POST /v1/token`. */
export interface TokenRequest {
  /** Profile to use. If omitted, exactly one profile must match the caller's claims. */
  profile?: string | undefined;
  /** Requested lifetime such as `10m` or `1h`. Capped at the profile's `max_ttl`. */
  ttl?: string | undefined;
}

/** `200` response of `POST /v1/token`. */
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
