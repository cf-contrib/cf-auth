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
  token: string;
  token_id: string;
  account_id: string;
  /** RFC 3339 timestamp, e.g. `2026-09-28T12:15:00Z`. */
  expires_on: string;
  profile: string;
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
