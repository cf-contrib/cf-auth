import type { ErrorCode } from "./api.js";

const STATUS: Record<ErrorCode, number> = {
  bad_request: 400,
  unauthorized: 401,
  forbidden: 403,
  not_found: 404,
  misconfigured: 500,
  upstream_error: 502,
  internal: 500,
};

/**
 * An error that maps to an HTTP response. `reason` and `detail` are for the audit
 * log only; callers just see `{ "error": code }`.
 */
export class HttpError extends Error {
  readonly status: number;

  constructor(
    readonly code: ErrorCode,
    readonly reason: string,
    readonly detail?: string,
  ) {
    super(detail ? `${reason}: ${detail}` : reason);
    this.name = "HttpError";
    this.status = STATUS[code];
  }
}
