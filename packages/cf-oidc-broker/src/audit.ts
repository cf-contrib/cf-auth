import type { Claims, Subject } from "./policy.js";

/** Claims copied into audit lines. None of them are secret. */
const CLAIMS = [
  "repository",
  "repository_id",
  "ref",
  "environment",
  "event_name",
  "workflow_ref",
  "job_workflow_ref",
  "run_id",
  "run_attempt",
  "actor",
  "actor_id",
] as const;

export type AuditEvent =
  | "token.mint"
  | "token.deny"
  | "token.revoke"
  | "token.cleanup"
  | "r2.issued"
  | "token.issue"
  | "policy.loaded"
  | "policy.invalid";

export interface AuditFields {
  claims?: Claims | undefined;
  subject?: Subject | undefined;
  profile?: string | undefined;
  reason?: string | undefined;
  detail?: string | undefined;
  token_id?: string | undefined;
  expires_on?: string | undefined;
  [key: string]: unknown;
}

/**
 * Emits one structured line to Workers Logs. Callers must never pass token
 * values, R2 secrets or raw JWTs.
 */
export function audit(event: AuditEvent, { claims, ...fields }: AuditFields = {}) {
  const line: Record<string, unknown> = { event };
  if (fields.subject !== undefined) line.subject = fields.subject;
  if (fields.profile !== undefined) line.profile = fields.profile;
  for (const key of CLAIMS) {
    const value = claims?.[key];
    if (typeof value === "string" && value !== "") line[key] = value;
  }
  for (const [key, value] of Object.entries(fields)) {
    if (value !== undefined && !(key in line)) line[key] = value;
  }
  const log = event === "token.deny" || event === "policy.invalid" ? console.warn : console.log;
  log(JSON.stringify(line));
}
