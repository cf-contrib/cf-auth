import { calculateJwkThumbprint, exportJWK, importPKCS8, type JWK, SignJWT } from "jose";
import { HttpError } from "./errors.js";
import type { Claims } from "./policy.js";

/** RFC 8037's name for Ed25519 in JWS headers, which every JOSE library understands. */
export const ALGORITHM = "EdDSA";

/**
 * Verified claims copied into the broker's tokens under GitHub's own names, so a service's
 * existing rules keep working. None are secret; `team_ids` is left out, as it can be long.
 */
const COPIED = [
  "repository",
  "repository_id",
  "repository_owner",
  "repository_owner_id",
  "ref",
  "ref_type",
  "environment",
  "event_name",
  "workflow_ref",
  "job_workflow_ref",
  "run_id",
  "run_attempt",
  "runner_environment",
  "actor",
  "actor_id",
  "repository_permission",
] as const;

export interface SigningKey {
  privateKey: CryptoKey;
  /** The public half as published in the JWKS, with `kid`, `alg` and `use`. */
  publicJwk: JWK;
  kid: string;
}

// Imported once per isolate and keyed by the secret's value, so a rotated key is imported again.
let cached: { pem: string; key: SigningKey } | undefined;

/** Test hook: forget the imported key. */
export function clearSigningKey() {
  cached = undefined;
}

/**
 * The Ed25519 signing key, from a Secrets Store binding holding a PKCS#8 PEM (as
 * `openssl genpkey -algorithm ed25519` writes it). Its `kid` is the public key's RFC 7638
 * thumbprint, so a new key gets a new `kid` without any configuration.
 */
export async function signingKey(secret: SecretsStoreSecret | undefined): Promise<SigningKey> {
  const unavailable = (detail: string) => new HttpError("misconfigured", "signing_key_unavailable", detail);
  if (typeof (secret as Partial<SecretsStoreSecret> | undefined)?.get !== "function") {
    throw unavailable("CF_OIDC_BROKER_SIGNING_KEY must be a Secrets Store binding");
  }
  let pem: string;
  try {
    pem = await (secret as SecretsStoreSecret).get();
  } catch (err) {
    throw unavailable((err as Error).message);
  }
  if (!pem) throw unavailable("empty value");
  if (cached?.pem === pem) return cached.key;

  let privateKey: CryptoKey;
  try {
    privateKey = await importPKCS8(pem, ALGORITHM, { extractable: true });
  } catch {
    throw unavailable("not an Ed25519 private key in PKCS#8 PEM");
  }
  // The private JWK carries the public `x` alongside `d`; only the public members are published.
  const { kty, crv, x } = await exportJWK(privateKey);
  const kid = await calculateJwkThumbprint({ kty, crv, x } as JWK);
  const key = { privateKey, publicJwk: { kty, crv, x, kid, alg: ALGORITHM, use: "sig" } as JWK, kid };
  cached = { pem, key };
  return key;
}

export interface IssueRequest {
  /** The broker's own URL. */
  issuer: string;
  audience: string;
  /** GitHub's `sub` for a job, `user:<actor_id>` for a person. */
  subject: string;
  profile: string;
  claims: Claims;
  /** The profile's TTL, in milliseconds. */
  ttl: number;
  /** Unix seconds the token mustn't outlive: the presented token's `exp`, when it has one. */
  notAfter?: number | undefined;
}

/** Signs a token for another service. It never outlives the token the caller presented. */
export async function issueJwt(key: SigningKey, req: IssueRequest) {
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = Math.min(now + Math.floor(req.ttl / 1000), req.notAfter ?? Number.POSITIVE_INFINITY);
  // The GitHub token was accepted with clock tolerance; a token that can't live at all isn't issued.
  if (expiresAt <= now) throw new HttpError("unauthorized", "invalid_jwt", "subject token has expired");

  const copied: Record<string, string> = {};
  for (const name of COPIED) {
    const value = req.claims[name];
    if (typeof value === "string" && value !== "") copied[name] = value;
  }
  const jti = crypto.randomUUID();
  const jwt = await new SignJWT({ ...copied, profile: req.profile })
    .setProtectedHeader({ alg: ALGORITHM, kid: key.kid, typ: "JWT" })
    .setIssuer(req.issuer)
    .setAudience(req.audience)
    .setSubject(req.subject)
    .setIssuedAt(now)
    .setNotBefore(now)
    .setExpirationTime(expiresAt)
    .setJti(jti)
    .sign(key.privateKey);
  return { jwt, jti, expiresAt };
}
