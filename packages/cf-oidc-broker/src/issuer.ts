import { calculateJwkThumbprint, exportJWK, importPKCS8, type JWK, SignJWT } from "jose";
import { HttpError } from "./errors.js";
import type { Claims } from "./policy.js";

/** RS256: what OIDC verifiers support by default, cf-nix-cache included. Signed with Workers' WebCrypto. */
export const ALGORITHM = "RS256";

/** The smallest RSA key accepted, as NIST and jose require. */
const MIN_MODULUS_BITS = 2048;

/**
 * Verified claims always copied into the broker's tokens when the caller's token has them,
 * under the issuer's own names, so a service's rules keep working: GitHub's. Other issuers'
 * claims are copied when the policy matches on them. None are secret; `team_ids` is left
 * out, as it can be long.
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
 * The RSA signing key, from a Secrets Store binding holding a PKCS#8 PEM (as
 * `openssl genpkey -algorithm RSA` writes it). Its `kid` is the public key's RFC 7638
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
    throw unavailable("not an RSA private key in PKCS#8 PEM");
  }
  const bits = (privateKey.algorithm as { modulusLength: number }).modulusLength;
  if (bits < MIN_MODULUS_BITS) throw unavailable(`RSA key is ${bits} bits, at least ${MIN_MODULUS_BITS} needed`);
  // The private JWK carries the public `n` and `e` alongside the private members; only those two are published.
  const { kty, n, e } = await exportJWK(privateKey);
  const kid = await calculateJwkThumbprint({ kty, n, e } as JWK);
  const key = { privateKey, publicJwk: { kty, n, e, kid, alg: ALGORITHM, use: "sig" } as JWK, kid };
  cached = { pem, key };
  return key;
}

export interface IssueRequest {
  /** The broker's own URL. */
  issuer: string;
  audience: string;
  /** The caller's `sub` from its issuer, or `user:<actor_id>` for a person. */
  subject: string;
  /** The provider the caller's token came from. */
  provider: string;
  profile: string;
  /** Claims the policy matched on, also copied, so a service can match on the same ones. */
  matched: string[];
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
  for (const name of new Set<string>([...COPIED, ...req.matched])) {
    const value = req.claims[name];
    if (typeof value === "string" && value !== "") copied[name] = value;
  }
  const jti = crypto.randomUUID();
  const jwt = await new SignJWT({ ...copied, provider: req.provider, profile: req.profile })
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
