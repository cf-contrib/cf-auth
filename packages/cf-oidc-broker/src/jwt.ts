import { createRemoteJWKSet, decodeJwt, type JWTVerifyGetKey, jwtVerify } from "jose";
import { HttpError } from "./errors.js";
import { type Claims, isIssuerUrl, type Provider } from "./policy.js";

/** Per-isolate key sets, by issuer. `jose` refetches on an unknown `kid`. */
const jwks = new Map<string, JWTVerifyGetKey>();

/** Test hook: forget every issuer's keys. */
export function clearKeys() {
  jwks.clear();
}

const unavailable = (detail: string) => new HttpError("upstream_error", "jwks_unavailable", detail);

/**
 * An issuer's keys: from its configured `jwks_uri`, or from its discovery document, which
 * must name the same issuer, so one issuer can't hand out another's keys. Never from the token.
 */
async function keysFor(provider: Provider): Promise<JWTVerifyGetKey> {
  const issuer = provider.issuer as string;
  const known = jwks.get(issuer);
  if (known) return known;

  let uri = provider.jwks_uri;
  if (uri === undefined) {
    const url = `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
    let doc: { issuer?: unknown; jwks_uri?: unknown };
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
      if (!res.ok) throw new Error(`returned ${res.status}`);
      doc = await res.json();
    } catch (err) {
      throw unavailable(`${url}: ${(err as Error).message}`);
    }
    if (doc.issuer !== issuer) throw unavailable(`${url} is for issuer ${String(doc.issuer).slice(0, 200)}`);
    if (typeof doc.jwks_uri !== "string" || !URL.canParse(doc.jwks_uri) || !isIssuerUrl(doc.jwks_uri)) {
      throw unavailable(`${url}: jwks_uri must be an https:// URL`);
    }
    uri = doc.jwks_uri;
  }
  const keys = createRemoteJWKSet(new URL(uri));
  jwks.set(issuer, keys);
  return keys;
}

/**
 * The OIDC provider whose issuer the token names. Its `iss` is read unverified, only to pick
 * the keys to verify it with; `verifyOidcToken` then checks `iss` again.
 */
export function providerFor(jwt: string, providers: Provider[]): Provider {
  let iss: unknown;
  try {
    iss = decodeJwt(jwt).iss;
  } catch {
    throw new HttpError("unauthorized", "invalid_jwt", "not a JWT");
  }
  const provider = providers.find((p) => p.type === "oidc" && p.issuer === iss);
  if (!provider) throw new HttpError("unauthorized", "unknown_issuer", String(iss).slice(0, 200));
  return provider;
}

/**
 * Verifies an OIDC token from `provider`: signature against the issuer's keys (RS256), plus
 * `iss`, `aud`, `exp` and `nbf` with 30s of clock tolerance. The provider's and profiles'
 * claims are checked when a profile is picked.
 */
export async function verifyOidcToken(jwt: string, provider: Provider, keys?: JWTVerifyGetKey): Promise<Claims> {
  const getKey = keys ?? (await keysFor(provider));
  try {
    const { payload } = await jwtVerify(jwt, getKey, {
      issuer: provider.issuer as string,
      audience: provider.audience as string,
      algorithms: ["RS256"],
      clockTolerance: 30,
      requiredClaims: ["exp", "iat"],
    });
    return payload;
  } catch (err) {
    const code = (err as { code?: string }).code;
    // jose errors carry a code; anything else (network failure) means we couldn't fetch the JWKS.
    if (code === undefined || code === "ERR_JWKS_TIMEOUT") throw unavailable((err as Error).message);
    throw new HttpError("unauthorized", "invalid_jwt", code);
  }
}
