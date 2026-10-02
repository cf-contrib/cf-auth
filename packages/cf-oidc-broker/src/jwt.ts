import { createRemoteJWKSet, type JWTVerifyGetKey, jwtVerify } from "jose";
import { HttpError } from "./errors.js";
import type { Claims, Policy } from "./policy.js";

/** Per-isolate JWKS cache. `jose` refetches on an unknown `kid`. */
const jwks = new Map<string, JWTVerifyGetKey>();

function remoteKeys(issuer: string): JWTVerifyGetKey {
  let keys = jwks.get(issuer);
  if (!keys) {
    keys = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks`));
    jwks.set(issuer, keys);
  }
  return keys;
}

/**
 * Verifies a GitHub Actions OIDC token: signature against the issuer's JWKS, plus
 * `iss`, `aud`, `exp` and `nbf` with 30s of clock tolerance.
 */
export async function verifyGitHubJWT(
  jwt: string,
  github: Policy["github"],
  keys: JWTVerifyGetKey = remoteKeys(github.issuer),
): Promise<Claims> {
  try {
    const { payload } = await jwtVerify(jwt, keys, {
      issuer: github.issuer,
      audience: github.audience,
      algorithms: ["RS256"],
      clockTolerance: 30,
      requiredClaims: ["exp", "iat", "repository_owner_id"],
    });
    return payload;
  } catch (err) {
    const code = (err as { code?: string }).code;
    // jose errors carry a code; anything else (network failure) means we couldn't fetch the JWKS.
    if (code === undefined || code === "ERR_JWKS_TIMEOUT") {
      throw new HttpError("upstream_error", "jwks_unavailable", (err as Error).message);
    }
    throw new HttpError("unauthorized", "invalid_jwt", code);
  }
}
