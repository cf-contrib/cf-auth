import { createLocalJWKSet } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { HttpError } from "../src/errors.js";
import { bearer, verifyGitHubJWT } from "../src/jwt.js";
import { AUDIENCE, createIssuer, githubClaims, OWNER_ID } from "./helpers.js";

const github = { issuer: "https://token.actions.githubusercontent.com", audience: AUDIENCE, owner_id: OWNER_ID };

let issuer: Awaited<ReturnType<typeof createIssuer>>;
let keys: ReturnType<typeof createLocalJWKSet>;

beforeAll(async () => {
  issuer = await createIssuer(github.issuer);
  keys = createLocalJWKSet(issuer.jwks as Parameters<typeof createLocalJWKSet>[0]);
});

async function reason(jwt: string): Promise<string | undefined> {
  try {
    await verifyGitHubJWT(jwt, github, keys);
    return undefined;
  } catch (err) {
    return err instanceof HttpError ? `${err.reason}:${err.detail}` : String(err);
  }
}

describe("verifyGitHubJWT", () => {
  it("returns the claims of a valid token", async () => {
    const claims = await verifyGitHubJWT(await issuer.sign(), github, keys);
    expect(claims.repository).toBe("example-org/api");
    expect(claims.repository_owner_id).toBe(OWNER_ID);
  });

  it("rejects the wrong audience (e.g. a JWT requested for AWS)", async () => {
    expect(await reason(await issuer.sign(undefined, { audience: "sts.amazonaws.com" }))).toMatch(
      /invalid_jwt:ERR_JWT_CLAIM_VALIDATION_FAILED/,
    );
  });

  it("rejects GitHub's default audience", async () => {
    expect(await reason(await issuer.sign(undefined, { audience: "https://github.com/example-org" }))).toMatch(
      /invalid_jwt/,
    );
  });

  it("rejects the wrong issuer", async () => {
    expect(await reason(await issuer.sign(undefined, { issuer: "https://evil.example.com" }))).toMatch(/invalid_jwt/);
  });

  it("rejects an expired token beyond the clock tolerance", async () => {
    const past = Math.floor(Date.now() / 1000) - 120;
    expect(await reason(await issuer.sign(undefined, { expiresIn: past }))).toMatch(/invalid_jwt:ERR_JWT_EXPIRED/);
  });

  it("tolerates 30s of clock skew", async () => {
    const justExpired = Math.floor(Date.now() / 1000) - 10;
    expect(await reason(await issuer.sign(undefined, { expiresIn: justExpired }))).toBeUndefined();
  });

  it("rejects a token signed by another key", async () => {
    const other = await createIssuer(github.issuer);
    expect(await reason(await other.sign())).toMatch(/invalid_jwt/);
  });

  it("rejects a token without repository_owner_id", async () => {
    const { repository_owner_id: _, ...claims } = githubClaims();
    expect(await reason(await issuer.sign(claims))).toMatch(/invalid_jwt/);
  });

  it("rejects garbage", async () => {
    expect(await reason("not.a.jwt")).toMatch(/invalid_jwt/);
  });
});

describe("bearer", () => {
  const req = (authorization?: string) =>
    new Request("https://x", authorization ? { headers: { authorization } } : undefined);

  it("extracts the token", () => {
    expect(bearer(req("Bearer abc"))).toBe("abc");
    expect(bearer(req("bearer abc"))).toBe("abc");
  });

  it.each([undefined, "", "Basic abc", "Bearer", "Bearer a b"])("rejects %j", (header) => {
    expect(() => bearer(req(header))).toThrow(HttpError);
  });
});
