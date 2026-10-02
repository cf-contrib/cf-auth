import { createLocalJWKSet } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { HttpError } from "../src/errors.js";
import { providerFor, verifyOidcToken } from "../src/jwt.js";
import type { Provider } from "../src/policy.js";
import { AUDIENCE, createIssuer, OWNER_ID } from "./helpers.js";

const github: Provider = {
  name: "github",
  type: "oidc",
  issuer: "https://token.actions.githubusercontent.com",
  audience: AUDIENCE,
  claims: { repository_owner_id: OWNER_ID },
};

let issuer: Awaited<ReturnType<typeof createIssuer>>;
let keys: ReturnType<typeof createLocalJWKSet>;

beforeAll(async () => {
  issuer = await createIssuer(github.issuer as string);
  keys = createLocalJWKSet(issuer.jwks as Parameters<typeof createLocalJWKSet>[0]);
});

/** The `reason:detail` a failure is audited with, or undefined when it succeeds. */
async function reason(fn: () => unknown): Promise<string | undefined> {
  try {
    await fn();
    return undefined;
  } catch (err) {
    return err instanceof HttpError ? `${err.reason}:${err.detail}` : String(err);
  }
}

const verify = (jwt: string) => reason(() => verifyOidcToken(jwt, github, keys));

describe("verifyOidcToken", () => {
  it("returns the claims of a valid token", async () => {
    const claims = await verifyOidcToken(await issuer.sign(), github, keys);
    expect(claims.repository).toBe("example-org/api");
    expect(claims.repository_owner_id).toBe(OWNER_ID);
  });

  it("rejects the wrong audience (e.g. a JWT requested for AWS)", async () => {
    expect(await verify(await issuer.sign(undefined, { audience: "sts.amazonaws.com" }))).toMatch(
      /invalid_jwt:ERR_JWT_CLAIM_VALIDATION_FAILED/,
    );
  });

  it("rejects GitHub's default audience", async () => {
    expect(await verify(await issuer.sign(undefined, { audience: "https://github.com/example-org" }))).toMatch(
      /invalid_jwt/,
    );
  });

  it("rejects the wrong issuer", async () => {
    expect(await verify(await issuer.sign(undefined, { issuer: "https://evil.example.com" }))).toMatch(/invalid_jwt/);
  });

  it("rejects an expired token beyond the clock tolerance", async () => {
    const past = Math.floor(Date.now() / 1000) - 120;
    expect(await verify(await issuer.sign(undefined, { expiresIn: past }))).toMatch(/invalid_jwt:ERR_JWT_EXPIRED/);
  });

  it("tolerates 30s of clock skew", async () => {
    const justExpired = Math.floor(Date.now() / 1000) - 10;
    expect(await verify(await issuer.sign(undefined, { expiresIn: justExpired }))).toBeUndefined();
  });

  it("rejects a token signed by another key", async () => {
    const other = await createIssuer(github.issuer as string);
    expect(await verify(await other.sign())).toMatch(/invalid_jwt/);
  });

  it("rejects garbage", async () => {
    expect(await verify("not.a.jwt")).toMatch(/invalid_jwt/);
  });
});

describe("providerFor", () => {
  const gitlab: Provider = {
    name: "gitlab",
    type: "oidc",
    issuer: "https://gitlab.com",
    audience: AUDIENCE,
    claims: {},
  };
  const people: Provider = { name: "people", type: "github-user", claims: { repository_owner_id: OWNER_ID } };

  it("picks the provider by the token's issuer", async () => {
    expect(providerFor(await issuer.sign(), [people, gitlab, github])).toBe(github);
  });

  it("refuses a token from an issuer no provider is for", async () => {
    const jwt = await issuer.sign(undefined, { issuer: "https://other.example.com" });
    expect(await reason(() => providerFor(jwt, [github, gitlab]))).toBe("unknown_issuer:https://other.example.com");
  });

  it("refuses something that isn't a JWT", async () => {
    expect(await reason(() => providerFor("gho_notAJwt", [github]))).toBe("invalid_jwt:not a JWT");
  });
});
