// @ts-check
// Runs main.js and post.js as the runner would: separate Node processes, with
// INPUT_*, GITHUB_ENV, GITHUB_STATE and the OIDC request variables set.
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import {
  REQUEST_TOKEN,
  STUB_ACCOUNT_ID,
  STUB_BUCKET,
  STUB_R2_PROFILE,
  STUB_TOKEN,
  STUB_TOKEN_ID,
  startStub,
} from "./stub.js";

const run = promisify(execFile);
const SRC = new URL("../src/", import.meta.url);

/** @type {Awaited<ReturnType<typeof startStub>> | undefined} */
let stub;
afterEach(async () => {
  await stub?.close();
  stub = undefined;
});

/** Parses the `KEY<<DELIM\nvalue\nDELIM` format of GITHUB_ENV / GITHUB_STATE. @param {string} path */
function parseCommandFile(path) {
  /** @type {Record<string, string>} */
  const out = {};
  const lines = readFileSync(path, "utf8").split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = /^([^<]+)<<(.+)$/.exec(lines[i] ?? "");
    if (!m) continue;
    const [, key, eof] = m;
    const value = [];
    while (lines[++i] !== eof) value.push(lines[i]);
    out[/** @type {string} */ (key)] = value.join("\n");
  }
  return out;
}

/**
 * @param {"main.js" | "post.js"} script
 * @param {Record<string, string | undefined>} env
 */
async function action(script, env) {
  const dir = mkdtempSync(join(tmpdir(), "cf-auth-"));
  const files = { GITHUB_ENV: join(dir, "env"), GITHUB_STATE: join(dir, "state") };
  writeFileSync(files.GITHUB_ENV, "");
  writeFileSync(files.GITHUB_STATE, "");
  /** @type {Record<string, string>} */
  const clean = {};
  for (const [k, v] of Object.entries({ PATH: process.env.PATH, ...files, ...env })) if (v !== undefined) clean[k] = v;

  let stdout = "";
  let code = 0;
  try {
    ({ stdout } = await run(process.execPath, [new URL(script, SRC).pathname], { env: clean }));
  } catch (err) {
    const e = /** @type {{ stdout: string, code: number }} */ (err);
    stdout = e.stdout;
    code = e.code;
  }
  return { code, stdout, env: parseCommandFile(files.GITHUB_ENV), state: parseCommandFile(files.GITHUB_STATE) };
}

/** @param {string} url */
const oidcEnv = (url) => ({
  ACTIONS_ID_TOKEN_REQUEST_URL: `${url}/oidc?api-version=2.0`,
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: REQUEST_TOKEN,
});

describe("main", () => {
  it("mints a token, masks it and exports it", async () => {
    stub = await startStub();
    const r = await action("main.js", {
      ...oidcEnv(stub.url),
      "INPUT_BROKER-URL": `${stub.url}/`,
      INPUT_PROFILE: "workers-deploy",
      INPUT_TTL: " 10m ",
    });

    expect(r.code).toBe(0);
    expect(r.env).toEqual({ CLOUDFLARE_API_TOKEN: STUB_TOKEN, CLOUDFLARE_ACCOUNT_ID: STUB_ACCOUNT_ID });
    expect(r.state).toEqual({ token: STUB_TOKEN, token_id: STUB_TOKEN_ID });

    const out = r.stdout.split("\n");
    const maskAt = out.indexOf(`::add-mask::${STUB_TOKEN}`);
    expect(maskAt).toBeGreaterThanOrEqual(0);
    expect(out.some((l) => l.startsWith("::add-mask::stub-jwt."))).toBe(true);
    expect(r.stdout).toContain(
      `cf-oidc: minted token ${STUB_TOKEN_ID} (profile workers-deploy, expires 2026-09-28T12:15:00Z)`,
    );
    // The token value itself only ever appears in the mask command.
    expect(out.filter((l) => l.includes(STUB_TOKEN)).length).toBe(1);

    const oidc = stub.calls.find((c) => c.path === "/oidc");
    expect(oidc).toBeDefined();
    const token = stub.calls.find((c) => c.path === "/v1/token");
    // The audience is the broker's origin, without the trailing slash.
    expect(token?.authorization).toBe(`Bearer stub-jwt.${Buffer.from(stub.url).toString("base64url")}`);
    expect(token?.body).toEqual({ profile: "workers-deploy", ttl: "10m" });
  });

  it("omits profile and ttl when not given", async () => {
    stub = await startStub();
    const r = await action("main.js", {
      ...oidcEnv(stub.url),
      "INPUT_BROKER-URL": stub.url,
      INPUT_PROFILE: "",
      INPUT_TTL: "",
    });
    expect(r.code).toBe(0);
    expect(stub.calls.find((c) => c.path === "/v1/token")?.body).toEqual({});
  });

  const R2_ENV = {
    AWS_ACCESS_KEY_ID: STUB_BUCKET.access_key_id,
    AWS_SECRET_ACCESS_KEY: STUB_BUCKET.secret_access_key,
    AWS_SESSION_TOKEN: STUB_BUCKET.session_token,
    AWS_SECURITY_TOKEN: STUB_BUCKET.session_token,
    AWS_ENDPOINT_URL_S3: `https://${STUB_ACCOUNT_ID}.r2.cloudflarestorage.com`,
    AWS_REGION: "auto",
    AWS_DEFAULT_REGION: "auto",
    CLOUDFLARE_R2_BUCKET: STUB_BUCKET.name,
  };

  it("exports R2 credentials, and no API token, for a profile with only buckets", async () => {
    stub = await startStub();
    const r = await action("main.js", {
      ...oidcEnv(stub.url),
      "INPUT_BROKER-URL": stub.url,
      INPUT_PROFILE: STUB_R2_PROFILE,
    });

    expect(r.code).toBe(0);
    expect(r.env).toEqual({
      CLOUDFLARE_ACCOUNT_ID: STUB_ACCOUNT_ID,
      ...R2_ENV,
      CLOUDFLARE_R2_PREFIX: "github.com/example-org/app/",
    });
    expect(r.state).toEqual({ r2_expires_on: STUB_BUCKET.expires_on });
    expect(r.stdout).toContain(
      "cf-oidc: issued R2 credentials for bucket org-terraform-state under github.com/example-org/app/ (profile smoke-r2, expires 2026-09-28T12:15:00Z)",
    );
    expect(r.stdout).not.toContain("minted token");
    // The secrets only ever appear in the mask commands.
    const out = r.stdout.split("\n");
    for (const secret of [STUB_BUCKET.secret_access_key, STUB_BUCKET.session_token]) {
      expect(out.filter((l) => l.includes(secret))).toEqual([`::add-mask::${secret}`]);
    }
  });

  it("exports both for a profile with a token and buckets", async () => {
    stub = await startStub({ tokenFields: { buckets: [STUB_BUCKET] } });
    const r = await action("main.js", { ...oidcEnv(stub.url), "INPUT_BROKER-URL": stub.url });
    expect(r.code).toBe(0);
    expect(r.env).toEqual({
      CLOUDFLARE_API_TOKEN: STUB_TOKEN,
      CLOUDFLARE_ACCOUNT_ID: STUB_ACCOUNT_ID,
      ...R2_ENV,
      CLOUDFLARE_R2_PREFIX: "github.com/example-org/app/",
    });
    expect(r.state).toEqual({ token: STUB_TOKEN, token_id: STUB_TOKEN_ID, r2_expires_on: STUB_BUCKET.expires_on });
  });

  it.each([[[]], [["a/", "b/"]]])("exports no CLOUDFLARE_R2_PREFIX for prefixes %j", async (prefixes) => {
    stub = await startStub({ tokenFields: { buckets: [{ ...STUB_BUCKET, prefixes }] } });
    const r = await action("main.js", { ...oidcEnv(stub.url), "INPUT_BROKER-URL": stub.url });
    expect(r.code).toBe(0);
    expect(r.env).toMatchObject(R2_ENV);
    expect(r.env).not.toHaveProperty("CLOUDFLARE_R2_PREFIX");
  });

  it("exports no AWS variables when the profile has no buckets", async () => {
    stub = await startStub();
    const r = await action("main.js", { ...oidcEnv(stub.url), "INPUT_BROKER-URL": stub.url });
    expect(Object.keys(r.env).some((k) => k.startsWith("AWS_") || k.startsWith("CLOUDFLARE_R2_"))).toBe(false);
  });

  it("fails before exporting anything when the profile has several buckets", async () => {
    stub = await startStub({ tokenFields: { buckets: [STUB_BUCKET, { ...STUB_BUCKET, name: "org-artifacts" }] } });
    const r = await action("main.js", { ...oidcEnv(stub.url), "INPUT_BROKER-URL": stub.url });
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("::error::profile default has 2 buckets; this version of the action exports one");
    expect(r.env).toEqual({});
    expect(r.state).toEqual({});
  });

  it.each([
    ["token", { token: undefined }],
    ["token_id", { token_id: undefined }],
    ["account_id", { account_id: undefined }],
    ["token and buckets", { token: undefined, token_id: undefined }],
    ["buckets.0.name", { buckets: [{ ...STUB_BUCKET, name: undefined }] }],
    ["buckets.0.session_token", { buckets: [{ ...STUB_BUCKET, session_token: undefined }] }],
    ["buckets.0.secret_access_key", { buckets: [{ ...STUB_BUCKET, secret_access_key: "" }] }],
    ["buckets.0.prefixes", { buckets: [{ ...STUB_BUCKET, prefixes: undefined }] }],
  ])("fails clearly when the broker response lacks %s", async (field, tokenFields) => {
    stub = await startStub({ tokenFields });
    const r = await action("main.js", { ...oidcEnv(stub.url), "INPUT_BROKER-URL": stub.url });
    expect(r.code).toBe(1);
    expect(r.stdout).toContain(`::error::cf-oidc broker returned an invalid response: missing ${field}`);
    expect(r.env).toEqual({});
    expect(r.state).toEqual({});
  });

  it("explains a missing id-token permission", async () => {
    const r = await action("main.js", { "INPUT_BROKER-URL": "https://cf-auth.example.com" });
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("::error::OIDC unavailable: add `permissions: id-token: write` to the job");
  });

  it("requires broker-url", async () => {
    const r = await action("main.js", {});
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("::error::Input required and not supplied: broker-url");
  });

  it("refuses plain-http brokers that aren't loopback", async () => {
    const r = await action("main.js", { "INPUT_BROKER-URL": "http://cf-auth.example.com" });
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("broker-url must use https");
  });

  it("fails with a hint when the broker denies the request", async () => {
    stub = await startStub({ tokenStatus: 403 });
    const r = await action("main.js", { ...oidcEnv(stub.url), "INPUT_BROKER-URL": stub.url });
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("::error::cf-oidc broker returned 403 (forbidden): no profile allows this workflow");
    expect(r.env).toEqual({});
    expect(r.state).toEqual({});
  });

  it("retries a flaky OIDC endpoint", async () => {
    stub = await startStub({ oidcStatuses: [503] });
    const r = await action("main.js", { ...oidcEnv(stub.url), "INPUT_BROKER-URL": stub.url });
    expect(r.code).toBe(0);
    expect(stub.calls.filter((c) => c.path === "/oidc").length).toBe(2);
  });
});

describe("post", () => {
  it("revokes the minted token", async () => {
    stub = await startStub();
    const r = await action("post.js", {
      "INPUT_BROKER-URL": stub.url,
      STATE_token: STUB_TOKEN,
      STATE_token_id: STUB_TOKEN_ID,
    });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain(`cf-oidc: revoked token ${STUB_TOKEN_ID}`);
    expect(stub.calls).toEqual([
      { method: "POST", path: "/v1/revoke", authorization: `Bearer ${STUB_TOKEN}`, body: undefined },
    ]);
  });

  it("only logs when the R2 credentials expire for a profile with only buckets", async () => {
    stub = await startStub();
    const r = await action("post.js", { "INPUT_BROKER-URL": stub.url, STATE_r2_expires_on: STUB_BUCKET.expires_on });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain(
      "cf-oidc: R2 temporary credentials can't be revoked; they expire at 2026-09-28T12:15:00Z",
    );
    expect(stub.calls).toEqual([]);
  });

  it("logs the R2 expiry and revokes the token for a profile with both", async () => {
    stub = await startStub();
    const r = await action("post.js", {
      "INPUT_BROKER-URL": stub.url,
      STATE_token: STUB_TOKEN,
      STATE_token_id: STUB_TOKEN_ID,
      STATE_r2_expires_on: STUB_BUCKET.expires_on,
    });
    expect(r.stdout).toContain("they expire at 2026-09-28T12:15:00Z");
    expect(r.stdout).toContain(`cf-oidc: revoked token ${STUB_TOKEN_ID}`);
  });

  it("does nothing when main didn't mint", async () => {
    stub = await startStub();
    const r = await action("post.js", { "INPUT_BROKER-URL": stub.url });
    expect(r.code).toBe(0);
    expect(stub.calls).toEqual([]);
  });

  it("warns instead of failing when revocation fails", async () => {
    stub = await startStub({ revokeStatus: 502 });
    const r = await action("post.js", {
      "INPUT_BROKER-URL": stub.url,
      STATE_token: STUB_TOKEN,
      STATE_token_id: STUB_TOKEN_ID,
    });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("::warning::cf-oidc: revoking token stub-token-id returned 502; it expires on its own");
  });

  it("warns instead of failing when the broker is unreachable", async () => {
    const r = await action("post.js", { "INPUT_BROKER-URL": "http://127.0.0.1:9", STATE_token: STUB_TOKEN });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("::warning::cf-oidc: revoking token");
  });
});
