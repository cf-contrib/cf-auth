// @ts-check
// Runs main.js and post.js as the runner would: separate Node processes, with
// INPUT_*, GITHUB_ENV, GITHUB_STATE and the OIDC request variables set.
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { REQUEST_TOKEN, STUB_ACCOUNT_ID, STUB_TOKEN, STUB_TOKEN_ID, startStub } from "./stub.js";

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

  it("exports S3-compatible R2 credentials derived from the token when asked", async () => {
    stub = await startStub();
    const r = await action("main.js", {
      ...oidcEnv(stub.url),
      "INPUT_BROKER-URL": stub.url,
      "INPUT_R2-CREDENTIALS": "true",
    });

    const secret = createHash("sha256").update(STUB_TOKEN).digest("hex");
    expect(r.code).toBe(0);
    expect(r.env).toEqual({
      CLOUDFLARE_API_TOKEN: STUB_TOKEN,
      CLOUDFLARE_ACCOUNT_ID: STUB_ACCOUNT_ID,
      AWS_ACCESS_KEY_ID: STUB_TOKEN_ID,
      AWS_SECRET_ACCESS_KEY: secret,
      AWS_SESSION_TOKEN: "",
      AWS_SECURITY_TOKEN: "",
      AWS_ENDPOINT_URL_S3: `https://${STUB_ACCOUNT_ID}.r2.cloudflarestorage.com`,
      AWS_REGION: "auto",
      AWS_DEFAULT_REGION: "auto",
    });
    // The secret only ever appears in the mask command.
    const out = r.stdout.split("\n");
    expect(out.filter((l) => l.includes(secret))).toEqual([`::add-mask::${secret}`]);
  });

  it("rejects a non-boolean r2-credentials before minting", async () => {
    stub = await startStub();
    const r = await action("main.js", {
      ...oidcEnv(stub.url),
      "INPUT_BROKER-URL": stub.url,
      "INPUT_R2-CREDENTIALS": "yes",
    });
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("::error::Input r2-credentials must be true or false, got: yes");
    expect(stub.calls).toEqual([]);
    expect(r.env).toEqual({});
  });

  it.each(["token", "token_id", "account_id"])("fails clearly when the broker response lacks %s", async (field) => {
    stub = await startStub({ tokenFields: { [field]: undefined } });
    const r = await action("main.js", {
      ...oidcEnv(stub.url),
      "INPUT_BROKER-URL": stub.url,
      "INPUT_R2-CREDENTIALS": "true",
    });
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
