// @ts-check
// Runs main.js and post.js as the runner would: separate Node processes, with
// INPUT_*, GITHUB_ENV, GITHUB_STATE and the OIDC request variables set.
import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import {
  REQUEST_TOKEN,
  STUB_ACCOUNT_ID,
  STUB_BUCKET,
  STUB_BUCKET_2,
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
  const dir = mkdtempSync(join(tmpdir(), "cf-oidc-exchange-"));
  const files = { GITHUB_ENV: join(dir, "env"), GITHUB_STATE: join(dir, "state"), RUNNER_TEMP: join(dir, "temp") };
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
  return {
    code,
    stdout,
    env: parseCommandFile(files.GITHUB_ENV),
    state: parseCommandFile(files.GITHUB_STATE),
    /** Where main.js writes the R2 credentials file. */
    credentialsFile: join(files.RUNNER_TEMP, "cf-oidc", "credentials"),
  };
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
    const token = stub.calls.find((c) => c.path === "/oauth/token");
    // The OIDC token goes in the body, as an RFC 8693 subject token, not in a header.
    expect(token?.authorization).toBeUndefined();
    expect(token?.body).toEqual({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      // The audience is the broker's origin, without the trailing slash.
      subject_token: `stub-jwt.${Buffer.from(stub.url).toString("base64url")}`,
      subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
      profile: "workers-deploy",
      ttl: "10m",
    });
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
    expect(stub.calls.find((c) => c.path === "/oauth/token")?.body).toEqual({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: expect.stringMatching(/^stub-jwt\./),
      subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
    });
  });

  /** @param {typeof STUB_BUCKET} b */
  const profile = (b) =>
    `[${b.name}]\naws_access_key_id = ${b.access_key_id}\naws_secret_access_key = ${b.secret_access_key}\naws_session_token = ${b.session_token}\n`;
  const ARTIFACTS = STUB_BUCKET_2;

  /** What every response with buckets exports. @param {string} file */
  const bucketEnv = (file) => ({
    AWS_SHARED_CREDENTIALS_FILE: file,
    AWS_ENDPOINT_URL_S3: `https://${STUB_ACCOUNT_ID}.r2.cloudflarestorage.com`,
    AWS_REGION: "auto",
    AWS_DEFAULT_REGION: "auto",
  });
  /** What a single bucket also exports. */
  const SINGLE_ENV = {
    AWS_ACCESS_KEY_ID: STUB_BUCKET.access_key_id,
    AWS_SECRET_ACCESS_KEY: STUB_BUCKET.secret_access_key,
    AWS_SESSION_TOKEN: STUB_BUCKET.session_token,
    AWS_SECURITY_TOKEN: STUB_BUCKET.session_token,
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
      ...bucketEnv(r.credentialsFile),
      CLOUDFLARE_R2_BUCKETS: JSON.stringify({ "org-terraform-state": ["github.com/example-org/app/"] }),
      ...SINGLE_ENV,
      CLOUDFLARE_R2_PREFIX: "github.com/example-org/app/",
    });
    expect(r.state).toEqual({ credentials_file: r.credentialsFile, r2_expires_on: STUB_BUCKET.expires_on });
    expect(r.stdout).toContain(
      "cf-oidc: issued R2 credentials for bucket org-terraform-state under github.com/example-org/app/ as AWS profile org-terraform-state (profile smoke-r2, expires 2026-09-28T12:15:00Z)",
    );
    expect(r.stdout).not.toContain("minted token");
    // The secrets only ever appear in the mask commands.
    const out = r.stdout.split("\n");
    for (const secret of [STUB_BUCKET.secret_access_key, STUB_BUCKET.session_token]) {
      expect(out.filter((l) => l.includes(secret))).toEqual([`::add-mask::${secret}`]);
    }
  });

  it("also writes a single bucket's credentials as a named profile, readable only by the runner user", async () => {
    stub = await startStub({ tokenFields: { buckets: [STUB_BUCKET] } });
    const r = await action("main.js", { ...oidcEnv(stub.url), "INPUT_BROKER-URL": stub.url });
    expect(r.code).toBe(0);
    expect(readFileSync(r.credentialsFile, "utf8")).toBe(profile(STUB_BUCKET));
    expect(statSync(r.credentialsFile).mode & 0o777).toBe(0o600);
  });

  it("exports both for a profile with a token and buckets", async () => {
    stub = await startStub({ tokenFields: { buckets: [STUB_BUCKET] } });
    const r = await action("main.js", { ...oidcEnv(stub.url), "INPUT_BROKER-URL": stub.url });
    expect(r.code).toBe(0);
    expect(r.env).toMatchObject({
      CLOUDFLARE_API_TOKEN: STUB_TOKEN,
      CLOUDFLARE_ACCOUNT_ID: STUB_ACCOUNT_ID,
      ...bucketEnv(r.credentialsFile),
      ...SINGLE_ENV,
    });
    expect(r.state).toEqual({
      token: STUB_TOKEN,
      token_id: STUB_TOKEN_ID,
      credentials_file: r.credentialsFile,
      r2_expires_on: STUB_BUCKET.expires_on,
    });
  });

  it.each([[[]], [["a/", "b/"]]])("exports an empty CLOUDFLARE_R2_PREFIX for prefixes %j", async (prefixes) => {
    stub = await startStub({ tokenFields: { buckets: [{ ...STUB_BUCKET, prefixes }] } });
    const r = await action("main.js", { ...oidcEnv(stub.url), "INPUT_BROKER-URL": stub.url });
    expect(r.code).toBe(0);
    expect(r.env).toMatchObject({ ...SINGLE_ENV, CLOUDFLARE_R2_PREFIX: "" });
  });

  it("exports no AWS variables when the profile has no buckets", async () => {
    stub = await startStub();
    const r = await action("main.js", { ...oidcEnv(stub.url), "INPUT_BROKER-URL": stub.url });
    expect(Object.keys(r.env).some((k) => k.startsWith("AWS_") || k.startsWith("CLOUDFLARE_R2_"))).toBe(false);
    expect(existsSync(r.credentialsFile)).toBe(false);
  });

  it("exports several buckets as named profiles, with no default credentials", async () => {
    stub = await startStub({ tokenFields: { buckets: [STUB_BUCKET, ARTIFACTS] } });
    const r = await action("main.js", { ...oidcEnv(stub.url), "INPUT_BROKER-URL": stub.url });
    expect(r.code).toBe(0);
    expect(r.env).toEqual({
      CLOUDFLARE_API_TOKEN: STUB_TOKEN,
      CLOUDFLARE_ACCOUNT_ID: STUB_ACCOUNT_ID,
      ...bucketEnv(r.credentialsFile),
      CLOUDFLARE_R2_BUCKETS: JSON.stringify({
        "org-terraform-state": ["github.com/example-org/app/"],
        "org-artifacts": [],
      }),
      // Cleared, so a step that forgets its profile fails instead of using stale credentials.
      AWS_ACCESS_KEY_ID: "",
      AWS_SECRET_ACCESS_KEY: "",
      AWS_SESSION_TOKEN: "",
      AWS_SECURITY_TOKEN: "",
      CLOUDFLARE_R2_BUCKET: "",
      CLOUDFLARE_R2_PREFIX: "",
    });
    expect(readFileSync(r.credentialsFile, "utf8")).toBe(`${profile(STUB_BUCKET)}\n${profile(ARTIFACTS)}`);
    expect(r.stdout).toContain("as AWS profile org-artifacts");
    const out = r.stdout.split("\n");
    for (const secret of [ARTIFACTS.secret_access_key, ARTIFACTS.session_token]) {
      expect(out.filter((l) => l.includes(secret))).toEqual([`::add-mask::${secret}`]);
    }
  });

  it.each([
    ["a bucket name that isn't R2's", { ...STUB_BUCKET, name: "org]\n[default" }],
    ["a newline in a secret", { ...STUB_BUCKET, secret_access_key: "secret\naws_access_key_id = x" }],
  ])("refuses %s, before writing the credentials file", async (_, bucket) => {
    stub = await startStub({ tokenFields: { buckets: [bucket] } });
    const r = await action("main.js", { ...oidcEnv(stub.url), "INPUT_BROKER-URL": stub.url });
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("::error::cf-oidc broker returned an invalid response: malformed buckets.0");
    expect(existsSync(r.credentialsFile)).toBe(false);
    expect(r.env).toEqual({});
  });

  it.each([
    ["access_token", { access_token: undefined }],
    ["token_id", { token_id: undefined }],
    ["expires_at", { expires_at: undefined }],
    ["account_id", { account_id: undefined }],
    ["token and buckets", { access_token: undefined, token_id: undefined }],
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
    const r = await action("main.js", { "INPUT_BROKER-URL": "https://cf-oidc-exchange.example.com" });
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("::error::OIDC unavailable: add `permissions: id-token: write` to the job");
  });

  it("requires broker-url", async () => {
    const r = await action("main.js", {});
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("::error::Input required and not supplied: broker-url");
  });

  it("refuses plain-http brokers that aren't loopback", async () => {
    const r = await action("main.js", { "INPUT_BROKER-URL": "http://cf-oidc-exchange.example.com" });
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("broker-url must use https");
  });

  it("fails with a hint when the broker denies the request", async () => {
    stub = await startStub({ tokenStatus: 403 });
    const r = await action("main.js", { ...oidcEnv(stub.url), "INPUT_BROKER-URL": stub.url });
    expect(r.code).toBe(1);
    expect(r.stdout).toContain(
      "::error::cf-oidc broker returned 403 (forbidden: no profile matches the token): the policy doesn't allow this workflow",
    );
    expect(r.env).toEqual({});
    expect(r.state).toEqual({});
  });

  it("fails with a hint when the broker is older than the action", async () => {
    stub = await startStub({ tokenStatus: 404 });
    const r = await action("main.js", { ...oidcEnv(stub.url), "INPUT_BROKER-URL": stub.url });
    expect(r.code).toBe(1);
    expect(r.stdout).toContain(
      "::error::cf-oidc broker returned 404 (not_found: no route for POST /oauth/token): the broker doesn't serve /oauth/token",
    );
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
      // RFC 7009: the token in a form body, not a header.
      {
        method: "POST",
        path: "/oauth/revoke",
        authorization: undefined,
        body: { token: STUB_TOKEN, token_type_hint: "access_token" },
      },
    ]);
  });

  it("deletes the credentials file", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cf-oidc-exchange-"));
    const file = join(dir, "credentials");
    writeFileSync(file, "[org-terraform-state]\n");
    const r = await action("post.js", {
      "INPUT_BROKER-URL": "https://cf-oidc-exchange.example.com",
      STATE_credentials_file: file,
      STATE_r2_expires_on: STUB_BUCKET.expires_on,
    });
    expect(r.code).toBe(0);
    expect(existsSync(file)).toBe(false);
    expect(r.stdout).toContain(`cf-oidc: deleted ${file}`);
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
