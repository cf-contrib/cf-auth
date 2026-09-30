// @ts-check
// A stand-in for both the runner's OIDC endpoint and the broker.
// Used by the action tests, and run standalone by CI's clean-checkout smoke test:
//   node packages/cf-oidc-action/test/stub.js   (listens on $PORT, default 8787)
import { createServer } from "node:http";

export const REQUEST_TOKEN = "stub-request-token";
export const STUB_TOKEN = "stub-cloudflare-token";
export const STUB_TOKEN_ID = "stub-token-id";
export const STUB_ACCOUNT_ID = "0123456789abcdef0123456789abcdef";
export const STUB_BUCKET = {
  name: "org-terraform-state",
  access_key_id: "stub-r2-access-key-id",
  secret_access_key: "stub-r2-secret-access-key",
  session_token: "stub-r2-session-token",
  prefixes: ["github.com/example-org/app/"],
  endpoint: `https://${STUB_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  expires_on: "2026-09-28T12:15:00Z",
};
export const STUB_BUCKET_2 = {
  ...STUB_BUCKET,
  name: "org-artifacts",
  access_key_id: "stub-r2-access-key-id-2",
  secret_access_key: "stub-r2-secret-access-key-2",
  session_token: "stub-r2-session-token-2",
  prefixes: [],
};
/** A profile the stub answers as one with only buckets: no token, just STUB_BUCKET. */
export const STUB_R2_PROFILE = "smoke-r2";
/** A profile the stub answers as one with two buckets and no token. */
export const STUB_R2_PROFILE_2 = "smoke-r2-multi";

/**
 * @typedef {{ method: string, path: string, authorization?: string, body?: unknown }} Call
 * @param {{ port?: number, tokenStatus?: number, revokeStatus?: number, oidcStatuses?: number[], tokenFields?: Record<string, unknown> }} [options]
 *   `tokenFields` overrides fields of the 200 token response; `undefined` removes one.
 */
export function startStub({
  port = 0,
  tokenStatus = 200,
  revokeStatus = 204,
  oidcStatuses = [],
  tokenFields = {},
} = {}) {
  /** @type {Call[]} */
  const calls = [];
  const oidc = [...oidcStatuses];

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://stub");
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const body = raw ? JSON.parse(raw) : undefined;
    calls.push({ method: req.method ?? "", path: url.pathname, authorization: req.headers.authorization, body });

    /** @param {number} status @param {unknown} [json] */
    const send = (status, json) => {
      res.writeHead(status, json === undefined ? {} : { "content-type": "application/json" });
      res.end(json === undefined ? undefined : JSON.stringify(json));
    };

    if (req.method === "GET" && url.pathname === "/oidc") {
      const status = oidc.shift() ?? 200;
      if (status !== 200) return send(status, { message: "stub failure" });
      if (req.headers.authorization !== `bearer ${REQUEST_TOKEN}`) return send(401, { message: "bad request token" });
      return send(200, {
        value: `stub-jwt.${Buffer.from(url.searchParams.get("audience") ?? "").toString("base64url")}`,
      });
    }
    if (req.method === "POST" && url.pathname === "/v1/token") {
      if (!req.headers.authorization?.startsWith("Bearer stub-jwt.")) return send(401, { error: "unauthorized" });
      if (tokenStatus !== 200) return send(tokenStatus, { error: "forbidden" });
      const common = { account_id: STUB_ACCOUNT_ID, expires_on: "2026-09-28T12:15:00Z" };
      if (body?.profile === STUB_R2_PROFILE) {
        return send(200, { ...common, profile: STUB_R2_PROFILE, buckets: [STUB_BUCKET], ...tokenFields });
      }
      if (body?.profile === STUB_R2_PROFILE_2) {
        return send(200, {
          ...common,
          profile: STUB_R2_PROFILE_2,
          buckets: [STUB_BUCKET, STUB_BUCKET_2],
          ...tokenFields,
        });
      }
      return send(200, {
        token: STUB_TOKEN,
        token_id: STUB_TOKEN_ID,
        ...common,
        profile: body?.profile ?? "default",
        ...tokenFields,
      });
    }
    if (req.method === "POST" && url.pathname === "/v1/revoke") {
      return send(req.headers.authorization === `Bearer ${STUB_TOKEN}` ? revokeStatus : 401);
    }
    send(404, { error: "not_found" });
  });

  return new Promise(
    /** @param {(stub: { url: string, calls: Call[], close: () => Promise<void> }) => void} resolve */
    (resolve) => {
      server.listen(port, "127.0.0.1", () => {
        const address = /** @type {import("node:net").AddressInfo} */ (server.address());
        resolve({
          url: `http://127.0.0.1:${address.port}`,
          calls,
          close: () => new Promise((done) => server.close(() => done())),
        });
      });
    },
  );
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const stub = await startStub({ port: Number(process.env.PORT ?? 8787) });
  console.log(`stub listening on ${stub.url}`);
  process.on("SIGTERM", () => {
    for (const call of stub.calls) console.log(JSON.stringify({ ...call, authorization: undefined }));
    process.exit(0);
  });
}
