// @ts-check
// A stand-in for both the runner's OIDC endpoint and the cf-auth broker.
// Used by the action tests, and run standalone by CI's clean-checkout smoke test:
//   node packages/cf-oidc-action/test/stub.js   (listens on $PORT, default 8787)
import { createServer } from "node:http";

export const REQUEST_TOKEN = "stub-request-token";
export const STUB_TOKEN = "stub-cloudflare-token";
export const STUB_TOKEN_ID = "stub-token-id";
export const STUB_ACCOUNT_ID = "0123456789abcdef0123456789abcdef";

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
      return send(200, {
        token: STUB_TOKEN,
        token_id: STUB_TOKEN_ID,
        account_id: STUB_ACCOUNT_ID,
        expires_on: "2026-09-28T12:15:00Z",
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
