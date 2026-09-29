// @ts-check
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { booleanInput, brokerURL, idToken, input, write } from "../src/runner.js";

beforeEach(() => {
  vi.stubEnv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://runner.example.com/token?api-version=2.0");
  vi.stubEnv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token");
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

/** @param {Array<number | Error>} outcomes */
function stubFetch(outcomes) {
  const fetch = vi.fn(async (/** @type {URL} */ _url, /** @type {RequestInit} */ _init) => {
    const next = outcomes.shift();
    if (next instanceof Error) throw next;
    return new Response(next === 200 ? JSON.stringify({ value: "jwt" }) : "{}", { status: next });
  });
  vi.stubGlobal("fetch", fetch);
  return fetch;
}

describe("idToken", () => {
  it("requests the given audience with the runner's bearer token", async () => {
    const fetch = stubFetch([200]);
    expect(await idToken("https://cf-auth.example.com")).toBe("jwt");
    const [url, init] = /** @type {[URL, RequestInit]} */ (fetch.mock.calls[0]);
    expect(url.searchParams.get("audience")).toBe("https://cf-auth.example.com");
    expect(url.searchParams.get("api-version")).toBe("2.0");
    expect(init.headers).toEqual({ authorization: "bearer request-token" });
  });

  it("retries 5xx and network errors", async () => {
    const fetch = stubFetch([500, new TypeError("fetch failed"), 200]);
    expect(await idToken("aud", { delay: 1 })).toBe("jwt");
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  it("gives up after the last attempt", async () => {
    stubFetch([502, 502, 502]);
    await expect(idToken("aud", { delay: 1 })).rejects.toThrow("OIDC token request failed: 502");
  });

  it("doesn't retry 4xx", async () => {
    const fetch = stubFetch([403, 200]);
    await expect(idToken("aud", { delay: 1 })).rejects.toThrow("OIDC token request failed: 403");
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("explains a missing id-token permission", async () => {
    vi.stubEnv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "");
    await expect(idToken("aud")).rejects.toThrow("permissions: id-token: write");
  });
});

describe("input", () => {
  it("reads and trims INPUT_* like @actions/core", () => {
    vi.stubEnv("INPUT_BROKER-URL", "  https://x.example.com \n");
    expect(input("broker-url")).toBe("https://x.example.com");
    expect(input("missing")).toBe("");
  });
});

describe("booleanInput", () => {
  it("accepts the YAML 1.2 core booleans like @actions/core", () => {
    for (const value of ["true", "True", "TRUE", " true "]) {
      vi.stubEnv("INPUT_FLAG", value);
      expect(booleanInput("flag")).toBe(true);
    }
    for (const value of ["false", "False", "FALSE", ""]) {
      vi.stubEnv("INPUT_FLAG", value);
      expect(booleanInput("flag")).toBe(false);
    }
    expect(booleanInput("missing")).toBe(false);
  });

  it("rejects anything else", () => {
    vi.stubEnv("INPUT_FLAG", "yes");
    expect(() => booleanInput("flag")).toThrow("Input flag must be true or false, got: yes");
  });
});

describe("write", () => {
  it("appends a heredoc with a random delimiter", () => {
    const file = join(mkdtempSync(join(tmpdir(), "cf-auth-")), "env");
    vi.stubEnv("GITHUB_ENV", file);
    write("GITHUB_ENV", "A", "one\ntwo");
    write("GITHUB_ENV", "B", "three");
    const text = readFileSync(file, "utf8");
    expect(text).toMatch(/^A<<(EOF_[0-9a-f-]{36})\none\ntwo\n\1\nB<<(EOF_[0-9a-f-]{36})\nthree\n\2\n$/);
  });
});

describe("brokerURL", () => {
  it.each(["https://cf-auth.example.com", "http://localhost:8787", "http://127.0.0.1:8787"])("accepts %s", (url) => {
    expect(brokerURL(url).href).toContain(new URL(url).host);
  });

  it.each(["", "not a url", "http://cf-auth.example.com", "ftp://cf-auth.example.com"])("rejects %j", (url) => {
    expect(() => brokerURL(url)).toThrow();
  });
});
