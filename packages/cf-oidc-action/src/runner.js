// @ts-check
// A small replacement for @actions/core: inputs, env, state, masking and OIDC.
// Node built-ins only. This file runs straight from the git checkout of the tag.

import { randomUUID } from "node:crypto";
import { appendFileSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";

/** @param {string} name */
export const input = (name) => process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`]?.trim() ?? "";

/**
 * Reads a boolean input the way @actions/core does: `true`/`True`/`TRUE` or
 * `false`/`False`/`FALSE`. Unset counts as false.
 * @param {string} name
 */
export function booleanInput(name) {
  const value = input(name);
  if (["true", "True", "TRUE"].includes(value)) return true;
  if (["", "false", "False", "FALSE"].includes(value)) return false;
  throw new Error(`Input ${name} must be true or false, got: ${value}`);
}

/** @param {string} name */
export const state = (name) => process.env[`STATE_${name}`] ?? "";

/** @param {string} value */
export const mask = (value) => console.log(`::add-mask::${value}`);

/** @param {string} message */
const escapeData = (message) => message.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");

/** @param {string} message */
export const warning = (message) => console.log(`::warning::${escapeData(message)}`);

/** Reports an error as a workflow annotation and fails the step. @param {unknown} err */
export function fail(err) {
  console.log(`::error::${escapeData(err instanceof Error ? err.message : String(err))}`);
  process.exitCode = 1;
}

/** @param {"GITHUB_ENV" | "GITHUB_STATE"} file @param {string} key @param {string} value */
export const write = (file, key, value) => {
  const path = process.env[file];
  if (!path) throw new Error(`${file} is not set; is this running in GitHub Actions?`);
  const eof = `EOF_${randomUUID()}`;
  appendFileSync(path, `${key}<<${eof}\n${value}\n${eof}\n`);
};

/**
 * Parses the `broker-url` input. HTTPS is required, except for loopback hosts
 * (used by the smoke test), because the OIDC token travels in the request.
 * @param {string} value
 */
export function brokerURL(value) {
  if (!value) throw new Error("Input required and not supplied: broker-url");
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`broker-url is not a valid URL: ${value}`);
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new Error(`broker-url must use https: ${value}`);
  }
  return url;
}

/**
 * Requests a GitHub OIDC JWT. Retries network errors and 5xx responses,
 * because the runner's token endpoint occasionally has brief failures.
 * @param {string} audience
 * @param {{ attempts?: number, delay?: number }} [options]
 */
export async function idToken(audience, { attempts = 3, delay = 500 } = {}) {
  const { ACTIONS_ID_TOKEN_REQUEST_URL: url, ACTIONS_ID_TOKEN_REQUEST_TOKEN: bearer } = process.env;
  if (!url || !bearer) throw new Error("OIDC unavailable: add `permissions: id-token: write` to the job");

  const req = new URL(url);
  req.searchParams.set("audience", audience);

  for (let i = 1; ; i++) {
    /** @type {Response} */
    let response;
    try {
      response = await fetch(req, {
        headers: { authorization: `bearer ${bearer}` },
        signal: AbortSignal.timeout(30_000),
      });
    } catch (err) {
      if (i >= attempts) throw err;
      await sleep(delay * 2 ** (i - 1));
      continue;
    }
    if (response.ok) {
      const { value } = /** @type {{ value?: string }} */ (await response.json());
      if (!value) throw new Error("OIDC token response had no value");
      return value;
    }
    if (response.status < 500 || i >= attempts) throw new Error(`OIDC token request failed: ${response.status}`);
    await sleep(delay * 2 ** (i - 1));
  }
}
