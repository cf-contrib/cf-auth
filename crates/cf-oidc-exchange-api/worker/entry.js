// The Worker's entry module. worker-build's index.js is the Worker; this hands it
// the policy, a module beside it: Terraform uploads policy.json as text, and a
// wrangler build bundles it as JSON. The wasm reads it on its first request.
import policy from "./policy.json";

globalThis.CF_OIDC_EXCHANGE_API_POLICY = policy;

export { default } from "./index.js";
