// The Worker entry point. policy.json is supplied at deploy time: the Terraform
// module uploads it as a text module next to broker.js, and a wrangler build
// bundles src/policy.json. The release build leaves the import external.
import { createBroker } from "./broker.js";
import policy from "./policy.json";

export type { Env } from "./broker.js";
export default createBroker(policy);
