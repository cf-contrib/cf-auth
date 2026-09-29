import { describe, expect, it } from "vitest";
import { HttpError } from "../src/errors.js";
import {
  clampTTL,
  DEFAULT_ISSUER,
  glob,
  loadPolicy,
  matches,
  type PolicyError,
  parseDuration,
  selectRule,
} from "../src/policy.js";
import { ACCOUNT_ID, githubClaims, OWNER_ID, testPolicy } from "./helpers.js";

const policy = () => testPolicy(DEFAULT_ISSUER);

/** Loads a policy and returns its issues, or [] if it's valid. */
function issues(input: unknown): string[] {
  try {
    loadPolicy(input);
    return [];
  } catch (err) {
    return (err as PolicyError).issues;
  }
}

function denial(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (err) {
    if (err instanceof HttpError) return err.reason;
    throw err;
  }
  return undefined;
}

describe("parseDuration", () => {
  it.each([
    ["30s", 30_000],
    ["15m", 900_000],
    ["1h", 3_600_000],
    ["1h30m", 5_400_000],
  ])("parses %s", (input, ms) => {
    expect(parseDuration(input)).toBe(ms);
  });

  it.each(["", "15", "m", "1d", "-5m", "1.5h", "15 m"])("rejects %j", (input) => {
    expect(parseDuration(input)).toBeUndefined();
  });
});

describe("glob", () => {
  it("matches exact strings without *", () => {
    expect(glob("refs/heads/main", "refs/heads/main")).toBe(true);
    expect(glob("refs/heads/main", "refs/heads/main2")).toBe(false);
  });

  it("lets * span any characters, including /", () => {
    expect(glob("example-org/*", "example-org/api")).toBe(true);
    expect(glob("refs/heads/release/*", "refs/heads/release/2026/09")).toBe(true);
    expect(glob("example-org/*", "other-org/api")).toBe(false);
  });

  it("treats regex metacharacters literally", () => {
    expect(glob("a.b*", "a.bc")).toBe(true);
    expect(glob("a.b*", "axbc")).toBe(false);
  });
});

describe("loadPolicy", () => {
  it("accepts the example policy and applies defaults", () => {
    const p = loadPolicy(JSON.stringify(policy()));
    expect(p.github.issuer).toBe(DEFAULT_ISSUER);
    const deploy = p.rules.find((r) => r.name === "workers-deploy");
    expect(deploy?.ttl).toBe(15 * 60_000);
    expect(deploy?.max_ttl).toBe(60 * 60_000);
    expect(deploy?.policies[0]?.effect).toBe("allow");
  });

  it("adds the owner pin to every rule", () => {
    for (const rule of loadPolicy(policy()).rules) {
      expect(rule.match.repository_owner_id).toBe(OWNER_ID);
    }
  });

  it("defaults the issuer to github.com", () => {
    const p = policy();
    const { issuer: _, ...github } = p.github;
    expect(loadPolicy({ ...p, github }).github.issuer).toBe(DEFAULT_ISSUER);
  });

  it("accepts unquoted numeric IDs from YAML", () => {
    const p = policy();
    p.github.owner_id = Number(OWNER_ID) as unknown as string;
    (p.rules[0] as { match: Record<string, unknown> }).match.repository_id = 200000002;
    const loaded = loadPolicy(p);
    expect(loaded.github.owner_id).toBe(OWNER_ID);
    expect(loaded.rules[0]?.match.repository_id).toBe("200000002");
  });

  it("rejects invalid JSON", () => {
    expect(issues("{")[0]).toMatch(/not valid JSON/);
  });

  it("rejects unknown keys", () => {
    expect(issues({ ...policy(), extra: true }).join()).toMatch(/extra/);
  });

  describe("guardrails", () => {
    it("1: requires github.owner_id", () => {
      const p = policy();
      const { owner_id: _, ...github } = p.github;
      expect(issues({ ...p, github }).join()).toMatch(/owner_id/);
    });

    it("1: rejects a non-numeric owner_id", () => {
      const p = policy();
      p.github.owner_id = "example-org";
      expect(issues(p).join()).toMatch(/owner_id: must be a numeric ID/);
    });

    it("1: rejects a rule that overrides the owner pin", () => {
      const p = policy();
      (p.rules[1]?.match as Record<string, string>).repository_owner_id = "999";
      expect(issues(p).join()).toMatch(/conflicts with github.owner_id/);
    });

    it("2: rejects globs on ID claims", () => {
      const p = policy();
      (p.rules[0]?.match as Record<string, string>).repository_id = "2000*";
      expect(issues(p).join()).toMatch(/repository_id: ID claims must be exact/);
    });

    it.each(["API Tokens Write", "Account API Tokens Write", "API Tokens Read"])(
      "3: rejects granting %s",
      (permission) => {
        const p = policy();
        p.rules[1]?.token.policies[0]?.permissions.push(permission);
        expect(issues(p).join()).toMatch(/not grantable/);
      },
    );

    it("3: allows denying token-management permissions", () => {
      const p = policy();
      p.rules[1]?.token.policies.push({
        effect: "deny",
        permissions: ["API Tokens Write"],
        resources: { [`com.cloudflare.api.account.${ACCOUNT_ID}`]: "*" },
      });
      expect(issues(p)).toEqual([]);
    });

    it("4: caps max_ttl at 24h", () => {
      const p = policy();
      (p.rules[1]?.token as Record<string, unknown>).max_ttl = "25h";
      expect(issues(p).join()).toMatch(/max_ttl: must be at most 24h/);
    });

    it("4: rejects ttl above max_ttl", () => {
      const p = policy();
      p.defaults = { ttl: "2h", max_ttl: "1h" };
      expect(issues(p).join()).toMatch(/defaults.ttl: must not exceed max_ttl/);
    });

    it("4: rejects a rule ttl above the default max_ttl", () => {
      const p = policy();
      (p.rules[1]?.token as Record<string, unknown>).ttl = "2h";
      expect(issues(p).join()).toMatch(/ttl: must not exceed max_ttl/);
    });

    it("5: requires an audience", () => {
      const p = policy();
      const { audience: _, ...github } = p.github;
      expect(issues({ ...p, github }).join()).toMatch(/audience/);
    });

    it.each(["https://github.com/example-org", "https://github.com"])("5: rejects GitHub's audience %s", (aud) => {
      const p = policy();
      p.github.audience = aud;
      expect(issues(p).join()).toMatch(/must be a bare origin|default audience/);
    });

    it("5: requires the audience to be a bare origin", () => {
      const p = policy();
      p.github.audience = "https://cf-auth.example.com/";
      expect(issues(p).join()).toMatch(/bare origin/);
    });
  });

  it("rejects duplicate rule names", () => {
    const p = policy();
    p.rules.push({ ...(p.rules[1] as (typeof p.rules)[number]) });
    expect(issues(p).join()).toMatch(/duplicate rule name/);
  });

  describe("resources", () => {
    const withResources = (resources: Record<string, unknown>) => {
      const p = policy();
      (p.rules[1]?.token.policies[0] as { resources: unknown }).resources = resources;
      return p;
    };

    it("accepts Cloudflare's flat and nested forms", () => {
      expect(
        issues(withResources({ "com.cloudflare.api.account.zone.fedcba9876543210fedcba9876543210": "*" })),
      ).toEqual([]);
      expect(
        issues(
          withResources({ [`com.cloudflare.api.account.${ACCOUNT_ID}`]: { "com.cloudflare.api.account.zone.*": "*" } }),
        ),
      ).toEqual([]);
    });

    it("rejects an empty resources map", () => {
      expect(issues(withResources({})).join()).toMatch(/must name at least one resource/);
    });

    it("rejects keys that aren't Cloudflare resource names", () => {
      expect(issues(withResources({ "example.com": "*" })).join()).toMatch(/must be a Cloudflare resource name/);
    });

    it("rejects another account's ID when the broker's account is known", () => {
      const other = withResources({ "com.cloudflare.api.account.ffffffffffffffffffffffffffffffff": "*" });
      expect(issues(other)).toEqual([]);
      try {
        loadPolicy(other, ACCOUNT_ID);
        expect.unreachable();
      } catch (err) {
        expect((err as PolicyError).issues.join()).toMatch(/is not the broker's account/);
      }
      expect(() => loadPolicy(policy(), ACCOUNT_ID)).not.toThrow();
    });
  });

  it("reports every problem at once", () => {
    const p = policy();
    p.defaults = { ttl: "2h", max_ttl: "30h" };
    (p.rules[0]?.match as Record<string, string>).repository_id = "*";
    expect(issues(p).length).toBeGreaterThanOrEqual(3);
  });
});

describe("matching", () => {
  const loaded = loadPolicy(policy());
  const rule = (name: string) => loaded.rules.find((r) => r.name === name) as (typeof loaded.rules)[number];

  it("ANDs every match key", () => {
    expect(matches(rule("workers-deploy"), githubClaims())).toBe(true);
    expect(matches(rule("workers-deploy"), githubClaims({ environment: "staging" }))).toBe(false);
  });

  it("requires the owner pin", () => {
    expect(matches(rule("workers-deploy"), githubClaims({ repository_owner_id: "999" }))).toBe(false);
  });

  it("fails when a matched claim is missing", () => {
    const { environment: _, ...claims } = githubClaims();
    expect(matches(rule("workers-deploy"), claims)).toBe(false);
  });

  it("compares ID claims exactly", () => {
    expect(matches(rule("infra-cloudflare"), githubClaims({ repository_id: "200000002" }))).toBe(true);
    expect(matches(rule("infra-cloudflare"), githubClaims({ repository_id: "2000000021" }))).toBe(false);
  });

  it("selects the single matching rule", () => {
    expect(selectRule(loaded, githubClaims()).name).toBe("workers-deploy");
  });

  it("denies when nothing matches", () => {
    expect(denial(() => selectRule(loaded, githubClaims({ ref: "refs/heads/dev" })))).toBe("no_match");
  });

  it("denies when several rules match and none is named", () => {
    const claims = githubClaims({ repository: "example-org/infra", repository_id: "200000002" });
    expect(denial(() => selectRule(loaded, claims))).toBe("ambiguous");
    expect(selectRule(loaded, claims, "infra-cloudflare").name).toBe("infra-cloudflare");
  });

  it("denies a named rule that doesn't match", () => {
    expect(denial(() => selectRule(loaded, githubClaims(), "infra-cloudflare"))).toBe("rule_mismatch");
    expect(denial(() => selectRule(loaded, githubClaims(), "nope"))).toBe("rule_mismatch");
  });

  it("clamps ttl to max_ttl and rejects nonsense", () => {
    const r = rule("workers-deploy");
    expect(clampTTL(undefined, r)).toBe(15 * 60_000);
    expect(clampTTL("5m", r)).toBe(5 * 60_000);
    expect(clampTTL("10h", r)).toBe(60 * 60_000);
    expect(denial(() => clampTTL("forever", r))).toBe("invalid_ttl");
    expect(denial(() => clampTTL("30s", r))).toBe("invalid_ttl");
  });
});
