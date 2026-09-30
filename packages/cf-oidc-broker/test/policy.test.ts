import { describe, expect, it } from "vitest";
import { HttpError } from "../src/errors.js";
import {
  clampTTL,
  DEFAULT_ISSUER,
  glob,
  loadPolicy,
  matches,
  type PolicyError,
  type Profile,
  parseDuration,
  r2Prefixes,
  selectProfile,
} from "../src/policy.js";
import { ACCOUNT_ID, githubClaims, OWNER_ID, type TestPolicy, testPolicy } from "./helpers.js";

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
    const deploy = p.profiles.find((r) => r.name === "workers-deploy");
    expect(deploy?.ttl).toBe(15 * 60_000);
    expect(deploy?.max_ttl).toBe(60 * 60_000);
    expect(deploy?.policies?.[0]?.effect).toBe("allow");
  });

  it("adds the owner pin to every profile", () => {
    for (const profile of loadPolicy(policy()).profiles) {
      expect(profile.match.repository_owner_id).toBe(OWNER_ID);
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
    (p.profiles[0] as { match: Record<string, unknown> }).match.repository_id = 200000002;
    const loaded = loadPolicy(p);
    expect(loaded.github.owner_id).toBe(OWNER_ID);
    expect(loaded.profiles[0]?.match.repository_id).toBe("200000002");
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

    it("1: rejects a profile that overrides the owner pin", () => {
      const p = policy();
      (p.profiles[1]?.match as Record<string, string>).repository_owner_id = "999";
      expect(issues(p).join()).toMatch(/conflicts with github.owner_id/);
    });

    it("2: rejects globs on ID claims", () => {
      const p = policy();
      (p.profiles[0]?.match as Record<string, string>).repository_id = "2000*";
      expect(issues(p).join()).toMatch(/repository_id: ID claims must be exact/);
    });

    it.each(["API Tokens Write", "Account API Tokens Write", "API Tokens Read"])(
      "3: rejects granting %s",
      (permission) => {
        const p = policy();
        p.profiles[1]?.token.policies[0]?.permissions.push(permission);
        expect(issues(p).join()).toMatch(/not grantable/);
      },
    );

    it("3: allows denying token-management permissions", () => {
      const p = policy();
      p.profiles[1]?.token.policies.push({
        effect: "deny",
        permissions: ["API Tokens Write"],
        resources: { [`com.cloudflare.api.account.${ACCOUNT_ID}`]: "*" },
      });
      expect(issues(p)).toEqual([]);
    });

    it("4: caps max_ttl at 24h", () => {
      const p = policy();
      (p.profiles[1]?.token as Record<string, unknown>).max_ttl = "25h";
      expect(issues(p).join()).toMatch(/max_ttl: must be at most 24h/);
    });

    it("4: rejects ttl above max_ttl", () => {
      const p = policy();
      p.defaults = { ttl: "2h", max_ttl: "1h" };
      expect(issues(p).join()).toMatch(/defaults.ttl: must not exceed max_ttl/);
    });

    it("4: rejects a profile ttl above the default max_ttl", () => {
      const p = policy();
      (p.profiles[1]?.token as Record<string, unknown>).ttl = "2h";
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

  it("rejects duplicate profile names", () => {
    const p = policy();
    p.profiles.push({ ...(p.profiles[1] as (typeof p.profiles)[number]) });
    expect(issues(p).join()).toMatch(/duplicate profile name/);
  });

  describe("resources", () => {
    const withResources = (resources: Record<string, unknown>) => {
      const p = policy();
      (p.profiles[1]?.token.policies[0] as { resources: unknown }).resources = resources;
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
    (p.profiles[0]?.match as Record<string, string>).repository_id = "*";
    expect(issues(p).length).toBeGreaterThanOrEqual(3);
  });
});

describe("matching", () => {
  const loaded = loadPolicy(policy());
  const profile = (name: string) => loaded.profiles.find((r) => r.name === name) as (typeof loaded.profiles)[number];

  it("ANDs every match key", () => {
    expect(matches(profile("workers-deploy"), githubClaims())).toBe(true);
    expect(matches(profile("workers-deploy"), githubClaims({ environment: "staging" }))).toBe(false);
  });

  it("requires the owner pin", () => {
    expect(matches(profile("workers-deploy"), githubClaims({ repository_owner_id: "999" }))).toBe(false);
  });

  it("fails when a matched claim is missing", () => {
    const { environment: _, ...claims } = githubClaims();
    expect(matches(profile("workers-deploy"), claims)).toBe(false);
  });

  it("compares ID claims exactly", () => {
    expect(matches(profile("infra-cloudflare"), githubClaims({ repository_id: "200000002" }))).toBe(true);
    expect(matches(profile("infra-cloudflare"), githubClaims({ repository_id: "2000000021" }))).toBe(false);
  });

  it("selects the single matching profile", () => {
    expect(selectProfile(loaded, githubClaims()).name).toBe("workers-deploy");
  });

  it("denies when nothing matches", () => {
    expect(denial(() => selectProfile(loaded, githubClaims({ ref: "refs/heads/dev" })))).toBe("no_match");
  });

  it("denies when several profiles match and none is named", () => {
    const claims = githubClaims({ repository: "example-org/infra", repository_id: "200000002" });
    expect(denial(() => selectProfile(loaded, claims))).toBe("ambiguous");
    expect(selectProfile(loaded, claims, "infra-cloudflare").name).toBe("infra-cloudflare");
  });

  it("denies a named profile that doesn't match", () => {
    expect(denial(() => selectProfile(loaded, githubClaims(), "infra-cloudflare"))).toBe("profile_mismatch");
    expect(denial(() => selectProfile(loaded, githubClaims(), "nope"))).toBe("profile_mismatch");
  });

  it("clamps ttl to max_ttl and rejects nonsense", () => {
    const r = profile("workers-deploy");
    expect(clampTTL(undefined, r)).toBe(15 * 60_000);
    expect(clampTTL("5m", r)).toBe(5 * 60_000);
    expect(clampTTL("10h", r)).toBe(60 * 60_000);
    expect(denial(() => clampTTL("forever", r))).toBe("invalid_ttl");
    expect(denial(() => clampTTL("30s", r))).toBe("invalid_ttl");
  });
});

describe("buckets", () => {
  /** workers-deploy with one bucket, plus profile-level fields such as ttl, and without its token by default. */
  const withBucket = (bucket: Record<string, unknown>, { token = false, ...profile }: Record<string, unknown> = {}) => {
    const p = policy();
    const target = p.profiles[1] as TestPolicy["profiles"][number];
    if (!token) delete (target as { token?: unknown }).token;
    Object.assign(target, profile, {
      buckets: [{ name: "org-terraform-state", permission: "object-read-write", ...bucket }],
    });
    return p;
  };
  const loaded = (p: TestPolicy) => loadPolicy(p).profiles[1] as Profile;

  it("accepts a profile with only buckets, using the default ttls", () => {
    const profile = loaded(withBucket({ prefixes: ["github.com/{repository}/"] }));
    expect(profile.policies).toBeUndefined();
    expect(profile.buckets).toEqual([
      { name: "org-terraform-state", permission: "object-read-write", prefixes: ["github.com/{repository}/"] },
    ]);
    expect(profile.ttl).toBe(15 * 60_000);
    expect(profile.max_ttl).toBe(60 * 60_000);
  });

  it("takes ttl and max_ttl from the profile", () => {
    const profile = loaded(withBucket({}, { ttl: "5m", max_ttl: "10m" }));
    expect(profile.ttl).toBe(5 * 60_000);
    expect(profile.max_ttl).toBe(10 * 60_000);
    expect(issues(withBucket({}, { ttl: "20m", max_ttl: "10m" })).join()).toMatch(
      /\(workers-deploy\)\.ttl: must not exceed max_ttl/,
    );
    expect(issues(withBucket({}, { max_ttl: "25h" })).join()).toMatch(
      /\(workers-deploy\)\.max_ttl: must be at most 24h/,
    );
  });

  it("applies the profile's ttl to the token too", () => {
    const p = policy();
    Object.assign(p.profiles[1] as object, { ttl: "5m" });
    expect(loaded(p).ttl).toBe(5 * 60_000);
  });

  it("still takes ttl from token, but not from both places", () => {
    const p = policy();
    (p.profiles[1] as TestPolicy["profiles"][number]).token.ttl = "5m";
    expect(loaded(p).ttl).toBe(5 * 60_000);
    Object.assign(p.profiles[1] as object, { max_ttl: "30m" });
    expect(issues(p).join()).toMatch(/set ttl and max_ttl on the profile or on its token, not both/);
  });

  it("accepts a profile with a token and buckets", () => {
    const profile = loaded(withBucket({}, { token: true }));
    expect(profile.policies).toHaveLength(1);
    expect(profile.buckets?.[0]?.prefixes).toEqual([]);
  });

  it("requires a token, buckets or both", () => {
    const p = policy();
    delete (p.profiles[1] as { token?: unknown }).token;
    expect(issues(p).join()).toMatch(/must have a token, buckets or both/);
  });

  it("accepts several buckets, each once", () => {
    const p = withBucket({});
    const target = p.profiles[1] as unknown as { buckets: unknown[] };
    target.buckets.push({ name: "org-artifacts", permission: "object-read-only", prefixes: ["{repository_id}/"] });
    expect(loaded(p).buckets?.map((b) => b.name)).toEqual(["org-terraform-state", "org-artifacts"]);

    target.buckets.push({ name: "org-terraform-state", permission: "object-read-only" });
    expect(issues(p)).toEqual(["profiles.1 (workers-deploy).buckets.2.name: duplicate bucket org-terraform-state"]);

    target.buckets = [];
    expect(issues(p).join()).toMatch(/buckets: /);
  });

  it.each(["ab", "Org-State", "org_state", "-org-state", "org-state-", "x".repeat(64)])(
    "rejects the bucket name %j",
    (name) => {
      expect(issues(withBucket({ name })).join()).toMatch(/buckets\.0\.name: must be a valid R2 bucket name/);
    },
  );

  it.each(["admin-read-write", "admin-read-only", "read-write"])("rejects the permission %s", (permission) => {
    expect(issues(withBucket({ permission })).join()).toMatch(
      /buckets\.0\.permission: must be object-read-write or object-read-only/,
    );
  });

  it.each([
    "github.com/{repository}/",
    "{repository_owner_id}/{repository_id}/",
    "{repository_owner}/shared/",
    "shared/",
  ])("accepts the prefix %j", (prefix) => {
    expect(issues(withBucket({ prefixes: [prefix] }))).toEqual([]);
  });

  it.each([
    ["github.com/{repository}", /must end with \//],
    ["/github.com/{repository}/", /must not start with \//],
    ["github.com/*/", /must not contain \*/],
    ["github.com/../{repository}/", /must not contain \.\./],
    ["github.com//{repository}/", /empty or \. path segments/],
    ["./{repository}/", /empty or \. path segments/],
    ["/", /must not start with \//],
    ["", /must end with \//],
    // biome-ignore lint/suspicious/noTemplateCurlyInString: the mistake under test
    ["github.com/${repository}/", /not \$\{claim\}/],
    ["github.com/{ref}/", /unknown placeholder \{ref\}/],
    ["github.com/{}/", /unknown placeholder \{\}/],
    ["github.com/{repository/", /unmatched/],
    ["github.com/repository}/", /unmatched/],
    ["state-{repository_id}/", /whole path segment/],
    ["{repository_owner}{repository_id}/", /whole path segment/],
    ["github.com\t/{repository}/", /control characters/],
  ])("rejects the prefix %j", (prefix, message) => {
    const found = issues(withBucket({ prefixes: [prefix] }));
    expect(found).toHaveLength(1);
    expect(found[0]).toMatch(/^profiles\.1 \(workers-deploy\)\.buckets\.0\.prefixes\.0: /);
    expect(found[0]).toMatch(message);
  });

  describe("r2Prefixes", () => {
    const fill = (prefixes: string[], claims = githubClaims()) =>
      r2Prefixes({ name: "org-terraform-state", permission: "object-read-write", prefixes }, claims);

    it("fills placeholders from the claims", () => {
      expect(
        fill(["github.com/{repository}/", "{repository_owner_id}/{repository_id}/", "{repository_owner}/"]),
      ).toEqual(["github.com/example-org/api/", `${OWNER_ID}/200000003/`, "example-org/"]);
      expect(fill([])).toEqual([]);
    });

    it("keeps a repo whose name starts with another's out of it", () => {
      const [site] = fill(["github.com/{repository}/"], githubClaims({ repository: "example-org/site" }));
      const [old] = fill(["github.com/{repository}/"], githubClaims({ repository: "example-org/site-old" }));
      expect(old?.startsWith(site as string)).toBe(false);
      expect(`${old}terraform.tfstate`.startsWith(site as string)).toBe(false);
    });

    it.each([
      ["missing", { repository: undefined }],
      ["empty", { repository: "" }],
      ["a number", { repository: 42 }],
      ["without an owner", { repository: "api" }],
      ["with two slashes", { repository: "example-org/api/../other" }],
      ["a leading slash", { repository: "/example-org/api" }],
      ["a space", { repository: "example-org/my api" }],
      ["a percent escape", { repository: "example-org/%2e%2e" }],
      ["a backslash", { repository: "example-org\\api" }],
      ["a non-ASCII character", { repository: "example-org/аpi" }],
      ["a newline", { repository: "example-org/api\n" }],
      ["a *", { repository: "example-org/*" }],
    ])("403s when repository is %s", (_, overrides) => {
      expect(denial(() => fill(["github.com/{repository}/"], githubClaims(overrides)))).toBe("invalid_r2_prefix");
    });

    it.each([
      ["..", { repository: "example-org/.." }],
      [". as the repo", { repository: "example-org/." }],
      [".. as the owner", { repository_owner: ".." }],
      ["a slash in the owner", { repository_owner: "example-org/api" }],
      ["a non-numeric ID", { repository_id: "200000003a" }],
      ["an empty ID", { repository_owner_id: "" }],
    ])("403s on %s", (_, overrides) => {
      const templates = ["github.com/{repository}/", "{repository_owner}/", "{repository_owner_id}/{repository_id}/"];
      expect(denial(() => fill(templates, githubClaims(overrides)))).toBe("invalid_r2_prefix");
    });
  });
});
