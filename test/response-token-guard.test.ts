import { describe, expect, it } from "vitest";
import { validateConfig } from "../src/config.js";
import { guardResponseTokenCandidates } from "../src/responseTokenGuard.js";
import { TokenBroker } from "../src/tokens.js";
import type { AuthContext } from "../src/types.js";

describe("response opaque-token prefix guard", () => {
  it.each([
    [`tok_ghp_${"a".repeat(36)}`, "ghp_"],
    [`sec_sk-proj-${"b".repeat(48)}`, "sk-proj-"],
    ["tok_eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.signature", "eyJhbGci"],
    [`sec_AKIA${"C".repeat(16)}`, "AKIA"],
    ["tok_configured-secret", "configured-secret"],
  ])("wraps a forged prefix before real secret material: %s", (attack, secretFragment) => {
    const broker = new TokenBroker(config());
    const result = guardResponseTokenCandidates(`before ${attack} after`, broker, auth("alice"), "service-a");
    expect(result.value).toMatch(/^before sec_[A-Za-z0-9_-]+ after$/);
    expect(result.value).not.toContain(attack);
    expect(result.value).not.toContain(secretFragment);
    expect(result.warnings).toEqual([{ prefix: attack.startsWith("tok_") ? "tok" : "sec", reason: "unknown", count: 1 }]);
  });

  it("passes through valid same-scope values and wraps cross-scope real tokens", () => {
    const broker = new TokenBroker(config());
    const own = broker.issueOrReuseResponseSecret(auth("alice"), "service-a", "own-secret").token;
    const other = broker.issueOrReuseResponseSecret(auth("bob"), "service-a", "other-secret").token;
    const result = guardResponseTokenCandidates(`${own} ${other}`, broker, auth("alice"), "service-a");
    const [first, second] = result.value.split(" ");
    expect(first).toBe(own);
    expect(second).toMatch(/^sec_/);
    expect(second).not.toBe(other);
    expect(result.warnings).toEqual([{ prefix: "sec", reason: "wrong_subject", count: 1 }]);
  });

  it("wraps a fake prefix placed before another real opaque token", () => {
    const broker = new TokenBroker(config());
    const actual = broker.issueOrReuseResponseSecret(auth("bob"), "service-a", "other-secret").token;
    const attack = `tok_${actual}`;
    const result = guardResponseTokenCandidates(attack, broker, auth("alice"), "service-a");
    expect(result.value).toMatch(/^sec_/);
    expect(result.value).not.toContain(actual);
    expect(result.value).not.toContain(attack);
  });
});

function auth(subject: string): AuthContext {
  return { subject, scopes: [], mode: "bearer" };
}

function config() {
  return validateConfig({
    server: { listen: "127.0.0.1:8080", mcp_path: "/mcp" },
    auth: { mode: "bearer", bearer: { token_env: "AUTH" } },
    services: {
      "service-a": {
        name: "A", destinations: [{ name: "primary", base_url: "https://a.example.org" }],
        credentials: [{ id: "key", usage: { kind: "header" }, source: { kind: "env", name: "KEY_A" } }], access: { users: ["alice", "bob"] },
      },
      "service-b": {
        name: "B", destinations: [{ name: "primary", base_url: "https://b.example.org" }],
        credentials: [{ id: "key", usage: { kind: "header" }, source: { kind: "env", name: "KEY_B" } }], access: { users: ["alice"] },
      },
    },
  }, { AUTH: "auth", KEY_A: "configured-secret", KEY_B: "other-configured-secret" });
}
