import { describe, expect, it } from "vitest";
import { validateConfig } from "../src/config.js";
import { substituteTokens } from "../src/substitution.js";
import { TokenBroker } from "../src/tokens.js";
import type { AuthContext } from "../src/types.js";

describe("response secret substitution", () => {
  it("substitutes sec tokens in headers, query-like objects, and nested bodies", () => {
    const config = makeConfig();
    const broker = new TokenBroker(config);
    const token = broker.issueOrReuseResponseSecret(auth("alice"), "service-a", "returned-secret").token;
    const result = substituteTokens({ header: token, nested: [token], text: `Bearer ${token}` }, broker, auth("alice"), {
      service: "service-a", destination: "primary",
    }, config.services["service-a"]!);
    expect(result.value).toEqual({ header: "returned-secret", nested: ["returned-secret"], text: "Bearer returned-secret" });
    expect(result.responseSecretRecords).toHaveLength(3);
    expect(result.records).toEqual([]);
  });

  it("performs only one substitution pass and rejects cross-service redemption", () => {
    const config = makeConfig();
    const broker = new TokenBroker(config);
    const credential = broker.issueTokens(auth("alice"), {
      service: "service-a", destination: "primary", credential_ids: ["key"], reason: "Test.",
    }).tokens[0]?.token ?? "";
    const wrapper = broker.issueOrReuseResponseSecret(auth("alice"), "service-a", credential).token;
    const service = config.services["service-a"]!;
    expect(substituteTokens(wrapper, broker, auth("alice"), { service: "service-a", destination: "primary" }, service).value).toBe(credential);
    expect(() => substituteTokens(wrapper, broker, auth("alice"), { service: "service-b", destination: "primary" }, config.services["service-b"]!)).toThrow(/service/);
  });
});

function auth(subject: string): AuthContext { return { subject, scopes: [], mode: "bearer" }; }

function makeConfig() {
  return validateConfig({
    server: { listen: "127.0.0.1:8080", mcp_path: "/mcp" },
    auth: { mode: "bearer", bearer: { token_env: "AUTH" } },
    services: {
      "service-a": { name: "A", destinations: [{ name: "primary", base_url: "https://a.example.org" }], credentials: [{ id: "key", usage: { kind: "header" }, source: { kind: "env", name: "KEY_A" } }], access: { users: ["alice"] } },
      "service-b": { name: "B", destinations: [{ name: "primary", base_url: "https://b.example.org" }], credentials: [{ id: "key", usage: { kind: "header" }, source: { kind: "env", name: "KEY_B" } }], access: { users: ["alice"] } },
    },
  }, { AUTH: "auth", KEY_A: "configured-a", KEY_B: "configured-b" });
}
