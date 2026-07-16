import { describe, expect, it } from "vitest";
import { validateConfig } from "../src/config.js";
import { substituteRequestBodyTokens, substituteTokens } from "../src/substitution.js";
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

  it("substitutes tokens inside declared Base64 request bodies and re-encodes canonically", () => {
    const config = makeConfig();
    const broker = new TokenBroker(config);
    const token = broker.issueOrReuseResponseSecret(auth("alice"), "service-a", "returned-秘密").token;
    const configured = broker.issueTokens(auth("alice"), {
      service: "service-a", destination: "primary", credential_ids: ["key"], reason: "Test Base64 substitution.",
    }).tokens[0]?.token ?? "";
    const encoded = Buffer.from(`prefix ${token} configured=${configured} suffix`, "utf8").toString("base64").replace(/(.{8})/g, "$1\n");
    const result = substituteRequestBodyTokens(encoded, { "Content-Transfer-Encoding": " Base64 " }, broker, auth("alice"), {
      service: "service-a", destination: "primary",
    }, config.services["service-a"]!);

    expect(Buffer.from(result.value as string, "base64").toString("utf8")).toBe("prefix returned-秘密 configured=configured-a suffix");
    expect(result.value).not.toContain("\n");
    expect(result.responseSecretRecords).toHaveLength(1);
    expect(result.records).toHaveLength(1);
  });

  it("leaves undeclared Base64 opaque and rejects invalid declared request bodies", () => {
    const config = makeConfig();
    const broker = new TokenBroker(config);
    const target = { service: "service-a", destination: "primary" };
    const service = config.services["service-a"]!;
    const encodedToken = Buffer.from("sec_unknown", "utf8").toString("base64");
    expect(substituteRequestBodyTokens(encodedToken, {}, broker, auth("alice"), target, service).value).toBe(encodedToken);

    for (const [body, headers, code] of [
      [{ value: encodedToken }, { "Content-Transfer-Encoding": "base64" }, "unsupported_transfer_encoding"],
      ["%%%", { "Content-Transfer-Encoding": "base64" }, "unsupported_transfer_encoding"],
      ["/w==", { "Content-Transfer-Encoding": "base64" }, "unsupported_transfer_encoding"],
      [encodedToken, { "Content-Transfer-Encoding": "gzip" }, "unsupported_transfer_encoding"],
      [encodedToken, { "Content-Transfer-Encoding": "base64", "content-transfer-encoding": "base64" }, "unsupported_transfer_encoding"],
      [encodedToken, { "Content-Transfer-Encoding": "base64" }, "token_invalid"],
    ] as const) {
      try {
        substituteRequestBodyTokens(body, headers, broker, auth("alice"), target, service);
        throw new Error("Expected request body substitution to fail");
      } catch (error) {
        expect(error).toMatchObject({ code });
      }
    }
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
