import { describe, expect, it } from "vitest";
import { validateConfig } from "../src/config.js";
import { enforceCredentialHeaderUsage } from "../src/headerEnforcement.js";
import { createLogger } from "../src/logger.js";
import { substituteTokens } from "../src/substitution.js";
import { TokenBroker } from "../src/tokens.js";
import type { AuthContext } from "../src/types.js";

describe("optional credential header enforcement", () => {
  it("accepts the exact hinted template and substitutes only the reference", () => {
    const fixture = setup(true);
    const headers = { "X-API-Key": `Bearer ${fixture.reference}`, "X-Trace": "visible" };

    const enforced = enforceCredentialHeaderUsage(
      { headers, query: {}, body: undefined }, fixture.broker, fixture.auth, fixture.target, fixture.service, fixture.logger,
    );
    const substituted = substituteTokens(enforced, fixture.broker, fixture.auth, fixture.target, fixture.service);

    expect(substituted.value).toEqual({ "X-API-Key": "Bearer clean-token", "X-Trace": "visible" });
    expect(fixture.lines).toEqual([]);
  });

  it("clobbers duplicate or malformed owned headers with a sanitized warning", () => {
    const fixture = setup(true);
    const headers = {
      "X-API-Key": `wrong ${fixture.reference}`,
      "x-api-key": "caller-controlled",
    };

    const enforced = enforceCredentialHeaderUsage(
      { headers, query: {}, body: undefined }, fixture.broker, fixture.auth, fixture.target, fixture.service, fixture.logger,
    );

    expect(enforced).toEqual({ "X-API-Key": `Bearer ${fixture.reference}` });
    expect(fixture.lines).toHaveLength(1);
    const serialized = fixture.lines.join("\n");
    expect(serialized).toContain("auth_header_override_clobbered");
    expect(serialized).toContain('"access_id":"key"');
    expect(serialized).not.toContain(fixture.reference);
    expect(serialized).not.toContain("clean-token");
    expect(serialized).not.toContain("caller-controlled");
  });

  it("rejects owned headers without one matching reference and references in other locations", () => {
    for (const input of [
      { headers: { "X-API-Key": "caller-controlled" }, query: {}, body: undefined },
      { headers: {}, query: { token: "REFERENCE" }, body: undefined },
      { headers: {}, query: {}, body: { token: "REFERENCE" } },
      { headers: { Authorization: "REFERENCE" }, query: {}, body: undefined },
    ]) {
      const fixture = setup(true);
      const materialized = JSON.parse(JSON.stringify(input).replaceAll("REFERENCE", fixture.reference)) as typeof input;
      expect(() => enforceCredentialHeaderUsage(
        materialized, fixture.broker, fixture.auth, fixture.target, fixture.service, fixture.logger,
      )).toThrow(expect.objectContaining({ code: "reference_invalid" }));
      const serialized = fixture.lines.join("\n");
      expect(serialized).toContain("auth_header_override_rejected");
      expect(serialized).not.toContain(fixture.reference);
      expect(serialized).not.toContain("clean-token");
      expect(serialized).not.toContain("caller-controlled");
    }
  });

  it("preserves flexible substring substitution when enforcement is disabled", () => {
    const fixture = setup(false, ":signed");
    const headers = { "X-Other": `Bearer ${fixture.reference}:signed` };

    const enforced = enforceCredentialHeaderUsage(
      { headers, query: {}, body: undefined }, fixture.broker, fixture.auth, fixture.target, fixture.service, fixture.logger,
    );
    const substituted = substituteTokens(enforced, fixture.broker, fixture.auth, fixture.target, fixture.service);

    expect(substituted.value).toEqual({ "X-Other": "Bearer clean-token:signed" });
    expect(fixture.lines).toEqual([]);
  });
});

function setup(enforce: boolean, suffix?: string) {
  const config = validateConfig({
    server: { listen: "127.0.0.1:8080", mcp_path: "/mcp" },
    auth: { mode: "bearer", bearer: { token_env: "AUTH" } },
    services: {
      demo: {
        name: "Demo",
        destinations: [{ name: "primary", base_url: "https://api.example.org" }],
        credentials: [{
          id: "key",
          usage: { kind: "header", name: "X-API-Key", prefix: "Bearer ", ...(suffix === undefined ? {} : { suffix }), enforce },
          source: { kind: "env", name: "KEY" },
        }],
        access: { users: ["alice"] },
      },
    },
  }, { AUTH: "auth", KEY: "clean-token" });
  const auth: AuthContext = { subject: "alice", scopes: [], mode: "bearer" };
  const broker = new TokenBroker(config);
  const target = { service: "demo", destination: "primary" };
  const reference = broker.issueTokens(auth, {
    service: "demo", destination: "primary", access_ids: ["key"], reason: "Test header enforcement.",
  }).tokens[0]!.token;
  const lines: string[] = [];
  return {
    broker, auth, target, reference, service: config.services.demo!, lines,
    logger: createLogger({ level: "debug" }, (line) => lines.push(line)),
  };
}
