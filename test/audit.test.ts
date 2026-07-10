import { describe, expect, it } from "vitest";
import { auditEvents } from "../src/audit.js";
import { validateConfig } from "../src/config.js";
import { executeServiceRequest } from "../src/gateway.js";
import { TokenBroker, defaultTokenBrokers } from "../src/tokens.js";
import type { AuthContext } from "../src/types.js";

describe("audit logging", () => {
  it("omits raw credentials, opaque tokens, auth headers, cookies, and bodies from token and service request events", async () => {
    auditEvents.length = 0;
    const config = validateConfig({
      server: { listen: "127.0.0.1:8080", mcp_path: "/mcp" },
      auth: { mode: "bearer", bearer: { token_env: "TEST_GATEWAY_TOKEN" } },
      services: {
        "demo-service": {
          type: "http",
          name: "Demo Service",
          destinations: [{ name: "primary", base_url: "http://127.0.0.1:1", schemes: ["http"], hosts: [{ exact: "127.0.0.1" }] }],
          credentials: [{
            id: "api_key",
            usage: { kind: "header", name: "Authorization" },
            source: { kind: "env", name: "DEMO_API_KEY" },
          }],
          access: { users: ["henric@example.com"] },
          policy: { mode: "deny", rules: [{ id: "deny-all", effect: "deny", priority: 1, methods: ["GET"], paths: ["/.*"] }] },
        },
      },
    }, {
      TEST_GATEWAY_TOKEN: "dev-token",
      DEMO_API_KEY: "raw-secret",
    });
    const broker = new TokenBroker(config);
    defaultTokenBrokers.set(config, broker);
    const auth = actor();
    const issued = broker.issueTokens(auth, {
      service: "demo-service",
      destination: "primary",
      credential_ids: ["api_key"],
      reason: "Need token.",
    });

    await expect(executeServiceRequest(config, auth, {
      service: "demo-service",
      destination: "primary",
      method: "GET",
      path: "/blocked",
      headers: {
        Authorization: issued.tokens[0]?.token ?? "",
        Cookie: "session=abc",
      },
      body: "do not log me",
      reason: "Denied request audit.",
    })).rejects.toThrow();

    const serialized = JSON.stringify(auditEvents);
    expect(serialized).not.toContain("raw-secret");
    expect(serialized).not.toContain(issued.tokens[0]?.token ?? "");
    expect(serialized).not.toContain("Authorization");
    expect(serialized).not.toContain("Cookie");
    expect(serialized).not.toContain("do not log me");
    expect(auditEvents.map((event) => event.type)).toContain("token_issued");
    expect(auditEvents.map((event) => event.type)).toContain("service_request");
  });
});

function actor(): AuthContext {
  return { subject: "henric@example.com", scopes: ["gateway.request"], mode: "bearer" };
}
