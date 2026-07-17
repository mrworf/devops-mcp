import { describe, expect, it, vi } from "vitest";
import { validateConfig } from "../src/config.js";
import { GatewayError } from "../src/errors.js";
import { executeServiceRequest } from "../src/gateway.js";
import type { AuthContext } from "../src/types.js";

describe("gateway debug logging", () => {
  it("logs policy denials with setup context but without secrets", async () => {
    const lines: string[] = [];
    const log = vi.spyOn(console, "log").mockImplementation((line) => {
      lines.push(String(line));
    });

    try {
      const config = validateConfig({
        server: { listen: "127.0.0.1:8080", mcp_path: "/mcp" },
        auth: { mode: "bearer", bearer: { token_env: "TEST_GATEWAY_TOKEN" } },
        logging: { level: "debug" },
        services: {
          "demo-service": {
            type: "http",
            name: "Demo Service",
            destinations: [{ name: "primary", base_url: "https://demo.internal" }],
            credentials: [{
              id: "api_key",
              usage: { kind: "header", name: "X-API-Key" },
              source: { kind: "env", name: "DEMO_API_KEY" },
            }],
            access: { users: ["henric@example.com"] },
            policy: {
              mode: "deny",
              rules: [{ id: "deny-blocked", effect: "deny", priority: 100, methods: ["GET"], paths: ["/api/blocked"] }],
            },
          },
        },
      }, {
        TEST_GATEWAY_TOKEN: "dev-token",
        DEMO_API_KEY: "real-downstream-secret",
      });

      await expect(executeServiceRequest(config, actor(), {
        service: "demo-service",
        destination: "primary",
        method: "GET",
        path: "/api/blocked",
        headers: {
          Authorization: "Bearer gref_secret",
          "X-Trace-Id": "trace-1",
        },
        reason: "Check debug denial log.",
      })).rejects.toMatchObject({ code: "policy_denied" } satisfies Partial<GatewayError>);
    } finally {
      log.mockRestore();
    }

    const serialized = lines.join("\n");
    expect(serialized).toContain("service_request.denied");
    expect(serialized).toContain("demo-service");
    expect(serialized).toContain("demo.internal");
    expect(serialized).toContain("/api/blocked");
    expect(serialized).not.toContain("real-downstream-secret");
    expect(serialized).not.toContain("gref_secret");
    expect(serialized).not.toContain("Authorization");
  });
});

function actor(): AuthContext {
  return { subject: "henric@example.com", scopes: ["gateway.request"], mode: "bearer" };
}
