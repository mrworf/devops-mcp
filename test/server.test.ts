import { once } from "node:events";
import { describe, expect, it } from "vitest";
import { validateConfig } from "../src/config.js";
import { createGatewayServer } from "../src/server.js";

describe("health server", () => {
  it("returns ready health status", async () => {
    const config = validateConfig({
      server: { listen: "127.0.0.1:8080", mcp_path: "/mcp" },
      auth: { mode: "bearer", bearer: { token_env: "TEST_GATEWAY_TOKEN" } },
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
        },
      },
    }, {
      TEST_GATEWAY_TOKEN: "dev-token",
      DEMO_API_KEY: "secret",
    });
    const server = createGatewayServer(config);
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Expected TCP address");

    try {
      const response = await fetch(`http://127.0.0.1:${address.port}/health`);
      const body = await response.json() as { status: string; service_count: number };

      expect(response.status).toBe(200);
      expect(body).toEqual({ status: "ready", service_count: 1 });
    } finally {
      server.close();
    }
  });
});
