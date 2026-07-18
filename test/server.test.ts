import { once } from "node:events";
import { describe, expect, it } from "vitest";
import { validateConfig } from "../src/config.js";
import { createGatewayServer } from "../src/server.js";
import { BRAND_ICON_PATH, BRAND_LOCKUP_PATH } from "../src/brandAssets.js";

describe("health server", () => {
  it("returns ready health status", async () => {
    const config = serverConfig();
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

  it("serves only allowlisted public brand assets", async () => {
    const server = createGatewayServer(serverConfig());
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Expected TCP address");
    const baseUrl = `http://127.0.0.1:${address.port}`;

    try {
      for (const path of [BRAND_ICON_PATH, BRAND_LOCKUP_PATH]) {
        const response = await fetch(`${baseUrl}${path}`);
        const body = new Uint8Array(await response.arrayBuffer());
        expect(response.status).toBe(200);
        expect(response.headers.get("content-type")).toBe("image/png");
        expect(response.headers.get("cache-control")).toBe("public, max-age=86400");
        expect(response.headers.get("x-content-type-options")).toBe("nosniff");
        expect([...body.slice(0, 8)]).toEqual([137, 80, 78, 71, 13, 10, 26, 10]);
      }

      const unknown = await fetch(`${baseUrl}/assets/brand/not-allowlisted.png`);
      expect(unknown.status).toBe(404);
      const traversal = await fetch(`${baseUrl}/assets/brand/%2e%2e/package.json`);
      expect(traversal.status).toBe(404);
      const unsupportedMethod = await fetch(`${baseUrl}${BRAND_ICON_PATH}`, { method: "POST" });
      expect(unsupportedMethod.status).toBe(404);
    } finally {
      server.close();
    }
  });
});

function serverConfig() {
  return validateConfig({
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
}
