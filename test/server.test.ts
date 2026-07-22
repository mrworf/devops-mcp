import { once } from "node:events";
import { describe, expect, it, vi } from "vitest";
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

  it("emits every sanitized configuration warning once at server startup", async () => {
    const config = serverConfig();
    config.server.resource = "http://mcp.example.org/private?access_token=do-not-log";
    config.services["demo-service"]!.destinations[0]!.hosts = [{ type: "regex", value: ".*", regex: /.*/ }];
    config.warnings.push(
      "server.resource uses HTTP for a non-loopback URL; use HTTPS for production deployments.",
      "Broad host regex warning: .*",
    );
    const lines: string[] = [];
    const log = vi.spyOn(console, "log").mockImplementation((line) => lines.push(String(line)));
    let server: ReturnType<typeof createGatewayServer> | undefined;

    try {
      server = createGatewayServer(config);
      server.listen(0, "127.0.0.1");
      await once(server, "listening");
    } finally {
      server?.close();
      log.mockRestore();
    }

    const warningRecords = lines.map((line) => JSON.parse(line) as Record<string, unknown>)
      .filter((record) => record.event === "config.warning");
    expect(warningRecords).toEqual([
      expect.objectContaining({
        level: "warn",
        event: "config.warning",
        message: "server.resource uses HTTP for a non-loopback URL; use HTTPS for production deployments.",
      }),
      expect.objectContaining({
        level: "warn",
        event: "config.warning",
        message: "Broad host regex warning: .*",
      }),
    ]);
    const serialized = lines.join("\n");
    expect(serialized).not.toContain("mcp.example.org");
    expect(serialized).not.toContain("do-not-log");
  });

  it("emits credential-source whitespace diagnostics only at debug level without values", () => {
    const config = serverConfig();
    config.logging.level = "debug";
    config.debugDiagnostics.push({
      code: "credential_source_contains_whitespace", serviceId: "demo-service", credentialId: "api_key",
    });
    const lines: string[] = [];
    const log = vi.spyOn(console, "log").mockImplementation((line) => lines.push(String(line)));
    try {
      const server = createGatewayServer(config);
      server.close();
    } finally {
      log.mockRestore();
    }

    expect(lines.map((line) => JSON.parse(line))).toContainEqual(expect.objectContaining({
      level: "debug", event: "config.credential_source_contains_whitespace",
      service: "demo-service", access_id: "api_key",
    }));
    expect(lines.join("\n")).not.toContain("DEMO_API_KEY");
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
