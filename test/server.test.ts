import { once } from "node:events";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { validateConfig } from "../src/config.js";
import { createGatewayServer } from "../src/server.js";
import { BRAND_ICON_PATH, BRAND_LOCKUP_PATH } from "../src/brandAssets.js";
import { AuditSink, initializeAuditSink } from "../src/audit.js";
import { GatewayRuntime } from "../src/runtime.js";
import { initializeSecretRuntime } from "../src/secretRuntime.js";
import { SecretScanBusyError } from "../src/secretScannerPool.js";
import { TokenBroker } from "../src/tokens.js";
import { explainDenial } from "../src/denials.js";
import { GatewayError } from "../src/errors.js";

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
      "server.allow_insecure_oauth_http permits non-loopback cleartext OAuth trust URLs; use only on an explicitly trusted development network.",
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
        message: "server.allow_insecure_oauth_http permits non-loopback cleartext OAuth trust URLs; use only on an explicitly trusted development network.",
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

  it("initializes and closes the durable audit sink with the server", async () => {
    const config = serverConfig();
    const auditFile = join(mkdtempSync(join(tmpdir(), "gateway-server-audit-")), "nested", "audit.jsonl");
    config.audit.file = auditFile;
    const server = createGatewayServer(config);
    const sink = initializeAuditSink(config);

    expect(existsSync(auditFile)).toBe(true);
    expect(sink.closed).toBe(false);
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const health = await fetchHealth(server);
    expect(health.response.status).toBe(200);
    expect(health.body).toEqual({ status: "ready", service_count: 1 });
    server.close();
    await once(server, "close");
    expect(sink.closed).toBe(true);
  });

  it("reports a sanitized not-ready response after audit initialization failure", async () => {
    const config = serverConfig();
    config.audit.file = "/private/raw-secret/audit.jsonl";
    const sink = new AuditSink(config, {
      ensureDirectory: () => undefined,
      open: () => { throw new Error("raw-secret /private/raw-secret/audit.jsonl"); },
      write: () => { throw new Error("unexpected write"); },
      close: () => undefined,
    });
    const server = createGatewayServer(config, { auditSink: sink });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    try {
      const health = await fetchHealth(server);
      expect(health.response.status).toBe(503);
      expect(health.body).toEqual({ status: "not_ready", service_count: 1, checks: { audit: "degraded" } });
      expect(JSON.stringify(health.body)).not.toContain("raw-secret");
      expect(JSON.stringify(health.body)).not.toContain("/private");
    } finally {
      server.close();
    }
  });

  it("keeps audit write degradation sticky while requests remain fail-open", async () => {
    const config = serverConfig();
    config.audit.file = "/not-used/audit.jsonl";
    let failWrite = true;
    const sink = new AuditSink(config, {
      ensureDirectory: () => undefined,
      open: () => 42,
      write: (_fd, _buffer, _offset, length) => {
        if (failWrite) throw new Error("raw-secret /private/audit.jsonl");
        return length;
      },
      close: () => undefined,
    });
    const server = createGatewayServer(config, { auditSink: sink });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    try {
      expect((await fetchHealth(server)).response.status).toBe(200);
      expect(() => sink.record({
        type: "tool_invocation", subject: "raw-secret", tool: "list_services", outcome: "allow", timestamp: new Date().toISOString(),
      })).not.toThrow();
      failWrite = false;
      const degraded = await fetchHealth(server);
      expect(degraded.response.status).toBe(503);
      expect(degraded.body).toEqual({ status: "not_ready", service_count: 1, checks: { audit: "degraded" } });
      expect((await fetchHealth(server)).response.status).toBe(503);
      expect(JSON.stringify(sink.events)).not.toContain("raw-secret");
    } finally {
      server.close();
    }
  });

  it("closes runtime resources once when the server closes and permits repeated close", async () => {
    const config = serverConfig();
    const stopMaintenance = vi.fn();
    const runtime = new GatewayRuntime(config, { startMaintenance: () => stopMaintenance });
    const server = createGatewayServer(config, { runtime });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");

    server.close();
    await once(server, "close");
    await runtime.close();
    await runtime.close();

    expect(stopMaintenance).toHaveBeenCalledTimes(1);
    expect(runtime.auditSink.closed).toBe(true);
    await expect(runtime.secretRuntime.pool.scan("actor", "benign", [], 100))
      .rejects.toBeInstanceOf(SecretScanBusyError);
  });

  it("cleans resources created before partial runtime initialization failure", async () => {
    const config = serverConfig();
    const auditSink = new AuditSink(config);
    const secretRuntime = initializeSecretRuntime(config, new TokenBroker(config));

    expect(() => new GatewayRuntime(config, {
      auditSink,
      secretRuntime,
      startMaintenance: () => { throw new Error("maintenance startup failed"); },
    })).toThrow("maintenance startup failed");

    expect(auditSink.closed).toBe(true);
    await expect(secretRuntime.pool.scan("actor", "benign", [], 100))
      .rejects.toBeInstanceOf(SecretScanBusyError);
  });

  it("keeps separately configured runtime scanner lifecycles independent", async () => {
    const first = new GatewayRuntime(serverConfig());
    const second = new GatewayRuntime(serverConfig());
    try {
      await first.close();
      await expect(first.secretRuntime.pool.scan("actor", "benign", [], 100))
        .rejects.toBeInstanceOf(SecretScanBusyError);
      await expect(second.secretRuntime.pool.scan("actor", "benign", [], 1_000)).resolves.toEqual([]);
    } finally {
      await second.close();
    }
  });

  it("isolates capability, denial, and admission state between runtimes", async () => {
    const actor = { subject: "bearer-dev", scopes: ["gateway.request"], mode: "bearer" as const };
    const firstConfig = serverConfig();
    const secondConfig = serverConfig();
    firstConfig.services["demo-service"]!.access.users = [actor.subject];
    secondConfig.services["demo-service"]!.access.users = [actor.subject];
    const first = new GatewayRuntime(firstConfig);
    const second = new GatewayRuntime(secondConfig);
    try {
      const reference = first.capabilities.tokenBroker.issueTokens(actor, {
        service: "demo-service", destination: "primary", access_ids: ["api_key"], reason: "Test runtime isolation.",
      }).tokens[0]?.token ?? "";
      expect(() => second.capabilities.tokenBroker.validateTokenUse(actor, {
        service: "demo-service", destination: "primary",
      }, reference)).toThrowError(GatewayError);

      const denial = first.capabilities.denialStore.record({
        subject: actor.subject, reason: "first runtime only", policy_mode: "deny",
      });
      expect(explainDenial(second.capabilities.denialStore, actor, denial.request_id)).toBeUndefined();
      expect(explainDenial(first.capabilities.denialStore, actor, denial.request_id)?.reason).toBe("first runtime only");

      const firstReleases = Array.from({ length: first.config.limits.maxServiceRequestsInflightPerSubject }, () =>
        first.capabilities.serviceRequestLimiter.acquire(actor.subject, "demo-service"));
      expect(first.capabilities.serviceRequestLimiter.acquire(actor.subject, "demo-service")).toBeUndefined();
      const secondRelease = second.capabilities.serviceRequestLimiter.acquire(actor.subject, "demo-service");
      expect(secondRelease).toBeTypeOf("function");
      for (const release of firstReleases) release?.();
      secondRelease?.();
    } finally {
      await Promise.all([first.close(), second.close()]);
    }
  });
});

async function fetchHealth(server: ReturnType<typeof createGatewayServer>) {
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Expected TCP address");
  const response = await fetch(`http://127.0.0.1:${address.port}/health`);
  const body = await response.json() as Record<string, unknown>;
  return { response, body };
}

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
