import { once } from "node:events";
import { mkdtempSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { audit, clearAuditEvents, getAuditEvents, type AuditEvent } from "../src/audit.js";
import { validateConfig } from "../src/config.js";
import { executeServiceRequest } from "../src/gateway.js";
import { callTool } from "../src/mcp/tools.js";
import { TokenBroker, defaultTokenBrokers } from "../src/tokens.js";
import type { AuthContext, GatewayConfig } from "../src/types.js";

describe("audit logging", () => {
  it("omits raw credentials, opaque tokens, auth headers, cookies, and bodies from token and service request events", async () => {
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
    clearAuditEvents(config);
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

    const auditEvents = getAuditEvents(config);
    const serialized = JSON.stringify(auditEvents);
    expect(serialized).not.toContain("raw-secret");
    expect(serialized).not.toContain(issued.tokens[0]?.token ?? "");
    expect(serialized).not.toContain("Authorization");
    expect(serialized).not.toContain("Cookie");
    expect(serialized).not.toContain("do not log me");
    expect(auditEvents.map((event) => event.type)).toContain("token_issued");
    expect(auditEvents.map((event) => event.type)).toContain("service_request");
  });

  it("persists sanitized audit events as JSONL when audit.file is configured", async () => {
    const downstream = await startDownstream();
    try {
      const auditFile = join(mkdtempSync(join(tmpdir(), "gateway-audit-")), "audit.jsonl");
      const config = auditConfig(auditFile, downstream.baseUrl);
      clearAuditEvents(config);
      const broker = new TokenBroker(config);
      defaultTokenBrokers.set(config, broker);
      const auth = actor();
      const issued = broker.issueTokens(auth, {
        service: "demo-service",
        destination: "primary",
        credential_ids: ["api_key"],
        reason: "Need token.",
      });

      await executeServiceRequest(config, auth, {
        service: "demo-service",
        destination: "primary",
        method: "GET",
        path: "/allowed",
        headers: { Authorization: issued.tokens[0]?.token ?? "" },
        reason: "Allowed audit.",
      });
      await expect(executeServiceRequest(config, auth, {
        service: "demo-service",
        destination: "primary",
        method: "GET",
        path: "/blocked",
        headers: { Authorization: issued.tokens[0]?.token ?? "", Cookie: "session=abc" },
        body: "do not log me",
        reason: "Denied audit.",
      })).rejects.toThrow();
      await callTool("list_services", {}, config, auth);
      await callTool("describe_service_policy", { service: "demo-service" }, config, auth);
      await callTool("explain_denial", { request_id: "missing-denial" }, config, auth);

      const events = readJsonl(auditFile);
      const serialized = JSON.stringify(events);
      expect(events.map((event) => event.type)).toEqual(expect.arrayContaining([
        "token_issued",
        "service_request",
        "invalid_opaque_response_tokens",
        "tool_invocation",
      ]));
      expect(events.filter((event) => event.type === "service_request").map((event) => event.policy_decision)).toEqual(expect.arrayContaining(["allow", "deny"]));
      expect(events.filter((event) => event.type === "tool_invocation").map((event) => event.tool)).toEqual(expect.arrayContaining(["list_services", "describe_service_policy", "explain_denial"]));
      expect(serialized).not.toContain("raw-secret");
      expect(serialized).not.toContain(issued.tokens[0]?.token ?? "");
      expect(serialized).not.toContain("Authorization");
      expect(serialized).not.toContain("Cookie");
      expect(serialized).not.toContain("do not log me");
      expect(serialized).not.toContain("ghp_");
      const warning = events.find((event) => event.type === "invalid_opaque_response_tokens");
      expect(warning).toMatchObject({ warnings: [{ prefix: "gref", reason: "unknown", count: 1 }] });
    } finally {
      await downstream.close();
    }
  });

  it("does not fail tool execution when the audit file cannot be appended", () => {
    const auditDirectory = mkdtempSync(join(tmpdir(), "gateway-audit-dir-"));
    const config = auditConfig(auditDirectory, "http://127.0.0.1:1");
    clearAuditEvents(config);
    const broker = new TokenBroker(config);
    defaultTokenBrokers.set(config, broker);

    expect(() => broker.issueTokens(actor(), {
      service: "demo-service",
      destination: "primary",
      credential_ids: ["api_key"],
      reason: "Audit file failure should not block issuance.",
    })).not.toThrow();
    expect(getAuditEvents(config).map((event) => event.type)).toContain("token_issued");
  });

  it("bounds memory history while preserving every file-backed event", () => {
    const auditFile = join(mkdtempSync(join(tmpdir(), "gateway-audit-ring-")), "audit.jsonl");
    const config = auditConfig(auditFile, "http://127.0.0.1:1", 2);
    clearAuditEvents(config);
    for (const tool of ["list_services", "get_gateway_service_references", "service_request"] as const) {
      audit({ type: "tool_invocation", subject: "actor", tool, outcome: "allow", timestamp: new Date().toISOString() }, config);
    }
    expect(getAuditEvents(config).map((event) => event.type)).toEqual(["tool_invocation", "tool_invocation"]);
    expect((getAuditEvents(config)[0] as { tool: string }).tool).toBe("get_gateway_service_references");
    expect(readJsonl(auditFile)).toHaveLength(3);
  });
});

function actor(): AuthContext {
  return { subject: "henric@example.com", scopes: ["gateway.request"], mode: "bearer" };
}

function auditConfig(auditFile: string, baseUrl: string, memoryEvents = 1000): GatewayConfig {
  return validateConfig({
    server: { listen: "127.0.0.1:8080", mcp_path: "/mcp" },
    auth: { mode: "bearer", bearer: { token_env: "TEST_GATEWAY_TOKEN" } },
    audit: { file: auditFile, memory_events: memoryEvents },
    services: {
      "demo-service": {
        type: "http",
        name: "Demo Service",
        destinations: [{ name: "primary", base_url: baseUrl, schemes: ["http"], hosts: [{ exact: "127.0.0.1" }] }],
        credentials: [{
          id: "api_key",
          usage: { kind: "header", name: "Authorization" },
          source: { kind: "env", name: "DEMO_API_KEY" },
        }],
        access: { users: ["henric@example.com"] },
        policy: {
          mode: "deny",
          rules: [
            { id: "allow", effect: "allow", priority: 100, methods: ["GET"], paths: ["/allowed"] },
            { id: "deny", effect: "deny", priority: 200, methods: ["GET"], paths: ["/blocked"] },
          ],
        },
      },
    },
  }, {
    TEST_GATEWAY_TOKEN: "dev-token",
    DEMO_API_KEY: "raw-secret",
  });
}

function readJsonl(path: string): AuditEvent[] {
  return readFileSync(path, "utf8").trim().split("\n").map((line) => JSON.parse(line) as AuditEvent);
}

async function startDownstream() {
  const server = createServer((_request, response) => {
    response.writeHead(200, {
      "content-type": "text/plain",
      "x-leaked-secret": "raw-secret",
    });
    response.end(`ok raw-secret gref_ghp_${"x".repeat(36)}`);
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Expected TCP address");
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    close: () => new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    }),
  };
}
