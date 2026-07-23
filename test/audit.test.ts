import { once } from "node:events";
import { closeSync, mkdirSync, mkdtempSync, openSync, readFileSync, statSync, writeSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it, vi } from "vitest";
import { AuditSink, audit, clearAuditEvents, closeAuditSink, getAuditEvents, type AuditEvent, type AuditFileOperations } from "../src/audit.js";
import { validateConfig } from "../src/config.js";
import { executeServiceRequest } from "../src/gateway.js";
import { callTool } from "../src/mcp/tools.js";
import { TokenBroker, defaultTokenBrokers } from "../src/tokens.js";
import type { AuthContext, GatewayConfig } from "../src/types.js";

describe("audit logging", () => {
  it("omits protected values, opaque references, auth headers, cookies, and bodies from reference and service request events", async () => {
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
      access_ids: ["api_key"],
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
    expect(auditEvents.map((event) => event.type)).toContain("reference_issued");
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
        access_ids: ["api_key"],
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
        "reference_issued",
        "service_request",
        "invalid_opaque_response_references",
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
      const warning = events.find((event) => event.type === "invalid_opaque_response_references");
      expect(warning).toMatchObject({ warnings: [{ prefix: "gref", reason: "unknown", count: 1 }] });
      const referenceEvent = events.find((event) => event.type === "reference_issued");
      expect(referenceEvent).toMatchObject({
        access_ids: ["api_key"],
        internal_reference_ids: [expect.stringMatching(/^grefrec_/)],
      });
      const allowedRequest = events.find((event) => event.type === "service_request" && event.policy_decision === "allow");
      expect(allowedRequest).toMatchObject({
        access_ids: ["api_key"],
        internal_reference_ids: [expect.stringMatching(/^grefrec_/)],
      });
      const deniedRequest = events.find((event) => event.type === "service_request" && event.policy_decision === "deny");
      expect(deniedRequest).toMatchObject({
        access_ids: [],
        internal_reference_ids: [],
      });
      for (const removed of [
        "credential_ids",
        "internal_token_ids",
        "response_internal_token_ids",
        "token_issued",
        "unknown_credential",
        "token_invalid",
        "token_expired",
      ]) {
        expect(serialized).not.toContain(`"${removed}"`);
      }
    } finally {
      await downstream.close();
    }
  });

  it("sanitizes caller-controlled audit text centrally in memory and JSONL", () => {
    const auditFile = join(mkdtempSync(join(tmpdir(), "gateway-audit-sanitize-")), "audit.jsonl");
    const config = auditConfig(auditFile, "http://127.0.0.1:1");
    clearAuditEvents(config);
    const broker = new TokenBroker(config);
    defaultTokenBrokers.set(config, broker);
    const first = broker.issueTokens(actor(), {
      service: "demo-service", destination: "primary", access_ids: ["api_key"],
      reason: "Basic authentication is enabled for this benign request.",
    });
    const opaqueReference = first.tokens[0]?.token ?? "";
    const basicCredential = `Basic ${Buffer.from("audit-user:audit-password", "utf8").toString("base64")}`;
    const patternedCredential = `ghp_${"a".repeat(36)}`;

    const second = broker.issueTokens(actor(), {
      service: "demo-service", destination: "primary", access_ids: ["api_key"],
      reason: `Use raw-secret ${opaqueReference} sec_forged-reference ${basicCredential} ${patternedCredential}`,
    });

    const memoryEvents = getAuditEvents(config).filter((event) => event.type === "reference_issued");
    const fileEvents = readJsonl(auditFile).filter((event) => event.type === "reference_issued");
    expect(memoryEvents[0]).toMatchObject({ reason: "Basic authentication is enabled for this benign request." });
    expect(second.audit.reason).toContain("[REDACTED]");
    expect(memoryEvents).toEqual(fileEvents);
    for (const serialized of [JSON.stringify(second.audit), JSON.stringify(memoryEvents), JSON.stringify(fileEvents)]) {
      expect(serialized).not.toContain("raw-secret");
      expect(serialized).not.toContain(opaqueReference);
      expect(serialized).not.toContain("sec_forged-reference");
      expect(serialized).not.toContain(basicCredential);
      expect(serialized).not.toContain(patternedCredential);
    }
    expect(second.audit.internal_reference_ids[0]).toMatch(/^grefrec_/);
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
      access_ids: ["api_key"],
      reason: "Audit file failure should not block issuance.",
    })).not.toThrow();
    expect(getAuditEvents(config).map((event) => event.type)).toContain("reference_issued");
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
    closeAuditSink(config);
  });

  it("owns one append descriptor, completes partial writes, and closes idempotently", () => {
    const auditFile = join(mkdtempSync(join(tmpdir(), "gateway-audit-writer-")), "nested", "audit.jsonl");
    const config = auditConfig(auditFile, "http://127.0.0.1:1");
    const operations = countingFileOperations();
    const sink = new AuditSink(config, operations.api);

    sink.record(toolEvent("list_services"));
    sink.record(toolEvent("service_request"));
    sink.close();
    sink.close();

    expect(operations.counts).toMatchObject({ ensureDirectory: 1, open: 1, close: 1 });
    expect(operations.counts.write).toBeGreaterThan(2);
    expect(readJsonl(auditFile)).toHaveLength(2);
    expect(statSync(auditFile).mode & 0o777).toBe(0o600);
  });

  it("marks open and write failures degraded without retaining sensitive diagnostics", () => {
    const config = auditConfig("/not-used/audit.jsonl", "http://127.0.0.1:1", 1);
    const lines: string[] = [];
    const log = vi.spyOn(console, "log").mockImplementation((line) => lines.push(String(line)));
    try {
      const openFailure = new AuditSink(config, {
        ensureDirectory: () => undefined,
        open: () => { throw new Error("raw-secret /private/audit.jsonl"); },
        write: () => { throw new Error("unexpected write"); },
        close: () => undefined,
      });
      openFailure.record(toolEvent("list_services", "raw-secret"));
      openFailure.record(toolEvent("service_request", "raw-secret"));
      expect(openFailure.degraded).toBe(true);
      expect(openFailure.events).toHaveLength(1);
      expect(JSON.stringify(openFailure.events)).not.toContain("raw-secret");

      const writeFailure = new AuditSink(config, {
        ensureDirectory: () => undefined,
        open: () => 42,
        write: () => { throw new Error("raw-secret /private/audit.jsonl"); },
        close: () => undefined,
      });
      expect(() => writeFailure.record(toolEvent("list_services", "raw-secret"))).not.toThrow();
      expect(writeFailure.degraded).toBe(true);
      expect(JSON.stringify(writeFailure.events)).not.toContain("raw-secret");
    } finally {
      log.mockRestore();
    }
    expect(lines.join("\n")).not.toContain("raw-secret");
    expect(lines.join("\n")).not.toContain("/private/audit.jsonl");
    expect(lines.map((line) => JSON.parse(line))).toEqual(expect.arrayContaining([
      expect.objectContaining({ event: "audit.write_failed", operation: "open" }),
      expect.objectContaining({ event: "audit.write_failed", operation: "write" }),
    ]));
  });

  it("does not write, leak, or throw after close", () => {
    const config = auditConfig("/not-used/audit.jsonl", "http://127.0.0.1:1");
    let writes = 0;
    const sink = new AuditSink(config, {
      ensureDirectory: () => undefined,
      open: () => 42,
      write: (_fd, _buffer, _offset, length) => { writes += 1; return length; },
      close: () => undefined,
    });
    sink.close();
    expect(() => sink.record(toolEvent("service_request", "raw-secret"))).not.toThrow();
    expect(writes).toBe(0);
    expect(JSON.stringify(sink.events)).not.toContain("raw-secret");
  });
});

function toolEvent(tool: "list_services" | "service_request", subject = "actor"): AuditEvent {
  return { type: "tool_invocation", subject, tool, outcome: "allow", timestamp: new Date().toISOString() };
}

function countingFileOperations() {
  const counts = { ensureDirectory: 0, open: 0, write: 0, close: 0 };
  const api: AuditFileOperations = {
    ensureDirectory: (path) => { counts.ensureDirectory += 1; mkdirSync(path, { recursive: true }); },
    open: (path) => { counts.open += 1; return openSync(path, "a", 0o600); },
    write: (fd, buffer, offset, length) => {
      counts.write += 1;
      const partialLength = Math.max(1, Math.floor(length / 2));
      return writeSync(fd, buffer, offset, partialLength);
    },
    close: (fd) => { counts.close += 1; closeSync(fd); },
  };
  return { counts, api };
}

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
