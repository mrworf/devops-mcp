import { createServer } from "node:http";
import { once } from "node:events";
import { createHash } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { classifyResponseBody, DEFAULT_BINARY_RESPONSE_MAX_BYTES, inspectBinaryBody } from "../src/binaryResponse.js";
import { getAuditEvents as getAuditEventsFromSink } from "../src/audit.js";
import { validateConfig } from "../src/config.js";
import { GatewayError } from "../src/errors.js";
import { executeServiceRequest as executeServiceRequestWithDependencies, type ServiceRequestInput } from "../src/gateway.js";
import { callTool as callToolWithDependencies } from "../src/mcp/tools.js";
import { publicRequestIdPattern } from "../src/requestId.js";
import { TokenBroker } from "../src/tokens.js";
import type { AuthContext, GatewayConfig } from "../src/types.js";
import { installTokenBroker, requestDependenciesFor } from "./capabilityHelpers.js";

function executeServiceRequest(config: GatewayConfig, auth: AuthContext, input: ServiceRequestInput) {
  return executeServiceRequestWithDependencies(config, auth, input, requestDependenciesFor(config));
}

function callTool(name: string, args: Record<string, unknown> | undefined, config: GatewayConfig, auth: AuthContext) {
  return callToolWithDependencies(name, args, config, auth, requestDependenciesFor(config));
}

function getAuditEvents(config: GatewayConfig) {
  return getAuditEventsFromSink(requestDependenciesFor(config).auditSink);
}

describe("binary response classification", () => {
  it("recognizes UTF-8 text and conservative binary indicators", () => {
    expect(classifyResponseBody(Buffer.from("text 雪", "utf8"))).toEqual({ kind: "text", reason: "utf8_text" });
    expect(classifyResponseBody(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))).toMatchObject({ kind: "binary", reason: "binary_signature" });
    expect(classifyResponseBody(Buffer.from([0x66, 0x00, 0x6f]))).toMatchObject({ kind: "binary", reason: "nul_byte" });
    expect(classifyResponseBody(Buffer.from([0xff, 0xfe]))).toMatchObject({ kind: "binary", reason: "invalid_utf8" });
    expect(classifyResponseBody(Buffer.from([0x61, 0x01, 0x02, 0x62]))).toMatchObject({ kind: "binary", reason: "control_bytes" });
  });

  it("finds mandatory protected byte sequences without returning their values", () => {
    const config = gatewayConfig("https://api.example.org");
    const broker = new TokenBroker(config);
    const body = Buffer.concat([
      pngPrefix(),
      Buffer.from(`demo-secret Basic ${Buffer.from("user:password").toString("base64")} gref_unknown-value`, "ascii"),
    ]);

    const inspection = inspectBinaryBody(body, broker, actor(), config.services["demo-service"]!);

    expect(inspection.ruleIds).toEqual([
      "gateway:configured-credential",
      "gateway:http-basic-credential",
      "gateway:invalid-opaque-prefix",
    ]);
    expect(JSON.stringify(inspection)).not.toContain("demo-secret");
    expect(JSON.stringify(inspection)).not.toContain("password");
  });
});

describe("binary gateway responses", () => {
  let downstream: Awaited<ReturnType<typeof startDownstream>>;
  let config: GatewayConfig;

  beforeAll(async () => {
    downstream = await startDownstream();
    config = gatewayConfig(downstream.baseUrl);
    installTokenBroker(config, (auditSink) => new TokenBroker(config, undefined, auditSink));
  });

  afterAll(async () => {
    await downstream?.close();
  });

  it("fully scans textual octet-stream bodies while preserving surrounding bytes", async () => {
    const response = await executeServiceRequest(config, actor(), request("/text-octet"));
    const body = response.binaryBody;

    expect(response.body).toBeNull();
    expect(response.body_encoding).toBe("mcp_blob");
    expect(body).toBeDefined();
    expect(body?.subarray(0, Buffer.byteLength("prefix-雪-"))).toEqual(Buffer.from("prefix-雪-"));
    expect(body?.toString("utf8")).toMatch(/^prefix-雪-sec_[A-Za-z0-9_-]+-suffix$/);
    expect(response.body_sha256).toBe(createHash("sha256").update(body!).digest("hex"));
  });

  it("returns clean binary bytes unchanged and continues protecting headers", async () => {
    const response = await executeServiceRequest(config, actor(), request("/binary"));

    expect(response.binaryBody).toEqual(cleanBinary());
    expect(response.headers["x-api-key"]).toMatch(/^sec_/);
    expect(response.body_size_bytes).toBe(cleanBinary().byteLength);
    expect(response.secret_tokenization_count).toBe(1);
  });

  it("returns binary through an MCP embedded blob", async () => {
    const result = await callTool("service_request", request("/binary") as unknown as Record<string, unknown>, config, actor());
    const resource = result.content.find((item) => item.type === "resource");

    expect(result.structuredContent).toMatchObject({ body: null, body_encoding: "mcp_blob", body_size_bytes: cleanBinary().length });
    expect(result.structuredContent.request_id).toMatch(publicRequestIdPattern);
    expect(result.structuredContent).not.toHaveProperty("binaryBody");
    expect(resource).toMatchObject({ type: "resource", resource: { mimeType: "application/octet-stream" } });
    if (resource?.type !== "resource") throw new Error("Expected embedded binary resource");
    expect(resource.resource.uri).toBe(`secretsauce://response/${result.structuredContent.request_id as string}`);
    expect(Buffer.from(resource.resource.blob, "base64")).toEqual(cleanBinary());
  });

  it("logs and rejects protected data in likely-binary bodies", async () => {
    const lines: string[] = [];
    const log = vi.spyOn(console, "log").mockImplementation((line) => lines.push(String(line)));
    try {
      await expect(executeServiceRequest(config, actor(), request("/binary-secret")))
        .rejects.toMatchObject({ code: "secret_scan_failed" } satisfies Partial<GatewayError>);
    } finally {
      log.mockRestore();
    }
    const serialized = lines.join("\n");
    expect(serialized).toContain("binary_response_rejected");
    expect(serialized).toContain("protected_data");
    expect(serialized).not.toContain("demo-secret");
  });

  it("accepts the exact binary limit and rejects limit plus one", async () => {
    const exact = await executeServiceRequest(config, actor(), request("/binary-exact-limit"));
    expect(exact.binaryBody).toHaveLength(DEFAULT_BINARY_RESPONSE_MAX_BYTES);
    await expect(executeServiceRequest(config, actor(), request("/binary-over-limit")))
      .rejects.toMatchObject({ code: "response_too_large" } satisfies Partial<GatewayError>);
  });

  it("can bypass binary scanning without bypassing the default size limit or header protection", async () => {
    const bypassConfig = gatewayConfig(downstream.baseUrl, { binaryResponse: { scan: false } });
    installTokenBroker(bypassConfig, (auditSink) => new TokenBroker(bypassConfig, undefined, auditSink));
    const lines: string[] = [];
    const log = vi.spyOn(console, "log").mockImplementation((line) => lines.push(String(line)));
    let response;
    try {
      response = await executeServiceRequest(bypassConfig, actor(), request("/binary-secret"));
    } finally {
      log.mockRestore();
    }

    expect(response?.binaryBody?.includes(Buffer.from("demo-secret"))).toBe(true);
    expect(response?.headers["x-api-key"]).toMatch(/^sec_/);
    expect(lines.join("\n")).toContain("binary_scan_bypassed");
    expect(lines.join("\n")).not.toContain("demo-secret");
    expect(getAuditEvents(bypassConfig)).toContainEqual(expect.objectContaining({
      type: "service_request",
      binary_scan_bypassed: true,
    }));
    await expect(executeServiceRequest(bypassConfig, actor(), request("/binary-over-limit")))
      .rejects.toMatchObject({ code: "response_too_large" } satisfies Partial<GatewayError>);
  });

  it("continues scanning likely-text bodies when binary scanning is disabled", async () => {
    const bypassConfig = gatewayConfig(downstream.baseUrl, { binaryResponse: { scan: false } });
    installTokenBroker(bypassConfig, (auditSink) => new TokenBroker(bypassConfig, undefined, auditSink));

    const response = await executeServiceRequest(bypassConfig, actor(), request("/text-octet"));
    expect(response.binaryBody?.toString("utf8")).toMatch(/^prefix-雪-sec_[A-Za-z0-9_-]+-suffix$/);
    expect(response.binaryBody?.toString("utf8")).not.toContain("demo-secret");
    expect(getAuditEvents(bypassConfig)).not.toContainEqual(expect.objectContaining({ binary_scan_bypassed: true }));
  });

  it("can remove the binary size guard while retaining scanning", async () => {
    const unlimitedConfig = gatewayConfig(downstream.baseUrl, { binaryResponse: { max_size: "unlimited" } });
    installTokenBroker(unlimitedConfig, (auditSink) => new TokenBroker(unlimitedConfig, undefined, auditSink));

    const clean = await executeServiceRequest(unlimitedConfig, actor(), request("/binary-over-limit"));
    expect(clean.binaryBody).toHaveLength(DEFAULT_BINARY_RESPONSE_MAX_BYTES + 1);
    await expect(executeServiceRequest(unlimitedConfig, actor(), request("/binary-over-limit-secret")))
      .rejects.toMatchObject({ code: "secret_scan_failed" } satisfies Partial<GatewayError>);
  });

  it("can remove both binary safeguards while preserving the global response cap", async () => {
    const unrestrictedConfig = gatewayConfig(downstream.baseUrl, {
      binaryResponse: { scan: false, max_size: "unlimited" },
    });
    installTokenBroker(unrestrictedConfig, (auditSink) => new TokenBroker(unrestrictedConfig, undefined, auditSink));

    const response = await executeServiceRequest(unrestrictedConfig, actor(), request("/binary-over-limit-secret"));
    expect(response.binaryBody?.includes(Buffer.from("demo-secret"))).toBe(true);

    const globallyBoundedConfig = gatewayConfig(downstream.baseUrl, {
      binaryResponse: { scan: false, max_size: "unlimited" },
      maxResponseBody: "100kb",
    });
    installTokenBroker(globallyBoundedConfig, (auditSink) => new TokenBroker(globallyBoundedConfig, undefined, auditSink));
    await expect(executeServiceRequest(globallyBoundedConfig, actor(), request("/binary-over-limit")))
      .rejects.toMatchObject({ code: "response_too_large" } satisfies Partial<GatewayError>);
  });

  it("honors a custom binary size boundary", async () => {
    const customConfig = gatewayConfig(downstream.baseUrl, { binaryResponse: { max_size: "101kb" } });
    installTokenBroker(customConfig, (auditSink) => new TokenBroker(customConfig, undefined, auditSink));

    const response = await executeServiceRequest(customConfig, actor(), request("/binary-over-limit"));
    expect(response.binaryBody).toHaveLength(DEFAULT_BINARY_RESPONSE_MAX_BYTES + 1);
  });
});

function gatewayConfig(baseUrl: string, options: {
  binaryResponse?: { scan?: boolean; max_size?: string };
  maxResponseBody?: string;
} = {}): GatewayConfig {
  return validateConfig({
    auth: { mode: "bearer", bearer: { token_env: "AUTH" } },
    limits: { max_response_body: options.maxResponseBody ?? "1mb" },
    services: {
      "demo-service": {
        name: "Demo",
        destinations: [{ name: "primary", base_url: baseUrl }],
        credentials: [{ id: "key", usage: { kind: "header" }, source: { kind: "env", name: "KEY" } }],
        access: { users: ["alice"] },
        policy: {
          mode: "deny",
          rules: [{
            id: "allow-binary",
            effect: "allow",
            priority: 1,
            methods: ["GET"],
            paths: ["^/"],
            ...(options.binaryResponse === undefined ? {} : { binary_response: options.binaryResponse }),
          }],
        },
      },
    },
  }, { AUTH: "auth", KEY: "demo-secret" });
}

function actor(): AuthContext {
  return { subject: "alice", scopes: ["gateway.request"], mode: "bearer" };
}

function request(path: string) {
  return { service: "demo-service", method: "GET", path, reason: "Test binary response." };
}

function pngPrefix(): Buffer {
  return Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
}

function cleanBinary(): Buffer {
  return Buffer.concat([pngPrefix(), Buffer.from([0x00, 0xff, 0x10, 0x42])]);
}

async function startDownstream() {
  const server = createServer((request, response) => {
    response.setHeader("content-type", "application/octet-stream");
    if (request.url === "/text-octet") {
      response.end("prefix-雪-demo-secret-suffix");
      return;
    }
    if (request.url === "/binary-secret") {
      response.setHeader("x-api-key", "demo-secret");
      response.end(Buffer.concat([pngPrefix(), Buffer.from("demo-secret", "ascii")]));
      return;
    }
    if (request.url === "/binary-exact-limit") {
      response.end(Buffer.concat([pngPrefix(), Buffer.alloc(DEFAULT_BINARY_RESPONSE_MAX_BYTES - pngPrefix().length, 0xff)]));
      return;
    }
    if (request.url === "/binary-over-limit") {
      response.end(Buffer.concat([pngPrefix(), Buffer.alloc(DEFAULT_BINARY_RESPONSE_MAX_BYTES + 1 - pngPrefix().length, 0xff)]));
      return;
    }
    if (request.url === "/binary-over-limit-secret") {
      response.end(Buffer.concat([
        pngPrefix(),
        Buffer.from("demo-secret", "ascii"),
        Buffer.alloc(DEFAULT_BINARY_RESPONSE_MAX_BYTES + 1 - pngPrefix().length - "demo-secret".length, 0xff),
      ]));
      return;
    }
    response.setHeader("x-api-key", "demo-secret");
    response.end(cleanBinary());
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Expected TCP address");
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    close: () => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}
