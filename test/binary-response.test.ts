import { createServer } from "node:http";
import { once } from "node:events";
import { createHash } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { classifyResponseBody, DEFAULT_BINARY_RESPONSE_MAX_BYTES, inspectBinaryBody } from "../src/binaryResponse.js";
import { validateConfig } from "../src/config.js";
import { GatewayError } from "../src/errors.js";
import { executeServiceRequest } from "../src/gateway.js";
import { callTool } from "../src/mcp/tools.js";
import { TokenBroker, defaultTokenBrokers } from "../src/tokens.js";
import type { AuthContext, GatewayConfig } from "../src/types.js";

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
    defaultTokenBrokers.set(config, new TokenBroker(config));
  });

  afterAll(async () => {
    await downstream.close();
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
    expect(result.structuredContent).not.toHaveProperty("binaryBody");
    expect(resource).toMatchObject({ type: "resource", resource: { mimeType: "application/octet-stream" } });
    if (resource?.type !== "resource") throw new Error("Expected embedded binary resource");
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
});

function gatewayConfig(baseUrl: string): GatewayConfig {
  return validateConfig({
    auth: { mode: "bearer", bearer: { token_env: "AUTH" } },
    limits: { max_response_body: "1mb" },
    services: {
      "demo-service": {
        name: "Demo",
        destinations: [{ name: "primary", base_url: baseUrl }],
        credentials: [{ id: "key", usage: { kind: "header" }, source: { kind: "env", name: "KEY" } }],
        access: { users: ["alice"] },
        policy: {
          mode: "deny",
          rules: [{ id: "allow-binary", effect: "allow", priority: 1, methods: ["GET"], paths: ["^/"] }],
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
