import { once } from "node:events";
import { createServer, type IncomingMessage } from "node:http";
import { describe, expect, it } from "vitest";
import { validateConfig } from "../src/config.js";
import { MCP_INSTRUCTIONS } from "../src/mcp/instructions.js";
import { callTool, toolDescriptors } from "../src/mcp/tools.js";
import { createGatewayServer } from "../src/server.js";

describe("MCP surface", () => {
  it("keeps the required safety opening in the first 512 instruction characters", () => {
    const opening = MCP_INSTRUCTIONS.slice(0, 512);
    expect(opening).toContain("without exposing raw configured credentials");
    expect(opening).toContain("enforced by the gateway backend before content reaches you");
    expect(opening).toContain("does not rely on you recognizing or keeping secrets confidential");
    expect(opening).toContain("Always call list_services first");
  });

  it("tells agents how backend-issued opaque tokens are constrained", () => {
    expect(MCP_INSTRUCTIONS).toContain("bound to the authenticated subject, originating service, destination, and credential");
    expect(MCP_INSTRUCTIONS).toContain("idle and maximum lifetimes");
    expect(MCP_INSTRUCTIONS).toContain("work only through this gateway");
    expect(MCP_INSTRUCTIONS).toContain("scanned on the backend before delivery");
    expect(MCP_INSTRUCTIONS).toContain("detected secrets are replaced with sec_ placeholders");
    expect(MCP_INSTRUCTIONS).toContain("mcp-session-id is not an authorization boundary");
  });

  it("defines exactly five OpenAI-compatible tool descriptors", () => {
    expect(toolDescriptors.map((tool) => tool.name)).toEqual([
      "list_services",
      "request_tokens",
      "describe_service_policy",
      "service_request",
      "explain_denial",
    ]);

    for (const descriptor of toolDescriptors) {
      expect(descriptor.title).toBeTruthy();
      expect(descriptor.description).toBeTruthy();
      expect(descriptor.inputSchema).toMatchObject({ type: "object" });
      expect(descriptor.outputSchema).toMatchObject({ type: "object" });
      expect(descriptor.securitySchemes.length).toBeGreaterThan(0);
      expect(descriptor._meta.securitySchemes).toEqual(descriptor.securitySchemes);
      expect(descriptor._meta["openai/toolInvocation/invoking"]).toBeTruthy();
      expect(descriptor._meta["openai/toolInvocation/invoked"]).toBeTruthy();
      expect(descriptor.annotations).toHaveProperty("readOnlyHint");
      expect(descriptor.annotations).toHaveProperty("destructiveHint");
      expect(descriptor.annotations).toHaveProperty("openWorldHint");
    }

    expect(toolDescriptors.find((tool) => tool.name === "list_services")?.annotations.readOnlyHint).toBe(true);
    expect(toolDescriptors.find((tool) => tool.name === "describe_service_policy")?.annotations).toMatchObject({
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    });
    expect(toolDescriptors.find((tool) => tool.name === "describe_service_policy")?.securitySchemes).toEqual([{ type: "oauth2", scopes: ["gateway.read"] }]);
    expect(toolDescriptors.find((tool) => tool.name === "explain_denial")?.annotations.readOnlyHint).toBe(true);
    expect(toolDescriptors.find((tool) => tool.name === "service_request")?.annotations.destructiveHint).toBe(true);
    expect(toolDescriptors.find((tool) => tool.name === "service_request")?.annotations.openWorldHint).toBe(true);

    const requestTokensDescription = toolDescriptors.find((tool) => tool.name === "request_tokens")?.description ?? "";
    expect(requestTokensDescription).toContain("configured credentials remain on the gateway backend");
    expect(requestTokensDescription).toContain("bound to the authenticated subject, service, destination, and credential");
    expect(requestTokensDescription).toContain("idle and maximum TTLs");
    expect(requestTokensDescription).toContain("work only through this gateway");

    const serviceRequestDescription = toolDescriptors.find((tool) => tool.name === "service_request")?.description ?? "";
    expect(serviceRequestDescription).toContain("backend substitutes opaque tokens only after authorization");
    expect(serviceRequestDescription).toContain("Before the response reaches the agent");
    expect(serviceRequestDescription).toContain("replaces detected secrets with subject- and service-bound sec_ tokens");
  });

  it("initializes and lists tools through the configured MCP endpoint", async () => {
    const fixture = await startFixtureServer();
    try {
      const initialize = await postMcp(fixture.url, {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "mcp-surface-test", version: "1.0.0" },
        },
      });
      expect(initialize.body.result.instructions).toContain("Always call list_services first");
      const sessionId = initialize.response.headers.get("mcp-session-id");
      expect(sessionId).toBeTruthy();

      const list = await postMcp(fixture.url, {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
      }, sessionId ?? undefined);

      expect(list.body.result.tools.map((tool: { name: string }) => tool.name)).toEqual([
        "list_services",
        "request_tokens",
        "describe_service_policy",
        "service_request",
        "explain_denial",
      ]);
      expect(list.body.result.tools[0].securitySchemes).toEqual([{ type: "oauth2", scopes: ["gateway.read"] }]);
      expect(list.body.result.tools[0]._meta.securitySchemes).toEqual(list.body.result.tools[0].securitySchemes);
    } finally {
      await fixture.close();
    }
  });

  it("returns a clear error for stale MCP sessions and allows reinitialization", async () => {
    const fixture = await startFixtureServer();
    try {
      const stale = await postMcp(fixture.url, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/list",
      }, "stale-session-id");
      expect(stale.response.status).toBe(400);
      expect(stale.body.error.code).toBe(-32001);
      expect(stale.body.error.message).toContain("MCP session expired");

      const initialize = await postMcp(fixture.url, {
        jsonrpc: "2.0",
        id: 2,
        method: "initialize",
        params: {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "mcp-surface-test", version: "1.0.0" },
        },
      });
      expect(initialize.response.headers.get("mcp-session-id")).toBeTruthy();
    } finally {
      await fixture.close();
    }
  });

  it("bounds MCP transports without disturbing existing sessions", async () => {
    const fixture = await startFixtureServer({ maxMcpTransports: 1 });
    try {
      const first = await postMcp(fixture.url, {
        jsonrpc: "2.0", id: 1, method: "initialize",
        params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "first", version: "1.0" } },
      });
      const firstSession = first.response.headers.get("mcp-session-id") ?? undefined;
      expect(firstSession).toBeTruthy();

      const rejected = await postMcp(fixture.url, {
        jsonrpc: "2.0", id: 2, method: "initialize",
        params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "second", version: "1.0" } },
      });
      expect(rejected.response.status).toBe(429);
      expect(rejected.body.error.code).toBe(-32003);

      const existing = await postMcp(fixture.url, { jsonrpc: "2.0", id: 3, method: "tools/list" }, firstSession);
      expect(existing.response.status).toBe(200);
      expect(existing.body.result.tools).toBeDefined();
    } finally {
      await fixture.close();
    }
  });

  it("reclaims idle MCP transports and allows reinitialization", async () => {
    const fixture = await startFixtureServer({ maxMcpTransports: 1, mcpTransportIdleTtl: "10ms" });
    try {
      const first = await postMcp(fixture.url, {
        jsonrpc: "2.0", id: 1, method: "initialize",
        params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "first", version: "1.0" } },
      });
      const staleSession = first.response.headers.get("mcp-session-id") ?? undefined;
      await new Promise((resolve) => setTimeout(resolve, 20));
      const replacement = await postMcp(fixture.url, {
        jsonrpc: "2.0", id: 2, method: "initialize",
        params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "replacement", version: "1.0" } },
      });
      expect(replacement.response.status).toBe(200);
      expect(replacement.response.headers.get("mcp-session-id")).toBeTruthy();
      const stale = await postMcp(fixture.url, { jsonrpc: "2.0", id: 3, method: "tools/list" }, staleSession);
      expect(stale.response.status).toBe(400);
      expect(stale.body.error.code).toBe(-32001);
    } finally {
      await fixture.close();
    }
  });

  it("issues opaque tokens through request_tokens without configured secrets", async () => {
    const fixture = await startFixtureServer();
    try {
      const initialize = await postMcp(fixture.url, {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "mcp-surface-test", version: "1.0.0" },
        },
      });
      const sessionId = initialize.response.headers.get("mcp-session-id");
      const call = await postMcp(fixture.url, {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: {
          name: "request_tokens",
          arguments: {
            service: "demo-service",
            credential_ids: ["api_key"],
            reason: "test",
          },
        },
      }, sessionId ?? undefined);

      const serialized = JSON.stringify(call.body);
      expect(call.body.result.structuredContent.tokens).toHaveLength(1);
      expect(call.body.result.structuredContent.tokens[0].token).toMatch(/^tok_/);
      expect(serialized).not.toContain("super-secret-api-key");
      expect(serialized).not.toContain("dev-token");
    } finally {
      await fixture.close();
    }
  });

  it("uses opaque tokens across different MCP transport sessions", async () => {
    const downstream = await startDownstream();
    const fixture = await startFixtureServer({ destinationBaseUrl: downstream.baseUrl });
    try {
      const firstInitialize = await postMcp(fixture.url, {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "mcp-surface-test", version: "1.0.0" },
        },
      });
      const secondInitialize = await postMcp(fixture.url, {
        jsonrpc: "2.0",
        id: 2,
        method: "initialize",
        params: {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "mcp-surface-test", version: "1.0.0" },
        },
      });
      const firstSessionId = firstInitialize.response.headers.get("mcp-session-id") ?? undefined;
      const secondSessionId = secondInitialize.response.headers.get("mcp-session-id") ?? undefined;
      expect(firstSessionId).toBeTruthy();
      expect(secondSessionId).toBeTruthy();
      expect(secondSessionId).not.toBe(firstSessionId);

      const tokenCall = await postMcp(fixture.url, {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: {
          name: "request_tokens",
          arguments: {
            service: "demo-service",
            credential_ids: ["api_key"],
            reason: "test cross-session token use",
          },
        },
      }, firstSessionId);
      const token = tokenCall.body.result.structuredContent.tokens[0].token;

      const requestCall = await postMcp(fixture.url, {
        jsonrpc: "2.0",
        id: 4,
        method: "tools/call",
        params: {
          name: "service_request",
          arguments: {
            service: "demo-service",
            method: "GET",
            path: "/api/echo",
            headers: { "X-API-Key": token },
            reason: "verify token survives transport session changes",
          },
        },
      }, secondSessionId);
      const serialized = JSON.stringify(requestCall.body);

      expect(requestCall.body.result.isError).not.toBe(true);
      expect(requestCall.body.result.structuredContent.status_code).toBe(200);
      expect(requestCall.body.result.structuredContent.body).not.toContain("super-secret-api-key");
      expect(serialized).not.toContain("super-secret-api-key");
      expect(serialized).not.toContain("dev-token");
      expect(downstream.requests).toHaveLength(1);
      expect(downstream.requests[0]?.headers["x-api-key"]).toBe("super-secret-api-key");
    } finally {
      await fixture.close();
      await downstream.close();
    }
  });

  it("keeps explain_denial as a safe stub without configured secrets", async () => {
    const fixture = await startFixtureServer();
    try {
      const initialize = await postMcp(fixture.url, {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "mcp-surface-test", version: "1.0.0" },
        },
      });
      const sessionId = initialize.response.headers.get("mcp-session-id");
      const call = await postMcp(fixture.url, {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: {
          name: "explain_denial",
          arguments: {
            request_id: "req_test",
          },
        },
      }, sessionId ?? undefined);

      const serialized = JSON.stringify(call.body);
      expect(call.body.result.isError).toBe(true);
      expect(serialized).not.toContain("super-secret-api-key");
      expect(serialized).toContain("No denial context found");
    } finally {
      await fixture.close();
    }
  });

  it("returns visible services through list_services without raw credentials", async () => {
    const fixture = await startFixtureServer();
    try {
      const initialize = await postMcp(fixture.url, {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "mcp-surface-test", version: "1.0.0" },
        },
      });
      const sessionId = initialize.response.headers.get("mcp-session-id");
      const call = await postMcp(fixture.url, {
        jsonrpc: "2.0",
        id: 4,
        method: "tools/call",
        params: {
          name: "list_services",
          arguments: {},
        },
      }, sessionId ?? undefined);
      const serialized = JSON.stringify(call.body);

      expect(call.body.result.structuredContent.services).toHaveLength(1);
      expect(call.body.result.structuredContent.services[0].id).toBe("demo-service");
      expect(serialized).not.toContain("super-secret-api-key");
    } finally {
      await fixture.close();
    }
  });

  it("describes service policy for authorized users without raw credentials", async () => {
    const config = fixtureConfig();
    const call = await callTool("describe_service_policy", {
      service: "demo-service",
    }, config, {
      subject: "bearer-dev",
      scopes: ["gateway.read"],
      mode: "bearer",
    });
    const serialized = JSON.stringify(call);

    expect(call.isError).not.toBe(true);
    expect(call.structuredContent).toMatchObject({
      id: "demo-service",
      name: "Demo Service",
      description: "Demo HTTP API",
      api_docs_url: "https://api.example.org/demo/openapi.json",
      destinations: [{ id: "primary", base_url_hint: "https://demo.internal" }],
      credentials: [{ id: "api_key", usage_hint: "Use token as X-API-Key header" }],
      policy: {
        mode: "deny",
        rules: [
          { id: "deny-delete", effect: "deny", priority: 200, methods: ["DELETE"], paths: ["/.*"] },
          { id: "allow-echo", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/echo"] },
        ],
      },
    });
    expect(serialized).not.toContain("super-secret-api-key");
    expect(serialized).not.toContain("dev-token");
  });

  it("does not let unauthorized users inspect service policy", async () => {
    const config = fixtureConfig();
    const call = await callTool("describe_service_policy", {
      service: "demo-service",
    }, config, {
      subject: "ada@example.com",
      scopes: ["gateway.read"],
      mode: "bearer",
    });
    const serialized = JSON.stringify(call);

    expect(call.isError).toBe(true);
    expect(serialized).toContain("Not authorized for service");
    expect(serialized).not.toContain("super-secret-api-key");
    expect(serialized).not.toContain("dev-token");
  });

  it("rejects malformed service policy requests without raw credentials", async () => {
    const config = fixtureConfig();
    const call = await callTool("describe_service_policy", {}, config, {
      subject: "bearer-dev",
      scopes: ["gateway.read"],
      mode: "bearer",
    });
    const serialized = JSON.stringify(call);

    expect(call.isError).toBe(true);
    expect(serialized).toContain("service must be a string");
    expect(serialized).not.toContain("super-secret-api-key");
    expect(serialized).not.toContain("dev-token");
  });


  it("returns a safe error for unknown MCP paths", async () => {
    const fixture = await startFixtureServer();
    try {
      const response = await fetch(`${fixture.baseUrl}/not-mcp`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
      });
      const body = await response.json() as { error: { code: string; message: string } };

      expect(response.status).toBe(404);
      expect(body.error).toEqual({ code: "not_found", message: "Not found." });
    } finally {
      await fixture.close();
    }
  });

  it("rejects oversized MCP bodies after authentication and authenticates before parsing", async () => {
    const fixture = await startFixtureServer({ maxInboundBody: "32b" });
    try {
      const oversized = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", padding: "x".repeat(64) });
      const rejected = await fetch(fixture.url, {
        method: "POST",
        headers: { authorization: "Bearer dev-token", "content-type": "application/json" },
        body: oversized,
      });
      expect(rejected.status).toBe(413);
      await expect(rejected.json()).resolves.toMatchObject({ error: { code: "request_too_large" } });

      const unauthenticated = await fetch(fixture.url, {
        method: "POST", headers: { "content-type": "application/json" }, body: oversized,
      });
      expect(unauthenticated.status).toBe(401);
    } finally {
      await fixture.close();
    }
  });
});

async function startFixtureServer(options: {
  destinationBaseUrl?: string; maxInboundBody?: string; maxMcpTransports?: number; mcpTransportIdleTtl?: string;
} = {}) {
  const config = fixtureConfig(options);
  const server = createGatewayServer(config);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Expected TCP address");
  const baseUrl = `http://127.0.0.1:${address.port}`;
  return {
    baseUrl,
    url: `${baseUrl}/mcp`,
    close: () => new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    }),
  };
}

function fixtureConfig(options: {
  destinationBaseUrl?: string; maxInboundBody?: string; maxMcpTransports?: number; mcpTransportIdleTtl?: string;
} = {}) {
  return validateConfig({
    server: { listen: "127.0.0.1:8080", mcp_path: "/mcp" },
    auth: { mode: "bearer", bearer: { token_env: "TEST_GATEWAY_TOKEN" } },
    limits: {
      max_inbound_body: options.maxInboundBody ?? "1mb",
      max_mcp_transports: options.maxMcpTransports ?? 1000,
      mcp_transport_idle_ttl: options.mcpTransportIdleTtl ?? "30m",
    },
    services: {
      "demo-service": {
        type: "http",
        name: "Demo Service",
        description: "Demo HTTP API",
        api_docs_url: "https://api.example.org/demo/openapi.json",
        destinations: [{
          name: "primary",
          base_url: options.destinationBaseUrl ?? "https://demo.internal",
          ...(options.destinationBaseUrl === undefined ? {} : { schemes: ["http"], hosts: [{ exact: "127.0.0.1" }] }),
        }],
        tls: { verify: options.destinationBaseUrl === undefined },
        credentials: [{
          id: "api_key",
          usage: { kind: "header", name: "X-API-Key" },
          source: { kind: "env", name: "DEMO_API_KEY" },
        }],
        access: { users: ["bearer-dev"] },
        policy: {
          mode: "deny",
          rules: [
            { id: "allow-echo", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/echo"] },
            { id: "deny-delete", effect: "deny", priority: 200, methods: ["DELETE"], paths: ["/.*"] },
          ],
        },
      },
    },
  }, {
    TEST_GATEWAY_TOKEN: "dev-token",
    DEMO_API_KEY: "super-secret-api-key",
  });
}

async function startDownstream() {
  const requests: Array<{ headers: Record<string, string | string[] | undefined>; body: string }> = [];
  const server = createServer(async (request, response) => {
    const body = await readBody(request);
    requests.push({ headers: request.headers, body });
    response.writeHead(200, {
      "content-type": "text/plain",
      "x-leaked-secret": "super-secret-api-key",
    });
    response.end("ok super-secret-api-key");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Expected TCP address");
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    requests,
    close: () => new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    }),
  };
}

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function postMcp(url: string, body: Record<string, unknown>, sessionId?: string) {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "accept": "application/json, text/event-stream",
    "authorization": "Bearer dev-token",
  };
  if (sessionId !== undefined) headers["mcp-session-id"] = sessionId;
  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  return {
    response,
    body: await response.json() as any,
  };
}
