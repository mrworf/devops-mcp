import { once } from "node:events";
import { createServer, type IncomingMessage } from "node:http";
import { describe, expect, it } from "vitest";
import { validateConfig } from "../src/config.js";
import { MCP_INSTRUCTIONS } from "../src/mcp/instructions.js";
import { toolDescriptors } from "../src/mcp/tools.js";
import { createGatewayServer } from "../src/server.js";

describe("MCP surface", () => {
  it("keeps the required safety opening in the first 512 instruction characters", () => {
    const requiredOpening = "This MCP server lets agents call configured HTTP services without exposing raw credentials. Always call list_services first, then request_tokens with a clear reason, then use service_request with service, destination, method, path or allowed URL, headers/body containing opaque tokens, and a request reason. Tokens are not real credentials and only work through this MCP server. Requests may be denied by service policy.";

    expect(MCP_INSTRUCTIONS.slice(0, 512)).toContain(requiredOpening);
  });

  it("defines exactly four OpenAI-compatible tool descriptors", () => {
    expect(toolDescriptors.map((tool) => tool.name)).toEqual([
      "list_services",
      "request_tokens",
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
    expect(toolDescriptors.find((tool) => tool.name === "explain_denial")?.annotations.readOnlyHint).toBe(true);
    expect(toolDescriptors.find((tool) => tool.name === "service_request")?.annotations.destructiveHint).toBe(true);
    expect(toolDescriptors.find((tool) => tool.name === "service_request")?.annotations.openWorldHint).toBe(true);
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
        "service_request",
        "explain_denial",
      ]);
      expect(list.body.result.tools[0].securitySchemes).toEqual([{ type: "oauth2", scopes: ["gateway.read"] }]);
      expect(list.body.result.tools[0]._meta.securitySchemes).toEqual(list.body.result.tools[0].securitySchemes);
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
});

async function startFixtureServer(options: { destinationBaseUrl?: string } = {}) {
  const config = validateConfig({
    server: { listen: "127.0.0.1:8080", mcp_path: "/mcp" },
    auth: { mode: "bearer", bearer: { token_env: "TEST_GATEWAY_TOKEN" } },
    services: {
      "demo-service": {
        type: "http",
        name: "Demo Service",
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
        policy: options.destinationBaseUrl === undefined ? undefined : {
          mode: "deny",
          rules: [
            { id: "allow-echo", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/echo"] },
          ],
        },
      },
    },
  }, {
    TEST_GATEWAY_TOKEN: "dev-token",
    DEMO_API_KEY: "super-secret-api-key",
  });
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
