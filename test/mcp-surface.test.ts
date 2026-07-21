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
    expect(opening).toContain("without exposing protected backend values");
    expect(opening).toContain("enforced by the gateway backend before content reaches you");
    expect(opening).toContain("does not rely on you recognizing or keeping secrets confidential");
    expect(opening).toContain("Always call list_services first");
  });

  it("tells agents how gateway service references are constrained", () => {
    expect(MCP_INSTRUCTIONS).toContain("bound to the authenticated subject, originating service, destination, and access entry");
    expect(MCP_INSTRUCTIONS).toContain("idle and maximum lifetimes");
    expect(MCP_INSTRUCTIONS).toContain("work only through this gateway");
    expect(MCP_INSTRUCTIONS).toContain("scanned on the backend before delivery");
    expect(MCP_INSTRUCTIONS).toContain("detected secrets are replaced with sec_ references");
    expect(MCP_INSTRUCTIONS).toContain("MCP transport is stateless");
    expect(MCP_INSTRUCTIONS).toContain("reference continuity comes from authenticated-subject binding");
  });

  it("defines exactly five OpenAI-compatible tool descriptors", () => {
    expect(toolDescriptors.map((tool) => tool.name)).toEqual([
      "list_services",
      "get_gateway_service_references",
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

    const referenceTool = toolDescriptors.find((tool) => tool.name === "get_gateway_service_references");
    expect(referenceTool?.securitySchemes).toEqual([{ type: "oauth2", scopes: ["gateway.references"] }]);
    expect(referenceTool?.annotations).toMatchObject({
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: false,
      idempotentHint: false,
    });
    expect(referenceTool?.inputSchema).toMatchObject({ required: ["service", "access_ids", "reason"] });
    expect(referenceTool?.outputSchema).toMatchObject({ required: ["references"] });
    expect(referenceTool?.description).toContain("cannot reveal or export");
    expect(referenceTool?.description).toContain("does not contact or modify the downstream service");

    const serviceRequestDescription = toolDescriptors.find((tool) => tool.name === "service_request")?.description ?? "";
    expect(toolDescriptors.find((tool) => tool.name === "service_request")?.inputSchema)
      .toMatchObject({ properties: { service_reference: { type: "string" } } });
    expect(serviceRequestDescription).toContain("backend resolves gateway references only after authorization");
    expect(serviceRequestDescription).toContain("never forwarded downstream");
    expect(serviceRequestDescription).toContain("Before the response reaches the agent");
    expect(serviceRequestDescription).toContain("replaces detected secrets with subject- and service-bound sec_ references");
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
      expect(initialize.body.result.serverInfo.name).toBe("secretsauce-mcp");
      expect(initialize.body.result.serverInfo.name).not.toBe(["agent", "credential", "gateway", "mcp"].join("-"));
      expect(initialize.body.result.serverInfo.icons).toEqual([{
        src: `${fixture.baseUrl}/assets/brand/secretsauce-icon.png`,
        sizes: ["512x512"],
        mimeType: "image/png",
      }]);
      expect(initialize.body.result.instructions).toContain("Always call list_services first");
      expect(initialize.response.headers.get("mcp-session-id")).toBeNull();

      const list = await postMcp(fixture.url, {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
      });

      expect(list.body.result.tools.map((tool: { name: string }) => tool.name)).toEqual([
        "list_services",
        "get_gateway_service_references",
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

  it("uses the configured public resource origin for the advertised MCP icon", async () => {
    const fixture = await startFixtureServer({ publicResource: "https://mcp.example.org" });
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
      expect(initialize.body.result.serverInfo.icons[0].src).toBe("https://mcp.example.org/assets/brand/secretsauce-icon.png");
    } finally {
      await fixture.close();
    }
  });

  it("ignores caller-supplied transport IDs and authenticates every stateless request", async () => {
    const fixture = await startFixtureServer();
    try {
      const list = await postMcp(fixture.url, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/list",
      }, "caller-controlled-session");
      expect(list.response.status).toBe(200);
      expect(list.body.result.tools).toBeDefined();
      expect(list.response.headers.get("mcp-session-id")).toBeNull();

      const unauthenticated = await postMcp(fixture.url, {
        jsonrpc: "2.0", id: 2, method: "tools/list",
      }, "caller-controlled-session", "wrong-token");
      expect(unauthenticated.response.status).toBe(401);
    } finally {
      await fixture.close();
    }
  });

  it("allows repeated initialization without retaining transport capacity", async () => {
    const fixture = await startFixtureServer();
    try {
      for (let id = 1; id <= 25; id += 1) {
        const initialized = await postMcp(fixture.url, initializeRequest(id));
        expect(initialized.response.status).toBe(200);
        expect(initialized.response.headers.get("mcp-session-id")).toBeNull();
      }
    } finally {
      await fixture.close();
    }
  });

  it("accepts stateless notifications without a transport session", async () => {
    const fixture = await startFixtureServer();
    try {
      const notification = await fetch(fixture.url, {
        method: "POST",
        headers: {
          authorization: "Bearer dev-token",
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({
          jsonrpc: "2.0", method: "notifications/initialized", params: {},
        }),
      });
      expect(notification.status).toBe(202);
      expect(notification.headers.get("mcp-session-id")).toBeNull();
    } finally {
      await fixture.close();
    }
  });

  it("returns structured gateway service references without protected values", async () => {
    const fixture = await startFixtureServer();
    try {
      const call = await postMcp(fixture.url, {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: {
          name: "get_gateway_service_references",
          arguments: {
            service: "demo-service",
            access_ids: ["api_key"],
            reason: "test",
          },
        },
      });

      const serialized = JSON.stringify(call.body);
      expect(call.body.result.structuredContent.references).toHaveLength(1);
      expect(call.body.result.structuredContent.references[0]).toMatchObject({
        access_id: "api_key",
        reference: expect.stringMatching(/^gref_/),
        exportable: false,
        usable_outside_gateway: false,
        reveals_protected_value: false,
      });
      expect(serialized).not.toContain("super-secret-api-key");
      expect(serialized).not.toContain("dev-token");
    } finally {
      await fixture.close();
    }
  });

  it("rejects malformed access ids and the removed tool name", async () => {
    const config = fixtureConfig();
    const auth = { subject: "bearer-dev", scopes: ["gateway.references"], mode: "bearer" as const };

    const malformed = await callTool("get_gateway_service_references", {
      service: "demo-service",
      access_ids: ["api_key", 7],
      reason: "test malformed access ids",
    }, config, auth);
    const empty = await callTool("get_gateway_service_references", {
      service: "demo-service",
      access_ids: [],
      reason: "test empty access ids",
    }, config, auth);
    const removed = await callTool("request_tokens", {}, config, auth);
    const malformedServiceReference = await callTool("service_request", {
      service: "demo-service", method: "GET", path: "/api/echo", service_reference: 7, reason: "test malformed reference",
    }, config, auth);

    expect(malformed).toMatchObject({ isError: true, structuredContent: { error: { code: "unknown_access" } } });
    expect(empty).toMatchObject({ isError: true, structuredContent: { error: { code: "unknown_access" } } });
    expect(removed).toMatchObject({ isError: true, structuredContent: { error: { code: "not_implemented" } } });
    expect(malformedServiceReference).toMatchObject({ isError: true, structuredContent: { error: { code: "reference_invalid" } } });
  });

  it("uses gateway service references across independent stateless requests", async () => {
    const downstream = await startDownstream();
    const fixture = await startFixtureServer({ destinationBaseUrl: downstream.baseUrl });
    try {
      const referenceCall = await postMcp(fixture.url, {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: {
          name: "get_gateway_service_references",
          arguments: {
            service: "demo-service",
            access_ids: ["api_key"],
            reason: "test stateless reference use",
          },
        },
      });
      const reference = referenceCall.body.result.structuredContent.references[0].reference;

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
            headers: { "X-API-Key": reference },
            reason: "verify reference survives independent stateless requests",
          },
        },
      });
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
      });

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
      const call = await postMcp(fixture.url, {
        jsonrpc: "2.0",
        id: 4,
        method: "tools/call",
        params: {
          name: "list_services",
          arguments: {},
        },
      });
      const serialized = JSON.stringify(call.body);

      expect(call.body.result.structuredContent.services).toHaveLength(1);
      expect(call.body.result.structuredContent.services[0].id).toBe("demo-service");
      expect(call.body.result.structuredContent.services[0].access_methods).toEqual([
        { id: "api_key", usage_hint: "Use reference as X-API-Key header" },
      ]);
      expect(serialized).not.toContain("super-secret-api-key");
      expect(serialized).not.toContain('"credentials"');
    } finally {
      await fixture.close();
    }
  });

  it("presents credential-free services as referenced gateway access", async () => {
    const config = fixtureConfig({ noAuth: true });
    const auth = { subject: "bearer-dev", scopes: ["gateway.read", "gateway.references"], mode: "bearer" as const };

    const listed = await callTool("list_services", {}, config, auth);
    expect(listed.structuredContent?.services).toMatchObject([{
      id: "demo-service",
      access_methods: [{ id: "gateway_access", usage_hint: "Pass reference as service_reference" }],
    }]);

    const described = await callTool("describe_service_policy", { service: "demo-service" }, config, auth);
    expect(described.structuredContent?.access_methods).toEqual([
      { id: "gateway_access", usage_hint: "Pass reference as service_reference" },
    ]);

    const referenced = await callTool("get_gateway_service_references", {
      service: "demo-service", destination: "primary", access_ids: ["gateway_access"], reason: "Inspect cameras.",
    }, config, auth);
    expect(referenced.structuredContent?.references).toMatchObject([{
      access_id: "gateway_access",
      reference: expect.stringMatching(/^gref_/),
      usage_hint: "Pass reference as service_reference",
    }]);
    expect(JSON.stringify({ listed, described, referenced })).not.toContain('"no_auth"');
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
      access_methods: [{ id: "api_key", usage_hint: "Use reference as X-API-Key header" }],
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
    expect(serialized).not.toContain('"credentials"');
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
  destinationBaseUrl?: string; maxInboundBody?: string; publicResource?: string; noAuth?: boolean;
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
  destinationBaseUrl?: string; maxInboundBody?: string; publicResource?: string; noAuth?: boolean;
} = {}) {
  return validateConfig({
    server: { listen: "127.0.0.1:8080", mcp_path: "/mcp", ...(options.publicResource === undefined ? {} : { resource: options.publicResource }) },
    auth: { mode: "bearer", bearer: { token_env: "TEST_GATEWAY_TOKEN" } },
    limits: {
      max_inbound_body: options.maxInboundBody ?? "1mb",
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
        ...(options.noAuth ? { no_auth: true } : {
          credentials: [{
            id: "api_key",
            usage: { kind: "header", name: "X-API-Key" },
            source: { kind: "env", name: "DEMO_API_KEY" },
          }],
        }),
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

async function postMcp(url: string, body: Record<string, unknown>, sessionId?: string, token = "dev-token") {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "accept": "application/json, text/event-stream",
    "authorization": `Bearer ${token}`,
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

function initializeRequest(id: number): Record<string, unknown> {
  return {
    jsonrpc: "2.0", id, method: "initialize",
    params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "fairness-test", version: "1.0" } },
  };
}
