import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  isInitializeRequest,
  type JSONRPCMessage,
} from "@modelcontextprotocol/sdk/types.js";
import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { MCP_INSTRUCTIONS } from "./instructions.js";
import { callTool, toolDescriptors } from "./tools.js";
import type { AuthContext, GatewayConfig } from "../types.js";
import { readBoundedBody } from "../httpBody.js";
import { registerMaintenanceTask } from "../maintenance.js";
import { BRAND_ICON_PATH, publicBrandAssetUrl } from "../brandAssets.js";
import { McpInitializationLimiter } from "./initializationLimiter.js";

type NodeRequestWithBody = IncomingMessage & { body?: unknown };

interface TransportRecord { transport: StreamableHTTPServerTransport; lastActivityAt: number; subject: string }
interface TransportState { records: Map<string, TransportRecord>; initializations: McpInitializationLimiter }
const transportStates = new WeakMap<GatewayConfig, TransportState>();

export function createMcpServer(config: GatewayConfig, iconUrl: string): Server {
  const server = new Server(
    {
      name: "secretsauce-mcp",
      version: "0.1.0",
      icons: [{ src: iconUrl, sizes: ["512x512"], mimeType: "image/png" }],
    },
    {
      instructions: MCP_INSTRUCTIONS,
      capabilities: {
        tools: {
          listChanged: false,
        },
      },
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, () => ({
    tools: toolDescriptors,
  }));

  server.setRequestHandler(CallToolRequestSchema, (request, extra) => {
    const auth = extra.authInfo as AuthContext | undefined;
    if (auth === undefined) {
      return {
        structuredContent: {
          error: {
            code: "unauthenticated",
            message: "Authentication context is required.",
          },
        },
        content: [{ type: "text", text: "Authentication context is required." }],
        isError: true,
      };
    }
    return callTool(request.params.name, request.params.arguments, config, auth);
  });

  return server;
}

export async function handleMcpRequest(
  config: GatewayConfig,
  request: IncomingMessage,
  response: ServerResponse,
  parsedBody: unknown,
): Promise<void> {
  const state = getTransportState(config);
  sweepTransports(config, state, Date.now());
  const auth = (request as IncomingMessage & { auth?: AuthContext }).auth;
  if (auth === undefined) {
    writeJsonRpcError(response, 401, -32002, "Authentication context is required.");
    return;
  }
  const sessionId = readHeader(request, "mcp-session-id");
  const existingRecord = sessionId === undefined ? undefined : state.records.get(sessionId);
  if (existingRecord !== undefined) {
    if (existingRecord.subject !== auth.subject) {
      writeStaleSession(response);
      return;
    }
    existingRecord.lastActivityAt = Date.now();
    await existingRecord.transport.handleRequest(request, response, parsedBody);
    return;
  }

  if (sessionId !== undefined) {
    writeStaleSession(response);
    return;
  }

  if (!isInitializeRequest(parsedBody)) {
    writeJsonRpcError(response, 400, -32000, "Bad Request: No valid session ID provided");
    return;
  }
  if (state.records.size >= config.limits.maxMcpTransports) {
    writeJsonRpcError(response, 429, -32003, "MCP transport capacity is temporarily exhausted. Retry later.");
    return;
  }
  const subjectTransportCount = [...state.records.values()].filter((record) => record.subject === auth.subject).length;
  if (subjectTransportCount >= config.limits.maxMcpTransportsPerSubject) {
    writeJsonRpcError(response, 429, -32003, "MCP transport capacity is temporarily exhausted. Retry later.");
    return;
  }
  const admission = state.initializations.admit(auth.subject, Date.now());
  if (!admission.allowed) {
    response.setHeader("retry-after", String(Math.max(1, Math.ceil(admission.retryAfterMs / 1000))));
    writeJsonRpcError(response, 429, -32003, "MCP initialization rate limit is temporarily exhausted. Retry later.");
    return;
  }

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    enableJsonResponse: true,
    onsessioninitialized: (newSessionId) => {
      state.records.set(newSessionId, { transport, lastActivityAt: Date.now(), subject: auth.subject });
    },
  });
  transport.onclose = () => {
    const closedSessionId = transport.sessionId;
    if (closedSessionId !== undefined) state.records.delete(closedSessionId);
  };

  const server = createMcpServer(config, publicBrandAssetUrl(config, request, BRAND_ICON_PATH));
  // SDK transport typings are not exactOptionalPropertyTypes-clean in this version.
  await server.connect(transport as Parameters<Server["connect"]>[0]);
  await transport.handleRequest(request as NodeRequestWithBody, response, parsedBody);
}

function getTransportState(config: GatewayConfig): TransportState {
  let state = transportStates.get(config);
  if (state === undefined) {
    state = {
      records: new Map(),
      initializations: new McpInitializationLimiter(
        config.limits.maxMcpInitializationsPerSubject,
        config.limits.mcpInitializationWindowMs,
        config.limits.maxMcpInitializationRecords,
      ),
    };
    transportStates.set(config, state);
    registerMaintenanceTask(config, (now) => sweepTransports(config, state!, now));
  }
  return state;
}

function sweepTransports(config: GatewayConfig, state: TransportState, now: number): void {
  state.initializations.sweep(now);
  for (const [sessionId, record] of state.records) {
    if (record.lastActivityAt + config.limits.mcpTransportIdleTtlMs > now) continue;
    state.records.delete(sessionId);
    void record.transport.close().catch(() => undefined);
  }
}

function writeStaleSession(response: ServerResponse): void {
  writeJsonRpcError(response, 400, -32001, "MCP session expired or is no longer available. Reinitialize the MCP connection and retry the request.");
}

export function isMcpPost(request: IncomingMessage, mcpPath: string): boolean {
  return request.method === "POST" && request.url?.split("?")[0] === mcpPath;
}

export function isMcpGet(request: IncomingMessage, mcpPath: string): boolean {
  return request.method === "GET" && request.url?.split("?")[0] === mcpPath;
}

export async function readJsonBody(request: IncomingMessage, maxBytes: number, timeoutMs?: number): Promise<JSONRPCMessage | unknown> {
  const body = await readBoundedBody(request, maxBytes, timeoutMs);
  if (body.byteLength === 0) return undefined;
  return JSON.parse(body.toString("utf8")) as unknown;
}

function readHeader(request: IncomingMessage, name: string): string | undefined {
  const value = request.headers[name];
  if (Array.isArray(value)) return value[0];
  return value;
}

function writeJsonRpcError(response: ServerResponse, statusCode: number, code: number, message: string): void {
  response.writeHead(statusCode, { "content-type": "application/json; charset=utf-8" });
  response.end(`${JSON.stringify({ jsonrpc: "2.0", error: { code, message }, id: null })}\n`);
}
