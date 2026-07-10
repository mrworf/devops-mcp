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
import { callStubTool, toolDescriptors } from "./tools.js";

type NodeRequestWithBody = IncomingMessage & { body?: unknown };

const transports = new Map<string, StreamableHTTPServerTransport>();

export function createMcpServer(): Server {
  const server = new Server(
    {
      name: "agent-credential-gateway-mcp",
      version: "0.1.0",
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

  server.setRequestHandler(CallToolRequestSchema, (request) => callStubTool(request.params.name));

  return server;
}

export async function handleMcpRequest(request: IncomingMessage, response: ServerResponse, parsedBody: unknown): Promise<void> {
  const sessionId = readHeader(request, "mcp-session-id");
  const existingTransport = sessionId === undefined ? undefined : transports.get(sessionId);
  if (existingTransport !== undefined) {
    await existingTransport.handleRequest(request, response, parsedBody);
    return;
  }

  if (sessionId !== undefined || !isInitializeRequest(parsedBody)) {
    writeJsonRpcError(response, 400, -32000, "Bad Request: No valid session ID provided");
    return;
  }

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    enableJsonResponse: true,
    onsessioninitialized: (newSessionId) => {
      transports.set(newSessionId, transport);
    },
  });
  transport.onclose = () => {
    const closedSessionId = transport.sessionId;
    if (closedSessionId !== undefined) transports.delete(closedSessionId);
  };

  const server = createMcpServer();
  // SDK transport typings are not exactOptionalPropertyTypes-clean in this version.
  await server.connect(transport as Parameters<Server["connect"]>[0]);
  await transport.handleRequest(request as NodeRequestWithBody, response, parsedBody);
}

export function isMcpPost(request: IncomingMessage, mcpPath: string): boolean {
  return request.method === "POST" && request.url?.split("?")[0] === mcpPath;
}

export function isMcpGet(request: IncomingMessage, mcpPath: string): boolean {
  return request.method === "GET" && request.url?.split("?")[0] === mcpPath;
}

export async function readJsonBody(request: IncomingMessage): Promise<JSONRPCMessage | unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  if (chunks.length === 0) return undefined;
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
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
