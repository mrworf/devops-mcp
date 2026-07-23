import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type JSONRPCMessage,
} from "@modelcontextprotocol/sdk/types.js";
import type { IncomingMessage, ServerResponse } from "node:http";
import { MCP_INSTRUCTIONS } from "./instructions.js";
import { callTool, toolDescriptors } from "./tools.js";
import type { AuthContext, GatewayConfig } from "../types.js";
import { readBoundedBody } from "../httpBody.js";
import { BRAND_ICON_PATH, publicBrandAssetUrl } from "../brandAssets.js";
import type { RequestDependencies } from "../requestDependencies.js";

type NodeRequestWithBody = IncomingMessage & { body?: unknown };

export function createMcpServer(config: GatewayConfig, iconUrl: string, dependencies: RequestDependencies): Server {
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
    return callTool(request.params.name, request.params.arguments, config, auth, dependencies);
  });

  return server;
}

export async function handleMcpRequest(
  config: GatewayConfig,
  request: IncomingMessage,
  response: ServerResponse,
  parsedBody: unknown,
  dependencies: RequestDependencies,
): Promise<void> {
  const auth = (request as IncomingMessage & { auth?: AuthContext }).auth;
  if (auth === undefined) {
    writeJsonRpcError(response, 401, -32002, "Authentication context is required.");
    return;
  }

  const transport = new StreamableHTTPServerTransport({
    enableJsonResponse: true,
  });
  const server = createMcpServer(config, publicBrandAssetUrl(config, request, BRAND_ICON_PATH), dependencies);
  try {
    // SDK transport typings are not exactOptionalPropertyTypes-clean in this version.
    await server.connect(transport as Parameters<Server["connect"]>[0]);
    await transport.handleRequest(request as NodeRequestWithBody, response, parsedBody);
  } finally {
    await server.close();
  }
}

export function isMcpPost(request: IncomingMessage, mcpPath: string): boolean {
  return request.method === "POST" && request.url?.split("?")[0] === mcpPath;
}

export function isMcpGet(request: IncomingMessage, mcpPath: string): boolean {
  return request.method === "GET" && request.url?.split("?")[0] === mcpPath;
}

export function isMcpDelete(request: IncomingMessage, mcpPath: string): boolean {
  return request.method === "DELETE" && request.url?.split("?")[0] === mcpPath;
}

export async function readJsonBody(request: IncomingMessage, maxBytes: number, timeoutMs?: number): Promise<JSONRPCMessage | unknown> {
  const body = await readBoundedBody(request, maxBytes, timeoutMs);
  if (body.byteLength === 0) return undefined;
  return JSON.parse(body.toString("utf8")) as unknown;
}

function writeJsonRpcError(response: ServerResponse, statusCode: number, code: number, message: string): void {
  response.writeHead(statusCode, { "content-type": "application/json; charset=utf-8" });
  response.end(`${JSON.stringify({ jsonrpc: "2.0", error: { code, message }, id: null })}\n`);
}
