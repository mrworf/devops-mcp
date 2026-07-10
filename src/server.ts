import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { loadConfig } from "./config.js";
import { handleMcpRequest, isMcpGet, isMcpPost, readJsonBody } from "./mcp/server.js";
import type { GatewayConfig } from "./types.js";

export function createGatewayServer(config: GatewayConfig) {
  return createServer(async (request, response) => {
    if (request.method === "GET" && request.url === "/health") {
      writeJson(response, 200, {
        status: "ready",
        service_count: Object.keys(config.services).length,
      });
      return;
    }

    if (isMcpPost(request, config.server.mcpPath)) {
      try {
        const body = await readJsonBody(request);
        await handleMcpRequest(request, response, body);
      } catch {
        writeJson(response, 400, {
          error: {
            code: "invalid_request",
            message: "Invalid MCP request.",
          },
        });
      }
      return;
    }

    if (isMcpGet(request, config.server.mcpPath)) {
      writeJson(response, 400, {
        error: {
          code: "invalid_request",
          message: "MCP session streaming is not available before initialization.",
        },
      });
      return;
    }

    writeJson(response, 404, {
      error: {
        code: "not_found",
        message: "Not found.",
      },
    });
  });
}

function writeJson(response: ServerResponse, statusCode: number, body: unknown): void {
  response.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
  });
  response.end(`${JSON.stringify(body)}\n`);
}

export async function startServer(config: GatewayConfig): Promise<void> {
  const server = createGatewayServer(config);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.server.port, config.server.host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  console.log(JSON.stringify({
    level: "info",
    message: "gateway server started",
    listen: config.server.listen,
    mcp_path: config.server.mcpPath,
  }));
}

export function requestBody(_request: IncomingMessage): never {
  throw new Error("Request body handling is not implemented in milestone 01.");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const configPath = process.env.CONFIG_PATH;
  if (!configPath) {
    console.error(JSON.stringify({
      level: "error",
      error: {
        code: "config_error",
        message: "CONFIG_PATH is required.",
      },
    }));
    process.exit(1);
  }

  try {
    const config = loadConfig(configPath);
    await startServer(config);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown startup error.";
    console.error(JSON.stringify({
      level: "error",
      error: {
        code: "config_error",
        message,
      },
    }));
    process.exit(1);
  }
}
