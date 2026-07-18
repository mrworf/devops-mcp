import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { authenticateRequest, buildAuthenticateChallenge, requireScopes } from "./auth.js";
import { handleBuiltinOAuthRequest, initializeBuiltinOAuthState, isBuiltinOAuthRequest } from "./builtinOAuth.js";
import { loadConfig } from "./config.js";
import { handleMcpRequest, isMcpGet, isMcpPost, readJsonBody } from "./mcp/server.js";
import { handleOAuthMetadataRequest, isOAuthMetadataRequest } from "./oauthMetadata.js";
import { createLogger } from "./logger.js";
import type { GatewayConfig } from "./types.js";
import type { AuthContext } from "./types.js";
import { initializeSecretRuntime } from "./secretRuntime.js";
import { RequestBodyError } from "./httpBody.js";
import { startMaintenance } from "./maintenance.js";
import { handleBrandAssetRequest, isBrandAssetRequest } from "./brandAssets.js";

type AuthenticatedRequest = IncomingMessage & { auth?: AuthContext };

export function createGatewayServer(config: GatewayConfig) {
  const logger = createLogger(config.logging);
  initializeBuiltinOAuthState(config);
  const stopMaintenance = startMaintenance(config);
  const server = createServer(async (request, response) => {
    if (request.method === "GET" && request.url === "/health") {
      logger.debug("http.health", { method: request.method, path: "/health", service_count: Object.keys(config.services).length });
      writeJson(response, 200, {
        status: "ready",
        service_count: Object.keys(config.services).length,
      });
      return;
    }

    if (isBrandAssetRequest(request)) {
      handleBrandAssetRequest(request, response);
      return;
    }

    if (isOAuthMetadataRequest(request)) {
      logger.debug("oauth.metadata_request", { method: request.method, path: request.url });
      handleOAuthMetadataRequest(config, request, response);
      return;
    }

    if (isBuiltinOAuthRequest(config, request)) {
      logger.debug("oauth.builtin_request", { method: request.method, path: request.url?.split("?")[0] });
      await handleBuiltinOAuthRequest(config, request, response);
      return;
    }

    if (isMcpPost(request, config.server.mcpPath)) {
      let requiredScopes = configuredMcpScopes(config);
      try {
        const auth = await authenticateRequest(request, config);
        const body = await readJsonBody(request, config.limits.maxInboundBodyBytes, config.limits.inboundBodyTimeoutMs);
        requiredScopes = requiredScopesForMcpBody(body);
        requireScopes(auth, requiredScopes);
        (request as AuthenticatedRequest).auth = auth;
        logger.debug("mcp.request_authenticated", {
          method: request.method,
          path: config.server.mcpPath,
          rpc: summarizeMcpBody(body),
          required_scopes: requiredScopes,
          subject: auth.subject,
          session_present: auth.sessionId !== undefined,
          auth_mode: auth.mode,
        });
        await handleMcpRequest(config, request, response, body);
      } catch (error) {
        if (error instanceof RequestBodyError) {
          response.setHeader("connection", "close");
          response.once("finish", () => request.destroy());
          writeJson(response, error.statusCode, { error: { code: error.code, message: error.message } });
          return;
        }
        if (error instanceof Error && error.name === "GatewayError") {
          logger.debug("mcp.request_rejected", {
            method: request.method,
            path: config.server.mcpPath,
            required_scopes: requiredScopes,
            error_code: "unauthenticated",
            message: error.message,
          });
          writeAuthError(response, buildAuthenticateChallenge(config, request, requiredScopes));
          return;
        }
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
      try {
        const auth = await authenticateRequest(request, config);
        (request as AuthenticatedRequest).auth = auth;
        logger.debug("mcp.request_authenticated", {
          method: request.method,
          path: config.server.mcpPath,
          required_scopes: [],
          subject: auth.subject,
          session_present: auth.sessionId !== undefined,
          auth_mode: auth.mode,
        });
      } catch (error) {
        if (error instanceof Error && error.name === "GatewayError") {
          logger.debug("mcp.request_rejected", {
            method: request.method,
            path: config.server.mcpPath,
            required_scopes: [],
            error_code: "unauthenticated",
            message: error.message,
          });
          writeAuthError(response, buildAuthenticateChallenge(config, request));
          return;
        }
        writeJson(response, 400, {
          error: {
            code: "invalid_request",
            message: "Invalid MCP request.",
          },
        });
        return;
      }
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
  server.once("close", stopMaintenance);
  return server;
}

function writeAuthError(response: ServerResponse, challenge: string): void {
  response.writeHead(401, {
    "content-type": "application/json; charset=utf-8",
    "www-authenticate": challenge,
  });
  response.end(`${JSON.stringify({
    error: {
      code: "unauthenticated",
      message: "Authentication required.",
    },
  })}\n`);
}

function requiredScopesForMcpBody(body: unknown): string[] {
  if (Array.isArray(body)) {
    return [...new Set(body.flatMap((message) => requiredScopesForMcpBody(message)))];
  }
  if (!body || typeof body !== "object") return [];
  const message = body as { method?: unknown; params?: { name?: unknown } };
  if (message.method === "tools/list") return ["gateway.read"];
  if (message.method !== "tools/call") return [];
  if (message.params?.name === "get_gateway_service_references") return ["gateway.references"];
  if (message.params?.name === "service_request") return ["gateway.request"];
  if (message.params?.name === "list_services" || message.params?.name === "describe_service_policy" || message.params?.name === "explain_denial") return ["gateway.read"];
  return [];
}

function configuredMcpScopes(config: GatewayConfig): string[] {
  if (config.auth.mode === "oauth") return config.auth.oauth.requiredScopes;
  if (config.auth.mode === "builtin_oauth") return config.auth.builtinOAuth.requiredScopes;
  return ["gateway.read", "gateway.references", "gateway.request"];
}

function writeJson(response: ServerResponse, statusCode: number, body: unknown): void {
  response.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
  });
  response.end(`${JSON.stringify(body)}\n`);
}

export async function startServer(config: GatewayConfig): Promise<void> {
  const server = createGatewayServer(config);
  const logger = createLogger(config.logging);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.server.port, config.server.host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  logger.info("server.started", {
    listen: config.server.listen,
    mcp_path: config.server.mcpPath,
  });
}

function summarizeMcpBody(body: unknown): Record<string, unknown> {
  const messages = Array.isArray(body) ? body : [body];
  const methods = messages
    .filter((message): message is { method?: unknown; params?: { name?: unknown } } => Boolean(message) && typeof message === "object")
    .map((message) => ({
      method: typeof message.method === "string" ? message.method : "unknown",
      ...(typeof message.params?.name === "string" ? { tool: message.params.name } : {}),
    }));
  return { message_count: methods.length, methods };
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
    initializeSecretRuntime(config);
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
