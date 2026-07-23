import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { authenticateRequest, buildAuthenticateChallenge, requireScopes } from "./auth.js";
import { handleBuiltinOAuthRequest, isBuiltinOAuthRequest } from "./builtinOAuth.js";
import { loadConfig } from "./config.js";
import { handleMcpRequest, isMcpDelete, isMcpGet, isMcpPost, readJsonBody } from "./mcp/server.js";
import { handleOAuthMetadataRequest, isOAuthMetadataRequest } from "./oauthMetadata.js";
import { createLogger } from "./logger.js";
import type { GatewayConfig } from "./types.js";
import type { AuthContext } from "./types.js";
import { RequestBodyError } from "./httpBody.js";
import { handleBrandAssetRequest, isBrandAssetRequest } from "./brandAssets.js";
import { GatewayError, type ConfigDiagnostic } from "./errors.js";
import type { AuditSink } from "./audit.js";
import { GatewayRuntime } from "./runtime.js";
import { requiredScopeForTool } from "./mcp/tools.js";

type AuthenticatedRequest = IncomingMessage & { auth?: AuthContext };

export function createGatewayServer(
  config: GatewayConfig,
  options: { auditSink?: AuditSink; runtime?: GatewayRuntime; closeRuntimeOnServerClose?: boolean } = {},
) {
  const logger = createLogger(config.logging);
  for (const message of config.warnings) {
    logger.warn("config.warning", { message });
  }
  for (const diagnostic of config.debugDiagnostics) {
    logger.debug("config.credential_source_contains_whitespace", {
      service: diagnostic.serviceId,
      access_id: diagnostic.credentialId,
      suggestion: "Store only the credential value and describe static request syntax with usage prefix or suffix.",
    });
  }
  const runtime = options.runtime ?? new GatewayRuntime(config, { ...(options.auditSink === undefined ? {} : { auditSink: options.auditSink }) });
  const auditSink = runtime.auditSink;
  const server = createServer(async (request, response) => {
    if (request.method === "GET" && request.url === "/health") {
      logger.debug("http.health", { method: request.method, path: "/health", service_count: Object.keys(config.services).length });
      writeJson(response, auditSink.degraded ? 503 : 200, {
        status: auditSink.degraded ? "not_ready" : "ready",
        service_count: Object.keys(config.services).length,
        ...(auditSink.degraded ? { checks: { audit: "degraded" } } : {}),
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
      await handleBuiltinOAuthRequest(config, request, response, runtime.builtinOAuth);
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
          auth_mode: auth.mode,
        });
        await handleMcpRequest(config, request, response, body, {
          auditSink: runtime.auditSink,
          capabilities: runtime.capabilities,
          secretRuntime: runtime.secretRuntime,
        });
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

    if (isMcpGet(request, config.server.mcpPath) || isMcpDelete(request, config.server.mcpPath)) {
      try {
        const auth = await authenticateRequest(request, config);
        (request as AuthenticatedRequest).auth = auth;
        logger.debug("mcp.request_authenticated", {
          method: request.method,
          path: config.server.mcpPath,
          required_scopes: [],
          subject: auth.subject,
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
      writeJson(response, 405, {
        error: {
          code: "method_not_allowed",
          message: "Stateless MCP supports POST requests only.",
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
  if (options.closeRuntimeOnServerClose !== false) {
    server.once("close", () => {
      void runtime.close().catch(() => logger.error("runtime.close_failed"));
    });
  }
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
  const scope = requiredScopeForTool(message.params?.name);
  return scope === undefined ? [] : [scope];
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

export interface GatewayApplication {
  server: Server;
  runtime: GatewayRuntime;
  close(): Promise<void>;
}

export async function startServer(config: GatewayConfig): Promise<GatewayApplication> {
  const runtime = new GatewayRuntime(config);
  let server: ReturnType<typeof createGatewayServer>;
  const logger = createLogger(config.logging);
  try {
    server = createGatewayServer(config, { runtime, closeRuntimeOnServerClose: false });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(config.server.port, config.server.host, () => {
        server.off("error", reject);
        resolve();
      });
    });
  } catch (error) {
    await runtime.close();
    throw error;
  }
  logger.info("server.started", {
    listen: config.server.listen,
    mcp_path: config.server.mcpPath,
  });
  let closePromise: Promise<void> | undefined;
  return {
    server,
    runtime,
    close: () => {
      closePromise ??= (async () => {
        await closeHttpServer(server);
        await runtime.close();
      })();
      return closePromise;
    },
  };
}

function closeHttpServer(server: Server): Promise<void> {
  if (!server.listening) return Promise.resolve();
  return new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

interface SignalTarget {
  once(event: NodeJS.Signals, listener: (signal: NodeJS.Signals) => void): unknown;
  off(event: NodeJS.Signals, listener: (signal: NodeJS.Signals) => void): unknown;
  exitCode: string | number | null | undefined;
}

export function installShutdownSignalHandlers(
  application: Pick<GatewayApplication, "close">,
  logger: ReturnType<typeof createLogger>,
  signalTarget: SignalTarget = process,
): { uninstall(): void; completion(): Promise<void> | undefined } {
  let shutdown: Promise<void> | undefined;
  const uninstall = () => {
    signalTarget.off("SIGTERM", handleSignal);
    signalTarget.off("SIGINT", handleSignal);
  };
  const handleSignal = (signal: NodeJS.Signals) => {
    shutdown ??= application.close()
      .then(() => {
        logger.info("runtime.shutdown_completed", { signal });
        signalTarget.exitCode = 0;
      })
      .catch((error: unknown) => {
        logger.error("runtime.shutdown_failed", {
          signal,
          error_type: error instanceof Error ? error.name : "UnknownError",
        });
        signalTarget.exitCode = 1;
      })
      .finally(uninstall);
  };
  signalTarget.once("SIGTERM", handleSignal);
  signalTarget.once("SIGINT", handleSignal);
  return { uninstall, completion: () => shutdown };
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

export function startupErrorPayload(error: unknown): Record<string, unknown> {
  const gatewayError = error instanceof GatewayError ? error : undefined;
  const message = error instanceof Error ? error.message : "Unknown startup error.";
  return {
    level: "error",
    error: {
      code: gatewayError?.code ?? "config_error",
      message,
      ...(gatewayError?.diagnostics === undefined ? {} : {
        diagnostics: gatewayError.diagnostics.map(publicConfigDiagnostic),
      }),
    },
  };
}

function publicConfigDiagnostic(diagnostic: ConfigDiagnostic): Omit<ConfigDiagnostic, "configPath"> {
  const { configPath: _configPath, ...publicDiagnostic } = diagnostic;
  return publicDiagnostic;
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
    const application = await startServer(config);
    installShutdownSignalHandlers(application, createLogger(config.logging));
  } catch (error) {
    console.error(JSON.stringify(startupErrorPayload(error)));
    process.exit(1);
  }
}
