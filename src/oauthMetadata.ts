import type { IncomingMessage, ServerResponse } from "node:http";
import { protectedResourceMetadata } from "./auth.js";
import type { GatewayConfig } from "./types.js";

export const OAUTH_PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource";

export function isOAuthMetadataRequest(request: IncomingMessage): boolean {
  return request.method === "GET" && request.url?.split("?")[0] === OAUTH_PROTECTED_RESOURCE_PATH;
}

export function handleOAuthMetadataRequest(config: GatewayConfig, request: IncomingMessage, response: ServerResponse): void {
  response.writeHead(200, { "content-type": "application/json; charset=utf-8" });
  response.end(`${JSON.stringify(protectedResourceMetadata(config, request))}\n`);
}
