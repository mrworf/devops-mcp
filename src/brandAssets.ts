import { readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { GatewayConfig } from "./types.js";

export const BRAND_ICON_PATH = "/assets/brand/secretsauce-icon.png";
export const BRAND_LOCKUP_PATH = "/assets/brand/secretsauce-lockup.png";

const BRAND_ASSETS = new Map<string, Buffer>([
  [BRAND_ICON_PATH, readFileSync(new URL("../assets/brand/secretsauce-icon.png", import.meta.url))],
  [BRAND_LOCKUP_PATH, readFileSync(new URL("../assets/brand/secretsauce-lockup.png", import.meta.url))],
]);

export function isBrandAssetRequest(request: IncomingMessage): boolean {
  return request.method === "GET" && BRAND_ASSETS.has(request.url?.split("?")[0] ?? "");
}

export function handleBrandAssetRequest(request: IncomingMessage, response: ServerResponse): void {
  const asset = BRAND_ASSETS.get(request.url?.split("?")[0] ?? "");
  if (asset === undefined) throw new Error("Expected an allowlisted brand asset request");
  response.writeHead(200, {
    "cache-control": "public, max-age=86400",
    "content-length": asset.byteLength,
    "content-type": "image/png",
    "x-content-type-options": "nosniff",
  });
  response.end(asset);
}

export function publicBrandAssetUrl(config: GatewayConfig, request: IncomingMessage, path: string): string {
  const origin = config.server.resource ?? `http://${request.headers.host ?? "localhost"}`;
  return new URL(path, origin).href;
}
