import { GatewayError } from "./errors.js";
import type { AuthContext, ServiceConfig } from "./types.js";
import type { TokenBroker, TokenInspectionReason } from "./tokens.js";

export const DEFAULT_BINARY_RESPONSE_MAX_BYTES = 100 * 1024;

const tokenCandidatePattern = /\b(?:gref|sec)_[^\s"'<>()[\]{},;]+/g;
const httpBasicCredentialPattern = /\bBasic +(?<encoded>(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)(?![A-Za-z0-9+/=])/gi;
const binarySignatures: Array<{ name: string; bytes: readonly number[] }> = [
  { name: "png", bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { name: "jpeg", bytes: [0xff, 0xd8, 0xff] },
  { name: "gif", bytes: [0x47, 0x49, 0x46, 0x38] },
  { name: "pdf", bytes: [0x25, 0x50, 0x44, 0x46, 0x2d] },
  { name: "zip", bytes: [0x50, 0x4b, 0x03, 0x04] },
  { name: "gzip", bytes: [0x1f, 0x8b] },
  { name: "elf", bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { name: "wasm", bytes: [0x00, 0x61, 0x73, 0x6d] },
];

export interface BodyClassification {
  kind: "text" | "binary";
  reason: "utf8_text" | "binary_signature" | "invalid_utf8" | "nul_byte" | "control_bytes";
}

export interface BinaryInspection {
  ruleIds: string[];
  warnings: Array<{ prefix: "gref" | "sec"; reason: TokenInspectionReason; count: number }>;
}

export function classifyResponseBody(body: Buffer): BodyClassification {
  if (binarySignatures.some((signature) => startsWith(body, signature.bytes))) {
    return { kind: "binary", reason: "binary_signature" };
  }
  if (body.includes(0)) return { kind: "binary", reason: "nul_byte" };
  try {
    decodeUtf8Bytes(body);
  } catch {
    return { kind: "binary", reason: "invalid_utf8" };
  }
  let controls = 0;
  for (const byte of body) {
    if ((byte < 0x20 && byte !== 0x09 && byte !== 0x0a && byte !== 0x0c && byte !== 0x0d) || byte === 0x7f) controls += 1;
  }
  if (body.length > 0 && controls / body.length > 0.01) return { kind: "binary", reason: "control_bytes" };
  return { kind: "text", reason: "utf8_text" };
}

export function decodeUtf8Bytes(body: Buffer): string {
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body);
}

export function isBinaryMediaType(headers: Record<string, string>): boolean {
  const value = Object.entries(headers).find(([name]) => name.toLowerCase() === "content-type")?.[1];
  const mimeType = value?.split(";", 1)[0]?.trim().toLowerCase();
  if (mimeType === undefined) return false;
  return mimeType === "application/octet-stream"
    || mimeType === "application/pdf"
    || mimeType === "application/zip"
    || mimeType.startsWith("image/")
    || mimeType.startsWith("audio/")
    || mimeType.startsWith("video/")
    || mimeType.startsWith("font/");
}

export function responseMimeType(headers: Record<string, string>): string {
  const value = Object.entries(headers).find(([name]) => name.toLowerCase() === "content-type")?.[1];
  return value?.split(";", 1)[0]?.trim().toLowerCase() || "application/octet-stream";
}

export function inspectBinaryBody(
  body: Buffer,
  broker: TokenBroker,
  auth: AuthContext,
  service: ServiceConfig,
): BinaryInspection {
  const ruleIds = new Set<string>();
  for (const credential of service.credentials) {
    for (const value of [credential.secret, JSON.stringify(credential.secret).slice(1, -1)]) {
      if (value.length > 0 && body.indexOf(Buffer.from(value, "utf8")) >= 0) ruleIds.add("gateway:configured-credential");
    }
  }

  const projected = body.toString("latin1");
  for (const match of projected.matchAll(httpBasicCredentialPattern)) {
    const encoded = match.groups?.encoded;
    if (encoded && isValidHttpBasic(encoded)) ruleIds.add("gateway:http-basic-credential");
  }

  const warnings = new Map<string, { prefix: "gref" | "sec"; reason: TokenInspectionReason; count: number }>();
  for (const match of projected.matchAll(tokenCandidatePattern)) {
    const candidate = match[0];
    const inspection = broker.inspectResponseToken(auth, service.id, candidate);
    if (inspection.valid) continue;
    ruleIds.add("gateway:invalid-opaque-prefix");
    const prefix = candidate.startsWith("gref_") ? "gref" : "sec";
    const key = `${prefix}:${inspection.reason}`;
    const existing = warnings.get(key);
    if (existing) existing.count += 1;
    else warnings.set(key, { prefix, reason: inspection.reason, count: 1 });
  }
  return { ruleIds: [...ruleIds].sort(), warnings: [...warnings.values()] };
}

export function assertSafeBinaryBody(inspection: BinaryInspection, requestId: string): void {
  if (inspection.ruleIds.length > 0) {
    throw new GatewayError("secret_scan_failed", "Binary response contains protected data.", requestId);
  }
}

function startsWith(body: Buffer, signature: readonly number[]): boolean {
  return body.length >= signature.length && signature.every((byte, index) => body[index] === byte);
}

function isValidHttpBasic(encoded: string): boolean {
  const decoded = Buffer.from(encoded, "base64");
  if (decoded.toString("base64") !== encoded) return false;
  const separator = decoded.indexOf(0x3a);
  return separator > 0 && separator < decoded.length - 1;
}
