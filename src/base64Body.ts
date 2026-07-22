import { GatewayError, type GatewayErrorCode } from "./errors.js";
import { decodeUtf8 } from "./secretScanner.js";

type Base64BodyDirection = "request" | "response";

export function decodeDeclaredBase64Body(
  headers: Record<string, string>,
  body: unknown,
  direction: Base64BodyDirection,
): string | undefined {
  const declarations = Object.entries(headers).filter(([name]) => name.toLowerCase() === "content-transfer-encoding");
  if (declarations.length === 0) return undefined;
  if (declarations.length !== 1 || declarations[0]?.[1].trim().toLowerCase() !== "base64") {
    throw new GatewayError("unsupported_transfer_encoding", "Unsupported or conflicting Content-Transfer-Encoding.");
  }
  if (typeof body !== "string") {
    throw new GatewayError(errorCode(direction), `Base64 ${direction} body must be a string.`);
  }

  const normalized = body.replace(/[\t\n\f\r ]/g, "");
  if (!isCanonicalBase64Shape(normalized)) {
    const label = direction === "response" ? "Response" : "Request";
    throw new GatewayError(errorCode(direction), `${label} body is not valid Base64.`);
  }
  try {
    return decodeUtf8(Buffer.from(normalized, "base64"));
  } catch {
    throw new GatewayError(errorCode(direction), `Base64 ${direction} body is not valid UTF-8.`);
  }
}

export function encodeBase64Body(body: string): string {
  return Buffer.from(body, "utf8").toString("base64");
}

export function decodeDeclaredBase64Bytes(
  headers: Record<string, string>,
  body: Buffer,
): Buffer | undefined {
  const declarations = Object.entries(headers).filter(([name]) => name.toLowerCase() === "content-transfer-encoding");
  if (declarations.length === 0) return undefined;
  if (declarations.length !== 1 || declarations[0]?.[1].trim().toLowerCase() !== "base64") {
    throw new GatewayError("unsupported_transfer_encoding", "Unsupported or conflicting Content-Transfer-Encoding.");
  }
  const projected = body.toString("latin1");
  if (!/^[\x00-\x7f]*$/.test(projected)) throw new GatewayError("secret_scan_failed", "Response body is not valid Base64.");
  const normalized = projected.replace(/[\t\n\f\r ]/g, "");
  if (!isCanonicalBase64Shape(normalized)) throw new GatewayError("secret_scan_failed", "Response body is not valid Base64.");
  return Buffer.from(normalized, "base64");
}

export function encodeBase64Bytes(body: Buffer): Buffer {
  return Buffer.from(body.toString("base64"), "ascii");
}

function errorCode(direction: Base64BodyDirection): GatewayErrorCode {
  return direction === "response" ? "secret_scan_failed" : "unsupported_transfer_encoding";
}

function isCanonicalBase64Shape(value: string): boolean {
  if (value === "") return true;
  return /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value);
}
