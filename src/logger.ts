import type { LoggingConfig } from "./types.js";

export type LogSink = (line: string) => void;

export interface Logger {
  debug(event: string, fields?: Record<string, unknown>): void;
  info(event: string, fields?: Record<string, unknown>): void;
  warn(event: string, fields?: Record<string, unknown>): void;
  error(event: string, fields?: Record<string, unknown>): void;
}

const sensitiveKeyPattern = /(^|[_-])(authorization|cookie|set-cookie|secret|password|api[-_]?key|access[-_]?token|refresh[-_]?token|bearer[-_]?token|opaque[-_]?token|raw[-_]?token|token[-_]?value|credential[-_]?value|body)(s|[_-]|$)/i;
const sensitiveHeaderNames = new Set(["authorization", "cookie", "set-cookie", "proxy-authorization"]);

export function createLogger(config: LoggingConfig, sink: LogSink = console.log): Logger {
  return {
    debug: (event, fields) => write("debug", event, fields, config, sink),
    info: (event, fields) => write("info", event, fields, config, sink),
    warn: (event, fields) => write("warn", event, fields, config, sink),
    error: (event, fields) => write("error", event, fields, config, sink),
  };
}

export function headerNames(headers: Record<string, unknown> | undefined): string[] {
  return Object.keys(headers ?? {})
    .filter((name) => !sensitiveHeaderNames.has(name.toLowerCase()))
    .sort();
}

export function bodySummary(body: unknown): Record<string, unknown> {
  if (body === undefined || body === null) return { present: false };
  if (typeof body === "string") return { present: true, type: "string", bytes: Buffer.byteLength(body) };
  if (Buffer.isBuffer(body)) return { present: true, type: "buffer", bytes: body.byteLength };
  if (typeof body === "object") return { present: true, type: Array.isArray(body) ? "array" : "object" };
  return { present: true, type: typeof body };
}

export function sanitizeLogFields(value: unknown, key = ""): unknown {
  if (isSensitiveKey(key)) return "[REDACTED]";
  if (value === undefined) return undefined;
  if (value === null || typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map((item) => sanitizeLogFields(item));
  if (value instanceof Error) return { name: value.name, message: value.message };
  if (typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([entryKey, entryValue]) => [
      entryKey,
      sanitizeLogFields(entryValue, entryKey),
    ]));
  }
  return String(value);
}

function isSensitiveKey(key: string): boolean {
  const normalized = key.toLowerCase().replaceAll("-", "_");
  return normalized === "token" || normalized === "tokens" || sensitiveKeyPattern.test(key);
}

function write(
  level: "debug" | "info" | "warn" | "error",
  event: string,
  fields: Record<string, unknown> | undefined,
  config: LoggingConfig,
  sink: LogSink,
): void {
  if (level === "debug" && config.level !== "debug") return;

  sink(JSON.stringify({
    timestamp: new Date().toISOString(),
    level,
    event,
    ...(fields === undefined ? {} : sanitizeLogFields(fields) as Record<string, unknown>),
  }));
}
