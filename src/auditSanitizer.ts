import { findHttpBasicCredentialRanges } from "./httpBasicCredential.js";
import type { AuditEvent } from "./audit.js";
import type { GatewayConfig } from "./types.js";

const REDACTED = "[REDACTED]";
const opaqueCandidatePattern = /\b(?:gref|sec)_[^\s"'<>()[\]{},;]+/g;
const credentialPatterns = [
  /\bgh[pousr]_[A-Za-z0-9_]{36,255}\b/g,
  /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
];
const structuralStringKeys = new Set([
  "type", "tool", "outcome", "service", "destination", "access_ids", "internal_reference_ids",
  "response_internal_reference_ids", "method", "policy_decision", "matched_policy_rule", "error_code",
  "request_id", "timestamp", "request_timestamp", "secret_rule_ids", "prefix",
]);

export function sanitizeAuditEvent(event: AuditEvent, config?: GatewayConfig): AuditEvent {
  const configuredSecrets = config === undefined
    ? []
    : [...new Set(Object.values(config.services).flatMap((service) => service.credentials.map((credential) => credential.secret)))]
      .filter((secret) => secret.length > 0)
      .sort((left, right) => right.length - left.length);
  return sanitizeValue(event, "", configuredSecrets) as AuditEvent;
}

function sanitizeValue(value: unknown, key: string, configuredSecrets: string[]): unknown {
  if (typeof value === "string") {
    return structuralStringKeys.has(key) ? value : sanitizeAuditText(value, configuredSecrets);
  }
  if (Array.isArray(value)) return value.map((item) => sanitizeValue(item, key, configuredSecrets));
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([entryKey, entryValue]) => [
      entryKey,
      sanitizeValue(entryValue, entryKey, configuredSecrets),
    ]));
  }
  return value;
}

function sanitizeAuditText(value: string, configuredSecrets: string[]): string {
  let sanitized = value;
  for (const secret of configuredSecrets) sanitized = sanitized.split(secret).join(REDACTED);
  sanitized = replaceRanges(sanitized, findHttpBasicCredentialRanges(sanitized));
  sanitized = sanitized.replace(opaqueCandidatePattern, REDACTED);
  for (const pattern of credentialPatterns) sanitized = sanitized.replace(pattern, REDACTED);
  return sanitized;
}

function replaceRanges(value: string, ranges: Array<{ start: number; end: number }>): string {
  let sanitized = value;
  for (const range of [...ranges].sort((left, right) => right.start - left.start)) {
    sanitized = `${sanitized.slice(0, range.start)}${REDACTED}${sanitized.slice(range.end)}`;
  }
  return sanitized;
}
