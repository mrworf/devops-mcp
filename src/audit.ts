import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { createLogger } from "./logger.js";
import type { GatewayConfig } from "./types.js";

export interface TokenIssuedAuditEvent {
  type: "token_issued";
  subject: string;
  session_id?: string;
  service: string;
  destination: string;
  credential_ids: string[];
  internal_token_ids: string[];
  reason: string;
  timestamp: string;
}

export interface ServiceRequestAuditEvent {
  type: "service_request";
  request_id: string;
  subject: string;
  session_id?: string;
  service: string;
  destination: string;
  credential_ids: string[];
  internal_token_ids: string[];
  method: string;
  target_host: string;
  target_path: string;
  policy_decision: "allow" | "deny";
  matched_policy_rule?: string;
  downstream_status_code?: number;
  request_timestamp: string;
  request_duration_ms: number;
  tls_verify: boolean;
  secret_tokenization_count: number;
  secret_rule_ids?: string[];
  response_internal_token_ids?: string[];
  error_code?: string;
  error_message?: string;
}

export interface InvalidOpaqueResponseTokensAuditEvent {
  type: "invalid_opaque_response_tokens";
  request_id: string;
  subject: string;
  session_id?: string;
  service: string;
  destination: string;
  warnings: Array<{ prefix: "gref" | "sec"; reason: "unknown" | "expired" | "wrong_subject" | "wrong_service"; count: number }>;
  timestamp: string;
}

export interface ToolInvocationAuditEvent {
  type: "tool_invocation";
  subject: string;
  session_id?: string;
  tool: "list_services" | "describe_service_policy" | "request_tokens" | "service_request" | "explain_denial";
  outcome: "allow" | "deny" | "error";
  service?: string;
  request_id?: string;
  error_code?: string;
  timestamp: string;
}

export type AuditEvent = TokenIssuedAuditEvent | ServiceRequestAuditEvent | ToolInvocationAuditEvent | InvalidOpaqueResponseTokensAuditEvent;

const auditEventStores = new WeakMap<GatewayConfig, AuditEvent[]>();
const fallbackAuditEvents: AuditEvent[] = [];

export function getAuditEvents(config?: GatewayConfig): readonly AuditEvent[] {
  return config === undefined ? fallbackAuditEvents : auditEventStores.get(config) ?? [];
}

export function clearAuditEvents(config?: GatewayConfig): void {
  if (config === undefined) fallbackAuditEvents.length = 0;
  else auditEventStores.delete(config);
}

export function audit(event: AuditEvent, config?: GatewayConfig): void {
  const events = auditStore(config);
  events.push(event);
  const capacity = config?.audit.memoryEvents ?? 1000;
  if (events.length > capacity) events.splice(0, events.length - capacity);
  if (config?.audit.file === undefined) return;
  try {
    mkdirSync(dirname(config.audit.file), { recursive: true });
    appendFileSync(config.audit.file, `${JSON.stringify(event)}\n`, { encoding: "utf8" });
  } catch (error) {
    createLogger(config.logging).error("audit.write_failed", {
      audit_file: config.audit.file,
      error,
    });
  }
}

function auditStore(config?: GatewayConfig): AuditEvent[] {
  if (config === undefined) return fallbackAuditEvents;
  let events = auditEventStores.get(config);
  if (events === undefined) {
    events = [];
    auditEventStores.set(config, events);
  }
  return events;
}

export function tokenIssuedAuditEvent(input: TokenIssuedAuditEvent, config?: GatewayConfig): TokenIssuedAuditEvent {
  audit(input, config);
  return input;
}
