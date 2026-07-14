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
  redaction_count: number;
  error_code?: string;
  error_message?: string;
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

export type AuditEvent = TokenIssuedAuditEvent | ServiceRequestAuditEvent | ToolInvocationAuditEvent;

export const auditEvents: AuditEvent[] = [];

export function audit(event: AuditEvent, config?: GatewayConfig): void {
  auditEvents.push(event);
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

export function tokenIssuedAuditEvent(input: TokenIssuedAuditEvent, config?: GatewayConfig): TokenIssuedAuditEvent {
  audit(input, config);
  return input;
}
