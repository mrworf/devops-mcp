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

export type AuditEvent = TokenIssuedAuditEvent | ServiceRequestAuditEvent;

export const auditEvents: AuditEvent[] = [];

export function audit(event: AuditEvent): void {
  auditEvents.push(event);
}

export function tokenIssuedAuditEvent(input: TokenIssuedAuditEvent): TokenIssuedAuditEvent {
  audit(input);
  return input;
}
