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

export function tokenIssuedAuditEvent(input: TokenIssuedAuditEvent): TokenIssuedAuditEvent {
  return input;
}
