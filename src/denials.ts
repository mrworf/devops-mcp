import { randomUUID } from "node:crypto";

export interface DenialRecord {
  request_id: string;
  subject: string;
  session_id?: string;
  reason: string;
  matched_rule?: string;
  policy_mode: "allow" | "deny";
  suggestion?: string;
}

export class DenialStore {
  private readonly records = new Map<string, DenialRecord>();

  record(input: Omit<DenialRecord, "request_id">): DenialRecord {
    const requestId = `req_${randomUUID()}`;
    const record: DenialRecord = {
      request_id: requestId,
      subject: input.subject,
      ...(input.session_id === undefined ? {} : { session_id: input.session_id }),
      reason: input.reason,
      policy_mode: input.policy_mode,
      ...(input.matched_rule === undefined ? {} : { matched_rule: input.matched_rule }),
      ...(input.suggestion === undefined ? {} : { suggestion: input.suggestion }),
    };
    this.records.set(requestId, record);
    return record;
  }

  get(requestId: string): DenialRecord | undefined {
    return this.records.get(requestId);
  }
}

export const denialStore = new DenialStore();

export interface DenialExplanation {
  request_id: string;
  reason: string;
  matched_rule?: string;
  policy_mode: "allow" | "deny";
  suggestion?: string;
}

export function explainDenial(auth: { subject: string; sessionId?: string }, requestId: string): DenialExplanation | undefined {
  const record = denialStore.get(requestId);
  if (!record) return undefined;
  if (record.subject !== auth.subject) return undefined;
  if (record.session_id !== undefined && record.session_id !== auth.sessionId) return undefined;
  return {
    request_id: record.request_id,
    reason: record.reason,
    ...(record.matched_rule === undefined ? {} : { matched_rule: record.matched_rule }),
    policy_mode: record.policy_mode,
    ...(record.suggestion === undefined ? {} : { suggestion: record.suggestion }),
  };
}
