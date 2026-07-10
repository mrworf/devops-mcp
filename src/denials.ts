import { randomUUID } from "node:crypto";

export interface DenialRecord {
  request_id: string;
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
