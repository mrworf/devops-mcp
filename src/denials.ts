import { registerMaintenanceTask } from "./maintenance.js";
import { createRequestId } from "./requestId.js";
import type { GatewayConfig } from "./types.js";

export interface DenialRecord {
  request_id: string;
  subject: string;
  reason: string;
  matched_rule?: string;
  policy_mode: "allow" | "deny";
  suggestion?: string;
}

export class DenialStore {
  private readonly records = new Map<string, DenialRecord & { expiresAt: number }>();

  constructor(
    private readonly capacity = 1000,
    private readonly ttlMs = 15 * 60_000,
    private readonly now: () => number = () => Date.now(),
  ) {}

  record(input: Omit<DenialRecord, "request_id">, requestId = createRequestId()): DenialRecord {
    this.sweep(this.now());
    if (this.records.size >= this.capacity) {
      const oldest = this.records.keys().next().value as string | undefined;
      if (oldest !== undefined) this.records.delete(oldest);
    }
    const record: DenialRecord & { expiresAt: number } = {
      request_id: requestId,
      subject: input.subject,
      reason: input.reason,
      policy_mode: input.policy_mode,
      ...(input.matched_rule === undefined ? {} : { matched_rule: input.matched_rule }),
      ...(input.suggestion === undefined ? {} : { suggestion: input.suggestion }),
      expiresAt: this.now() + this.ttlMs,
    };
    this.records.set(requestId, record);
    return record;
  }

  get(requestId: string): DenialRecord | undefined {
    const record = this.records.get(requestId);
    if (record === undefined) return undefined;
    if (record.expiresAt <= this.now()) {
      this.records.delete(requestId);
      return undefined;
    }
    this.records.delete(requestId);
    this.records.set(requestId, record);
    const { expiresAt: _expiresAt, ...result } = record;
    return result;
  }

  sweep(now = this.now()): void {
    for (const [requestId, record] of this.records) if (record.expiresAt <= now) this.records.delete(requestId);
  }
}

const denialStores = new WeakMap<GatewayConfig, DenialStore>();

export function getDenialStore(config: GatewayConfig): DenialStore {
  let store = denialStores.get(config);
  if (store === undefined) {
    store = new DenialStore(config.limits.maxDenialRecords, config.limits.denialTtlMs);
    denialStores.set(config, store);
    registerMaintenanceTask(config, (now) => store?.sweep(now));
  }
  return store;
}

export interface DenialExplanation {
  request_id: string;
  reason: string;
  matched_rule?: string;
  policy_mode: "allow" | "deny";
  suggestion?: string;
}

export function explainDenial(config: GatewayConfig, auth: { subject: string }, requestId: string): DenialExplanation | undefined {
  const record = getDenialStore(config).get(requestId);
  if (!record) return undefined;
  if (record.subject !== auth.subject) return undefined;
  return {
    request_id: record.request_id,
    reason: record.reason,
    ...(record.matched_rule === undefined ? {} : { matched_rule: record.matched_rule }),
    policy_mode: record.policy_mode,
    ...(record.suggestion === undefined ? {} : { suggestion: record.suggestion }),
  };
}
