interface InitializationRecord {
  count: number;
  windowStartedAt: number;
  lastSeenAt: number;
}

export class McpInitializationLimiter {
  private readonly records = new Map<string, InitializationRecord>();

  constructor(
    private readonly maxPerSubject: number,
    private readonly windowMs: number,
    private readonly maxRecords: number,
  ) {}

  admit(subject: string, now: number): { allowed: true } | { allowed: false; retryAfterMs: number } {
    this.sweep(now);
    let record = this.records.get(subject);
    if (record === undefined) {
      if (this.records.size >= this.maxRecords) this.evictOldest();
      record = { count: 0, windowStartedAt: now, lastSeenAt: now };
      this.records.set(subject, record);
    } else if (now - record.windowStartedAt >= this.windowMs) {
      record.count = 0;
      record.windowStartedAt = now;
    }
    record.lastSeenAt = now;
    this.records.delete(subject);
    this.records.set(subject, record);
    if (record.count >= this.maxPerSubject) {
      return { allowed: false, retryAfterMs: Math.max(1, record.windowStartedAt + this.windowMs - now) };
    }
    record.count += 1;
    return { allowed: true };
  }

  sweep(now: number): void {
    for (const [subject, record] of this.records) {
      if (record.windowStartedAt + this.windowMs <= now) this.records.delete(subject);
    }
  }

  private evictOldest(): void {
    const oldest = this.records.keys().next().value as string | undefined;
    if (oldest !== undefined) this.records.delete(oldest);
  }
}
