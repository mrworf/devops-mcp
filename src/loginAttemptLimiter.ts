export interface LoginAttemptLimits {
  windowMs: number;
  perSource: number;
  perAccount: number;
  global: number;
  initialLockoutMs: number;
  maxLockoutMs: number;
  maxEntries: number;
}

interface Counter {
  count: number;
  windowStartedAt: number;
  lockoutUntil: number;
  lockoutLevel: number;
  lastSeenAt: number;
}

export class LoginAttemptLimiter {
  private readonly sources = new Map<string, Counter>();
  private readonly accounts = new Map<string, Counter>();
  private readonly globalCounter: Counter;

  constructor(private readonly limits: LoginAttemptLimits, private readonly now: () => number = () => Date.now()) {
    this.globalCounter = this.newCounter(this.now());
  }

  check(source: string, account: string): { allowed: true } | { allowed: false; retryAfterMs: number } {
    const now = this.now();
    this.sweep(now);
    const blockedUntil = Math.max(
      this.sources.get(source)?.lockoutUntil ?? 0,
      this.accounts.get(account)?.lockoutUntil ?? 0,
      this.globalCounter.lockoutUntil,
    );
    return blockedUntil > now ? { allowed: false, retryAfterMs: blockedUntil - now } : { allowed: true };
  }

  recordFailure(source: string, account: string): void {
    const now = this.now();
    this.increment(this.getCounter(this.sources, source, now), this.limits.perSource, now);
    this.increment(this.getCounter(this.accounts, account, now), this.limits.perAccount, now);
    this.increment(this.globalCounter, this.limits.global, now);
  }

  recordSuccess(source: string, account: string): void {
    this.sources.delete(source);
    this.accounts.delete(account);
  }

  private getCounter(store: Map<string, Counter>, key: string, now: number): Counter {
    const existing = store.get(key);
    if (existing !== undefined) return existing;
    if (store.size >= this.limits.maxEntries) {
      const oldest = [...store.entries()].sort((left, right) => left[1].lastSeenAt - right[1].lastSeenAt)[0];
      if (oldest !== undefined) store.delete(oldest[0]);
    }
    const created = this.newCounter(now);
    store.set(key, created);
    return created;
  }

  private increment(counter: Counter, threshold: number, now: number): void {
    if (now - counter.windowStartedAt >= this.limits.windowMs) {
      counter.count = 0;
      counter.windowStartedAt = now;
    }
    counter.count += 1;
    counter.lastSeenAt = now;
    if (counter.count < threshold) return;
    const duration = Math.min(this.limits.initialLockoutMs * (2 ** counter.lockoutLevel), this.limits.maxLockoutMs);
    counter.lockoutUntil = now + duration;
    counter.lockoutLevel += 1;
    counter.count = 0;
    counter.windowStartedAt = counter.lockoutUntil;
  }

  private sweep(now: number): void {
    const staleBefore = now - this.limits.windowMs - this.limits.maxLockoutMs;
    for (const [key, counter] of this.sources) if (counter.lastSeenAt < staleBefore && counter.lockoutUntil <= now) this.sources.delete(key);
    for (const [key, counter] of this.accounts) if (counter.lastSeenAt < staleBefore && counter.lockoutUntil <= now) this.accounts.delete(key);
    if (this.globalCounter.lockoutUntil <= now && now - this.globalCounter.windowStartedAt >= this.limits.windowMs) {
      this.globalCounter.count = 0;
      this.globalCounter.windowStartedAt = now;
    }
  }

  private newCounter(now: number): Counter {
    return { count: 0, windowStartedAt: now, lockoutUntil: 0, lockoutLevel: 0, lastSeenAt: now };
  }
}
