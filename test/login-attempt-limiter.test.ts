import { describe, expect, it } from "vitest";
import { LoginAttemptLimiter } from "../src/loginAttemptLimiter.js";

describe("login attempt limiter", () => {
  it("enforces source, account, and global thresholds", () => {
    let now = 0;
    const limiter = new LoginAttemptLimiter(limits(), () => now);
    limiter.recordFailure("source-a", "account-a");
    expect(limiter.check("source-a", "other").allowed).toBe(true);
    limiter.recordFailure("source-a", "account-b");
    expect(limiter.check("source-a", "other")).toEqual({ allowed: false, retryAfterMs: 100 });

    now = 101;
    limiter.recordFailure("source-b", "shared");
    limiter.recordFailure("source-c", "shared");
    expect(limiter.check("source-d", "shared").allowed).toBe(false);

    now = 202;
    limiter.recordFailure("source-d", "account-d");
    limiter.recordFailure("source-e", "account-e");
    expect(limiter.check("source-e", "account-e").allowed).toBe(false);
  });

  it("resets on success and doubles repeated lockouts up to the maximum", () => {
    let now = 0;
    const limiter = new LoginAttemptLimiter(limits(), () => now);
    limiter.recordFailure("source", "account");
    limiter.recordSuccess("source", "account");
    expect(limiter.check("source", "account").allowed).toBe(true);

    limiter.recordFailure("source", "account");
    limiter.recordFailure("source", "account");
    expect(limiter.check("source", "account")).toEqual({ allowed: false, retryAfterMs: 100 });
    now = 101;
    limiter.recordFailure("source", "account");
    limiter.recordFailure("source", "account");
    expect(limiter.check("source", "account")).toEqual({ allowed: false, retryAfterMs: 200 });
  });
});

function limits() {
  return {
    windowMs: 1_000, perSource: 2, perAccount: 2, global: 6,
    initialLockoutMs: 100, maxLockoutMs: 400, maxEntries: 3,
  };
}
