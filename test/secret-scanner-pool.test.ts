import { describe, expect, it } from "vitest";
import { SecretScanBusyError, SecretScannerPool, loadSecretScannerPoolConfig } from "../src/secretScannerPool.js";

const githubRule = [{ id: "@secretlint/secretlint-rule-github" as const }];

describe("Secretlint worker pool", () => {
  it("scans with persistent bounded workers for different subjects", async () => {
    const pool = new SecretScannerPool({ workers: 2, queueMax: 4, subjectActiveMax: 1, subjectQueueMax: 2, queueTimeoutMs: 1_000 });
    try {
      const [first, second] = await Promise.all([
        pool.scan("alice", `ghp_${"a".repeat(36)}`, githubRule, 5_000),
        pool.scan("bob", "no secret", githubRule, 5_000),
      ]);
      expect(first).toHaveLength(1);
      expect(second).toEqual([]);
    } finally { await pool.close(); }
  });

  it("rejects work beyond the per-subject queue limit", async () => {
    const pool = new SecretScannerPool({ workers: 1, queueMax: 1, subjectActiveMax: 1, subjectQueueMax: 1, queueTimeoutMs: 1_000 });
    try {
      const first = pool.scan("alice", "x".repeat(1_000_000), githubRule, 5_000);
      const second = pool.scan("alice", "queued", githubRule, 5_000);
      await expect(pool.scan("alice", "rejected", githubRule, 5_000)).rejects.toBeInstanceOf(SecretScanBusyError);
      await Promise.all([first, second]);
    } finally { await pool.close(); }
  });

  it("validates environment overrides", () => {
    expect(loadSecretScannerPoolConfig({ SECRETLINT_WORKERS: "3", SECRETLINT_QUEUE_MAX: "40" })).toMatchObject({ workers: 3, queueMax: 40 });
    expect(() => loadSecretScannerPoolConfig({ SECRETLINT_WORKERS: "0" })).toThrow(/SECRETLINT_WORKERS/);
    expect(() => loadSecretScannerPoolConfig({ SECRETLINT_QUEUE_MAX: "many" })).toThrow(/SECRETLINT_QUEUE_MAX/);
  });
});
