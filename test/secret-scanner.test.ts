import { once } from "node:events";
import { Worker } from "node:worker_threads";
import { describe, expect, it } from "vitest";
import {
  decodeUtf8,
  scanSecretText,
  SECRET_SCANNER_WORKER_SOURCE,
  secretScannerWorkerEnv,
  validateFindings,
} from "../src/secretScanner.js";

describe("isolated Secretlint scanner", () => {
  it("returns validated ranges for a GitHub token without returning the secret in metadata", async () => {
    const secret = `ghp_${"a".repeat(36)}`;
    const findings = await scanSecretText(`before ${secret} after`, [
      { id: "@secretlint/secretlint-rule-github" },
    ], 5_000);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "@secretlint/secretlint-rule-github", messageId: "GITHUB_TOKEN" });
    expect(JSON.stringify(findings)).not.toContain(secret);
  });

  it("does not report UUID-shaped noise", async () => {
    const findings = await scanSecretText("request 123e4567-e89b-12d3-a456-426614174000", [
      { id: "@secretlint/secretlint-rule-github" },
    ], 5_000);
    expect(findings).toEqual([]);
  });

  it("isolates Secretlint diagnostics from the parent DEBUG setting", async () => {
    const parentEnv = { DEBUG: "*" };
    expect(secretScannerWorkerEnv(false, parentEnv).DEBUG).toBeUndefined();
    expect(secretScannerWorkerEnv(true, parentEnv).DEBUG).toBe("@secretlint/*");

    const disabledFindings = await scanSecretText("no secret", [
      { id: "@secretlint/secretlint-rule-github" },
    ], 5_000, parentEnv);
    expect(disabledFindings).toEqual([]);

    const disabledRun = await runScannerWorker(secretScannerWorkerEnv(false, parentEnv));
    const enabledRun = await runScannerWorker(secretScannerWorkerEnv(true, parentEnv));
    expect(disabledRun.findings).toEqual([]);
    expect(enabledRun.findings).toEqual([]);
    expect(disabledRun.stderr).not.toContain("@secretlint/core");
    expect(enabledRun.stderr).toContain("@secretlint/core");
  });

  it("rejects malformed finding ranges and invalid UTF-8", () => {
    expect(() => validateFindings([{ start: 0, end: 99, ruleId: "rule", messageId: "id" }], 3)).toThrow(/range/);
    expect(() => validateFindings([{ start: 1, end: 1, ruleId: "rule", messageId: "id" }], 3)).toThrow(/range/);
    expect(() => decodeUtf8(Uint8Array.from([0xff, 0xfe]))).toThrow();
  });
});

async function runScannerWorker(env: NodeJS.ProcessEnv): Promise<{ findings: unknown; stderr: string }> {
  const worker = new Worker(SECRET_SCANNER_WORKER_SOURCE, { eval: true, env, stderr: true });
  let stderr = "";
  worker.stderr?.setEncoding("utf8");
  worker.stderr?.on("data", (chunk: string) => { stderr += chunk; });
  worker.postMessage({ id: 1, text: "no secret", rules: [{ id: "@secretlint/secretlint-rule-github" }] });
  const [message] = await once(worker, "message") as [{ findings?: unknown }];
  await worker.terminate();
  return { findings: message.findings, stderr };
}
