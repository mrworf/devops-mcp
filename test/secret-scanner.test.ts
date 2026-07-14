import { describe, expect, it } from "vitest";
import { decodeUtf8, scanSecretText, validateFindings } from "../src/secretScanner.js";

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

  it("rejects malformed finding ranges and invalid UTF-8", () => {
    expect(() => validateFindings([{ start: 0, end: 99, ruleId: "rule", messageId: "id" }], 3)).toThrow(/range/);
    expect(() => validateFindings([{ start: 1, end: 1, ruleId: "rule", messageId: "id" }], 3)).toThrow(/range/);
    expect(() => decodeUtf8(Uint8Array.from([0xff, 0xfe]))).toThrow();
  });
});
