import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { GatewayError } from "../src/errors.js";
import { loadSecretlintConfig, validateSecretlintConfig } from "../src/secretlintConfig.js";

describe("Secretlint configuration", () => {
  it("loads a valid replacement config with normalized limits", () => {
    const dir = mkdtempSync(join(tmpdir(), "secretlint-config-"));
    const path = join(dir, "secretlint.yaml");
    writeFileSync(path, `version: 1\nmode: replace\nlimits:\n  max_unique_secrets: 25\n  timeout: 750ms\nrules:\n  - id: '@secretlint/secretlint-rule-github'\n`);

    expect(loadSecretlintConfig(path)).toEqual({
      version: 1,
      mode: "replace",
      limits: { maxUniqueSecrets: 25, timeoutMs: 750 },
      rules: [{ id: "@secretlint/secretlint-rule-github" }],
    });
  });

  it("rejects unknown, duplicate, and malformed rules", () => {
    expectConfigError(() => validateSecretlintConfig({ version: 1, rules: [{ id: "unknown" }] }));
    expectConfigError(() => validateSecretlintConfig({
      version: 1,
      rules: [
        { id: "@secretlint/secretlint-rule-github" },
        { id: "@secretlint/secretlint-rule-github" },
      ],
    }));
    expectConfigError(() => validateSecretlintConfig({ version: 1, limits: { timeout: "5m" } }));
  });

  it("rejects a missing configuration file", () => {
    expectConfigError(() => loadSecretlintConfig("/tmp/definitely-missing-secretlint.yaml"));
  });
});

function expectConfigError(fn: () => unknown): void {
  expect(fn).toThrowError(GatewayError);
  try {
    fn();
  } catch (error) {
    expect((error as GatewayError).code).toBe("config_error");
  }
}
