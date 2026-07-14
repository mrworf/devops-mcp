import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { GatewayError } from "../src/errors.js";
import { loadSecretlintConfig, resolveSecretlintRules, validateSecretlintConfig } from "../src/secretlintConfig.js";

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

  it("extends defaults with deterministic overrides", () => {
    const configured = validateSecretlintConfig({
      version: 1,
      mode: "extend",
      rules: [
        { id: "@secretlint/secretlint-rule-github", options: { allows: ["example"] } },
        { id: "@secretlint/secretlint-rule-openai" },
      ],
    });
    expect(resolveSecretlintRules(configured, [
      { id: "@secretlint/secretlint-rule-github" },
      { id: "@secretlint/secretlint-rule-aws" },
    ])).toEqual([
      { id: "@secretlint/secretlint-rule-github", options: { allows: ["example"] } },
      { id: "@secretlint/secretlint-rule-aws" },
      { id: "@secretlint/secretlint-rule-openai" },
    ]);
  });

  it("replaces defaults, including with an empty rule list", () => {
    const configured = validateSecretlintConfig({ version: 1, mode: "replace", rules: [] });
    expect(resolveSecretlintRules(configured, [{ id: "@secretlint/secretlint-rule-github" }])).toEqual([]);
  });

  it("loads the bundled strict defaults without UUID heuristics", () => {
    const config = loadSecretlintConfig("config/secretlint.yaml");
    expect(config.rules.map((rule) => rule.id)).toContain("@secretlint/secretlint-rule-privatekey");
    expect(config.rules.map((rule) => rule.id)).toContain("@secretlint/secretlint-rule-pattern");
    expect(JSON.stringify(config)).not.toMatch(/uuid/i);
    expect(config.rules.find((rule) => rule.id === "@secretlint/secretlint-rule-aws")?.allowMessageIds)
      .toContain("AWSAccountID");
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
