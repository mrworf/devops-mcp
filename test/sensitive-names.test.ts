import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { GatewayError } from "../src/errors.js";
import {
  loadSensitiveNameConfig,
  normalizeSensitiveName,
  resolveSensitiveNameConfig,
  SensitiveNameMatcher,
  validateSensitiveNameConfig,
} from "../src/sensitiveNames.js";

describe("sensitive-name configuration", () => {
  it("matches bundled conservative names case-insensitively after normalization", () => {
    const matcher = new SensitiveNameMatcher(loadSensitiveNameConfig("config/sensitive-names.yaml"));
    for (const name of [
      "SECRETSAUCE_OAUTH_SIGNING_KEY_PEM_B64",
      "SECRETSAUCE_ADMIN_PASSWORD_HASH_B64",
      "clientSecret",
      "X-API-Key",
      "refresh-token",
      "databaseUrl",
    ]) expect(matcher.match(name)).not.toEqual([]);
    for (const name of ["public_key", "key_id", "key_name", "signing_algorithm", "token_type", "payload_b64", "hash"]) {
      expect(matcher.match(name)).toEqual([]);
    }
    expect(normalizeSensitiveName("adminPassword-HASH.b64")).toBe("admin_Password_HASH_b64");
  });

  it("extends defaults with id overrides and allow-pattern precedence", () => {
    const defaults = loadSensitiveNameConfig("config/sensitive-names.yaml");
    const configured = validateSensitiveNameConfig({
      version: 1,
      mode: "extend",
      allow_patterns: ["(?:^|_)safe_password(?:_|$)"],
      patterns: [
        { id: "passwords", regex: "(?:^|_)pin(?:_|$)" },
        { id: "custom", regex: "(?:^|_)recovery_code(?:_|$)" },
      ],
    });
    const resolved = resolveSensitiveNameConfig(configured, defaults);
    const matcher = new SensitiveNameMatcher(resolved);
    expect(matcher.match("admin_password")).toEqual([]);
    expect(matcher.match("admin_pin")).toEqual(["gateway:sensitive-name:passwords"]);
    expect(matcher.match("recovery_code")).toEqual(["gateway:sensitive-name:custom"]);
    expect(matcher.match("safe_password")).toEqual([]);
  });

  it("supports an empty replacement catalog", () => {
    const defaults = loadSensitiveNameConfig("config/sensitive-names.yaml");
    const configured = validateSensitiveNameConfig({ version: 1, mode: "replace", patterns: [] });
    expect(new SensitiveNameMatcher(resolveSensitiveNameConfig(configured, defaults)).match("password")).toEqual([]);
  });

  it("loads a valid file and rejects malformed external configuration", () => {
    const directory = mkdtempSync(join(tmpdir(), "sensitive-names-"));
    const path = join(directory, "rules.yaml");
    writeFileSync(path, "version: 1\nmode: replace\npatterns:\n  - id: custom\n    regex: '(?:^|_)custom_secret(?:_|$)'\n");
    expect(loadSensitiveNameConfig(path).patterns).toEqual([{ id: "custom", regex: "(?:^|_)custom_secret(?:_|$)" }]);

    for (const invalid of [
      { version: 1, unknown: true },
      { version: 1, patterns: [{ id: "bad id", regex: "value" }] },
      { version: 1, patterns: [{ id: "bad", regex: "(" }] },
      { version: 1, patterns: [{ id: "same", regex: "a" }, { id: "same", regex: "b" }] },
      { version: 1, allow_patterns: [""], patterns: [] },
      { version: 1, patterns: [{ id: "long", regex: "x".repeat(513) }] },
    ]) expectConfigError(() => validateSensitiveNameConfig(invalid));
    expectConfigError(() => loadSensitiveNameConfig(join(directory, "missing.yaml")));
  });
});

function expectConfigError(fn: () => unknown): void {
  expect(fn).toThrowError(GatewayError);
  try { fn(); } catch (error) { expect((error as GatewayError).code).toBe("config_error"); }
}
