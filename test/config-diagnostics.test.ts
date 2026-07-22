import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { configError, GatewayError, type ConfigDiagnostic } from "../src/errors.js";
import { loadSecretlintConfig } from "../src/secretlintConfig.js";
import { loadSensitiveNameConfig } from "../src/sensitiveNames.js";
import { startupErrorPayload } from "../src/server.js";

describe("source-located configuration diagnostics", () => {
  it("reports malformed gateway YAML with a safe line and caret", () => {
    const file = temporaryYaml("gateway-malformed", "server:\n  listen: ]raw-secret-value\n");

    const error = captureConfigError(() => loadConfig(file));

    expect(error.message).toContain("Failed to parse config");
    expect(error.diagnostics?.[0]).toMatchObject({ file, line: 2, column: 11 });
    expect(JSON.stringify(error.diagnostics)).not.toContain("raw-secret-value");
    expect(error.diagnostics?.[0]?.pointer).toContain("^");
  });

  it("reports schema paths, nearest locations, and detailed type expectations", () => {
    const file = temporaryYaml("gateway-schema", [
      "server:",
      "  listen: 42",
      "auth:",
      "  mode: bearer",
      "  bearer: {}",
      "services: {}",
      "",
    ].join("\n"));

    const error = captureConfigError(() => loadConfig(file));
    const listen = diagnostic(error, "server.listen");
    expect(listen).toMatchObject({ line: 2, column: 11, detail: "Invalid input: expected string, received number" });
    expect(listen.source).toBe("  listen: ••");

    const validSource = readFileSync("test/fixtures/config.valid.yaml", "utf8");
    const missingFile = temporaryYaml("gateway-missing", validSource.replace("  bearer:\n    token_env: TEST_GATEWAY_TOKEN", "  bearer: {}"));
    const missingError = captureConfigError(() => loadConfig(missingFile));
    expect(diagnostic(missingError, "auth.bearer")).toMatchObject({
      line: 7,
      detail: "auth.bearer must include exactly one of token_env or token_file",
    });
  });

  it("locates unknown fields without exposing arbitrary scalar values", () => {
    process.env.TEST_GATEWAY_TOKEN = "dev-token";
    process.env.PORTAINER_API_KEY = "portainer-secret";
    const source = `${readFileSync("test/fixtures/config.valid.yaml", "utf8")}unexpected: sk-live-arbitrary-secret\n`;
    const file = temporaryYaml("gateway-unknown", source);

    const error = captureConfigError(() => loadConfig(file));
    const unknown = diagnostic(error, "unexpected");
    const serialized = JSON.stringify(startupErrorPayload(error));

    expect(unknown.line).toBe(source.split("\n").length - 1);
    expect(unknown.source).toMatch(/^unexpected: /);
    expect(serialized).not.toContain("sk-live-arbitrary-secret");
    expect(serialized).not.toContain("configPath");
  });

  it("locates semantic gateway validation failures", () => {
    process.env.TEST_GATEWAY_TOKEN = "dev-token";
    process.env.PORTAINER_API_KEY = "portainer-secret";
    const source = readFileSync("test/fixtures/config.valid.yaml", "utf8").replace("idle_ttl: 10m", "idle_ttl: forever");
    const file = temporaryYaml("gateway-semantic", source);

    const error = captureConfigError(() => loadConfig(file));

    expect(diagnostic(error, "tokens.idle_ttl")).toMatchObject({
      line: 11,
      column: 13,
      detail: expect.stringContaining("must be a duration"),
      source: "  idle_ttl: •••••••",
    });
  });

  it("provides syntax and validation locations for Secretlint YAML", () => {
    const malformed = temporaryYaml("secretlint-malformed", "version: 1\nrules: ]credential-value\n");
    expect(captureConfigError(() => loadSecretlintConfig(malformed)).diagnostics?.[0]).toMatchObject({ line: 2, column: 8 });

    const invalid = temporaryYaml("secretlint-invalid", "version: wrong-value\nrules: []\n");
    const error = captureConfigError(() => loadSecretlintConfig(invalid));
    expect(diagnostic(error, "version")).toMatchObject({ line: 1, column: 10 });
    expect(JSON.stringify(error.diagnostics)).not.toContain("wrong-value");
  });

  it("provides syntax and semantic locations for sensitive-name YAML", () => {
    const malformed = temporaryYaml("names-malformed", "version: 1\npatterns: ]credential-value\n");
    expect(captureConfigError(() => loadSensitiveNameConfig(malformed)).diagnostics?.[0]).toMatchObject({ line: 2, column: 11 });

    const invalid = temporaryYaml("names-invalid", "version: 1\npatterns:\n  - id: invalid\n    regex: '('\n");
    const error = captureConfigError(() => loadSensitiveNameConfig(invalid));
    expect(diagnostic(error, "patterns[0].regex")).toMatchObject({ line: 4, column: 12 });
    expect(JSON.stringify(error.diagnostics)).not.toContain("regex: '('");
  });

  it("serializes structured startup diagnostics", () => {
    const error = configError("Invalid config", [{
      file: "/config/config.yaml",
      path: "server.listen",
      configPath: ["server", "listen"],
      line: 2,
      column: 11,
      detail: "Expected a host:port string",
      source: "  listen: •••",
      pointer: "          ^",
    }]);

    expect(startupErrorPayload(error)).toEqual({
      level: "error",
      error: {
        code: "config_error",
        message: "Invalid config",
        diagnostics: [{
          file: "/config/config.yaml",
          path: "server.listen",
          line: 2,
          column: 11,
          detail: "Expected a host:port string",
          source: "  listen: •••",
          pointer: "          ^",
        }],
      },
    });
  });

  it("reports unreadable files without fabricating a source position", () => {
    const file = join(tmpdir(), "definitely-missing-gateway-config.yaml");
    const error = captureConfigError(() => loadConfig(file));

    expect(error.diagnostics?.[0]).toMatchObject({ file, detail: expect.stringContaining("ENOENT") });
    expect(error.diagnostics?.[0]).not.toHaveProperty("line");
    expect(error.diagnostics?.[0]).not.toHaveProperty("column");
  });
});

function temporaryYaml(prefix: string, source: string): string {
  const file = join(mkdtempSync(join(tmpdir(), `${prefix}-`)), "config.yaml");
  writeFileSync(file, source);
  return file;
}

function captureConfigError(run: () => unknown): GatewayError {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(GatewayError);
    expect((error as GatewayError).code).toBe("config_error");
    return error as GatewayError;
  }
  throw new Error("Expected config error");
}

function diagnostic(error: GatewayError, path: string): ConfigDiagnostic {
  const result = error.diagnostics?.find((item) => item.path === path);
  if (result === undefined) throw new Error(`Missing diagnostic for ${path}: ${JSON.stringify(error.diagnostics)}`);
  return result;
}
