import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { GatewayError } from "../src/errors.js";
import { loadConfig, validateConfig } from "../src/config.js";

const validEnv = {
  TEST_GATEWAY_TOKEN: "dev-token",
  PORTAINER_API_KEY: "portainer-secret",
};

function validRaw(): any {
  return {
    server: {
      listen: "127.0.0.1:8080",
      mcp_path: "/mcp",
    },
    auth: {
      mode: "bearer",
      bearer: {
        token_env: "TEST_GATEWAY_TOKEN",
      },
    },
    tokens: {
      idle_ttl: "10m",
      max_ttl: "1h",
    },
    limits: {
      max_request_body: "1mb",
      max_response_body: "5mb",
      timeout: "30s",
    },
    services: {
      "portainer-prod": {
        type: "http",
        name: "Portainer Production",
        destinations: [{
          name: "primary",
          base_url: "https://portainer.internal:9443",
          schemes: ["https"],
          hosts: [{ exact: "portainer.internal" }],
          ports: [9443],
        }],
        tls: { verify: false },
        credentials: [{
          id: "api_key",
          usage: { kind: "header", name: "X-API-Key" },
          source: { kind: "env", name: "PORTAINER_API_KEY" },
        }],
        access: { users: ["henric@example.com"] },
        policy: {
          mode: "deny",
          rules: [{
            id: "allow-stack-read",
            effect: "allow",
            priority: 100,
            methods: ["get"],
            paths: ["/api/stacks.*"],
          }],
        },
      },
    },
  };
}

describe("config validation", () => {
  it("loads the sample config and resolves env secrets", () => {
    process.env.TEST_GATEWAY_TOKEN = "dev-token";
    process.env.PORTAINER_API_KEY = "portainer-secret";
    const config = loadConfig("test/fixtures/config.valid.yaml");
    expect(config.server.host).toBe("127.0.0.1");
    expect(config.server.port).toBe(8080);
    expect(config.logging.level).toBe("info");
    expect(config.services["portainer-prod"]?.credentials[0]?.secret).toBe("portainer-secret");
  });

  it("accepts debug logging level", () => {
    const raw = validRaw();
    raw.logging = { level: "debug" };

    const config = validateConfig(raw, validEnv);

    expect(config.logging.level).toBe("debug");
  });

  it("accepts service API documentation URLs", () => {
    const raw = validRaw();
    raw.services["portainer-prod"].api_docs_url = "https://api.example.org/openapi.json";

    const config = validateConfig(raw, validEnv);

    expect(config.services["portainer-prod"]?.apiDocsUrl).toBe("https://api.example.org/openapi.json");
  });

  it("resolves file credential sources", () => {
    const dir = mkdtempSync(join(tmpdir(), "gateway-config-"));
    const secretPath = join(dir, "api-key");
    writeFileSync(secretPath, "file-secret\n");
    const raw = validRaw();
    raw.services["portainer-prod"].credentials[0].source = { kind: "file", path: secretPath };

    const config = validateConfig(raw, validEnv);

    expect(config.services["portainer-prod"]?.credentials[0]?.secret).toBe("file-secret");
  });

  it("warns but does not fail for broad host regexes", () => {
    const raw = validRaw();
    raw.services["portainer-prod"].destinations[0].hosts = [{ regex: ".*" }];

    const config = validateConfig(raw, validEnv);

    expect(config.warnings).toContain("Broad host regex warning: .*");
  });

  it("fails malformed yaml", () => {
    expect(() => parse("server: [")).toThrow();
  });

  it("fails duplicate destination ids", () => {
    const raw = validRaw();
    raw.services["portainer-prod"].destinations.push({
      name: "primary",
      base_url: "https://portainer2.internal:9443",
      schemes: ["https"],
      hosts: [{ exact: "portainer2.internal" }],
      ports: [9443],
    });

    expectConfigError(() => validateConfig(raw, validEnv), "Duplicate destination id");
  });

  it("fails duplicate credential ids", () => {
    const raw = validRaw();
    raw.services["portainer-prod"].credentials.push({
      id: "api_key",
      usage: { kind: "header", name: "X-Second-Key" },
      source: { kind: "env", name: "PORTAINER_API_KEY" },
    });

    expectConfigError(() => validateConfig(raw, validEnv), "Duplicate credential id");
  });

  it("fails invalid base urls", () => {
    const raw = validRaw();
    raw.services["portainer-prod"].destinations[0].base_url = "not-a-url";

    expectConfigError(() => validateConfig(raw, validEnv), "Invalid config");
  });

  it("fails invalid service API documentation URLs", () => {
    const raw = validRaw();
    raw.services["portainer-prod"].api_docs_url = "not-a-url";

    expectConfigError(() => validateConfig(raw, validEnv), "Invalid config");
  });

  it("fails invalid host regexes", () => {
    const raw = validRaw();
    raw.services["portainer-prod"].destinations[0].hosts = [{ regex: "[" }];

    expectConfigError(() => validateConfig(raw, validEnv), "Invalid host regex");
  });

  it("fails invalid policy path regexes", () => {
    const raw = validRaw();
    raw.services["portainer-prod"].policy.rules[0].paths = ["["];

    expectConfigError(() => validateConfig(raw, validEnv), "Invalid policy path regex");
  });

  it("fails invalid ttl and size limits", () => {
    const ttlRaw = validRaw();
    ttlRaw.tokens.idle_ttl = "10days";
    expectConfigError(() => validateConfig(ttlRaw, validEnv), "tokens.idle_ttl");

    const sizeRaw = validRaw();
    sizeRaw.limits.max_request_body = "1gb";
    expectConfigError(() => validateConfig(sizeRaw, validEnv), "limits.max_request_body");
  });

  it("fails invalid logging levels", () => {
    const raw = validRaw();
    raw.logging = { level: "trace" };

    expectConfigError(() => validateConfig(raw, validEnv), "Invalid config");
  });

  it("fails missing env secrets", () => {
    expectConfigError(() => validateConfig(validRaw(), { TEST_GATEWAY_TOKEN: "dev-token" }), "Missing credential environment variable");
  });

  it("accepts endpoint Secretlint disable controls", () => {
    const allDisabled = validRaw();
    allDisabled.services["portainer-prod"].policy.rules[0].secretlint = { enabled: false };
    expect(validateConfig(allDisabled, validEnv).services["portainer-prod"]?.policy.rules[0]?.secretlint).toEqual({ enabled: false });

    const selected = validRaw();
    selected.services["portainer-prod"].policy.rules[0].secretlint = { disabled_rules: ["@secretlint/secretlint-rule-github"] };
    expect(validateConfig(selected, validEnv).services["portainer-prod"]?.policy.rules[0]?.secretlint)
      .toEqual({ disabledRuleIds: ["@secretlint/secretlint-rule-github"] });
  });

  it("rejects conflicting or unknown endpoint Secretlint controls", () => {
    const conflicting = validRaw();
    conflicting.services["portainer-prod"].policy.rules[0].secretlint = {
      enabled: false, disabled_rules: ["@secretlint/secretlint-rule-github"],
    };
    expectConfigError(() => validateConfig(conflicting, validEnv), "Invalid config");
    const unknown = validRaw();
    unknown.services["portainer-prod"].policy.rules[0].secretlint = { disabled_rules: ["unknown"] };
    expectConfigError(() => validateConfig(unknown, validEnv), "Invalid config");
  });
});

function expectConfigError(fn: () => unknown, message: string) {
  try {
    fn();
    throw new Error("Expected config error");
  } catch (error) {
    expect(error).toBeInstanceOf(GatewayError);
    expect((error as GatewayError).message).toContain(message);
  }
}
