import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync } from "node:crypto";
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

  it("defaults and validates the in-memory audit capacity", () => {
    const raw = validRaw();
    expect(validateConfig(raw, validEnv).audit.memoryEvents).toBe(1000);
    raw.audit = { memory_events: 2 };
    expect(validateConfig(raw, validEnv).audit.memoryEvents).toBe(2);
    raw.audit.memory_events = 0;
    expectConfigError(() => validateConfig(raw, validEnv), "Invalid config");
  });

  it("defaults and validates built-in OAuth login rate limits", async () => {
    const keyPath = join(mkdtempSync(join(tmpdir(), "gateway-login-limit-")), "key.pem");
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    writeFileSync(keyPath, privateKey.export({ type: "pkcs8", format: "pem" }));
    const raw = validRaw();
    raw.auth = {
      mode: "builtin_oauth",
      builtin_oauth: {
        issuer: "https://mcp.example.org", admin_username_env: "ADMIN_USERNAME",
        admin_password_hash_env: "ADMIN_HASH", signing_key_file: keyPath,
        allowed_clients: ["https://chatgpt.com"],
      },
    };
    const env = { ...validEnv, ADMIN_USERNAME: "admin@example.com", ADMIN_HASH: "pbkdf2-sha256$1000$salt$hash" };
    const defaults = validateConfig(raw, env).auth;
    expect(defaults.mode).toBe("builtin_oauth");
    if (defaults.mode !== "builtin_oauth") throw new Error("Expected built-in OAuth");
    expect(defaults.builtinOAuth.loginRateLimit).toMatchObject({ perSource: 10, perAccount: 10, global: 100, maxEntries: 1000 });

    raw.auth.builtin_oauth.login_rate_limit = { initial_lockout: "1h", max_lockout: "15m" };
    expectConfigError(() => validateConfig(raw, env), "max_lockout");
  });

  it("defaults and validates the inbound request body limit", () => {
    const defaults = validRaw();
    delete defaults.limits.max_inbound_body;
    expect(validateConfig(defaults, validEnv).limits.maxInboundBodyBytes).toBe(1024 * 1024);

    const configured = validRaw();
    configured.limits.max_inbound_body = "2kb";
    expect(validateConfig(configured, validEnv).limits.maxInboundBodyBytes).toBe(2 * 1024);

    configured.limits.max_inbound_body = "2gb";
    expectConfigError(() => validateConfig(configured, validEnv), "limits.max_inbound_body");
  });

  it("defaults and validates the inbound body timeout", () => {
    const defaults = validRaw();
    expect(validateConfig(defaults, validEnv).limits.inboundBodyTimeoutMs).toBe(10_000);
    defaults.limits.inbound_body_timeout = "25ms";
    expect(validateConfig(defaults, validEnv).limits.inboundBodyTimeoutMs).toBe(25);
    defaults.limits.inbound_body_timeout = "forever";
    expectConfigError(() => validateConfig(defaults, validEnv), "limits.inbound_body_timeout");
  });

  it("defaults and validates unauthenticated in-flight limits", () => {
    const raw = validRaw();
    const defaults = validateConfig(raw, validEnv).limits;
    expect(defaults.maxUnauthenticatedInflight).toBe(32);
    expect(defaults.maxUnauthenticatedInflightPerSource).toBe(4);

    raw.limits.max_unauthenticated_inflight = 2;
    raw.limits.max_unauthenticated_inflight_per_source = 3;
    expectConfigError(() => validateConfig(raw, validEnv), "must not exceed");
    raw.limits.max_unauthenticated_inflight_per_source = 0;
    expectConfigError(() => validateConfig(raw, validEnv), "Invalid config");
  });

  it("defaults and validates password-verification limits", () => {
    const raw = validRaw();
    const defaults = validateConfig(raw, validEnv).limits;
    expect(defaults.maxPasswordVerifications).toBe(2);
    expect(defaults.maxPasswordVerificationsPerSource).toBe(1);
    raw.limits.max_password_verifications = 1;
    raw.limits.max_password_verifications_per_source = 2;
    expectConfigError(() => validateConfig(raw, validEnv), "must not exceed");
  });

  it("defaults and validates denial retention limits", () => {
    const raw = validRaw();
    const defaults = validateConfig(raw, validEnv).limits;
    expect(defaults).toMatchObject({ maxDenialRecords: 1000, denialTtlMs: 900_000, stateSweepIntervalMs: 60_000 });
    raw.limits.max_denial_records = 0;
    expectConfigError(() => validateConfig(raw, validEnv), "Invalid config");
    raw.limits.max_denial_records = 2;
    raw.limits.denial_ttl = "never";
    expectConfigError(() => validateConfig(raw, validEnv), "limits.denial_ttl");
  });

  it("defaults and validates opaque-token capacities", () => {
    const raw = validRaw();
    expect(validateConfig(raw, validEnv).limits).toMatchObject({ maxTokenRecords: 10_000, maxTokenRecordsPerSubject: 1_000 });
    raw.limits.max_token_records = 1;
    raw.limits.max_token_records_per_subject = 2;
    expectConfigError(() => validateConfig(raw, validEnv), "must not exceed");
  });

  it("defaults and validates authorization-code capacity", () => {
    const raw = validRaw();
    expect(validateConfig(raw, validEnv).limits.maxAuthorizationCodes).toBe(1000);
    raw.limits.max_authorization_codes = 0;
    expectConfigError(() => validateConfig(raw, validEnv), "Invalid config");
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
