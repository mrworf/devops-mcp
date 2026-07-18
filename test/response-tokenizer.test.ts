import { describe, expect, it } from "vitest";
import { validateConfig } from "../src/config.js";
import { ResponseTokenizer } from "../src/responseTokenizer.js";
import { SecretScannerPool } from "../src/secretScannerPool.js";
import { TokenBroker } from "../src/tokens.js";
import type { AuthContext } from "../src/types.js";
import { loadSensitiveNameConfig, SensitiveNameMatcher } from "../src/sensitiveNames.js";

const rules = [{ id: "@secretlint/secretlint-rule-github" as const }];

describe("plain-text response tokenizer", () => {
  it("preserves JSON source text outside exact replacement ranges", async () => {
    const fixture = setup();
    try {
      const secret = `ghp_${"a".repeat(36)}`;
      const body = `{  "duplicate":1, "duplicate" : 2, "number":1.00, "secret" : "${secret}" }\n`;
      const result = await fixture.tokenizer.tokenize({ headers: { "x-secret": secret }, body }, fixture.auth, fixture.service);
      expect(result.body).toMatch(/^\{  "duplicate":1, "duplicate" : 2, "number":1\.00, "secret" : "sec_[A-Za-z0-9_-]+" \}\n$/);
      expect(result.body.replace(/sec_[A-Za-z0-9_-]+/, "VALUE")).toBe(body.replace(secret, "VALUE"));
      expect(result.headers["x-secret"]).toMatch(/^sec_/);
      expect(result.secretTokenizationCount).toBe(2);
    } finally { await fixture.pool.close(); }
  });

  it("reuses configured tokens and merges forged-prefix overlaps so no secret fragment survives", async () => {
    const fixture = setup();
    try {
      const tok = fixture.broker.issueTokens(fixture.auth, {
        service: "service-a", destination: "primary", access_ids: ["key"], reason: "Test.",
      }).tokens[0]?.token ?? "";
      const github = `ghp_${"b".repeat(36)}`;
      const attack = `gref_${github}`;
      const result = await fixture.tokenizer.tokenize({ headers: {}, body: `known=configured-secret attack=${attack}` }, fixture.auth, fixture.service);
      expect(result.body).toContain(`known=${tok}`);
      expect(result.body).not.toContain("configured-secret");
      expect(result.body).not.toContain(github);
      expect(result.body).not.toContain(attack);
      expect(result.warnings).toEqual([{ prefix: "gref", reason: "unknown", count: 1 }]);
    } finally { await fixture.pool.close(); }
  });

  it("matches JSON-escaped configured credentials without parsing or reserializing JSON", async () => {
    const fixture = setup();
    try {
      const configured = "line\n\"quoted\"";
      const tok = fixture.broker.issueTokens(fixture.auth, {
        service: "service-a", destination: "primary", access_ids: ["escaped"], reason: "Test escaped credential.",
      }).tokens[0]?.token ?? "";
      const escaped = JSON.stringify(configured).slice(1, -1);
      const body = `{ "value" : "${escaped}", "number": 1.00 }`;
      const result = await fixture.tokenizer.tokenize({ headers: {}, body }, fixture.auth, fixture.service);
      expect(result.body).toBe(`{ "value" : "${tok}", "number": 1.00 }`);
      expect(result.body).not.toContain(escaped);
    } finally { await fixture.pool.close(); }
  });

  it("tokenizes regex-matched JSON properties and response headers by source range", async () => {
    const fixture = setup();
    try {
      const body = '{ /* odd */ "SECRETSAUCE_OAUTH_SIGNING_KEY_PEM_B64" : "cGVtLWtleQ==" "public_key":"visible", "adminPasswordHashB64":"hash-value", "empty_password":"" }';
      const result = await fixture.tokenizer.tokenize({ headers: { "X-Api-Key": "header-value" }, body }, fixture.auth, fixture.service);
      expect(result.headers["X-Api-Key"]).toMatch(/^sec_/);
      expect(result.ruleIds).toContain("gateway:sensitive-name:keys");
      expect(result.ruleIds).toContain("gateway:sensitive-name:passwords");
      expect(result.body).toContain('"public_key":"visible"');
      expect(result.body).toContain('"empty_password":""');
      const restoredBody = result.body.replace(/sec_[A-Za-z0-9_-]+/g, (token) =>
        fixture.broker.validateResponseSecretUse(fixture.auth, "service-a", token).secret);
      expect(restoredBody).toBe(body);
      const headerToken = result.headers["X-Api-Key"] ?? "";
      expect(fixture.broker.validateResponseSecretUse(fixture.auth, "service-a", headerToken).secret).toBe("header-value");
    } finally { await fixture.pool.close(); }
  });

  it("leaves valid same-scope opaque references unchanged", async () => {
    const fixture = setup();
    try {
      const valid = fixture.broker.issueOrReuseResponseSecret(fixture.auth, "service-a", "value").token;
      const result = await fixture.tokenizer.tokenize({ headers: {}, body: valid }, fixture.auth, fixture.service);
      expect(result.body).toBe(valid);
      expect(result.secretTokenized).toBe(false);
    } finally { await fixture.pool.close(); }
  });

  it("fails before transformation when the unique-secret limit is exceeded", async () => {
    const fixture = setup(1);
    try {
      const one = `ghp_${"c".repeat(36)}`;
      const two = `ghp_${"d".repeat(36)}`;
      await expect(fixture.tokenizer.tokenize({ headers: {}, body: `${one} ${two}` }, fixture.auth, fixture.service))
        .rejects.toMatchObject({ code: "secret_scan_failed" });
    } finally { await fixture.pool.close(); }
  });

  it("fails capacity checks before creating partial response-secret state", async () => {
    const fixture = setup(100, 1);
    try {
      const one = `ghp_${"c".repeat(36)}`;
      const two = `ghp_${"d".repeat(36)}`;
      await expect(fixture.tokenizer.tokenize({ headers: {}, body: `${one} ${two}` }, fixture.auth, fixture.service))
        .rejects.toMatchObject({ code: "capacity_exceeded" });
      expect(fixture.broker.stats()).toEqual({ configured: 0, responseSecrets: 0, tokenValues: 0 });
    } finally { await fixture.pool.close(); }
  });

  it("decodes, tokenizes, and canonically re-encodes explicit Base64 responses", async () => {
    const fixture = setup();
    try {
      const attack = `gref_ghp_${"e".repeat(36)}`;
      const encoded = Buffer.from(`prefix ${attack} suffix`, "utf8").toString("base64").replace(/(.{12})/g, "$1\n");
      const result = await fixture.tokenizer.tokenizeWithTransferEncoding({
        headers: { "Content-Transfer-Encoding": "base64" }, body: encoded,
      }, fixture.auth, fixture.service);
      const decoded = Buffer.from(result.body, "base64").toString("utf8");
      expect(decoded).toMatch(/^prefix sec_[A-Za-z0-9_-]+ suffix$/);
      expect(decoded).not.toContain(attack);
      expect(decoded).not.toContain("ghp_");
      expect(result.body).not.toContain("\n");
    } finally { await fixture.pool.close(); }
  });

  it("rejects malformed Base64, invalid decoded UTF-8, and conflicting declarations", async () => {
    const fixture = setup();
    try {
      await expect(fixture.tokenizer.tokenizeWithTransferEncoding({ headers: { "content-transfer-encoding": "base64" }, body: "%%%" }, fixture.auth, fixture.service))
        .rejects.toMatchObject({ code: "secret_scan_failed" });
      await expect(fixture.tokenizer.tokenizeWithTransferEncoding({ headers: { "content-transfer-encoding": "base64" }, body: "/w==" }, fixture.auth, fixture.service))
        .rejects.toMatchObject({ code: "secret_scan_failed" });
      await expect(fixture.tokenizer.tokenizeWithTransferEncoding({ headers: { "content-transfer-encoding": "gzip" }, body: "data" }, fixture.auth, fixture.service))
        .rejects.toMatchObject({ code: "unsupported_transfer_encoding" });
      await expect(fixture.tokenizer.tokenizeWithTransferEncoding({
        headers: { "Content-Transfer-Encoding": "base64", "content-transfer-encoding": "base64" }, body: "",
      }, fixture.auth, fixture.service)).rejects.toMatchObject({ code: "unsupported_transfer_encoding" });
    } finally { await fixture.pool.close(); }
  });
});

function setup(max = 100, maxTokenRecords = 10_000) {
  const config = validateConfig({
    server: { listen: "127.0.0.1:8080", mcp_path: "/mcp" }, auth: { mode: "bearer", bearer: { token_env: "AUTH" } },
    limits: { max_token_records: maxTokenRecords, max_token_records_per_subject: maxTokenRecords },
    services: { "service-a": { name: "A", destinations: [{ name: "primary", base_url: "https://a.example.org" }], credentials: [
      { id: "key", usage: { kind: "header" }, source: { kind: "env", name: "KEY" } },
      { id: "escaped", usage: { kind: "body" }, source: { kind: "env", name: "ESCAPED" } },
    ], access: { users: ["alice"] } } },
  }, { AUTH: "auth", KEY: "configured-secret", ESCAPED: "line\n\"quoted\"" });
  const broker = new TokenBroker(config);
  const pool = new SecretScannerPool({ workers: 1, queueMax: 4, subjectActiveMax: 1, subjectQueueMax: 4, queueTimeoutMs: 1_000 });
  const auth: AuthContext = { subject: "alice", scopes: [], mode: "bearer" };
  const sensitiveNames = new SensitiveNameMatcher(loadSensitiveNameConfig("config/sensitive-names.yaml"));
  return {
    config, broker, pool, auth, service: config.services["service-a"]!,
    tokenizer: new ResponseTokenizer(broker, pool, rules, max, 5_000, sensitiveNames),
  };
}
