import { describe, expect, it } from "vitest";
import { validateConfig } from "../src/config.js";
import { ResponseTokenizer } from "../src/responseTokenizer.js";
import { SecretScannerPool } from "../src/secretScannerPool.js";
import { TokenBroker } from "../src/tokens.js";
import type { AuthContext } from "../src/types.js";

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
        service: "service-a", destination: "primary", credential_ids: ["key"], reason: "Test.",
      }).tokens[0]?.token ?? "";
      const github = `ghp_${"b".repeat(36)}`;
      const attack = `tok_${github}`;
      const result = await fixture.tokenizer.tokenize({ headers: {}, body: `known=configured-secret attack=${attack}` }, fixture.auth, fixture.service);
      expect(result.body).toContain(`known=${tok}`);
      expect(result.body).not.toContain("configured-secret");
      expect(result.body).not.toContain(github);
      expect(result.body).not.toContain(attack);
      expect(result.warnings).toEqual([{ prefix: "tok", reason: "unknown", count: 1 }]);
    } finally { await fixture.pool.close(); }
  });

  it("leaves valid same-scope opaque tokens unchanged", async () => {
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
});

function setup(max = 100) {
  const config = validateConfig({
    server: { listen: "127.0.0.1:8080", mcp_path: "/mcp" }, auth: { mode: "bearer", bearer: { token_env: "AUTH" } },
    services: { "service-a": { name: "A", destinations: [{ name: "primary", base_url: "https://a.example.org" }], credentials: [{ id: "key", usage: { kind: "header" }, source: { kind: "env", name: "KEY" } }], access: { users: ["alice"] } } },
  }, { AUTH: "auth", KEY: "configured-secret" });
  const broker = new TokenBroker(config);
  const pool = new SecretScannerPool({ workers: 1, queueMax: 4, subjectActiveMax: 1, subjectQueueMax: 4, queueTimeoutMs: 1_000 });
  const auth: AuthContext = { subject: "alice", scopes: [], mode: "bearer" };
  return { config, broker, pool, auth, service: config.services["service-a"]!, tokenizer: new ResponseTokenizer(broker, pool, rules, max, 5_000) };
}
