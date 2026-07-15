import { describe, expect, it } from "vitest";
import { bodySummary, createLogger, headerNames, sanitizeLogFields } from "../src/logger.js";

describe("safe debug logging", () => {
  it("emits debug records only when debug logging is enabled", () => {
    const lines: string[] = [];
    const infoLogger = createLogger({ level: "info" }, (line) => lines.push(line));
    const debugLogger = createLogger({ level: "debug" }, (line) => lines.push(line));

    infoLogger.debug("service_request.downstream_ready", { service: "demo-service" });
    debugLogger.debug("service_request.downstream_ready", { service: "demo-service" });

    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0] ?? "{}")).toMatchObject({
      level: "debug",
      event: "service_request.downstream_ready",
      service: "demo-service",
    });
  });

  it("redacts sensitive fields before writing log lines", () => {
    const lines: string[] = [];
    const logger = createLogger({ level: "debug" }, (line) => lines.push(line));

    logger.debug("sensitive.sample", {
      authorization: "Bearer dev-token",
      cookie: "session=secret",
      token: "tok_plain",
      tokens: ["tok_array"],
      raw_token: "tok_secret",
      api_key: "real-api-key",
      credential_value: "real-credential",
      body: "contains a secret",
      safe: {
        target_host: "service.internal",
        credential_ids: ["api_key"],
        internal_token_ids: ["itok_123"],
      },
    });

    const serialized = lines[0] ?? "";
    expect(serialized).not.toContain("Bearer dev-token");
    expect(serialized).not.toContain("session=secret");
    expect(serialized).not.toContain("tok_plain");
    expect(serialized).not.toContain("tok_array");
    expect(serialized).not.toContain("tok_secret");
    expect(serialized).not.toContain("real-api-key");
    expect(serialized).not.toContain("real-credential");
    expect(serialized).not.toContain("contains a secret");
    expect(serialized).toContain("[REDACTED]");
    expect(JSON.parse(serialized).safe).toEqual({
      target_host: "service.internal",
      credential_ids: ["api_key"],
      internal_token_ids: ["itok_123"],
    });
  });

  it("summarizes headers and bodies without values", () => {
    expect(headerNames({
      Authorization: "Bearer dev-token",
      Cookie: "session=secret",
      "X-Trace-Id": "trace-1",
    })).toEqual(["X-Trace-Id"]);

    expect(bodySummary({ api_key: "secret" })).toEqual({ present: true, type: "object" });
    expect(bodySummary("hello")).toEqual({ present: true, type: "string", bytes: 5 });
  });

  it("can sanitize arbitrary records as a final guard", () => {
    expect(sanitizeLogFields({
      nested: {
        token_value: "tok_secret",
        target_path: "/api/stacks",
      },
    })).toEqual({
      nested: {
        token_value: "[REDACTED]",
        target_path: "/api/stacks",
      },
    });
  });

  it("emits warning-level events without exposing sensitive fields", () => {
    const lines: string[] = [];
    createLogger({ level: "info" }, (line) => lines.push(line)).warn("cookie.removed", { cookie: "session=secret", direction: "response" });
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain('"level":"warn"');
    expect(lines[0]).not.toContain("session=secret");
  });
});
