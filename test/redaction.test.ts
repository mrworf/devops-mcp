import { describe, expect, it } from "vitest";
import { redactResponse } from "../src/redaction.js";

describe("response redaction", () => {
  it("redacts raw credentials from response headers and body", () => {
    const redacted = redactResponse({
      headers: { "x-token": "secret-value" },
      body: "body has secret-value",
    }, ["secret-value"]);

    expect(redacted.redacted).toBe(true);
    expect(redacted.redaction_count).toBe(2);
    expect(redacted.headers["x-token"]).toBe("[REDACTED]");
    expect(redacted.body).toBe("body has [REDACTED]");
  });

  it("redacts JSON-escaped credential values", () => {
    const redacted = redactResponse({
      headers: {},
      body: String.raw`{"password":"line\nsecret"}`,
    }, ["line\nsecret"]);

    expect(redacted.redacted).toBe(true);
    expect(redacted.body).toBe(String.raw`{"password":"[REDACTED]"}`);
  });
});
