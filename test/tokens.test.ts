import { describe, expect, it } from "vitest";
import { validateConfig } from "../src/config.js";
import { GatewayError } from "../src/errors.js";
import { TokenBroker } from "../src/tokens.js";
import type { AuthContext, GatewayConfig } from "../src/types.js";

describe("token broker", () => {
  it("issues opaque tokens for authorized credentials and omits raw values from audit", () => {
    let now = 1_000;
    const broker = new TokenBroker(tokenConfig(), () => now);

    const result = broker.issueTokens(auth("henric@example.com", "session-a"), {
      service: "portainer-prod",
      destination: "primary",
      credential_ids: ["api_key", "password"],
      reason: "Inspect configured stacks.",
    });

    expect(result.tokens).toHaveLength(2);
    expect(result.tokens[0]?.token).toMatch(/^tok_/);
    expect(result.tokens[0]?.token).not.toContain("portainer-secret");
    expect(result.tokens[1]?.token).not.toBe(result.tokens[0]?.token);
    const auditJson = JSON.stringify(result.audit);
    expect(auditJson).not.toContain(result.tokens[0]?.token ?? "");
    expect(auditJson).not.toContain("portainer-secret");
    expect(result.audit.internal_token_ids).toHaveLength(2);

    const originalMax = broker.validateTokenUse(auth("henric@example.com", "session-a"), {
      service: "portainer-prod",
      destination: "primary",
    }, result.tokens[0]?.token ?? "").maxExpiresAt;
    now += 20;
    const used = broker.validateTokenUse(auth("henric@example.com", "session-a"), {
      service: "portainer-prod",
      destination: "primary",
    }, result.tokens[0]?.token ?? "");

    expect(used.lastUsedAt).toBe(now);
    expect(used.maxExpiresAt).toBe(originalMax);
    expect(used.idleExpiresAt).toBeLessThanOrEqual(originalMax);
  });

  it("rejects missing reasons and unknown credentials", () => {
    const broker = new TokenBroker(tokenConfig());

    expectGatewayError(() => broker.issueTokens(auth("henric@example.com"), {
      service: "portainer-prod",
      destination: "primary",
      credential_ids: ["api_key"],
      reason: " ",
    }), "token_invalid");
    expectGatewayError(() => broker.issueTokens(auth("henric@example.com"), {
      service: "portainer-prod",
      destination: "primary",
      credential_ids: ["missing"],
      reason: "Need a token.",
    }), "unknown_credential");
  });

  it("rejects expired tokens", () => {
    let now = 1_000;
    const broker = new TokenBroker(tokenConfig(), () => now);
    const result = broker.issueTokens(auth("henric@example.com"), {
      service: "portainer-prod",
      destination: "primary",
      credential_ids: ["api_key"],
      reason: "Need a token.",
    });

    now += 101;

    expectGatewayError(() => broker.validateTokenUse(auth("henric@example.com"), {
      service: "portainer-prod",
      destination: "primary",
    }, result.tokens[0]?.token ?? ""), "token_expired");
  });

  it("allows same-subject token use across changing or missing MCP transport sessions", () => {
    const broker = new TokenBroker(tokenConfig());
    const result = broker.issueTokens(auth("henric@example.com", "session-a"), {
      service: "portainer-prod",
      destination: "primary",
      credential_ids: ["api_key"],
      reason: "Need a token.",
    });
    const token = result.tokens[0]?.token ?? "";

    expect(broker.validateTokenUse(auth("henric@example.com", "session-b"), {
      service: "portainer-prod",
      destination: "primary",
    }, token).credentialId).toBe("api_key");
    expect(broker.validateTokenUse(auth("henric@example.com"), {
      service: "portainer-prod",
      destination: "primary",
    }, token).credentialId).toBe("api_key");
  });

  it("rejects cross-user, cross-service, and cross-destination token use", () => {
    const broker = new TokenBroker(tokenConfig());
    const result = broker.issueTokens(auth("henric@example.com", "session-a"), {
      service: "portainer-prod",
      destination: "primary",
      credential_ids: ["api_key"],
      reason: "Need a token.",
    });
    const token = result.tokens[0]?.token ?? "";

    expectGatewayError(() => broker.validateTokenUse(auth("ada@example.com", "session-a"), {
      service: "portainer-prod",
      destination: "primary",
    }, token), "token_invalid");
    expectGatewayError(() => broker.validateTokenUse(auth("henric@example.com", "session-a"), {
      service: "opnsense-home",
      destination: "primary",
    }, token), "token_invalid");
    expectGatewayError(() => broker.validateTokenUse(auth("henric@example.com", "session-a"), {
      service: "portainer-prod",
      destination: "secondary",
    }, token), "token_invalid");
  });

  it("issues and reuses service-scoped response secret tokens", () => {
    let now = 1_000;
    const broker = new TokenBroker(tokenConfig(), () => now);
    const first = broker.issueOrReuseResponseSecret(auth("henric@example.com"), "portainer-prod", "returned-secret");
    expect(first.token).toMatch(/^sec_/);
    expect(first.token).not.toContain("returned-secret");
    expect(first.reused).toBe(false);

    now += 20;
    const reused = broker.issueOrReuseResponseSecret(auth("henric@example.com"), "portainer-prod", "returned-secret");
    expect(reused.token).toBe(first.token);
    expect(reused.reused).toBe(true);
    expect(reused.record.lastUsedAt).toBe(now);
    expect(broker.validateResponseSecretUse(auth("henric@example.com"), "portainer-prod", first.token).secret).toBe("returned-secret");
  });

  it("isolates response secret tokens by subject and service and expires them", () => {
    let now = 1_000;
    const broker = new TokenBroker(tokenConfig(), () => now);
    const issued = broker.issueOrReuseResponseSecret(auth("henric@example.com"), "portainer-prod", "returned-secret");
    const otherSubject = broker.issueOrReuseResponseSecret(auth("ada@example.com"), "portainer-prod", "returned-secret");
    const otherService = broker.issueOrReuseResponseSecret(auth("henric@example.com"), "opnsense-home", "returned-secret");
    expect(otherSubject.token).not.toBe(issued.token);
    expect(otherService.token).not.toBe(issued.token);
    expectGatewayError(() => broker.validateResponseSecretUse(auth("ada@example.com"), "portainer-prod", issued.token), "token_invalid");
    expectGatewayError(() => broker.validateResponseSecretUse(auth("henric@example.com"), "opnsense-home", issued.token), "token_invalid");
    now += 101;
    expectGatewayError(() => broker.validateResponseSecretUse(auth("henric@example.com"), "portainer-prod", issued.token), "token_expired");
    const replacement = broker.issueOrReuseResponseSecret(auth("henric@example.com"), "portainer-prod", "returned-secret");
    expect(replacement.token).not.toBe(issued.token);
  });

  it("reuses the most recently used configured token across destinations", () => {
    let now = 1_000;
    const broker = new TokenBroker(tokenConfig(), () => now);
    const first = broker.issueTokens(auth("henric@example.com"), {
      service: "portainer-prod", destination: "primary", credential_ids: ["api_key"], reason: "First token.",
    }).tokens[0]?.token ?? "";
    now += 10;
    const second = broker.issueTokens(auth("henric@example.com"), {
      service: "portainer-prod", destination: "secondary", credential_ids: ["api_key"], reason: "Second token.",
    }).tokens[0]?.token ?? "";
    now += 10;
    broker.validateTokenUse(auth("henric@example.com"), { service: "portainer-prod", destination: "primary" }, first);
    now += 10;

    const match = broker.findConfiguredTokenForSecret(auth("henric@example.com"), "portainer-prod", "portainer-secret");
    expect(match?.token).toBe(first);
    expect(match?.record.lastUsedAt).toBe(now);
    expect(match?.token).not.toBe(second);
  });

  it("does not reverse-match expired, cross-subject, cross-service, or unknown configured values", () => {
    let now = 1_000;
    const broker = new TokenBroker(tokenConfig(), () => now);
    broker.issueTokens(auth("henric@example.com"), {
      service: "portainer-prod", destination: "primary", credential_ids: ["api_key"], reason: "Token.",
    });
    expect(broker.findConfiguredTokenForSecret(auth("ada@example.com"), "portainer-prod", "portainer-secret")).toBeUndefined();
    expect(broker.findConfiguredTokenForSecret(auth("henric@example.com"), "opnsense-home", "portainer-secret")).toBeUndefined();
    expect(broker.findConfiguredTokenForSecret(auth("henric@example.com"), "portainer-prod", "unknown")).toBeUndefined();
    now += 101;
    expect(broker.findConfiguredTokenForSecret(auth("henric@example.com"), "portainer-prod", "portainer-secret")).toBeUndefined();
  });
});

function tokenConfig(): GatewayConfig {
  return validateConfig({
    server: { listen: "127.0.0.1:8080", mcp_path: "/mcp" },
    auth: { mode: "bearer", bearer: { token_env: "TEST_GATEWAY_TOKEN" } },
    tokens: { idle_ttl: "50ms", max_ttl: "100ms" },
    services: {
      "portainer-prod": {
        type: "http",
        name: "Portainer Production",
        destinations: [
          { name: "primary", base_url: "https://portainer.internal:9443", ports: [9443] },
          { name: "secondary", base_url: "https://portainer-lab.internal:9443", ports: [9443] },
        ],
        credentials: [
          {
            id: "api_key",
            usage: { kind: "header", name: "X-API-Key" },
            source: { kind: "env", name: "PORTAINER_API_KEY" },
          },
          {
            id: "password",
            usage: { kind: "body", name: "password" },
            source: { kind: "env", name: "PORTAINER_PASSWORD" },
          },
        ],
        access: { users: ["henric@example.com"] },
      },
      "opnsense-home": {
        type: "http",
        name: "OPNsense Home",
        destinations: [{ name: "primary", base_url: "https://opnsense.internal" }],
        credentials: [{
          id: "api_key",
          usage: { kind: "header", name: "X-API-Key" },
          source: { kind: "env", name: "OPNSENSE_API_KEY" },
        }],
        access: { users: ["henric@example.com"] },
      },
    },
  }, {
    TEST_GATEWAY_TOKEN: "dev-token",
    PORTAINER_API_KEY: "portainer-secret",
    PORTAINER_PASSWORD: "password-secret",
    OPNSENSE_API_KEY: "opnsense-secret",
  });
}

function auth(subject: string, sessionId?: string): AuthContext {
  return {
    subject,
    scopes: ["gateway.tokens"],
    mode: "bearer",
    ...(sessionId === undefined ? {} : { sessionId }),
  };
}

function expectGatewayError(fn: () => unknown, code: GatewayError["code"]) {
  try {
    fn();
    throw new Error("Expected gateway error");
  } catch (error) {
    expect(error).toBeInstanceOf(GatewayError);
    expect((error as GatewayError).code).toBe(code);
  }
}
