import { describe, expect, it } from "vitest";
import { validateConfig } from "../src/config.js";
import { GatewayError } from "../src/errors.js";
import { evaluatePolicy } from "../src/policy.js";
import { getService, resolveDestination } from "../src/registry.js";
import type { AuthContext, GatewayConfig } from "../src/types.js";

describe("policy engine", () => {
  it("allows a GET request that matches an allow rule", () => {
    const context = policyContext(policyConfig("deny"));

    const decision = evaluatePolicy(context.service, context.target("/api/stacks"), "GET");

    expect(decision).toMatchObject({
      allowed: true,
      matchedRule: "allow-stack-read",
      policyMode: "deny",
    });
  });

  it("allows unmatched requests when mode is allow", () => {
    const context = policyContext(policyConfig("allow"));

    const decision = evaluatePolicy(context.service, context.target("/api/other"), "GET");

    expect(decision).toMatchObject({
      allowed: true,
      policyMode: "allow",
      reason: "Allowed by default policy mode.",
    });
  });

  it("matches host-specific rules against normalized hosts", () => {
    const context = policyContext(policyConfig("deny"));

    const decision = evaluatePolicy(context.service, context.targetUrl("https://PORTAINER.INTERNAL.:9443/api/hosted"), "GET");

    expect(decision).toMatchObject({
      allowed: true,
      matchedRule: "allow-host-read",
    });
  });

  it("denies DELETE requests with the matching deny rule", () => {
    const context = policyContext(policyConfig("deny"));

    const decision = evaluatePolicy(context.service, context.target("/api/stacks"), "DELETE");

    expect(decision).toMatchObject({
      allowed: false,
      matchedRule: "deny-delete",
      policyMode: "deny",
    });
    expect(decision.suggestion).not.toContain("bypass");
  });

  it("denies unmatched requests when mode is deny", () => {
    const context = policyContext(policyConfig("deny"));

    const decision = evaluatePolicy(context.service, context.target("/api/other"), "GET");

    expect(decision).toMatchObject({
      allowed: false,
      policyMode: "deny",
      reason: "Denied by default policy mode.",
    });
  });

  it("chooses deny when matching priorities tie", () => {
    const context = policyContext(policyConfig("allow"));

    const decision = evaluatePolicy(context.service, context.target("/api/tie"), "POST");

    expect(decision).toMatchObject({
      allowed: false,
      matchedRule: "deny-tie",
    });
  });

  it("rejects invalid policy regexes during config validation", () => {
    const raw = rawPolicyConfig("deny");
    raw.services["portainer-prod"].policy.rules[0].paths = ["["];

    expect(() => validateConfig(raw, policyEnv())).toThrow(GatewayError);
  });
});

function policyContext(config: GatewayConfig) {
  const actor = auth();
  const service = getService(config, "portainer-prod", actor);
  return {
    service,
    target: (path: string) => resolveDestination(config, actor, "portainer-prod", "primary", { path }),
    targetUrl: (url: string) => resolveDestination(config, actor, "portainer-prod", "primary", { url }),
  };
}

function policyConfig(mode: "allow" | "deny"): GatewayConfig {
  return validateConfig(rawPolicyConfig(mode), policyEnv());
}

function rawPolicyConfig(mode: "allow" | "deny"): any {
  return {
    server: { listen: "127.0.0.1:8080", mcp_path: "/mcp" },
    auth: { mode: "bearer", bearer: { token_env: "TEST_GATEWAY_TOKEN" } },
    services: {
      "portainer-prod": {
        type: "http",
        name: "Portainer Production",
        destinations: [{
          name: "primary",
          base_url: "https://portainer.internal:9443",
          hosts: [{ exact: "portainer.internal" }],
          ports: [9443],
        }],
        credentials: [{
          id: "api_key",
          usage: { kind: "header", name: "X-API-Key" },
          source: { kind: "env", name: "PORTAINER_API_KEY" },
        }],
        access: { users: ["henric@example.com"] },
        policy: {
          mode,
          rules: [
            {
              id: "allow-stack-read",
              effect: "allow",
              priority: 100,
              methods: ["GET"],
              paths: ["/api/stacks.*"],
            },
            {
              id: "allow-host-read",
              effect: "allow",
              priority: 200,
              methods: ["GET"],
              hosts: ["^portainer\\.internal$"],
              paths: ["/api/hosted"],
            },
            {
              id: "allow-tie",
              effect: "allow",
              priority: 500,
              methods: ["POST"],
              paths: ["/api/tie"],
            },
            {
              id: "deny-tie",
              effect: "deny",
              priority: 500,
              methods: ["POST"],
              paths: ["/api/tie"],
            },
            {
              id: "deny-delete",
              effect: "deny",
              priority: 1000,
              methods: ["DELETE"],
              paths: ["/.*"],
              reason: "DELETE blocked in MVP",
            },
          ],
        },
      },
    },
  };
}

function policyEnv() {
  return {
    TEST_GATEWAY_TOKEN: "dev-token",
    PORTAINER_API_KEY: "portainer-secret",
  };
}

function auth(): AuthContext {
  return { subject: "henric@example.com", scopes: ["gateway.request"], mode: "bearer" };
}
