import { describe, expect, it } from "vitest";
import { DenialStore, explainDenial as explainDenialWithStore } from "../src/denials.js";
import { GatewayError } from "../src/errors.js";
import { executeServiceRequest as executeServiceRequestWithDependencies, type ServiceRequestInput } from "../src/gateway.js";
import { TokenBroker } from "../src/tokens.js";
import { auth, registryConfig } from "./helpers.js";
import { createRequestId, publicRequestIdPattern } from "../src/requestId.js";
import { getAuditEvents as getAuditEventsFromSink } from "../src/audit.js";
import type { AuthContext, GatewayConfig } from "../src/types.js";
import { capabilitiesFor, installTokenBroker, requestDependenciesFor } from "./capabilityHelpers.js";

function executeServiceRequest(config: GatewayConfig, actor: AuthContext, input: ServiceRequestInput) {
  return executeServiceRequestWithDependencies(config, actor, input, requestDependenciesFor(config));
}

function getAuditEvents(config: GatewayConfig) {
  return getAuditEventsFromSink(requestDependenciesFor(config).auditSink);
}

function explainDenial(config: GatewayConfig, actor: { subject: string }, requestId: string) {
  return explainDenialWithStore(capabilitiesFor(config).denialStore, actor, requestId);
}

describe("denial explanations", () => {
  it("returns safe denial context for the same subject", async () => {
    const config = registryConfig();
    installTokenBroker(config, (auditSink) => new TokenBroker(config, undefined, auditSink));
    let requestId = "";

    try {
      await executeServiceRequest(config, auth("henric@example.com"), {
        service: "portainer-prod",
        destination: "primary",
        method: "GET",
        path: "/api/not-allowed",
        reason: "Trigger policy denial.",
      });
    } catch (error) {
      expect(error).toBeInstanceOf(GatewayError);
      requestId = (error as GatewayError).requestId ?? "";
    }

    const explanation = explainDenial(config, auth("henric@example.com"), requestId);
    expect(requestId).toMatch(publicRequestIdPattern);
    expect(explanation).toMatchObject({
      request_id: requestId,
      reason: "Denied by default policy mode.",
      policy_mode: "deny",
    });
    expect(getAuditEvents(config)).toContainEqual(expect.objectContaining({
      type: "service_request", request_id: requestId, policy_decision: "deny", error_code: "policy_denied",
    }));
    expect(explanation?.suggestion).not.toContain("bypass");
  });

  it("keeps denial context subject-bound across stateless requests", async () => {
    const config = registryConfig();
    installTokenBroker(config, (auditSink) => new TokenBroker(config, undefined, auditSink));
    const sameSubject = auth("henric@example.com");
    let requestId = "";

    try {
      await executeServiceRequest(config, sameSubject, {
        service: "portainer-prod",
        destination: "primary",
        method: "GET",
        path: "/api/not-allowed",
        reason: "Trigger policy denial.",
      });
    } catch (error) {
      requestId = (error as GatewayError).requestId ?? "";
    }

    expect(explainDenial(config, auth("ada@example.com"), requestId)).toBeUndefined();
    expect(explainDenial(config, sameSubject, requestId)?.request_id).toBe(requestId);
  });

  it("expires denial records and evicts the least recently used record", () => {
    let now = 0;
    const store = new DenialStore(2, 10, () => now);
    const first = store.record({ subject: "actor", reason: "first", policy_mode: "deny" });
    const second = store.record({ subject: "actor", reason: "second", policy_mode: "deny" });
    expect(store.get(first.request_id)?.reason).toBe("first");
    const third = store.record({ subject: "actor", reason: "third", policy_mode: "deny" });
    expect(store.get(second.request_id)).toBeUndefined();
    expect(store.get(third.request_id)?.reason).toBe("third");
    now = 11;
    store.sweep(now);
    expect(store.get(first.request_id)).toBeUndefined();
  });

  it("generates unique public request IDs even when the clock is fixed", () => {
    const now = Date.now;
    Date.now = () => 1234;
    try {
      const ids = Array.from({ length: 1000 }, () => createRequestId());
      expect(new Set(ids)).toHaveLength(ids.length);
      expect(ids.every((id) => publicRequestIdPattern.test(id))).toBe(true);
    } finally {
      Date.now = now;
    }
  });
});
