import { describe, expect, it } from "vitest";
import { explainDenial } from "../src/denials.js";
import { GatewayError } from "../src/errors.js";
import { executeServiceRequest } from "../src/gateway.js";
import { TokenBroker, defaultTokenBrokers } from "../src/tokens.js";
import { auth, registryConfig } from "./helpers.js";

describe("denial explanations", () => {
  it("returns safe denial context for the same subject", async () => {
    const config = registryConfig();
    defaultTokenBrokers.set(config, new TokenBroker(config));
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

    const explanation = explainDenial(auth("henric@example.com"), requestId);
    expect(explanation).toMatchObject({
      request_id: requestId,
      reason: "Denied by default policy mode.",
      policy_mode: "deny",
    });
    expect(explanation?.suggestion).not.toContain("bypass");
  });

  it("does not expose denial context to another subject or session", async () => {
    const config = registryConfig();
    defaultTokenBrokers.set(config, new TokenBroker(config));
    const sameSession = auth("henric@example.com", "session-a");
    let requestId = "";

    try {
      await executeServiceRequest(config, sameSession, {
        service: "portainer-prod",
        destination: "primary",
        method: "GET",
        path: "/api/not-allowed",
        reason: "Trigger policy denial.",
      });
    } catch (error) {
      requestId = (error as GatewayError).requestId ?? "";
    }

    expect(explainDenial(auth("ada@example.com", "session-a"), requestId)).toBeUndefined();
    expect(explainDenial(auth("henric@example.com", "session-b"), requestId)).toBeUndefined();
  });
});
