import { createServer, type IncomingMessage } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { once } from "node:events";
import { describe, expect, it, vi } from "vitest";
import { validateConfig } from "../src/config.js";
import { getAuditEvents } from "../src/audit.js";
import { GatewayError } from "../src/errors.js";
import { executeServiceRequest as executeServiceRequestWithDependencies, type ServiceRequestInput } from "../src/gateway.js";
import { TokenBroker } from "../src/tokens.js";
import type { AuthContext, GatewayConfig } from "../src/types.js";
import { capabilitiesFor, installTokenBroker } from "./capabilityHelpers.js";

function executeServiceRequest(config: GatewayConfig, auth: AuthContext, input: ServiceRequestInput) {
  return executeServiceRequestWithDependencies(config, auth, input, capabilitiesFor(config));
}

describe("HTTP gateway", () => {
  it("requires and consumes a bound gateway access reference for credential-free services", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl, { noAuth: true });
      const broker = installBroker(config);
      const auth = actor();
      const token = broker.issueTokens(auth, {
        service: "demo-service", destination: "primary", access_ids: ["gateway_access"], reason: "Inspect cameras.",
      }).tokens[0]?.token ?? "";

      const response = await executeServiceRequest(config, auth, {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/echo",
        service_reference: token, reason: "Inspect cameras.",
      });

      expect(response.status_code).toBe(200);
      expect(downstream.requests).toHaveLength(1);
      expect(JSON.stringify(downstream.requests[0])).not.toContain(token);
      const event = getAuditEvents(config).find((item) => item.type === "service_request");
      expect(event).toMatchObject({ access_ids: ["gateway_access"] });
      expect(JSON.stringify(event)).not.toContain(token);
    } finally {
      await downstream.close();
    }
  });

  it("rejects missing, wrong-subject, wrong-destination, and expired service references before downstream I/O", async () => {
    const downstream = await startDownstream();
    try {
      let now = 1_000;
      const config = gatewayConfig(downstream.baseUrl, { noAuth: true, includeSecondary: true });
      const broker = new TokenBroker(config, () => now);
      installTokenBroker(config, broker);
      const token = broker.issueTokens(actor(), {
        service: "demo-service", destination: "primary", access_ids: ["gateway_access"], reason: "Inspect cameras.",
      }).tokens[0]?.token ?? "";
      const request = {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/echo", reason: "Inspect cameras.",
      } as const;

      await expectGatewayError(() => executeServiceRequest(config, actor(), request), "reference_invalid");
      await expectGatewayError(() => executeServiceRequest(config, { ...actor(), subject: "ada@example.com" }, {
        ...request, service_reference: token,
      }), "reference_invalid");
      await expectGatewayError(() => executeServiceRequest(config, actor(), {
        ...request, destination: "secondary", service_reference: token,
      }), "reference_invalid");
      now += 3_600_001;
      await expectGatewayError(() => executeServiceRequest(config, actor(), {
        ...request, service_reference: token,
      }), "reference_expired");
      expect(downstream.requests).toHaveLength(0);
    } finally {
      await downstream.close();
    }
  });

  it("rejects service_reference for credential-backed services before downstream I/O", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      const broker = installBroker(config);
      const token = broker.issueTokens(actor(), {
        service: "demo-service", destination: "primary", access_ids: ["api_key"], reason: "Inspect service.",
      }).tokens[0]?.token ?? "";

      await expectGatewayError(() => executeServiceRequest(config, actor(), {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/echo",
        service_reference: token, reason: "Inspect service.",
      }), "reference_invalid");
      expect(downstream.requests).toHaveLength(0);
    } finally {
      await downstream.close();
    }
  });

  it("substitutes tokens in headers, query, and body after policy allows the request", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      const broker = installBroker(config);
      const auth = actor();
      const issued = broker.issueTokens(auth, {
        service: "demo-service",
        destination: "primary",
        access_ids: ["api_key"],
        reason: "Call downstream test service.",
      });
      const token = issued.tokens[0]?.token ?? "";

      const response = await executeServiceRequest(config, auth, {
        service: "demo-service",
        destination: "primary",
        method: "POST",
        path: "/api/echo",
        headers: { "X-API-Key": token, "X-Request-Mode": "ordinary" },
        query: { api_key: token },
        body: { credential: token },
        reason: "Exercise substitution.",
      });

      expect(response.status_code).toBe(200);
      expect(response.tls.verify).toBe(false);
      expect(response.body).not.toContain("demo-secret");
      expect(response.secret_tokenized).toBe(true);
      expect(response.secret_tokenization_count).toBeGreaterThan(0);
      expect(response).not.toHaveProperty("redacted");
      expect(response.headers["content-length"]).toBe(String(Buffer.byteLength(response.body)));
      expect(downstream.requests).toHaveLength(1);
      expect(downstream.requests[0]?.headers["x-api-key"]).toBe("demo-secret");
      expect(downstream.requests[0]?.headers["x-request-mode"]).toBe("ordinary");
      expect(downstream.requests[0]?.headers["host"]).toBe(new URL(downstream.baseUrl).host);
      expect(downstream.requests[0]?.url).toContain("api_key=demo-secret");
      expect(downstream.requests[0]?.body).toContain("demo-secret");
      expect(downstream.requests[0]?.headers["content-length"]).toBe(String(Buffer.byteLength(downstream.requests[0]?.body ?? "")));
    } finally {
      await downstream.close();
    }
  });

  it("enforces an opted-in header template and tokenizes a clean credential under a token key", async () => {
    const downstream = await startDownstream();
    const lines: string[] = [];
    const log = vi.spyOn(console, "log").mockImplementation((line) => lines.push(String(line)));
    try {
      const config = gatewayConfig(downstream.baseUrl, { headerTemplate: { prefix: "Bearer ", enforce: true } });
      const broker = installBroker(config);
      const auth = actor();
      const reference = broker.issueTokens(auth, {
        service: "demo-service", destination: "primary", access_ids: ["api_key"], reason: "Test enforced header.",
      }).tokens[0]!.token;

      const response = await executeServiceRequest(config, auth, {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/token",
        headers: { "X-API-Key": `wrong ${reference}`, "x-api-key": "caller-controlled" },
        reason: "Verify header ownership and response protection.",
      });

      expect(downstream.requests).toHaveLength(1);
      expect(downstream.requests[0]?.headers["x-api-key"]).toBe("Bearer demo-secret");
      expect(response.body).toBe(`{\n  "token": "${reference}",\n  "status": "ok"\n}`);
      expect(response.secret_tokenized).toBe(true);
      expect(response.secret_tokenization_count).toBe(1);
      const serialized = lines.join("\n");
      expect(serialized).toContain("auth_header_override_clobbered");
      expect(serialized).not.toContain(reference);
      expect(serialized).not.toContain("demo-secret");
      expect(serialized).not.toContain("caller-controlled");

      await expectGatewayError(() => executeServiceRequest(config, auth, {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/token",
        headers: { "X-API-Key": "caller-controlled" }, reason: "Reject an auth header override.",
      }), "reference_invalid");
      expect(downstream.requests).toHaveLength(1);
    } finally {
      log.mockRestore();
      await downstream.close();
    }
  });

  it("keeps header placement flexible when usage enforcement is omitted", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl, { headerTemplate: { prefix: "Bearer ", enforce: false } });
      const broker = installBroker(config);
      const reference = broker.issueTokens(actor(), {
        service: "demo-service", destination: "primary", access_ids: ["api_key"], reason: "Test compatibility.",
      }).tokens[0]!.token;

      await executeServiceRequest(config, actor(), {
        service: "demo-service", destination: "primary", method: "POST", path: "/api/echo",
        headers: { "X-Other": `Bearer ${reference}` }, reason: "Keep flexible placement.",
      });

      expect(downstream.requests[0]?.headers["x-other"]).toBe("Bearer demo-secret");
    } finally { await downstream.close(); }
  });

  it("rejects a suffix sibling host before credential substitution or downstream I/O", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      const destination = config.services["demo-service"]?.destinations[0];
      if (destination === undefined) throw new Error("Expected destination");
      destination.hosts = [{ type: "suffix", value: "example.org" }];
      const broker = installBroker(config);
      const auth = actor();
      const token = broker.issueTokens(auth, {
        service: "demo-service", destination: "primary", access_ids: ["api_key"], reason: "Test suffix boundary.",
      }).tokens[0]?.token ?? "";

      await expect(executeServiceRequest(config, auth, {
        service: "demo-service", destination: "primary", method: "GET",
        url: "http://attackerexample.org/api/echo", headers: { "X-API-Key": token }, reason: "Reject sibling host.",
      })).rejects.toMatchObject({ code: "host_not_allowed" });
      expect(downstream.requests).toHaveLength(0);
    } finally {
      await downstream.close();
    }
  });

  it("rejects ambiguous encoded paths before credential substitution or downstream I/O", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      const broker = installBroker(config);
      const auth = actor();
      const token = broker.issueTokens(auth, {
        service: "demo-service", destination: "primary", access_ids: ["api_key"], reason: "Test encoded path rejection.",
      }).tokens[0]?.token ?? "";

      await expect(executeServiceRequest(config, auth, {
        service: "demo-service", destination: "primary", method: "GET",
        path: "/%61pi/echo", headers: { "X-API-Key": token }, reason: "Reject ambiguous path.",
      })).rejects.toMatchObject({ code: "destination_not_allowed" });
      expect(downstream.requests).toHaveLength(0);
    } finally {
      await downstream.close();
    }
  });

  it("round trips response-generated sec tokens through headers, query, and nested bodies", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      installBroker(config);
      const auth = actor();
      const first = await executeServiceRequest(config, auth, {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/echo",
        reason: "Obtain a response secret reference.",
      });
      const token = first.headers["x-leaked-secret"] ?? "";
      expect(token).toMatch(/^sec_[A-Za-z0-9_-]+$/);
      expect(first.body).toBe(`ok ${token} `);
      expect(first.body).not.toContain("demo-secret");

      await executeServiceRequest(config, auth, {
        service: "demo-service", destination: "primary", method: "POST", path: "/api/echo",
        headers: { "X-Returned-Secret": token }, query: { returned_secret: token },
        body: { returned_secret: token, nested: [`prefix ${token} suffix`] },
        reason: "Reuse the response secret reference.",
      });

      expect(downstream.requests).toHaveLength(2);
      expect(downstream.requests[1]?.headers["x-returned-secret"]).toBe("demo-secret");
      expect(downstream.requests[1]?.url).toContain("returned_secret=demo-secret");
      expect(downstream.requests[1]?.body).toBe('{"returned_secret":"demo-secret","nested":["prefix demo-secret suffix"]}');
    } finally { await downstream.close(); }
  });

  it("round trips response-generated sec tokens through JSON without changing source text", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      installBroker(config);
      const auth = actor();
      const first = await executeServiceRequest(config, auth, {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/json",
        reason: "Obtain tokenized JSON.",
      });
      const token = first.body.match(/sec_[A-Za-z0-9_-]+/)?.[0] ?? "";
      expect(token).toMatch(/^sec_[A-Za-z0-9_-]+$/);
      expect(first.body.split(token).join("demo-secret")).toBe(JSON_RESPONSE_BODY);

      await executeServiceRequest(config, auth, {
        service: "demo-service", destination: "primary", method: "POST", path: "/api/echo",
        headers: { "Content-Type": "application/json" }, body: first.body,
        reason: "Round trip tokenized JSON.",
      });

      expect(downstream.requests).toHaveLength(2);
      expect(downstream.requests[1]?.body).toBe(JSON_RESPONSE_BODY);
    } finally { await downstream.close(); }
  });

  it("round trips tolerant sensitive-name environment shapes without changing surrounding JSON source", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      installBroker(config);
      const auth = actor();
      const first = await executeServiceRequest(config, auth, {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/sensitive-json",
        reason: "Obtain tolerant sensitive-name JSON.",
      });
      const tokens = first.body.match(/sec_[A-Za-z0-9_-]+/g) ?? [];
      expect(tokens).toHaveLength(6);
      expect(first.body).toContain('"public_key":"visible"');
      expect(first.body).toContain('"token_type":"Bearer"');
      expect(first.body).not.toContain("pem-value-雪");
      expect(first.headers["content-length"]).toBe(String(Buffer.byteLength(first.body)));

      await executeServiceRequest(config, auth, {
        service: "demo-service", destination: "primary", method: "POST", path: "/api/echo",
        headers: { "Content-Type": "application/json", "Content-Length": "1" }, body: first.body,
        reason: "Restore tolerant sensitive-name JSON.",
      });
      expect(downstream.requests[1]?.body).toBe(SENSITIVE_JSON_RESPONSE_BODY);
      expect(downstream.requests[1]?.headers["content-length"]).toBe(String(Buffer.byteLength(SENSITIVE_JSON_RESPONSE_BODY)));

      const token = tokens[0]!;
      const altered = `${token.slice(0, -1)}${token.endsWith("A") ? "B" : "A"}`;
      await expectGatewayError(() => executeServiceRequest(config, auth, {
        service: "demo-service", destination: "primary", method: "POST", path: "/api/echo",
        headers: { "Content-Type": "application/json" }, body: first.body.replace(token, altered),
        reason: "Reject altered sensitive-name JSON token.",
      }), "reference_invalid");
      expect(downstream.requests).toHaveLength(2);
    } finally { await downstream.close(); }
  });

  it("round trips tolerant sensitive-name JSON through declared Base64", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      installBroker(config);
      const auth = actor();
      const first = await executeServiceRequest(config, auth, {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/sensitive-base64",
        reason: "Obtain encoded sensitive-name JSON.",
      });
      const decoded = Buffer.from(first.body, "base64").toString("utf8");
      expect(decoded.match(/sec_[A-Za-z0-9_-]+/g)).toHaveLength(6);
      expect(decoded).toContain('"public_key":"visible"');
      expect(first.headers["content-transfer-encoding"]).toBe("base64");
      expect(first.headers["content-length"]).toBe(String(Buffer.byteLength(first.body)));

      await executeServiceRequest(config, auth, {
        service: "demo-service", destination: "primary", method: "POST", path: "/api/echo",
        headers: {
          "Content-Type": "application/json", "Content-Transfer-Encoding": "base64", "Content-Length": "1",
        },
        body: first.body,
        reason: "Restore encoded sensitive-name JSON.",
      });
      const delivered = downstream.requests[1]!;
      expect(Buffer.from(delivered.body, "base64").toString("utf8")).toBe(SENSITIVE_JSON_RESPONSE_BODY);
      expect(delivered.headers["content-transfer-encoding"]).toBe("base64");
      expect(delivered.headers["content-length"]).toBe(String(Buffer.byteLength(delivered.body)));
    } finally { await downstream.close(); }
  });

  it("fails closed on an incomplete sensitive JSON value", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      installBroker(config);
      await expectGatewayError(() => executeServiceRequest(config, actor(), {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/sensitive-incomplete",
        reason: "Reject an unsafe sensitive value range.",
      }), "secret_scan_failed");
      expect(downstream.requests).toHaveLength(1);
    } finally { await downstream.close(); }
  });

  it("rejects an altered response-generated sec token before downstream I/O", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      installBroker(config);
      const auth = actor();
      const first = await executeServiceRequest(config, auth, {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/echo",
        reason: "Obtain a response secret reference.",
      });
      const token = first.headers["x-leaked-secret"] ?? "";
      const replacement = token.endsWith("A") ? "B" : "A";
      const altered = `${token.slice(0, -1)}${replacement}`;

      await expectGatewayError(() => executeServiceRequest(config, auth, {
        service: "demo-service", destination: "primary", method: "POST", path: "/api/echo",
        body: altered, reason: "Reject an altered response token.",
      }), "reference_invalid");
      expect(downstream.requests).toHaveLength(1);
    } finally { await downstream.close(); }
  });

  it("rejects caller-controlled authority headers before substitution or HTTP I/O", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      const broker = installBroker(config);
      const token = broker.issueTokens(actor(), {
        service: "demo-service", destination: "primary", access_ids: ["api_key"], reason: "Test authority rejection.",
      }).tokens[0]?.token ?? "";

      for (const name of ["Host", ":AUTHORITY", "Forwarded", "X-Forwarded-Host", "x-FORWARDED-proto"]) {
        await expectGatewayError(() => executeServiceRequest(config, actor(), {
          service: "demo-service", destination: "primary", method: "GET", path: "/api/echo",
          headers: { [name]: token }, reason: "Reject authority override.",
        }), "destination_not_allowed");
      }
      expect(downstream.requests).toHaveLength(0);
    } finally {
      await downstream.close();
    }
  });

  it("rejects caller-controlled authority before self-signed HTTPS I/O", async () => {
    const downstream = await startHttpsDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl, { tlsVerify: false });
      const broker = installBroker(config);
      const token = broker.issueTokens(actor(), {
        service: "demo-service", destination: "primary", access_ids: ["api_key"], reason: "Test HTTPS authority rejection.",
      }).tokens[0]?.token ?? "";

      await expectGatewayError(() => executeServiceRequest(config, actor(), {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/echo",
        headers: { Host: "unapproved.example.org", "X-API-Key": token }, reason: "Reject HTTPS authority override.",
      }), "destination_not_allowed");
      expect(downstream.requests).toHaveLength(0);
    } finally {
      await downstream.close();
    }
  });

  it("rejects hop-by-hop and forwarding headers before substitution or I/O", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      const broker = installBroker(config);
      const token = broker.issueTokens(actor(), {
        service: "demo-service", destination: "primary", access_ids: ["api_key"], reason: "Test hop-by-hop rejection.",
      }).tokens[0]?.token ?? "";

      for (const name of [
        "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection",
        "TE", "Trailer", "Upgrade", "X-Forwarded-For", "x-forwarded-custom",
      ]) {
        await expectGatewayError(() => executeServiceRequest(config, actor(), {
          service: "demo-service", destination: "primary", method: "GET", path: "/api/echo",
          headers: { [name]: token }, reason: "Reject hop-by-hop header.",
        }), "destination_not_allowed");
      }
      expect(downstream.requests).toHaveLength(0);
    } finally {
      await downstream.close();
    }
  });

  it("allows self-signed HTTPS downstream requests when TLS verification is disabled", async () => {
    const downstream = await startHttpsDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl, { tlsVerify: false });
      installBroker(config);

      const response = await executeServiceRequest(config, actor(), {
        service: "demo-service",
        destination: "primary",
        method: "GET",
        path: "/api/echo",
        reason: "Call self-signed downstream test service.",
      });

      expect(response.status_code).toBe(200);
      expect(response.tls.verify).toBe(false);
      expect(downstream.requests).toHaveLength(1);
    } finally {
      await downstream.close();
    }
  });

  it("rejects self-signed HTTPS downstream requests when TLS verification is enabled", async () => {
    const downstream = await startHttpsDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl, { tlsVerify: true });
      installBroker(config);

      await expectGatewayError(() => executeServiceRequest(config, actor(), {
        service: "demo-service",
        destination: "primary",
        method: "GET",
        path: "/api/echo",
        reason: "Reject self-signed downstream test service.",
      }), "tls_error");
      expect(downstream.requests).toHaveLength(0);
    } finally {
      await downstream.close();
    }
  });

  it("does not send policy-denied requests downstream", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      const broker = installBroker(config);
      const issued = broker.issueTokens(actor(), {
        service: "demo-service",
        destination: "primary",
        access_ids: ["api_key"],
        reason: "Call downstream test service.",
      });

      await expectGatewayError(() => executeServiceRequest(config, actor(), {
        service: "demo-service",
        destination: "primary",
        method: "GET",
        path: "/api/blocked",
        headers: { "X-API-Key": issued.tokens[0]?.token ?? "" },
        reason: "This should be denied.",
      }), "policy_denied");
      expect(downstream.requests).toHaveLength(0);
    } finally {
      await downstream.close();
    }
  });

  it("rejects globally saturated work before reference validation or downstream I/O and reuses released slots", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl, {
        maxServiceRequestsInflight: 1,
        maxServiceRequestsInflightPerSubject: 1,
      });
      installBroker(config);
      const first = executeServiceRequest(config, actor(), {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/slow",
        reason: "Hold the only downstream slot.",
      });
      await waitForRequestCount(downstream.requests, 1);

      await expectGatewayError(() => executeServiceRequest(config, { ...actor(), subject: "ada@example.com" }, {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/echo",
        headers: { "X-API-Key": "gref_invalid" }, reason: "Reject before reference validation.",
      }), "capacity_exceeded");
      expect(downstream.requests.map((request) => request.path)).toEqual(["/api/slow"]);

      await first;
      await executeServiceRequest(config, actor(), {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/echo",
        reason: "Reuse the released slot.",
      });
      expect(downstream.requests.map((request) => request.path)).toEqual(["/api/slow", "/api/echo"]);
    } finally {
      await downstream.close();
    }
  });

  it("limits one subject without blocking another subject below global capacity", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl, {
        maxServiceRequestsInflight: 2,
        maxServiceRequestsInflightPerSubject: 1,
      });
      installBroker(config);
      const first = executeServiceRequest(config, actor(), {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/slow",
        reason: "Hold this subject's slot.",
      });
      await waitForRequestCount(downstream.requests, 1);

      await expectGatewayError(() => executeServiceRequest(config, actor(), {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/echo",
        reason: "Exceed this subject's capacity.",
      }), "capacity_exceeded");
      const other = await executeServiceRequest(config, { ...actor(), subject: "ada@example.com" }, {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/echo",
        reason: "Use another subject's slot.",
      });

      expect(other.status_code).toBe(200);
      await first;
      expect(downstream.requests.map((request) => request.path)).toEqual(["/api/slow", "/api/echo"]);
    } finally {
      await downstream.close();
    }
  });

  it("isolates a saturated slow service from another service and releases service capacity", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl, {
        maxServiceRequestsInflight: 2,
        maxServiceRequestsInflightPerSubject: 2,
        maxServiceRequestsInflightPerService: 1,
      });
      const original = config.services["demo-service"];
      if (original === undefined) throw new Error("Expected demo service");
      config.services["other-service"] = { ...original, id: "other-service", name: "Other Service" };
      installBroker(config);
      const first = executeServiceRequest(config, actor(), {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/slow",
        reason: "Hold one service's slot.",
      });
      await waitForRequestCount(downstream.requests, 1);

      await expectGatewayError(() => executeServiceRequest(config, actor(), {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/echo",
        reason: "Exceed one service's capacity.",
      }), "capacity_exceeded");
      const other = await executeServiceRequest(config, actor(), {
        service: "other-service", destination: "primary", method: "GET", path: "/api/echo",
        reason: "Use another service's capacity.",
      });

      expect(other.status_code).toBe(200);
      await first;
      await executeServiceRequest(config, actor(), {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/echo",
        reason: "Reuse released service capacity.",
      });
      expect(downstream.requests.map((request) => request.path)).toEqual(["/api/slow", "/api/echo", "/api/echo"]);
    } finally {
      await downstream.close();
    }
  });

  it("rejects unknown and wrong-destination tokens before downstream calls", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl, { includeSecondary: true });
      const broker = installBroker(config);
      const issued = broker.issueTokens(actor(), {
        service: "demo-service",
        destination: "primary",
        access_ids: ["api_key"],
        reason: "Call downstream test service.",
      });

      await expectGatewayError(() => executeServiceRequest(config, actor(), {
        service: "demo-service",
        destination: "primary",
        method: "GET",
        path: "/api/echo",
        headers: { "X-API-Key": "gref_unknown" },
        reason: "Unknown token.",
      }), "reference_invalid");
      await expectGatewayError(() => executeServiceRequest(config, actor(), {
        service: "demo-service",
        destination: "secondary",
        method: "GET",
        path: "/api/echo",
        headers: { "X-API-Key": issued.tokens[0]?.token ?? "" },
        reason: "Wrong destination.",
      }), "reference_invalid");
      expect(downstream.requests).toHaveLength(0);
    } finally {
      await downstream.close();
    }
  });

  it("does not follow redirects", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      installBroker(config);

      const response = await executeServiceRequest(config, actor(), {
        service: "demo-service",
        destination: "primary",
        method: "GET",
        path: "/api/redirect",
        reason: "Check redirect handling.",
      });

      expect(response.status_code).toBe(302);
      expect(downstream.requests.map((request) => request.path)).toEqual(["/api/redirect"]);
    } finally {
      await downstream.close();
    }
  });

  it("reports downstream timeouts", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl, {
        timeout: "10ms",
        maxServiceRequestsInflight: 1,
        maxServiceRequestsInflightPerSubject: 1,
        maxServiceRequestsInflightPerService: 1,
      });
      installBroker(config);

      await expectGatewayError(() => executeServiceRequest(config, actor(), {
        service: "demo-service",
        destination: "primary",
        method: "GET",
        path: "/api/slow",
        reason: "Check timeout.",
      }), "downstream_timeout");
      const response = await executeServiceRequest(config, actor(), {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/echo",
        reason: "Reuse capacity after timeout.",
      });
      expect(response.status_code).toBe(200);
    } finally {
      await downstream.close();
    }
  });

  it("rejects oversized requests and fails closed on oversized responses", async () => {
    const downstream = await startDownstream();
    try {
      const smallRequestConfig = gatewayConfig(downstream.baseUrl, { maxRequestBody: "5b" });
      installBroker(smallRequestConfig);
      await expectGatewayError(() => executeServiceRequest(smallRequestConfig, actor(), {
        service: "demo-service",
        destination: "primary",
        method: "POST",
        path: "/api/echo",
        body: "too large",
        reason: "Check request size.",
      }), "response_too_large");

      const smallResponseConfig = gatewayConfig(downstream.baseUrl, { maxResponseBody: "10b" });
      installBroker(smallResponseConfig);
      await expectGatewayError(() => executeServiceRequest(smallResponseConfig, actor(), {
        service: "demo-service",
        destination: "primary",
        method: "GET",
        path: "/api/large",
        reason: "Check response truncation.",
      }), "response_too_large");

      const exact = await executeServiceRequest(smallResponseConfig, actor(), {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/exact",
        reason: "Accept exact response limit.",
      });
      expect(exact.body).toBe("0123456789");
      expect(exact.truncated).toBe(false);
    } finally {
      await downstream.close();
    }
  });

  it("aborts chunked and declared oversized downstream responses", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl, { maxResponseBody: "10b" });
      installBroker(config);
      for (const path of ["/api/chunked-large", "/api/declared-large", "/api/slow-large"]) {
        await expectGatewayError(() => executeServiceRequest(config, actor(), {
          service: "demo-service", destination: "primary", method: "GET", path,
          reason: "Reject streamed oversized response.",
        }), "response_too_large");
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(downstream.closedResponses).toBeGreaterThan(0);
    } finally {
      await downstream.close();
    }
  });

  it("rewrites request content length after substitution and rejects transfer encoding", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      const broker = installBroker(config);
      const secretToken = broker.issueOrReuseResponseSecret(actor(), "demo-service", "longer-秘密-value").token;
      await executeServiceRequest(config, actor(), {
        service: "demo-service", destination: "primary", method: "POST", path: "/api/echo",
        headers: { "Content-Length": "1", "content-LENGTH": "999" }, body: secretToken, reason: "Check framing.",
      });
      expect(downstream.requests[0]?.body).toBe("longer-秘密-value");
      expect(downstream.requests[0]?.headers["content-length"]).toBe(String(Buffer.byteLength("longer-秘密-value")));

      await expectGatewayError(() => executeServiceRequest(config, actor(), {
        service: "demo-service", destination: "primary", method: "POST", path: "/api/echo",
        headers: { "Transfer-Encoding": "chunked" }, body: "data", reason: "Reject framing.",
      }), "unsupported_transfer_encoding");
      expect(downstream.requests).toHaveLength(1);
    } finally { await downstream.close(); }
  });

  it("rejects request cookies and removes downstream response cookies", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      installBroker(config);
      await expectGatewayError(() => executeServiceRequest(config, actor(), {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/echo",
        headers: { Cookie: "session=secret" }, reason: "Reject cookies.",
      }), "cookie_not_allowed");
      expect(downstream.requests).toHaveLength(0);

      const response = await executeServiceRequest(config, actor(), {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/cookies", reason: "Strip cookies.",
      });
      expect(Object.keys(response.headers).map((name) => name.toLowerCase())).not.toContain("set-cookie");
      expect(response.headers["x-safe"]).toBe("yes");
    } finally { await downstream.close(); }
  });

  it("blocks forged opaque prefixes from exfiltrating an actual provider token end to end", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      installBroker(config);
      const response = await executeServiceRequest(config, actor(), {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/forged", reason: "Test prefix guard.",
      });
      expect(response.body).toMatch(/^sec_[A-Za-z0-9_-]+$/);
      expect(response.body).not.toContain("gref_ghp_");
      expect(response.body).not.toContain("ghp_");
      expect(response.secret_tokenized).toBe(true);
    } finally { await downstream.close(); }
  });

  it("recomputes returned length after Base64 tokenization", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      installBroker(config);
      const response = await executeServiceRequest(config, actor(), {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/base64", reason: "Test Base64 framing.",
      });
      const decoded = Buffer.from(response.body, "base64").toString("utf8");
      const token = decoded.match(/sec_[A-Za-z0-9_-]+/)?.[0] ?? "";
      expect(token).toMatch(/^sec_/);
      expect(decoded.split(token).join("demo-secret")).toBe(BASE64_RESPONSE_BODY);
      expect(response.headers["content-length"]).toBe(String(Buffer.byteLength(response.body)));
    } finally { await downstream.close(); }
  });

  it("round trips declared Base64 response tokens without corrupting decoded content", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      installBroker(config);
      const auth = actor();
      const first = await executeServiceRequest(config, auth, {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/base64",
        reason: "Obtain tokenized Base64 content.",
      });
      const decoded = Buffer.from(first.body, "base64").toString("utf8");
      const token = decoded.match(/sec_[A-Za-z0-9_-]+/)?.[0] ?? "";
      expect(token).toMatch(/^sec_[A-Za-z0-9_-]+$/);
      expect(decoded.split(token).join("demo-secret")).toBe(BASE64_RESPONSE_BODY);

      await executeServiceRequest(config, auth, {
        service: "demo-service", destination: "primary", method: "POST", path: "/api/echo",
        headers: { "Content-Transfer-Encoding": "base64", "Content-Length": "1" }, body: first.body,
        reason: "Round trip declared Base64 content.",
      });
      const declaredRequest = downstream.requests[1];
      expect(Buffer.from(declaredRequest?.body ?? "", "base64").toString("utf8")).toBe(BASE64_RESPONSE_BODY);
      expect(declaredRequest?.headers["content-transfer-encoding"]).toBe("base64");
      expect(declaredRequest?.headers["content-length"]).toBe(String(Buffer.byteLength(declaredRequest?.body ?? "")));

      await executeServiceRequest(config, auth, {
        service: "demo-service", destination: "primary", method: "POST", path: "/api/echo",
        body: first.body, reason: "Keep undeclared Base64 opaque.",
      });
      expect(downstream.requests[2]?.body).toBe(first.body);
    } finally { await downstream.close(); }
  });

  it("rejects invalid declared Base64 request bodies before downstream I/O", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      installBroker(config);
      const auth = actor();
      const first = await executeServiceRequest(config, auth, {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/base64",
        reason: "Obtain a Base64 response token.",
      });
      const decoded = Buffer.from(first.body, "base64").toString("utf8");
      const token = decoded.match(/sec_[A-Za-z0-9_-]+/)?.[0] ?? "";
      const replacement = token.endsWith("A") ? "B" : "A";
      const altered = decoded.replace(token, `${token.slice(0, -1)}${replacement}`);
      const invalidInputs: Array<{ headers: Record<string, string>; body: unknown; code: GatewayError["code"] }> = [
        { headers: { "Content-Transfer-Encoding": "base64" }, body: { encoded: first.body }, code: "unsupported_transfer_encoding" },
        { headers: { "Content-Transfer-Encoding": "base64" }, body: "%%%", code: "unsupported_transfer_encoding" },
        { headers: { "Content-Transfer-Encoding": "base64" }, body: "/w==", code: "unsupported_transfer_encoding" },
        { headers: { "Content-Transfer-Encoding": "gzip" }, body: first.body, code: "unsupported_transfer_encoding" },
        { headers: { "Content-Transfer-Encoding": "base64", "content-transfer-encoding": "base64" }, body: first.body, code: "unsupported_transfer_encoding" },
        { headers: { "Content-Transfer-Encoding": "base64" }, body: Buffer.from(altered, "utf8").toString("base64"), code: "reference_invalid" },
      ];

      for (const input of invalidInputs) {
        await expectGatewayError(() => executeServiceRequest(config, auth, {
          service: "demo-service", destination: "primary", method: "POST", path: "/api/echo",
          headers: input.headers, body: input.body, reason: "Reject invalid declared Base64.",
        }), input.code);
      }
      expect(downstream.requests).toHaveLength(1);
    } finally { await downstream.close(); }
  });

  it("returns clean invalid UTF-8 response bytes as a binary body", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      installBroker(config);
      const response = await executeServiceRequest(config, actor(), {
        service: "demo-service", destination: "primary", method: "GET", path: "/api/invalid-utf8", reason: "Reject invalid text.",
      });
      expect(response.body_encoding).toBe("mcp_blob");
      expect(response.binaryBody).toEqual(Buffer.from([0xff, 0xfe]));
    } finally { await downstream.close(); }
  });
});

function gatewayConfig(baseUrl: string, options: {
  includeSecondary?: boolean;
  noAuth?: boolean;
  timeout?: string;
  maxRequestBody?: string;
  maxResponseBody?: string;
  maxServiceRequestsInflight?: number;
  maxServiceRequestsInflightPerSubject?: number;
  maxServiceRequestsInflightPerService?: number;
  tlsVerify?: boolean;
  headerTemplate?: { prefix?: string; suffix?: string; enforce?: boolean };
} = {}): GatewayConfig {
  const base = new URL(baseUrl);
  const destinations = [
    { name: "primary", base_url: baseUrl, schemes: [base.protocol.replace(/:$/, "")], hosts: [{ exact: "127.0.0.1" }] },
  ];
  if (options.includeSecondary) {
    destinations.push({ name: "secondary", base_url: baseUrl, schemes: [base.protocol.replace(/:$/, "")], hosts: [{ exact: "127.0.0.1" }] });
  }
  return validateConfig({
    server: { listen: "127.0.0.1:8080", mcp_path: "/mcp" },
    auth: { mode: "bearer", bearer: { token_env: "TEST_GATEWAY_TOKEN" } },
    limits: {
      max_request_body: options.maxRequestBody ?? "1mb",
      max_response_body: options.maxResponseBody ?? "1mb",
      max_service_requests_inflight: options.maxServiceRequestsInflight ?? 32,
      max_service_requests_inflight_per_subject: options.maxServiceRequestsInflightPerSubject ?? 4,
      max_service_requests_inflight_per_service: options.maxServiceRequestsInflightPerService
        ?? Math.min(8, options.maxServiceRequestsInflight ?? 32),
      timeout: options.timeout ?? "1s",
    },
    services: {
      "demo-service": {
        type: "http",
        name: "Demo Service",
        destinations,
        tls: { verify: options.tlsVerify ?? false },
        ...(options.noAuth ? { no_auth: true } : {
          credentials: [{
            id: "api_key",
            usage: { kind: "header", name: "X-API-Key", ...options.headerTemplate },
            source: { kind: "env", name: "DEMO_API_KEY" },
          }],
        }),
        access: { users: ["henric@example.com", "ada@example.com"] },
        policy: {
          mode: "deny",
          rules: [
            { id: "allow-echo", effect: "allow", priority: 100, methods: ["GET", "POST"], paths: ["/api/echo"] },
            { id: "allow-json", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/json"] },
            { id: "allow-token", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/token"] },
            { id: "allow-sensitive-json", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/sensitive-json"], secretlint: { enabled: false } },
            { id: "allow-sensitive-base64", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/sensitive-base64"], secretlint: { enabled: false } },
            { id: "allow-sensitive-incomplete", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/sensitive-incomplete"], secretlint: { enabled: false } },
            { id: "allow-large", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/large"] },
            { id: "allow-exact", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/exact"] },
            { id: "allow-chunked-large", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/chunked-large"] },
            { id: "allow-declared-large", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/declared-large"] },
            { id: "allow-slow-large", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/slow-large"] },
            { id: "allow-redirect", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/redirect"] },
            { id: "allow-slow", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/slow"] },
            { id: "allow-cookies", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/cookies"] },
            { id: "allow-forged", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/forged"], secretlint: { enabled: false } },
            { id: "allow-base64", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/base64"] },
            { id: "allow-invalid-utf8", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/invalid-utf8"] },
            { id: "deny-blocked", effect: "deny", priority: 200, methods: ["GET"], paths: ["/api/blocked"] },
          ],
        },
      },
    },
  }, {
    TEST_GATEWAY_TOKEN: "dev-token",
    DEMO_API_KEY: "demo-secret",
  });
}

function installBroker(config: GatewayConfig): TokenBroker {
  const broker = new TokenBroker(config);
  installTokenBroker(config, broker);
  return broker;
}

function actor(): AuthContext {
  return { subject: "henric@example.com", scopes: ["gateway.request"], mode: "bearer" };
}

async function expectGatewayError(fn: () => Promise<unknown>, code: GatewayError["code"]) {
  try {
    await fn();
    throw new Error("Expected gateway error");
  } catch (error) {
    expect(error).toBeInstanceOf(GatewayError);
    expect((error as GatewayError).code).toBe(code);
  }
}

async function waitForRequestCount(requests: unknown[], count: number): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (requests.length >= count) return;
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  throw new Error(`Timed out waiting for ${count} downstream request(s)`);
}

async function startDownstream() {
  const requests: Array<{ path: string; url: string; headers: Record<string, string | string[] | undefined>; body: string }> = [];
  let closedResponses = 0;
  const server = createServer(async (request, response) => {
    response.on("close", () => {
      if (!response.writableEnded) closedResponses += 1;
    });
    const body = await readBody(request);
    requests.push({
      path: new URL(request.url ?? "/", "http://127.0.0.1").pathname,
      url: request.url ?? "/",
      headers: request.headers,
      body,
    });
    if (request.url?.startsWith("/api/redirect")) {
      response.writeHead(302, { location: "/api/echo" });
      response.end();
      return;
    }
    if (request.url === "/api/slow") {
      await new Promise((resolve) => setTimeout(resolve, 100));
      response.end("slow");
      return;
    }
    if (request.url?.startsWith("/api/large")) {
      response.end("x".repeat(100));
      return;
    }
    if (request.url?.startsWith("/api/exact")) {
      response.end("0123456789");
      return;
    }
    if (request.url?.startsWith("/api/chunked-large")) {
      response.write("123456");
      response.end("78901");
      return;
    }
    if (request.url?.startsWith("/api/declared-large")) {
      response.writeHead(200, { "content-length": "100" });
      response.end("x");
      return;
    }
    if (request.url?.startsWith("/api/slow-large")) {
      response.write("123456");
      await new Promise((resolve) => setTimeout(resolve, 10));
      response.write("78901");
      await Promise.race([
        once(response, "close"),
        new Promise((resolve) => setTimeout(resolve, 100)),
      ]);
      if (!response.destroyed) response.end();
      return;
    }
    if (request.url?.startsWith("/api/cookies")) {
      response.writeHead(200, { "set-cookie": ["session=secret; HttpOnly", "other=value"], "x-safe": "yes" });
      response.end("cookie response");
      return;
    }
    if (request.url?.startsWith("/api/json")) {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON_RESPONSE_BODY);
      return;
    }
    if (request.url?.startsWith("/api/token")) {
      response.writeHead(200, { "content-type": "application/json" });
      response.end('{\n  "token": "demo-secret",\n  "status": "ok"\n}');
      return;
    }
    if (request.url?.startsWith("/api/sensitive-json")) {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(SENSITIVE_JSON_RESPONSE_BODY);
      return;
    }
    if (request.url?.startsWith("/api/sensitive-base64")) {
      const encoded = Buffer.from(SENSITIVE_JSON_RESPONSE_BODY, "utf8").toString("base64");
      response.writeHead(200, {
        "content-type": "application/json", "content-transfer-encoding": "base64", "content-length": String(Buffer.byteLength(encoded)),
      });
      response.end(encoded);
      return;
    }
    if (request.url?.startsWith("/api/sensitive-incomplete")) {
      response.writeHead(200, { "content-type": "application/json" });
      response.end('{"SECRETSAUCE_ADMIN_PASSWORD_HASH_B64":"unterminated');
      return;
    }
    if (request.url?.startsWith("/api/forged")) {
      response.end(`gref_ghp_${"z".repeat(36)}`);
      return;
    }
    if (request.url?.startsWith("/api/base64")) {
      const encoded = Buffer.from(BASE64_RESPONSE_BODY, "utf8").toString("base64");
      response.writeHead(200, { "content-transfer-encoding": "base64", "content-length": String(Buffer.byteLength(encoded)) });
      response.end(encoded);
      return;
    }
    if (request.url?.startsWith("/api/invalid-utf8")) {
      response.end(Buffer.from([0xff, 0xfe]));
      return;
    }
    response.writeHead(200, {
      "content-type": "text/plain",
      "x-leaked-secret": "demo-secret",
    });
    response.end(`ok demo-secret ${body}`);
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Expected TCP address");
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    requests,
    get closedResponses() { return closedResponses; },
    close: () => new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    }),
  };
}

const JSON_RESPONSE_BODY = '{  "duplicate":1, "duplicate" : 2, "number":1.00, "unicode":"雪", "secret" : "demo-secret" }\n';
const BASE64_RESPONSE_BODY = 'prefix\n{ "unicode": "雪", "punctuation": "!@#$%^&*()", "secret": "demo-secret" }\nsuffix';
const SENSITIVE_JSON_RESPONSE_BODY = `{ /* preserve */
 "SECRETSAUCE_OAUTH_SIGNING_KEY_PEM_B64" : "pem-value-雪"
 "adminPasswordHashB64":"hash-value", "duplicate_password":"first", "duplicate_password" : "second",
 "public_key":"visible", "token_type":"Bearer", "PAYLOAD_B64":"visible",
 "environment":[
   {"value":"signing-value", "name":"SECRETSAUCE_OAUTH_SIGNING_KEY_PEM_B64"},
   "SECRETSAUCE_ADMIN_PASSWORD_HASH_B64=array-hash"
 ]`;

async function startHttpsDownstream() {
  const requests: Array<{ path: string; url: string; headers: Record<string, string | string[] | undefined>; body: string }> = [];
  const server = createHttpsServer({
    key: TEST_SELF_SIGNED_KEY,
    cert: TEST_SELF_SIGNED_CERT,
  }, async (request, response) => {
    const body = await readBody(request);
    requests.push({
      path: new URL(request.url ?? "/", "https://127.0.0.1").pathname,
      url: request.url ?? "/",
      headers: request.headers,
      body,
    });
    response.writeHead(200, {
      "content-type": "text/plain",
      "x-leaked-secret": "demo-secret",
    });
    response.end(`ok demo-secret ${body}`);
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Expected TCP address");
  return {
    baseUrl: `https://127.0.0.1:${address.port}`,
    requests,
    close: () => new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    }),
  };
}

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

const TEST_SELF_SIGNED_CERT = `-----BEGIN CERTIFICATE-----
MIIDGjCCAgKgAwIBAgIUbLd+/B7IaA/RJQIspVwlUEFjCZcwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJMTI3LjAuMC4xMB4XDTI2MDcxNDE0MDY0MFoXDTM2MDcx
MTE0MDY0MFowFDESMBAGA1UEAwwJMTI3LjAuMC4xMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA4zTvD4puMVojFM1kWVe9/2qF5QBHDMrGa+NaUTjizSkY
Hjqnb9rckl8t705ztCx7p9qtybgTE9ta/GrH/w7F1tSucZThc+alk6gd7SOoqSTr
iHuHuf73IvNkDv3TFALKCZDxl73CvCwYEtD0LhK0ZJWzhLUY1SJDHTVvdFZ5o92o
mksKJkVEk58llvl+e9okPmqbxvRJ+3I9v80ek5H5FoQy/juu0o7XCIASlT/iopDi
zZxPQcd3Clt4ygsR8KUdaxeiVvI6CYeHP6+lmZGmTThQOWeNXoUNp8875c/u/uNk
gHvEWXduTG+DzXx/qO6JyXp+VGLN22sa1DGpEtnCcQIDAQABo2QwYjAdBgNVHQ4E
FgQUWsHznlXzQy1YbMgIMSXgiTW/7UYwHwYDVR0jBBgwFoAUWsHznlXzQy1YbMgI
MSXgiTW/7UYwDwYDVR0TAQH/BAUwAwEB/zAPBgNVHREECDAGhwR/AAABMA0GCSqG
SIb3DQEBCwUAA4IBAQBkmRyr73A4f814jnGJBV6tN1Eq+iWfTCwwPOmRwjFwLXkA
iTbvlyLaNhLGC83fFe3v8C8sAJCTy7q6X7n8fYzEdHR5W4x9CM90klIcT6cjLBYg
iwnlW0Auzz0ZHuRWks5mnN2BxtDB4OzHLRMSw38LpTe22FesYtaC8YDE9Ar+74GG
lbgFbnnM/Q/uMw+234ggjAj6fT+ATLuajFfxNmtoEY8kPKaDdkXTp4/Bs7N2oIg/
JX/GmPEshIWOHwEqD0zk4wjYz6xYTbC1P0WumV0cVyPaQVmYOLUdSqCL3zocJJ6h
KLDF42+5to1QZuI2ZKv6L6rzaTL1AIzw9d0OHmRW
-----END CERTIFICATE-----`;

const TEST_SELF_SIGNED_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4zTvD4puMVojFM1kWVe9/2qF5QBHDMrGa+NaUTjizSkYHjqn
b9rckl8t705ztCx7p9qtybgTE9ta/GrH/w7F1tSucZThc+alk6gd7SOoqSTriHuH
uf73IvNkDv3TFALKCZDxl73CvCwYEtD0LhK0ZJWzhLUY1SJDHTVvdFZ5o92omksK
JkVEk58llvl+e9okPmqbxvRJ+3I9v80ek5H5FoQy/juu0o7XCIASlT/iopDizZxP
Qcd3Clt4ygsR8KUdaxeiVvI6CYeHP6+lmZGmTThQOWeNXoUNp8875c/u/uNkgHvE
WXduTG+DzXx/qO6JyXp+VGLN22sa1DGpEtnCcQIDAQABAoIBAA3/HIv/Sd8B77/Q
EFK9qD90CzgKfpX/5t3OFWoEAFrFoY35LIfkOmrM8Lo5gcCzbdGvE74luA0k2fPL
SzM/8HmVxAJMut/GMWSJeoB5jiIPW3AetgOD/Kr7Repzgf2NV29j7bIcl0K6z6fX
FffBoLnCjBrMgjFdCTfjKxDGY/tvZjtXr2cehtkq56LIAywluYNPNHoGapVT+IbE
VdOMrziFsQPyRtiYkIRc+FSy4Hz2tLQxbbYVTT6I/rLLeio/4XAZuQvTILMXCfK3
noGaqeRtoDOXnStXnMIxhQymBTSZmbKBgU7i07u6gz3NyNLV/rl+wA7vX1bcTcZ1
T/5TvYECgYEA/ZZwhBRwGSQmYgbudWYTCHrIvUFE73Zz0rEykbmPGKVtUM2jVsac
HmURs5Vz0KLPGv2S2mw73GThyyLS7pNuGkf0c7MVRhq9fbWxKInptHjeXA5sEGMo
0no5lyoLU/zYhNSkeiCs778HlHIEqfyeiMOzAb+BawV8ci9G0+eNG5ECgYEA5V4/
xetpN5DneTgVsPObSEaHA1Uq6n264WVTMVfYwXP+9b4vkqk1mGIm4WPgOQGJNWgR
lDB9VQBbj1M45s889fshtudyVAgran3k+9WT+IuKT6drW5FeigpDfzdRJWQ+kLg9
lMxeNw38H/jpiSFUlNzJXqP57IvcY2JpOgt4COECgYEAmIH/TQ/VkukwxEeS5bvr
um/NhjRYtwMwCQhUd1t3ecUTh0ME9s0fWxBBoxVAv7sKfxr9VKs/HP725GofHShB
UUDw/Rw4sR6n05CP6Od4S/ddE1QBHaHlDSBAvm6kvXAU713LRT+dgdoLPvWLZIfu
+CVp5KU9uhVkkG9qU0qwjGECgYEAn+EMbvdjBhp5XuObKxcDXGPc5JPPMFinlUk9
rh1ft6kVRVJmcsKD204/b8hgmRva+mEqL7OFCWUQbV1DQo+eHJAKtiWqaaywJrDO
lkQPuqX5qQA4M0GnNm1lEx4J8BhqDBKAymGSIqoa3mZw0udqv8EOlGuUYDA1VQlZ
893es8ECgYAn1jbkC2qY/aTmeCtC9Vt7l1n47lV0rL89WRnB6lbrmT5VhpXoT4S3
3nZR+vxKO87eoC1k6/JXQTSRtqS64WdqaRuR+u7PLkWFxBSaRIVmJQoN+/iBBVI/
tfFbVnWJ+ztxB+Iv5sCzryGtH9Owi2kVFhcjxO8qSjmQNAtUIS/dBw==
-----END RSA PRIVATE KEY-----`;
