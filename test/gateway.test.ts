import { createServer, type IncomingMessage } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { once } from "node:events";
import { describe, expect, it } from "vitest";
import { validateConfig } from "../src/config.js";
import { GatewayError } from "../src/errors.js";
import { executeServiceRequest } from "../src/gateway.js";
import { TokenBroker, defaultTokenBrokers } from "../src/tokens.js";
import type { AuthContext, GatewayConfig } from "../src/types.js";

describe("HTTP gateway", () => {
  it("substitutes tokens in headers, query, and body after policy allows the request", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl);
      const broker = installBroker(config);
      const auth = actor();
      const issued = broker.issueTokens(auth, {
        service: "demo-service",
        destination: "primary",
        credential_ids: ["api_key"],
        reason: "Call downstream test service.",
      });
      const token = issued.tokens[0]?.token ?? "";

      const response = await executeServiceRequest(config, auth, {
        service: "demo-service",
        destination: "primary",
        method: "POST",
        path: "/api/echo",
        headers: { "X-API-Key": token },
        query: { api_key: token },
        body: { credential: token },
        reason: "Exercise substitution.",
      });

      expect(response.status_code).toBe(200);
      expect(response.tls.verify).toBe(false);
      expect(response.body).not.toContain("demo-secret");
      expect(response.redacted).toBe(true);
      expect(downstream.requests).toHaveLength(1);
      expect(downstream.requests[0]?.headers["x-api-key"]).toBe("demo-secret");
      expect(downstream.requests[0]?.url).toContain("api_key=demo-secret");
      expect(downstream.requests[0]?.body).toContain("demo-secret");
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
        credential_ids: ["api_key"],
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

  it("rejects unknown and wrong-destination tokens before downstream calls", async () => {
    const downstream = await startDownstream();
    try {
      const config = gatewayConfig(downstream.baseUrl, { includeSecondary: true });
      const broker = installBroker(config);
      const issued = broker.issueTokens(actor(), {
        service: "demo-service",
        destination: "primary",
        credential_ids: ["api_key"],
        reason: "Call downstream test service.",
      });

      await expectGatewayError(() => executeServiceRequest(config, actor(), {
        service: "demo-service",
        destination: "primary",
        method: "GET",
        path: "/api/echo",
        headers: { "X-API-Key": "tok_unknown" },
        reason: "Unknown token.",
      }), "token_invalid");
      await expectGatewayError(() => executeServiceRequest(config, actor(), {
        service: "demo-service",
        destination: "secondary",
        method: "GET",
        path: "/api/echo",
        headers: { "X-API-Key": issued.tokens[0]?.token ?? "" },
        reason: "Wrong destination.",
      }), "token_invalid");
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
      const config = gatewayConfig(downstream.baseUrl, { timeout: "10ms" });
      installBroker(config);

      await expectGatewayError(() => executeServiceRequest(config, actor(), {
        service: "demo-service",
        destination: "primary",
        method: "GET",
        path: "/api/slow",
        reason: "Check timeout.",
      }), "downstream_timeout");
    } finally {
      await downstream.close();
    }
  });

  it("rejects oversized requests and truncates oversized responses", async () => {
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
      const response = await executeServiceRequest(smallResponseConfig, actor(), {
        service: "demo-service",
        destination: "primary",
        method: "GET",
        path: "/api/large",
        reason: "Check response truncation.",
      });

      expect(response.truncated).toBe(true);
      expect(response.body.length).toBeLessThanOrEqual(10);
    } finally {
      await downstream.close();
    }
  });
});

function gatewayConfig(baseUrl: string, options: {
  includeSecondary?: boolean;
  timeout?: string;
  maxRequestBody?: string;
  maxResponseBody?: string;
  tlsVerify?: boolean;
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
      timeout: options.timeout ?? "1s",
    },
    services: {
      "demo-service": {
        type: "http",
        name: "Demo Service",
        destinations,
        tls: { verify: options.tlsVerify ?? false },
        credentials: [{
          id: "api_key",
          usage: { kind: "header", name: "X-API-Key" },
          source: { kind: "env", name: "DEMO_API_KEY" },
        }],
        access: { users: ["henric@example.com"] },
        policy: {
          mode: "deny",
          rules: [
            { id: "allow-echo", effect: "allow", priority: 100, methods: ["GET", "POST"], paths: ["/api/echo"] },
            { id: "allow-large", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/large"] },
            { id: "allow-redirect", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/redirect"] },
            { id: "allow-slow", effect: "allow", priority: 100, methods: ["GET"], paths: ["/api/slow"] },
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
  defaultTokenBrokers.set(config, broker);
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

async function startDownstream() {
  const requests: Array<{ path: string; url: string; headers: Record<string, string | string[] | undefined>; body: string }> = [];
  const server = createServer(async (request, response) => {
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
    if (request.url?.startsWith("/api/slow")) {
      await new Promise((resolve) => setTimeout(resolve, 100));
      response.end("slow");
      return;
    }
    if (request.url?.startsWith("/api/large")) {
      response.end("x".repeat(100));
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
    close: () => new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    }),
  };
}

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
