import { createServer } from "node:http";
import { once } from "node:events";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { authenticateRequest } from "../src/auth.js";
import { validateConfig } from "../src/config.js";
import { GatewayError } from "../src/errors.js";
import { createGatewayServer } from "../src/server.js";
import type { GatewayConfig } from "../src/types.js";

describe("auth", () => {
  it("accepts bearer dev tokens only in bearer mode", async () => {
    const config = bearerConfig();

    const context = await authenticateRequest(requestWithBearer("dev-token"), config, ["gateway.read"]);

    expect(context).toMatchObject({ subject: "bearer-dev", mode: "bearer", scopes: ["gateway.read"] });
    await expect(authenticateRequest(requestWithBearer("wrong-token"), config)).rejects.toThrow("Invalid bearer token");
  });

  it("publishes protected resource metadata without authentication", async () => {
    const fixture = await startServer(bearerConfig());
    try {
      const response = await fetch(`${fixture.baseUrl}/.well-known/oauth-protected-resource`);
      const body = await response.json() as {
        resource: string;
        authorization_servers: string[];
        scopes_supported: string[];
      };

      expect(response.status).toBe(200);
      expect(body.resource).toBe(fixture.baseUrl);
      expect(body.authorization_servers).toEqual([]);
      expect(body.scopes_supported).toEqual(["gateway.read", "gateway.tokens", "gateway.request"]);
    } finally {
      await fixture.close();
    }
  });

  it("publishes OAuth issuer and scopes in protected resource metadata", async () => {
    const config = oauthConfig("http://127.0.0.1:1/jwks");
    const fixture = await startServer(config);
    try {
      const response = await fetch(`${fixture.baseUrl}/.well-known/oauth-protected-resource`);
      const body = await response.json() as {
        authorization_servers: string[];
        scopes_supported: string[];
      };

      expect(response.status).toBe(200);
      expect(body.authorization_servers).toEqual(["https://auth.example.com"]);
      expect(body.scopes_supported).toEqual(["gateway.read", "gateway.tokens", "gateway.request"]);
    } finally {
      await fixture.close();
    }
  });

  it("rejects missing tokens on MCP calls with a WWW-Authenticate challenge", async () => {
    const fixture = await startServer(bearerConfig());
    try {
      const response = await fetch(`${fixture.baseUrl}/mcp`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "accept": "application/json, text/event-stream",
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
      });
      const body = await response.json() as { error: { code: string; message: string } };

      expect(response.status).toBe(401);
      expect(response.headers.get("www-authenticate")).toContain("resource_metadata=");
      expect(response.headers.get("www-authenticate")).toContain("gateway.read");
      expect(body.error).toEqual({ code: "unauthenticated", message: "Authentication required." });
    } finally {
      await fixture.close();
    }
  });

  it("accepts valid OAuth JWTs from JWKS and enforces scopes", async () => {
    const jwks = await startJwks();
    try {
      const config = oauthConfig(jwks.jwksUri);
      const token = await jwks.sign({ aud: "agent-credential-gateway", scope: "gateway.read gateway.tokens" });

      const context = await authenticateRequest(requestWithBearer(token), config, ["gateway.tokens"]);

      expect(context.subject).toBe("henric@example.com");
      expect(context.scopes).toContain("gateway.tokens");
      await expect(authenticateRequest(requestWithBearer(token), config, ["gateway.request"])).rejects.toThrow("required scopes");
    } finally {
      await jwks.close();
    }
  });

  it("rejects invalid OAuth issuer, audience, expiry, nbf, and signature", async () => {
    const jwks = await startJwks();
    const otherJwks = await startJwks();
    try {
      const config = oauthConfig(jwks.jwksUri);
      const validClaims = { aud: "agent-credential-gateway", scope: "gateway.read" };
      const invalidIssuer = await jwks.sign(validClaims, { issuer: "https://other-issuer.example.com" });
      const invalidAudience = await jwks.sign({ aud: "other-audience", scope: "gateway.read" });
      const expired = await jwks.sign(validClaims, { expiresIn: -60 });
      const notYetValid = await jwks.sign(validClaims, { notBefore: 3600 });
      const invalidSignature = await otherJwks.sign(validClaims);

      for (const token of [invalidIssuer, invalidAudience, expired, notYetValid, invalidSignature]) {
        await expect(authenticateRequest(requestWithBearer(token), config, ["gateway.read"])).rejects.toThrow("Invalid OAuth access token");
      }
    } finally {
      await jwks.close();
      await otherJwks.close();
    }
  });

  it("rejects bearer tokens in OAuth mode and OAuth JWTs in bearer mode", async () => {
    const jwks = await startJwks();
    try {
      const oauth = oauthConfig(jwks.jwksUri);
      const jwt = await jwks.sign({ aud: "agent-credential-gateway", scope: "gateway.read" });

      await expect(authenticateRequest(requestWithBearer("dev-token"), oauth)).rejects.toThrow("Invalid OAuth access token");
      await expect(authenticateRequest(requestWithBearer(jwt), bearerConfig())).rejects.toThrow("Invalid bearer token");
    } finally {
      await jwks.close();
    }
  });
});

function bearerConfig(): GatewayConfig {
  return validateConfig(baseRawConfig({
    mode: "bearer",
    bearer: { token_env: "TEST_GATEWAY_TOKEN" },
  }), {
    TEST_GATEWAY_TOKEN: "dev-token",
    DEMO_API_KEY: "secret",
  });
}

function oauthConfig(jwksUri: string): GatewayConfig {
  return validateConfig(baseRawConfig({
    mode: "oauth",
    oauth: {
      issuer: "https://auth.example.com",
      audience: "agent-credential-gateway",
      jwks_uri: jwksUri,
      required_scopes: ["gateway.read", "gateway.tokens", "gateway.request"],
    },
  }), {
    DEMO_API_KEY: "secret",
  });
}

function baseRawConfig(auth: Record<string, unknown>): Record<string, unknown> {
  return {
    server: { listen: "127.0.0.1:8080", mcp_path: "/mcp" },
    auth,
    services: {
      "demo-service": {
        type: "http",
        name: "Demo Service",
        destinations: [{ name: "primary", base_url: "https://demo.internal" }],
        credentials: [{
          id: "api_key",
          usage: { kind: "header", name: "X-API-Key" },
          source: { kind: "env", name: "DEMO_API_KEY" },
        }],
      },
    },
  };
}

function requestWithBearer(token: string) {
  return {
    headers: {
      authorization: `Bearer ${token}`,
    },
  } as any;
}

async function startServer(config: GatewayConfig) {
  const server = createGatewayServer(config);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Expected TCP address");
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    close: () => new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    }),
  };
}

async function startJwks() {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = await exportJWK(publicKey);
  jwk.kid = "test-key";
  jwk.use = "sig";
  jwk.alg = "RS256";

  const server = createServer((_request, response) => {
    response.writeHead(200, { "content-type": "application/json; charset=utf-8" });
    response.end(JSON.stringify({ keys: [jwk] }));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Expected TCP address");
  const jwksUri = `http://127.0.0.1:${address.port}/jwks`;

  return {
    jwksUri,
    sign: async (
      claims: { aud: string; scope: string },
      options: { issuer?: string; expiresIn?: number; notBefore?: number } = {},
    ) => {
      const now = Math.floor(Date.now() / 1000);
      const jwt = new SignJWT({ scope: claims.scope })
        .setProtectedHeader({ alg: "RS256", kid: "test-key" })
        .setSubject("henric@example.com")
        .setIssuer(options.issuer ?? "https://auth.example.com")
        .setAudience(claims.aud)
        .setIssuedAt(now)
        .setExpirationTime(now + (options.expiresIn ?? 3600));
      if (options.notBefore !== undefined) jwt.setNotBefore(now + options.notBefore);
      return jwt.sign(privateKey);
    },
    close: () => new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    }),
  };
}
