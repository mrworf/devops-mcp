import { createServer, request as httpRequest } from "node:http";
import { once } from "node:events";
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exportJWK, exportPKCS8, generateKeyPair, SignJWT } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import { authenticateRequest } from "../src/auth.js";
import { hashBuiltinOAuthPassword } from "../src/builtinOAuth.js";
import { validateConfig } from "../src/config.js";
import { GatewayError } from "../src/errors.js";
import { createGatewayServer } from "../src/server.js";
import { TokenBroker } from "../src/tokens.js";
import type { GatewayConfig } from "../src/types.js";

describe("auth", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

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

  it("publishes built-in OAuth issuer and authorization server metadata", async () => {
    const config = await builtinOAuthConfig();
    const fixture = await startServer(config);
    try {
      const protectedResource = await fetch(`${fixture.baseUrl}/.well-known/oauth-protected-resource`);
      const protectedBody = await protectedResource.json() as {
        resource: string;
        authorization_servers: string[];
        scopes_supported: string[];
      };
      expect(protectedBody.resource).toBe("https://mcp.example.org");
      expect(protectedBody.authorization_servers).toEqual(["https://mcp.example.org"]);
      expect(protectedBody.scopes_supported).toEqual(["gateway.read", "gateway.tokens", "gateway.request"]);

      const metadata = await fetch(`${fixture.baseUrl}/.well-known/oauth-authorization-server`);
      const metadataBody = await metadata.json() as Record<string, unknown>;
      expect(metadataBody).toMatchObject({
        issuer: "https://mcp.example.org",
        authorization_endpoint: "https://mcp.example.org/oauth/authorize",
        token_endpoint: "https://mcp.example.org/oauth/token",
        jwks_uri: "https://mcp.example.org/oauth/jwks.json",
        client_id_metadata_document_supported: true,
      });
      expect(metadataBody.code_challenge_methods_supported).toEqual(["S256"]);
      expect(metadataBody.token_endpoint_auth_methods_supported).toEqual(["none"]);

      const jwks = await fetch(`${fixture.baseUrl}/oauth/jwks.json`);
      const jwksBody = await jwks.json() as { keys: unknown[] };
      expect(jwksBody.keys).toHaveLength(1);
    } finally {
      await fixture.close();
    }
  });

  it("completes built-in OAuth authorization code flow and authenticates the issued token", async () => {
    const config = await builtinOAuthConfig();
    const fixture = await startServer(config);
    const codeVerifier = "test-verifier";
    const redirectUri = "https://chatgpt.com/oauth/callback";
    vi.stubGlobal("fetch", async (url: string) => {
      expect(url).toBe("https://chatgpt.com/oauth/client");
      return new Response(JSON.stringify({ redirect_uris: [redirectUri] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });

    try {
      const authorize = await localRequest(`${fixture.baseUrl}/oauth/authorize`, {
        method: "POST",
        body: authorizationBody({
          redirect_uri: redirectUri,
          code_challenge: pkceChallenge(codeVerifier),
          username: "admin@example.com",
          password: "correct horse battery staple",
          state: "setup-state",
        }),
      });
      expect(authorize.status).toBe(302);
      const location = new URL(authorize.headers.location ?? "");
      expect(location.origin + location.pathname).toBe(redirectUri);
      expect(location.searchParams.get("state")).toBe("setup-state");
      const code = location.searchParams.get("code");
      expect(code).toBeTruthy();

      const token = await localRequest(`${fixture.baseUrl}/oauth/token`, {
        method: "POST",
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code ?? "",
          client_id: "https://chatgpt.com/oauth/client",
          redirect_uri: redirectUri,
          code_verifier: codeVerifier,
        }).toString(),
      });
      expect(token.status).toBe(200);
      const tokenBody = JSON.parse(token.body) as { access_token: string; token_type: string; scope: string };
      expect(tokenBody.token_type).toBe("Bearer");
      expect(tokenBody.scope).toBe("gateway.read");

      const context = await authenticateRequest(requestWithBearer(tokenBody.access_token), config, ["gateway.read"]);
      expect(context).toMatchObject({ subject: "admin@example.com", mode: "builtin_oauth" });
    } finally {
      await fixture.close();
    }
  });

  it("keeps built-in OAuth access tokens valid across restart with the same signing key", async () => {
    const signingKeyPath = await createSigningKeyFile();
    const config = await builtinOAuthConfig({ signingKeyPath });
    const fixture = await startServer(config);
    const redirectUri = "https://chatgpt.com/oauth/callback";
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: [redirectUri] }), { status: 200 }));

    try {
      const verifier = "restart-verifier";
      const code = await authorizeCode(fixture.baseUrl, redirectUri, verifier);
      const token = await localRequest(`${fixture.baseUrl}/oauth/token`, {
        method: "POST",
        body: tokenBody(code, redirectUri, verifier),
      });
      expect(token.status).toBe(200);
      const tokenBodyJson = JSON.parse(token.body) as { access_token: string };

      await fixture.close();
      const restartedConfig = await builtinOAuthConfig({ signingKeyPath });
      const context = await authenticateRequest(requestWithBearer(tokenBodyJson.access_token), restartedConfig, ["gateway.read"]);
      expect(context).toMatchObject({ subject: "admin@example.com", mode: "builtin_oauth" });
    } finally {
      await fixture.close().catch(() => undefined);
    }
  });

  it("does not keep opaque gateway tokens across fresh token broker instances", () => {
    const config = opaqueTokenRestartConfig();
    const broker = new TokenBroker(config);
    const issued = broker.issueTokens({ subject: "henric@example.com", scopes: ["gateway.tokens"], mode: "bearer" }, {
      service: "demo-service",
      destination: "primary",
      credential_ids: ["api_key"],
      reason: "Issue token before restart.",
    });

    const restartedBroker = new TokenBroker(config);
    expect(() => restartedBroker.validateTokenUse({ subject: "henric@example.com", scopes: ["gateway.request"], mode: "bearer" }, {
      service: "demo-service",
      destination: "primary",
    }, issued.tokens[0]?.token ?? "")).toThrow("Unknown opaque token");
  });

  it("accepts matching or omitted built-in OAuth token resources and rejects mismatches", async () => {
    const config = await builtinOAuthConfig();
    const fixture = await startServer(config);
    const redirectUri = "https://chatgpt.com/oauth/callback";
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: [redirectUri] }), { status: 200 }));

    try {
      const matchingVerifier = "matching-resource-verifier";
      const matchingCode = await authorizeCode(fixture.baseUrl, redirectUri, matchingVerifier);
      const matching = await localRequest(`${fixture.baseUrl}/oauth/token`, {
        method: "POST",
        body: tokenBody(matchingCode, redirectUri, matchingVerifier, { resource: "https://mcp.example.org" }),
      });
      expect(matching.status).toBe(200);

      const omittedVerifier = "omitted-resource-verifier";
      const omittedCode = await authorizeCode(fixture.baseUrl, redirectUri, omittedVerifier);
      const omitted = await localRequest(`${fixture.baseUrl}/oauth/token`, {
        method: "POST",
        body: tokenBody(omittedCode, redirectUri, omittedVerifier),
      });
      expect(omitted.status).toBe(200);

      const mismatchedVerifier = "mismatched-resource-verifier";
      const mismatchedCode = await authorizeCode(fixture.baseUrl, redirectUri, mismatchedVerifier);
      const mismatched = await localRequest(`${fixture.baseUrl}/oauth/token`, {
        method: "POST",
        body: tokenBody(mismatchedCode, redirectUri, mismatchedVerifier, { resource: "https://other.example.org" }),
      });
      expect(mismatched.status).toBe(400);
      expect(JSON.parse(mismatched.body)).toEqual({ error: "invalid_target" });
    } finally {
      await fixture.close();
    }
  });

  it("logs sanitized built-in OAuth outcomes in debug mode", async () => {
    const config = await builtinOAuthConfig({ loggingLevel: "debug" });
    const redirectUri = "https://chatgpt.com/oauth/callback";
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const fixture = await startServer(config);
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: [redirectUri] }), { status: 200 }));

    try {
      const verifier = "log-verifier";
      const authorize = await localRequest(`${fixture.baseUrl}/oauth/authorize`, {
        method: "POST",
        body: authorizationBody({
          redirect_uri: redirectUri,
          code_challenge: pkceChallenge(verifier),
          username: "admin@example.com",
          password: "correct horse battery staple",
        }),
      });
      const code = new URL(authorize.headers.location ?? "").searchParams.get("code") ?? "";
      const token = await localRequest(`${fixture.baseUrl}/oauth/token`, {
        method: "POST",
        body: tokenBody(code, redirectUri, verifier, { resource: "https://mcp.example.org" }),
      });
      expect(token.status).toBe(200);

      const logs = logSpy.mock.calls.map(([line]) => String(line)).join("\n");
      expect(logs).toContain("oauth.authorize.completed");
      expect(logs).toContain("oauth.token.completed");
      expect(logs).toContain("\"resource_status\":\"match\"");
      expect(logs).toContain("\"scope_count\":1");
      expect(logs).not.toContain("admin@example.com");
      expect(logs).not.toContain("correct horse battery staple");
      expect(logs).not.toContain(code);
      expect(logs).not.toContain(verifier);
      expect(logs).not.toContain(JSON.parse(token.body).access_token);
    } finally {
      logSpy.mockRestore();
      await fixture.close();
    }
  });

  it("rejects invalid built-in OAuth login without leaking credentials", async () => {
    const config = await builtinOAuthConfig();
    const fixture = await startServer(config);
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: ["https://chatgpt.com/oauth/callback"] }), { status: 200 }));
    try {
      const response = await localRequest(`${fixture.baseUrl}/oauth/authorize`, {
        method: "POST",
        body: authorizationBody({
          password: "wrong-password",
          code_challenge: pkceChallenge("verifier"),
        }),
      });

      expect(response.status).toBe(401);
      expect(response.body).toContain("Invalid username or password.");
      expect(response.body).not.toContain("admin@example.com");
      expect(response.body).not.toContain("wrong-password");
    } finally {
      await fixture.close();
    }
  });

  it("keeps health responsive during asynchronous password verification", async () => {
    const config = await builtinOAuthConfig({ passwordIterations: 500_000 });
    const fixture = await startServer(config);
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: ["https://chatgpt.com/oauth/callback"] }), { status: 200 }));
    try {
      const login = localRequest(`${fixture.baseUrl}/oauth/authorize`, {
        method: "POST", body: authorizationBody({ code_challenge: pkceChallenge("async-verifier") }),
      });
      await new Promise<void>((resolve) => setImmediate(resolve));
      const health = await fetch(`${fixture.baseUrl}/health`);
      expect(health.status).toBe(200);
      expect((await login).status).toBe(302);
    } finally {
      await fixture.close();
    }
  });

  it("fails safely when the configured password hash is malformed", async () => {
    const config = await builtinOAuthConfig({ adminPasswordHash: "malformed" });
    const fixture = await startServer(config);
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: ["https://chatgpt.com/oauth/callback"] }), { status: 200 }));
    try {
      const response = await localRequest(`${fixture.baseUrl}/oauth/authorize`, {
        method: "POST", body: authorizationBody({ code_challenge: pkceChallenge("malformed-verifier") }),
      });
      expect(response.status).toBe(401);
    } finally {
      await fixture.close();
    }
  });

  it("accepts exact-limit authorization forms and rejects limit-plus-one before parsing", async () => {
    const body = authorizationBody({ code_challenge: pkceChallenge("bounded-verifier") });
    const allowedConfig = await builtinOAuthConfig({ maxInboundBody: `${Buffer.byteLength(body)}b` });
    const allowedFixture = await startServer(allowedConfig);
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: ["https://chatgpt.com/oauth/callback"] }), { status: 200 }));
    try {
      const allowed = await localRequest(`${allowedFixture.baseUrl}/oauth/authorize`, { method: "POST", body });
      expect(allowed.status).toBe(302);
    } finally {
      await allowedFixture.close();
    }

    const rejectedConfig = await builtinOAuthConfig({ maxInboundBody: `${Buffer.byteLength(body) - 1}b` });
    const rejectedFixture = await startServer(rejectedConfig);
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    try {
      const rejected = await localRequest(`${rejectedFixture.baseUrl}/oauth/authorize`, { method: "POST", body });
      expect(rejected.status).toBe(413);
      expect(JSON.parse(rejected.body)).toEqual({ error: "request_too_large" });
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      await rejectedFixture.close();
    }
  });

  it("rejects excess OAuth body readers by direct source regardless of forwarding headers", async () => {
    const config = await builtinOAuthConfig({ maxUnauthenticatedInflight: 2, maxUnauthenticatedInflightPerSource: 1 });
    const fixture = await startServer(config);
    const stalled = httpRequest(`${fixture.baseUrl}/oauth/authorize`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", "x-forwarded-for": "198.51.100.20" },
    });
    stalled.on("error", () => undefined);
    stalled.write("partial=body");
    await once(stalled, "socket");
    await new Promise<void>((resolve) => setImmediate(resolve));
    try {
      const rejected = await localRequest(`${fixture.baseUrl}/oauth/token`, {
        method: "POST", body: "grant_type=authorization_code", headers: { "x-forwarded-for": "203.0.113.30" },
      });
      expect(rejected.status).toBe(429);
      expect(rejected.headers["retry-after"]).toBe("1");
      expect(JSON.parse(rejected.body)).toEqual({ error: "temporarily_unavailable" });
    } finally {
      stalled.destroy();
      await fixture.close();
    }
  });

  it("rejects unallowed built-in OAuth CIMD clients and redirect mismatches", async () => {
    const config = await builtinOAuthConfig();
    const fixture = await startServer(config);
    try {
      const unallowed = await localRequest(`${fixture.baseUrl}/oauth/authorize`, {
        method: "POST",
        body: authorizationBody({
          client_id: "https://evil.example.com/client",
          redirect_uri: "https://evil.example.com/callback",
          code_challenge: pkceChallenge("verifier"),
        }),
      });
      expect(unallowed.status).toBe(400);
      expect(JSON.parse(unallowed.body)).toEqual({ error: "invalid_client" });

      vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: ["https://chatgpt.com/other"] }), { status: 200 }));
      const redirectMismatch = await localRequest(`${fixture.baseUrl}/oauth/authorize`, {
        method: "POST",
        body: authorizationBody({ code_challenge: pkceChallenge("verifier") }),
      });
      expect(redirectMismatch.status).toBe(400);
      expect(JSON.parse(redirectMismatch.body)).toEqual({ error: "invalid_request" });
    } finally {
      await fixture.close();
    }
  });

  it("treats exact built-in OAuth CIMD client allowlist entries as exact URLs", async () => {
    const config = await builtinOAuthConfig({ allowedClients: ["https://chatgpt.com/oauth/client"] });
    const fixture = await startServer(config);
    try {
      const sameOriginDifferentUrl = await localRequest(`${fixture.baseUrl}/oauth/authorize`, {
        method: "POST",
        body: authorizationBody({
          client_id: "https://chatgpt.com/oauth/other-client",
          code_challenge: pkceChallenge("verifier"),
        }),
      });
      expect(sameOriginDifferentUrl.status).toBe(400);
      expect(JSON.parse(sameOriginDifferentUrl.body)).toEqual({ error: "invalid_client" });
    } finally {
      await fixture.close();
    }
  });

  it("rejects missing or wrong built-in OAuth resource", async () => {
    const config = await builtinOAuthConfig();
    const fixture = await startServer(config);
    try {
      const missing = await localRequest(`${fixture.baseUrl}/oauth/authorize`, {
        method: "POST",
        body: authorizationBody({ resource: "", code_challenge: pkceChallenge("verifier") }),
      });
      expect(missing.status).toBe(400);
      expect(JSON.parse(missing.body)).toEqual({ error: "invalid_target" });

      const wrong = await localRequest(`${fixture.baseUrl}/oauth/authorize`, {
        method: "POST",
        body: authorizationBody({ resource: "https://other.example.com", code_challenge: pkceChallenge("verifier") }),
      });
      expect(wrong.status).toBe(400);
      expect(JSON.parse(wrong.body)).toEqual({ error: "invalid_target" });
    } finally {
      await fixture.close();
    }
  });

  it("rejects reused codes and wrong PKCE verifiers in built-in OAuth token exchange", async () => {
    const config = await builtinOAuthConfig();
    const fixture = await startServer(config);
    const redirectUri = "https://chatgpt.com/oauth/callback";
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: [redirectUri] }), { status: 200 }));
    try {
      const verifier = "verifier";
      const authorize = await localRequest(`${fixture.baseUrl}/oauth/authorize`, {
        method: "POST",
        body: authorizationBody({
          redirect_uri: redirectUri,
          code_challenge: pkceChallenge(verifier),
          username: "admin@example.com",
          password: "correct horse battery staple",
        }),
      });
      const code = new URL(authorize.headers.location ?? "").searchParams.get("code") ?? "";

      const wrongPkce = await localRequest(`${fixture.baseUrl}/oauth/token`, {
        method: "POST",
        body: tokenBody(code, redirectUri, "wrong-verifier"),
      });
      expect(wrongPkce.status).toBe(400);
      expect(JSON.parse(wrongPkce.body)).toEqual({ error: "invalid_grant" });

      const reused = await localRequest(`${fixture.baseUrl}/oauth/token`, {
        method: "POST",
        body: tokenBody(code, redirectUri, verifier),
      });
      expect(reused.status).toBe(400);
      expect(JSON.parse(reused.body)).toEqual({ error: "invalid_grant" });
    } finally {
      await fixture.close();
    }
  });

  it("rejects oversized token forms without consuming the authorization code", async () => {
    const config = await builtinOAuthConfig({ maxInboundBody: "1kb" });
    const fixture = await startServer(config);
    const redirectUri = "https://chatgpt.com/oauth/callback";
    const verifier = "bounded-token-verifier";
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: [redirectUri] }), { status: 200 }));
    try {
      const code = await authorizeCode(fixture.baseUrl, redirectUri, verifier);
      const normalBody = tokenBody(code, redirectUri, verifier);
      const oversized = await localRequest(`${fixture.baseUrl}/oauth/token`, {
        method: "POST", body: `${normalBody}&padding=${"x".repeat(1024)}`,
      });
      expect(oversized.status).toBe(413);
      expect(JSON.parse(oversized.body)).toEqual({ error: "request_too_large" });

      const retry = await localRequest(`${fixture.baseUrl}/oauth/token`, { method: "POST", body: normalBody });
      expect(retry.status).toBe(200);
    } finally {
      await fixture.close();
    }
  });

  it("rejects expired built-in OAuth authorization codes", async () => {
    const config = await builtinOAuthConfig({ authorizationCodeTtl: "1ms" });
    const fixture = await startServer(config);
    const redirectUri = "https://chatgpt.com/oauth/callback";
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: [redirectUri] }), { status: 200 }));
    try {
      const verifier = "verifier";
      const authorize = await localRequest(`${fixture.baseUrl}/oauth/authorize`, {
        method: "POST",
        body: authorizationBody({
          redirect_uri: redirectUri,
          code_challenge: pkceChallenge(verifier),
          username: "admin@example.com",
          password: "correct horse battery staple",
        }),
      });
      const code = new URL(authorize.headers.location ?? "").searchParams.get("code") ?? "";
      await new Promise((resolve) => setTimeout(resolve, 10));

      const expired = await localRequest(`${fixture.baseUrl}/oauth/token`, {
        method: "POST",
        body: tokenBody(code, redirectUri, verifier),
      });
      expect(expired.status).toBe(400);
      expect(JSON.parse(expired.body)).toEqual({ error: "invalid_grant" });
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

  it("challenges unauthenticated MCP GET requests with protected resource metadata", async () => {
    const config = await builtinOAuthConfig();
    const fixture = await startServer(config);
    try {
      const response = await fetch(`${fixture.baseUrl}/mcp`);
      const body = await response.json() as { error: { code: string; message: string } };

      expect(response.status).toBe(401);
      expect(response.headers.get("www-authenticate")).toBe(
        "Bearer resource_metadata=\"https://mcp.example.org/.well-known/oauth-protected-resource\"",
      );
      expect(body.error).toEqual({ code: "unauthenticated", message: "Authentication required." });
    } finally {
      await fixture.close();
    }
  });

  it("keeps the MCP session-streaming error for authenticated MCP GET requests", async () => {
    const fixture = await startServer(bearerConfig());
    try {
      const response = await fetch(`${fixture.baseUrl}/mcp`, {
        headers: { authorization: "Bearer dev-token" },
      });
      const body = await response.json() as { error: { code: string; message: string } };

      expect(response.status).toBe(400);
      expect(body.error).toEqual({
        code: "invalid_request",
        message: "MCP session streaming is not available before initialization.",
      });
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

async function builtinOAuthConfig(options: {
  authorizationCodeTtl?: string;
  allowedClients?: string[];
  loggingLevel?: "info" | "debug";
  signingKeyPath?: string;
  maxInboundBody?: string;
  maxUnauthenticatedInflight?: number;
  maxUnauthenticatedInflightPerSource?: number;
  passwordIterations?: number;
  adminPasswordHash?: string;
} = {}): Promise<GatewayConfig> {
  const keyPath = options.signingKeyPath ?? await createSigningKeyFile();
  return validateConfig({
    ...baseRawConfig({
      mode: "builtin_oauth",
      builtin_oauth: {
        issuer: "https://mcp.example.org",
        admin_username_env: "ADMIN_USERNAME",
        admin_password_hash_env: "ADMIN_PASSWORD_HASH",
        signing_key_file: keyPath,
        access_token_ttl: "1h",
        authorization_code_ttl: options.authorizationCodeTtl ?? "5m",
        allowed_clients: options.allowedClients ?? ["https://chatgpt.com"],
        required_scopes: ["gateway.read", "gateway.tokens", "gateway.request"],
      },
    }),
    server: {
      listen: "127.0.0.1:8080",
      mcp_path: "/mcp",
      resource: "https://mcp.example.org",
    },
    logging: { level: options.loggingLevel ?? "info" },
    limits: {
      max_inbound_body: options.maxInboundBody ?? "1mb",
      max_unauthenticated_inflight: options.maxUnauthenticatedInflight ?? 32,
      max_unauthenticated_inflight_per_source: options.maxUnauthenticatedInflightPerSource ?? 4,
    },
  }, {
    ADMIN_USERNAME: "admin@example.com",
    ADMIN_PASSWORD_HASH: options.adminPasswordHash
      ?? hashBuiltinOAuthPassword("correct horse battery staple", "test-salt", options.passwordIterations ?? 1000),
    DEMO_API_KEY: "secret",
  });
}

async function createSigningKeyFile(): Promise<string> {
  const { privateKey } = await generateKeyPair("RS256", { extractable: true });
  const dir = mkdtempSync(join(tmpdir(), "gateway-builtin-oauth-"));
  const keyPath = join(dir, "signing-key.pem");
  writeFileSync(keyPath, await exportPKCS8(privateKey));
  return keyPath;
}

function opaqueTokenRestartConfig(): GatewayConfig {
  return validateConfig({
    server: { listen: "127.0.0.1:8080", mcp_path: "/mcp" },
    auth: { mode: "bearer", bearer: { token_env: "TEST_GATEWAY_TOKEN" } },
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
        access: { users: ["henric@example.com"] },
      },
    },
  }, {
    TEST_GATEWAY_TOKEN: "dev-token",
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

function authorizationBody(overrides: Record<string, string> = {}): string {
  return new URLSearchParams({
    response_type: "code",
    client_id: "https://chatgpt.com/oauth/client",
    redirect_uri: "https://chatgpt.com/oauth/callback",
    scope: "gateway.read",
    state: "state",
    code_challenge_method: "S256",
    code_challenge: "challenge",
    resource: "https://mcp.example.org",
    username: "admin@example.com",
    password: "correct horse battery staple",
    ...overrides,
  }).toString();
}

function tokenBody(code: string, redirectUri: string, verifier: string, overrides: Record<string, string> = {}): string {
  return new URLSearchParams({
    grant_type: "authorization_code",
    code,
    client_id: "https://chatgpt.com/oauth/client",
    redirect_uri: redirectUri,
    code_verifier: verifier,
    ...overrides,
  }).toString();
}

function pkceChallenge(verifier: string): string {
  return Buffer.from(createHash("sha256").update(verifier).digest()).toString("base64url");
}

async function localRequest(urlText: string, options: { method: string; body?: string; headers?: Record<string, string> }): Promise<{ status: number; headers: Record<string, string>; body: string }> {
  const url = new URL(urlText);
  const body = options.body ?? "";
  return new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: url.hostname,
      port: url.port,
      path: `${url.pathname}${url.search}`,
      method: options.method,
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "content-length": Buffer.byteLength(body),
        ...options.headers,
      },
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
      response.on("end", () => {
        resolve({
          status: response.statusCode ?? 0,
          headers: Object.fromEntries(Object.entries(response.headers).map(([key, value]) => [key, Array.isArray(value) ? value[0] ?? "" : value ?? ""])),
          body: Buffer.concat(chunks).toString("utf8"),
        });
      });
    });
    request.on("error", reject);
    request.end(body);
  });
}

async function authorizeCode(baseUrl: string, redirectUri: string, verifier: string): Promise<string> {
  const authorize = await localRequest(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    body: authorizationBody({
      redirect_uri: redirectUri,
      code_challenge: pkceChallenge(verifier),
      username: "admin@example.com",
      password: "correct horse battery staple",
    }),
  });
  expect(authorize.status).toBe(302);
  const code = new URL(authorize.headers.location ?? "").searchParams.get("code");
  expect(code).toBeTruthy();
  return code ?? "";
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
