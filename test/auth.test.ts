import { createServer, request as httpRequest } from "node:http";
import { once } from "node:events";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmdirSync, statSync, unlinkSync, writeFileSync } from "node:fs";
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
      expect(metadataBody.grant_types_supported).toEqual(["authorization_code", "refresh_token"]);

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
      const tokenBody = JSON.parse(token.body) as { access_token: string; refresh_token: string; token_type: string; scope: string };
      expect(tokenBody.token_type).toBe("Bearer");
      expect(tokenBody.scope).toBe("gateway.read");
      expect(tokenBody.refresh_token).toBeTruthy();

      const context = await authenticateRequest(requestWithBearer(tokenBody.access_token), config, ["gateway.read"]);
      expect(context).toMatchObject({ subject: "admin@example.com", mode: "builtin_oauth" });
    } finally {
      await fixture.close();
    }
  });

  it("rotates built-in OAuth refresh tokens and permits reduced access-token scopes", async () => {
    const config = await builtinOAuthConfig();
    const fixture = await startServer(config);
    const redirectUri = "https://chatgpt.com/oauth/callback";
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: [redirectUri] }), { status: 200 }));
    try {
      const verifier = "refresh-verifier";
      const code = await authorizeCode(fixture.baseUrl, redirectUri, verifier, "gateway.read gateway.tokens");
      const issued = await localRequest(`${fixture.baseUrl}/oauth/token`, {
        method: "POST", body: tokenBody(code, redirectUri, verifier),
      });
      const issuedBody = JSON.parse(issued.body) as { refresh_token: string };

      const refreshed = await localRequest(`${fixture.baseUrl}/oauth/token`, {
        method: "POST", body: refreshBody(issuedBody.refresh_token, { scope: "gateway.read" }),
      });
      expect(refreshed.status).toBe(200);
      const refreshedBody = JSON.parse(refreshed.body) as { access_token: string; refresh_token: string; scope: string };
      expect(refreshedBody.refresh_token).not.toBe(issuedBody.refresh_token);
      expect(refreshedBody.scope).toBe("gateway.read");
      await expect(authenticateRequest(requestWithBearer(refreshedBody.access_token), config, ["gateway.read"])).resolves.toMatchObject({ subject: "admin@example.com" });
      await expect(authenticateRequest(requestWithBearer(refreshedBody.access_token), config, ["gateway.tokens"])).rejects.toThrow("required scopes");
    } finally {
      await fixture.close();
    }
  });

  it("rejects refresh-token escalation and revokes a family when a rotated token is reused", async () => {
    const config = await builtinOAuthConfig();
    const fixture = await startServer(config);
    const redirectUri = "https://chatgpt.com/oauth/callback";
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: [redirectUri] }), { status: 200 }));
    try {
      const verifier = "refresh-reuse-verifier";
      const code = await authorizeCode(fixture.baseUrl, redirectUri, verifier, "gateway.read");
      const issued = await localRequest(`${fixture.baseUrl}/oauth/token`, { method: "POST", body: tokenBody(code, redirectUri, verifier) });
      const first = JSON.parse(issued.body) as { refresh_token: string };

      const escalation = await localRequest(`${fixture.baseUrl}/oauth/token`, {
        method: "POST", body: refreshBody(first.refresh_token, { scope: "gateway.read gateway.tokens" }),
      });
      expect(escalation.status).toBe(400);
      expect(JSON.parse(escalation.body)).toEqual({ error: "invalid_scope" });

      const rotated = await localRequest(`${fixture.baseUrl}/oauth/token`, { method: "POST", body: refreshBody(first.refresh_token) });
      const second = JSON.parse(rotated.body) as { refresh_token: string };
      const replay = await localRequest(`${fixture.baseUrl}/oauth/token`, { method: "POST", body: refreshBody(first.refresh_token) });
      expect(replay.status).toBe(400);
      expect(JSON.parse(replay.body)).toEqual({ error: "invalid_grant" });
      const revoked = await localRequest(`${fixture.baseUrl}/oauth/token`, { method: "POST", body: refreshBody(second.refresh_token) });
      expect(revoked.status).toBe(400);
      expect(JSON.parse(revoked.body)).toEqual({ error: "invalid_grant" });
    } finally {
      await fixture.close();
    }
  });

  it("binds refresh tokens to their client and resource without consuming them on mismatch", async () => {
    const config = await builtinOAuthConfig();
    const fixture = await startServer(config);
    const redirectUri = "https://chatgpt.com/oauth/callback";
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: [redirectUri] }), { status: 200 }));
    try {
      const verifier = "refresh-binding-verifier";
      const code = await authorizeCode(fixture.baseUrl, redirectUri, verifier);
      const issued = await localRequest(`${fixture.baseUrl}/oauth/token`, { method: "POST", body: tokenBody(code, redirectUri, verifier) });
      const token = (JSON.parse(issued.body) as { refresh_token: string }).refresh_token;

      const wrongClient = await localRequest(`${fixture.baseUrl}/oauth/token`, {
        method: "POST", body: refreshBody(token, { client_id: "https://codex.example.org/oauth/client" }),
      });
      expect(wrongClient.status).toBe(400);
      expect(JSON.parse(wrongClient.body)).toEqual({ error: "invalid_grant" });
      const wrongResource = await localRequest(`${fixture.baseUrl}/oauth/token`, {
        method: "POST", body: refreshBody(token, { resource: "https://other.example.org" }),
      });
      expect(wrongResource.status).toBe(400);
      expect(JSON.parse(wrongResource.body)).toEqual({ error: "invalid_target" });
      const valid = await localRequest(`${fixture.baseUrl}/oauth/token`, { method: "POST", body: refreshBody(token) });
      expect(valid.status).toBe(200);
    } finally {
      await fixture.close();
    }
  });

  it("expires inactive refresh grants", async () => {
    const config = await builtinOAuthConfig({ refreshTokenIdleTtl: "1ms", refreshTokenMaxTtl: "1d" });
    const fixture = await startServer(config);
    const redirectUri = "https://chatgpt.com/oauth/callback";
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: [redirectUri] }), { status: 200 }));
    try {
      const verifier = "refresh-expiry-verifier";
      const code = await authorizeCode(fixture.baseUrl, redirectUri, verifier);
      const issued = await localRequest(`${fixture.baseUrl}/oauth/token`, { method: "POST", body: tokenBody(code, redirectUri, verifier) });
      const token = (JSON.parse(issued.body) as { refresh_token: string }).refresh_token;
      await new Promise((resolve) => setTimeout(resolve, 10));
      const expired = await localRequest(`${fixture.baseUrl}/oauth/token`, { method: "POST", body: refreshBody(token) });
      expect(expired.status).toBe(400);
      expect(JSON.parse(expired.body)).toEqual({ error: "invalid_grant" });
    } finally {
      await fixture.close();
    }
  });

  it("preserves the active refresh token when record capacity is exhausted", async () => {
    const config = await builtinOAuthConfig({ maxRefreshTokenRecords: 1 });
    const fixture = await startServer(config);
    const redirectUri = "https://chatgpt.com/oauth/callback";
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: [redirectUri] }), { status: 200 }));
    try {
      const verifier = "refresh-capacity-verifier";
      const code = await authorizeCode(fixture.baseUrl, redirectUri, verifier);
      const issued = await localRequest(`${fixture.baseUrl}/oauth/token`, { method: "POST", body: tokenBody(code, redirectUri, verifier) });
      const token = (JSON.parse(issued.body) as { refresh_token: string }).refresh_token;
      const full = await localRequest(`${fixture.baseUrl}/oauth/token`, { method: "POST", body: refreshBody(token) });
      expect(full.status).toBe(503);
      expect(JSON.parse(full.body)).toEqual({ error: "temporarily_unavailable" });
      config.limits.maxRefreshTokenRecords = 2;
      const retry = await localRequest(`${fixture.baseUrl}/oauth/token`, { method: "POST", body: refreshBody(token) });
      expect(retry.status).toBe(200);
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

  it("persists refresh rotation and replay history without storing raw tokens", async () => {
    const signingKeyPath = await createSigningKeyFile();
    const statePath = join(mkdtempSync(join(tmpdir(), "gateway-refresh-state-")), "refresh-state.json");
    const redirectUri = "https://chatgpt.com/oauth/callback";
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: [redirectUri] }), { status: 200 }));

    const firstConfig = await builtinOAuthConfig({ signingKeyPath, refreshTokenStoreFile: statePath });
    const firstServer = await startServer(firstConfig);
    const verifier = "persistent-refresh-verifier";
    const code = await authorizeCode(firstServer.baseUrl, redirectUri, verifier);
    const issued = await localRequest(`${firstServer.baseUrl}/oauth/token`, { method: "POST", body: tokenBody(code, redirectUri, verifier) });
    const issuedBody = JSON.parse(issued.body) as { access_token: string; refresh_token: string };
    await firstServer.close();

    const secondConfig = await builtinOAuthConfig({ signingKeyPath, refreshTokenStoreFile: statePath });
    const secondServer = await startServer(secondConfig);
    const refreshed = await localRequest(`${secondServer.baseUrl}/oauth/token`, { method: "POST", body: refreshBody(issuedBody.refresh_token) });
    expect(refreshed.status).toBe(200);
    const refreshedBody = JSON.parse(refreshed.body) as { refresh_token: string };
    await secondServer.close();

    const stored = readFileSync(statePath, "utf8");
    expect(stored).not.toContain(issuedBody.access_token);
    expect(stored).not.toContain(issuedBody.refresh_token);
    expect(stored).not.toContain(refreshedBody.refresh_token);
    expect(statSync(statePath).mode & 0o777).toBe(0o600);

    const thirdConfig = await builtinOAuthConfig({ signingKeyPath, refreshTokenStoreFile: statePath });
    const thirdServer = await startServer(thirdConfig);
    try {
      const replay = await localRequest(`${thirdServer.baseUrl}/oauth/token`, { method: "POST", body: refreshBody(issuedBody.refresh_token) });
      expect(replay.status).toBe(400);
      expect(JSON.parse(replay.body)).toEqual({ error: "invalid_grant" });
      const revoked = await localRequest(`${thirdServer.baseUrl}/oauth/token`, { method: "POST", body: refreshBody(refreshedBody.refresh_token) });
      expect(revoked.status).toBe(400);
      expect(JSON.parse(revoked.body)).toEqual({ error: "invalid_grant" });
    } finally {
      await thirdServer.close();
    }
  });

  it("loses memory-only refresh grants across a fresh gateway configuration", async () => {
    const signingKeyPath = await createSigningKeyFile();
    const redirectUri = "https://chatgpt.com/oauth/callback";
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: [redirectUri] }), { status: 200 }));
    const first = await startServer(await builtinOAuthConfig({ signingKeyPath }));
    const verifier = "ephemeral-refresh-verifier";
    const code = await authorizeCode(first.baseUrl, redirectUri, verifier);
    const issued = await localRequest(`${first.baseUrl}/oauth/token`, { method: "POST", body: tokenBody(code, redirectUri, verifier) });
    const refreshToken = (JSON.parse(issued.body) as { refresh_token: string }).refresh_token;
    await first.close();

    const second = await startServer(await builtinOAuthConfig({ signingKeyPath }));
    try {
      const refresh = await localRequest(`${second.baseUrl}/oauth/token`, { method: "POST", body: refreshBody(refreshToken) });
      expect(refresh.status).toBe(400);
      expect(JSON.parse(refresh.body)).toEqual({ error: "invalid_grant" });
    } finally {
      await second.close();
    }
  });

  it("rejects malformed refresh state during server creation", async () => {
    const statePath = join(mkdtempSync(join(tmpdir(), "gateway-refresh-invalid-")), "refresh-state.json");
    writeFileSync(statePath, "{}\n");
    const config = await builtinOAuthConfig({ refreshTokenStoreFile: statePath });
    expect(() => createGatewayServer(config)).toThrow("Invalid built-in OAuth refresh state");
  });

  it("returns no tokens and restores memory state when refresh persistence fails", async () => {
    const statePath = join(mkdtempSync(join(tmpdir(), "gateway-refresh-failure-")), "refresh-state.json");
    const config = await builtinOAuthConfig({ refreshTokenStoreFile: statePath });
    const fixture = await startServer(config);
    const redirectUri = "https://chatgpt.com/oauth/callback";
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: [redirectUri] }), { status: 200 }));
    try {
      const verifier = "failed-refresh-write-verifier";
      const code = await authorizeCode(fixture.baseUrl, redirectUri, verifier);
      const issued = await localRequest(`${fixture.baseUrl}/oauth/token`, { method: "POST", body: tokenBody(code, redirectUri, verifier) });
      const refreshToken = (JSON.parse(issued.body) as { refresh_token: string }).refresh_token;
      const priorState = readFileSync(statePath, "utf8");
      unlinkSync(statePath);
      mkdirSync(statePath);

      const failed = await localRequest(`${fixture.baseUrl}/oauth/token`, { method: "POST", body: refreshBody(refreshToken) });
      expect(failed.status).toBe(503);
      expect(JSON.parse(failed.body)).toEqual({ error: "temporarily_unavailable" });
      expect(failed.body).not.toContain("access_token");
      expect(failed.body).not.toContain("refresh_token");

      rmdirSync(statePath);
      writeFileSync(statePath, priorState, { mode: 0o600 });
      const retry = await localRequest(`${fixture.baseUrl}/oauth/token`, { method: "POST", body: refreshBody(refreshToken) });
      expect(retry.status).toBe(200);
    } finally {
      await fixture.close();
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
      expect(logs).toContain("oauth.refresh_state_ephemeral");
      expect(logs).toContain("oauth.authorize.completed");
      expect(logs).toContain("oauth.token.completed");
      expect(logs).toContain("\"resource_status\":\"match\"");
      expect(logs).toContain("\"scope_count\":1");
      expect(logs).not.toContain("admin@example.com");
      expect(logs).not.toContain("correct horse battery staple");
      expect(logs).not.toContain(code);
      expect(logs).not.toContain(verifier);
      expect(logs).not.toContain(JSON.parse(token.body).access_token);
      expect(logs).not.toContain(JSON.parse(token.body).refresh_token);
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

  it("returns identical failures for invalid usernames and passwords, then throttles before verification", async () => {
    const config = await builtinOAuthConfig({ loginRateLimit: {
      window: "1m", per_source: 2, per_account: 2, global: 10,
      initial_lockout: "1m", max_lockout: "2m", max_entries: 20,
    } });
    const fixture = await startServer(config);
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: ["https://chatgpt.com/oauth/callback"] }), { status: 200 }));
    try {
      const wrongUsername = await localRequest(`${fixture.baseUrl}/oauth/authorize`, {
        method: "POST", body: authorizationBody({ username: "nobody@example.org", code_challenge: pkceChallenge("wrong-user") }),
      });
      const wrongPassword = await localRequest(`${fixture.baseUrl}/oauth/authorize`, {
        method: "POST", body: authorizationBody({ password: "wrong-password", code_challenge: pkceChallenge("wrong-password") }),
      });
      expect(wrongUsername.status).toBe(401);
      expect(wrongPassword.status).toBe(401);
      expect(wrongUsername.body).toBe(wrongPassword.body);

      const throttled = await localRequest(`${fixture.baseUrl}/oauth/authorize`, {
        method: "POST", body: authorizationBody({ code_challenge: pkceChallenge("throttled") }),
      });
      expect(throttled.status).toBe(429);
      expect(throttled.headers["retry-after"]).toBe("60");
      expect(JSON.parse(throttled.body)).toEqual({ error: "temporarily_unavailable" });
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

  it("rejects password verification above the direct-source concurrency limit", async () => {
    const config = await builtinOAuthConfig({
      passwordIterations: 500_000,
      maxPasswordVerifications: 2,
      maxPasswordVerificationsPerSource: 1,
    });
    const fixture = await startServer(config);
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: ["https://chatgpt.com/oauth/callback"] }), { status: 200 }));
    try {
      const first = localRequest(`${fixture.baseUrl}/oauth/authorize`, {
        method: "POST", body: authorizationBody({ code_challenge: pkceChallenge("first-verifier") }),
      });
      await new Promise<void>((resolve) => setImmediate(resolve));
      const rejected = await localRequest(`${fixture.baseUrl}/oauth/authorize`, {
        method: "POST", body: authorizationBody({ code_challenge: pkceChallenge("second-verifier") }),
      });
      expect(rejected.status).toBe(429);
      expect(rejected.headers["retry-after"]).toBe("1");
      expect(JSON.parse(rejected.body)).toEqual({ error: "temporarily_unavailable" });
      expect((await first).status).toBe(302);
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

  it("bounds authorization codes without disturbing live codes", async () => {
    const config = await builtinOAuthConfig({ maxAuthorizationCodes: 1 });
    const fixture = await startServer(config);
    const redirectUri = "https://chatgpt.com/oauth/callback";
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: [redirectUri] }), { status: 200 }));
    try {
      const firstVerifier = "first-capacity-verifier";
      const firstCode = await authorizeCode(fixture.baseUrl, redirectUri, firstVerifier);
      const rejected = await localRequest(`${fixture.baseUrl}/oauth/authorize`, {
        method: "POST", body: authorizationBody({ redirect_uri: redirectUri, code_challenge: pkceChallenge("second-capacity-verifier") }),
      });
      expect(rejected.status).toBe(429);
      expect(JSON.parse(rejected.body)).toEqual({ error: "temporarily_unavailable" });

      const exchange = await localRequest(`${fixture.baseUrl}/oauth/token`, {
        method: "POST", body: tokenBody(firstCode, redirectUri, firstVerifier),
      });
      expect(exchange.status).toBe(200);
      const replacement = await authorizeCode(fixture.baseUrl, redirectUri, "replacement-verifier");
      expect(replacement).toBeTruthy();
    } finally {
      await fixture.close();
    }
  });

  it("isolates authorization codes between gateway configurations", async () => {
    const signingKeyPath = await createSigningKeyFile();
    const firstConfig = await builtinOAuthConfig({ signingKeyPath });
    const secondConfig = await builtinOAuthConfig({ signingKeyPath });
    const first = await startServer(firstConfig);
    const second = await startServer(secondConfig);
    const redirectUri = "https://chatgpt.com/oauth/callback";
    const verifier = "isolated-code-verifier";
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ redirect_uris: [redirectUri] }), { status: 200 }));
    try {
      const code = await authorizeCode(first.baseUrl, redirectUri, verifier);
      const crossConfig = await localRequest(`${second.baseUrl}/oauth/token`, {
        method: "POST", body: tokenBody(code, redirectUri, verifier),
      });
      expect(crossConfig.status).toBe(400);
      expect(JSON.parse(crossConfig.body)).toEqual({ error: "invalid_grant" });
    } finally {
      await first.close();
      await second.close();
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

  it("uses the configured stable OAuth principal claim and rejects invalid identities", async () => {
    const jwks = await startJwks();
    try {
      const config = oauthConfig(jwks.jwksUri, "client_id");
      const firstToken = await jwks.sign(
        { aud: "agent-credential-gateway", scope: "gateway.tokens" },
        { subject: null, extraClaims: { client_id: "client-a" } },
      );
      const secondToken = await jwks.sign(
        { aud: "agent-credential-gateway", scope: "gateway.request" },
        { subject: null, extraClaims: { client_id: "client-b" } },
      );
      const first = await authenticateRequest(requestWithBearer(firstToken), config, ["gateway.tokens"]);
      const second = await authenticateRequest(requestWithBearer(secondToken), config, ["gateway.request"]);
      expect(first.subject).toBe("client-a");
      expect(second.subject).toBe("client-b");

      config.services["demo-service"]?.access.users.push("client-a", "client-b");
      const broker = new TokenBroker(config);
      const issued = broker.issueTokens(first, {
        service: "demo-service", destination: "primary", credential_ids: ["api_key"], reason: "Principal isolation.",
      });
      expect(() => broker.validateTokenUse(second, { service: "demo-service", destination: "primary" }, issued.tokens[0]?.token ?? ""))
        .toThrow("not bound to this subject");

      for (const extraClaims of [{}, { client_id: "" }, { client_id: "   " }, { client_id: 42 }]) {
        const invalid = await jwks.sign(
          { aud: "agent-credential-gateway", scope: "gateway.read" },
          { subject: null, extraClaims },
        );
        await expect(authenticateRequest(requestWithBearer(invalid), config)).rejects.toThrow("stable principal claim");
      }
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

function oauthConfig(jwksUri: string, principalClaim?: string): GatewayConfig {
  return validateConfig(baseRawConfig({
    mode: "oauth",
    oauth: {
      issuer: "https://auth.example.com",
      audience: "agent-credential-gateway",
      jwks_uri: jwksUri,
      required_scopes: ["gateway.read", "gateway.tokens", "gateway.request"],
      ...(principalClaim === undefined ? {} : { principal_claim: principalClaim }),
    },
  }), {
    DEMO_API_KEY: "secret",
  });
}

async function builtinOAuthConfig(options: {
  authorizationCodeTtl?: string;
  refreshTokenIdleTtl?: string;
  refreshTokenMaxTtl?: string;
  refreshTokenStoreFile?: string;
  allowedClients?: string[];
  loggingLevel?: "info" | "debug";
  signingKeyPath?: string;
  maxInboundBody?: string;
  maxUnauthenticatedInflight?: number;
  maxUnauthenticatedInflightPerSource?: number;
  passwordIterations?: number;
  adminPasswordHash?: string;
  maxPasswordVerifications?: number;
  maxPasswordVerificationsPerSource?: number;
  loginRateLimit?: {
    window: string; per_source: number; per_account: number; global: number;
    initial_lockout: string; max_lockout: string; max_entries: number;
  };
  maxAuthorizationCodes?: number;
  maxRefreshTokenRecords?: number;
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
        refresh_token_idle_ttl: options.refreshTokenIdleTtl ?? "30d",
        refresh_token_max_ttl: options.refreshTokenMaxTtl ?? "90d",
        ...(options.refreshTokenStoreFile === undefined ? {} : { refresh_token_store_file: options.refreshTokenStoreFile }),
        allowed_clients: options.allowedClients ?? ["https://chatgpt.com"],
        required_scopes: ["gateway.read", "gateway.tokens", "gateway.request"],
        ...(options.loginRateLimit === undefined ? {} : { login_rate_limit: options.loginRateLimit }),
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
      max_password_verifications: options.maxPasswordVerifications ?? 2,
      max_password_verifications_per_source: options.maxPasswordVerificationsPerSource ?? 1,
      max_authorization_codes: options.maxAuthorizationCodes ?? 1000,
      max_refresh_token_records: options.maxRefreshTokenRecords ?? 10_000,
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

function refreshBody(refreshToken: string, overrides: Record<string, string> = {}): string {
  return new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: "https://chatgpt.com/oauth/client",
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

async function authorizeCode(baseUrl: string, redirectUri: string, verifier: string, scope = "gateway.read"): Promise<string> {
  const authorize = await localRequest(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    body: authorizationBody({
      redirect_uri: redirectUri,
      code_challenge: pkceChallenge(verifier),
      scope,
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
      options: {
        issuer?: string; expiresIn?: number; notBefore?: number; subject?: string | null;
        extraClaims?: Record<string, unknown>;
      } = {},
    ) => {
      const now = Math.floor(Date.now() / 1000);
      const jwt = new SignJWT({ scope: claims.scope, ...options.extraClaims })
        .setProtectedHeader({ alg: "RS256", kid: "test-key" })
        .setIssuer(options.issuer ?? "https://auth.example.com")
        .setAudience(claims.aud)
        .setIssuedAt(now)
        .setExpirationTime(now + (options.expiresIn ?? 3600));
      if (options.subject !== null) jwt.setSubject(options.subject ?? "henric@example.com");
      if (options.notBefore !== undefined) jwt.setNotBefore(now + options.notBefore);
      return jwt.sign(privateKey);
    },
    close: () => new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    }),
  };
}
