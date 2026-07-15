import { createHash, pbkdf2, pbkdf2Sync, randomBytes, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import type { IncomingMessage, ServerResponse } from "node:http";
import { exportJWK, importPKCS8, importSPKI, SignJWT } from "jose";
import { createLogger } from "./logger.js";
import type { BuiltinOAuthAuthConfig, GatewayConfig } from "./types.js";
import { readBoundedBody, RequestBodyError } from "./httpBody.js";
import { InflightLimiter } from "./inflightLimiter.js";
import { LoginAttemptLimiter } from "./loginAttemptLimiter.js";

const AUTHORIZATION_SERVER_METADATA_PATH = "/.well-known/oauth-authorization-server";
const OPENID_CONFIGURATION_PATH = "/.well-known/openid-configuration";
const JWKS_PATH = "/oauth/jwks.json";
const AUTHORIZE_PATH = "/oauth/authorize";
const TOKEN_PATH = "/oauth/token";

interface AuthorizationCode {
  clientId: string;
  redirectUri: string;
  resource: string;
  scopes: string[];
  codeChallenge: string;
  subject: string;
  expiresAt: number;
}

const authorizationCodes = new Map<string, AuthorizationCode>();
const privateKeyCache = new Map<string, ReturnType<typeof importPKCS8>>();
const publicKeyCache = new Map<string, ReturnType<typeof importSPKI>>();
const bodyLimiters = new WeakMap<GatewayConfig, InflightLimiter>();
const passwordLimiters = new WeakMap<GatewayConfig, InflightLimiter>();
const loginAttemptLimiters = new WeakMap<GatewayConfig, LoginAttemptLimiter>();
const pbkdf2Async = promisify(pbkdf2);

export function isBuiltinOAuthRequest(config: GatewayConfig, request: IncomingMessage): boolean {
  if (config.auth.mode !== "builtin_oauth") return false;
  const path = request.url?.split("?")[0];
  return path === AUTHORIZATION_SERVER_METADATA_PATH
    || path === OPENID_CONFIGURATION_PATH
    || path === JWKS_PATH
    || path === AUTHORIZE_PATH
    || path === TOKEN_PATH;
}

export async function handleBuiltinOAuthRequest(
  config: GatewayConfig,
  request: IncomingMessage,
  response: ServerResponse,
): Promise<void> {
  if (config.auth.mode !== "builtin_oauth") {
    writeJson(response, 404, { error: "not_found" });
    return;
  }

  const path = request.url?.split("?")[0];
  if (request.method === "GET" && (path === AUTHORIZATION_SERVER_METADATA_PATH || path === OPENID_CONFIGURATION_PATH)) {
    writeJson(response, 200, authorizationServerMetadata(config));
    return;
  }
  if (request.method === "GET" && path === JWKS_PATH) {
    writeJson(response, 200, await jwks(config.auth.builtinOAuth));
    return;
  }
  if (request.method === "GET" && path === AUTHORIZE_PATH) {
    renderLoginForm(config, request, response);
    return;
  }
  if (request.method === "POST" && path === AUTHORIZE_PATH) {
    await handleAuthorizePost(config, request, response);
    return;
  }
  if (request.method === "POST" && path === TOKEN_PATH) {
    await handleTokenPost(config, request, response);
    return;
  }

  writeJson(response, 405, { error: "method_not_allowed" });
}

export function hashBuiltinOAuthPassword(password: string, salt = randomBytes(16).toString("base64url"), iterations = 210_000): string {
  const hash = pbkdf2Sync(password, salt, iterations, 32, "sha256").toString("base64url");
  return `pbkdf2-sha256$${iterations}$${salt}$${hash}`;
}

function authorizationServerMetadata(config: GatewayConfig): Record<string, unknown> {
  if (config.auth.mode !== "builtin_oauth") throw new Error("Expected built-in OAuth config");
  const issuer = config.auth.builtinOAuth.issuer;
  return {
    issuer,
    authorization_endpoint: `${issuer}${AUTHORIZE_PATH}`,
    token_endpoint: `${issuer}${TOKEN_PATH}`,
    jwks_uri: `${issuer}${JWKS_PATH}`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    client_id_metadata_document_supported: true,
    scopes_supported: config.auth.builtinOAuth.requiredScopes,
  };
}

async function jwks(auth: BuiltinOAuthAuthConfig["builtinOAuth"]): Promise<Record<string, unknown>> {
  const publicKey = await getPublicKey(auth.signingPublicKeyPem);
  const jwk = await exportJWK(publicKey);
  return {
    keys: [{
      ...jwk,
      kid: auth.signingKeyId,
      use: "sig",
      alg: "RS256",
    }],
  };
}

function renderLoginForm(config: GatewayConfig, request: IncomingMessage, response: ServerResponse): void {
  const params = new URL(request.url ?? AUTHORIZE_PATH, config.auth.mode === "builtin_oauth" ? config.auth.builtinOAuth.issuer : "http://localhost").searchParams;
  const hidden = [...params.entries()]
    .map(([key, value]) => `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`)
    .join("\n");
  response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  response.end(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Authorize MCP Gateway</title></head>
<body>
<main>
<h1>Authorize MCP Gateway</h1>
<form method="post" action="${AUTHORIZE_PATH}">
${hidden}
<label>Username <input name="username" autocomplete="username" required></label>
<label>Password <input name="password" type="password" autocomplete="current-password" required></label>
<button type="submit">Authorize</button>
</form>
</main>
</body>
</html>`);
}

async function handleAuthorizePost(config: GatewayConfig, request: IncomingMessage, response: ServerResponse): Promise<void> {
  const auth = config.auth.mode === "builtin_oauth" ? config.auth.builtinOAuth : undefined;
  if (auth === undefined) throw new Error("Expected built-in OAuth config");
  const logger = createLogger(config.logging);

  let body: URLSearchParams;
  try {
    const limitedBody = await readLimitedFormBody(config, request, response);
    if (limitedBody === undefined) return;
    body = limitedBody;
  } catch (error) {
    if (error instanceof RequestBodyError) {
      closeAfterResponse(request, response);
      writeOAuthError(response, error.statusCode, oauthBodyError(error));
      return;
    }
    throw error;
  }
  const validation = await validateAuthorizationRequest(config, body);
  if (!validation.ok) {
    logger.debug("oauth.authorize.completed", {
      endpoint: AUTHORIZE_PATH,
      status: "error",
      status_code: 400,
      error_code: validation.error,
      client_status: clientStatus(body.get("client_id"), auth.allowedClients),
      resource_status: resourceStatus(body.get("resource"), config.server.resource ?? auth.issuer),
      scope_count: scopesFromRequest(body.get("scope"), auth.requiredScopes).length,
    });
    writeJson(response, 400, { error: validation.error });
    return;
  }

  const source = request.socket.remoteAddress ?? "unknown";
  const account = (body.get("username") ?? "").trim().toLowerCase();
  const attemptLimiter = getLoginAttemptLimiter(config);
  const admission = attemptLimiter.check(source, account);
  if (!admission.allowed) {
    response.setHeader("retry-after", String(Math.max(1, Math.ceil(admission.retryAfterMs / 1000))));
    writeOAuthError(response, 429, "temporarily_unavailable");
    return;
  }

  let passwordValid = false;
  if (body.get("username") === auth.adminUsername) {
    const release = acquirePasswordVerification(config, request);
    if (release === undefined) {
      response.setHeader("retry-after", "1");
      writeOAuthError(response, 429, "temporarily_unavailable");
      return;
    }
    try {
      passwordValid = await verifyPassword(body.get("password") ?? "", auth.adminPasswordHash);
    } finally {
      release();
    }
  }
  if (!passwordValid) {
    attemptLimiter.recordFailure(source, account);
    logger.debug("oauth.authorize.completed", {
      endpoint: AUTHORIZE_PATH,
      status: "error",
      status_code: 401,
      error_code: "invalid_login",
      client_status: "allowed",
      resource_status: "match",
      scope_count: validation.scopes.length,
    });
    response.writeHead(401, { "content-type": "text/html; charset=utf-8" });
    response.end("<!doctype html><html><body><p>Invalid username or password.</p></body></html>");
    return;
  }

  attemptLimiter.recordSuccess(source, account);

  const code = randomBytes(32).toString("base64url");
  authorizationCodes.set(code, {
    clientId: validation.clientId,
    redirectUri: validation.redirectUri,
    resource: validation.resource,
    scopes: validation.scopes,
    codeChallenge: validation.codeChallenge,
    subject: auth.adminUsername,
    expiresAt: Date.now() + auth.authorizationCodeTtlMs,
  });

  const redirect = new URL(validation.redirectUri);
  redirect.searchParams.set("code", code);
  const state = body.get("state");
  if (state) redirect.searchParams.set("state", state);
  logger.debug("oauth.authorize.completed", {
    endpoint: AUTHORIZE_PATH,
    status: "success",
    status_code: 302,
    client_status: "allowed",
    resource_status: "match",
    scope_count: validation.scopes.length,
  });
  response.writeHead(302, { location: redirect.toString() });
  response.end();
}

function acquirePasswordVerification(config: GatewayConfig, request: IncomingMessage): (() => void) | undefined {
  let limiter = passwordLimiters.get(config);
  if (limiter === undefined) {
    limiter = new InflightLimiter(
      config.limits.maxPasswordVerifications,
      config.limits.maxPasswordVerificationsPerSource,
    );
    passwordLimiters.set(config, limiter);
  }
  return limiter.acquire(request.socket.remoteAddress ?? "unknown");
}

function getLoginAttemptLimiter(config: GatewayConfig): LoginAttemptLimiter {
  let limiter = loginAttemptLimiters.get(config);
  if (limiter === undefined) {
    limiter = new LoginAttemptLimiter(config.auth.mode === "builtin_oauth" ? config.auth.builtinOAuth.loginRateLimit : {
      windowMs: 15 * 60_000, perSource: 10, perAccount: 10, global: 100,
      initialLockoutMs: 15 * 60_000, maxLockoutMs: 60 * 60_000, maxEntries: 1000,
    });
    loginAttemptLimiters.set(config, limiter);
  }
  return limiter;
}

async function handleTokenPost(config: GatewayConfig, request: IncomingMessage, response: ServerResponse): Promise<void> {
  const auth = config.auth.mode === "builtin_oauth" ? config.auth.builtinOAuth : undefined;
  if (auth === undefined) throw new Error("Expected built-in OAuth config");
  const logger = createLogger(config.logging);

  let body: URLSearchParams;
  try {
    const limitedBody = await readLimitedFormBody(config, request, response);
    if (limitedBody === undefined) return;
    body = limitedBody;
  } catch (error) {
    if (error instanceof RequestBodyError) {
      closeAfterResponse(request, response);
      writeOAuthError(response, error.statusCode, oauthBodyError(error));
      return;
    }
    throw error;
  }
  if (body.get("grant_type") !== "authorization_code") {
    logTokenOutcome(logger, "error", 400, "unsupported_grant_type", "unavailable", "unavailable");
    writeOAuthError(response, 400, "unsupported_grant_type");
    return;
  }
  const code = body.get("code") ?? "";
  const record = authorizationCodes.get(code);
  if (record === undefined || record.expiresAt <= Date.now()) {
    authorizationCodes.delete(code);
    logTokenOutcome(logger, "error", 400, "invalid_grant", "unavailable", "unavailable");
    writeOAuthError(response, 400, "invalid_grant");
    return;
  }
  authorizationCodes.delete(code);

  if (body.get("client_id") !== record.clientId || body.get("redirect_uri") !== record.redirectUri) {
    logTokenOutcome(logger, "error", 400, "invalid_grant", resourceStatus(body.get("resource"), record.resource), record.scopes.length);
    writeOAuthError(response, 400, "invalid_grant");
    return;
  }
  const requestedResource = body.get("resource");
  if (requestedResource !== null && requestedResource !== record.resource) {
    logTokenOutcome(logger, "error", 400, "invalid_target", "mismatch", record.scopes.length);
    writeOAuthError(response, 400, "invalid_target");
    return;
  }
  const codeVerifier = body.get("code_verifier") ?? "";
  if (pkceChallenge(codeVerifier) !== record.codeChallenge) {
    logTokenOutcome(logger, "error", 400, "invalid_grant", resourceStatus(requestedResource, record.resource), record.scopes.length);
    writeOAuthError(response, 400, "invalid_grant");
    return;
  }

  const now = Math.floor(Date.now() / 1000);
  const accessToken = await new SignJWT({ scope: record.scopes.join(" ") })
    .setProtectedHeader({ alg: "RS256", kid: auth.signingKeyId })
    .setSubject(record.subject)
    .setIssuer(auth.issuer)
    .setAudience(record.resource)
    .setIssuedAt(now)
    .setExpirationTime(now + Math.floor(auth.accessTokenTtlMs / 1000))
    .sign(await getPrivateKey(auth.signingPrivateKeyPem));

  logTokenOutcome(logger, "success", 200, undefined, resourceStatus(requestedResource, record.resource), record.scopes.length);
  writeJson(response, 200, {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: Math.floor(auth.accessTokenTtlMs / 1000),
    scope: record.scopes.join(" "),
  });
}

async function validateAuthorizationRequest(
  config: GatewayConfig,
  body: URLSearchParams,
): Promise<
  | { ok: true; clientId: string; redirectUri: string; resource: string; scopes: string[]; codeChallenge: string }
  | { ok: false; error: string }
> {
  const auth = config.auth.mode === "builtin_oauth" ? config.auth.builtinOAuth : undefined;
  if (auth === undefined) throw new Error("Expected built-in OAuth config");

  if (body.get("response_type") !== "code") return { ok: false, error: "unsupported_response_type" };
  if (body.get("code_challenge_method") !== "S256") return { ok: false, error: "invalid_request" };

  const resource = body.get("resource");
  const expectedResource = config.server.resource ?? auth.issuer;
  if (resource !== expectedResource) return { ok: false, error: "invalid_target" };

  const clientId = body.get("client_id");
  if (!clientId || !isAllowedClient(auth.allowedClients, clientId)) return { ok: false, error: "invalid_client" };
  let clientUrl: URL;
  try {
    clientUrl = new URL(clientId);
  } catch {
    return { ok: false, error: "invalid_client" };
  }
  if (clientUrl.protocol !== "https:") return { ok: false, error: "invalid_client" };

  const redirectUri = body.get("redirect_uri");
  if (!redirectUri) return { ok: false, error: "invalid_request" };
  if (!await clientMetadataAllowsRedirect(clientId, redirectUri)) return { ok: false, error: "invalid_request" };

  const codeChallenge = body.get("code_challenge");
  if (!codeChallenge) return { ok: false, error: "invalid_request" };

  const scopes = scopesFromRequest(body.get("scope"), auth.requiredScopes);
  if (scopes.some((scope) => !auth.requiredScopes.includes(scope))) return { ok: false, error: "invalid_scope" };

  return { ok: true, clientId, redirectUri, resource, scopes, codeChallenge };
}

async function clientMetadataAllowsRedirect(clientId: string, redirectUri: string): Promise<boolean> {
  try {
    const response = await fetch(clientId, { signal: AbortSignal.timeout(5000) });
    if (!response.ok) return false;
    const metadata = await response.json() as { redirect_uris?: unknown };
    return Array.isArray(metadata.redirect_uris) && metadata.redirect_uris.includes(redirectUri);
  } catch {
    return false;
  }
}

function isAllowedClient(allowedClients: string[], clientId: string): boolean {
  return allowedClients.some((allowed) => {
    if (allowed === clientId) return true;
    try {
      const allowedUrl = new URL(allowed);
      const clientUrl = new URL(clientId);
      const allowedIsOrigin = allowedUrl.pathname === "/" && allowedUrl.search === "" && allowedUrl.hash === "";
      return allowedIsOrigin && allowedUrl.origin === clientUrl.origin;
    } catch {
      return false;
    }
  });
}

function clientStatus(clientId: string | null, allowedClients: string[]): "allowed" | "rejected" | "missing" {
  if (!clientId) return "missing";
  return isAllowedClient(allowedClients, clientId) ? "allowed" : "rejected";
}

function resourceStatus(resource: string | null, expectedResource: string): "match" | "mismatch" | "missing" | "omitted" {
  if (resource === null) return "omitted";
  if (resource === "") return "missing";
  return resource === expectedResource ? "match" : "mismatch";
}

function logTokenOutcome(
  logger: ReturnType<typeof createLogger>,
  status: "success" | "error",
  statusCode: number,
  errorCode: string | undefined,
  resourceStatusValue: ReturnType<typeof resourceStatus> | "unavailable",
  scopeCount: number | "unavailable",
): void {
  logger.debug("oauth.token.completed", {
    endpoint: TOKEN_PATH,
    status,
    status_code: statusCode,
    ...(errorCode === undefined ? {} : { error_code: errorCode }),
    resource_status: resourceStatusValue,
    scope_count: scopeCount,
  });
}

function scopesFromRequest(scope: string | null, defaultScopes: string[]): string[] {
  if (scope === null || scope.trim() === "") return defaultScopes;
  return scope.split(/\s+/).filter(Boolean);
}

async function verifyPassword(password: string, expectedHash: string): Promise<boolean> {
  const parts = expectedHash.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2-sha256") return false;
  const iterations = Number(parts[1]);
  const salt = parts[2];
  const expected = parts[3];
  if (!Number.isInteger(iterations) || iterations <= 0 || !salt || !expected) return false;
  let actual: Buffer;
  try {
    actual = await pbkdf2Async(password, salt, iterations, 32, "sha256");
  } catch {
    return false;
  }
  const expectedBuffer = Buffer.from(expected, "base64url");
  return actual.length === expectedBuffer.length && timingSafeEqual(actual, expectedBuffer);
}

function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

function getPrivateKey(privateKeyPem: string): ReturnType<typeof importPKCS8> {
  const cached = privateKeyCache.get(privateKeyPem);
  if (cached !== undefined) return cached;
  const key = importPKCS8(privateKeyPem, "RS256");
  privateKeyCache.set(privateKeyPem, key);
  return key;
}

function getPublicKey(publicKeyPem: string): ReturnType<typeof importSPKI> {
  const cached = publicKeyCache.get(publicKeyPem);
  if (cached !== undefined) return cached;
  const key = importSPKI(publicKeyPem, "RS256");
  publicKeyCache.set(publicKeyPem, key);
  return key;
}

async function readFormBody(request: IncomingMessage, maxBytes?: number, timeoutMs?: number): Promise<URLSearchParams> {
  if (maxBytes !== undefined) {
    return new URLSearchParams((await readBoundedBody(request, maxBytes, timeoutMs)).toString("utf8"));
  }
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

async function readLimitedFormBody(
  config: GatewayConfig,
  request: IncomingMessage,
  response: ServerResponse,
): Promise<URLSearchParams | undefined> {
  let limiter = bodyLimiters.get(config);
  if (limiter === undefined) {
    limiter = new InflightLimiter(
      config.limits.maxUnauthenticatedInflight,
      config.limits.maxUnauthenticatedInflightPerSource,
    );
    bodyLimiters.set(config, limiter);
  }
  const source = request.socket.remoteAddress ?? "unknown";
  const release = limiter.acquire(source);
  if (release === undefined) {
    response.setHeader("retry-after", "1");
    closeAfterResponse(request, response);
    writeOAuthError(response, 429, "temporarily_unavailable");
    return undefined;
  }
  try {
    return await readFormBody(request, config.limits.maxInboundBodyBytes, config.limits.inboundBodyTimeoutMs);
  } finally {
    release();
  }
}

function oauthBodyError(error: RequestBodyError): string {
  if (error.code === "request_too_large") return "request_too_large";
  if (error.code === "request_timeout") return "request_timeout";
  return "invalid_request";
}

function closeAfterResponse(request: IncomingMessage, response: ServerResponse): void {
  response.setHeader("connection", "close");
  response.once("finish", () => request.destroy());
}

function writeJson(response: ServerResponse, statusCode: number, body: unknown): void {
  response.writeHead(statusCode, { "content-type": "application/json; charset=utf-8" });
  response.end(`${JSON.stringify(body)}\n`);
}

function writeOAuthError(response: ServerResponse, statusCode: number, error: string): void {
  writeJson(response, statusCode, { error });
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;");
}
