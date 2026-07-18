import { createHash, pbkdf2, pbkdf2Sync, randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { promisify } from "node:util";
import type { IncomingMessage, ServerResponse } from "node:http";
import { exportJWK, importPKCS8, importSPKI, SignJWT } from "jose";
import { createLogger } from "./logger.js";
import type { BuiltinOAuthAuthConfig, GatewayConfig } from "./types.js";
import { readBoundedBody, RequestBodyError } from "./httpBody.js";
import { InflightLimiter } from "./inflightLimiter.js";
import { LoginAttemptLimiter } from "./loginAttemptLimiter.js";
import { registerMaintenanceTask } from "./maintenance.js";
import { BRAND_ICON_PATH, BRAND_LOCKUP_PATH } from "./brandAssets.js";

const AUTHORIZATION_SERVER_METADATA_PATH = "/.well-known/oauth-authorization-server";
const OPENID_CONFIGURATION_PATH = "/.well-known/openid-configuration";
const JWKS_PATH = "/oauth/jwks.json";
const AUTHORIZE_PATH = "/oauth/authorize";
const TOKEN_PATH = "/oauth/token";
const AUTHORIZE_FORM_PARAMETER_NAMES = [
  "response_type",
  "client_id",
  "redirect_uri",
  "scope",
  "state",
  "code_challenge_method",
  "code_challenge",
  "resource",
] as const;
const AUTHORIZE_PAGE_HEADERS = {
  "cache-control": "no-store",
  "content-security-policy": "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  "content-type": "text/html; charset=utf-8",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
} as const;

interface AuthorizationCode {
  clientId: string;
  redirectUri: string;
  resource: string;
  scopes: string[];
  codeChallenge: string;
  subject: string;
  expiresAt: number;
}

interface RefreshGrant {
  id: string;
  clientId: string;
  resource: string;
  scopes: string[];
  subject: string;
  createdAt: number;
  idleExpiresAt: number;
  expiresAt: number;
}

interface RefreshTokenRecord {
  grantId: string;
  status: "active" | "rotating" | "used";
}

interface BuiltinOAuthState {
  authorizationCodes: Map<string, AuthorizationCode>;
  refreshGrants: Map<string, RefreshGrant>;
  refreshTokens: Map<string, RefreshTokenRecord>;
}

interface PersistedRefreshState {
  version: 1;
  refreshGrants: RefreshGrant[];
  refreshTokens: Array<RefreshTokenRecord & { hash: string }>;
}
const oauthStates = new WeakMap<GatewayConfig, BuiltinOAuthState>();
const privateKeyCache = new Map<string, ReturnType<typeof importPKCS8>>();
const publicKeyCache = new Map<string, ReturnType<typeof importSPKI>>();
const bodyLimiters = new WeakMap<GatewayConfig, InflightLimiter>();
const passwordLimiters = new WeakMap<GatewayConfig, InflightLimiter>();
const loginAttemptLimiters = new WeakMap<GatewayConfig, LoginAttemptLimiter>();
const pbkdf2Async = promisify(pbkdf2);
const MAX_CLIENT_NAME_LENGTH = 120;
const PERMISSION_SCOPE_ORDER = ["gateway.read", "gateway.request", "gateway.references"] as const;

interface VerifiedClientMetadata {
  clientId: string;
  redirectUris: string[];
  clientName: string | null;
}

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
    await renderLoginForm(config, request, response);
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
    grant_types_supported: ["authorization_code", "refresh_token"],
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

async function renderLoginForm(config: GatewayConfig, request: IncomingMessage, response: ServerResponse): Promise<void> {
  const params = new URL(request.url ?? AUTHORIZE_PATH, config.auth.mode === "builtin_oauth" ? config.auth.builtinOAuth.issuer : "http://localhost").searchParams;
  const validation = await validateAuthorizationRequest(config, params);
  if (!validation.ok) {
    renderInvalidAuthorizationPage(response);
    return;
  }
  renderLoginPage(config, response, params, validation);
}

function renderLoginPage(
  config: GatewayConfig,
  response: ServerResponse,
  params: URLSearchParams,
  client: Extract<Awaited<ReturnType<typeof validateAuthorizationRequest>>, { ok: true }>,
  statusCode = 200,
  errorMessage?: string,
): void {
  const hidden = AUTHORIZE_FORM_PARAMETER_NAMES
    .flatMap((key) => {
      const value = params.get(key);
      return value === null ? [] : [`<input type="hidden" name="${key}" value="${escapeHtml(value)}">`];
    })
    .join("\n");
  const clientName = client.clientName ?? "MCP client";
  const escapedClientName = escapeHtml(clientName);
  const connectClientName = client.clientName === null ? "an MCP client" : escapedClientName;
  const sentenceClientName = client.clientName === null ? "An MCP client" : escapedClientName;
  const definiteClientName = client.clientName === null ? "the MCP client" : escapedClientName;
  const possessiveClientName = client.clientName === null ? "the MCP client&rsquo;s" : `${escapedClientName}&rsquo;s`;
  const gateway = gatewayHost(config);
  const permissions = PERMISSION_SCOPE_ORDER
    .filter((scope) => client.scopes.includes(scope))
    .map((scope) => `<li>${escapeHtml(permissionDescription(scope))}</li>`)
    .join("\n");
  const error = errorMessage === undefined
    ? ""
    : `<div class="error" role="alert"><strong>Sign-in failed.</strong> ${escapeHtml(errorMessage)}</div>`;
  response.writeHead(statusCode, AUTHORIZE_PAGE_HEADERS);
  response.end(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connect to SecretSauce</title>
<link rel="icon" type="image/png" href="${BRAND_ICON_PATH}">
<style>
:root {
  color-scheme: light;
  --bg: #f5f4f1;
  --panel: #ffffff;
  --text: #111827;
  --muted: #2a3744;
  --border: #d8dde1;
  --accent: #111827;
  --accent-dark: #2a3744;
  --paprika: #e44d26;
  --amber: #f5a623;
  --error-bg: #fef2f2;
  --error-border: #fecaca;
  --error-text: #991b1b;
}
* {
  box-sizing: border-box;
}
body {
  margin: 0;
  min-height: 100vh;
  background: var(--bg);
  color: var(--text);
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  line-height: 1.5;
}
main {
  width: min(880px, calc(100% - 32px));
  margin: 0 auto;
  padding: 40px 0;
}
.panel {
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--panel);
  box-shadow: 0 18px 45px rgba(23, 32, 51, 0.08);
}
.intro {
  padding: 32px 32px 24px;
  border-bottom: 1px solid var(--border);
}
.brand-lockup {
  display: block;
  width: min(360px, 78%);
  height: auto;
  margin: 0 0 24px;
}
h1 {
  margin: 0 0 12px;
  font-size: clamp(1.75rem, 4vw, 2.5rem);
  line-height: 1.1;
}
p {
  margin: 0 0 16px;
}
.description {
  max-width: 68ch;
  color: var(--muted);
}
.trust-summary {
  display: grid;
  gap: 8px;
  margin-top: 18px;
  padding: 14px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: #f8fafc;
}
.trust-row,
.detail-row {
  display: grid;
  grid-template-columns: 140px minmax(0, 1fr);
  gap: 10px;
  color: var(--muted);
  overflow-wrap: anywhere;
}
.trust-row strong,
.detail-row strong {
  color: var(--text);
}
.permissions {
  margin: 22px 0 0;
}
.permissions h2,
.sign-in h2 {
  margin: 0 0 8px;
  font-size: 1.12rem;
}
.permissions ul {
  margin: 8px 0 0;
  padding-left: 22px;
}
.permissions li + li {
  margin-top: 5px;
}
details {
  margin-top: 20px;
  border-top: 1px solid var(--border);
  padding-top: 14px;
}
summary {
  color: var(--paprika);
  font-weight: 700;
  cursor: pointer;
}
.connection-details {
  display: grid;
  gap: 8px;
  margin-top: 12px;
  padding: 14px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: #f8fafc;
}
.info-box,
.error {
  margin-top: 20px;
  padding: 12px 14px;
  border-radius: 8px;
}
.info-box {
  border: 1px solid #f6c46d;
  background: #fff8e8;
  color: var(--text);
}
.error {
  margin: 0 0 20px;
  border: 1px solid var(--error-border);
  background: var(--error-bg);
  color: var(--error-text);
}
form {
  padding: 28px 32px 32px;
}
.sign-in p {
  color: var(--muted);
}
.field-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}
label {
  display: grid;
  gap: 6px;
  color: var(--muted);
  font-size: 0.94rem;
  font-weight: 650;
}
input {
  width: 100%;
  min-height: 44px;
  border: 1px solid #aeb8c8;
  border-radius: 6px;
  padding: 10px 12px;
  background: #ffffff;
  color: var(--text);
  font: inherit;
}
input:focus {
  border-color: var(--paprika);
  box-shadow: 0 0 0 3px rgba(228, 77, 38, 0.18);
  outline: none;
}
.actions {
  display: flex;
  justify-content: flex-end;
  padding-top: 24px;
}
button {
  min-height: 44px;
  border: 0;
  border-radius: 6px;
  padding: 0 20px;
  background: var(--accent);
  color: #ffffff;
  font: inherit;
  font-weight: 750;
  cursor: pointer;
}
button:hover {
  background: var(--accent-dark);
}
button:focus-visible {
  outline: 3px solid rgba(245, 166, 35, 0.65);
  outline-offset: 2px;
}
@media (max-width: 680px) {
  main {
    width: min(100% - 20px, 880px);
    padding: 10px 0;
  }
  .intro,
  form {
    padding-left: 18px;
    padding-right: 18px;
  }
  .trust-row,
  .detail-row,
  .field-grid {
    grid-template-columns: 1fr;
  }
  .trust-row,
  .detail-row {
    gap: 2px;
  }
  .actions {
    justify-content: stretch;
  }
  button {
    width: 100%;
  }
}
</style>
</head>
<body>
<main>
<section class="panel" aria-labelledby="authorize-title">
<div class="intro">
<img class="brand-lockup" src="${BRAND_LOCKUP_PATH}" alt="SecretSauce MCP">
<h1 id="authorize-title">Connect ${connectClientName} to SecretSauce</h1>
<p class="description"><strong>${sentenceClientName}</strong> is requesting access to use services configured in this gateway. Stored service credentials will not be shared with ${definiteClientName}.</p>
<div class="trust-summary" aria-label="Connection summary">
<div class="trust-row"><strong>Client</strong><span>${escapedClientName}</span></div>
<div class="trust-row"><strong>Gateway</strong><span>${escapeHtml(gateway)}</span></div>
<div class="trust-row"><strong>You will sign in to</strong><span>SecretSauce</span></div>
</div>
<div class="permissions" aria-labelledby="permissions-title">
<h2 id="permissions-title">What ${definiteClientName} will be able to do</h2>
<ul>${permissions}</ul>
</div>
<div class="info-box" role="note">The gateway authenticates ${definiteClientName}, validates each destination and request against gateway policy, and uses stored service credentials on ${possessiveClientName} behalf. Credential values are never shared with ${definiteClientName}.</div>
<details>
<summary>Connection details</summary>
<div class="connection-details" aria-label="OAuth request details">
<div class="detail-row"><strong>Client ID</strong><span>${escapeHtml(client.clientId)}</span></div>
<div class="detail-row"><strong>Redirect URI</strong><span>${escapeHtml(client.redirectUri)}</span></div>
<div class="detail-row"><strong>Resource</strong><span>${escapeHtml(client.resource)}</span></div>
<div class="detail-row"><strong>Scopes</strong><span>${escapeHtml(client.scopes.join(", "))}</span></div>
</div>
</details>
</div>
<form method="post" action="${AUTHORIZE_PATH}">
${hidden}
<div class="sign-in">
<h2>Sign in to this gateway</h2>
<p>These credentials are sent only to ${escapeHtml(gateway)} and are not shared with ${definiteClientName}.</p>
</div>
${error}
<div class="field-grid">
<label for="username">Username <input id="username" name="username" autocomplete="username" required></label>
<label for="password">Password <input id="password" name="password" type="password" autocomplete="current-password" required></label>
</div>
<div class="actions"><button type="submit">Sign in and connect</button></div>
</form>
</section>
</main>
</body>
</html>`);
}

function renderInvalidAuthorizationPage(response: ServerResponse): void {
  response.writeHead(400, AUTHORIZE_PAGE_HEADERS);
  response.end(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connection request could not be verified</title>
<link rel="icon" type="image/png" href="${BRAND_ICON_PATH}">
<style>
:root { color-scheme: light; --bg: #f5f4f1; --panel: #ffffff; --text: #111827; --muted: #2a3744; --border: #d8dde1; }
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; background: var(--bg); color: var(--text); font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.5; }
main { width: min(680px, calc(100% - 32px)); margin: 0 auto; padding: 40px 0; }
.panel { padding: 32px; border: 1px solid var(--border); border-radius: 8px; background: var(--panel); box-shadow: 0 18px 45px rgba(23, 32, 51, 0.08); }
h1 { margin: 0 0 12px; font-size: clamp(1.75rem, 4vw, 2.25rem); line-height: 1.1; }
p { margin: 0; color: var(--muted); }
.brand-lockup { display: block; width: min(320px, 78%); height: auto; margin: 0 0 24px; }
@media (max-width: 680px) { main { width: min(100% - 20px, 680px); padding: 10px 0; } .panel { padding: 24px 18px; } }
</style>
</head>
<body>
<main>
<section class="panel" aria-labelledby="error-title">
<img class="brand-lockup" src="${BRAND_LOCKUP_PATH}" alt="SecretSauce MCP">
<h1 id="error-title">Connection request could not be verified</h1>
<p>SecretSauce could not verify this client or its callback address. Return to your MCP client and try connecting again.</p>
</section>
</main>
</body>
</html>`);
}

function gatewayHost(config: GatewayConfig): string {
  if (config.auth.mode !== "builtin_oauth") throw new Error("Expected built-in OAuth config");
  return new URL(config.auth.builtinOAuth.issuer).host;
}

function permissionDescription(scope: string): string {
  if (scope === "gateway.read") return "View available services";
  if (scope === "gateway.request") return "Make requests permitted by gateway policy";
  if (scope === "gateway.references") return "Use temporary references returned by the gateway";
  return scope;
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
    renderLoginPage(config, response, body, validation, 401, "Invalid username or password.");
    return;
  }

  attemptLimiter.recordSuccess(source, account);

  const oauthState = getOAuthState(config);
  sweepAuthorizationCodes(oauthState, Date.now());
  if (oauthState.authorizationCodes.size >= config.limits.maxAuthorizationCodes) {
    response.setHeader("retry-after", "1");
    writeOAuthError(response, 429, "temporarily_unavailable");
    return;
  }

  const code = randomBytes(32).toString("base64url");
  oauthState.authorizationCodes.set(code, {
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
  const grantType = body.get("grant_type");
  if (grantType === "authorization_code") {
    await exchangeAuthorizationCode(config, body, response, logger);
    return;
  }
  if (grantType === "refresh_token") {
    await exchangeRefreshToken(config, body, response, logger);
    return;
  }
  logTokenOutcome(logger, "error", 400, "unsupported_grant_type", "unavailable", "unavailable");
  writeOAuthError(response, 400, "unsupported_grant_type");
}

async function exchangeAuthorizationCode(
  config: GatewayConfig,
  body: URLSearchParams,
  response: ServerResponse,
  logger: ReturnType<typeof createLogger>,
): Promise<void> {
  const auth = config.auth.mode === "builtin_oauth" ? config.auth.builtinOAuth : undefined;
  if (auth === undefined) throw new Error("Expected built-in OAuth config");
  const code = body.get("code") ?? "";
  const oauthState = getOAuthState(config);
  const authorizationCodes = oauthState.authorizationCodes;
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

  const now = Date.now();
  if (sweepRefreshGrants(oauthState, now)) persistRefreshStateSafely(config, oauthState);
  if (oauthState.refreshTokens.size >= config.limits.maxRefreshTokenRecords) {
    logTokenOutcome(logger, "error", 503, "temporarily_unavailable", resourceStatus(requestedResource, record.resource), record.scopes.length);
    writeOAuthError(response, 503, "temporarily_unavailable");
    return;
  }
  const accessToken = await signAccessToken(auth, record.subject, record.resource, record.scopes, now);
  const issuedRefresh = issueRefreshGrant(oauthState, auth, record, now);
  if (!persistRefreshStateForRequest(config, oauthState, logger)) {
    revokeRefreshGrant(oauthState, issuedRefresh.grantId);
    logTokenOutcome(logger, "error", 503, "temporarily_unavailable", resourceStatus(requestedResource, record.resource), record.scopes.length);
    writeOAuthError(response, 503, "temporarily_unavailable");
    return;
  }

  logTokenOutcome(logger, "success", 200, undefined, resourceStatus(requestedResource, record.resource), record.scopes.length);
  writeJson(response, 200, {
    access_token: accessToken,
    refresh_token: issuedRefresh.token,
    token_type: "Bearer",
    expires_in: Math.floor(auth.accessTokenTtlMs / 1000),
    scope: record.scopes.join(" "),
  });
}

async function exchangeRefreshToken(
  config: GatewayConfig,
  body: URLSearchParams,
  response: ServerResponse,
  logger: ReturnType<typeof createLogger>,
): Promise<void> {
  const auth = config.auth.mode === "builtin_oauth" ? config.auth.builtinOAuth : undefined;
  if (auth === undefined) throw new Error("Expected built-in OAuth config");
  const oauthState = getOAuthState(config);
  const now = Date.now();
  if (sweepRefreshGrants(oauthState, now)) persistRefreshStateSafely(config, oauthState);

  const tokenHash = hashRefreshToken(body.get("refresh_token") ?? "");
  const tokenRecord = oauthState.refreshTokens.get(tokenHash);
  const grant = tokenRecord === undefined ? undefined : oauthState.refreshGrants.get(tokenRecord.grantId);
  if (tokenRecord === undefined || grant === undefined) {
    logTokenOutcome(logger, "error", 400, "invalid_grant", "unavailable", "unavailable");
    writeOAuthError(response, 400, "invalid_grant");
    return;
  }
  if (tokenRecord.status !== "active") {
    revokeRefreshGrant(oauthState, grant.id);
    persistRefreshStateSafely(config, oauthState);
    logger.warn("oauth.refresh_token_reuse_detected", { client_status: "bound", resource_status: "bound" });
    logTokenOutcome(logger, "error", 400, "invalid_grant", "unavailable", grant.scopes.length);
    writeOAuthError(response, 400, "invalid_grant");
    return;
  }
  if (body.get("client_id") !== grant.clientId) {
    logTokenOutcome(logger, "error", 400, "invalid_grant", resourceStatus(body.get("resource"), grant.resource), grant.scopes.length);
    writeOAuthError(response, 400, "invalid_grant");
    return;
  }
  const requestedResource = body.get("resource");
  if (requestedResource !== null && requestedResource !== grant.resource) {
    logTokenOutcome(logger, "error", 400, "invalid_target", "mismatch", grant.scopes.length);
    writeOAuthError(response, 400, "invalid_target");
    return;
  }
  const scopes = scopesFromRequest(body.get("scope"), grant.scopes);
  if (scopes.some((scope) => !grant.scopes.includes(scope))) {
    logTokenOutcome(logger, "error", 400, "invalid_scope", resourceStatus(requestedResource, grant.resource), scopes.length);
    writeOAuthError(response, 400, "invalid_scope");
    return;
  }
  if (oauthState.refreshTokens.size >= config.limits.maxRefreshTokenRecords) {
    logTokenOutcome(logger, "error", 503, "temporarily_unavailable", resourceStatus(requestedResource, grant.resource), scopes.length);
    writeOAuthError(response, 503, "temporarily_unavailable");
    return;
  }

  tokenRecord.status = "rotating";
  const rotatedToken = randomBytes(32).toString("base64url");
  const rotatedHash = hashRefreshToken(rotatedToken);
  let accessToken: string;
  try {
    accessToken = await signAccessToken(auth, grant.subject, grant.resource, scopes, now);
  } catch (error) {
    if (oauthState.refreshGrants.has(grant.id) && tokenRecord.status === "rotating") tokenRecord.status = "active";
    throw error;
  }
  if (!oauthState.refreshGrants.has(grant.id) || tokenRecord.status !== "rotating") {
    logTokenOutcome(logger, "error", 400, "invalid_grant", "unavailable", scopes.length);
    writeOAuthError(response, 400, "invalid_grant");
    return;
  }
  tokenRecord.status = "used";
  oauthState.refreshTokens.set(rotatedHash, { grantId: grant.id, status: "active" });
  const previousIdleExpiresAt = grant.idleExpiresAt;
  grant.idleExpiresAt = Math.min(now + auth.refreshTokenIdleTtlMs, grant.expiresAt);
  if (!persistRefreshStateForRequest(config, oauthState, logger)) {
    oauthState.refreshTokens.delete(rotatedHash);
    tokenRecord.status = "active";
    grant.idleExpiresAt = previousIdleExpiresAt;
    logTokenOutcome(logger, "error", 503, "temporarily_unavailable", resourceStatus(requestedResource, grant.resource), scopes.length);
    writeOAuthError(response, 503, "temporarily_unavailable");
    return;
  }

  logTokenOutcome(logger, "success", 200, undefined, resourceStatus(requestedResource, grant.resource), scopes.length);
  writeJson(response, 200, {
    access_token: accessToken,
    refresh_token: rotatedToken,
    token_type: "Bearer",
    expires_in: Math.floor(auth.accessTokenTtlMs / 1000),
    scope: scopes.join(" "),
  });
}

function getOAuthState(config: GatewayConfig): BuiltinOAuthState {
  initializeBuiltinOAuthState(config);
  const state = oauthStates.get(config);
  if (state === undefined) throw new Error("Expected initialized built-in OAuth state");
  return state;
}

export function initializeBuiltinOAuthState(config: GatewayConfig): void {
  if (config.auth.mode !== "builtin_oauth" || oauthStates.has(config)) return;
  const state = config.auth.builtinOAuth.refreshTokenStoreFile === undefined
    ? emptyOAuthState()
    : loadRefreshState(config);
  oauthStates.set(config, state);
  if (config.auth.builtinOAuth.refreshTokenStoreFile === undefined) {
    createLogger(config.logging).warn("oauth.refresh_state_ephemeral", { restart_continuity: false });
  }
  registerMaintenanceTask(config, (now) => {
    sweepAuthorizationCodes(state, now);
    if (sweepRefreshGrants(state, now)) persistRefreshStateSafely(config, state);
  });
}

function emptyOAuthState(): BuiltinOAuthState {
  return { authorizationCodes: new Map(), refreshGrants: new Map(), refreshTokens: new Map() };
}

function sweepAuthorizationCodes(state: BuiltinOAuthState, now: number): void {
  for (const [code, record] of state.authorizationCodes) if (record.expiresAt <= now) state.authorizationCodes.delete(code);
}

function issueRefreshGrant(
  state: BuiltinOAuthState,
  auth: BuiltinOAuthAuthConfig["builtinOAuth"],
  authorizationCode: AuthorizationCode,
  now: number,
): { token: string; grantId: string } {
  const token = randomBytes(32).toString("base64url");
  const grantId = randomBytes(16).toString("base64url");
  const expiresAt = now + auth.refreshTokenMaxTtlMs;
  state.refreshGrants.set(grantId, {
    id: grantId,
    clientId: authorizationCode.clientId,
    resource: authorizationCode.resource,
    scopes: [...authorizationCode.scopes],
    subject: authorizationCode.subject,
    createdAt: now,
    idleExpiresAt: Math.min(now + auth.refreshTokenIdleTtlMs, expiresAt),
    expiresAt,
  });
  state.refreshTokens.set(hashRefreshToken(token), { grantId, status: "active" });
  return { token, grantId };
}

function sweepRefreshGrants(state: BuiltinOAuthState, now: number): boolean {
  let changed = false;
  for (const grant of state.refreshGrants.values()) {
    if (grant.idleExpiresAt <= now || grant.expiresAt <= now) {
      revokeRefreshGrant(state, grant.id);
      changed = true;
    }
  }
  return changed;
}

function revokeRefreshGrant(state: BuiltinOAuthState, grantId: string): void {
  state.refreshGrants.delete(grantId);
  for (const [tokenHash, record] of state.refreshTokens) {
    if (record.grantId === grantId) state.refreshTokens.delete(tokenHash);
  }
}

function hashRefreshToken(token: string): string {
  return createHash("sha256").update(token).digest("base64url");
}

function loadRefreshState(config: GatewayConfig): BuiltinOAuthState {
  if (config.auth.mode !== "builtin_oauth" || config.auth.builtinOAuth.refreshTokenStoreFile === undefined) return emptyOAuthState();
  const path = config.auth.builtinOAuth.refreshTokenStoreFile;
  let source: string;
  try {
    source = readFileSync(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      const state = emptyOAuthState();
      persistRefreshState(config, state);
      return state;
    }
    throw new Error(`Failed to read built-in OAuth refresh state: ${error instanceof Error ? error.message : String(error)}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    throw new Error("Invalid built-in OAuth refresh state: expected valid JSON");
  }
  const persisted = validatePersistedRefreshState(parsed, config.limits.maxRefreshTokenRecords);
  const state = emptyOAuthState();
  for (const grant of persisted.refreshGrants) state.refreshGrants.set(grant.id, { ...grant, scopes: [...grant.scopes] });
  for (const record of persisted.refreshTokens) state.refreshTokens.set(record.hash, { grantId: record.grantId, status: record.status });
  if (sweepRefreshGrants(state, Date.now())) persistRefreshState(config, state);
  chmodSync(path, 0o600);
  return state;
}

function validatePersistedRefreshState(value: unknown, maxRecords: number): PersistedRefreshState {
  if (!isRecord(value) || value.version !== 1 || !Array.isArray(value.refreshGrants) || !Array.isArray(value.refreshTokens)) {
    throw new Error("Invalid built-in OAuth refresh state: unsupported structure or version");
  }
  if (value.refreshTokens.length > maxRecords) throw new Error("Invalid built-in OAuth refresh state: token record capacity exceeded");
  const grants: RefreshGrant[] = [];
  const grantIds = new Set<string>();
  for (const item of value.refreshGrants) {
    if (!isRefreshGrant(item) || grantIds.has(item.id)) throw new Error("Invalid built-in OAuth refresh state: invalid or duplicate grant");
    grantIds.add(item.id);
    grants.push(item);
  }
  const tokens: PersistedRefreshState["refreshTokens"] = [];
  const hashes = new Set<string>();
  const activeCounts = new Map<string, number>();
  for (const item of value.refreshTokens) {
    if (!isPersistedRefreshToken(item) || hashes.has(item.hash) || !grantIds.has(item.grantId)) {
      throw new Error("Invalid built-in OAuth refresh state: invalid token record");
    }
    hashes.add(item.hash);
    tokens.push(item);
    if (item.status === "active") activeCounts.set(item.grantId, (activeCounts.get(item.grantId) ?? 0) + 1);
  }
  if ([...grantIds].some((id) => activeCounts.get(id) !== 1)) {
    throw new Error("Invalid built-in OAuth refresh state: each grant must have one active token");
  }
  return { version: 1, refreshGrants: grants, refreshTokens: tokens };
}

function isRefreshGrant(value: unknown): value is RefreshGrant {
  if (!isRecord(value)) return false;
  return nonEmptyString(value.id) && nonEmptyString(value.clientId) && nonEmptyString(value.resource)
    && Array.isArray(value.scopes) && value.scopes.every(nonEmptyString) && nonEmptyString(value.subject)
    && finiteTimestamp(value.createdAt) && finiteTimestamp(value.idleExpiresAt) && finiteTimestamp(value.expiresAt)
    && value.createdAt <= value.idleExpiresAt && value.idleExpiresAt <= value.expiresAt;
}

function isPersistedRefreshToken(value: unknown): value is PersistedRefreshState["refreshTokens"][number] {
  return isRecord(value) && typeof value.hash === "string" && /^[A-Za-z0-9_-]{43}$/.test(value.hash)
    && nonEmptyString(value.grantId) && (value.status === "active" || value.status === "used");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function finiteTimestamp(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function persistRefreshState(config: GatewayConfig, state: BuiltinOAuthState): void {
  if (config.auth.mode !== "builtin_oauth" || config.auth.builtinOAuth.refreshTokenStoreFile === undefined) return;
  const path = config.auth.builtinOAuth.refreshTokenStoreFile;
  const persisted: PersistedRefreshState = {
    version: 1,
    refreshGrants: [...state.refreshGrants.values()].map((grant) => ({ ...grant, scopes: [...grant.scopes] })),
    refreshTokens: [...state.refreshTokens.entries()].map(([hash, record]) => ({ hash, ...record, status: record.status === "rotating" ? "active" : record.status })),
  };
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporaryPath = `${path}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  try {
    writeFileSync(temporaryPath, `${JSON.stringify(persisted)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
    renameSync(temporaryPath, path);
  } catch (error) {
    try { unlinkSync(temporaryPath); } catch { /* no temporary file to remove */ }
    throw error;
  }
}

function persistRefreshStateSafely(config: GatewayConfig, state: BuiltinOAuthState): void {
  try {
    persistRefreshState(config, state);
  } catch (error) {
    createLogger(config.logging).error("oauth.refresh_state_write_failed", { error });
  }
}

function persistRefreshStateForRequest(
  config: GatewayConfig,
  state: BuiltinOAuthState,
  logger: ReturnType<typeof createLogger>,
): boolean {
  try {
    persistRefreshState(config, state);
    return true;
  } catch (error) {
    logger.error("oauth.refresh_state_write_failed", { error });
    return false;
  }
}

async function signAccessToken(
  auth: BuiltinOAuthAuthConfig["builtinOAuth"],
  subject: string,
  resource: string,
  scopes: string[],
  nowMs: number,
): Promise<string> {
  const now = Math.floor(nowMs / 1000);
  return new SignJWT({ scope: scopes.join(" ") })
    .setProtectedHeader({ alg: "RS256", kid: auth.signingKeyId })
    .setSubject(subject)
    .setIssuer(auth.issuer)
    .setAudience(resource)
    .setIssuedAt(now)
    .setExpirationTime(now + Math.floor(auth.accessTokenTtlMs / 1000))
    .sign(await getPrivateKey(auth.signingPrivateKeyPem));
}

async function validateAuthorizationRequest(
  config: GatewayConfig,
  body: URLSearchParams,
): Promise<
  | { ok: true; clientId: string; clientName: string | null; redirectUri: string; resource: string; scopes: string[]; codeChallenge: string }
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
  const clientMetadata = await fetchVerifiedClientMetadata(clientId);
  if (clientMetadata === undefined || !clientMetadata.redirectUris.includes(redirectUri)) {
    return { ok: false, error: "invalid_request" };
  }

  const codeChallenge = body.get("code_challenge");
  if (!codeChallenge) return { ok: false, error: "invalid_request" };

  const scopes = scopesFromRequest(body.get("scope"), auth.requiredScopes);
  if (scopes.some((scope) => !auth.requiredScopes.includes(scope))) return { ok: false, error: "invalid_scope" };

  return { ok: true, clientId, clientName: clientMetadata.clientName, redirectUri, resource, scopes, codeChallenge };
}

async function fetchVerifiedClientMetadata(clientId: string): Promise<VerifiedClientMetadata | undefined> {
  try {
    const response = await fetch(clientId, { signal: AbortSignal.timeout(5000) });
    if (!response.ok) return undefined;
    const metadata = await response.json() as unknown;
    if (typeof metadata !== "object" || metadata === null || Array.isArray(metadata)) return undefined;
    const record = metadata as Record<string, unknown>;
    if (record.client_id !== clientId || !Array.isArray(record.redirect_uris)) return undefined;
    const redirectUris = record.redirect_uris.filter((value): value is string => typeof value === "string");
    const rawClientName = record.client_name;
    const trimmedClientName = typeof rawClientName === "string" ? rawClientName.trim() : "";
    const clientName = trimmedClientName !== "" && [...trimmedClientName].length <= MAX_CLIENT_NAME_LENGTH
      ? trimmedClientName
      : null;
    return { clientId, redirectUris, clientName };
  } catch {
    return undefined;
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
