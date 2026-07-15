import { createRemoteJWKSet, importSPKI, jwtVerify, type JWTPayload, type JWTVerifyGetKey, type JWTVerifyOptions } from "jose";
import { timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";
import { GatewayError } from "./errors.js";
import type { AuthContext, GatewayConfig } from "./types.js";

const jwksCache = new Map<string, JWTVerifyGetKey>();
const publicKeyCache = new Map<string, ReturnType<typeof importSPKI>>();

export async function authenticateRequest(
  request: IncomingMessage,
  config: GatewayConfig,
  requiredScopes: string[] = [],
): Promise<AuthContext> {
  const bearer = extractBearerToken(request);
  if (bearer === undefined) {
    throw new GatewayError("unauthenticated", "Missing bearer token.");
  }

  if (config.auth.mode === "bearer") {
    if (!safeEqual(bearer, config.auth.bearer.token)) {
      throw new GatewayError("unauthenticated", "Invalid bearer token.");
    }
    const sessionId = readHeader(request, "mcp-session-id");
    return {
      subject: "bearer-dev",
      scopes: requiredScopes,
      mode: "bearer",
      ...(sessionId === undefined ? {} : { sessionId }),
    };
  }

  if (config.auth.mode === "builtin_oauth") {
    const builtin = config.auth.builtinOAuth;
    let payload: JWTPayload;
    try {
      const verified = await jwtVerify(bearer, await getPublicKey(builtin.signingPublicKeyPem), {
        issuer: builtin.issuer,
        audience: config.server.resource ?? builtin.issuer,
      });
      payload = verified.payload;
    } catch {
      throw new GatewayError("unauthenticated", "Invalid OAuth access token.");
    }

    const scopes = extractScopes(payload);
    const missing = requiredScopes.filter((scope) => !scopes.includes(scope));
    if (missing.length > 0) {
      throw new GatewayError("unauthenticated", "OAuth token does not include required scopes.");
    }

    const sessionId = readHeader(request, "mcp-session-id");
    return {
      subject: subjectFromPayload(payload),
      scopes,
      mode: "builtin_oauth",
      ...(sessionId === undefined ? {} : { sessionId }),
    };
  }

  const oauth = config.auth.oauth;
  const jwksUri = oauth.jwksUri ?? `${oauth.issuer.replace(/\/$/, "")}/.well-known/jwks.json`;
  const jwks = getJwks(jwksUri);
  let payload: JWTPayload;
  try {
    const audience = oauth.audience ?? oauth.resource;
    const verifyOptions: JWTVerifyOptions = {
      issuer: oauth.issuer,
      ...(audience === undefined ? {} : { audience }),
    };
    const verified = await jwtVerify(bearer, jwks, {
      ...verifyOptions,
    });
    payload = verified.payload;
  } catch {
    throw new GatewayError("unauthenticated", "Invalid OAuth access token.");
  }

  const scopes = extractScopes(payload);
  const missing = requiredScopes.filter((scope) => !scopes.includes(scope));
  if (missing.length > 0) {
    throw new GatewayError("unauthenticated", "OAuth token does not include required scopes.");
  }

  const sessionId = readHeader(request, "mcp-session-id");
  return {
    subject: subjectFromPayload(payload),
    scopes,
    mode: "oauth",
    ...(sessionId === undefined ? {} : { sessionId }),
  };
}

export function requireScopes(auth: AuthContext, requiredScopes: string[]): void {
  if (auth.mode === "bearer") return;
  const missing = requiredScopes.filter((scope) => !auth.scopes.includes(scope));
  if (missing.length > 0) {
    throw new GatewayError("unauthenticated", "OAuth token does not include required scopes.");
  }
}

export function buildAuthenticateChallenge(config: GatewayConfig, request: IncomingMessage, requiredScopes: string[] = []): string {
  const metadataUrl = protectedResourceMetadataUrl(config, request);
  const scope = requiredScopes.length > 0 ? `, scope="${requiredScopes.join(" ")}"` : "";
  return `Bearer resource_metadata="${metadataUrl}"${scope}`;
}

export function protectedResourceMetadata(config: GatewayConfig, request: IncomingMessage): Record<string, unknown> {
  const resource = config.server.resource ?? requestOrigin(request);
  const scopes = config.auth.mode === "oauth"
    ? config.auth.oauth.requiredScopes
    : config.auth.mode === "builtin_oauth"
      ? config.auth.builtinOAuth.requiredScopes
      : ["gateway.read", "gateway.tokens", "gateway.request"];
  const authorizationServers = config.auth.mode === "oauth"
    ? [config.auth.oauth.issuer]
    : config.auth.mode === "builtin_oauth"
      ? [config.auth.builtinOAuth.issuer]
      : [];
  return {
    resource,
    authorization_servers: authorizationServers,
    scopes_supported: scopes,
    resource_documentation: `${resource.replace(/\/$/, "")}/docs`,
  };
}

function protectedResourceMetadataUrl(config: GatewayConfig, request: IncomingMessage): string {
  return `${config.server.resource ?? requestOrigin(request)}/.well-known/oauth-protected-resource`;
}

function requestOrigin(request: IncomingMessage): string {
  const host = request.headers.host ?? "localhost";
  return `http://${host}`;
}

function extractBearerToken(request: IncomingMessage): string | undefined {
  const authorization = readHeader(request, "authorization");
  const match = /^Bearer\s+(.+)$/i.exec(authorization ?? "");
  return match?.[1];
}

function readHeader(request: IncomingMessage, name: string): string | undefined {
  const value = request.headers[name];
  if (Array.isArray(value)) return value[0];
  return value;
}

function safeEqual(actual: string, expected: string): boolean {
  const actualBuffer = Buffer.from(actual);
  const expectedBuffer = Buffer.from(expected);
  if (actualBuffer.length !== expectedBuffer.length) return false;
  return timingSafeEqual(actualBuffer, expectedBuffer);
}

function getJwks(jwksUri: string): JWTVerifyGetKey {
  const cached = jwksCache.get(jwksUri);
  if (cached !== undefined) return cached;
  const jwks = createRemoteJWKSet(new URL(jwksUri));
  jwksCache.set(jwksUri, jwks);
  return jwks;
}

function getPublicKey(publicKeyPem: string): ReturnType<typeof importSPKI> {
  const cached = publicKeyCache.get(publicKeyPem);
  if (cached !== undefined) return cached;
  const key = importSPKI(publicKeyPem, "RS256");
  publicKeyCache.set(publicKeyPem, key);
  return key;
}

function extractScopes(payload: JWTPayload): string[] {
  const scope = payload.scope;
  if (typeof scope === "string") return scope.split(/\s+/).filter(Boolean);
  const scp = payload.scp;
  if (Array.isArray(scp)) return scp.filter((value): value is string => typeof value === "string");
  return [];
}

function subjectFromPayload(payload: JWTPayload): string {
  if (payload.sub) return payload.sub;
  const clientId = payload.client_id;
  if (typeof clientId === "string") return clientId;
  return "unknown";
}
