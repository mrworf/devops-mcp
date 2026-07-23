import { createHash, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";
import { z } from "zod";
import { configError, configValidationError, type ConfigPath } from "./errors.js";
import type {
  AccessConfig,
  AuditConfig,
  AuthConfig,
  CredentialConfig,
  CredentialSourceConfig,
  ConfigDebugDiagnostic,
  DestinationConfig,
  GatewayConfig,
  HostMatcherConfig,
  LimitsConfig,
  LoggingConfig,
  PolicyConfig,
  PolicyRuleConfig,
  ServiceConfig,
  ServerConfig,
  TlsConfig,
  TokenConfig,
} from "./types.js";
import { SECRET_RULE_IDS } from "./secretlintConfig.js";
import { loadYamlConfig, validationDiagnostics } from "./yamlConfig.js";

const durationPattern = /^(\d+)(ms|s|m|h|d)$/;
const sizePattern = /^(\d+)(b|kb|mb)$/i;
const broadHostRegexes = new Set([".*", "^.*$", ".*internal.*"]);

const hostMatcherSchema = z.union([
  z.object({ exact: z.string().min(1) }).strict(),
  z.object({ suffix: z.string().min(1) }).strict(),
  z.object({ regex: z.string().min(1) }).strict(),
]);

const credentialSourceSchema = z.union([
  z.object({ kind: z.literal("env"), name: z.string().min(1) }).strict(),
  z.object({ kind: z.literal("file"), path: z.string().min(1) }).strict(),
]);

const credentialUsageSchema = z.object({
  kind: z.string().min(1),
  name: z.string().min(1).optional(),
  prefix: z.string().optional(),
  suffix: z.string().optional(),
  enforce: z.boolean().default(false),
}).strict().superRefine((usage, context) => {
  for (const field of ["prefix", "suffix"] as const) {
    if (usage[field] !== undefined && /[\r\n\0]/.test(usage[field])) {
      context.addIssue({ code: "custom", path: [field], message: `${field} must not contain CR, LF, or NUL` });
    }
  }
  if (usage.suffix !== undefined && usage.suffix.length > 0 && /^[A-Za-z0-9_-]/.test(usage.suffix)) {
    context.addIssue({
      code: "custom", path: ["suffix"],
      message: "suffix must begin with a delimiter outside the opaque-reference alphabet",
    });
  }
  if (usage.enforce && (usage.kind.toLowerCase() !== "header" || usage.name === undefined)) {
    context.addIssue({ code: "custom", path: ["enforce"], message: "enforce requires usage.kind header and a header name" });
  }
});

const serviceSchema = z.object({
  type: z.literal("http").default("http"),
  name: z.string().min(1),
  description: z.string().optional(),
  api_docs_url: z.string().url().optional(),
  destinations: z.array(z.object({
    id: z.string().min(1).optional(),
    name: z.string().min(1).optional(),
    base_url: z.string().url(),
    schemes: z.array(z.string().min(1)).optional(),
    hosts: z.array(hostMatcherSchema).optional(),
    ports: z.array(z.number().int().min(1).max(65535)).optional(),
    tls: z.object({ verify: z.boolean().default(true) }).optional(),
  }).strict()).min(1),
  tls: z.object({ verify: z.boolean().default(true) }).default({ verify: true }),
  no_auth: z.boolean().default(false),
  credentials: z.array(z.object({
    id: z.string().min(1),
    usage: credentialUsageSchema,
    source: credentialSourceSchema,
  }).strict()).default([]),
  access: z.object({
    users: z.array(z.string().min(1)).default([]),
  }).default({ users: [] }),
  policy: z.object({
    mode: z.enum(["allow", "deny"]).default("deny"),
    rules: z.array(z.object({
      id: z.string().min(1),
      effect: z.enum(["allow", "deny"]),
      priority: z.number().int(),
      methods: z.array(z.string().min(1)).default([]),
      hosts: z.array(z.string().min(1)).default([]),
      paths: z.array(z.string().min(1)).default([]),
      reason: z.string().optional(),
      secretlint: z.union([
        z.object({ enabled: z.literal(false) }).strict(),
        z.object({ disabled_rules: z.array(z.enum(SECRET_RULE_IDS)).min(1) }).strict(),
      ]).optional(),
      binary_response: z.object({
        scan: z.boolean().default(true),
        max_size: z.string().min(1).default("100kb"),
      }).strict().optional(),
    }).strict()).default([]),
  }).default({ mode: "deny", rules: [] }),
}).strict().superRefine((service, context) => {
  if (service.no_auth && service.credentials.length > 0) {
    context.addIssue({ code: "custom", path: ["credentials"], message: "credentials must be empty when no_auth is true" });
  }
  if (!service.no_auth && service.credentials.length === 0) {
    context.addIssue({ code: "custom", path: ["credentials"], message: "at least one credential is required unless no_auth is true" });
  }
});

const rawConfigSchema = z.object({
  server: z.object({
    listen: z.string().default("0.0.0.0:8080"),
    mcp_path: z.string().default("/mcp"),
    resource: z.string().url().optional(),
    allow_insecure_oauth_http: z.boolean().default(false),
  }).default({ listen: "0.0.0.0:8080", mcp_path: "/mcp", allow_insecure_oauth_http: false }),
  auth: z.discriminatedUnion("mode", [
    z.object({
      mode: z.literal("oauth").default("oauth"),
      oauth: z.object({
        issuer: z.string().url(),
        audience: z.string().min(1).optional(),
        resource: z.string().url().optional(),
        jwks_uri: z.string().url().optional(),
        required_scopes: z.array(z.string().min(1)).default([]),
        principal_claim: z.string().trim().min(1).default("sub"),
      }).strict(),
    }).strict(),
    z.object({
      mode: z.literal("builtin_oauth"),
      builtin_oauth: z.object({
        issuer: z.string().url(),
        admin_username_env: z.string().min(1),
        admin_password_hash_env: z.string().min(1).optional(),
        admin_password_hash_file: z.string().min(1).optional(),
        signing_key_file: z.string().min(1),
        access_token_ttl: z.string().default("1h"),
        authorization_code_ttl: z.string().default("5m"),
        refresh_token_idle_ttl: z.string().default("30d"),
        refresh_token_max_ttl: z.string().default("90d"),
        refresh_token_store_file: z.string().min(1).optional(),
        allowed_clients: z.array(z.string().min(1)).min(1),
        required_scopes: z.array(z.string().min(1)).default(["gateway.read", "gateway.references", "gateway.request"]),
        login_rate_limit: z.object({
          window: z.string().default("15m"),
          per_source: z.number().int().positive().default(10),
          per_account: z.number().int().positive().default(10),
          global: z.number().int().positive().default(100),
          initial_lockout: z.string().default("15m"),
          max_lockout: z.string().default("1h"),
          max_entries: z.number().int().positive().default(1000),
        }).default({
          window: "15m", per_source: 10, per_account: 10, global: 100,
          initial_lockout: "15m", max_lockout: "1h", max_entries: 1000,
        }),
      }).strict(),
    }).strict(),
    z.object({
      mode: z.literal("bearer"),
      bearer: z.object({
        token_env: z.string().min(1).optional(),
        token_file: z.string().min(1).optional(),
      }).strict(),
    }).strict(),
  ]),
  tokens: z.object({
    idle_ttl: z.string().default("10m"),
    max_ttl: z.string().default("1h"),
  }).default({ idle_ttl: "10m", max_ttl: "1h" }),
  limits: z.object({
    max_inbound_body: z.string().default("1mb"),
    inbound_body_timeout: z.string().default("10s"),
    max_unauthenticated_inflight: z.number().int().positive().default(32),
    max_unauthenticated_inflight_per_source: z.number().int().positive().default(4),
    max_password_verifications: z.number().int().positive().default(2),
    max_password_verifications_per_source: z.number().int().positive().default(1),
    max_denial_records: z.number().int().positive().default(1000),
    denial_ttl: z.string().default("15m"),
    state_sweep_interval: z.string().default("1m"),
    max_token_records: z.number().int().positive().default(10000),
    max_token_records_per_subject: z.number().int().positive().default(1000),
    max_authorization_codes: z.number().int().positive().default(1000),
    max_refresh_token_records: z.number().int().positive().default(10000),
    max_oauth_client_metadata_inflight: z.number().int().positive().default(4),
    max_oauth_client_metadata_inflight_per_origin: z.number().int().positive().default(2),
    max_service_requests_inflight: z.number().int().positive().default(32),
    max_service_requests_inflight_per_subject: z.number().int().positive().default(4),
    max_request_body: z.string().default("1mb"),
    max_response_body: z.string().default("5mb"),
    timeout: z.string().default("30s"),
  }).default({
    max_inbound_body: "1mb", inbound_body_timeout: "10s",
    max_unauthenticated_inflight: 32, max_unauthenticated_inflight_per_source: 4,
    max_password_verifications: 2, max_password_verifications_per_source: 1,
    max_denial_records: 1000, denial_ttl: "15m", state_sweep_interval: "1m",
    max_token_records: 10000, max_token_records_per_subject: 1000,
    max_authorization_codes: 1000, max_refresh_token_records: 10000,
    max_oauth_client_metadata_inflight: 4, max_oauth_client_metadata_inflight_per_origin: 2,
    max_service_requests_inflight: 32, max_service_requests_inflight_per_subject: 4,
    max_request_body: "1mb", max_response_body: "5mb", timeout: "30s",
  }),
  logging: z.object({
    level: z.enum(["info", "debug"]).default("info"),
  }).default({ level: "info" }),
  audit: z.object({
    file: z.string().min(1).optional(),
    memory_events: z.number().int().positive().default(1000),
  }).default({ memory_events: 1000 }),
  services: z.record(z.string().min(1), serviceSchema)
    .refine((services) => Object.keys(services).length > 0, "at least one service is required"),
}).strict();

type RawConfig = z.infer<typeof rawConfigSchema>;
type RawService = RawConfig["services"][string];
type RawDestination = RawService["destinations"][number];

export function loadConfig(path: string): GatewayConfig {
  return loadYamlConfig(path, "config", (raw) => validateConfig(raw));
}

export function validateConfig(raw: unknown, env: NodeJS.ProcessEnv = process.env): GatewayConfig {
  const warnings: string[] = [];
  const debugDiagnostics: ConfigDebugDiagnostic[] = [];
  const parsed = parseRawConfig(raw);
  validateOAuthTrustUrls(parsed, warnings);
  const server = normalizeServer(parsed.server);
  const auth = normalizeAuth(parsed.auth, env);
  const tokens = normalizeTokens(parsed.tokens);
  const limits = normalizeLimits(parsed.limits);
  const logging: LoggingConfig = { level: parsed.logging.level };
  const audit: AuditConfig = {
    memoryEvents: parsed.audit.memory_events,
    ...(parsed.audit.file === undefined ? {} : { file: parsed.audit.file }),
  };
  appendPublicOAuthWarnings(server, auth, warnings);
  const services = normalizeServices(parsed.services, env, warnings, debugDiagnostics);

  return { server, auth, tokens, limits, logging, audit, services, warnings, debugDiagnostics };
}

function parseRawConfig(raw: unknown): RawConfig {
  rejectRemovedMcpTransportLimits(raw);
  const result = rawConfigSchema.safeParse(raw);
  if (!result.success) {
    const diagnostics = validationDiagnostics(result.error.issues);
    throw configError(`Invalid config: ${diagnostics.map((issue) => issue.detail).join("; ")}`, diagnostics);
  }
  return result.data;
}

function validateOAuthTrustUrls(raw: RawConfig, warnings: string[]): void {
  const insecurePaths: ConfigPath[] = [];
  if (raw.server.resource !== undefined) {
    validateOAuthTrustUrl(raw.server.resource, ["server", "resource"]);
    if (isNonLoopbackHttpUrl(raw.server.resource)) insecurePaths.push(["server", "resource"]);
  }
  if (raw.auth.mode === "oauth") {
    validateOAuthTrustUrl(raw.auth.oauth.issuer, ["auth", "oauth", "issuer"]);
    if (isNonLoopbackHttpUrl(raw.auth.oauth.issuer)) insecurePaths.push(["auth", "oauth", "issuer"]);
    if (raw.auth.oauth.jwks_uri !== undefined) {
      validateOAuthTrustUrl(raw.auth.oauth.jwks_uri, ["auth", "oauth", "jwks_uri"]);
      if (isNonLoopbackHttpUrl(raw.auth.oauth.jwks_uri)) insecurePaths.push(["auth", "oauth", "jwks_uri"]);
    } else {
      const effectiveJwksUrl = `${raw.auth.oauth.issuer.replace(/\/$/, "")}/.well-known/jwks.json`;
      if (isNonLoopbackHttpUrl(effectiveJwksUrl)) insecurePaths.push(["auth", "oauth", "issuer"]);
    }
  } else if (raw.auth.mode === "builtin_oauth") {
    validateOAuthTrustUrl(raw.auth.builtin_oauth.issuer, ["auth", "builtin_oauth", "issuer"]);
    if (isNonLoopbackHttpUrl(raw.auth.builtin_oauth.issuer)) insecurePaths.push(["auth", "builtin_oauth", "issuer"]);
  }
  if (insecurePaths.length === 0) return;
  const firstPath = insecurePaths[0] ?? ["server", "resource"];
  if (!raw.server.allow_insecure_oauth_http) {
    throw configValidationError(
      `${firstPath.join(".")} must use HTTPS for non-loopback OAuth trust; set server.allow_insecure_oauth_http only when explicitly accepting trusted-network development risk`,
      firstPath,
    );
  }
  warnings.push("server.allow_insecure_oauth_http permits non-loopback cleartext OAuth trust URLs; use only on an explicitly trusted development network.");
}

function validateOAuthTrustUrl(value: string, path: ConfigPath): void {
  const url = new URL(value);
  if (url.username.length > 0 || url.password.length > 0) {
    throw configValidationError(`${path.join(".")} must not include URL userinfo`, path);
  }
  if (url.hash.length > 0) {
    throw configValidationError(`${path.join(".")} must not include a URL fragment`, path);
  }
}

function rejectRemovedMcpTransportLimits(raw: unknown): void {
  if (!raw || typeof raw !== "object") return;
  const limits = (raw as { limits?: unknown }).limits;
  if (!limits || typeof limits !== "object") return;
  const removed = [
    "max_mcp_transports",
    "max_mcp_transports_per_subject",
    "max_mcp_initializations_per_subject",
    "mcp_initialization_window",
    "max_mcp_initialization_records",
    "mcp_transport_idle_ttl",
  ].filter((name) => Object.prototype.hasOwnProperty.call(limits, name));
  if (removed.length > 0) {
    throw configValidationError(
      `Removed stateful MCP limits: ${removed.join(", ")}. MCP transport is now stateless; remove these fields.`,
      ["limits", removed[0] ?? "max_mcp_transports"],
    );
  }
}

function normalizeServer(raw: RawConfig["server"]): ServerConfig {
  if (!raw.mcp_path.startsWith("/")) {
    throw configValidationError("server.mcp_path must start with /", ["server", "mcp_path"]);
  }

  const lastColon = raw.listen.lastIndexOf(":");
  if (lastColon <= 0) {
    throw configValidationError("server.listen must use host:port format", ["server", "listen"]);
  }
  const host = raw.listen.slice(0, lastColon);
  const portText = raw.listen.slice(lastColon + 1);
  const port = Number(portText);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw configValidationError("server.listen port must be between 1 and 65535", ["server", "listen"]);
  }

  const base = {
    listen: raw.listen,
    host,
    port,
    mcpPath: raw.mcp_path,
    allowInsecureOAuthHttp: raw.allow_insecure_oauth_http,
  };
  return raw.resource === undefined ? base : { ...base, resource: raw.resource };
}

function normalizeAuth(raw: RawConfig["auth"], env: NodeJS.ProcessEnv): AuthConfig {
  if (raw.mode === "oauth") {
    if (!raw.oauth.audience && !raw.oauth.resource) {
      throw configValidationError("auth.oauth must include audience or resource", ["auth", "oauth"]);
    }
    return {
      mode: "oauth",
      oauth: {
        issuer: raw.oauth.issuer,
        ...(raw.oauth.audience === undefined ? {} : { audience: raw.oauth.audience }),
        ...(raw.oauth.resource === undefined ? {} : { resource: raw.oauth.resource }),
        ...(raw.oauth.jwks_uri === undefined ? {} : { jwksUri: raw.oauth.jwks_uri }),
        requiredScopes: raw.oauth.required_scopes,
        principalClaim: raw.oauth.principal_claim,
      },
    };
  }

  if (raw.mode === "builtin_oauth") {
    const username = env[raw.builtin_oauth.admin_username_env];
    if (!username) throw configValidationError(
      `Missing built-in OAuth admin username environment variable: ${raw.builtin_oauth.admin_username_env}`,
      ["auth", "builtin_oauth", "admin_username_env"],
    );

    const hashEnv = raw.builtin_oauth.admin_password_hash_env;
    const hashFile = raw.builtin_oauth.admin_password_hash_file;
    if ((hashEnv === undefined && hashFile === undefined) || (hashEnv !== undefined && hashFile !== undefined)) {
      throw configValidationError(
        "auth.builtin_oauth must include exactly one of admin_password_hash_env or admin_password_hash_file",
        ["auth", "builtin_oauth"],
      );
    }
    const adminPasswordHash = hashEnv === undefined
      ? readSecretFile(hashFile, ["auth", "builtin_oauth", "admin_password_hash_file"])
      : env[hashEnv];
    if (!adminPasswordHash) throw configValidationError(
      `Missing built-in OAuth admin password hash environment variable: ${hashEnv}`,
      ["auth", "builtin_oauth", "admin_password_hash_env"],
    );

    const signingPrivateKeyPem = readSecretFile(raw.builtin_oauth.signing_key_file, ["auth", "builtin_oauth", "signing_key_file"]);
    let signingPublicKeyPem: string;
    try {
      signingPublicKeyPem = createPublicKey(signingPrivateKeyPem).export({ type: "spki", format: "pem" }).toString();
    } catch {
      throw configValidationError(
        "auth.builtin_oauth.signing_key_file must contain a valid private key",
        ["auth", "builtin_oauth", "signing_key_file"],
      );
    }

    const accessTokenTtlMs = parseDuration(raw.builtin_oauth.access_token_ttl, "auth.builtin_oauth.access_token_ttl");
    const authorizationCodeTtlMs = parseDuration(raw.builtin_oauth.authorization_code_ttl, "auth.builtin_oauth.authorization_code_ttl");
    const refreshTokenIdleTtlMs = parseDuration(raw.builtin_oauth.refresh_token_idle_ttl, "auth.builtin_oauth.refresh_token_idle_ttl");
    const refreshTokenMaxTtlMs = parseDuration(raw.builtin_oauth.refresh_token_max_ttl, "auth.builtin_oauth.refresh_token_max_ttl");
    if (accessTokenTtlMs <= 0 || authorizationCodeTtlMs <= 0 || refreshTokenIdleTtlMs <= 0 || refreshTokenMaxTtlMs <= 0) {
      throw configValidationError("auth.builtin_oauth token TTL values must be positive", ["auth", "builtin_oauth", "access_token_ttl"]);
    }
    if (refreshTokenIdleTtlMs > refreshTokenMaxTtlMs) {
      throw configValidationError(
        "auth.builtin_oauth.refresh_token_idle_ttl must not exceed refresh_token_max_ttl",
        ["auth", "builtin_oauth", "refresh_token_idle_ttl"],
      );
    }

    return {
      mode: "builtin_oauth",
      builtinOAuth: {
        issuer: raw.builtin_oauth.issuer.replace(/\/$/, ""),
        adminUsername: username,
        adminPasswordHash,
        signingPrivateKeyPem,
        signingPublicKeyPem,
        signingKeyId: keyIdForPublicKey(signingPublicKeyPem),
        accessTokenTtlMs,
        authorizationCodeTtlMs,
        refreshTokenIdleTtlMs,
        refreshTokenMaxTtlMs,
        ...(raw.builtin_oauth.refresh_token_store_file === undefined ? {} : { refreshTokenStoreFile: raw.builtin_oauth.refresh_token_store_file }),
        allowedClients: raw.builtin_oauth.allowed_clients,
        requiredScopes: raw.builtin_oauth.required_scopes,
        loginRateLimit: normalizeLoginRateLimit(raw.builtin_oauth.login_rate_limit),
      },
    };
  }

  const tokenEnv = raw.bearer.token_env;
  const tokenFile = raw.bearer.token_file;
  if ((tokenEnv === undefined && tokenFile === undefined) || (tokenEnv !== undefined && tokenFile !== undefined)) {
    throw configValidationError("auth.bearer must include exactly one of token_env or token_file", ["auth", "bearer"]);
  }
  if (tokenEnv !== undefined) {
    const token = env[tokenEnv];
    if (!token) throw configValidationError(`Missing bearer token environment variable: ${tokenEnv}`, ["auth", "bearer", "token_env"]);
    return { mode: "bearer", bearer: { token, source: "env" } };
  }

  return { mode: "bearer", bearer: { token: readSecretFile(tokenFile, ["auth", "bearer", "token_file"]), source: "file" } };
}

function appendPublicOAuthWarnings(server: ServerConfig, auth: AuthConfig, warnings: string[]): void {
  if (auth.mode !== "bearer" && server.resource === undefined) {
    warnings.push("server.resource is missing in OAuth mode; configure the public HTTPS origin explicitly when using a reverse proxy.");
  }
}

function isNonLoopbackHttpUrl(value: string): boolean {
  const url = new URL(value);
  return url.protocol === "http:" && !isLoopbackHost(url.hostname);
}

function isLoopbackHost(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (normalized === "localhost" || normalized === "::1") return true;
  if (isIP(normalized) !== 4) return false;
  return normalized.split(".")[0] === "127";
}

function normalizeLoginRateLimit(raw: {
  window: string; per_source: number; per_account: number; global: number;
  initial_lockout: string; max_lockout: string; max_entries: number;
}) {
  const windowMs = parseDuration(raw.window, "auth.builtin_oauth.login_rate_limit.window");
  const initialLockoutMs = parseDuration(raw.initial_lockout, "auth.builtin_oauth.login_rate_limit.initial_lockout");
  const maxLockoutMs = parseDuration(raw.max_lockout, "auth.builtin_oauth.login_rate_limit.max_lockout");
  if (windowMs <= 0 || initialLockoutMs <= 0 || maxLockoutMs < initialLockoutMs) {
    throw configValidationError(
      "auth.builtin_oauth.login_rate_limit durations must be positive and max_lockout must not be shorter than initial_lockout",
      ["auth", "builtin_oauth", "login_rate_limit", "max_lockout"],
    );
  }
  return {
    windowMs, perSource: raw.per_source, perAccount: raw.per_account, global: raw.global,
    initialLockoutMs, maxLockoutMs, maxEntries: raw.max_entries,
  };
}

function keyIdForPublicKey(publicKeyPem: string): string {
  return createHash("sha256").update(publicKeyPem).digest("base64url").slice(0, 16);
}

function normalizeTokens(raw: RawConfig["tokens"]): TokenConfig {
  const idleTtlMs = parseDuration(raw.idle_ttl, "tokens.idle_ttl");
  const maxTtlMs = parseDuration(raw.max_ttl, "tokens.max_ttl");
  if (idleTtlMs <= 0 || maxTtlMs <= 0) throw configValidationError("token TTL values must be positive", ["tokens", "idle_ttl"]);
  if (idleTtlMs > maxTtlMs) throw configValidationError("tokens.idle_ttl must not exceed tokens.max_ttl", ["tokens", "idle_ttl"]);
  return { idleTtlMs, maxTtlMs };
}

function normalizeLimits(raw: RawConfig["limits"]): LimitsConfig {
  const maxInboundBodyBytes = parseSize(raw.max_inbound_body, "limits.max_inbound_body");
  const inboundBodyTimeoutMs = parseDuration(raw.inbound_body_timeout, "limits.inbound_body_timeout");
  const maxRequestBodyBytes = parseSize(raw.max_request_body, "limits.max_request_body");
  const maxResponseBodyBytes = parseSize(raw.max_response_body, "limits.max_response_body");
  const timeoutMs = parseDuration(raw.timeout, "limits.timeout");
  const denialTtlMs = parseDuration(raw.denial_ttl, "limits.denial_ttl");
  const stateSweepIntervalMs = parseDuration(raw.state_sweep_interval, "limits.state_sweep_interval");
  if (maxInboundBodyBytes <= 0 || inboundBodyTimeoutMs <= 0 || maxRequestBodyBytes <= 0 || maxResponseBodyBytes <= 0 || timeoutMs <= 0 || denialTtlMs <= 0 || stateSweepIntervalMs <= 0) {
    throw configValidationError("limits values must be positive", ["limits"]);
  }
  if (raw.max_unauthenticated_inflight_per_source > raw.max_unauthenticated_inflight) {
    throw configValidationError("limits.max_unauthenticated_inflight_per_source must not exceed limits.max_unauthenticated_inflight", ["limits", "max_unauthenticated_inflight_per_source"]);
  }
  if (raw.max_password_verifications_per_source > raw.max_password_verifications) {
    throw configValidationError("limits.max_password_verifications_per_source must not exceed limits.max_password_verifications", ["limits", "max_password_verifications_per_source"]);
  }
  if (raw.max_token_records_per_subject > raw.max_token_records) {
    throw configValidationError("limits.max_token_records_per_subject must not exceed limits.max_token_records", ["limits", "max_token_records_per_subject"]);
  }
  if (raw.max_oauth_client_metadata_inflight_per_origin > raw.max_oauth_client_metadata_inflight) {
    throw configValidationError("limits.max_oauth_client_metadata_inflight_per_origin must not exceed limits.max_oauth_client_metadata_inflight", ["limits", "max_oauth_client_metadata_inflight_per_origin"]);
  }
  if (raw.max_service_requests_inflight_per_subject > raw.max_service_requests_inflight) {
    throw configValidationError("limits.max_service_requests_inflight_per_subject must not exceed limits.max_service_requests_inflight", ["limits", "max_service_requests_inflight_per_subject"]);
  }
  return {
    maxInboundBodyBytes,
    inboundBodyTimeoutMs,
    maxUnauthenticatedInflight: raw.max_unauthenticated_inflight,
    maxUnauthenticatedInflightPerSource: raw.max_unauthenticated_inflight_per_source,
    maxPasswordVerifications: raw.max_password_verifications,
    maxPasswordVerificationsPerSource: raw.max_password_verifications_per_source,
    maxDenialRecords: raw.max_denial_records,
    denialTtlMs,
    stateSweepIntervalMs,
    maxTokenRecords: raw.max_token_records,
    maxTokenRecordsPerSubject: raw.max_token_records_per_subject,
    maxAuthorizationCodes: raw.max_authorization_codes,
    maxRefreshTokenRecords: raw.max_refresh_token_records,
    maxOAuthClientMetadataInflight: raw.max_oauth_client_metadata_inflight,
    maxOAuthClientMetadataInflightPerOrigin: raw.max_oauth_client_metadata_inflight_per_origin,
    maxServiceRequestsInflight: raw.max_service_requests_inflight,
    maxServiceRequestsInflightPerSubject: raw.max_service_requests_inflight_per_subject,
    maxRequestBodyBytes,
    maxResponseBodyBytes,
    timeoutMs,
  };
}

function normalizeServices(
  rawServices: RawConfig["services"],
  env: NodeJS.ProcessEnv,
  warnings: string[],
  debugDiagnostics: ConfigDebugDiagnostic[],
): Record<string, ServiceConfig> {
  return Object.fromEntries(Object.entries(rawServices).map(([id, raw]) => {
    const servicePath: ConfigPath = ["services", id];
    const tls = normalizeTls(raw.tls);
    const destinations = normalizeDestinations(raw.destinations, tls, warnings, servicePath);
    const credentials = normalizeCredentials(raw.credentials, env, servicePath, id, debugDiagnostics);
    const access: AccessConfig = { users: raw.access.users };
    const policy = normalizePolicy(raw.policy, servicePath);

    return [id, {
      id,
      type: "http" as const,
      name: raw.name,
      ...(raw.description === undefined ? {} : { description: raw.description }),
      ...(raw.api_docs_url === undefined ? {} : { apiDocsUrl: raw.api_docs_url }),
      destinations,
      tls,
      credentials,
      access,
      policy,
    }];
  }));
}

function normalizeDestinations(
  rawDestinations: RawDestination[],
  serviceTls: TlsConfig,
  warnings: string[],
  servicePath: ConfigPath,
): DestinationConfig[] {
  const seen = new Set<string>();
  return rawDestinations.map((raw, index) => {
    const destinationPath = [...servicePath, "destinations", index];
    const id = raw.id ?? raw.name;
    if (!id) throw configValidationError("destination must include id or name", destinationPath);
    ensureUnique(seen, id, "destination", [...destinationPath, raw.id === undefined ? "name" : "id"]);

    const base = new URL(raw.base_url);
    const schemes = raw.schemes ?? [base.protocol.replace(/:$/, "")];
    const hosts = normalizeHosts(raw.hosts, base.hostname, warnings, [...destinationPath, "hosts"]);
    const ports = raw.ports ?? [Number(base.port || defaultPortForScheme(base.protocol, [...destinationPath, "base_url"]))];
    const tls = raw.tls === undefined ? serviceTls : normalizeTls(raw.tls);

    return { id, baseUrl: raw.base_url, schemes, hosts, ports, tls };
  });
}

function normalizeHosts(
  rawHosts: RawDestination["hosts"],
  baseHost: string,
  warnings: string[],
  hostsPath: ConfigPath,
): HostMatcherConfig[] {
  const hosts = rawHosts ?? [{ exact: baseHost }];
  return hosts.map((matcher, index) => {
    if ("exact" in matcher) return { type: "exact", value: normalizeHost(matcher.exact) };
    if ("suffix" in matcher) return { type: "suffix", value: normalizeHostSuffix(matcher.suffix, [...hostsPath, index, "suffix"]) };

    validateRegex(matcher.regex, "host regex", [...hostsPath, index, "regex"]);
    if (broadHostRegexes.has(matcher.regex)) {
      warnings.push(`Broad host regex warning: ${matcher.regex}`);
    }
    return { type: "regex", value: matcher.regex, regex: new RegExp(matcher.regex) };
  });
}

function normalizeHostSuffix(raw: string, path: ConfigPath): string {
  const withoutLeadingDot = raw.startsWith(".") ? raw.slice(1) : raw;
  const withoutTrailingDot = withoutLeadingDot.endsWith(".") ? withoutLeadingDot.slice(0, -1) : withoutLeadingDot;
  const ascii = domainToASCII(withoutTrailingDot);
  if (
    ascii === ""
    || ascii.startsWith(".")
    || ascii.endsWith(".")
    || ascii.split(".").some((label) => label === "")
    || isIP(ascii) !== 0
  ) {
    throw configValidationError("destination host suffix must be a valid DNS name, not an IP address", path);
  }
  return normalizeHost(ascii);
}

function normalizeCredentials(
  rawCredentials: RawService["credentials"],
  env: NodeJS.ProcessEnv,
  servicePath: ConfigPath,
  serviceId: string,
  debugDiagnostics: ConfigDebugDiagnostic[],
): CredentialConfig[] {
  const seen = new Set<string>();
  return rawCredentials.map((raw, index) => {
    const credentialPath = [...servicePath, "credentials", index];
    ensureUnique(seen, raw.id, "credential", [...credentialPath, "id"]);
    const source = normalizeSource(raw.source);
    const secret = resolveSecret(source, env, [...credentialPath, "source"]);
    if (/\s/.test(secret)) {
      debugDiagnostics.push({ code: "credential_source_contains_whitespace", serviceId, credentialId: raw.id });
    }
    const credential: CredentialConfig = {
      id: raw.id,
      usage: {
        kind: raw.usage.kind,
        ...(raw.usage.name === undefined ? {} : { name: raw.usage.name }),
        ...(raw.usage.prefix === undefined ? {} : { prefix: raw.usage.prefix }),
        ...(raw.usage.suffix === undefined ? {} : { suffix: raw.usage.suffix }),
        enforce: raw.usage.enforce,
      },
      source,
      secret,
    };
    return credential;
  });
}

function normalizeSource(source: z.infer<typeof credentialSourceSchema>): CredentialSourceConfig {
  return source.kind === "env" ? { kind: "env", name: source.name } : { kind: "file", path: source.path };
}

function resolveSecret(source: CredentialSourceConfig, env: NodeJS.ProcessEnv, sourcePath: ConfigPath): string {
  if (source.kind === "env") {
    const value = env[source.name];
    if (!value) throw configValidationError(`Missing credential environment variable: ${source.name}`, [...sourcePath, "name"]);
    return value;
  }
  return readSecretFile(source.path, [...sourcePath, "path"]);
}

function readSecretFile(path: string | undefined, configPath: ConfigPath): string {
  if (!path) throw configValidationError("secret file path is required", configPath);
  try {
    const value = readFileSync(path, "utf8").trim();
    if (!value) throw configValidationError(`Secret file is empty: ${path}`, configPath);
    return value;
  } catch (error) {
    if (error instanceof Error && error.name === "GatewayError") throw error;
    throw configValidationError(`Unable to read secret file: ${path}`, configPath);
  }
}

function normalizePolicy(raw: RawService["policy"], servicePath: ConfigPath): PolicyConfig {
  const seen = new Set<string>();
  const rules = raw.rules.map((rule, index) => {
    const rulePath = [...servicePath, "policy", "rules", index];
    ensureUnique(seen, rule.id, "policy rule", [...rulePath, "id"]);
    rule.paths.forEach((path, pathIndex) => validateRegex(path, "policy path regex", [...rulePath, "paths", pathIndex]));
    rule.hosts.forEach((host, hostIndex) => validateRegex(host, "policy host regex", [...rulePath, "hosts", hostIndex]));
    const normalized: PolicyRuleConfig = {
      id: rule.id,
      effect: rule.effect,
      priority: rule.priority,
      methods: rule.methods.map((method) => method.toUpperCase()),
      hosts: rule.hosts,
      paths: rule.paths,
      binaryResponse: {
        scan: rule.binary_response?.scan ?? true,
        maxBytes: rule.binary_response?.max_size === "unlimited"
          ? null
          : parseSize(
            rule.binary_response?.max_size ?? "100kb",
            "binary_response.max_size",
            [...rulePath, "binary_response", "max_size"],
          ),
      },
      ...(rule.secretlint === undefined ? {} : {
        secretlint: "enabled" in rule.secretlint
          ? { enabled: false as const }
          : { disabledRuleIds: rule.secretlint.disabled_rules },
      }),
    };
    return rule.reason === undefined ? normalized : { ...normalized, reason: rule.reason };
  });
  return { mode: raw.mode, rules };
}

function normalizeTls(raw: { verify?: boolean }): TlsConfig {
  return { verify: raw.verify ?? true };
}

function ensureUnique(seen: Set<string>, id: string, label: string, path: ConfigPath): void {
  if (seen.has(id)) throw configValidationError(`Duplicate ${label} id`, path);
  seen.add(id);
}

function validateRegex(pattern: string, label: string, path: ConfigPath): void {
  try {
    new RegExp(pattern);
  } catch {
    throw configValidationError(`Invalid ${label}`, path);
  }
}

function normalizeHost(host: string): string {
  return host.toLowerCase().replace(/\.$/, "");
}

function defaultPortForScheme(protocol: string, path: ConfigPath): string {
  if (protocol === "https:") return "443";
  if (protocol === "http:") return "80";
  throw configValidationError("Unsupported URL scheme", path);
}

function parseDuration(value: string, label: string): number {
  const match = durationPattern.exec(value);
  if (!match) throw configValidationError(`${label} must be a duration like 500ms, 30s, 10m, 1h, or 1d`, label.split("."));
  const amount = Number(match[1] ?? 0);
  if (amount === 0) throw configValidationError(`${label} must be positive`, label.split("."));
  const unit = match[2] ?? "";
  const multipliers: Record<string, number> = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };
  const multiplier = multipliers[unit];
  if (multiplier === undefined) throw configValidationError(`${label} has unsupported duration unit`, label.split("."));
  return amount * multiplier;
}

function parseSize(value: string, label: string, path: ConfigPath = label.split(".")): number {
  const match = sizePattern.exec(value);
  if (!match) throw configValidationError(`${label} must be a size like 512b, 128kb, or 1mb`, path);
  const amount = Number(match[1] ?? 0);
  if (amount === 0) throw configValidationError(`${label} must be positive`, path);
  const unit = (match[2] ?? "").toLowerCase();
  const multipliers: Record<string, number> = { b: 1, kb: 1024, mb: 1024 * 1024 };
  const multiplier = multipliers[unit];
  if (multiplier === undefined) throw configValidationError(`${label} has unsupported size unit`, path);
  return amount * multiplier;
}
