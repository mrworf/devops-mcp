import { createHash, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { configError } from "./errors.js";
import type {
  AccessConfig,
  AuditConfig,
  AuthConfig,
  CredentialConfig,
  CredentialSourceConfig,
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

const rawConfigSchema = z.object({
  server: z.object({
    listen: z.string().default("0.0.0.0:8080"),
    mcp_path: z.string().default("/mcp"),
    resource: z.string().url().optional(),
  }).default({ listen: "0.0.0.0:8080", mcp_path: "/mcp" }),
  auth: z.union([
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
    max_mcp_transports: z.number().int().positive().default(1000),
    mcp_transport_idle_ttl: z.string().default("30m"),
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
    max_mcp_transports: 1000, mcp_transport_idle_ttl: "30m",
    max_request_body: "1mb", max_response_body: "5mb", timeout: "30s",
  }),
  logging: z.object({
    level: z.enum(["info", "debug"]).default("info"),
  }).default({ level: "info" }),
  audit: z.object({
    file: z.string().min(1).optional(),
    memory_events: z.number().int().positive().default(1000),
  }).default({ memory_events: 1000 }),
  services: z.record(z.string().min(1), z.object({
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
    credentials: z.array(z.object({
      id: z.string().min(1),
      usage: z.object({
        kind: z.string().min(1),
        name: z.string().min(1).optional(),
      }).strict(),
      source: credentialSourceSchema,
    }).strict()).min(1),
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
      }).strict()).default([]),
    }).default({ mode: "deny", rules: [] }),
  }).strict()).refine((services) => Object.keys(services).length > 0, "at least one service is required"),
}).strict();

type RawConfig = z.infer<typeof rawConfigSchema>;
type RawService = RawConfig["services"][string];
type RawDestination = RawService["destinations"][number];

export function loadConfig(path: string): GatewayConfig {
  let raw: unknown;
  try {
    raw = parseYaml(readFileSync(path, "utf8"));
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw configError(`Failed to read or parse config: ${detail}`);
  }
  return validateConfig(raw);
}

export function validateConfig(raw: unknown, env: NodeJS.ProcessEnv = process.env): GatewayConfig {
  const warnings: string[] = [];
  const parsed = parseRawConfig(raw);
  const server = normalizeServer(parsed.server);
  const auth = normalizeAuth(parsed.auth, env);
  const tokens = normalizeTokens(parsed.tokens);
  const limits = normalizeLimits(parsed.limits);
  const logging: LoggingConfig = { level: parsed.logging.level };
  const audit: AuditConfig = {
    memoryEvents: parsed.audit.memory_events,
    ...(parsed.audit.file === undefined ? {} : { file: parsed.audit.file }),
  };
  const services = normalizeServices(parsed.services, env, warnings);

  return { server, auth, tokens, limits, logging, audit, services, warnings };
}

function parseRawConfig(raw: unknown): RawConfig {
  const result = rawConfigSchema.safeParse(raw);
  if (!result.success) {
    throw configError(`Invalid config: ${result.error.issues.map((issue) => issue.message).join("; ")}`);
  }
  return result.data;
}

function normalizeServer(raw: RawConfig["server"]): ServerConfig {
  if (!raw.mcp_path.startsWith("/")) {
    throw configError("server.mcp_path must start with /");
  }

  const lastColon = raw.listen.lastIndexOf(":");
  if (lastColon <= 0) {
    throw configError("server.listen must use host:port format");
  }
  const host = raw.listen.slice(0, lastColon);
  const portText = raw.listen.slice(lastColon + 1);
  const port = Number(portText);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw configError("server.listen port must be between 1 and 65535");
  }

  const base = {
    listen: raw.listen,
    host,
    port,
    mcpPath: raw.mcp_path,
  };
  return raw.resource === undefined ? base : { ...base, resource: raw.resource };
}

function normalizeAuth(raw: RawConfig["auth"], env: NodeJS.ProcessEnv): AuthConfig {
  if (raw.mode === "oauth") {
    if (!raw.oauth.audience && !raw.oauth.resource) {
      throw configError("auth.oauth must include audience or resource");
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
    if (!username) throw configError(`Missing built-in OAuth admin username environment variable: ${raw.builtin_oauth.admin_username_env}`);

    const hashEnv = raw.builtin_oauth.admin_password_hash_env;
    const hashFile = raw.builtin_oauth.admin_password_hash_file;
    if ((hashEnv === undefined && hashFile === undefined) || (hashEnv !== undefined && hashFile !== undefined)) {
      throw configError("auth.builtin_oauth must include exactly one of admin_password_hash_env or admin_password_hash_file");
    }
    const adminPasswordHash = hashEnv === undefined ? readSecretFile(hashFile) : env[hashEnv];
    if (!adminPasswordHash) throw configError(`Missing built-in OAuth admin password hash environment variable: ${hashEnv}`);

    const signingPrivateKeyPem = readSecretFile(raw.builtin_oauth.signing_key_file);
    let signingPublicKeyPem: string;
    try {
      signingPublicKeyPem = createPublicKey(signingPrivateKeyPem).export({ type: "spki", format: "pem" }).toString();
    } catch {
      throw configError("auth.builtin_oauth.signing_key_file must contain a valid private key");
    }

    const accessTokenTtlMs = parseDuration(raw.builtin_oauth.access_token_ttl, "auth.builtin_oauth.access_token_ttl");
    const authorizationCodeTtlMs = parseDuration(raw.builtin_oauth.authorization_code_ttl, "auth.builtin_oauth.authorization_code_ttl");
    const refreshTokenIdleTtlMs = parseDuration(raw.builtin_oauth.refresh_token_idle_ttl, "auth.builtin_oauth.refresh_token_idle_ttl");
    const refreshTokenMaxTtlMs = parseDuration(raw.builtin_oauth.refresh_token_max_ttl, "auth.builtin_oauth.refresh_token_max_ttl");
    if (accessTokenTtlMs <= 0 || authorizationCodeTtlMs <= 0 || refreshTokenIdleTtlMs <= 0 || refreshTokenMaxTtlMs <= 0) {
      throw configError("auth.builtin_oauth token TTL values must be positive");
    }
    if (refreshTokenIdleTtlMs > refreshTokenMaxTtlMs) {
      throw configError("auth.builtin_oauth.refresh_token_idle_ttl must not exceed refresh_token_max_ttl");
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
    throw configError("auth.bearer must include exactly one of token_env or token_file");
  }
  if (tokenEnv !== undefined) {
    const token = env[tokenEnv];
    if (!token) throw configError(`Missing bearer token environment variable: ${tokenEnv}`);
    return { mode: "bearer", bearer: { token, source: "env" } };
  }

  return { mode: "bearer", bearer: { token: readSecretFile(tokenFile), source: "file" } };
}

function normalizeLoginRateLimit(raw: {
  window: string; per_source: number; per_account: number; global: number;
  initial_lockout: string; max_lockout: string; max_entries: number;
}) {
  const windowMs = parseDuration(raw.window, "auth.builtin_oauth.login_rate_limit.window");
  const initialLockoutMs = parseDuration(raw.initial_lockout, "auth.builtin_oauth.login_rate_limit.initial_lockout");
  const maxLockoutMs = parseDuration(raw.max_lockout, "auth.builtin_oauth.login_rate_limit.max_lockout");
  if (windowMs <= 0 || initialLockoutMs <= 0 || maxLockoutMs < initialLockoutMs) {
    throw configError("auth.builtin_oauth.login_rate_limit durations must be positive and max_lockout must not be shorter than initial_lockout");
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
  if (idleTtlMs <= 0 || maxTtlMs <= 0) throw configError("token TTL values must be positive");
  if (idleTtlMs > maxTtlMs) throw configError("tokens.idle_ttl must not exceed tokens.max_ttl");
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
  const mcpTransportIdleTtlMs = parseDuration(raw.mcp_transport_idle_ttl, "limits.mcp_transport_idle_ttl");
  if (maxInboundBodyBytes <= 0 || inboundBodyTimeoutMs <= 0 || maxRequestBodyBytes <= 0 || maxResponseBodyBytes <= 0 || timeoutMs <= 0 || denialTtlMs <= 0 || stateSweepIntervalMs <= 0 || mcpTransportIdleTtlMs <= 0) {
    throw configError("limits values must be positive");
  }
  if (raw.max_unauthenticated_inflight_per_source > raw.max_unauthenticated_inflight) {
    throw configError("limits.max_unauthenticated_inflight_per_source must not exceed limits.max_unauthenticated_inflight");
  }
  if (raw.max_password_verifications_per_source > raw.max_password_verifications) {
    throw configError("limits.max_password_verifications_per_source must not exceed limits.max_password_verifications");
  }
  if (raw.max_token_records_per_subject > raw.max_token_records) {
    throw configError("limits.max_token_records_per_subject must not exceed limits.max_token_records");
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
    maxMcpTransports: raw.max_mcp_transports,
    mcpTransportIdleTtlMs,
    maxRequestBodyBytes,
    maxResponseBodyBytes,
    timeoutMs,
  };
}

function normalizeServices(
  rawServices: RawConfig["services"],
  env: NodeJS.ProcessEnv,
  warnings: string[],
): Record<string, ServiceConfig> {
  return Object.fromEntries(Object.entries(rawServices).map(([id, raw]) => {
    const tls = normalizeTls(raw.tls);
    const destinations = normalizeDestinations(raw.destinations, tls, warnings);
    const credentials = normalizeCredentials(raw.credentials, env);
    const access: AccessConfig = { users: raw.access.users };
    const policy = normalizePolicy(raw.policy);

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

function normalizeDestinations(rawDestinations: RawDestination[], serviceTls: TlsConfig, warnings: string[]): DestinationConfig[] {
  const seen = new Set<string>();
  return rawDestinations.map((raw) => {
    const id = raw.id ?? raw.name;
    if (!id) throw configError("destination must include id or name");
    ensureUnique(seen, id, "destination");

    const base = new URL(raw.base_url);
    const schemes = raw.schemes ?? [base.protocol.replace(/:$/, "")];
    const hosts = normalizeHosts(raw.hosts, base.hostname, warnings);
    const ports = raw.ports ?? [Number(base.port || defaultPortForScheme(base.protocol))];
    const tls = raw.tls === undefined ? serviceTls : normalizeTls(raw.tls);

    return { id, baseUrl: raw.base_url, schemes, hosts, ports, tls };
  });
}

function normalizeHosts(rawHosts: RawDestination["hosts"], baseHost: string, warnings: string[]): HostMatcherConfig[] {
  const hosts = rawHosts ?? [{ exact: baseHost }];
  return hosts.map((matcher) => {
    if ("exact" in matcher) return { type: "exact", value: normalizeHost(matcher.exact) };
    if ("suffix" in matcher) return { type: "suffix", value: normalizeHost(matcher.suffix) };

    validateRegex(matcher.regex, "host regex");
    if (broadHostRegexes.has(matcher.regex)) {
      warnings.push(`Broad host regex warning: ${matcher.regex}`);
    }
    return { type: "regex", value: matcher.regex, regex: new RegExp(matcher.regex) };
  });
}

function normalizeCredentials(rawCredentials: RawService["credentials"], env: NodeJS.ProcessEnv): CredentialConfig[] {
  const seen = new Set<string>();
  return rawCredentials.map((raw) => {
    ensureUnique(seen, raw.id, "credential");
    const source = normalizeSource(raw.source);
    const secret = resolveSecret(source, env);
    const credential: CredentialConfig = {
      id: raw.id,
      usage: raw.usage.name === undefined ? { kind: raw.usage.kind } : { kind: raw.usage.kind, name: raw.usage.name },
      source,
      secret,
    };
    return credential;
  });
}

function normalizeSource(source: z.infer<typeof credentialSourceSchema>): CredentialSourceConfig {
  return source.kind === "env" ? { kind: "env", name: source.name } : { kind: "file", path: source.path };
}

function resolveSecret(source: CredentialSourceConfig, env: NodeJS.ProcessEnv): string {
  if (source.kind === "env") {
    const value = env[source.name];
    if (!value) throw configError(`Missing credential environment variable: ${source.name}`);
    return value;
  }
  return readSecretFile(source.path);
}

function readSecretFile(path: string | undefined): string {
  if (!path) throw configError("secret file path is required");
  try {
    const value = readFileSync(path, "utf8").trim();
    if (!value) throw configError(`Secret file is empty: ${path}`);
    return value;
  } catch (error) {
    if (error instanceof Error && error.name === "GatewayError") throw error;
    throw configError(`Unable to read secret file: ${path}`);
  }
}

function normalizePolicy(raw: RawService["policy"]): PolicyConfig {
  const seen = new Set<string>();
  const rules = raw.rules.map((rule) => {
    ensureUnique(seen, rule.id, "policy rule");
    rule.paths.forEach((path) => validateRegex(path, "policy path regex"));
    rule.hosts.forEach((host) => validateRegex(host, "policy host regex"));
    const normalized: PolicyRuleConfig = {
      id: rule.id,
      effect: rule.effect,
      priority: rule.priority,
      methods: rule.methods.map((method) => method.toUpperCase()),
      hosts: rule.hosts,
      paths: rule.paths,
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

function ensureUnique(seen: Set<string>, id: string, label: string): void {
  if (seen.has(id)) throw configError(`Duplicate ${label} id: ${id}`);
  seen.add(id);
}

function validateRegex(pattern: string, label: string): void {
  try {
    new RegExp(pattern);
  } catch {
    throw configError(`Invalid ${label}: ${pattern}`);
  }
}

function normalizeHost(host: string): string {
  return host.toLowerCase().replace(/\.$/, "");
}

function defaultPortForScheme(protocol: string): string {
  if (protocol === "https:") return "443";
  if (protocol === "http:") return "80";
  throw configError(`Unsupported URL scheme: ${protocol.replace(/:$/, "")}`);
}

function parseDuration(value: string, label: string): number {
  const match = durationPattern.exec(value);
  if (!match) throw configError(`${label} must be a duration like 500ms, 30s, 10m, 1h, or 1d`);
  const amount = Number(match[1] ?? 0);
  const unit = match[2] ?? "";
  const multipliers: Record<string, number> = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };
  const multiplier = multipliers[unit];
  if (multiplier === undefined) throw configError(`${label} has unsupported duration unit`);
  return amount * multiplier;
}

function parseSize(value: string, label: string): number {
  const match = sizePattern.exec(value);
  if (!match) throw configError(`${label} must be a size like 512b, 128kb, or 1mb`);
  const amount = Number(match[1] ?? 0);
  const unit = (match[2] ?? "").toLowerCase();
  const multipliers: Record<string, number> = { b: 1, kb: 1024, mb: 1024 * 1024 };
  const multiplier = multipliers[unit];
  if (multiplier === undefined) throw configError(`${label} has unsupported size unit`);
  return amount * multiplier;
}
