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
  PolicyConfig,
  PolicyRuleConfig,
  ServiceConfig,
  ServerConfig,
  TlsConfig,
  TokenConfig,
} from "./types.js";

const durationPattern = /^(\d+)(ms|s|m|h)$/;
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
    max_request_body: z.string().default("1mb"),
    max_response_body: z.string().default("5mb"),
    timeout: z.string().default("30s"),
  }).default({ max_request_body: "1mb", max_response_body: "5mb", timeout: "30s" }),
  audit: z.object({
    file: z.string().min(1).optional(),
  }).default({}),
  services: z.record(z.string().min(1), z.object({
    type: z.literal("http").default("http"),
    name: z.string().min(1),
    description: z.string().optional(),
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
  const audit: AuditConfig = parsed.audit.file === undefined ? {} : { file: parsed.audit.file };
  const services = normalizeServices(parsed.services, env, warnings);

  return { server, auth, tokens, limits, audit, services, warnings };
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

function normalizeTokens(raw: RawConfig["tokens"]): TokenConfig {
  const idleTtlMs = parseDuration(raw.idle_ttl, "tokens.idle_ttl");
  const maxTtlMs = parseDuration(raw.max_ttl, "tokens.max_ttl");
  if (idleTtlMs <= 0 || maxTtlMs <= 0) throw configError("token TTL values must be positive");
  if (idleTtlMs > maxTtlMs) throw configError("tokens.idle_ttl must not exceed tokens.max_ttl");
  return { idleTtlMs, maxTtlMs };
}

function normalizeLimits(raw: RawConfig["limits"]): LimitsConfig {
  const maxRequestBodyBytes = parseSize(raw.max_request_body, "limits.max_request_body");
  const maxResponseBodyBytes = parseSize(raw.max_response_body, "limits.max_response_body");
  const timeoutMs = parseDuration(raw.timeout, "limits.timeout");
  if (maxRequestBodyBytes <= 0 || maxResponseBodyBytes <= 0 || timeoutMs <= 0) {
    throw configError("limits values must be positive");
  }
  return { maxRequestBodyBytes, maxResponseBodyBytes, timeoutMs };
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
  if (!match) throw configError(`${label} must be a duration like 500ms, 30s, 10m, or 1h`);
  const amount = Number(match[1] ?? 0);
  const unit = match[2] ?? "";
  const multipliers: Record<string, number> = { ms: 1, s: 1000, m: 60_000, h: 3_600_000 };
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
