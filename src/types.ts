export interface GatewayConfig {
  server: ServerConfig;
  auth: AuthConfig;
  tokens: TokenConfig;
  limits: LimitsConfig;
  logging: LoggingConfig;
  audit: AuditConfig;
  services: Record<string, ServiceConfig>;
  warnings: string[];
}

export interface ServerConfig {
  listen: string;
  host: string;
  port: number;
  mcpPath: string;
  resource?: string;
}

export type AuthConfig = OAuthAuthConfig | BuiltinOAuthAuthConfig | BearerAuthConfig;

export interface AuthContext {
  subject: string;
  sessionId?: string;
  scopes: string[];
  mode: AuthConfig["mode"];
}

export interface OAuthAuthConfig {
  mode: "oauth";
  oauth: {
    issuer: string;
    audience?: string;
    resource?: string;
    jwksUri?: string;
    requiredScopes: string[];
    principalClaim: string;
  };
}

export interface BuiltinOAuthAuthConfig {
  mode: "builtin_oauth";
  builtinOAuth: {
    issuer: string;
    adminUsername: string;
    adminPasswordHash: string;
    signingPrivateKeyPem: string;
    signingPublicKeyPem: string;
    signingKeyId: string;
    accessTokenTtlMs: number;
    authorizationCodeTtlMs: number;
    refreshTokenIdleTtlMs: number;
    refreshTokenMaxTtlMs: number;
    refreshTokenStoreFile?: string;
    allowedClients: string[];
    requiredScopes: string[];
    loginRateLimit: LoginRateLimitConfig;
  };
}

export interface LoginRateLimitConfig {
  windowMs: number;
  perSource: number;
  perAccount: number;
  global: number;
  initialLockoutMs: number;
  maxLockoutMs: number;
  maxEntries: number;
}

export interface BearerAuthConfig {
  mode: "bearer";
  bearer: {
    token: string;
    source: "env" | "file";
  };
}

export interface TokenConfig {
  idleTtlMs: number;
  maxTtlMs: number;
}

export interface LimitsConfig {
  maxInboundBodyBytes: number;
  inboundBodyTimeoutMs: number;
  maxUnauthenticatedInflight: number;
  maxUnauthenticatedInflightPerSource: number;
  maxPasswordVerifications: number;
  maxPasswordVerificationsPerSource: number;
  maxDenialRecords: number;
  denialTtlMs: number;
  stateSweepIntervalMs: number;
  maxTokenRecords: number;
  maxTokenRecordsPerSubject: number;
  maxAuthorizationCodes: number;
  maxRefreshTokenRecords: number;
  maxMcpTransports: number;
  mcpTransportIdleTtlMs: number;
  maxRequestBodyBytes: number;
  maxResponseBodyBytes: number;
  timeoutMs: number;
}

export interface LoggingConfig {
  level: "info" | "debug";
}

export interface AuditConfig {
  file?: string;
  memoryEvents: number;
}

export interface ServiceConfig {
  id: string;
  type: "http";
  name: string;
  description?: string;
  apiDocsUrl?: string;
  destinations: DestinationConfig[];
  tls: TlsConfig;
  credentials: CredentialConfig[];
  access: AccessConfig;
  policy: PolicyConfig;
}

export interface DestinationConfig {
  id: string;
  baseUrl: string;
  schemes: string[];
  hosts: HostMatcherConfig[];
  ports: number[];
  tls: TlsConfig;
}

export type HostMatcherConfig =
  | { type: "exact"; value: string }
  | { type: "suffix"; value: string }
  | { type: "regex"; value: string; regex: RegExp };

export interface TlsConfig {
  verify: boolean;
}

export interface CredentialConfig {
  id: string;
  usage: CredentialUsageConfig;
  source: CredentialSourceConfig;
  secret: string;
}

export interface CredentialUsageConfig {
  kind: string;
  name?: string;
}

export type CredentialSourceConfig =
  | { kind: "env"; name: string }
  | { kind: "file"; path: string };

export interface AccessConfig {
  users: string[];
}

export interface PolicyConfig {
  mode: "allow" | "deny";
  rules: PolicyRuleConfig[];
}

export interface PolicyRuleConfig {
  id: string;
  effect: "allow" | "deny";
  priority: number;
  methods: string[];
  hosts: string[];
  paths: string[];
  reason?: string;
  secretlint?: { enabled: false } | { disabledRuleIds: string[] };
}
