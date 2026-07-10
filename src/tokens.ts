import { createHash, randomBytes, randomUUID } from "node:crypto";
import { GatewayError } from "./errors.js";
import { getCredential, getService } from "./registry.js";
import type { TokenIssuedAuditEvent } from "./audit.js";
import { tokenIssuedAuditEvent } from "./audit.js";
import type { AuthContext, GatewayConfig } from "./types.js";

export interface TokenRequestInput {
  service: string;
  destination?: string;
  credential_ids: string[];
  reason: string;
}

export interface TokenIssueResult {
  tokens: Array<{
    credential_id: string;
    token: string;
    usage_hint: string;
    expires_at: string;
  }>;
  audit: TokenIssuedAuditEvent;
}

export interface TokenUseTarget {
  service: string;
  destination?: string;
}

export interface TokenRecord {
  id: string;
  tokenHash: string;
  subject: string;
  sessionId?: string;
  service: string;
  destination: string;
  credentialId: string;
  reason: string;
  issuedAt: number;
  lastUsedAt: number;
  idleExpiresAt: number;
  maxExpiresAt: number;
}

export class TokenBroker {
  private readonly recordsByHash = new Map<string, TokenRecord>();
  readonly auditEvents: TokenIssuedAuditEvent[] = [];

  constructor(
    private readonly config: GatewayConfig,
    private readonly now: () => number = () => Date.now(),
  ) {}

  issueTokens(auth: AuthContext, input: TokenRequestInput): TokenIssueResult {
    if (!input.reason.trim()) {
      throw new GatewayError("token_invalid", "Token request reason is required.");
    }
    if (input.credential_ids.length === 0) {
      throw new GatewayError("unknown_credential", "At least one credential id is required.");
    }

    const service = getService(this.config, input.service, auth);
    const destination = resolveTokenDestination(service.destinations.map((item) => item.id), input.destination);
    const now = this.now();
    const issued: TokenIssueResult["tokens"] = [];
    const internalTokenIds: string[] = [];

    for (const credentialId of input.credential_ids) {
      const credential = getCredential(service, credentialId);
      const token = generateTokenValue();
      const id = `tokrec_${randomUUID()}`;
      const record: TokenRecord = {
        id,
        tokenHash: hashToken(token),
        subject: auth.subject,
        ...(auth.sessionId === undefined ? {} : { sessionId: auth.sessionId }),
        service: service.id,
        destination,
        credentialId,
        reason: input.reason,
        issuedAt: now,
        lastUsedAt: now,
        idleExpiresAt: now + this.config.tokens.idleTtlMs,
        maxExpiresAt: now + this.config.tokens.maxTtlMs,
      };
      this.recordsByHash.set(record.tokenHash, record);
      internalTokenIds.push(id);
      issued.push({
        credential_id: credentialId,
        token,
        usage_hint: usageHint(credential.usage.kind, credential.usage.name),
        expires_at: new Date(record.maxExpiresAt).toISOString(),
      });
    }

    const audit = tokenIssuedAuditEvent({
      type: "token_issued",
      subject: auth.subject,
      ...(auth.sessionId === undefined ? {} : { session_id: auth.sessionId }),
      service: service.id,
      destination,
      credential_ids: [...input.credential_ids],
      internal_token_ids: internalTokenIds,
      reason: input.reason,
      timestamp: new Date(now).toISOString(),
    });
    this.auditEvents.push(audit);
    return { tokens: issued, audit };
  }

  validateTokenUse(auth: AuthContext, target: TokenUseTarget, tokenValue: string): TokenRecord {
    const hash = hashToken(tokenValue);
    const record = this.recordsByHash.get(hash);
    if (!record) throw new GatewayError("token_invalid", "Unknown opaque token.");

    const now = this.now();
    if (record.idleExpiresAt <= now || record.maxExpiresAt <= now) {
      this.recordsByHash.delete(hash);
      throw new GatewayError("token_expired", "Opaque token has expired.");
    }
    if (record.subject !== auth.subject) throw new GatewayError("token_invalid", "Opaque token is not bound to this subject.");
    if (record.sessionId !== undefined && record.sessionId !== auth.sessionId) {
      throw new GatewayError("token_invalid", "Opaque token is not bound to this session.");
    }
    if (record.service !== target.service) throw new GatewayError("token_invalid", "Opaque token is not bound to this service.");
    if (target.destination !== undefined && record.destination !== target.destination) {
      throw new GatewayError("token_invalid", "Opaque token is not bound to this destination.");
    }

    record.lastUsedAt = now;
    record.idleExpiresAt = Math.min(now + this.config.tokens.idleTtlMs, record.maxExpiresAt);
    return record;
  }
}

export const defaultTokenBrokers = new WeakMap<GatewayConfig, TokenBroker>();

export function getTokenBroker(config: GatewayConfig): TokenBroker {
  const existing = defaultTokenBrokers.get(config);
  if (existing !== undefined) return existing;
  const broker = new TokenBroker(config);
  defaultTokenBrokers.set(config, broker);
  return broker;
}

function resolveTokenDestination(destinationIds: string[], requested: string | undefined): string {
  if (requested !== undefined) {
    if (!destinationIds.includes(requested)) throw new GatewayError("unknown_destination", `Unknown destination: ${requested}`);
    return requested;
  }
  if (destinationIds.length === 1) return destinationIds[0] as string;
  throw new GatewayError("unknown_destination", "destination is required when a service has multiple destinations");
}

function generateTokenValue(): string {
  return `tok_${randomBytes(24).toString("base64url")}`;
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("base64url");
}

function usageHint(kind: string, name?: string): string {
  if (name) return `Use as ${name} ${kind}`;
  return `Use as ${kind}`;
}
