import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { GatewayError } from "./errors.js";
import { getCredential, getService } from "./registry.js";
import type { TokenIssuedAuditEvent } from "./audit.js";
import { tokenIssuedAuditEvent } from "./audit.js";
import type { AuthContext, GatewayConfig } from "./types.js";
import { registerMaintenanceTask } from "./maintenance.js";

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
  service: string;
  destination: string;
  credentialId: string;
  reason: string;
  issuedAt: number;
  lastUsedAt: number;
  idleExpiresAt: number;
  maxExpiresAt: number;
}

export interface ResponseSecretTokenRecord {
  id: string;
  tokenHash: string;
  subject: string;
  service: string;
  secret: string;
  issuedAt: number;
  lastUsedAt: number;
  idleExpiresAt: number;
  maxExpiresAt: number;
}

export interface ResponseSecretIssueResult {
  token: string;
  record: ResponseSecretTokenRecord;
  reused: boolean;
}

export interface ConfiguredTokenMatch {
  token: string;
  record: TokenRecord;
}

export type TokenInspectionReason = "unknown" | "expired" | "wrong_subject" | "wrong_service";
export type TokenInspection = { valid: true } | { valid: false; reason: TokenInspectionReason };

export class TokenBroker {
  private readonly recordsByHash = new Map<string, TokenRecord>();
  private readonly responseSecretsByHash = new Map<string, ResponseSecretTokenRecord>();
  private readonly responseSecretIdsByIndex = new Map<string, string>();
  private readonly responseSecretsById = new Map<string, ResponseSecretTokenRecord>();
  private readonly tokenValuesById = new Map<string, string>();
  private readonly secretIndexKey = randomBytes(32);

  constructor(
    private readonly config: GatewayConfig,
    private readonly now: () => number = () => Date.now(),
  ) {}

  issueTokens(auth: AuthContext, input: TokenRequestInput): TokenIssueResult {
    this.sweepExpired();
    if (!input.reason.trim()) {
      throw new GatewayError("token_invalid", "Token request reason is required.");
    }
    if (input.credential_ids.length === 0) {
      throw new GatewayError("unknown_credential", "At least one credential id is required.");
    }

    const service = getService(this.config, input.service, auth);
    const destination = resolveTokenDestination(service.destinations.map((item) => item.id), input.destination);
    const credentials = input.credential_ids.map((credentialId) => getCredential(service, credentialId));
    this.ensureCapacity(auth.subject, credentials.length);
    const now = this.now();
    const issued: TokenIssueResult["tokens"] = [];
    const internalTokenIds: string[] = [];

    for (const credential of credentials) {
      const credentialId = credential.id;
      const token = generateTokenValue();
      const id = `tokrec_${randomUUID()}`;
      const record: TokenRecord = {
        id,
        tokenHash: hashToken(token),
        subject: auth.subject,
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
      this.tokenValuesById.set(record.id, token);
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
    }, this.config);
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
    if (record.service !== target.service) throw new GatewayError("token_invalid", "Opaque token is not bound to this service.");
    if (target.destination !== undefined && record.destination !== target.destination) {
      throw new GatewayError("token_invalid", "Opaque token is not bound to this destination.");
    }

    record.lastUsedAt = now;
    record.idleExpiresAt = Math.min(now + this.config.tokens.idleTtlMs, record.maxExpiresAt);
    return record;
  }

  issueOrReuseResponseSecret(auth: AuthContext, service: string, secret: string): ResponseSecretIssueResult {
    this.sweepExpired();
    if (!secret) throw new GatewayError("token_invalid", "Response secret must not be empty.");
    const index = this.responseSecretIndex(auth.subject, service, secret);
    const existingId = this.responseSecretIdsByIndex.get(index);
    if (existingId !== undefined) {
      const existing = this.responseSecretsById.get(existingId);
      const token = this.tokenValuesById.get(existingId);
      if (existing && token && !this.isExpired(existing)) {
        this.refresh(existing);
        return { token, record: existing, reused: true };
      }
      this.deleteResponseSecret(existingId, index);
    }

    const now = this.now();
    this.ensureCapacity(auth.subject, 1);
    const token = generateResponseSecretTokenValue();
    const record: ResponseSecretTokenRecord = {
      id: `secrec_${randomUUID()}`,
      tokenHash: hashToken(token),
      subject: auth.subject,
      service,
      secret,
      issuedAt: now,
      lastUsedAt: now,
      idleExpiresAt: now + this.config.tokens.idleTtlMs,
      maxExpiresAt: now + this.config.tokens.maxTtlMs,
    };
    this.responseSecretsByHash.set(record.tokenHash, record);
    this.responseSecretsById.set(record.id, record);
    this.responseSecretIdsByIndex.set(index, record.id);
    this.tokenValuesById.set(record.id, token);
    return { token, record, reused: false };
  }

  validateResponseSecretUse(auth: AuthContext, service: string, tokenValue: string): ResponseSecretTokenRecord {
    const record = this.responseSecretsByHash.get(hashToken(tokenValue));
    if (!record) throw new GatewayError("token_invalid", "Unknown response secret token.");
    if (this.isExpired(record)) {
      this.deleteResponseSecret(record.id, this.responseSecretIndex(record.subject, record.service, record.secret));
      throw new GatewayError("token_expired", "Response secret token has expired.");
    }
    if (record.subject !== auth.subject) throw new GatewayError("token_invalid", "Response secret token is not bound to this subject.");
    if (record.service !== service) throw new GatewayError("token_invalid", "Response secret token is not bound to this service.");
    this.refresh(record);
    return record;
  }

  findConfiguredTokenForSecret(auth: AuthContext, service: string, secret: string): ConfiguredTokenMatch | undefined {
    const configured = this.config.services[service];
    if (!configured) return undefined;
    const credentialIds = new Set(configured.credentials.filter((credential) => credential.secret === secret).map((credential) => credential.id));
    if (credentialIds.size === 0) return undefined;
    const matches: TokenRecord[] = [];
    for (const [hash, record] of this.recordsByHash) {
      if (this.isExpired(record)) {
        this.recordsByHash.delete(hash);
        this.tokenValuesById.delete(record.id);
        continue;
      }
      if (record.subject === auth.subject && record.service === service && credentialIds.has(record.credentialId)) matches.push(record);
    }
    matches.sort((left, right) => right.lastUsedAt - left.lastUsedAt || right.issuedAt - left.issuedAt);
    const record = matches[0];
    if (!record) return undefined;
    const token = this.tokenValuesById.get(record.id);
    if (!token) return undefined;
    this.refresh(record);
    return { token, record };
  }

  inspectResponseToken(auth: AuthContext, service: string, tokenValue: string): TokenInspection {
    const hash = hashToken(tokenValue);
    const credential = this.recordsByHash.get(hash);
    if (credential) {
      if (this.isExpired(credential)) {
        this.recordsByHash.delete(hash);
        this.tokenValuesById.delete(credential.id);
        return { valid: false, reason: "expired" };
      }
      if (credential.subject !== auth.subject) return { valid: false, reason: "wrong_subject" };
      if (credential.service !== service) return { valid: false, reason: "wrong_service" };
      this.refresh(credential);
      return { valid: true };
    }
    const responseSecret = this.responseSecretsByHash.get(hash);
    if (responseSecret) {
      if (this.isExpired(responseSecret)) {
        this.deleteResponseSecret(responseSecret.id, this.responseSecretIndex(responseSecret.subject, responseSecret.service, responseSecret.secret));
        return { valid: false, reason: "expired" };
      }
      if (responseSecret.subject !== auth.subject) return { valid: false, reason: "wrong_subject" };
      if (responseSecret.service !== service) return { valid: false, reason: "wrong_service" };
      this.refresh(responseSecret);
      return { valid: true };
    }
    return { valid: false, reason: "unknown" };
  }

  sweepExpired(now = this.now()): void {
    for (const [hash, record] of this.recordsByHash) {
      if (record.idleExpiresAt <= now || record.maxExpiresAt <= now) this.deleteConfiguredToken(hash, record.id);
    }
    for (const record of [...this.responseSecretsById.values()]) {
      if (record.idleExpiresAt <= now || record.maxExpiresAt <= now) {
        this.deleteResponseSecret(record.id, this.responseSecretIndex(record.subject, record.service, record.secret));
      }
    }
  }

  stats(): { configured: number; responseSecrets: number; tokenValues: number } {
    return {
      configured: this.recordsByHash.size,
      responseSecrets: this.responseSecretsById.size,
      tokenValues: this.tokenValuesById.size,
    };
  }

  assertResponseSecretCapacity(auth: AuthContext, service: string, secrets: Iterable<string>): void {
    this.sweepExpired();
    const indexes = new Set<string>();
    for (const secret of secrets) {
      if (this.findConfiguredTokenForSecret(auth, service, secret) !== undefined) continue;
      const index = this.responseSecretIndex(auth.subject, service, secret);
      const existingId = this.responseSecretIdsByIndex.get(index);
      const existing = existingId === undefined ? undefined : this.responseSecretsById.get(existingId);
      if (existing !== undefined && !this.isExpired(existing)) continue;
      indexes.add(index);
    }
    this.ensureCapacity(auth.subject, indexes.size);
  }

  private responseSecretIndex(subject: string, service: string, secret: string): string {
    return createHmac("sha256", this.secretIndexKey).update(subject).update("\0").update(service).update("\0").update(secret).digest("base64url");
  }

  private isExpired(record: { idleExpiresAt: number; maxExpiresAt: number }): boolean {
    const now = this.now();
    return record.idleExpiresAt <= now || record.maxExpiresAt <= now;
  }

  private refresh(record: { lastUsedAt: number; idleExpiresAt: number; maxExpiresAt: number }): void {
    const now = this.now();
    record.lastUsedAt = now;
    record.idleExpiresAt = Math.min(now + this.config.tokens.idleTtlMs, record.maxExpiresAt);
  }

  private deleteResponseSecret(id: string, index: string): void {
    const record = this.responseSecretsById.get(id);
    if (record) this.responseSecretsByHash.delete(record.tokenHash);
    this.responseSecretsById.delete(id);
    this.responseSecretIdsByIndex.delete(index);
    this.tokenValuesById.delete(id);
  }

  private deleteConfiguredToken(hash: string, id: string): void {
    this.recordsByHash.delete(hash);
    this.tokenValuesById.delete(id);
  }

  private ensureCapacity(subject: string, additional: number): void {
    if (additional === 0) return;
    const total = this.recordsByHash.size + this.responseSecretsById.size;
    let subjectTotal = 0;
    for (const record of this.recordsByHash.values()) if (record.subject === subject) subjectTotal += 1;
    for (const record of this.responseSecretsById.values()) if (record.subject === subject) subjectTotal += 1;
    if (total + additional > this.config.limits.maxTokenRecords || subjectTotal + additional > this.config.limits.maxTokenRecordsPerSubject) {
      throw new GatewayError("capacity_exceeded", "Opaque token capacity is exhausted.");
    }
  }
}

export const defaultTokenBrokers = new WeakMap<GatewayConfig, TokenBroker>();

export function getTokenBroker(config: GatewayConfig): TokenBroker {
  const existing = defaultTokenBrokers.get(config);
  if (existing !== undefined) return existing;
  const broker = new TokenBroker(config);
  defaultTokenBrokers.set(config, broker);
  registerMaintenanceTask(config, (now) => broker.sweepExpired(now));
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
  return `gref_${randomBytes(24).toString("base64url")}`;
}

function generateResponseSecretTokenValue(): string {
  return `sec_${randomBytes(24).toString("base64url")}`;
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("base64url");
}

function usageHint(kind: string, name?: string): string {
  if (name) return `Use as ${name} ${kind}`;
  return `Use as ${kind}`;
}
