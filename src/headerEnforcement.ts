import { credentialReferenceTemplate } from "./credentialUsage.js";
import { GatewayError } from "./errors.js";
import type { Logger } from "./logger.js";
import type { AuthContext, CredentialConfig, ServiceConfig } from "./types.js";
import type { TokenBroker, TokenRecord, TokenUseTarget } from "./tokens.js";

const gatewayReferencePattern = /gref_[A-Za-z0-9_-]+/g;

export function enforceCredentialHeaderUsage(
  input: { headers: Record<string, string>; query: Record<string, unknown>; body: unknown },
  broker: TokenBroker,
  auth: AuthContext,
  target: TokenUseTarget,
  service: ServiceConfig,
  logger: Logger,
): Record<string, string> {
  const enforced = service.credentials.filter(isEnforcedHeaderCredential);
  if (enforced.length === 0) return input.headers;

  const headers = { ...input.headers };
  const groups = groupByHeaderName(enforced);
  for (const [normalizedName, credentials] of groups) {
    const entries = Object.entries(headers).filter(([name]) => name.toLowerCase() === normalizedName);
    if (entries.length === 0) continue;

    const candidates = unique(entries.flatMap(([, value]) => findGatewayReferences(value)));
    const valid = candidates.flatMap((reference) => {
      const record = inspectReference(broker, auth, target, reference);
      return record === undefined ? [] : [{ reference, record }];
    });
    const matches = valid.filter(({ record }) =>
      record.kind === "credential" && record.credentialId !== undefined
      && credentials.some((credential) => credential.id === record.credentialId));

    if (matches.length !== 1 || valid.length !== 1) {
      logRejected(logger, service.id, target.destination, matches[0]?.record.credentialId, "missing_or_ambiguous_reference", entries.length);
      throw new GatewayError("reference_invalid", "Gateway-owned credential header requires exactly one matching reference.");
    }

    const selected = matches[0]!;
    const credential = credentials.find((candidate) => candidate.id === selected.record.credentialId)!;
    const expected = credentialReferenceTemplate(credential.usage, selected.reference);
    const exact = entries.length === 1 && entries[0]?.[1] === expected;
    for (const [name] of entries) delete headers[name];
    headers[credential.usage.name!] = expected;

    if (!exact) {
      logger.warn("service_request.auth_header_override_clobbered", {
        service: service.id,
        destination: target.destination,
        access_id: credential.id,
        override_category: entries.length > 1 ? "duplicate_or_wrong_shape" : "wrong_shape",
        duplicate_count: Math.max(0, entries.length - 1),
      });
    }
  }

  assertNoEnforcedReferenceOutsideOwnedHeader(headers, input.query, input.body, broker, auth, target, service, enforced, logger);
  return headers;
}

function assertNoEnforcedReferenceOutsideOwnedHeader(
  headers: Record<string, string>,
  query: Record<string, unknown>,
  body: unknown,
  broker: TokenBroker,
  auth: AuthContext,
  target: TokenUseTarget,
  service: ServiceConfig,
  enforced: CredentialConfig[],
  logger: Logger,
): void {
  const locations: Array<{ kind: "header" | "query" | "body"; name?: string; value: unknown }> = [
    ...Object.entries(headers).map(([name, value]) => ({ kind: "header" as const, name, value })),
    { kind: "query", value: query },
    { kind: "body", value: body },
  ];
  for (const location of locations) {
    for (const reference of unique(findGatewayReferences(location.value))) {
      const record = inspectReference(broker, auth, target, reference);
      if (record?.kind !== "credential" || record.credentialId === undefined) continue;
      const credential = enforced.find((candidate) => candidate.id === record.credentialId);
      if (credential === undefined) continue;
      const allowed = location.kind === "header"
        && location.name?.toLowerCase() === credential.usage.name!.toLowerCase()
        && location.value === credentialReferenceTemplate(credential.usage, reference);
      if (allowed) continue;
      logRejected(logger, service.id, target.destination, credential.id, "wrong_location", 0);
      throw new GatewayError("reference_invalid", "Enforced credential reference is not in its configured header template.");
    }
  }
}

function inspectReference(
  broker: TokenBroker,
  auth: AuthContext,
  target: TokenUseTarget,
  reference: string,
): TokenRecord | undefined {
  try {
    return broker.validateTokenUse(auth, target, reference);
  } catch (error) {
    if (error instanceof GatewayError) return undefined;
    throw error;
  }
}

function isEnforcedHeaderCredential(credential: CredentialConfig): boolean {
  return credential.usage.enforce
    && credential.usage.kind.toLowerCase() === "header"
    && credential.usage.name !== undefined;
}

function groupByHeaderName(credentials: CredentialConfig[]): Map<string, CredentialConfig[]> {
  const groups = new Map<string, CredentialConfig[]>();
  for (const credential of credentials) {
    const normalized = credential.usage.name!.toLowerCase();
    const existing = groups.get(normalized);
    if (existing === undefined) groups.set(normalized, [credential]);
    else existing.push(credential);
  }
  return groups;
}

function findGatewayReferences(value: unknown): string[] {
  if (typeof value === "string") return [...value.matchAll(gatewayReferencePattern)].map((match) => match[0]);
  if (Array.isArray(value)) return value.flatMap(findGatewayReferences);
  if (value && typeof value === "object") return Object.entries(value).flatMap(([key, item]) => [
    ...findGatewayReferences(key), ...findGatewayReferences(item),
  ]);
  return [];
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

function logRejected(
  logger: Logger,
  service: string,
  destination: string | undefined,
  credentialId: string | undefined,
  category: string,
  headerCount: number,
): void {
  logger.warn("service_request.auth_header_override_rejected", {
    service,
    ...(destination === undefined ? {} : { destination }),
    ...(credentialId === undefined ? {} : { access_id: credentialId }),
    override_category: category,
    duplicate_count: Math.max(0, headerCount - 1),
  });
}
