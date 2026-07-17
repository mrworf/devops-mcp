import { getCredential } from "./registry.js";
import { decodeDeclaredBase64Body, encodeBase64Body } from "./base64Body.js";
import { GatewayError } from "./errors.js";
import { findCompleteJsonStringRanges, isJsonLikeText } from "./sensitiveJson.js";
import type { ResponseSecretTokenRecord, TokenBroker, TokenRecord, TokenUseTarget } from "./tokens.js";
import type { AuthContext, ServiceConfig } from "./types.js";

const tokenPattern = /(?:gref|sec)_[A-Za-z0-9_-]+/g;

export interface SubstitutionResult<T> {
  value: T;
  records: TokenRecord[];
  responseSecretRecords: ResponseSecretTokenRecord[];
}

export function substituteTokens<T>(
  value: T,
  broker: TokenBroker,
  auth: AuthContext,
  target: TokenUseTarget,
  service: ServiceConfig,
): SubstitutionResult<T> {
  const records: TokenRecord[] = [];
  const responseSecretRecords: ResponseSecretTokenRecord[] = [];
  const replaced = substituteValue(value, (token) => {
    if (token.startsWith("sec_")) {
      const record = broker.validateResponseSecretUse(auth, target.service, token);
      responseSecretRecords.push(record);
      return record.secret;
    }
    const record = broker.validateTokenUse(auth, target, token);
    records.push(record);
    return getCredential(service, record.credentialId).secret;
  });
  return { value: replaced as T, records, responseSecretRecords };
}

export function substituteRequestBodyTokens(
  body: unknown,
  headers: Record<string, string>,
  broker: TokenBroker,
  auth: AuthContext,
  target: TokenUseTarget,
  service: ServiceConfig,
): SubstitutionResult<unknown> {
  const decoded = decodeDeclaredBase64Body(headers, body, "request");
  if (decoded === undefined) {
    if (typeof body === "string" && isJsonLikeText(headers, body)) {
      return substituteJsonTextTokens(body, broker, auth, target, service);
    }
    return substituteTokens(body, broker, auth, target, service);
  }
  const substituted = isJsonLikeText(headers, decoded)
    ? substituteJsonTextTokens(decoded, broker, auth, target, service)
    : substituteTokens(decoded, broker, auth, target, service);
  return { ...substituted, value: encodeBase64Body(substituted.value) };
}

function substituteJsonTextTokens(
  text: string,
  broker: TokenBroker,
  auth: AuthContext,
  target: TokenUseTarget,
  service: ServiceConfig,
): SubstitutionResult<string> {
  const records: TokenRecord[] = [];
  const responseSecretRecords: ResponseSecretTokenRecord[] = [];
  const ranges: Array<{ start: number; end: number; replacement: string }> = [];
  const safeCandidates: Array<{ start: number; end: number }> = [];
  for (const stringRange of findCompleteJsonStringRanges(text)) {
    const raw = text.slice(stringRange.start, stringRange.end);
    for (const match of raw.matchAll(tokenPattern)) {
      const token = match[0];
      const start = stringRange.start + match.index;
      const end = start + token.length;
      safeCandidates.push({ start, end });
      if (stringRange.isPropertyName) continue;
      const secret = redeemToken(token, broker, auth, target, service, records, responseSecretRecords);
      ranges.push({ start, end, replacement: JSON.stringify(secret).slice(1, -1) });
    }
  }
  for (const match of text.matchAll(tokenPattern)) {
    const start = match.index;
    const end = start + match[0].length;
    if (!safeCandidates.some((candidate) => candidate.start === start && candidate.end === end)
      || !ranges.some((range) => range.start === start && range.end === end)) {
      throw new GatewayError("reference_invalid", "Opaque references in JSON must be complete string values.");
    }
  }
  let value = text;
  for (const range of ranges.sort((left, right) => right.start - left.start)) {
    value = value.slice(0, range.start) + range.replacement + value.slice(range.end);
  }
  return { value, records, responseSecretRecords };
}

function redeemToken(
  token: string,
  broker: TokenBroker,
  auth: AuthContext,
  target: TokenUseTarget,
  service: ServiceConfig,
  records: TokenRecord[],
  responseSecretRecords: ResponseSecretTokenRecord[],
): string {
  if (token.startsWith("sec_")) {
    const record = broker.validateResponseSecretUse(auth, target.service, token);
    responseSecretRecords.push(record);
    return record.secret;
  }
  const record = broker.validateTokenUse(auth, target, token);
  records.push(record);
  return getCredential(service, record.credentialId).secret;
}

function substituteValue(value: unknown, replaceToken: (token: string) => string): unknown {
  if (typeof value === "string") {
    return value.replace(tokenPattern, (token) => replaceToken(token));
  }
  if (Array.isArray(value)) return value.map((item) => substituteValue(item, replaceToken));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, substituteValue(item, replaceToken)]));
  }
  return value;
}
