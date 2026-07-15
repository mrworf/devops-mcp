import { getCredential } from "./registry.js";
import type { ResponseSecretTokenRecord, TokenBroker, TokenRecord, TokenUseTarget } from "./tokens.js";
import type { AuthContext, ServiceConfig } from "./types.js";

const tokenPattern = /(?:tok|sec)_[A-Za-z0-9_-]+/g;

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
