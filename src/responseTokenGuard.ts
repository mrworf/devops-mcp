import type { AuthContext } from "./types.js";
import type { TokenBroker, TokenInspectionReason } from "./tokens.js";

const candidatePattern = /\b(?:gref|sec)_[^\s"'<>()[\]{},;]+/g;

export interface TokenGuardWarning {
  prefix: "gref" | "sec";
  reason: TokenInspectionReason;
  count: number;
}

export interface TokenGuardResult {
  value: string;
  tokenizationCount: number;
  warnings: TokenGuardWarning[];
}

export function guardResponseTokenCandidates(
  value: string,
  broker: TokenBroker,
  auth: AuthContext,
  service: string,
): TokenGuardResult {
  const invalidCandidates = [...value.matchAll(candidatePattern)]
    .map((match) => match[0])
    .filter((candidate) => !broker.inspectResponseToken(auth, service, candidate).valid);
  broker.assertResponseSecretCapacity(auth, service, invalidCandidates);
  let count = 0;
  const warningCounts = new Map<string, TokenGuardWarning>();
  const guarded = value.replace(candidatePattern, (candidate) => {
    const inspection = broker.inspectResponseToken(auth, service, candidate);
    if (inspection.valid) return candidate;
    count += 1;
    const prefix = candidate.startsWith("gref_") ? "gref" : "sec";
    const key = `${prefix}:${inspection.reason}`;
    const existing = warningCounts.get(key);
    if (existing) existing.count += 1;
    else warningCounts.set(key, { prefix, reason: inspection.reason, count: 1 });
    return broker.issueOrReuseResponseSecret(auth, service, candidate).token;
  });
  return { value: guarded, tokenizationCount: count, warnings: [...warningCounts.values()] };
}
