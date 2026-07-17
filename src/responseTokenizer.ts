import { GatewayError } from "./errors.js";
import { decodeDeclaredBase64Body, encodeBase64Body } from "./base64Body.js";
import type { SecretlintRuleConfig } from "./secretlintConfig.js";
import type { SecretFinding } from "./secretScanner.js";
import { SecretScanBusyError, type SecretScannerPool } from "./secretScannerPool.js";
import type { AuthContext, ServiceConfig } from "./types.js";
import type { TokenBroker, TokenInspectionReason } from "./tokens.js";
import { findSensitiveJsonValues, isJsonLikeText } from "./sensitiveJson.js";
import type { SensitiveNameMatcher } from "./sensitiveNames.js";

const tokenCandidatePattern = /\b(?:gref|sec)_[^\s"'<>()[\]{},;]+/g;

interface Range {
  start: number;
  end: number;
  ruleIds: Set<string>;
  configuredSecret?: string;
  secretValue?: string;
}

interface CollectedText {
  original: string;
  ranges: Range[];
  warnings: Map<string, { prefix: "gref" | "sec"; reason: TokenInspectionReason; count: number }>;
}

export interface TokenizedResponseText {
  headers: Record<string, string>;
  body: string;
  secretTokenized: boolean;
  secretTokenizationCount: number;
  ruleIds: string[];
  internalRecordIds: string[];
  warnings: Array<{ prefix: "gref" | "sec"; reason: TokenInspectionReason; count: number }>;
}

export class ResponseTokenizer {
  constructor(
    private readonly broker: TokenBroker,
    private readonly scanner: SecretScannerPool,
    private readonly rules: SecretlintRuleConfig[],
    private readonly maxUniqueSecrets: number,
    private readonly timeoutMs: number,
    private readonly sensitiveNames: SensitiveNameMatcher,
  ) {}

  async tokenize(
    response: { headers: Record<string, string>; body: string },
    auth: AuthContext,
    service: ServiceConfig,
    disabledRuleIds: ReadonlySet<string> = new Set(),
  ): Promise<TokenizedResponseText> {
    const headerEntries: Array<readonly [string, CollectedText]> = [];
    for (const [name, value] of Object.entries(response.headers)) {
      const ruleIds = this.sensitiveNames.match(name);
      const sensitive = value.length > 0 && ruleIds.length > 0
        ? [{ start: 0, end: value.length, secretValue: value, ruleIds: new Set(ruleIds) }]
        : [];
      headerEntries.push([name, await this.collect(value, auth, service, disabledRuleIds, sensitive)] as const);
    }
    const bodyRanges = isJsonLikeText(response.headers, response.body)
      ? findSensitiveJsonValues(response.body, this.sensitiveNames).map((finding) => ({
        start: finding.start, end: finding.end, secretValue: finding.secretValue, ruleIds: new Set(finding.ruleIds),
      }))
      : [];
    const body = await this.collect(response.body, auth, service, disabledRuleIds, bodyRanges);
    const all = [...headerEntries.map(([, collected]) => collected), body];
    const uniqueSecrets = new Set(all.flatMap((collected) => collected.ranges.map((range) => range.secretValue ?? collected.original.slice(range.start, range.end))));
    if (uniqueSecrets.size > this.maxUniqueSecrets) {
      throw new GatewayError("secret_scan_failed", "Response contains too many unique secrets.");
    }
    this.broker.assertResponseSecretCapacity(auth, service.id, uniqueSecrets);

    const internalRecordIds = new Set<string>();
    const ruleIds = new Set<string>();
    let count = 0;
    const transform = (collected: CollectedText): string => {
      let value = collected.original;
      for (const range of [...collected.ranges].sort((left, right) => right.start - left.start)) {
        const raw = collected.original.slice(range.start, range.end);
        const secret = range.configuredSecret ?? range.secretValue ?? raw;
        const configured = this.broker.findConfiguredTokenForSecret(auth, service.id, secret);
        const issued = configured ?? this.broker.issueOrReuseResponseSecret(auth, service.id, secret);
        internalRecordIds.add(issued.record.id);
        for (const ruleId of range.ruleIds) ruleIds.add(ruleId);
        value = value.slice(0, range.start) + issued.token + value.slice(range.end);
        count += 1;
      }
      return value;
    };
    const warnings = new Map<string, { prefix: "gref" | "sec"; reason: TokenInspectionReason; count: number }>();
    for (const collected of all) {
      for (const [key, warning] of collected.warnings) {
        const existing = warnings.get(key);
        if (existing) existing.count += warning.count;
        else warnings.set(key, { ...warning });
      }
    }
    return {
      headers: Object.fromEntries(headerEntries.map(([name, collected]) => [name, transform(collected)])),
      body: transform(body),
      secretTokenized: count > 0,
      secretTokenizationCount: count,
      ruleIds: [...ruleIds].sort(),
      internalRecordIds: [...internalRecordIds],
      warnings: [...warnings.values()],
    };
  }

  async tokenizeWithTransferEncoding(
    response: { headers: Record<string, string>; body: string },
    auth: AuthContext,
    service: ServiceConfig,
    disabledRuleIds: ReadonlySet<string> = new Set(),
  ): Promise<TokenizedResponseText> {
    const decoded = decodeDeclaredBase64Body(response.headers, response.body, "response");
    if (decoded === undefined) return await this.tokenize(response, auth, service, disabledRuleIds);
    const tokenized = await this.tokenize({ headers: response.headers, body: decoded }, auth, service, disabledRuleIds);
    return { ...tokenized, body: encodeBase64Body(tokenized.body) };
  }

  private async collect(
    text: string,
    auth: AuthContext,
    service: ServiceConfig,
    disabledRuleIds: ReadonlySet<string>,
    additionalRanges: Range[] = [],
  ): Promise<CollectedText> {
    let findings: SecretFinding[];
    try {
      findings = await this.scanner.scan(auth.subject, text, this.rules.filter((rule) => !disabledRuleIds.has(rule.id)), this.timeoutMs);
    } catch (error) {
      if (error instanceof GatewayError) throw error;
      if (error instanceof SecretScanBusyError) throw new GatewayError("secret_scan_busy", "Response secret scanner is busy.");
      throw new GatewayError("secret_scan_failed", "Response secret scanning failed.");
    }
    const ranges: Range[] = [
      ...findings.map((finding) => ({ start: finding.start, end: finding.end, ruleIds: new Set([finding.ruleId]) })),
      ...additionalRanges,
    ];
    for (const credential of service.credentials) {
      addExactRanges(ranges, text, credential.secret, "gateway:configured-credential", credential.secret);
      const escaped = JSON.stringify(credential.secret).slice(1, -1);
      if (escaped !== credential.secret) addExactRanges(ranges, text, escaped, "gateway:configured-credential", credential.secret);
    }

    const validCandidates: Array<{ start: number; end: number }> = [];
    const warnings = new Map<string, { prefix: "gref" | "sec"; reason: TokenInspectionReason; count: number }>();
    for (const match of text.matchAll(tokenCandidatePattern)) {
      const candidate = match[0];
      const start = match.index;
      const end = start + candidate.length;
      const inspection = this.broker.inspectResponseToken(auth, service.id, candidate);
      if (inspection.valid) {
        validCandidates.push({ start, end });
        continue;
      }
      ranges.push({ start, end, ruleIds: new Set(["gateway:invalid-opaque-prefix"]) });
      const prefix = candidate.startsWith("gref_") ? "gref" : "sec";
      const key = `${prefix}:${inspection.reason}`;
      const existing = warnings.get(key);
      if (existing) existing.count += 1;
      else warnings.set(key, { prefix, reason: inspection.reason, count: 1 });
    }
    const withoutValidCandidates = ranges.filter((range) => !validCandidates.some((valid) => overlaps(range, valid)));
    return { original: text, ranges: mergeRanges(withoutValidCandidates), warnings };
  }
}

function addExactRanges(ranges: Range[], text: string, secret: string, ruleId: string, configuredSecret?: string): void {
  if (!secret) return;
  let from = 0;
  while (from <= text.length - secret.length) {
    const start = text.indexOf(secret, from);
    if (start < 0) break;
    ranges.push({ start, end: start + secret.length, ruleIds: new Set([ruleId]), ...(configuredSecret === undefined ? {} : { configuredSecret }) });
    from = start + Math.max(1, secret.length);
  }
}

function overlaps(left: { start: number; end: number }, right: { start: number; end: number }): boolean {
  return left.start < right.end && right.start < left.end;
}

function mergeRanges(ranges: Range[]): Range[] {
  const sorted = [...ranges].sort((left, right) => left.start - right.start || right.end - left.end);
  const merged: Range[] = [];
  for (const range of sorted) {
    const previous = merged.at(-1);
    if (!previous || range.start >= previous.end) {
      merged.push({
        start: range.start, end: range.end, ruleIds: new Set(range.ruleIds),
        ...(range.configuredSecret === undefined ? {} : { configuredSecret: range.configuredSecret }),
        ...(range.secretValue === undefined ? {} : { secretValue: range.secretValue }),
      });
      continue;
    }
    const previousEnd = previous.end;
    const sameBounds = previous.start === range.start && previous.end === range.end;
    previous.end = Math.max(previous.end, range.end);
    if (range.end > previousEnd) {
      delete previous.configuredSecret;
      delete previous.secretValue;
    } else if (sameBounds) {
      if (previous.configuredSecret === undefined && range.configuredSecret !== undefined) previous.configuredSecret = range.configuredSecret;
      if (previous.secretValue === undefined && range.secretValue !== undefined) previous.secretValue = range.secretValue;
    }
    for (const id of range.ruleIds) previous.ruleIds.add(id);
  }
  return merged;
}
