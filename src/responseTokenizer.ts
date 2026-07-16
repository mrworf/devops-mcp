import { GatewayError } from "./errors.js";
import { decodeDeclaredBase64Body, encodeBase64Body } from "./base64Body.js";
import type { SecretlintRuleConfig } from "./secretlintConfig.js";
import type { SecretFinding } from "./secretScanner.js";
import { SecretScanBusyError, type SecretScannerPool } from "./secretScannerPool.js";
import type { AuthContext, ServiceConfig } from "./types.js";
import type { TokenBroker, TokenInspectionReason } from "./tokens.js";

const tokenCandidatePattern = /\b(?:tok|sec)_[^\s"'<>()[\]{},;]+/g;

interface Range {
  start: number;
  end: number;
  ruleIds: Set<string>;
  configuredSecret?: string;
}

interface CollectedText {
  original: string;
  ranges: Range[];
  warnings: Map<string, { prefix: "tok" | "sec"; reason: TokenInspectionReason; count: number }>;
}

export interface TokenizedResponseText {
  headers: Record<string, string>;
  body: string;
  secretTokenized: boolean;
  secretTokenizationCount: number;
  ruleIds: string[];
  internalRecordIds: string[];
  warnings: Array<{ prefix: "tok" | "sec"; reason: TokenInspectionReason; count: number }>;
}

export class ResponseTokenizer {
  constructor(
    private readonly broker: TokenBroker,
    private readonly scanner: SecretScannerPool,
    private readonly rules: SecretlintRuleConfig[],
    private readonly maxUniqueSecrets: number,
    private readonly timeoutMs: number,
  ) {}

  async tokenize(
    response: { headers: Record<string, string>; body: string },
    auth: AuthContext,
    service: ServiceConfig,
    disabledRuleIds: ReadonlySet<string> = new Set(),
  ): Promise<TokenizedResponseText> {
    const headerEntries: Array<readonly [string, CollectedText]> = [];
    for (const [name, value] of Object.entries(response.headers)) {
      headerEntries.push([name, await this.collect(value, auth, service, disabledRuleIds)] as const);
    }
    const body = await this.collect(response.body, auth, service, disabledRuleIds);
    const all = [...headerEntries.map(([, collected]) => collected), body];
    const uniqueSecrets = new Set(all.flatMap((collected) => collected.ranges.map((range) => collected.original.slice(range.start, range.end))));
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
        const configured = this.broker.findConfiguredTokenForSecret(auth, service.id, range.configuredSecret ?? raw);
        const issued = configured ?? this.broker.issueOrReuseResponseSecret(auth, service.id, raw);
        internalRecordIds.add(issued.record.id);
        for (const ruleId of range.ruleIds) ruleIds.add(ruleId);
        value = value.slice(0, range.start) + issued.token + value.slice(range.end);
        count += 1;
      }
      return value;
    };
    const warnings = new Map<string, { prefix: "tok" | "sec"; reason: TokenInspectionReason; count: number }>();
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

  private async collect(text: string, auth: AuthContext, service: ServiceConfig, disabledRuleIds: ReadonlySet<string>): Promise<CollectedText> {
    let findings: SecretFinding[];
    try {
      findings = await this.scanner.scan(auth.subject, text, this.rules.filter((rule) => !disabledRuleIds.has(rule.id)), this.timeoutMs);
    } catch (error) {
      if (error instanceof GatewayError) throw error;
      if (error instanceof SecretScanBusyError) throw new GatewayError("secret_scan_busy", "Response secret scanner is busy.");
      throw new GatewayError("secret_scan_failed", "Response secret scanning failed.");
    }
    const ranges: Range[] = findings.map((finding) => ({ start: finding.start, end: finding.end, ruleIds: new Set([finding.ruleId]) }));
    for (const credential of service.credentials) {
      addExactRanges(ranges, text, credential.secret, "gateway:configured-credential", credential.secret);
      const escaped = JSON.stringify(credential.secret).slice(1, -1);
      if (escaped !== credential.secret) addExactRanges(ranges, text, escaped, "gateway:configured-credential", credential.secret);
    }

    const validCandidates: Array<{ start: number; end: number }> = [];
    const warnings = new Map<string, { prefix: "tok" | "sec"; reason: TokenInspectionReason; count: number }>();
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
      const prefix = candidate.startsWith("tok_") ? "tok" : "sec";
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
      merged.push({ start: range.start, end: range.end, ruleIds: new Set(range.ruleIds), ...(range.configuredSecret === undefined ? {} : { configuredSecret: range.configuredSecret }) });
      continue;
    }
    const sameBounds = previous.start === range.start && previous.end === range.end;
    previous.end = Math.max(previous.end, range.end);
    if (!sameBounds) delete previous.configuredSecret;
    else if (previous.configuredSecret === undefined && range.configuredSecret !== undefined) previous.configuredSecret = range.configuredSecret;
    for (const id of range.ruleIds) previous.ruleIds.add(id);
  }
  return merged;
}
