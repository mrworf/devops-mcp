import { GatewayError } from "./errors.js";
import type { SecretlintRuleConfig } from "./secretlintConfig.js";
import type { SecretFinding } from "./secretScanner.js";
import type { SecretScannerPool } from "./secretScannerPool.js";
import type { AuthContext, ServiceConfig } from "./types.js";
import type { TokenBroker, TokenInspectionReason } from "./tokens.js";
import { decodeUtf8 } from "./secretScanner.js";

const tokenCandidatePattern = /\b(?:tok|sec)_[^\s"'<>()[\]{},;]+/g;

interface Range {
  start: number;
  end: number;
  ruleIds: Set<string>;
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

    const internalRecordIds = new Set<string>();
    const ruleIds = new Set<string>();
    let count = 0;
    const transform = (collected: CollectedText): string => {
      let value = collected.original;
      for (const range of [...collected.ranges].sort((left, right) => right.start - left.start)) {
        const raw = collected.original.slice(range.start, range.end);
        const configured = this.broker.findConfiguredTokenForSecret(auth, service.id, raw);
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
    const declarations = Object.entries(response.headers).filter(([name]) => name.toLowerCase() === "content-transfer-encoding");
    if (declarations.length === 0) return await this.tokenize(response, auth, service, disabledRuleIds);
    if (declarations.length !== 1 || declarations[0]?.[1].trim().toLowerCase() !== "base64") {
      throw new GatewayError("unsupported_transfer_encoding", "Unsupported or conflicting Content-Transfer-Encoding.");
    }
    const normalized = response.body.replace(/[\t\n\f\r ]/g, "");
    if (!isCanonicalBase64Shape(normalized)) throw new GatewayError("secret_scan_failed", "Response body is not valid Base64.");
    let decoded: string;
    try { decoded = decodeUtf8(Buffer.from(normalized, "base64")); }
    catch { throw new GatewayError("secret_scan_failed", "Base64 response is not valid UTF-8."); }
    const tokenized = await this.tokenize({ headers: response.headers, body: decoded }, auth, service, disabledRuleIds);
    return { ...tokenized, body: Buffer.from(tokenized.body, "utf8").toString("base64") };
  }

  private async collect(text: string, auth: AuthContext, service: ServiceConfig, disabledRuleIds: ReadonlySet<string>): Promise<CollectedText> {
    let findings: SecretFinding[];
    try {
      findings = await this.scanner.scan(auth.subject, text, this.rules.filter((rule) => !disabledRuleIds.has(rule.id)), this.timeoutMs);
    } catch (error) {
      if (error instanceof GatewayError) throw error;
      throw new GatewayError("secret_scan_failed", "Response secret scanning failed.");
    }
    const ranges: Range[] = findings.map((finding) => ({ start: finding.start, end: finding.end, ruleIds: new Set([finding.ruleId]) }));
    for (const credential of service.credentials) addExactRanges(ranges, text, credential.secret, "gateway:configured-credential");

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

function isCanonicalBase64Shape(value: string): boolean {
  if (value === "") return true;
  return /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value);
}

function addExactRanges(ranges: Range[], text: string, secret: string, ruleId: string): void {
  if (!secret) return;
  let from = 0;
  while (from <= text.length - secret.length) {
    const start = text.indexOf(secret, from);
    if (start < 0) break;
    ranges.push({ start, end: start + secret.length, ruleIds: new Set([ruleId]) });
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
      merged.push({ start: range.start, end: range.end, ruleIds: new Set(range.ruleIds) });
      continue;
    }
    previous.end = Math.max(previous.end, range.end);
    for (const id of range.ruleIds) previous.ruleIds.add(id);
  }
  return merged;
}
