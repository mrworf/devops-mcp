import { createScanner, ScanError, SyntaxKind } from "jsonc-parser";
import { GatewayError } from "./errors.js";
import type { SensitiveNameMatcher } from "./sensitiveNames.js";

export interface SensitiveSourceFinding {
  start: number;
  end: number;
  secretValue: string;
  ruleIds: string[];
}

export interface JsonStringRange {
  start: number;
  end: number;
  isPropertyName: boolean;
}

interface ScannedToken {
  kind: SyntaxKind;
  offset: number;
  length: number;
  value: string;
  error: ScanError;
  objectId?: number;
}

interface StringProperty {
  name: string;
  value: string;
  valueStart: number;
  valueEnd: number;
  valueError: ScanError;
  objectId: number;
}

export function findSensitiveJsonValues(text: string, matcher: SensitiveNameMatcher): SensitiveSourceFinding[] {
  const tokens = scanMeaningfulTokens(text);
  const properties = findStringProperties(tokens);
  const findings: SensitiveSourceFinding[] = [];

  for (const property of properties) {
    const ruleIds = matcher.match(property.name);
    if (ruleIds.length === 0) continue;
    if (property.valueError !== ScanError.None) throw unsafeSensitiveValue();
    if (property.value.length === 0) continue;
    findings.push(toFinding(property, property.value, ruleIds));
  }
  failOnMissingSensitiveValues(tokens, matcher);

  const propertiesByObject = new Map<number, StringProperty[]>();
  for (const property of properties) {
    const values = propertiesByObject.get(property.objectId) ?? [];
    values.push(property);
    propertiesByObject.set(property.objectId, values);
  }
  for (const objectProperties of propertiesByObject.values()) {
    const names = objectProperties.filter((property) => property.name === "name" || property.name === "key");
    const values = objectProperties.filter((property) => property.name === "value");
    if (names.length !== 1 || values.length !== 1) continue;
    const name = names[0]!;
    const value = values[0]!;
    if (name.valueError !== ScanError.None || value.valueError !== ScanError.None) {
      if (name.valueError === ScanError.None && matcher.match(name.value).length > 0) throw unsafeSensitiveValue();
      continue;
    }
    const ruleIds = matcher.match(name.value);
    if (ruleIds.length === 0 || value.value.length === 0) continue;
    findings.push(toFinding(value, value.value, ruleIds));
  }

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]!;
    if (token.kind !== SyntaxKind.StringLiteral || tokens[index + 1]?.kind === SyntaxKind.ColonToken) continue;
    const raw = text.slice(token.offset + 1, token.offset + token.length - 1);
    const equals = raw.indexOf("=");
    if (equals <= 0 || raw.slice(0, equals).includes("\\")) continue;
    const name = raw.slice(0, equals);
    const ruleIds = matcher.match(name);
    if (ruleIds.length > 0 && token.error !== ScanError.None) throw unsafeSensitiveValue();
    if (token.error !== ScanError.None) continue;
    const secretValue = token.value.slice(equals + 1);
    if (ruleIds.length === 0 || secretValue.length === 0) continue;
    findings.push({
      start: token.offset + equals + 2,
      end: token.offset + token.length - 1,
      secretValue,
      ruleIds,
    });
  }

  return mergeFindings(findings);
}

export function findCompleteJsonStringRanges(text: string): JsonStringRange[] {
  const tokens = scanMeaningfulTokens(text);
  return tokens.flatMap((token, index) => token.kind === SyntaxKind.StringLiteral && token.error === ScanError.None
    ? [{
      start: token.offset + 1,
      end: token.offset + token.length - 1,
      isPropertyName: tokens[index + 1]?.kind === SyntaxKind.ColonToken,
    }]
    : []);
}

export function isJsonLikeText(headers: Record<string, string>, body: string): boolean {
  const contentTypes = Object.entries(headers)
    .filter(([name]) => name.toLowerCase() === "content-type")
    .map(([, value]) => value.split(";", 1)[0]?.trim().toLowerCase() ?? "");
  if (contentTypes.some((value) => value === "application/json" || value.endsWith("+json"))) return true;
  const first = body.trimStart()[0];
  return first === "{" || first === "[";
}

function findStringProperties(tokens: ScannedToken[]): StringProperty[] {
  const properties: StringProperty[] = [];
  for (let index = 0; index + 2 < tokens.length; index += 1) {
    const key = tokens[index]!;
    const colon = tokens[index + 1]!;
    const value = tokens[index + 2]!;
    if (key.kind !== SyntaxKind.StringLiteral || key.error !== ScanError.None
      || colon.kind !== SyntaxKind.ColonToken || value.kind !== SyntaxKind.StringLiteral
      || key.objectId === undefined || key.objectId !== colon.objectId || key.objectId !== value.objectId) continue;
    properties.push({
      name: key.value,
      value: value.value,
      valueStart: value.offset + 1,
      valueEnd: value.offset + value.length - 1,
      valueError: value.error,
      objectId: key.objectId,
    });
  }
  return properties;
}

function failOnMissingSensitiveValues(tokens: ScannedToken[], matcher: SensitiveNameMatcher): void {
  for (let index = 0; index + 1 < tokens.length; index += 1) {
    const key = tokens[index]!;
    const colon = tokens[index + 1]!;
    if (key.kind !== SyntaxKind.StringLiteral || key.error !== ScanError.None
      || colon.kind !== SyntaxKind.ColonToken || key.objectId === undefined || key.objectId !== colon.objectId
      || matcher.match(key.value).length === 0) continue;
    const value = tokens[index + 2];
    if (value === undefined) throw unsafeSensitiveValue();
    if (value.kind === SyntaxKind.StringLiteral && value.error !== ScanError.None) throw unsafeSensitiveValue();
  }
}

function scanMeaningfulTokens(text: string): ScannedToken[] {
  const scanner = createScanner(text, false);
  const tokens: ScannedToken[] = [];
  const objects: number[] = [];
  let nextObjectId = 1;
  for (;;) {
    const kind = scanner.scan();
    if (kind === SyntaxKind.EOF) return tokens;
    if (kind === SyntaxKind.Trivia || kind === SyntaxKind.LineBreakTrivia
      || kind === SyntaxKind.LineCommentTrivia || kind === SyntaxKind.BlockCommentTrivia) continue;
    const currentObject = objects.at(-1);
    const token: ScannedToken = {
      kind,
      offset: scanner.getTokenOffset(),
      length: scanner.getTokenLength(),
      value: scanner.getTokenValue(),
      error: scanner.getTokenError(),
      ...(currentObject === undefined ? {} : { objectId: currentObject }),
    };
    tokens.push(token);
    if (kind === SyntaxKind.OpenBraceToken) objects.push(nextObjectId++);
    else if (kind === SyntaxKind.CloseBraceToken) objects.pop();
  }
}

function toFinding(property: StringProperty, secretValue: string, ruleIds: string[]): SensitiveSourceFinding {
  return { start: property.valueStart, end: property.valueEnd, secretValue, ruleIds };
}

function mergeFindings(findings: SensitiveSourceFinding[]): SensitiveSourceFinding[] {
  const merged = new Map<string, SensitiveSourceFinding>();
  for (const finding of findings) {
    const key = `${finding.start}:${finding.end}`;
    const existing = merged.get(key);
    if (existing) existing.ruleIds = [...new Set([...existing.ruleIds, ...finding.ruleIds])];
    else merged.set(key, { ...finding, ruleIds: [...finding.ruleIds] });
  }
  return [...merged.values()];
}

function unsafeSensitiveValue(): GatewayError {
  return new GatewayError("secret_scan_failed", "Sensitive JSON value does not have a safe complete string range.");
}
