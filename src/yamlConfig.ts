import { readFileSync } from "node:fs";
import { LineCounter, parseDocument, type Document, type Node } from "yaml";
import { configError, formatConfigPath, GatewayError, type ConfigDiagnostic, type ConfigPath } from "./errors.js";

const MAX_EXCERPT_LENGTH = 160;

export function loadYamlConfig<T>(
  file: string,
  label: string,
  validate: (raw: unknown) => T,
): T {
  let source: string;
  try {
    source = readFileSync(file, "utf8");
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw configError(`Failed to read ${label}: ${detail}`, [{ file, detail }]);
  }

  const lineCounter = new LineCounter();
  const document = parseDocument(source, { lineCounter, prettyErrors: false });
  if (document.errors.length > 0) {
    const diagnostics = document.errors.map((error) => diagnosticAtOffset(
      file,
      source,
      lineCounter,
      error.pos[0],
      safeParserDetail(error.message),
    ));
    throw configError(`Failed to parse ${label}: ${diagnostics.map((item) => item.detail).join("; ")}`, diagnostics);
  }

  let raw: unknown;
  try {
    raw = document.toJS();
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw configError(`Failed to parse ${label}: ${detail}`, [{ file, detail }]);
  }

  try {
    return validate(raw);
  } catch (error) {
    if (!(error instanceof GatewayError) || error.code !== "config_error") throw error;
    const diagnostics = (error.diagnostics ?? [{ detail: error.message }]).map((diagnostic) => enrichDiagnostic(
      diagnostic,
      file,
      source,
      document,
      lineCounter,
    ));
    throw configError(error.message, diagnostics);
  }
}

export function validationDiagnostics(issues: readonly unknown[]): ConfigDiagnostic[] {
  return issues.flatMap((issue) => expandIssue(issue)).map((issue) => {
    const path = issue.path.filter((segment): segment is string | number => typeof segment === "string" || typeof segment === "number");
    return {
      detail: issue.message,
      ...(path.length === 0 ? {} : { path: formatConfigPath(path), configPath: path }),
    };
  });
}

interface ValidationIssue {
  code: string;
  path: unknown[];
  message: string;
  keys?: string[];
  errors?: ValidationIssue[][];
}

function expandIssue(value: unknown): ValidationIssue[] {
  const issue = value as ValidationIssue;
  if (issue.code === "unrecognized_keys" && issue.keys !== undefined) {
    return issue.keys.map((key) => ({ ...issue, path: [...issue.path, key], message: `Unrecognized key: "${key}"` }));
  }
  if (issue.code === "invalid_union" && issue.errors !== undefined && issue.errors.length > 0) {
    const bestBranch = [...issue.errors].sort((left, right) => left.length - right.length)[0] ?? [];
    return bestBranch.flatMap((nested) => expandIssue(nested));
  }
  return [issue];
}

function enrichDiagnostic(
  diagnostic: ConfigDiagnostic,
  file: string,
  source: string,
  document: Document<Node, true>,
  lineCounter: LineCounter,
): ConfigDiagnostic {
  if (diagnostic.line !== undefined) return { ...diagnostic, file };
  const offset = nodeOffset(document, diagnostic.configPath ?? []);
  if (offset === undefined) return { ...withoutInternalPath(diagnostic), file };
  return {
    ...withoutInternalPath(diagnostic),
    ...diagnosticAtOffset(file, source, lineCounter, offset, diagnostic.detail),
  };
}

function nodeOffset(document: Document<Node, true>, path: ConfigPath): number | undefined {
  for (let length = path.length; length >= 0; length -= 1) {
    const candidate = document.getIn(path.slice(0, length), true) as { range?: [number, number, number] } | undefined;
    if (candidate?.range) return candidate.range[0];
  }
  return document.contents?.range?.[0];
}

function diagnosticAtOffset(
  file: string,
  source: string,
  lineCounter: LineCounter,
  offset: number,
  detail: string,
): ConfigDiagnostic {
  const position = lineCounter.linePos(Math.max(0, offset));
  const sourceLine = lineAt(source, position.line);
  const excerpt = safeExcerpt(sourceLine, position.col);
  return {
    file,
    detail,
    line: position.line,
    column: position.col,
    source: excerpt.source,
    pointer: `${" ".repeat(excerpt.pointerColumn - 1)}^`,
  };
}

function lineAt(source: string, line: number): string {
  return source.split(/\r?\n/)[line - 1] ?? "";
}

function safeExcerpt(line: string, column: number): { source: string; pointerColumn: number } {
  const mapping = /^(\s*(?:-\s+)?(?:[A-Za-z0-9_.-]+|"[^"]*"|'[^']*')\s*:)(.*)$/.exec(line);
  const masked = mapping
    ? `${mapping[1]}${maskScalarText(mapping[2] ?? "")}`
    : maskScalarText(line);
  if (masked.length <= MAX_EXCERPT_LENGTH) return { source: masked, pointerColumn: Math.min(column, masked.length + 1) };

  const desiredStart = Math.max(0, column - Math.floor(MAX_EXCERPT_LENGTH / 2));
  const start = Math.min(desiredStart, masked.length - MAX_EXCERPT_LENGTH);
  const end = start + MAX_EXCERPT_LENGTH;
  const leading = start > 0 ? "…" : "";
  const trailing = end < masked.length ? "…" : "";
  return {
    source: `${leading}${masked.slice(start, end)}${trailing}`,
    pointerColumn: Math.max(1, column - start + leading.length),
  };
}

function maskScalarText(value: string): string {
  return [...value].map((character) => /[\s\[\]{}:,?"'-]/.test(character) ? character : "•").join("");
}

function safeParserDetail(detail: string): string {
  return detail.replace(/(["'])(.*?)\1/g, (_match, quote: string, value: string) => `${quote}${maskScalarText(value)}${quote}`);
}

function withoutInternalPath(diagnostic: ConfigDiagnostic): ConfigDiagnostic {
  const { configPath: _configPath, ...publicDiagnostic } = diagnostic;
  return publicDiagnostic;
}
