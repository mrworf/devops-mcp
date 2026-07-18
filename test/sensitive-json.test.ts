import { describe, expect, it } from "vitest";
import { findCompleteJsonStringRanges, findSensitiveJsonValues } from "../src/sensitiveJson.js";
import { loadSensitiveNameConfig, SensitiveNameMatcher } from "../src/sensitiveNames.js";

const matcher = new SensitiveNameMatcher(loadSensitiveNameConfig(new URL("../config/sensitive-names.yaml", import.meta.url).pathname));

describe("tolerant sensitive JSON scanning", () => {
  it("finds direct, duplicate, name/value, and environment-string values without normalizing source", () => {
    const source = `{ /* keep */
 "SECRETSAUCE_OAUTH_SIGNING_KEY_PEM_B64" : "pem-key"
 "duplicate_password":"first", "duplicate_password" : "second",
 "public_key":"visible", "token_type":"Bearer", "empty_password":"", "password_count":2,
 "nested":{"clientSecret":"nested-secret"},
 "environment":[
   {"value":"admin-hash", "name":"SECRETSAUCE_ADMIN_PASSWORD_HASH_B64"},
   {"key":"SECRETSAUCE_OAUTH_SIGNING_KEY_PEM_B64", "extra":true, "value":"signing-key"},
   "SECRETSAUCE_ADMIN_PASSWORD_HASH_B64=array-hash",
   {"name":"safe_name", "value":"visible"}
 ]`;

    const findings = findSensitiveJsonValues(source, matcher);
    expect(findings.map((finding) => finding.secretValue)).toEqual([
      "pem-key", "first", "second", "nested-secret", "admin-hash", "signing-key", "array-hash",
    ]);
    expect(findings.flatMap((finding) => finding.ruleIds)).toEqual(expect.arrayContaining([
      "gateway:sensitive-name:keys", "gateway:sensitive-name:passwords", "gateway:sensitive-name:secrets",
    ]));

    for (const finding of findings) expect(source.slice(finding.start, finding.end)).toBe(finding.secretValue);
    const transformed = expectOutsideRangesPreserved(source, findings);
    expect(transformed).toContain('"public_key":"visible"');
    expect(transformed).toContain('"empty_password":""');
  });

  it("requires unambiguous environment objects and complete non-empty string values", () => {
    const source = `[
      {"name":"admin_password", "key":"signing_key", "value":"visible"},
      {"name":"admin_password", "value":"one", "value":"two"},
      {"name":"admin_password", "value":false},
      "admin_password=",
      "PAYLOAD_B64=visible"
    ]`;
    expect(findSensitiveJsonValues(source, matcher)).toEqual([]);
  });

  it("fails closed when a recognized sensitive string value has no safe closing range", () => {
    for (const source of [
      '{"password":"unterminated',
      '{"password":',
      '{"name":"admin_password","value":"unterminated',
      '["SECRETSAUCE_ADMIN_PASSWORD_HASH_B64=unterminated',
    ]) {
      expect(() => findSensitiveJsonValues(source, matcher)).toThrowError(expect.objectContaining({ code: "secret_scan_failed" }));
    }
    expect(findSensitiveJsonValues('{"password":123', matcher)).toEqual([]);
  });

  it("reports only complete JSON string source ranges", () => {
    const source = '{"key":"value", /* gap */ "broken":"unfinished';
    expect(findCompleteJsonStringRanges(source)).toEqual([
      { start: 2, end: 5, isPropertyName: true },
      { start: 8, end: 13, isPropertyName: false },
      { start: 27, end: 33, isPropertyName: true },
    ]);
  });
});

function expectOutsideRangesPreserved(
  source: string,
  findings: Array<{ start: number; end: number }>,
): string {
  const sorted = [...findings].sort((left, right) => left.start - right.start);
  const markers = sorted.map((_, index) => `<token-${index}>`);
  let transformed = "";
  let sourceCursor = 0;
  for (const [index, finding] of sorted.entries()) {
    transformed += source.slice(sourceCursor, finding.start) + markers[index];
    sourceCursor = finding.end;
  }
  transformed += source.slice(sourceCursor);

  sourceCursor = 0;
  let transformedCursor = 0;
  for (const [index, finding] of sorted.entries()) {
    const outside = source.slice(sourceCursor, finding.start);
    expect(transformed.slice(transformedCursor, transformedCursor + outside.length)).toBe(outside);
    transformedCursor += outside.length;
    expect(transformed.slice(transformedCursor, transformedCursor + markers[index]!.length)).toBe(markers[index]);
    transformedCursor += markers[index]!.length;
    sourceCursor = finding.end;
  }
  expect(transformed.slice(transformedCursor)).toBe(source.slice(sourceCursor));
  return transformed;
}
