const httpBasicCredentialPattern = /\bBasic +(?<encoded>(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)(?![A-Za-z0-9+/=])/gi;

export interface HttpBasicCredentialRange {
  start: number;
  end: number;
}

export function findHttpBasicCredentialRanges(text: string): HttpBasicCredentialRange[] {
  const ranges: HttpBasicCredentialRange[] = [];
  for (const match of text.matchAll(httpBasicCredentialPattern)) {
    const encoded = match.groups?.encoded;
    if (!encoded || !isValidHttpBasic(encoded)) continue;
    ranges.push({ start: match.index, end: match.index + match[0].length });
  }
  return ranges;
}

function isValidHttpBasic(encoded: string): boolean {
  const decoded = Buffer.from(encoded, "base64");
  if (decoded.toString("base64") !== encoded) return false;
  const separator = decoded.indexOf(0x3a);
  return separator > 0 && separator < decoded.length - 1;
}
