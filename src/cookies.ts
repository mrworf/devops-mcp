const prohibitedCookieHeaders = new Set(["cookie", "cookie2", "set-cookie", "set-cookie2"]);

export function prohibitedCookieHeaderNames(headers: Record<string, unknown>): string[] {
  return Object.keys(headers).filter((name) => prohibitedCookieHeaders.has(name.toLowerCase())).map((name) => name.toLowerCase()).sort();
}

export function stripCookieHeaders(headers: Record<string, string>): { headers: Record<string, string>; removed: string[] } {
  const removed = prohibitedCookieHeaderNames(headers);
  return {
    headers: Object.fromEntries(Object.entries(headers).filter(([name]) => !prohibitedCookieHeaders.has(name.toLowerCase()))),
    removed,
  };
}
