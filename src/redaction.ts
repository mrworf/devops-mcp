export interface ResponseToRedact {
  headers: Record<string, string>;
  body: string;
}

export interface RedactedResponse {
  headers: Record<string, string>;
  body: string;
  redacted: boolean;
  redaction_count: number;
}

export function redactResponse(response: ResponseToRedact, credentials: string[]): RedactedResponse {
  let count = 0;
  let body = response.body;
  const headers = { ...response.headers };

  for (const secret of credentials.filter(Boolean)) {
    for (const value of [secret, jsonEscaped(secret)]) {
      for (const key of Object.keys(headers)) {
        const current = headers[key] ?? "";
        const next = replaceAllCounted(current, value);
        headers[key] = next.value;
        count += next.count;
      }
      const nextBody = replaceAllCounted(body, value);
      body = nextBody.value;
      count += nextBody.count;
    }
  }

  return {
    headers,
    body,
    redacted: count > 0,
    redaction_count: count,
  };
}

function jsonEscaped(value: string): string {
  return JSON.stringify(value).slice(1, -1);
}

function replaceAllCounted(input: string, needle: string): { value: string; count: number } {
  if (!needle || !input.includes(needle)) return { value: input, count: 0 };
  const parts = input.split(needle);
  return { value: parts.join("[REDACTED]"), count: parts.length - 1 };
}
