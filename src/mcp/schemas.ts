export const emptyInputSchema = {
  type: "object",
  properties: {},
  additionalProperties: false,
} as const;

export const errorOutputSchema = {
  type: "object",
  properties: {
    error: {
      type: "object",
      properties: {
        code: { type: "string" },
        message: { type: "string" },
        request_id: { type: "string" },
      },
      required: ["code", "message"],
      additionalProperties: false,
    },
  },
  required: ["error"],
  additionalProperties: false,
} as const;

export const listServicesOutputSchema = {
  type: "object",
  properties: {
    services: {
      type: "array",
      items: { type: "object" },
    },
  },
  required: ["services"],
  additionalProperties: false,
} as const;

export const requestTokensInputSchema = {
  type: "object",
  properties: {
    service: { type: "string" },
    destination: { type: "string" },
    credential_ids: {
      type: "array",
      items: { type: "string" },
    },
    reason: { type: "string" },
  },
  required: ["service", "credential_ids", "reason"],
  additionalProperties: false,
} as const;

export const requestTokensOutputSchema = {
  type: "object",
  properties: {
    tokens: {
      type: "array",
      items: { type: "object" },
    },
  },
  required: ["tokens"],
  additionalProperties: false,
} as const;

export const serviceRequestInputSchema = {
  type: "object",
  properties: {
    service: { type: "string" },
    destination: { type: "string" },
    method: { type: "string" },
    path: { type: "string" },
    url: { type: "string" },
    headers: { type: "object", additionalProperties: { type: "string" } },
    query: { type: "object" },
    body: {},
    reason: { type: "string" },
  },
  required: ["service", "method", "reason"],
  additionalProperties: false,
} as const;

export const serviceRequestOutputSchema = {
  type: "object",
  properties: {
    request_id: { type: "string" },
    status_code: { type: "number" },
    headers: { type: "object" },
    body: {},
    redacted: { type: "boolean" },
    redaction_count: { type: "number" },
    tls: { type: "object" },
    truncated: { type: "boolean" },
  },
  required: ["request_id", "status_code", "headers", "body", "redacted", "redaction_count", "tls", "truncated"],
  additionalProperties: false,
} as const;

export const explainDenialInputSchema = {
  type: "object",
  properties: {
    request_id: { type: "string" },
  },
  required: ["request_id"],
  additionalProperties: false,
} as const;

export const explainDenialOutputSchema = {
  type: "object",
  properties: {
    request_id: { type: "string" },
    reason: { type: "string" },
    matched_rule: { type: "string" },
    policy_mode: { type: "string" },
    suggestion: { type: "string" },
  },
  required: ["request_id", "reason", "policy_mode"],
  additionalProperties: false,
} as const;
