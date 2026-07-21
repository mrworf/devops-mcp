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
      items: {
        type: "object",
        properties: {
          access_methods: {
            type: "array",
            items: {
              type: "object",
              properties: {
                id: { type: "string" },
                usage_hint: { type: "string" },
              },
              required: ["id", "usage_hint"],
              additionalProperties: false,
            },
          },
        },
        required: ["access_methods"],
      },
    },
  },
  required: ["services"],
  additionalProperties: false,
} as const;

export const gatewayServiceReferencesInputSchema = {
  type: "object",
  properties: {
    service: { type: "string" },
    destination: { type: "string" },
    access_ids: {
      type: "array",
      items: { type: "string" },
    },
    reason: { type: "string" },
  },
  required: ["service", "access_ids", "reason"],
  additionalProperties: false,
} as const;

export const describeServicePolicyInputSchema = {
  type: "object",
  properties: {
    service: { type: "string" },
  },
  required: ["service"],
  additionalProperties: false,
} as const;

export const describeServicePolicyOutputSchema = {
  type: "object",
  properties: {
    id: { type: "string" },
    name: { type: "string" },
    description: { type: "string" },
    api_docs_url: { type: "string" },
    destinations: {
      type: "array",
      items: { type: "object" },
    },
    access_methods: {
      type: "array",
      items: { type: "object" },
    },
    policy: { type: "object" },
  },
  required: ["id", "name", "destinations", "access_methods", "policy"],
  additionalProperties: false,
} as const;

export const gatewayServiceReferencesOutputSchema = {
  type: "object",
  properties: {
    references: {
      type: "array",
      items: {
        type: "object",
        properties: {
          access_id: { type: "string" },
          reference: { type: "string" },
          usage_hint: { type: "string" },
          expires_at: { type: "string" },
          exportable: { type: "boolean", const: false },
          usable_outside_gateway: { type: "boolean", const: false },
          reveals_protected_value: { type: "boolean", const: false },
        },
        required: [
          "access_id",
          "reference",
          "usage_hint",
          "expires_at",
          "exportable",
          "usable_outside_gateway",
          "reveals_protected_value",
        ],
        additionalProperties: false,
      },
    },
  },
  required: ["references"],
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
    service_reference: { type: "string" },
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
    secret_tokenized: { type: "boolean" },
    secret_tokenization_count: { type: "number" },
    tls: { type: "object" },
    truncated: { type: "boolean" },
  },
  required: ["request_id", "status_code", "headers", "body", "secret_tokenized", "secret_tokenization_count", "tls", "truncated"],
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
