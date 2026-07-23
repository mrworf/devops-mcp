import { z } from "zod";

export const emptyInputValidator = z.strictObject({});
export const gatewayServiceReferencesInputValidator = z.strictObject({
  service: z.string(),
  destination: z.string().optional(),
  access_ids: z.array(z.string()),
  reason: z.string(),
});
export const describeServicePolicyInputValidator = z.strictObject({ service: z.string() });
export const serviceRequestInputValidator = z.strictObject({
  service: z.string(),
  destination: z.string().optional(),
  method: z.string(),
  path: z.string().optional(),
  url: z.string().optional(),
  service_reference: z.string().optional(),
  headers: z.record(z.string(), z.string()).optional(),
  query: z.record(z.string(), z.unknown()).optional(),
  body: z.unknown().optional(),
  reason: z.string(),
});
export const explainDenialInputValidator = z.strictObject({ request_id: z.string() });

function advertisedInputSchema(schema: z.ZodType): Record<string, unknown> {
  return z.toJSONSchema(schema, { target: "draft-7", unrepresentable: "any" }) as Record<string, unknown>;
}

export const emptyInputSchema = advertisedInputSchema(emptyInputValidator);

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

export const gatewayServiceReferencesInputSchema = advertisedInputSchema(gatewayServiceReferencesInputValidator);

export const describeServicePolicyInputSchema = advertisedInputSchema(describeServicePolicyInputValidator);

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

export const serviceRequestInputSchema = advertisedInputSchema(serviceRequestInputValidator);

export const serviceRequestOutputSchema = {
  type: "object",
  properties: {
    request_id: { type: "string" },
    status_code: { type: "number" },
    headers: { type: "object" },
    body: {},
    body_encoding: { type: "string", enum: ["utf8", "mcp_blob"] },
    body_size_bytes: { type: "number" },
    body_sha256: { type: "string" },
    secret_tokenized: { type: "boolean" },
    secret_tokenization_count: { type: "number" },
    tls: { type: "object" },
    truncated: { type: "boolean" },
  },
  required: [
    "request_id", "status_code", "headers", "body", "body_encoding", "body_size_bytes", "body_sha256",
    "secret_tokenized", "secret_tokenization_count", "tls", "truncated",
  ],
  additionalProperties: false,
} as const;

export const explainDenialInputSchema = advertisedInputSchema(explainDenialInputValidator);

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
