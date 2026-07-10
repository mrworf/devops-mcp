import type { ToolResult } from "./results.js";
import { toolError } from "./results.js";
import {
  emptyInputSchema,
  errorOutputSchema,
  explainDenialInputSchema,
  explainDenialOutputSchema,
  listServicesOutputSchema,
  requestTokensInputSchema,
  requestTokensOutputSchema,
  serviceRequestInputSchema,
  serviceRequestOutputSchema,
} from "./schemas.js";

export interface SecurityScheme {
  type: "oauth2";
  scopes: string[];
}

export interface ToolDescriptor {
  name: string;
  title: string;
  description: string;
  inputSchema: Record<string, unknown>;
  outputSchema: Record<string, unknown>;
  securitySchemes: SecurityScheme[];
  annotations: {
    readOnlyHint: boolean;
    destructiveHint: boolean;
    openWorldHint: boolean;
    idempotentHint?: boolean;
  };
  _meta: {
    securitySchemes: SecurityScheme[];
    "openai/toolInvocation/invoking": string;
    "openai/toolInvocation/invoked": string;
  };
}

const readSecurity = [{ type: "oauth2" as const, scopes: ["gateway.read"] }];
const tokenSecurity = [{ type: "oauth2" as const, scopes: ["gateway.tokens"] }];
const requestSecurity = [{ type: "oauth2" as const, scopes: ["gateway.request"] }];

export const toolDescriptors: ToolDescriptor[] = [
  {
    name: "list_services",
    title: "List configured services",
    description: "List the HTTP services this authenticated user can access through the gateway. Does not return raw credentials.",
    inputSchema: emptyInputSchema,
    outputSchema: listServicesOutputSchema,
    securitySchemes: readSecurity,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
      idempotentHint: true,
    },
    _meta: {
      securitySchemes: readSecurity,
      "openai/toolInvocation/invoking": "Listing services",
      "openai/toolInvocation/invoked": "Services listed",
    },
  },
  {
    name: "request_tokens",
    title: "Request credential tokens",
    description: "Request temporary opaque tokens for a configured service credential. Tokens are not raw credentials and only work through this gateway.",
    inputSchema: requestTokensInputSchema,
    outputSchema: requestTokensOutputSchema,
    securitySchemes: tokenSecurity,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: false,
      idempotentHint: false,
    },
    _meta: {
      securitySchemes: tokenSecurity,
      "openai/toolInvocation/invoking": "Issuing tokens",
      "openai/toolInvocation/invoked": "Tokens issued",
    },
  },
  {
    name: "service_request",
    title: "Send service HTTP request",
    description: "Send an HTTP request to a configured service through the gateway. Opaque tokens in headers, query, or body are replaced with real credentials only after authorization and policy checks.",
    inputSchema: serviceRequestInputSchema,
    outputSchema: serviceRequestOutputSchema,
    securitySchemes: requestSecurity,
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      openWorldHint: true,
      idempotentHint: false,
    },
    _meta: {
      securitySchemes: requestSecurity,
      "openai/toolInvocation/invoking": "Sending service request",
      "openai/toolInvocation/invoked": "Service response received",
    },
  },
  {
    name: "explain_denial",
    title: "Explain denied request",
    description: "Explain why a gateway request was denied, including matched policy rule and suggested next step if available.",
    inputSchema: explainDenialInputSchema,
    outputSchema: explainDenialOutputSchema,
    securitySchemes: readSecurity,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
      idempotentHint: true,
    },
    _meta: {
      securitySchemes: readSecurity,
      "openai/toolInvocation/invoking": "Checking denial",
      "openai/toolInvocation/invoked": "Denial explained",
    },
  },
];

export function callStubTool(name: string): ToolResult {
  const descriptor = toolDescriptors.find((tool) => tool.name === name);
  if (!descriptor) {
    return toolError("not_implemented", `Tool ${name} is not available.`);
  }
  return toolError("not_implemented", `${descriptor.name} is registered but not implemented in this milestone.`);
}
