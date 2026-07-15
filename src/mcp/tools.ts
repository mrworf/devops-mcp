import type { ToolResult } from "./results.js";
import { toolError, toolSuccess } from "./results.js";
import { audit } from "../audit.js";
import { describeServicePolicy, listVisibleServices } from "../registry.js";
import type { AuthContext, GatewayConfig } from "../types.js";
import { getTokenBroker, type TokenRequestInput } from "../tokens.js";
import { GatewayError } from "../errors.js";
import { executeServiceRequest, type ServiceRequestInput } from "../gateway.js";
import { explainDenial } from "../denials.js";
import {
  emptyInputSchema,
  describeServicePolicyInputSchema,
  describeServicePolicyOutputSchema,
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
    name: "describe_service_policy",
    title: "Describe service policy",
    description: "Describe the configured destinations, credential usage hints, and ordered allow/deny policy rules for a service this authenticated user can access. Does not return raw credentials.",
    inputSchema: describeServicePolicyInputSchema,
    outputSchema: describeServicePolicyOutputSchema,
    securitySchemes: readSecurity,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
      idempotentHint: true,
    },
    _meta: {
      securitySchemes: readSecurity,
      "openai/toolInvocation/invoking": "Describing service policy",
      "openai/toolInvocation/invoked": "Service policy described",
    },
  },
  {
    name: "service_request",
    title: "Send service HTTP request",
    description: "Send an HTTP request to a configured service through the gateway. Opaque tokens in headers, query, or body are replaced only after authorization and policy checks; detected response secrets are returned as sec_ tokens. Cookie headers are not supported.",
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

export async function callTool(
  name: string,
  args: Record<string, unknown> | undefined,
  config: GatewayConfig,
  auth: AuthContext,
): Promise<ToolResult> {
  const descriptor = toolDescriptors.find((tool) => tool.name === name);
  if (!descriptor) {
    return toolError("not_implemented", `Tool ${name} is not available.`);
  }
  try {
    if (name === "list_services") {
      const services = listVisibleServices(config, auth);
      auditTool(config, auth, name, "allow");
      return toolSuccess({ services }, `Found ${services.length} configured service(s).`);
    }
    if (name === "request_tokens") {
      const input = parseTokenRequest(args);
      const result = getTokenBroker(config).issueTokens(auth, input);
      auditTool(config, auth, name, "allow", { service: input.service });
      return toolSuccess({ tokens: result.tokens }, `Issued ${result.tokens.length} opaque token(s).`);
    }
    if (name === "describe_service_policy") {
      const service = readString(args ?? {}, "service");
      const description = describeServicePolicy(config, auth, service);
      auditTool(config, auth, name, "allow", { service });
      return toolSuccess(description as unknown as Record<string, unknown>, `Policy for ${service} described.`);
    }
    if (name === "service_request") {
      const input = parseServiceRequest(args);
      const result = await executeServiceRequest(config, auth, input);
      auditTool(config, auth, name, "allow", { service: input.service, request_id: result.request_id });
      return toolSuccess(result as unknown as Record<string, unknown>, `Request ${result.request_id} completed with HTTP ${result.status_code}.`);
    }
    if (name === "explain_denial") {
      const requestId = readString(args ?? {}, "request_id");
      const explanation = explainDenial(auth, requestId);
      if (explanation === undefined) {
        auditTool(config, auth, name, "deny", { request_id: requestId, error_code: "unknown_service" });
        return toolError("unknown_service", "No denial context found for this request.");
      }
      auditTool(config, auth, name, "allow", { request_id: requestId });
      return toolSuccess(explanation as unknown as Record<string, unknown>, `Denial ${requestId} explained.`);
    }
  } catch (error) {
    if (error instanceof GatewayError) {
      auditTool(config, auth, descriptor.name, "error", {
        ...(error.requestId === undefined ? {} : { request_id: error.requestId }),
        error_code: error.code,
      });
      return toolError(error.code, error.message, error.requestId);
    }
    throw error;
  }
  return toolError("not_implemented", `${descriptor.name} is registered but not implemented in this milestone.`);
}

function auditTool(
  config: GatewayConfig,
  auth: AuthContext,
  tool: ToolDescriptor["name"],
  outcome: "allow" | "deny" | "error",
  fields: { service?: string; request_id?: string; error_code?: string } = {},
): void {
  if (tool !== "list_services" && tool !== "describe_service_policy" && tool !== "request_tokens" && tool !== "service_request" && tool !== "explain_denial") return;
  audit({
    type: "tool_invocation",
    subject: auth.subject,
    ...(auth.sessionId === undefined ? {} : { session_id: auth.sessionId }),
    tool,
    outcome,
    ...fields,
    timestamp: new Date().toISOString(),
  }, config);
}

function parseTokenRequest(args: Record<string, unknown> | undefined): TokenRequestInput {
  if (args === undefined) throw new GatewayError("token_invalid", "request_tokens arguments are required.");
  const service = readString(args, "service");
  const destination = readOptionalString(args, "destination");
  const reason = readString(args, "reason");
  const credentialIds = args["credential_ids"];
  if (!Array.isArray(credentialIds) || !credentialIds.every((value) => typeof value === "string")) {
    throw new GatewayError("unknown_credential", "credential_ids must be an array of strings.");
  }
  return {
    service,
    ...(destination === undefined ? {} : { destination }),
    credential_ids: credentialIds,
    reason,
  };
}

function readString(args: Record<string, unknown>, name: string): string {
  const value = args[name];
  if (typeof value !== "string") throw new GatewayError("token_invalid", `${name} must be a string.`);
  return value;
}

function readOptionalString(args: Record<string, unknown>, name: string): string | undefined {
  const value = args[name];
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw new GatewayError("token_invalid", `${name} must be a string.`);
  return value;
}

function parseServiceRequest(args: Record<string, unknown> | undefined): ServiceRequestInput {
  if (args === undefined) throw new GatewayError("destination_not_allowed", "service_request arguments are required.");
  const service = readString(args, "service");
  const destination = readOptionalString(args, "destination");
  const method = readString(args, "method");
  const path = readOptionalString(args, "path");
  const url = readOptionalString(args, "url");
  const reason = readString(args, "reason");
  const headers = readOptionalStringMap(args, "headers");
  const query = readOptionalRecord(args, "query");
  return {
    service,
    ...(destination === undefined ? {} : { destination }),
    method,
    ...(path === undefined ? {} : { path }),
    ...(url === undefined ? {} : { url }),
    ...(headers === undefined ? {} : { headers }),
    ...(query === undefined ? {} : { query }),
    ...(args["body"] === undefined ? {} : { body: args["body"] }),
    reason,
  };
}

function readOptionalStringMap(args: Record<string, unknown>, name: string): Record<string, string> | undefined {
  const value = args[name];
  if (value === undefined) return undefined;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new GatewayError("destination_not_allowed", `${name} must be an object.`);
  }
  const entries = Object.entries(value);
  if (!entries.every(([, item]) => typeof item === "string")) {
    throw new GatewayError("destination_not_allowed", `${name} values must be strings.`);
  }
  return Object.fromEntries(entries) as Record<string, string>;
}

function readOptionalRecord(args: Record<string, unknown>, name: string): Record<string, unknown> | undefined {
  const value = args[name];
  if (value === undefined) return undefined;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new GatewayError("destination_not_allowed", `${name} must be an object.`);
  }
  return value as Record<string, unknown>;
}
