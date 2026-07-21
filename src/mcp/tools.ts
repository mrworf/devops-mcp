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
  gatewayServiceReferencesInputSchema,
  gatewayServiceReferencesOutputSchema,
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
const referenceSecurity = [{ type: "oauth2" as const, scopes: ["gateway.references"] }];
const requestSecurity = [{ type: "oauth2" as const, scopes: ["gateway.request"] }];

export const toolDescriptors: ToolDescriptor[] = [
  {
    name: "list_services",
    title: "List configured services",
    description: "List the HTTP services and access methods available to this authenticated user through the gateway. Never returns protected backend values.",
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
    name: "get_gateway_service_references",
    title: "Get gateway service references",
    description: "Get short-lived gref_ references for configured service access. Protected values remain on the gateway: references cannot reveal or export them, have no meaning outside this gateway, and creating a reference does not contact or modify the downstream service.",
    inputSchema: gatewayServiceReferencesInputSchema,
    outputSchema: gatewayServiceReferencesOutputSchema,
    securitySchemes: referenceSecurity,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: false,
      idempotentHint: false,
    },
    _meta: {
      securitySchemes: referenceSecurity,
      "openai/toolInvocation/invoking": "Getting service references",
      "openai/toolInvocation/invoked": "Service references ready",
    },
  },
  {
    name: "describe_service_policy",
    title: "Describe service policy",
    description: "Describe configured destinations, service access methods, and ordered allow/deny policy rules for a service this authenticated user can access. Never returns protected backend values.",
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
    description: "Send an HTTP request through the gateway. The backend resolves gateway references only after authorization, destination, reference-binding, and policy checks. Pass a gateway_access reference in service_reference; that gateway-only field is never forwarded downstream. Before the response reaches the agent, the backend scans it and replaces detected secrets with subject- and service-bound sec_ references. Cookie headers are not supported.",
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
    if (name === "get_gateway_service_references") {
      const input = parseServiceReferenceRequest(args);
      const result = getTokenBroker(config).issueTokens(auth, input);
      auditTool(config, auth, name, "allow", { service: input.service });
      const references = result.tokens.map((item) => ({
        access_id: item.credential_id,
        reference: item.token,
        usage_hint: item.usage_hint,
        expires_at: item.expires_at,
        exportable: false,
        usable_outside_gateway: false,
        reveals_protected_value: false,
      }));
      return toolSuccess({ references }, `Prepared ${references.length} gateway service reference(s).`);
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
      const explanation = explainDenial(config, auth, requestId);
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
  if (tool !== "list_services" && tool !== "describe_service_policy" && tool !== "get_gateway_service_references" && tool !== "service_request" && tool !== "explain_denial") return;
  audit({
    type: "tool_invocation",
    subject: auth.subject,
    tool,
    outcome,
    ...fields,
    timestamp: new Date().toISOString(),
  }, config);
}

function parseServiceReferenceRequest(args: Record<string, unknown> | undefined): TokenRequestInput {
  if (args === undefined) throw new GatewayError("reference_invalid", "get_gateway_service_references arguments are required.");
  const service = readString(args, "service");
  const destination = readOptionalString(args, "destination");
  const reason = readString(args, "reason");
  const accessIds = args["access_ids"];
  if (!Array.isArray(accessIds) || !accessIds.every((value) => typeof value === "string")) {
    throw new GatewayError("unknown_access", "access_ids must be an array of strings.");
  }
  return {
    service,
    ...(destination === undefined ? {} : { destination }),
    access_ids: accessIds,
    reason,
  };
}

function readString(args: Record<string, unknown>, name: string): string {
  const value = args[name];
  if (typeof value !== "string") throw new GatewayError("reference_invalid", `${name} must be a string.`);
  return value;
}

function readOptionalString(args: Record<string, unknown>, name: string): string | undefined {
  const value = args[name];
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw new GatewayError("reference_invalid", `${name} must be a string.`);
  return value;
}

function parseServiceRequest(args: Record<string, unknown> | undefined): ServiceRequestInput {
  if (args === undefined) throw new GatewayError("destination_not_allowed", "service_request arguments are required.");
  const service = readString(args, "service");
  const destination = readOptionalString(args, "destination");
  const method = readString(args, "method");
  const path = readOptionalString(args, "path");
  const url = readOptionalString(args, "url");
  const serviceReference = readOptionalString(args, "service_reference");
  const reason = readString(args, "reason");
  const headers = readOptionalStringMap(args, "headers");
  const query = readOptionalRecord(args, "query");
  return {
    service,
    ...(destination === undefined ? {} : { destination }),
    method,
    ...(path === undefined ? {} : { path }),
    ...(url === undefined ? {} : { url }),
    ...(serviceReference === undefined ? {} : { service_reference: serviceReference }),
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
