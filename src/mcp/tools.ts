import type { ToolResult } from "./results.js";
import { toolError, toolSuccess } from "./results.js";
import { audit } from "../audit.js";
import { describeServicePolicy, listVisibleServices } from "../registry.js";
import type { AuthContext, GatewayConfig } from "../types.js";
import type { TokenRequestInput } from "../tokens.js";
import { GatewayError } from "../errors.js";
import { executeServiceRequest, type ServiceRequestInput } from "../gateway.js";
import { explainDenial } from "../denials.js";
import { createRequestDependencies, type RequestDependencies } from "../requestDependencies.js";
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
  emptyInputValidator,
  gatewayServiceReferencesInputValidator,
  describeServicePolicyInputValidator,
  serviceRequestInputValidator,
  explainDenialInputValidator,
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

type ToolHandler = (
  args: Record<string, unknown> | undefined,
  config: GatewayConfig,
  auth: AuthContext,
  dependencies: RequestDependencies,
) => Promise<ToolResult>;

export interface ToolContract extends ToolDescriptor {
  requiredScope: "gateway.read" | "gateway.references" | "gateway.request";
  handler: ToolHandler;
}

const READ_SCOPE = "gateway.read" as const;
const REFERENCE_SCOPE = "gateway.references" as const;
const REQUEST_SCOPE = "gateway.request" as const;
const readSecurity = [{ type: "oauth2" as const, scopes: [READ_SCOPE] }];
const referenceSecurity = [{ type: "oauth2" as const, scopes: [REFERENCE_SCOPE] }];
const requestSecurity = [{ type: "oauth2" as const, scopes: [REQUEST_SCOPE] }];

export const toolContracts: ToolContract[] = [
  {
    name: "list_services",
    requiredScope: READ_SCOPE,
    handler: handleListServices,
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
    requiredScope: REFERENCE_SCOPE,
    handler: handleGatewayServiceReferences,
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
    requiredScope: READ_SCOPE,
    handler: handleDescribeServicePolicy,
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
    requiredScope: REQUEST_SCOPE,
    handler: handleServiceRequest,
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
    requiredScope: READ_SCOPE,
    handler: handleExplainDenial,
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

export const toolDescriptors: ToolDescriptor[] = toolContracts.map(({ requiredScope: _requiredScope, handler: _handler, ...descriptor }) => descriptor);

export function requiredScopeForTool(name: unknown): ToolContract["requiredScope"] | undefined {
  return typeof name === "string" ? toolContracts.find((tool) => tool.name === name)?.requiredScope : undefined;
}

export async function callTool(
  name: string,
  args: Record<string, unknown> | undefined,
  config: GatewayConfig,
  auth: AuthContext,
  dependencies: RequestDependencies = createRequestDependencies(config),
): Promise<ToolResult> {
  const contract = toolContracts.find((tool) => tool.name === name);
  if (!contract) {
    return toolError("not_implemented", `Tool ${name} is not available.`);
  }
  try {
    return await contract.handler(args, config, auth, dependencies);
  } catch (error) {
    if (error instanceof GatewayError) {
      auditTool(auth, contract.name, "error", {
        ...(error.requestId === undefined ? {} : { request_id: error.requestId }),
        error_code: error.code,
      }, dependencies.auditSink);
      return toolError(error.code, error.message, error.requestId);
    }
    throw error;
  }
}

async function handleListServices(
  args: Record<string, unknown> | undefined, config: GatewayConfig, auth: AuthContext, dependencies: RequestDependencies,
): Promise<ToolResult> {
  parseEmptyInput(args);
  const services = listVisibleServices(config, auth);
  auditTool(auth, "list_services", "allow", {}, dependencies.auditSink);
  return toolSuccess({ services }, `Found ${services.length} configured service(s).`);
}

async function handleGatewayServiceReferences(
  args: Record<string, unknown> | undefined, _config: GatewayConfig, auth: AuthContext, dependencies: RequestDependencies,
): Promise<ToolResult> {
  const input = parseServiceReferenceRequest(args);
  const result = dependencies.capabilities.tokenBroker.issueTokens(auth, input);
  auditTool(auth, "get_gateway_service_references", "allow", { service: input.service }, dependencies.auditSink);
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

async function handleDescribeServicePolicy(
  args: Record<string, unknown> | undefined, config: GatewayConfig, auth: AuthContext, dependencies: RequestDependencies,
): Promise<ToolResult> {
  const service = parseSingleStringInput(args, "service");
  const description = describeServicePolicy(config, auth, service);
  auditTool(auth, "describe_service_policy", "allow", { service }, dependencies.auditSink);
  return toolSuccess(description as unknown as Record<string, unknown>, `Policy for ${service} described.`);
}

async function handleServiceRequest(
  args: Record<string, unknown> | undefined, config: GatewayConfig, auth: AuthContext, dependencies: RequestDependencies,
): Promise<ToolResult> {
  const input = parseServiceRequest(args);
  const result = await executeServiceRequest(config, auth, input, dependencies);
  auditTool(auth, "service_request", "allow", { service: input.service, request_id: result.request_id }, dependencies.auditSink);
  const { binaryBody, binaryMimeType, ...structured } = result;
  const binaryContent = binaryBody === undefined || binaryMimeType === undefined
    ? []
    : [{
      type: "resource" as const,
      resource: {
        uri: `secretsauce://response/${result.request_id}`,
        mimeType: binaryMimeType,
        blob: binaryBody.toString("base64"),
      },
    }];
  return toolSuccess(
    structured as unknown as Record<string, unknown>,
    `Request ${result.request_id} completed with HTTP ${result.status_code}.`,
    undefined,
    binaryContent,
  );
}

async function handleExplainDenial(
  args: Record<string, unknown> | undefined, _config: GatewayConfig, auth: AuthContext, dependencies: RequestDependencies,
): Promise<ToolResult> {
  const requestId = parseSingleStringInput(args, "request_id");
  const explanation = explainDenial(dependencies.capabilities.denialStore, auth, requestId);
  if (explanation === undefined) {
    auditTool(auth, "explain_denial", "deny", { request_id: requestId, error_code: "unknown_service" }, dependencies.auditSink);
    return toolError("unknown_service", "No denial context found for this request.");
  }
  auditTool(auth, "explain_denial", "allow", { request_id: requestId }, dependencies.auditSink);
  return toolSuccess(explanation as unknown as Record<string, unknown>, `Denial ${requestId} explained.`);
}

function auditTool(
  auth: AuthContext,
  tool: ToolDescriptor["name"],
  outcome: "allow" | "deny" | "error",
  fields: { service?: string; request_id?: string; error_code?: string } = {},
  auditSink?: import("../audit.js").AuditSink,
): void {
  if (tool !== "list_services" && tool !== "describe_service_policy" && tool !== "get_gateway_service_references" && tool !== "service_request" && tool !== "explain_denial") return;
  audit({
    type: "tool_invocation",
    subject: auth.subject,
    tool,
    outcome,
    ...fields,
    timestamp: new Date().toISOString(),
  }, auditSink);
}

function parseServiceReferenceRequest(args: Record<string, unknown> | undefined): TokenRequestInput {
  if (args === undefined) throw new GatewayError("reference_invalid", "get_gateway_service_references arguments are required.");
  const parsed = gatewayServiceReferencesInputValidator.safeParse(args);
  if (!parsed.success) {
    const accessIdsInvalid = parsed.error.issues.some((issue) => issue.path[0] === "access_ids");
    throw new GatewayError(
      accessIdsInvalid ? "unknown_access" : "reference_invalid",
      accessIdsInvalid ? "access_ids must be an array of strings." : "Invalid get_gateway_service_references arguments.",
    );
  }
  return {
    service: parsed.data.service,
    ...(parsed.data.destination === undefined ? {} : { destination: parsed.data.destination }),
    access_ids: parsed.data.access_ids,
    reason: parsed.data.reason,
  };
}

function parseServiceRequest(args: Record<string, unknown> | undefined): ServiceRequestInput {
  if (args === undefined) throw new GatewayError("destination_not_allowed", "service_request arguments are required.");
  const parsed = serviceRequestInputValidator.safeParse(args);
  if (parsed.success) {
    const value = parsed.data;
    return {
      service: value.service,
      ...(value.destination === undefined ? {} : { destination: value.destination }),
      method: value.method,
      ...(value.path === undefined ? {} : { path: value.path }),
      ...(value.url === undefined ? {} : { url: value.url }),
      ...(value.service_reference === undefined ? {} : { service_reference: value.service_reference }),
      ...(value.headers === undefined ? {} : { headers: value.headers }),
      ...(value.query === undefined ? {} : { query: value.query }),
      ...(value.body === undefined ? {} : { body: value.body }),
      reason: value.reason,
    };
  }
  const destinationShapeInvalid = parsed.error.issues.some((issue) => issue.path[0] === "headers" || issue.path[0] === "query");
  throw new GatewayError(
    destinationShapeInvalid ? "destination_not_allowed" : "reference_invalid",
    destinationShapeInvalid ? "headers and query must use their advertised object shapes." : "Invalid service_request arguments.",
  );
}

function parseEmptyInput(args: Record<string, unknown> | undefined): void {
  if (!emptyInputValidator.safeParse(args ?? {}).success) {
    throw new GatewayError("reference_invalid", "list_services does not accept arguments.");
  }
}

function parseSingleStringInput(
  args: Record<string, unknown> | undefined,
  field: "service" | "request_id",
): string {
  const schema = field === "service" ? describeServicePolicyInputValidator : explainDenialInputValidator;
  const parsed = schema.safeParse(args ?? {});
  if (!parsed.success) throw new GatewayError("reference_invalid", `${field} must be a string.`);
  return field === "service" ? (parsed.data as { service: string }).service : (parsed.data as { request_id: string }).request_id;
}
