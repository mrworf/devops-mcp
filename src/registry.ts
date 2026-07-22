import { GatewayError } from "./errors.js";
import type { AuthContext, CredentialConfig, GatewayConfig, PolicyRuleConfig, ServiceConfig } from "./types.js";
import { resolveDestinationTarget, type ResolvedTarget, type TargetInput } from "./urlValidation.js";

export const GATEWAY_ACCESS_ID = "gateway_access";
export const GATEWAY_ACCESS_USAGE_HINT = "Pass reference as service_reference";

export interface ServiceSummary {
  id: string;
  name: string;
  description?: string;
  api_docs_url?: string;
  destinations: Array<{
    id: string;
    base_url_hint: string;
    tls_verify: boolean;
  }>;
  access_methods: Array<{
    id: string;
    usage_hint: string;
  }>;
  policy_summary: string;
}

export interface ServicePolicyDescription {
  id: string;
  name: string;
  description?: string;
  api_docs_url?: string;
  destinations: Array<{
    id: string;
    base_url_hint: string;
    tls_verify: boolean;
  }>;
  access_methods: Array<{
    id: string;
    usage_hint: string;
  }>;
  policy: {
    mode: "allow" | "deny";
    rules: Array<{
      id: string;
      effect: "allow" | "deny";
      priority: number;
      methods: string[];
      hosts: string[];
      paths: string[];
      reason?: string;
      binary_response: { scan: boolean; max_size_bytes: number | null };
    }>;
  };
}

export function listVisibleServices(config: GatewayConfig, auth: AuthContext): ServiceSummary[] {
  return Object.values(config.services)
    .filter((service) => canAccessService(service, auth))
    .map(serviceSummary);
}

export function describeServicePolicy(config: GatewayConfig, auth: AuthContext, serviceId: string): ServicePolicyDescription {
  const service = getService(config, serviceId, auth);
  return {
    id: service.id,
    name: service.name,
    ...(service.description === undefined ? {} : { description: service.description }),
    ...(service.apiDocsUrl === undefined ? {} : { api_docs_url: service.apiDocsUrl }),
    destinations: service.destinations.map((destination) => ({
      id: destination.id,
      base_url_hint: destination.baseUrl,
      tls_verify: destination.tls.verify,
    })),
    access_methods: accessMethods(service),
    policy: {
      mode: service.policy.mode,
      rules: orderedRules(service.policy.rules).map((rule) => ({
        id: rule.id,
        effect: rule.effect,
        priority: rule.priority,
        methods: rule.methods,
        hosts: rule.hosts,
        paths: rule.paths,
        binary_response: { scan: rule.binaryResponse.scan, max_size_bytes: rule.binaryResponse.maxBytes },
        ...(rule.reason === undefined ? {} : { reason: rule.reason }),
      })),
    },
  };
}

export function getService(config: GatewayConfig, serviceId: string, auth?: AuthContext): ServiceConfig {
  const service = config.services[serviceId];
  if (!service) throw new GatewayError("unknown_service", `Unknown service: ${serviceId}`);
  if (auth !== undefined && !canAccessService(service, auth)) {
    throw new GatewayError("unauthorized_service", `Not authorized for service: ${serviceId}`);
  }
  return service;
}

export function getCredential(service: ServiceConfig, credentialId: string): CredentialConfig {
  const credential = service.credentials.find((candidate) => candidate.id === credentialId);
  if (!credential) throw new GatewayError("unknown_access", `Unknown access id: ${credentialId}`);
  return credential;
}

export function resolveDestination(
  config: GatewayConfig,
  auth: AuthContext,
  serviceId: string,
  destinationId: string | undefined,
  input: TargetInput,
): ResolvedTarget {
  const service = getService(config, serviceId, auth);
  return resolveDestinationTarget(service, destinationId, input);
}

function canAccessService(service: ServiceConfig, auth: AuthContext): boolean {
  return service.access.users.includes(auth.subject);
}

function serviceSummary(service: ServiceConfig): ServiceSummary {
  const summary: ServiceSummary = {
    id: service.id,
    name: service.name,
    destinations: service.destinations.map((destination) => ({
      id: destination.id,
      base_url_hint: destination.baseUrl,
      tls_verify: destination.tls.verify,
    })),
    access_methods: accessMethods(service),
    policy_summary: `mode=${service.policy.mode}`,
  };
  return {
    ...summary,
    ...(service.description === undefined ? {} : { description: service.description }),
    ...(service.apiDocsUrl === undefined ? {} : { api_docs_url: service.apiDocsUrl }),
  };
}

function usageHint(credential: CredentialConfig): string {
  if (credential.usage.name) return `Use reference as ${credential.usage.name} ${credential.usage.kind}`;
  return `Use reference as ${credential.usage.kind}`;
}

function accessMethods(service: ServiceConfig): ServiceSummary["access_methods"] {
  if (service.credentials.length === 0) {
    return [{ id: GATEWAY_ACCESS_ID, usage_hint: GATEWAY_ACCESS_USAGE_HINT }];
  }
  return service.credentials.map((credential) => ({ id: credential.id, usage_hint: usageHint(credential) }));
}

function orderedRules(rules: PolicyRuleConfig[]): PolicyRuleConfig[] {
  return [...rules].sort((a, b) => {
    if (a.priority !== b.priority) return b.priority - a.priority;
    if (a.effect === b.effect) return 0;
    return a.effect === "deny" ? -1 : 1;
  });
}
