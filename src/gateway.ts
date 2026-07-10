import { GatewayError } from "./errors.js";
import { evaluatePolicy } from "./policy.js";
import { getService, resolveDestination } from "./registry.js";
import { audit } from "./audit.js";
import { denialStore } from "./denials.js";
import { redactResponse } from "./redaction.js";
import { substituteTokens } from "./substitution.js";
import { getTokenBroker } from "./tokens.js";
import type { AuthContext, GatewayConfig } from "./types.js";

export interface ServiceRequestInput {
  service: string;
  destination?: string;
  method: string;
  path?: string;
  url?: string;
  headers?: Record<string, string>;
  query?: Record<string, unknown>;
  body?: unknown;
  reason: string;
}

export interface DownstreamRequest {
  url: string;
  init: RequestInit;
}

export interface ServiceResponse {
  request_id: string;
  status_code: number;
  headers: Record<string, string>;
  body: string;
  redacted: boolean;
  redaction_count: number;
  tls: {
    verify: boolean;
  };
  truncated: boolean;
}

export async function executeServiceRequest(
  config: GatewayConfig,
  auth: AuthContext,
  input: ServiceRequestInput,
): Promise<ServiceResponse> {
  validateRequestInput(input);
  const service = getService(config, input.service, auth);
  const target = resolveDestination(config, auth, input.service, input.destination, {
    ...(input.path === undefined ? {} : { path: input.path }),
    ...(input.url === undefined ? {} : { url: input.url }),
  });
  const policy = evaluatePolicy(service, target, input.method);
  if (!policy.allowed) {
    const denial = denialStore.record({
      subject: auth.subject,
      ...(auth.sessionId === undefined ? {} : { session_id: auth.sessionId }),
      reason: policy.reason,
      ...(policy.matchedRule === undefined ? {} : { matched_rule: policy.matchedRule }),
      policy_mode: policy.policyMode,
      ...(policy.suggestion === undefined ? {} : { suggestion: policy.suggestion }),
    });
    audit({
      type: "service_request",
      request_id: denial.request_id,
      subject: auth.subject,
      ...(auth.sessionId === undefined ? {} : { session_id: auth.sessionId }),
      service: service.id,
      destination: target.destination.id,
      credential_ids: [],
      internal_token_ids: [],
      method: input.method.toUpperCase(),
      target_host: target.url.hostname,
      target_path: target.methodPath,
      policy_decision: "deny",
      ...(policy.matchedRule === undefined ? {} : { matched_policy_rule: policy.matchedRule }),
      request_timestamp: new Date().toISOString(),
      request_duration_ms: 0,
      tls_verify: target.tls.verify,
      redaction_count: 0,
      error_code: "policy_denied",
      error_message: policy.reason,
    });
    throw new GatewayError("policy_denied", policy.reason, denial.request_id);
  }

  const broker = getTokenBroker(config);
  const tokenTarget = { service: service.id, destination: target.destination.id };
  const headers = input.headers ?? {};
  const headerSubstitution = substituteTokens(headers, broker, auth, tokenTarget, service);
  const querySubstitution = substituteTokens(input.query ?? {}, broker, auth, tokenTarget, service);
  const bodySubstitution = substituteTokens(input.body, broker, auth, tokenTarget, service);
  const substitutedHeaders = headerSubstitution.value;
  const substitutedQuery = querySubstitution.value;
  const substitutedBody = bodySubstitution.value;
  const tokenRecords = [...headerSubstitution.records, ...querySubstitution.records, ...bodySubstitution.records];

  const downstream = buildDownstreamRequest(config, target.url, input.method, substitutedHeaders, substitutedQuery, substitutedBody);
  const started = Date.now();
  const response = await fetchWithTimeout(downstream.url, downstream.init, config.limits.timeoutMs);
  const responseHeaders = Object.fromEntries(response.headers.entries());
  const rawBody = await limitedResponseText(response, config.limits.maxResponseBodyBytes);
  const redacted = redactResponse({ body: rawBody.body, headers: responseHeaders }, service.credentials.map((credential) => credential.secret));
  const requestId = `req_${started}`;
  audit({
    type: "service_request",
    request_id: requestId,
    subject: auth.subject,
    ...(auth.sessionId === undefined ? {} : { session_id: auth.sessionId }),
    service: service.id,
    destination: target.destination.id,
    credential_ids: [...new Set(tokenRecords.map((record) => record.credentialId))],
    internal_token_ids: [...new Set(tokenRecords.map((record) => record.id))],
    method: input.method.toUpperCase(),
    target_host: target.url.hostname,
    target_path: target.methodPath,
    policy_decision: "allow",
    ...(policy.matchedRule === undefined ? {} : { matched_policy_rule: policy.matchedRule }),
    downstream_status_code: response.status,
    request_timestamp: new Date(started).toISOString(),
    request_duration_ms: Date.now() - started,
    tls_verify: target.tls.verify,
    redaction_count: redacted.redaction_count,
  });

  return {
    request_id: requestId,
    status_code: response.status,
    headers: redacted.headers,
    body: redacted.body,
    redacted: redacted.redacted,
    redaction_count: redacted.redaction_count,
    tls: { verify: target.tls.verify },
    truncated: rawBody.truncated,
  };
}

function validateRequestInput(input: ServiceRequestInput): void {
  if (!input.reason.trim()) throw new GatewayError("policy_denied", "service_request reason is required.");
  if (!["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].includes(input.method.toUpperCase())) {
    throw new GatewayError("destination_not_allowed", `Unsupported method: ${input.method}`);
  }
}

function buildDownstreamRequest(
  config: GatewayConfig,
  url: URL,
  method: string,
  headers: Record<string, string>,
  query: Record<string, unknown>,
  body: unknown,
): DownstreamRequest {
  const targetUrl = new URL(url.href);
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null) continue;
    targetUrl.searchParams.set(key, String(value));
  }

  const requestHeaders = { ...headers };
  let requestBody: string | undefined;
  if (body !== undefined && method.toUpperCase() !== "GET" && method.toUpperCase() !== "HEAD") {
    if (typeof body === "string") {
      requestBody = body;
    } else {
      requestBody = JSON.stringify(body);
      if (!hasHeader(requestHeaders, "content-type")) requestHeaders["content-type"] = "application/json";
    }
    if (Buffer.byteLength(requestBody) > config.limits.maxRequestBodyBytes) {
      throw new GatewayError("response_too_large", "Request body is too large.");
    }
  }

  return {
    url: targetUrl.href,
    init: {
      method: method.toUpperCase(),
      headers: requestHeaders,
      redirect: "manual",
      ...(requestBody === undefined ? {} : { body: requestBody }),
    },
  };
}

async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new GatewayError("downstream_timeout", "Downstream request timed out.");
    }
    throw new GatewayError("downstream_error", "Downstream request failed.");
  } finally {
    clearTimeout(timeout);
  }
}

async function limitedResponseText(response: Response, maxBytes: number): Promise<{ body: string; truncated: boolean }> {
  const text = await response.text();
  if (Buffer.byteLength(text) <= maxBytes) return { body: text, truncated: false };
  return { body: text.slice(0, maxBytes), truncated: true };
}

function hasHeader(headers: Record<string, string>, name: string): boolean {
  const lower = name.toLowerCase();
  return Object.keys(headers).some((key) => key.toLowerCase() === lower);
}
