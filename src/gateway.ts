import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { GatewayError } from "./errors.js";
import { evaluatePolicy } from "./policy.js";
import { getService, resolveDestination } from "./registry.js";
import { audit } from "./audit.js";
import { denialStore } from "./denials.js";
import { bodySummary, createLogger, headerNames } from "./logger.js";
import { prohibitedCookieHeaderNames, stripCookieHeaders } from "./cookies.js";
import { getResponseTokenizer, getResponseTokenizerRuleIds, getSecretScannerPoolStats } from "./secretRuntime.js";
import { decodeUtf8 } from "./secretScanner.js";
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
  method: string;
  headers: Record<string, string>;
  body?: string;
  tlsVerify: boolean;
}

export interface ServiceResponse {
  request_id: string;
  status_code: number;
  headers: Record<string, string>;
  body: string;
  secret_tokenized: boolean;
  secret_tokenization_count: number;
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
  const logger = createLogger(config.logging);
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
      secret_tokenization_count: 0,
      error_code: "policy_denied",
      error_message: policy.reason,
    }, config);
    logger.debug("service_request.denied", {
      request_id: denial.request_id,
      subject: auth.subject,
      session_present: auth.sessionId !== undefined,
      service: service.id,
      destination: target.destination.id,
      method: input.method.toUpperCase(),
      target_host: target.url.hostname,
      target_path: target.methodPath,
      policy_mode: policy.policyMode,
      matched_policy_rule: policy.matchedRule,
      tls_verify: target.tls.verify,
      error_code: "policy_denied",
    });
    throw new GatewayError("policy_denied", policy.reason, denial.request_id);
  }

  const broker = getTokenBroker(config);
  const tokenTarget = { service: service.id, destination: target.destination.id };
  const headers = input.headers ?? {};
  const requestCookieHeaders = prohibitedCookieHeaderNames(headers);
  if (requestCookieHeaders.length > 0) {
    logger.warn("service_request.cookie_rejected", {
      direction: "request", service: service.id, destination: target.destination.id, header_types: requestCookieHeaders,
    });
    throw new GatewayError("cookie_not_allowed", "Cookie headers are not allowed in service requests.");
  }
  const headerSubstitution = substituteTokens(headers, broker, auth, tokenTarget, service);
  const querySubstitution = substituteTokens(input.query ?? {}, broker, auth, tokenTarget, service);
  const bodySubstitution = substituteTokens(input.body, broker, auth, tokenTarget, service);
  const substitutedHeaders = headerSubstitution.value;
  const substitutedQuery = querySubstitution.value;
  const substitutedBody = bodySubstitution.value;
  const tokenRecords = [...headerSubstitution.records, ...querySubstitution.records, ...bodySubstitution.records];

  const downstream = buildDownstreamRequest(config, target.url, input.method, substitutedHeaders, substitutedQuery, substitutedBody, target.tls.verify);
  logger.debug("service_request.downstream_ready", {
    subject: auth.subject,
    session_present: auth.sessionId !== undefined,
    service: service.id,
    destination: target.destination.id,
    method: input.method.toUpperCase(),
    target_scheme: target.url.protocol.replace(/:$/, ""),
    target_host: target.url.hostname,
    target_port: target.url.port || defaultPort(target.url.protocol),
    target_path: target.methodPath,
    tls_verify: target.tls.verify,
    matched_policy_rule: policy.matchedRule,
    credential_count: new Set(tokenRecords.map((record) => record.credentialId)).size,
    placeholder_count: new Set(tokenRecords.map((record) => record.id)).size,
    request_shape: {
      header_names: headerNames(headers),
      query_keys: Object.keys(input.query ?? {}).sort(),
      body: bodySummary(input.body),
    },
  });
  const started = Date.now();
  const response = await fetchWithTimeout(downstream, config.limits.timeoutMs);
  const cookieFiltered = stripCookieHeaders(Object.fromEntries(response.headers.entries()));
  if (cookieFiltered.removed.length > 0) {
    logger.warn("service_request.cookie_removed", {
      direction: "response", service: service.id, destination: target.destination.id, header_types: cookieFiltered.removed,
    });
  }
  const responseHeaders = cookieFiltered.headers;
  const rawBody = await limitedResponseText(response, config.limits.maxResponseBodyBytes);
  const matchedPolicyRule = policy.matchedRule === undefined ? undefined : service.policy.rules.find((rule) => rule.id === policy.matchedRule);
  const disabledSecretlintRules = matchedPolicyRule?.secretlint === undefined
    ? new Set<string>()
    : "enabled" in matchedPolicyRule.secretlint
      ? new Set<string>(getResponseTokenizerRuleIds(config))
      : new Set(matchedPolicyRule.secretlint.disabledRuleIds);
  const tokenized = await getResponseTokenizer(config).tokenizeWithTransferEncoding(
    { body: rawBody.body, headers: responseHeaders }, auth, service, disabledSecretlintRules,
  );
  const returnedHeaders = bodyChanged(rawBody.body, tokenized.body, rawBody.truncated)
    ? withContentLength(tokenized.headers, Buffer.byteLength(tokenized.body))
    : tokenized.headers;
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
    secret_tokenization_count: tokenized.secretTokenizationCount,
    secret_rule_ids: tokenized.ruleIds,
    response_internal_token_ids: tokenized.internalRecordIds,
  }, config);
  if (tokenized.warnings.length > 0) {
    audit({
      type: "invalid_opaque_response_tokens",
      request_id: requestId,
      subject: auth.subject,
      ...(auth.sessionId === undefined ? {} : { session_id: auth.sessionId }),
      service: service.id,
      destination: target.destination.id,
      warnings: tokenized.warnings,
      timestamp: new Date().toISOString(),
    }, config);
  }
  logger.debug("service_request.completed", {
    request_id: requestId,
    subject: auth.subject,
    service: service.id,
    destination: target.destination.id,
    method: input.method.toUpperCase(),
    target_host: target.url.hostname,
    target_path: target.methodPath,
    status_code: response.status,
    duration_ms: Date.now() - started,
    tls_verify: target.tls.verify,
    secret_tokenized: tokenized.secretTokenized,
    secret_tokenization_count: tokenized.secretTokenizationCount,
    secret_rule_ids: tokenized.ruleIds,
    secret_scan_pool: getSecretScannerPoolStats(config),
    truncated: rawBody.truncated,
  });

  return {
    request_id: requestId,
    status_code: response.status,
    headers: returnedHeaders,
    body: tokenized.body,
    secret_tokenized: tokenized.secretTokenized,
    secret_tokenization_count: tokenized.secretTokenizationCount,
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
  tlsVerify: boolean,
): DownstreamRequest {
  const targetUrl = new URL(url.href);
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null) continue;
    targetUrl.searchParams.set(key, String(value));
  }

  const requestHeaders = { ...headers };
  if (hasHeader(requestHeaders, "transfer-encoding")) {
    throw new GatewayError("unsupported_transfer_encoding", "Caller-supplied Transfer-Encoding is not allowed.");
  }
  removeHeader(requestHeaders, "transfer-encoding");
  removeHeader(requestHeaders, "content-length");
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
    requestHeaders["content-length"] = String(Buffer.byteLength(requestBody));
  }

  return {
    url: targetUrl.href,
    method: method.toUpperCase(),
    headers: requestHeaders,
    ...(requestBody === undefined ? {} : { body: requestBody }),
    tlsVerify,
  };
}

async function fetchWithTimeout(downstream: DownstreamRequest, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await sendDownstreamRequest(downstream, controller.signal);
  } catch (error) {
    if (isAbortError(error)) {
      throw new GatewayError("downstream_timeout", "Downstream request timed out.");
    }
    if (isTlsError(error)) {
      throw new GatewayError("tls_error", "Downstream TLS verification failed.");
    }
    throw new GatewayError("downstream_error", downstreamErrorMessage(error));
  } finally {
    clearTimeout(timeout);
  }
}

async function sendDownstreamRequest(downstream: DownstreamRequest, signal: AbortSignal): Promise<Response> {
  const url = new URL(downstream.url);
  const request = url.protocol === "https:" ? httpsRequest : httpRequest;

  return await new Promise<Response>((resolve, reject) => {
    const req = request(url, {
      method: downstream.method,
      headers: downstream.headers,
      signal,
      ...(url.protocol === "https:" ? { rejectUnauthorized: downstream.tlsVerify } : {}),
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk) => {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      });
      res.on("error", reject);
      res.on("end", () => {
        resolve(new Response(Buffer.concat(chunks), {
          status: res.statusCode ?? 0,
          headers: responseHeaders(res.headers),
        }));
      });
    });
    req.on("error", reject);
    if (downstream.body !== undefined) req.write(downstream.body);
    req.end();
  });
}

function responseHeaders(headers: Record<string, string | string[] | number | undefined>): Headers {
  const result = new Headers();
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) {
      for (const item of value) result.append(key, item);
    } else {
      result.set(key, String(value));
    }
  }
  return result;
}

function isAbortError(error: unknown): boolean {
  return error instanceof Error && (error.name === "AbortError" || readErrorCode(error) === "ABORT_ERR");
}

function isTlsError(error: unknown): boolean {
  const code = readErrorCode(error);
  return code === "DEPTH_ZERO_SELF_SIGNED_CERT"
    || code === "SELF_SIGNED_CERT_IN_CHAIN"
    || code === "CERT_HAS_EXPIRED"
    || code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE"
    || code === "ERR_TLS_CERT_ALTNAME_INVALID";
}

function downstreamErrorMessage(error: unknown): string {
  const code = readErrorCode(error);
  if (code === "ECONNREFUSED") return "Downstream connection was refused.";
  if (code === "ENETUNREACH") return "Downstream network is unreachable.";
  if (code === "EHOSTUNREACH") return "Downstream host is unreachable.";
  if (code === "ECONNRESET") return "Downstream connection was reset.";
  return "Downstream request failed.";
}

function readErrorCode(error: unknown): string | undefined {
  if (!error || typeof error !== "object" || !("code" in error)) return undefined;
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" ? code : undefined;
}

async function limitedResponseText(response: Response, maxBytes: number): Promise<{ body: string; truncated: boolean }> {
  const bytes = Buffer.from(await response.arrayBuffer());
  const truncated = bytes.byteLength > maxBytes;
  const selected = truncated ? bytes.subarray(0, maxBytes) : bytes;
  try {
    return { body: decodeUtf8(selected), truncated };
  } catch {
    throw new GatewayError("secret_scan_failed", "Downstream response is not valid UTF-8.");
  }
}

function hasHeader(headers: Record<string, string>, name: string): boolean {
  const lower = name.toLowerCase();
  return Object.keys(headers).some((key) => key.toLowerCase() === lower);
}

function removeHeader(headers: Record<string, string>, name: string): void {
  const lower = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) delete headers[key];
  }
}

function withContentLength(headers: Record<string, string>, length: number): Record<string, string> {
  const normalized = { ...headers };
  removeHeader(normalized, "content-length");
  normalized["content-length"] = String(length);
  return normalized;
}

function bodyChanged(before: string, after: string, truncated: boolean): boolean {
  return truncated || before !== after;
}

function defaultPort(protocol: string): string {
  return protocol === "https:" ? "443" : "80";
}
