import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { createHash } from "node:crypto";
import { GatewayError } from "./errors.js";
import { evaluatePolicy } from "./policy.js";
import { getService, resolveDestination } from "./registry.js";
import { audit } from "./audit.js";
import { getDenialStore } from "./denials.js";
import { bodySummary, createLogger, headerNames } from "./logger.js";
import { prohibitedCookieHeaderNames, stripCookieHeaders } from "./cookies.js";
import { getResponseTokenizer, getResponseTokenizerRuleIds, getSecretScannerPoolStats } from "./secretRuntime.js";
import { substituteRequestBodyTokens, substituteTokens } from "./substitution.js";
import { getTokenBroker, type TokenRecord } from "./tokens.js";
import type { AuthContext, GatewayConfig } from "./types.js";
import {
  assertSafeBinaryBody,
  classifyResponseBody,
  DEFAULT_BINARY_RESPONSE_MAX_BYTES,
  inspectBinaryBody,
  isBinaryMediaType,
  responseMimeType,
} from "./binaryResponse.js";
import { decodeDeclaredBase64Bytes, encodeBase64Bytes } from "./base64Body.js";
import { enforceCredentialHeaderUsage } from "./headerEnforcement.js";
import { acquireServiceRequest } from "./serviceRequestLimiter.js";
import { createRequestId } from "./requestId.js";

export interface ServiceRequestInput {
  service: string;
  destination?: string;
  method: string;
  path?: string;
  url?: string;
  headers?: Record<string, string>;
  query?: Record<string, unknown>;
  body?: unknown;
  service_reference?: string;
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
  body: string | null;
  body_encoding: "utf8" | "mcp_blob";
  body_size_bytes: number;
  body_sha256: string;
  secret_tokenized: boolean;
  secret_tokenization_count: number;
  tls: {
    verify: boolean;
  };
  truncated: boolean;
  binaryBody?: Buffer;
  binaryMimeType?: string;
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
  const requestStarted = Date.now();
  const requestId = createRequestId();
  const policy = evaluatePolicy(service, target, input.method);
  if (!policy.allowed) {
    const denial = getDenialStore(config).record({
      subject: auth.subject,
      reason: policy.reason,
      ...(policy.matchedRule === undefined ? {} : { matched_rule: policy.matchedRule }),
      policy_mode: policy.policyMode,
      ...(policy.suggestion === undefined ? {} : { suggestion: policy.suggestion }),
    }, requestId);
    audit({
      type: "service_request",
      request_id: denial.request_id,
      subject: auth.subject,
      service: service.id,
      destination: target.destination.id,
      access_ids: [],
      internal_reference_ids: [],
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

  let releaseCapacity: () => void;
  try {
    releaseCapacity = acquireServiceRequest(config, auth.subject, service.id);
  } catch (error) {
    if (!(error instanceof GatewayError) || error.code !== "capacity_exceeded") throw error;
    audit({
      type: "service_request",
      request_id: requestId,
      subject: auth.subject,
      service: service.id,
      destination: target.destination.id,
      access_ids: [],
      internal_reference_ids: [],
      method: input.method.toUpperCase(),
      target_host: target.url.hostname,
      target_path: target.methodPath,
      policy_decision: "allow",
      ...(policy.matchedRule === undefined ? {} : { matched_policy_rule: policy.matchedRule }),
      request_timestamp: new Date(requestStarted).toISOString(),
      request_duration_ms: Date.now() - requestStarted,
      tls_verify: target.tls.verify,
      secret_tokenization_count: 0,
      error_code: error.code,
      error_message: error.message,
    }, config);
    logger.debug("service_request.capacity_rejected", {
      request_id: requestId,
      subject: auth.subject,
      service: service.id,
      destination: target.destination.id,
      method: input.method.toUpperCase(),
      target_host: target.url.hostname,
      target_path: target.methodPath,
      matched_policy_rule: policy.matchedRule,
      error_code: error.code,
    });
    throw new GatewayError(error.code, error.message, requestId);
  }
  try {
  const broker = getTokenBroker(config);
  const tokenTarget = { service: service.id, destination: target.destination.id };
  let serviceReferenceRecord: TokenRecord | undefined;
  if (service.credentials.length === 0) {
    if (typeof input.service_reference !== "string" || input.service_reference.length === 0) {
      throw new GatewayError("reference_invalid", "service_reference is required for this service.");
    }
    serviceReferenceRecord = broker.validateServiceReferenceUse(auth, tokenTarget, input.service_reference);
  } else if (input.service_reference !== undefined) {
    throw new GatewayError("reference_invalid", "service_reference is only valid for gateway access references.");
  }
  const callerHeaders = input.headers ?? {};
  rejectCallerControlledHeaders(callerHeaders);
  const requestCookieHeaders = prohibitedCookieHeaderNames(callerHeaders);
  if (requestCookieHeaders.length > 0) {
    logger.warn("service_request.cookie_rejected", {
      direction: "request", service: service.id, destination: target.destination.id, header_types: requestCookieHeaders,
    });
    throw new GatewayError("cookie_not_allowed", "Cookie headers are not allowed in service requests.");
  }
  const query = input.query ?? {};
  const headers = enforceCredentialHeaderUsage(
    { headers: callerHeaders, query, body: input.body }, broker, auth, tokenTarget, service, logger,
  );
  const headerSubstitution = substituteTokens(headers, broker, auth, tokenTarget, service);
  const querySubstitution = substituteTokens(query, broker, auth, tokenTarget, service);
  const bodySubstitution = substituteRequestBodyTokens(input.body, headerSubstitution.value, broker, auth, tokenTarget, service);
  const substitutedHeaders = headerSubstitution.value;
  const substitutedQuery = querySubstitution.value;
  const substitutedBody = bodySubstitution.value;
  const tokenRecords = [
    ...(serviceReferenceRecord === undefined ? [] : [serviceReferenceRecord]),
    ...headerSubstitution.records,
    ...querySubstitution.records,
    ...bodySubstitution.records,
  ];

  const downstream = buildDownstreamRequest(config, target.url, input.method, substitutedHeaders, substitutedQuery, substitutedBody, target.tls.verify);
  logger.debug("service_request.downstream_ready", {
    subject: auth.subject,
    service: service.id,
    destination: target.destination.id,
    method: input.method.toUpperCase(),
    target_scheme: target.url.protocol.replace(/:$/, ""),
    target_host: target.url.host,
    target_port: target.url.port || defaultPort(target.url.protocol),
    target_path: target.methodPath,
    tls_verify: target.tls.verify,
    matched_policy_rule: policy.matchedRule,
    credential_count: new Set(tokenRecords.filter((record) => record.kind === "credential").map((record) => record.credentialId)).size,
    placeholder_count: new Set(tokenRecords.map((record) => record.id)).size,
    request_shape: {
      header_names: headerNames(callerHeaders),
      query_keys: Object.keys(query).sort(),
      body: bodySummary(input.body),
    },
  });
  const started = Date.now();
  const response = await fetchWithTimeout(downstream, config.limits.timeoutMs, config.limits.maxResponseBodyBytes);
  const cookieFiltered = stripCookieHeaders(Object.fromEntries(response.headers.entries()));
  if (cookieFiltered.removed.length > 0) {
    logger.warn("service_request.cookie_removed", {
      direction: "response", service: service.id, destination: target.destination.id, header_types: cookieFiltered.removed,
    });
  }
  const responseHeaders = cookieFiltered.headers;
  const rawBody = await limitedResponseBytes(response);
  const decodedBody = decodeDeclaredBase64Bytes(responseHeaders, rawBody.body);
  const entityBody = decodedBody ?? rawBody.body;
  const classification = classifyResponseBody(entityBody);
  const matchedPolicyRule = policy.matchedRule === undefined ? undefined : service.policy.rules.find((rule) => rule.id === policy.matchedRule);
  const disabledSecretlintRules = matchedPolicyRule?.secretlint === undefined
    ? new Set<string>()
    : "enabled" in matchedPolicyRule.secretlint
      ? new Set<string>(getResponseTokenizerRuleIds(config))
      : new Set(matchedPolicyRule.secretlint.disabledRuleIds);
  const binaryPolicy = matchedPolicyRule?.binaryResponse ?? { scan: true, maxBytes: DEFAULT_BINARY_RESPONSE_MAX_BYTES };
  const tokenizer = getResponseTokenizer(config);
  let binaryScanBypassed = false;
  let tokenized: Awaited<ReturnType<typeof tokenizer.tokenizeBytes>>;
  if (classification.kind === "binary") {
    if (binaryPolicy.maxBytes !== null && entityBody.byteLength > binaryPolicy.maxBytes) {
      logger.warn("service_request.binary_response_rejected", {
        request_id: requestId,
        service: service.id,
        destination: target.destination.id,
        matched_policy_rule: policy.matchedRule,
        content_type: responseMimeType(responseHeaders),
        response_bytes: entityBody.byteLength,
        binary_max_bytes: binaryPolicy.maxBytes,
        reason: "size_limit",
      });
      throw new GatewayError("response_too_large", "Binary response exceeds its policy size limit.", requestId);
    }
    if (binaryPolicy.scan) {
      const inspection = inspectBinaryBody(entityBody, broker, auth, service);
      if (inspection.ruleIds.length > 0) {
        logger.warn("service_request.binary_response_rejected", {
          request_id: requestId,
          service: service.id,
          destination: target.destination.id,
          matched_policy_rule: policy.matchedRule,
          content_type: responseMimeType(responseHeaders),
          response_bytes: entityBody.byteLength,
          reason: "protected_data",
          rule_ids: inspection.ruleIds,
        });
        assertSafeBinaryBody(inspection, requestId);
      }
    } else {
      binaryScanBypassed = true;
      logger.warn("service_request.binary_scan_bypassed", {
        request_id: requestId,
        service: service.id,
        destination: target.destination.id,
        matched_policy_rule: policy.matchedRule,
        content_type: responseMimeType(responseHeaders),
        response_bytes: entityBody.byteLength,
        reason: "policy_override",
      });
    }
    const headersOnly = await tokenizer.tokenizeHeaders(responseHeaders, auth, service, disabledSecretlintRules);
    tokenized = { ...headersOnly, body: entityBody };
  } else {
    tokenized = await tokenizer.tokenizeBytes(
      { body: entityBody, headers: responseHeaders }, auth, service, disabledSecretlintRules,
    );
  }
  const returnedBody = decodedBody === undefined ? tokenized.body : encodeBase64Bytes(tokenized.body);
  const returnedHeaders = bodyChanged(rawBody.body, returnedBody, rawBody.truncated)
    ? withContentLength(tokenized.headers, returnedBody.byteLength)
    : tokenized.headers;
  const blobResponse = classification.kind === "binary" || isBinaryMediaType(responseHeaders);
  const bodySha256 = createHash("sha256").update(returnedBody).digest("hex");
  audit({
    type: "service_request",
    request_id: requestId,
    subject: auth.subject,
    service: service.id,
    destination: target.destination.id,
    access_ids: [...new Set(tokenRecords.map((record) => record.accessId))],
    internal_reference_ids: [...new Set(tokenRecords.map((record) => record.id))],
    method: input.method.toUpperCase(),
    target_host: target.url.host,
    target_path: target.methodPath,
    policy_decision: "allow",
    ...(policy.matchedRule === undefined ? {} : { matched_policy_rule: policy.matchedRule }),
    downstream_status_code: response.status,
    request_timestamp: new Date(started).toISOString(),
    request_duration_ms: Date.now() - started,
    tls_verify: target.tls.verify,
    secret_tokenization_count: tokenized.secretTokenizationCount,
    secret_rule_ids: tokenized.ruleIds,
    response_internal_reference_ids: tokenized.internalRecordIds,
    ...(binaryScanBypassed ? { binary_scan_bypassed: true } : {}),
  }, config);
  if (tokenized.warnings.length > 0) {
    audit({
      type: "invalid_opaque_response_references",
      request_id: requestId,
      subject: auth.subject,
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
    target_host: target.url.host,
    target_path: target.methodPath,
    status_code: response.status,
    duration_ms: Date.now() - started,
    tls_verify: target.tls.verify,
    secret_tokenized: tokenized.secretTokenized,
    secret_tokenization_count: tokenized.secretTokenizationCount,
    secret_rule_ids: tokenized.ruleIds,
    secret_scan_pool: getSecretScannerPoolStats(config),
    response_kind: classification.kind,
    response_bytes: returnedBody.byteLength,
    truncated: rawBody.truncated,
  });

  return {
    request_id: requestId,
    status_code: response.status,
    headers: returnedHeaders,
    body: blobResponse ? null : returnedBody.toString("utf8"),
    body_encoding: blobResponse ? "mcp_blob" : "utf8",
    body_size_bytes: returnedBody.byteLength,
    body_sha256: bodySha256,
    secret_tokenized: tokenized.secretTokenized,
    secret_tokenization_count: tokenized.secretTokenizationCount,
    tls: { verify: target.tls.verify },
    truncated: rawBody.truncated,
    ...(blobResponse ? { binaryBody: returnedBody, binaryMimeType: responseMimeType(responseHeaders) } : {}),
  };
  } finally {
    releaseCapacity();
  }
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
  removeHeader(requestHeaders, "transfer-encoding");
  removeHeader(requestHeaders, "content-length");
  requestHeaders["host"] = targetUrl.host;
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

const CALLER_CONTROLLED_AUTHORITY_HEADERS = new Set([
  "host",
  ":authority",
  "forwarded",
  "x-forwarded-host",
  "x-forwarded-proto",
]);

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

function rejectCallerControlledHeaders(headers: Record<string, string>): void {
  for (const name of Object.keys(headers)) {
    const normalized = name.toLowerCase();
    if (CALLER_CONTROLLED_AUTHORITY_HEADERS.has(normalized) || normalized.startsWith("x-forwarded-")) {
      throw new GatewayError("destination_not_allowed", `Caller-supplied ${name} header is not allowed.`);
    }
    if (HOP_BY_HOP_HEADERS.has(normalized)) {
      if (normalized === "transfer-encoding") {
        throw new GatewayError("unsupported_transfer_encoding", "Caller-supplied Transfer-Encoding is not allowed.");
      }
      throw new GatewayError("destination_not_allowed", `Caller-supplied ${name} header is not allowed.`);
    }
  }
}

async function fetchWithTimeout(downstream: DownstreamRequest, timeoutMs: number, maxResponseBytes: number): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await sendDownstreamRequest(downstream, controller.signal, maxResponseBytes);
  } catch (error) {
    if (error instanceof GatewayError) throw error;
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

async function sendDownstreamRequest(downstream: DownstreamRequest, signal: AbortSignal, maxResponseBytes: number): Promise<Response> {
  const url = new URL(downstream.url);
  const request = url.protocol === "https:" ? httpsRequest : httpRequest;

  return await new Promise<Response>((resolve, reject) => {
    const req = request(url, {
      method: downstream.method,
      headers: downstream.headers,
      signal,
      ...(url.protocol === "https:" ? { rejectUnauthorized: downstream.tlsVerify } : {}),
    }, (res) => {
      const declaredLength = res.headers["content-length"];
      if (declaredLength !== undefined && /^\d+$/.test(declaredLength) && Number(declaredLength) > maxResponseBytes) {
        const error = new GatewayError("response_too_large", "Downstream response is too large.");
        res.destroy(error);
        reject(error);
        return;
      }
      const chunks: Buffer[] = [];
      let totalBytes = 0;
      let settled = false;
      res.on("data", (chunk) => {
        if (settled) return;
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        totalBytes += bytes.byteLength;
        if (totalBytes > maxResponseBytes) {
          settled = true;
          const error = new GatewayError("response_too_large", "Downstream response is too large.");
          res.destroy(error);
          req.destroy();
          reject(error);
          return;
        }
        chunks.push(bytes);
      });
      res.on("error", (error) => {
        if (!settled) reject(error);
      });
      res.on("end", () => {
        if (settled) return;
        settled = true;
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

async function limitedResponseBytes(response: Response): Promise<{ body: Buffer; truncated: false }> {
  return { body: Buffer.from(await response.arrayBuffer()), truncated: false };
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

function bodyChanged(before: Buffer, after: Buffer, truncated: boolean): boolean {
  return truncated || !before.equals(after);
}

function defaultPort(protocol: string): string {
  return protocol === "https:" ? "443" : "80";
}
