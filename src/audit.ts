import { closeSync, mkdirSync, openSync, writeSync } from "node:fs";
import { dirname } from "node:path";
import { createLogger } from "./logger.js";
import type { GatewayConfig } from "./types.js";
import { sanitizeAuditEvent } from "./auditSanitizer.js";

export interface ReferenceIssuedAuditEvent {
  type: "reference_issued";
  subject: string;
  service: string;
  destination: string;
  access_ids: string[];
  internal_reference_ids: string[];
  reason: string;
  timestamp: string;
}

export interface ServiceRequestAuditEvent {
  type: "service_request";
  request_id: string;
  subject: string;
  service: string;
  destination: string;
  access_ids: string[];
  internal_reference_ids: string[];
  method: string;
  target_host: string;
  target_path: string;
  policy_decision: "allow" | "deny";
  matched_policy_rule?: string;
  downstream_status_code?: number;
  request_timestamp: string;
  request_duration_ms: number;
  tls_verify: boolean;
  secret_tokenization_count: number;
  secret_rule_ids?: string[];
  response_internal_reference_ids?: string[];
  binary_scan_bypassed?: boolean;
  error_code?: string;
  error_message?: string;
}

export interface InvalidOpaqueResponseReferencesAuditEvent {
  type: "invalid_opaque_response_references";
  request_id: string;
  subject: string;
  service: string;
  destination: string;
  warnings: Array<{ prefix: "gref" | "sec"; reason: "unknown" | "expired" | "wrong_subject" | "wrong_service"; count: number }>;
  timestamp: string;
}

export interface ToolInvocationAuditEvent {
  type: "tool_invocation";
  subject: string;
  tool: "list_services" | "describe_service_policy" | "get_gateway_service_references" | "service_request" | "explain_denial";
  outcome: "allow" | "deny" | "error";
  service?: string;
  request_id?: string;
  error_code?: string;
  timestamp: string;
}

export type AuditEvent = ReferenceIssuedAuditEvent | ServiceRequestAuditEvent | ToolInvocationAuditEvent | InvalidOpaqueResponseReferencesAuditEvent;

export interface AuditFileOperations {
  ensureDirectory(path: string): void;
  open(path: string): number;
  write(fd: number, buffer: Uint8Array, offset: number, length: number): number;
  close(fd: number): void;
}

const defaultFileOperations: AuditFileOperations = {
  ensureDirectory: (path) => mkdirSync(path, { recursive: true }),
  open: (path) => openSync(path, "a", 0o600),
  write: (fd, buffer, offset, length) => writeSync(fd, buffer, offset, length),
  close: (fd) => closeSync(fd),
};

export class AuditSink {
  readonly #events: AuditEvent[] = [];
  readonly #logger;
  #fd: number | undefined;
  #degraded = false;
  #closed = false;

  constructor(
    readonly config: GatewayConfig,
    private readonly fileOperations: AuditFileOperations = defaultFileOperations,
  ) {
    this.#logger = createLogger(config.logging);
    this.initializeFile();
  }

  get events(): readonly AuditEvent[] {
    return this.#events;
  }

  get degraded(): boolean {
    return this.#degraded;
  }

  get closed(): boolean {
    return this.#closed;
  }

  clear(): void {
    this.#events.length = 0;
  }

  record(event: AuditEvent): AuditEvent {
    const sanitizedEvent = sanitizeAuditEvent(event, this.config);
    this.#events.push(sanitizedEvent);
    const capacity = this.config.audit.memoryEvents;
    if (this.#events.length > capacity) this.#events.splice(0, this.#events.length - capacity);
    if (this.#fd === undefined || this.#closed || this.#degraded) return sanitizedEvent;
    this.writeRecord(Buffer.from(`${JSON.stringify(sanitizedEvent)}\n`, "utf8"));
    return sanitizedEvent;
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    const fd = this.#fd;
    this.#fd = undefined;
    if (fd === undefined) return;
    try {
      this.fileOperations.close(fd);
    } catch {
      this.markDegraded("close");
    }
  }

  private initializeFile(): void {
    const path = this.config.audit.file;
    if (path === undefined) return;
    try {
      this.fileOperations.ensureDirectory(dirname(path));
      this.#fd = this.fileOperations.open(path);
    } catch {
      this.markDegraded("open");
    }
  }

  private writeRecord(record: Uint8Array): void {
    const fd = this.#fd;
    if (fd === undefined) return;
    try {
      let offset = 0;
      while (offset < record.length) {
        const written = this.fileOperations.write(fd, record, offset, record.length - offset);
        if (!Number.isInteger(written) || written <= 0) throw new Error("Audit write made no progress.");
        offset += written;
      }
    } catch {
      this.markDegraded("write");
    }
  }

  private markDegraded(operation: "open" | "write" | "close"): void {
    this.#degraded = true;
    this.#logger.error("audit.write_failed", { operation });
  }
}

const fallbackAuditEvents: AuditEvent[] = [];

export function getAuditEvents(sink?: AuditSink): readonly AuditEvent[] {
  return sink?.events ?? fallbackAuditEvents;
}

export function clearAuditEvents(sink?: AuditSink): void {
  if (sink !== undefined) sink.clear();
  else fallbackAuditEvents.length = 0;
}

export function audit(event: AuditEvent, sink?: AuditSink): AuditEvent {
  if (sink !== undefined) return sink.record(event);
  const sanitizedEvent = sanitizeAuditEvent(event);
  fallbackAuditEvents.push(sanitizedEvent);
  if (fallbackAuditEvents.length > 1000) fallbackAuditEvents.splice(0, fallbackAuditEvents.length - 1000);
  return sanitizedEvent;
}

export function referenceIssuedAuditEvent(input: ReferenceIssuedAuditEvent, sink?: AuditSink): ReferenceIssuedAuditEvent {
  return audit(input, sink) as ReferenceIssuedAuditEvent;
}
