export type GatewayErrorCode =
  | "unauthenticated"
  | "unauthorized_service"
  | "unknown_service"
  | "unknown_destination"
  | "unknown_access"
  | "reference_expired"
  | "reference_invalid"
  | "destination_not_allowed"
  | "host_not_allowed"
  | "scheme_not_allowed"
  | "port_not_allowed"
  | "policy_denied"
  | "tls_error"
  | "downstream_timeout"
  | "downstream_error"
  | "response_too_large"
  | "unsupported_transfer_encoding"
  | "cookie_not_allowed"
  | "secret_scan_busy"
  | "secret_scan_failed"
  | "capacity_exceeded"
  | "config_error";

export type ConfigPath = Array<string | number>;

export interface ConfigDiagnostic {
  detail: string;
  file?: string;
  path?: string;
  line?: number;
  column?: number;
  source?: string;
  pointer?: string;
  /** Used only while mapping a validation error back to its YAML node. */
  configPath?: ConfigPath;
}

export class GatewayError extends Error {
  readonly code: GatewayErrorCode;
  readonly requestId?: string;
  readonly diagnostics?: ConfigDiagnostic[];

  constructor(code: GatewayErrorCode, message: string, requestId?: string, diagnostics?: ConfigDiagnostic[]) {
    super(message);
    this.name = "GatewayError";
    this.code = code;
    if (requestId !== undefined) this.requestId = requestId;
    if (diagnostics !== undefined) this.diagnostics = diagnostics;
  }
}

export function formatConfigPath(path: ConfigPath): string {
  return path.reduce<string>((formatted, segment) => {
    if (typeof segment === "number") return `${formatted}[${segment}]`;
    return formatted.length === 0 ? segment : `${formatted}.${segment}`;
  }, "");
}

export function configError(message: string, diagnostics?: ConfigDiagnostic[]): GatewayError {
  return new GatewayError("config_error", message, undefined, diagnostics);
}

export function configValidationError(message: string, path: ConfigPath, detail = message): GatewayError {
  return configError(message, [{ detail, path: formatConfigPath(path), configPath: path }]);
}
