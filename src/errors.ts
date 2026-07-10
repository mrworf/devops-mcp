export type GatewayErrorCode =
  | "unauthenticated"
  | "unauthorized_service"
  | "unknown_service"
  | "unknown_destination"
  | "unknown_credential"
  | "token_expired"
  | "token_invalid"
  | "destination_not_allowed"
  | "host_not_allowed"
  | "scheme_not_allowed"
  | "port_not_allowed"
  | "policy_denied"
  | "tls_error"
  | "downstream_timeout"
  | "downstream_error"
  | "response_too_large"
  | "config_error";

export class GatewayError extends Error {
  readonly code: GatewayErrorCode;

  constructor(code: GatewayErrorCode, message: string) {
    super(message);
    this.name = "GatewayError";
    this.code = code;
  }
}

export function configError(message: string): GatewayError {
  return new GatewayError("config_error", message);
}
