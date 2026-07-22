import type { GatewayErrorCode } from "../errors.js";

export interface ToolResult {
  structuredContent: Record<string, unknown>;
  content: ToolContent[];
  _meta?: Record<string, unknown>;
  isError?: boolean;
}

export type ToolContent =
  | { type: "text"; text: string }
  | { type: "resource"; resource: { uri: string; mimeType: string; blob: string } };

export function toolSuccess(
  structuredContent: Record<string, unknown>,
  summary: string,
  meta?: Record<string, unknown>,
  additionalContent: ToolContent[] = [],
): ToolResult {
  const result: ToolResult = {
    structuredContent,
    content: [{ type: "text", text: summary }, ...additionalContent],
  };
  return meta === undefined ? result : { ...result, _meta: meta };
}

export function toolError(code: GatewayErrorCode | "not_implemented", message: string, requestId?: string): ToolResult {
  return {
    structuredContent: {
      error: requestId === undefined ? { code, message } : { code, message, request_id: requestId },
    },
    content: [{ type: "text", text: message }],
    isError: true,
  };
}
