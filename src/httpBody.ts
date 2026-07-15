import type { IncomingMessage } from "node:http";

export class RequestBodyError extends Error {
  constructor(
    readonly statusCode: 400 | 413,
    readonly code: "invalid_content_length" | "request_too_large",
    message: string,
  ) {
    super(message);
    this.name = "RequestBodyError";
  }
}

export async function readBoundedBody(request: IncomingMessage, maxBytes: number): Promise<Buffer> {
  const declaredLength = request.headers["content-length"];
  if (declaredLength !== undefined) {
    if (Array.isArray(declaredLength) || !/^\d+$/.test(declaredLength)) {
      throw new RequestBodyError(400, "invalid_content_length", "Invalid Content-Length header.");
    }
    if (Number(declaredLength) > maxBytes) {
      throw new RequestBodyError(413, "request_too_large", "Request body is too large.");
    }
  }

  const chunks: Buffer[] = [];
  let totalBytes = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    totalBytes += bytes.byteLength;
    if (totalBytes > maxBytes) {
      throw new RequestBodyError(413, "request_too_large", "Request body is too large.");
    }
    chunks.push(bytes);
  }
  return Buffer.concat(chunks, totalBytes);
}
