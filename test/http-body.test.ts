import { Readable } from "node:stream";
import { describe, expect, it } from "vitest";
import { readBoundedBody, RequestBodyError } from "../src/httpBody.js";
import type { IncomingMessage } from "node:http";

describe("bounded HTTP request bodies", () => {
  it("accepts an exact-limit chunked body", async () => {
    const request = requestFrom(["12", "34"], {});
    await expect(readBoundedBody(request, 4)).resolves.toEqual(Buffer.from("1234"));
  });

  it("rejects declared and streamed bodies over the limit", async () => {
    await expect(readBoundedBody(requestFrom([], { "content-length": "5" }), 4)).rejects.toMatchObject({
      statusCode: 413, code: "request_too_large",
    });
    await expect(readBoundedBody(requestFrom(["123", "45"], {}), 4)).rejects.toMatchObject({
      statusCode: 413, code: "request_too_large",
    });
  });

  it("rejects malformed declared lengths", async () => {
    await expect(readBoundedBody(requestFrom([], { "content-length": "not-a-number" }), 4)).rejects.toBeInstanceOf(RequestBodyError);
  });
});

function requestFrom(chunks: string[], headers: IncomingMessage["headers"]): IncomingMessage {
  const stream = Readable.from(chunks) as IncomingMessage;
  Object.defineProperty(stream, "headers", { value: headers });
  return stream;
}
