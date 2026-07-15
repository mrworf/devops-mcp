import { describe, expect, it } from "vitest";
import { InflightLimiter } from "../src/inflightLimiter.js";

describe("in-flight limiter", () => {
  it("admits work below both limits and releases slots idempotently", () => {
    const limiter = new InflightLimiter(2, 2);
    const first = limiter.acquire("source-a");
    const second = limiter.acquire("source-b");
    expect(first).toBeTypeOf("function");
    expect(second).toBeTypeOf("function");
    expect(limiter.acquire("source-c")).toBeUndefined();
    first?.();
    first?.();
    expect(limiter.acquire("source-c")).toBeTypeOf("function");
  });

  it("enforces source limits independently of the global limit", () => {
    const limiter = new InflightLimiter(3, 1);
    const release = limiter.acquire("source-a");
    expect(limiter.acquire("source-a")).toBeUndefined();
    expect(limiter.acquire("source-b")).toBeTypeOf("function");
    release?.();
    expect(limiter.acquire("source-a")).toBeTypeOf("function");
  });
});
