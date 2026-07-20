import { describe, expect, it } from "vitest";
import { McpInitializationLimiter } from "../src/mcp/initializationLimiter.js";

describe("MCP initialization limiter", () => {
  it("allows the configured subject rate and resets after the window", () => {
    const limiter = new McpInitializationLimiter(2, 1000, 10);
    expect(limiter.admit("alice", 100)).toEqual({ allowed: true });
    expect(limiter.admit("alice", 200)).toEqual({ allowed: true });
    expect(limiter.admit("alice", 300)).toEqual({ allowed: false, retryAfterMs: 800 });
    expect(limiter.admit("bob", 300)).toEqual({ allowed: true });
    expect(limiter.admit("alice", 1100)).toEqual({ allowed: true });
  });

  it("bounds subject records with LRU eviction", () => {
    const limiter = new McpInitializationLimiter(1, 1000, 2);
    expect(limiter.admit("alice", 0)).toEqual({ allowed: true });
    expect(limiter.admit("bob", 1)).toEqual({ allowed: true });
    expect(limiter.admit("alice", 2)).toMatchObject({ allowed: false });
    expect(limiter.admit("carol", 3)).toEqual({ allowed: true });
    expect(limiter.admit("bob", 4)).toEqual({ allowed: true });
  });
});
