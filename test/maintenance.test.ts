import { describe, expect, it, vi } from "vitest";
import { MaintenanceRegistry } from "../src/maintenance.js";
import { registryConfig } from "./helpers.js";

describe("state maintenance", () => {
  it("runs registered tasks on schedule and stops them on shutdown", () => {
    vi.useFakeTimers();
    try {
      const config = registryConfig();
      const maintenance = new MaintenanceRegistry(config.limits.stateSweepIntervalMs);
      let calls = 0;
      maintenance.register(() => { calls += 1; });
      const stop = maintenance.start();
      vi.advanceTimersByTime(config.limits.stateSweepIntervalMs);
      expect(calls).toBe(1);
      stop();
      vi.advanceTimersByTime(config.limits.stateSweepIntervalMs);
      expect(calls).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("isolates tasks and timers between maintenance registries", () => {
    vi.useFakeTimers();
    try {
      const first = new MaintenanceRegistry(10);
      const second = new MaintenanceRegistry(10);
      let firstCalls = 0;
      let secondCalls = 0;
      first.register(() => { firstCalls += 1; });
      second.register(() => { secondCalls += 1; });
      first.start();
      second.start();
      first.stop();
      vi.advanceTimersByTime(10);
      expect(firstCalls).toBe(0);
      expect(secondCalls).toBe(1);
      second.stop();
    } finally {
      vi.useRealTimers();
    }
  });
});
