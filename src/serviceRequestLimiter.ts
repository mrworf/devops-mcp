import { GatewayError } from "./errors.js";
import { InflightLimiter } from "./inflightLimiter.js";
import type { GatewayConfig } from "./types.js";

const limiters = new WeakMap<GatewayConfig, InflightLimiter>();

export function getServiceRequestLimiter(config: GatewayConfig): InflightLimiter {
  let limiter = limiters.get(config);
  if (limiter === undefined) {
    limiter = new InflightLimiter(
      config.limits.maxServiceRequestsInflight,
      config.limits.maxServiceRequestsInflightPerSubject,
    );
    limiters.set(config, limiter);
  }
  return limiter;
}

export function acquireServiceRequest(config: GatewayConfig, subject: string): () => void {
  const release = getServiceRequestLimiter(config).acquire(subject);
  if (release === undefined) {
    throw new GatewayError("capacity_exceeded", "Authenticated service request capacity is exhausted.");
  }
  return release;
}
