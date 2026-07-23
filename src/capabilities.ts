import { DenialStore } from "./denials.js";
import { ServiceRequestLimiter } from "./serviceRequestLimiter.js";
import { TokenBroker } from "./tokens.js";
import type { GatewayConfig } from "./types.js";
import type { AuditSink } from "./audit.js";

export interface CapabilityDependencies {
  tokenBroker: TokenBroker;
  denialStore: DenialStore;
  serviceRequestLimiter: ServiceRequestLimiter;
}

export function createCapabilityDependencies(config: GatewayConfig, auditSink?: AuditSink): CapabilityDependencies {
  return {
    tokenBroker: new TokenBroker(config, undefined, auditSink),
    denialStore: new DenialStore(config.limits.maxDenialRecords, config.limits.denialTtlMs),
    serviceRequestLimiter: new ServiceRequestLimiter(
      config.limits.maxServiceRequestsInflight,
      config.limits.maxServiceRequestsInflightPerSubject,
      config.limits.maxServiceRequestsInflightPerService,
    ),
  };
}
