import { AuditSink } from "./audit.js";
import { createCapabilityDependencies, type CapabilityDependencies } from "./capabilities.js";
import { createSecretRuntime, type SecretRuntime } from "./secretRuntime.js";
import type { GatewayConfig } from "./types.js";

export interface RequestDependencies {
  auditSink: AuditSink;
  capabilities: CapabilityDependencies;
  secretRuntime: SecretRuntime;
}

export function createRequestDependencies(config: GatewayConfig): RequestDependencies {
  const auditSink = new AuditSink(config);
  const capabilities = createCapabilityDependencies(config, auditSink);
  try {
    return { auditSink, capabilities, secretRuntime: createSecretRuntime(config, capabilities.tokenBroker) };
  } catch (error) {
    auditSink.close();
    throw error;
  }
}
