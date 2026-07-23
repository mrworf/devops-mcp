import { AuditSink } from "../src/audit.js";
import { createCapabilityDependencies, type CapabilityDependencies } from "../src/capabilities.js";
import { createRequestDependencies, type RequestDependencies } from "../src/requestDependencies.js";
import { createSecretRuntime } from "../src/secretRuntime.js";
import type { TokenBroker } from "../src/tokens.js";
import type { GatewayConfig } from "../src/types.js";

const dependenciesByConfig = new WeakMap<GatewayConfig, RequestDependencies>();

export function requestDependenciesFor(config: GatewayConfig): RequestDependencies {
  let dependencies = dependenciesByConfig.get(config);
  if (dependencies === undefined) {
    dependencies = createRequestDependencies(config);
    dependenciesByConfig.set(config, dependencies);
  }
  return dependencies;
}

export function capabilitiesFor(config: GatewayConfig): CapabilityDependencies {
  return requestDependenciesFor(config).capabilities;
}

export function installTokenBroker(config: GatewayConfig, createBroker: (auditSink: AuditSink) => TokenBroker): TokenBroker {
  const existing = dependenciesByConfig.get(config);
  existing?.auditSink.close();
  if (existing !== undefined) void existing.secretRuntime.pool.close();
  const auditSink = new AuditSink(config);
  const tokenBroker = createBroker(auditSink);
  const capabilities = createCapabilityDependencies(config, auditSink);
  capabilities.tokenBroker = tokenBroker;
  dependenciesByConfig.set(config, {
    auditSink,
    capabilities,
    secretRuntime: createSecretRuntime(config, tokenBroker),
  });
  return tokenBroker;
}
