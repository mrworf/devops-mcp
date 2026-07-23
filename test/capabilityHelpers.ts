import { createCapabilityDependencies, type CapabilityDependencies } from "../src/capabilities.js";
import type { TokenBroker } from "../src/tokens.js";
import type { GatewayConfig } from "../src/types.js";

const dependenciesByConfig = new WeakMap<GatewayConfig, CapabilityDependencies>();

export function capabilitiesFor(config: GatewayConfig): CapabilityDependencies {
  let dependencies = dependenciesByConfig.get(config);
  if (dependencies === undefined) {
    dependencies = createCapabilityDependencies(config);
    dependenciesByConfig.set(config, dependencies);
  }
  return dependencies;
}

export function installTokenBroker(config: GatewayConfig, tokenBroker: TokenBroker): CapabilityDependencies {
  const dependencies = createCapabilityDependencies(config);
  dependencies.tokenBroker = tokenBroker;
  dependenciesByConfig.set(config, dependencies);
  return dependencies;
}
