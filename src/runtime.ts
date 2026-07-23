import { AuditSink } from "./audit.js";
import { MaintenanceRegistry } from "./maintenance.js";
import { createSecretRuntime, type SecretRuntime } from "./secretRuntime.js";
import type { GatewayConfig } from "./types.js";
import { createCapabilityDependencies, type CapabilityDependencies } from "./capabilities.js";
import { BuiltinOAuthRuntime } from "./builtinOAuth.js";

export interface GatewayRuntimeOptions {
  auditSink?: AuditSink;
  secretRuntime?: SecretRuntime;
  capabilities?: CapabilityDependencies;
  startMaintenance?: (config: GatewayConfig) => () => void;
  builtinOAuth?: BuiltinOAuthRuntime;
  maintenance?: MaintenanceRegistry;
}

export class GatewayRuntime {
  readonly auditSink: AuditSink;
  readonly secretRuntime: SecretRuntime;
  readonly capabilities: CapabilityDependencies;
  readonly builtinOAuth: BuiltinOAuthRuntime;
  readonly maintenance: MaintenanceRegistry;
  readonly #stopMaintenance: () => void;
  #closePromise: Promise<void> | undefined;

  constructor(readonly config: GatewayConfig, options: GatewayRuntimeOptions = {}) {
    const auditSink = options.auditSink ?? new AuditSink(config);
    let secretRuntime: SecretRuntime | undefined;
    try {
      const capabilities = options.capabilities ?? createCapabilityDependencies(config, auditSink);
      secretRuntime = options.secretRuntime ?? createSecretRuntime(config, capabilities.tokenBroker);
      const builtinOAuth = options.builtinOAuth ?? new BuiltinOAuthRuntime(config);
      const maintenance = options.maintenance ?? new MaintenanceRegistry(config.limits.stateSweepIntervalMs);
      maintenance.register((now) => capabilities.tokenBroker.sweepExpired(now));
      maintenance.register((now) => capabilities.denialStore.sweep(now));
      maintenance.register((now) => builtinOAuth.sweep(now));
      const stopMaintenance = options.startMaintenance?.(config) ?? maintenance.start();
      this.auditSink = auditSink;
      this.secretRuntime = secretRuntime;
      this.capabilities = capabilities;
      this.builtinOAuth = builtinOAuth;
      this.maintenance = maintenance;
      this.#stopMaintenance = stopMaintenance;
    } catch (error) {
      auditSink.close();
      if (secretRuntime !== undefined) void secretRuntime.pool.close();
      throw error;
    }
  }

  close(): Promise<void> {
    this.#closePromise ??= this.closeOwnedResources();
    return this.#closePromise;
  }

  private async closeOwnedResources(): Promise<void> {
    const errors: unknown[] = [];
    try { this.#stopMaintenance(); } catch (error) { errors.push(error); }
    this.auditSink.close();
    try { await this.secretRuntime.pool.close(); } catch (error) { errors.push(error); }
    if (errors.length > 0) throw new AggregateError(errors, "Gateway runtime close failed.");
  }
}
