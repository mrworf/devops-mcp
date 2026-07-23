import { AuditSink } from "./audit.js";
import { startMaintenance } from "./maintenance.js";
import { createSecretRuntime, type SecretRuntime } from "./secretRuntime.js";
import type { GatewayConfig } from "./types.js";
import { createCapabilityDependencies, type CapabilityDependencies } from "./capabilities.js";
import { registerMaintenanceTask } from "./maintenance.js";

export interface GatewayRuntimeOptions {
  auditSink?: AuditSink;
  secretRuntime?: SecretRuntime;
  capabilities?: CapabilityDependencies;
  startMaintenance?: typeof startMaintenance;
}

export class GatewayRuntime {
  readonly auditSink: AuditSink;
  readonly secretRuntime: SecretRuntime;
  readonly capabilities: CapabilityDependencies;
  readonly #stopMaintenance: () => void;
  #closePromise: Promise<void> | undefined;

  constructor(readonly config: GatewayConfig, options: GatewayRuntimeOptions = {}) {
    const auditSink = options.auditSink ?? new AuditSink(config);
    let secretRuntime: SecretRuntime | undefined;
    try {
      const capabilities = options.capabilities ?? createCapabilityDependencies(config, auditSink);
      secretRuntime = options.secretRuntime ?? createSecretRuntime(config, capabilities.tokenBroker);
      registerMaintenanceTask(config, (now) => capabilities.tokenBroker.sweepExpired(now));
      registerMaintenanceTask(config, (now) => capabilities.denialStore.sweep(now));
      const stopMaintenance = (options.startMaintenance ?? startMaintenance)(config);
      this.auditSink = auditSink;
      this.secretRuntime = secretRuntime;
      this.capabilities = capabilities;
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
