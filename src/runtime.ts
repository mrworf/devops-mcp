import { AuditSink, initializeAuditSink } from "./audit.js";
import { startMaintenance } from "./maintenance.js";
import { initializeSecretRuntime, type SecretRuntime } from "./secretRuntime.js";
import type { GatewayConfig } from "./types.js";

export interface GatewayRuntimeOptions {
  auditSink?: AuditSink;
  secretRuntime?: SecretRuntime;
  startMaintenance?: typeof startMaintenance;
}

export class GatewayRuntime {
  readonly auditSink: AuditSink;
  readonly secretRuntime: SecretRuntime;
  readonly #stopMaintenance: () => void;
  #closePromise: Promise<void> | undefined;

  constructor(readonly config: GatewayConfig, options: GatewayRuntimeOptions = {}) {
    const auditSink = options.auditSink ?? initializeAuditSink(config);
    let secretRuntime: SecretRuntime | undefined;
    try {
      secretRuntime = options.secretRuntime ?? initializeSecretRuntime(config);
      const stopMaintenance = (options.startMaintenance ?? startMaintenance)(config);
      this.auditSink = auditSink;
      this.secretRuntime = secretRuntime;
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
