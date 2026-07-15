import { availableParallelism } from "node:os";
import { Worker } from "node:worker_threads";
import type { SecretlintRuleConfig } from "./secretlintConfig.js";
import { SECRET_SCANNER_WORKER_SOURCE, validateFindings, type SecretFinding } from "./secretScanner.js";

export interface SecretScannerPoolConfig {
  workers: number;
  queueMax: number;
  subjectActiveMax: number;
  subjectQueueMax: number;
  queueTimeoutMs: number;
}

interface Job {
  id: number;
  subject: string;
  text: string;
  rules: SecretlintRuleConfig[];
  timeoutMs: number;
  resolve: (findings: SecretFinding[]) => void;
  reject: (error: Error) => void;
  queueTimer?: NodeJS.Timeout;
  scanTimer?: NodeJS.Timeout;
}

interface PoolWorker {
  worker: Worker;
  job: Job | undefined;
}

export class SecretScanBusyError extends Error {
  constructor(message = "Secret scanner is busy") {
    super(message);
    this.name = "SecretScanBusyError";
  }
}

export class SecretScannerPool {
  private readonly workers: PoolWorker[] = [];
  private readonly queue: Job[] = [];
  private readonly activeBySubject = new Map<string, number>();
  private nextId = 1;
  private closed = false;

  constructor(readonly config: SecretScannerPoolConfig = loadSecretScannerPoolConfig()) {
    for (let index = 0; index < config.workers; index += 1) this.workers.push(this.createWorker());
  }

  async scan(subject: string, text: string, rules: SecretlintRuleConfig[], timeoutMs: number): Promise<SecretFinding[]> {
    if (this.closed) throw new SecretScanBusyError("Secret scanner is closed");
    const subjectActive = this.activeBySubject.get(subject) ?? 0;
    const subjectQueued = this.queue.filter((job) => job.subject === subject).length;
    const free = this.workers.find((entry) => entry.job === undefined);
    const canStart = free !== undefined && subjectActive < this.config.subjectActiveMax;
    if (!canStart && (this.queue.length >= this.config.queueMax || subjectQueued >= this.config.subjectQueueMax)) {
      throw new SecretScanBusyError();
    }
    return await new Promise<SecretFinding[]>((resolve, reject) => {
      const job: Job = { id: this.nextId++, subject, text, rules, timeoutMs, resolve, reject };
      if (canStart && free !== undefined) this.start(free, job);
      else {
        job.queueTimer = setTimeout(() => {
          const index = this.queue.indexOf(job);
          if (index >= 0) this.queue.splice(index, 1);
          reject(new SecretScanBusyError("Secret scanner queue timed out"));
        }, this.config.queueTimeoutMs);
        this.queue.push(job);
      }
    });
  }

  async close(): Promise<void> {
    this.closed = true;
    for (const job of this.queue.splice(0)) {
      if (job.queueTimer) clearTimeout(job.queueTimer);
      job.reject(new SecretScanBusyError("Secret scanner is closed"));
    }
    await Promise.all(this.workers.map((entry) => entry.worker.terminate()));
  }

  stats(): { workers: number; active: number; queued: number; activeSubjects: number } {
    return {
      workers: this.workers.length,
      active: this.workers.filter((entry) => entry.job !== undefined).length,
      queued: this.queue.length,
      activeSubjects: this.activeBySubject.size,
    };
  }

  private createWorker(): PoolWorker {
    const entry: PoolWorker = { worker: new Worker(SECRET_SCANNER_WORKER_SOURCE, { eval: true }), job: undefined };
    entry.worker.unref();
    entry.worker.on("message", (message: { id?: number; findings?: unknown; error?: string }) => {
      const job = entry.job;
      if (!job || message.id !== job.id) return;
      if (message.error !== undefined) this.finish(entry, new Error("Secretlint scan failed"));
      else {
        try { this.finish(entry, undefined, validateFindings(message.findings, job.text.length)); }
        catch (error) { this.finish(entry, error as Error); }
      }
    });
    entry.worker.on("error", () => this.recycle(entry, new Error("Secretlint worker failed")));
    entry.worker.on("exit", (code) => {
      if (!this.closed && code !== 0 && entry.job) this.recycle(entry, new Error("Secretlint worker exited"));
    });
    return entry;
  }

  private start(entry: PoolWorker, job: Job): void {
    if (job.queueTimer) clearTimeout(job.queueTimer);
    entry.job = job;
    this.activeBySubject.set(job.subject, (this.activeBySubject.get(job.subject) ?? 0) + 1);
    job.scanTimer = setTimeout(() => this.recycle(entry, new Error("Secretlint scan timed out")), job.timeoutMs);
    entry.worker.postMessage({ id: job.id, text: job.text, rules: job.rules });
  }

  private finish(entry: PoolWorker, error?: Error, findings?: SecretFinding[]): void {
    const job = entry.job;
    if (!job) return;
    if (job.scanTimer) clearTimeout(job.scanTimer);
    entry.job = undefined;
    this.decrementSubject(job.subject);
    if (error) job.reject(error);
    else job.resolve(findings ?? []);
    this.dispatch();
  }

  private recycle(entry: PoolWorker, error: Error): void {
    const index = this.workers.indexOf(entry);
    const job = entry.job;
    if (job?.scanTimer) clearTimeout(job.scanTimer);
    if (job) {
      entry.job = undefined;
      this.decrementSubject(job.subject);
      job.reject(error);
    }
    void entry.worker.terminate();
    if (!this.closed) this.workers[index] = this.createWorker();
    this.dispatch();
  }

  private decrementSubject(subject: string): void {
    const next = (this.activeBySubject.get(subject) ?? 1) - 1;
    if (next <= 0) this.activeBySubject.delete(subject);
    else this.activeBySubject.set(subject, next);
  }

  private dispatch(): void {
    for (const entry of this.workers) {
      if (entry.job) continue;
      const index = this.queue.findIndex((job) => (this.activeBySubject.get(job.subject) ?? 0) < this.config.subjectActiveMax);
      if (index < 0) return;
      const [job] = this.queue.splice(index, 1);
      if (job) this.start(entry, job);
    }
  }
}

export function loadSecretScannerPoolConfig(env: NodeJS.ProcessEnv = process.env): SecretScannerPoolConfig {
  return {
    workers: readInteger(env, "SECRETLINT_WORKERS", Math.min(4, availableParallelism()), 32),
    queueMax: readInteger(env, "SECRETLINT_QUEUE_MAX", 32, 10_000),
    subjectActiveMax: readInteger(env, "SECRETLINT_SUBJECT_ACTIVE_MAX", 1, 32),
    subjectQueueMax: readInteger(env, "SECRETLINT_SUBJECT_QUEUE_MAX", 4, 10_000),
    queueTimeoutMs: readInteger(env, "SECRETLINT_QUEUE_TIMEOUT_MS", 5_000, 300_000),
  };
}

function readInteger(env: NodeJS.ProcessEnv, name: string, fallback: number, max: number): number {
  const raw = env[name];
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1 || value > max) throw new Error(`${name} must be an integer between 1 and ${max}`);
  return value;
}
