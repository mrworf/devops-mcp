export type MaintenanceTask = (now: number) => void;

export class MaintenanceRegistry {
  readonly #tasks = new Set<MaintenanceTask>();
  #timer: NodeJS.Timeout | undefined;

  constructor(private readonly intervalMs: number) {}

  register(task: MaintenanceTask): void {
    this.#tasks.add(task);
  }

  run(now = Date.now()): void {
    for (const task of this.#tasks) task(now);
  }

  start(): () => void {
    if (this.#timer === undefined) {
      this.#timer = setInterval(() => this.run(), this.intervalMs);
      this.#timer.unref();
    }
    return () => this.stop();
  }

  stop(): void {
    if (this.#timer !== undefined) clearInterval(this.#timer);
    this.#timer = undefined;
  }
}
