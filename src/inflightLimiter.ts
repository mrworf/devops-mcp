export class InflightLimiter {
  private total = 0;
  private readonly bySource = new Map<string, number>();

  constructor(private readonly maxTotal: number, private readonly maxPerSource: number) {}

  acquire(source: string): (() => void) | undefined {
    const sourceCount = this.bySource.get(source) ?? 0;
    if (this.total >= this.maxTotal || sourceCount >= this.maxPerSource) return undefined;
    this.total += 1;
    this.bySource.set(source, sourceCount + 1);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.total -= 1;
      const remaining = (this.bySource.get(source) ?? 1) - 1;
      if (remaining === 0) this.bySource.delete(source);
      else this.bySource.set(source, remaining);
    };
  }
}
