import { GatewayError } from "./errors.js";
import { InflightLimiter } from "./inflightLimiter.js";

export class ServiceRequestLimiter {
  private readonly overall: InflightLimiter;
  private readonly byService = new Map<string, number>();

  constructor(maxTotal: number, maxPerSubject: number, private readonly maxPerService: number) {
    this.overall = new InflightLimiter(maxTotal, maxPerSubject);
  }

  acquire(subject: string, service: string): (() => void) | undefined {
    const serviceCount = this.byService.get(service) ?? 0;
    if (serviceCount >= this.maxPerService) return undefined;
    const releaseOverall = this.overall.acquire(subject);
    if (releaseOverall === undefined) return undefined;
    this.byService.set(service, serviceCount + 1);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      releaseOverall();
      const remaining = (this.byService.get(service) ?? 1) - 1;
      if (remaining === 0) this.byService.delete(service);
      else this.byService.set(service, remaining);
    };
  }
}

export function acquireServiceRequest(limiter: ServiceRequestLimiter, subject: string, service: string): () => void {
  const release = limiter.acquire(subject, service);
  if (release === undefined) {
    throw new GatewayError("capacity_exceeded", "Authenticated service request capacity is exhausted.");
  }
  return release;
}
