export interface NetworkRequestBudgetOptions {
  readonly requestsPerSecond: number;
  readonly maxConcurrentRequests: number;
  readonly maxRequests: number;
  readonly maxPendingRequests?: number;
  readonly now?: () => number;
}

type Release = () => void;
type PendingRequest = { readonly resolve: (release: Release | undefined) => void };

/** Per engagement/account budget for actual browser/API exchanges. */
export class NetworkRequestBudget {
  private readonly rate: number;
  private readonly maxConcurrent: number;
  private readonly maxPending: number;
  private readonly now: () => number;
  private readonly pending: PendingRequest[] = [];
  private tokens: number;
  private remaining: number;
  private active = 0;
  private lastRefill: number;
  private timer: NodeJS.Timeout | undefined;
  private closed = false;

  constructor(options: NetworkRequestBudgetOptions) {
    const maxPending = options.maxPendingRequests ?? 32;
    if (!Number.isFinite(options.requestsPerSecond) || options.requestsPerSecond <= 0 || options.requestsPerSecond > 1 ||
        !Number.isInteger(options.maxConcurrentRequests) || options.maxConcurrentRequests < 1 || options.maxConcurrentRequests > 1 ||
        !Number.isInteger(options.maxRequests) || options.maxRequests < 1 || options.maxRequests > 100 ||
        !Number.isInteger(maxPending) || maxPending < 1 || maxPending > 256) throw new Error('Network request budget is invalid');
    this.rate = options.requestsPerSecond;
    this.maxConcurrent = options.maxConcurrentRequests;
    this.maxPending = maxPending;
    this.now = options.now ?? Date.now;
    this.tokens = 1;
    this.remaining = options.maxRequests;
    this.lastRefill = this.now();
  }

  acquire(): Promise<Release | undefined> {
    if (this.closed || this.remaining <= 0 || this.pending.length >= this.maxPending) return Promise.resolve(undefined);
    return new Promise((resolve) => {
      this.pending.push({ resolve });
      this.pump();
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
    for (const entry of this.pending.splice(0)) entry.resolve(undefined);
  }

  snapshot(): Readonly<{ remaining: number; active: number; pending: number }> {
    return Object.freeze({ remaining: this.remaining, active: this.active, pending: this.pending.length });
  }

  private pump(): void {
    if (this.closed) return;
    this.refill();
    if (this.remaining <= 0) {
      for (const entry of this.pending.splice(0)) entry.resolve(undefined);
      return;
    }
    while (this.pending.length && this.active < this.maxConcurrent && this.tokens >= 1 && this.remaining > 0) {
      const entry = this.pending.shift()!;
      this.tokens -= 1;
      this.remaining -= 1;
      this.active += 1;
      let released = false;
      entry.resolve(() => {
        if (released) return;
        released = true;
        this.active = Math.max(0, this.active - 1);
        this.pump();
      });
    }
    if (this.remaining <= 0) {
      for (const entry of this.pending.splice(0)) entry.resolve(undefined);
      return;
    }
    if (this.pending.length && this.active < this.maxConcurrent && this.remaining > 0 && this.tokens < 1 && !this.timer) {
      const delay = Math.max(1, Math.ceil((1 - this.tokens) / this.rate * 1000));
      this.timer = setTimeout(() => { this.timer = undefined; this.pump(); }, delay);
    }
  }

  private refill(): void {
    const current = this.now();
    const elapsed = Math.max(0, current - this.lastRefill);
    this.tokens = Math.min(1, this.tokens + elapsed / 1000 * this.rate);
    this.lastRefill = current;
  }
}
