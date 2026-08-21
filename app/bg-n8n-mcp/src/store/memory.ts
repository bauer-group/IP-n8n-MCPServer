/**
 * In-memory backend — development and tests only.
 *
 * config.ts refuses to select this outside ENVIRONMENT=development, because
 * every grant dies with the process: a routine `docker compose pull && up -d`
 * would silently disconnect every user, and they would each have to find their
 * n8n API key again.
 */

import type { StoreBackend, WindowKind } from './backend.js';

interface Entry {
  value: string;
  expiresAt: number;
}

export class MemoryBackend implements StoreBackend {
  readonly #entries = new Map<string, Entry>();
  #sweeper: NodeJS.Timeout | undefined;

  constructor(sweepIntervalMs = 60_000) {
    // Expiry is enforced on read, so this timer is only about reclaiming memory
    // for keys nobody ever reads again — rate-limit counters, mostly.
    // `unref` keeps it from holding the event loop open at shutdown.
    if (sweepIntervalMs > 0) {
      this.#sweeper = setInterval(() => this.#sweep(), sweepIntervalMs);
      this.#sweeper.unref();
    }
  }

  #sweep(): void {
    const now = Date.now();
    for (const [key, entry] of this.#entries) {
      if (entry.expiresAt <= now) this.#entries.delete(key);
    }
  }

  #read(key: string): string | null {
    const entry = this.#entries.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= Date.now()) {
      this.#entries.delete(key);
      return null;
    }
    return entry.value;
  }

  get(key: string): Promise<string | null> {
    return Promise.resolve(this.#read(key));
  }

  set(key: string, value: string, ttlSeconds: number): Promise<void> {
    this.#entries.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
    return Promise.resolve();
  }

  take(key: string): Promise<string | null> {
    // Single-threaded JS makes read-then-delete atomic with respect to other
    // requests, since nothing awaits in between.
    const value = this.#read(key);
    this.#entries.delete(key);
    return Promise.resolve(value);
  }

  incr(key: string, ttlSeconds: number, window: WindowKind): Promise<number> {
    // `#read` clears an expired entry, so after it a surviving entry is a live
    // one and its `expiresAt` is the window this counter already belongs to.
    const current = Number(this.#read(key) ?? 0);
    const existing = this.#entries.get(key);
    const next = current + 1;
    this.#entries.set(key, {
      value: String(next),
      // A fixed window keeps the deadline the first request set; a sliding one
      // re-arms it. Mirrors RedisBackend.incr — see WindowKind in backend.ts.
      expiresAt:
        window === 'fixed' && existing ? existing.expiresAt : Date.now() + ttlSeconds * 1000,
    });
    return Promise.resolve(next);
  }

  del(key: string): Promise<void> {
    this.#entries.delete(key);
    return Promise.resolve();
  }

  ping(): Promise<boolean> {
    return Promise.resolve(true);
  }

  close(): Promise<void> {
    if (this.#sweeper) clearInterval(this.#sweeper);
    this.#entries.clear();
    return Promise.resolve();
  }

  /** Test helper: current entry count, expired entries included. */
  get size(): number {
    return this.#entries.size;
  }
}
