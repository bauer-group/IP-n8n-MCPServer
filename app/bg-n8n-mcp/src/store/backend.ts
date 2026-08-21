/**
 * The key/value contract every storage backend implements.
 *
 * Deliberately tiny — five operations, all string-valued. Everything typed and
 * domain-shaped lives one layer up in store/index.ts, so swapping Redis for
 * something else never touches grant logic.
 */
/**
 * How a counter's window behaves when it is incremented.
 *
 * - `sliding` — the TTL is re-armed on every increment, so each new attempt
 *   extends the lockout. Correct for a **brute-force** counter: someone still
 *   guessing should stay locked out.
 *
 * - `fixed` — the TTL is armed once, when the counter is created, and the
 *   window then expires on schedule however hard the caller keeps knocking.
 *   Correct for a **throughput** budget, and the only safe choice wherever a
 *   rejected request is also counted: under a sliding window a client that
 *   retries on 429 renews its own lockout with every retry, so the bucket
 *   never drains and the caller is locked out for as long as it keeps trying.
 *   With `register` and `cimd` at a one-hour window, that was effectively
 *   permanent.
 */
export type WindowKind = 'fixed' | 'sliding';

export interface StoreBackend {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlSeconds: number): Promise<void>;
  /**
   * Atomic read-and-delete.
   *
   * This is what makes an authorization code single-use. Under a `get` then
   * `del` pair, two concurrent redemptions of the same code both read it
   * before either deletes it, and both get a token — the exact replay OAuth
   * 2.1 requires the server to prevent.
   */
  take(key: string): Promise<string | null>;
  /**
   * Increment a counter and return the new value.
   *
   * `window` decides whether the TTL is re-armed (`sliding`) or set only when
   * the counter is created (`fixed`). It is required rather than defaulted:
   * picking wrong is silent, and the failure it causes — a bucket that never
   * drains — looks like an outage, not like a limiter.
   */
  incr(key: string, ttlSeconds: number, window: WindowKind): Promise<number>;
  del(key: string): Promise<void>;
  /** Liveness, for /healthz. */
  ping(): Promise<boolean>;
  close(): Promise<void>;
}
