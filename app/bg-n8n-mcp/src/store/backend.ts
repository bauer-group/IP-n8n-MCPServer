/**
 * The key/value contract every storage backend implements.
 *
 * Deliberately tiny — five operations, all string-valued. Everything typed and
 * domain-shaped lives one layer up in store/index.ts, so swapping Redis for
 * something else never touches grant logic.
 */
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
  /** Increment a counter, (re)setting its TTL. Returns the new value. */
  incr(key: string, ttlSeconds: number): Promise<number>;
  del(key: string): Promise<void>;
  /** Liveness, for /healthz. */
  ping(): Promise<boolean>;
  close(): Promise<void>;
}
