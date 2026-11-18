/**
 * Single use for every `state` (and Apple's hand-over value): the first callback that presents it
 * claims it, and every later one is refused, even with the same cookie and a fresh code. This is
 * what stops a captured callback URL plus flow cookie from being replayed within the 10-minute
 * window.
 *
 * Two implementations:
 * - {@link cacheReplayGuard} over the framework cache (`CacheManagerToken`): `add` is atomic within
 *   a store, so with the `file` store (one machine) or a shared store (several machines) a value
 *   can be claimed exactly once across processes. The provider uses it whenever a cache is bound.
 * - {@link memoryReplayGuard}: one process only (tests, or an app without a cache), bounded so a
 *   flood of callbacks can't grow it without limit.
 *
 * Only a SHA-256 of the value is stored, never the value itself.
 *
 * @module
 */
import { sha256Base64url } from '../crypto/encoding.ts'

/** Claims one-time values. */
export interface ReplayGuard {
  /** `true` the first time `value` is claimed within `ttlSeconds`, `false` afterwards. */
  claim(value: string, ttlSeconds: number): Promise<boolean>
}

/** The cache store methods {@link cacheReplayGuard} needs (the framework's `CacheStore` fits). */
export interface ReplayCacheStore {
  add(key: string, value: unknown, ttlSeconds?: number): Promise<boolean>
}

const PREFIX = 'social_login:once:'

/**
 * A replay guard on a framework cache store.
 *
 * @example
 * const guard = cacheReplayGuard(app.make(CacheManagerToken).store())
 */
export function cacheReplayGuard(store: ReplayCacheStore): ReplayGuard {
  return {
    claim: (value, ttlSeconds) => store.add(PREFIX + sha256Base64url(value), 1, ttlSeconds),
  }
}

/**
 * An in-process replay guard. When full, expired entries are dropped first; if it is still full,
 * the claim fails (closed) rather than forgetting a live value.
 *
 * @example
 * const guard = memoryReplayGuard({ now: Date.now })
 */
export function memoryReplayGuard(
  options: { readonly now?: () => number; readonly maxEntries?: number } = {},
): ReplayGuard {
  const now = options.now ?? Date.now
  const max = options.maxEntries ?? 100_000
  const seen = new Map<string, number>()
  return {
    async claim(value, ttlSeconds) {
      const at = now()
      const key = sha256Base64url(value)
      const until = seen.get(key)
      if (until !== undefined && until > at) return false
      if (seen.size >= max) {
        for (const [k, expiry] of seen) if (expiry <= at) seen.delete(k)
        if (seen.size >= max) return false
      }
      seen.set(key, at + ttlSeconds * 1000)
      return true
    },
  }
}
