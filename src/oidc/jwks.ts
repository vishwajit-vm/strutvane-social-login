/**
 * A provider's signing keys (JWKS), fetched from its configured URL and cached.
 *
 * Why the rules below:
 * - **Cache by `Cache-Control: max-age`, clamped to 5 minutes – 24 hours (default 1 hour).**
 *   Providers rotate keys with overlap and publish the new key before using it, so a cached set is
 *   normally enough; the clamp keeps a missing or silly header from hammering the provider or
 *   pinning a key forever.
 * - **An unknown `kid` refetches once, at most once a minute.** That picks up a rotation within
 *   seconds, while a flood of tokens with random `kid`s (an attacker probing) cannot turn into a
 *   flood of requests to the provider.
 * - **One fetch at a time** (single flight): a burst of sign-ins after a restart makes one request.
 * - **A failed refresh keeps serving the last good set until it is 24 hours old**: the keys were
 *   legitimately published by the provider, and a short provider outage shouldn't stop sign-ins
 *   that would otherwise verify. Without any good set, verification fails closed.
 * - **Keys come only from this URL**, never from token headers (see `crypto/jwt.ts`).
 *
 * @module
 */
import type { Jwk } from '../crypto/jwt.ts'
import { SocialLoginError } from '../errors.ts'
import { asObject, type HttpClient } from '../http/client.ts'

/** Options for {@link createJwksCache}. */
export interface JwksCacheOptions {
  /** The JWKS URL (from the provider's discovery document). */
  readonly url: string
  readonly http: HttpClient
  /** Milliseconds since the epoch. */
  readonly now: () => number
  /** For error reasons and logs, e.g. `"google"`. */
  readonly name: string
}

/** A cached key set. */
export interface JwksCache {
  /**
   * The key for a token's `kid`. Without a `kid`, the only key of the set (if exactly one).
   * `undefined` when no key matches, even after a refresh. Throws `social_provider_unavailable`
   * when no key set could ever be fetched.
   */
  key(kid: string | undefined): Promise<Jwk | undefined>
}

const MIN_TTL_MS = 5 * 60_000
const MAX_TTL_MS = 24 * 60 * 60_000
const DEFAULT_TTL_MS = 60 * 60_000
const REFETCH_COOLDOWN_MS = 60_000
const MAX_KEYS = 100

interface KeySet {
  readonly keys: readonly Jwk[]
  readonly fetchedAt: number
  readonly expiresAt: number
}

/** The TTL from `Cache-Control: max-age=N`, clamped; the default without one. */
export function ttlFrom(cacheControl: string | null): number {
  const match = /(?:^|,)\s*max-age\s*=\s*(\d{1,9})\s*(?:,|$)/i.exec(cacheControl ?? '')
  if (match?.[1] === undefined) return DEFAULT_TTL_MS
  const ms = Number(match[1]) * 1000
  return Math.min(MAX_TTL_MS, Math.max(MIN_TTL_MS, ms))
}

/**
 * Create a key cache for one provider.
 *
 * @example
 * const jwks = createJwksCache({ url, http, now: Date.now, name: 'google' })
 * const jwk = await jwks.key(header.kid)
 */
export function createJwksCache(options: JwksCacheOptions): JwksCache {
  let current: KeySet | undefined
  let pending: Promise<KeySet> | undefined
  let lastAttempt = Number.NEGATIVE_INFINITY

  async function fetchSet(): Promise<KeySet> {
    lastAttempt = options.now()
    const response = await options.http.json(
      options.url,
      { method: 'GET', headers: { accept: 'application/json' } },
      `${options.name} jwks`,
    )
    const list = asObject(response.body)?.['keys']
    if (response.status !== 200 || !Array.isArray(list))
      throw new SocialLoginError(
        'social_provider_unavailable',
        `${options.name} jwks: not a key set (status ${response.status})`,
      )
    const keys = list
      .slice(0, MAX_KEYS)
      .map(asObject)
      .filter((k): k is Jwk => k !== undefined)
    const at = options.now()
    return { keys, fetchedAt: at, expiresAt: at + ttlFrom(response.headers.get('cache-control')) }
  }

  /** Refresh once (single flight). A failure keeps the last good set while it is not too old. */
  async function refresh(): Promise<KeySet> {
    pending ??= fetchSet().finally(() => {
      pending = undefined
    })
    try {
      current = await pending
      return current
    } catch (error) {
      if (current !== undefined && options.now() - current.fetchedAt < MAX_TTL_MS) return current
      throw error
    }
  }

  function pick(set: KeySet, kid: string | undefined): Jwk | undefined {
    if (kid === undefined) return set.keys.length === 1 ? set.keys[0] : undefined
    return set.keys.find((k) => k.kid === kid)
  }

  return {
    async key(kid) {
      const now = options.now()
      let set = current !== undefined && current.expiresAt > now ? current : await refresh()
      const found = pick(set, kid)
      if (found !== undefined) return found
      // An unknown kid may mean the provider just rotated: refresh, but not more than once a minute.
      if (now - lastAttempt < REFETCH_COOLDOWN_MS) return undefined
      set = await refresh()
      return pick(set, kid)
    },
  }
}
