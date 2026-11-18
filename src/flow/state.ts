/**
 * The flow cookie: what this browser's sign-in attempt must remember between the redirect to the
 * provider and the callback, sealed (encrypted and authenticated, `crypto/sealer.ts`) so the
 * browser can neither read nor change it.
 *
 * - `state` (CSRF): the callback's `state` must equal this one, so a callback this browser didn't
 *   start (login CSRF, an attacker's code) is refused.
 * - `nonce`: the ID token must carry it (replay and code injection).
 * - the PKCE `verifier`: sent with the code; never leaves the server otherwise.
 * - `returnTo`: already checked to be a path on this app when the flow started.
 * - `intent` and `userId`: a link flow remembers who started it, and the callback must be the same
 *   signed-in user.
 * - `issuedAt`: a flow lives 10 minutes.
 *
 * One cookie per provider, purpose-bound to it (`flow:google`), so a Google flow cookie can't be
 * replayed at the GitHub callback (part of the mix-up defence). On https the name carries the
 * `__Host-` prefix: `Secure`, `Path=/` and no `Domain`, so a sibling subdomain can't plant one.
 *
 * The **hand-over** cookie carries a verified profile from Apple's cross-site form post to the
 * same-site `GET` that finishes the sign-in (2 minutes, single use).
 *
 * @module
 */
import type { Sealer } from '../crypto/sealer.ts'
import type { ProviderName, SocialProfile } from '../providers/types.ts'

/** Sign in, or connect the provider to the signed-in user. */
export type Intent = 'login' | 'link'

/** What the flow cookie holds. */
export interface FlowState {
  readonly provider: ProviderName
  readonly state: string
  readonly nonce: string
  readonly verifier: string
  readonly returnTo: string
  readonly intent: Intent
  /** The signed-in user who started a link flow; `null` for sign-in. */
  readonly userId: string | null
  /** Milliseconds since the epoch. */
  readonly issuedAt: number
}

/** What the hand-over cookie holds (Apple's form post → the finishing `GET`). */
export interface HandOff {
  /** A random id, claimed once when the hand-over is used. */
  readonly id: string
  readonly profile: SocialProfile
  readonly returnTo: string
  readonly intent: Intent
  readonly userId: string | null
  readonly issuedAt: number
}

/** How long a flow may take, from redirect to callback. */
export const FLOW_TTL_MS: number = 10 * 60_000
/** How long the Apple hand-over may take. */
export const HAND_OFF_TTL_MS: number = 2 * 60_000

/**
 * The cookie name for a provider's flow (`kind: 'flow'`) or hand-over (`kind: 'handoff'`).
 *
 * @example
 * cookieName('flow', 'google', true) // '__Host-sv_social_flow_google'
 */
export function cookieName(
  kind: 'flow' | 'handoff',
  provider: ProviderName,
  secure: boolean,
): string {
  return `${secure ? '__Host-' : ''}sv_social_${kind}_${provider}`
}

const isString = (v: unknown): v is string => typeof v === 'string'

/** Parse a JSON object; anything else (including `null`, arrays and bad JSON) is `undefined`. */
function parseObject(text: string): Record<string, unknown> | undefined {
  try {
    const value: unknown = JSON.parse(text)
    return typeof value === 'object' && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : undefined
  } catch {
    return undefined
  }
}

/**
 * Seal a flow for its provider's cookie.
 *
 * @example
 * const value = sealFlow(sealer, flow)
 */
export function sealFlow(sealer: Sealer, flow: FlowState): string {
  return sealer.seal(`flow:${flow.provider}`, JSON.stringify({ v: 1, ...flow }))
}

/**
 * Open a provider's flow cookie. `undefined` when it is missing, forged, sealed for another
 * provider, malformed or older than {@link FLOW_TTL_MS}.
 *
 * @example
 * const flow = openFlow(sealer, 'google', cookieValue, Date.now())
 */
export function openFlow(
  sealer: Sealer,
  provider: ProviderName,
  sealed: string | undefined,
  now: number,
): FlowState | undefined {
  if (sealed === undefined) return undefined
  const text = sealer.open(`flow:${provider}`, sealed)
  if (text === undefined) return undefined
  const v = parseObject(text)
  if (v === undefined) return undefined
  const { state, nonce, verifier, returnTo, intent, userId, issuedAt } = v
  if (
    v['v'] !== 1 ||
    v['provider'] !== provider ||
    !isString(state) ||
    !isString(nonce) ||
    !isString(verifier) ||
    !isString(returnTo) ||
    (intent !== 'login' && intent !== 'link') ||
    !(userId === null || isString(userId)) ||
    typeof issuedAt !== 'number'
  )
    return undefined
  if (issuedAt > now + 60_000 || now - issuedAt > FLOW_TTL_MS) return undefined
  return { provider, state, nonce, verifier, returnTo, intent, userId, issuedAt }
}

/**
 * Seal a hand-over for Apple's finishing request.
 *
 * @example
 * const value = sealHandOff(sealer, 'apple', handOff)
 */
export function sealHandOff(sealer: Sealer, provider: ProviderName, handOff: HandOff): string {
  return sealer.seal(`handoff:${provider}`, JSON.stringify({ v: 1, ...handOff }))
}

/**
 * Open a hand-over cookie; `undefined` when missing, forged, malformed or expired.
 *
 * @example
 * const handOff = openHandOff(sealer, 'apple', cookieValue, Date.now())
 */
export function openHandOff(
  sealer: Sealer,
  provider: ProviderName,
  sealed: string | undefined,
  now: number,
): HandOff | undefined {
  if (sealed === undefined) return undefined
  const text = sealer.open(`handoff:${provider}`, sealed)
  if (text === undefined) return undefined
  const v = parseObject(text)
  if (v === undefined) return undefined
  const { id, profile, returnTo, intent, userId, issuedAt } = v
  if (
    v['v'] !== 1 ||
    !isString(id) ||
    typeof profile !== 'object' ||
    profile === null ||
    Reflect.get(profile, 'provider') !== provider ||
    !isString(returnTo) ||
    (intent !== 'login' && intent !== 'link') ||
    !(userId === null || isString(userId)) ||
    typeof issuedAt !== 'number'
  )
    return undefined
  if (issuedAt > now + 60_000 || now - issuedAt > HAND_OFF_TTL_MS) return undefined
  // The profile was sealed by this server after verification; only its shape is re-checked.
  const p = profile as Record<string, unknown>
  if (
    !isString(p['subject']) ||
    !(p['email'] === null || isString(p['email'])) ||
    typeof p['emailVerified'] !== 'boolean' ||
    !(p['name'] === null || isString(p['name']))
  )
    return undefined
  return {
    id,
    profile: {
      provider,
      subject: p['subject'],
      email: p['email'],
      emailVerified: p['emailVerified'],
      name: p['name'],
    },
    returnTo,
    intent,
    userId,
    issuedAt,
  }
}
