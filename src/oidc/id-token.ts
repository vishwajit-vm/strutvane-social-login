/**
 * ID token validation (OpenID Connect Core 1.0 §3.1.3.7), all of it, in one place:
 *
 * 1. a well-formed compact JWS, signed with an allowed algorithm by a key from the provider's JWKS;
 * 2. `iss` is exactly the provider's issuer (for Microsoft's multi-tenant endpoint: the issuer of
 *    the token's own tenant, see `providers/microsoft.ts`);
 * 3. `aud` contains our client id; with several audiences, `azp` must be our client id, and an
 *    `azp` that is present must always be our client id;
 * 4. `exp` is in the future, `iat` is not in the future and not older than 10 minutes, `nbf` (when
 *    present) has passed: each with 60 seconds of clock skew;
 * 5. `nonce` equals the one this browser's flow sent (replay protection: a token minted for another
 *    sign-in, even a valid one for the same user, is refused);
 * 6. `sub` is a non-empty string of at most 255 characters.
 *
 * Every failure is `social_token_invalid` with a reason naming the check, never the claim values.
 *
 * @module
 */

import { safeEqual } from '../crypto/encoding.ts'
import { decodeJwt, type JwsAlgorithm, verifyJwt } from '../crypto/jwt.ts'
import { SocialLoginError } from '../errors.ts'
import type { JwksCache } from './jwks.ts'

/** The claims this package reads from a validated ID token (others stay available in `claims`). */
export interface IdTokenClaims {
  readonly iss: string
  readonly sub: string
  readonly aud: string | readonly string[]
  readonly exp: number
  readonly iat: number
  readonly nonce: string
  readonly [claim: string]: unknown
}

/** What a valid token must satisfy. */
export interface IdTokenExpectations {
  /**
   * The exact issuer, or a check for providers whose issuer depends on the token (Microsoft's
   * `/common` endpoint). The function receives the unverified-until-now claims after the
   * signature has been verified.
   */
  readonly issuer: string | ((iss: string, claims: Readonly<Record<string, unknown>>) => boolean)
  readonly clientId: string
  readonly nonce: string
  /** Milliseconds since the epoch. */
  readonly now: number
  readonly algorithms: readonly JwsAlgorithm[]
  /** Allowed clock skew in seconds. Default 60. */
  readonly clockSkewSeconds?: number
  /** Oldest acceptable `iat`, in seconds. Default 600. */
  readonly maxAgeSeconds?: number
}

const fail = (reason: string): never => {
  throw new SocialLoginError('social_token_invalid', `id_token: ${reason}`)
}

const isNumber = (value: unknown): value is number =>
  typeof value === 'number' && Number.isFinite(value)

/**
 * Validate an ID token and return its claims.
 *
 * @example
 * const claims = await verifyIdToken(tokens.id_token, jwks, {
 *   issuer: 'https://accounts.google.com', clientId, nonce: flow.nonce, now: Date.now(), algorithms: ['RS256'],
 * })
 */
export async function verifyIdToken(
  token: unknown,
  jwks: JwksCache,
  expect: IdTokenExpectations,
): Promise<IdTokenClaims> {
  if (typeof token !== 'string') return fail('missing')
  const jwt = decodeJwt(token)
  if (jwt === undefined) return fail('malformed')
  const kid = jwt.header['kid']
  if (kid !== undefined && typeof kid !== 'string') return fail('kid is not a string')
  const key = await jwks.key(kid)
  if (key === undefined) return fail('no matching signing key')
  if (!verifyJwt(jwt, key, expect.algorithms)) return fail('bad signature or algorithm')

  const c = jwt.payload
  const skew = expect.clockSkewSeconds ?? 60
  const maxAge = expect.maxAgeSeconds ?? 600
  const now = Math.floor(expect.now / 1000)

  const iss = c['iss']
  if (typeof iss !== 'string') return fail('iss missing')
  const issuerOk = typeof expect.issuer === 'string' ? iss === expect.issuer : expect.issuer(iss, c)
  if (!issuerOk) return fail('iss does not match the provider')

  const aud = c['aud']
  const audiences = typeof aud === 'string' ? [aud] : Array.isArray(aud) ? aud : undefined
  if (audiences === undefined || audiences.some((a) => typeof a !== 'string'))
    return fail('aud missing')
  if (!audiences.includes(expect.clientId)) return fail('aud does not contain the client id')
  const azp = c['azp']
  if (azp !== undefined && azp !== expect.clientId) return fail('azp is not the client id')
  if (audiences.length > 1 && azp === undefined) return fail('several audiences without azp')

  const exp = c['exp']
  const iat = c['iat']
  const nbf = c['nbf']
  if (!isNumber(exp) || exp + skew <= now) return fail('expired')
  if (!isNumber(iat) || iat - skew > now) return fail('iat in the future')
  if (iat < now - maxAge - skew) return fail('iat too old')
  if (nbf !== undefined && (!isNumber(nbf) || nbf - skew > now)) return fail('not yet valid')

  const nonce = c['nonce']
  if (typeof nonce !== 'string' || !safeEqual(nonce, expect.nonce))
    return fail('nonce does not match this sign-in')

  const sub = c['sub']
  if (typeof sub !== 'string' || sub.length === 0 || sub.length > 255) return fail('sub invalid')

  return c as IdTokenClaims
}
