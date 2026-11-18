import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { type Jwk, signJwt } from '../src/crypto/jwt.ts'
import { SocialLoginError } from '../src/errors.ts'
import type { HttpClient, JsonResponse } from '../src/http/client.ts'
import { type IdTokenExpectations, verifyIdToken } from '../src/oidc/id-token.ts'
import { createJwksCache, type JwksCache, ttlFrom } from '../src/oidc/jwks.ts'
import { manualClock } from './helpers.ts'

const key = generateKeyPairSync('rsa', { modulusLength: 2048 })
const jwk: Jwk = { ...key.publicKey.export({ format: 'jwk' }), kid: 'k1' }

/** An HttpClient whose answers the test scripts. */
function scripted(answers: (() => JsonResponse | Promise<JsonResponse>)[]) {
  let calls = 0
  const http: HttpClient = {
    async json() {
      const answer = answers[Math.min(calls, answers.length - 1)]
      calls++
      if (answer === undefined) throw new Error('no answer')
      return answer()
    },
  }
  return { http, calls: () => calls }
}

const keySet = (keys: unknown[], cacheControl = 'max-age=3600'): JsonResponse => ({
  status: 200,
  headers: new Headers({ 'cache-control': cacheControl }),
  body: { keys },
})

describe('JWKS cache', () => {
  it('reads max-age and clamps it to 5 minutes – 24 hours', () => {
    expect(ttlFrom('public, max-age=7200')).toBe(7_200_000)
    expect(ttlFrom('max-age=1')).toBe(300_000)
    expect(ttlFrom('max-age=99999999')).toBe(86_400_000)
    expect(ttlFrom(null)).toBe(3_600_000)
    expect(ttlFrom('no-cache')).toBe(3_600_000)
  })

  it('caches the set until it expires', async () => {
    const clock = manualClock()
    const s = scripted([() => keySet([jwk])])
    const jwks = createJwksCache({ url: 'https://x/jwks', http: s.http, now: clock.now, name: 'x' })
    expect(await jwks.key('k1')).toEqual(jwk)
    expect(await jwks.key('k1')).toEqual(jwk)
    expect(s.calls()).toBe(1)
    clock.advance(3_600_001)
    await jwks.key('k1')
    expect(s.calls()).toBe(2)
  })

  it('refetches for an unknown kid at most once a minute (rotation without a request flood)', async () => {
    const clock = manualClock()
    const rotated = { ...jwk, kid: 'k2' }
    const s = scripted([() => keySet([jwk]), () => keySet([jwk, rotated])])
    const jwks = createJwksCache({ url: 'https://x/jwks', http: s.http, now: clock.now, name: 'x' })
    await jwks.key('k1')
    expect(await jwks.key('k2')).toBeUndefined() // just fetched: cool-down
    clock.advance(60_001)
    expect(await jwks.key('k2')).toEqual(rotated)
    for (let i = 0; i < 20; i++) expect(await jwks.key(`random-${i}`)).toBeUndefined()
    expect(s.calls()).toBe(2)
  })

  it('makes one request for a burst (single flight)', async () => {
    const clock = manualClock()
    let release: (() => void) | undefined
    const gate = new Promise<void>((r) => {
      release = r
    })
    const s = scripted([
      async () => {
        await gate
        return keySet([jwk])
      },
    ])
    const jwks = createJwksCache({ url: 'https://x/jwks', http: s.http, now: clock.now, name: 'x' })
    const burst = Promise.all(Array.from({ length: 10 }, () => jwks.key('k1')))
    release?.()
    expect((await burst).every((k) => k?.kid === 'k1')).toBe(true)
    expect(s.calls()).toBe(1)
  })

  it('keeps the last good set through an outage (up to 24 hours), then fails closed', async () => {
    const clock = manualClock()
    const down = () => {
      throw new SocialLoginError('social_provider_unavailable', 'down')
    }
    const s = scripted([() => keySet([jwk]), down])
    const jwks = createJwksCache({ url: 'https://x/jwks', http: s.http, now: clock.now, name: 'x' })
    await jwks.key('k1')
    clock.advance(3_600_001)
    expect(await jwks.key('k1')).toEqual(jwk)
    clock.advance(86_400_000)
    await expect(jwks.key('k1')).rejects.toMatchObject({ code: 'social_provider_unavailable' })
  })

  it('fails closed when no set was ever fetched, or the answer is not a key set', async () => {
    const clock = manualClock()
    const bad = scripted([() => ({ status: 200, headers: new Headers(), body: { nope: 1 } })])
    const jwks = createJwksCache({
      url: 'https://x/jwks',
      http: bad.http,
      now: clock.now,
      name: 'x',
    })
    await expect(jwks.key('k1')).rejects.toMatchObject({ code: 'social_provider_unavailable' })
    const notFound = scripted([() => ({ status: 404, headers: new Headers(), body: { keys: [] } })])
    const j2 = createJwksCache({
      url: 'https://x/jwks',
      http: notFound.http,
      now: clock.now,
      name: 'x',
    })
    await expect(j2.key('k1')).rejects.toBeInstanceOf(SocialLoginError)
  })

  it('without a kid, uses the only key; with several keys, none', async () => {
    const clock = manualClock()
    const one = createJwksCache({
      url: 'u',
      http: scripted([() => keySet([jwk, 'junk'])]).http,
      now: clock.now,
      name: 'x',
    })
    expect(await one.key(undefined)).toEqual(jwk)
    const two = createJwksCache({
      url: 'u',
      http: scripted([() => keySet([jwk, { ...jwk, kid: 'k2' }])]).http,
      now: clock.now,
      name: 'x',
    })
    expect(await two.key(undefined)).toBeUndefined()
  })
})

describe('ID token validation', () => {
  const clock = manualClock()
  const now = Math.floor(clock.now() / 1000)
  const fixed: JwksCache = {
    key: async (kid) => (kid === 'k1' || kid === undefined ? jwk : undefined),
  }
  const base = {
    iss: 'https://idp.test',
    sub: 'user-1',
    aud: 'client',
    iat: now,
    exp: now + 3600,
    nonce: 'n-1',
  }
  const expect0: IdTokenExpectations = {
    issuer: 'https://idp.test',
    clientId: 'client',
    nonce: 'n-1',
    now: clock.now(),
    algorithms: ['RS256'],
  }
  const token = (
    claims: Record<string, unknown>,
    header: Record<string, unknown> = { kid: 'k1' },
  ) => signJwt('RS256', key.privateKey, header, claims)
  const reason = async (
    claims: Record<string, unknown>,
    e: Partial<IdTokenExpectations> = {},
    header?: Record<string, unknown>,
  ) => {
    try {
      await verifyIdToken(token(claims, header), fixed, { ...expect0, ...e })
      return 'ok'
    } catch (error) {
      return error instanceof SocialLoginError ? error.reason : String(error)
    }
  }

  it('accepts a valid token and returns its claims', async () => {
    const claims = await verifyIdToken(token({ ...base, email: 'a@b.c' }), fixed, expect0)
    expect(claims.sub).toBe('user-1')
    expect(claims['email']).toBe('a@b.c')
  })

  it.each([
    ['iss missing', { ...base, iss: undefined }],
    ['iss does not match the provider', { ...base, iss: 'https://idp.test/' }],
    ['aud missing', { ...base, aud: undefined }],
    ['aud missing', { ...base, aud: [1] }],
    ['aud does not contain the client id', { ...base, aud: 'other' }],
    ['azp is not the client id', { ...base, azp: 'other' }],
    ['several audiences without azp', { ...base, aud: ['client', 'other'] }],
    ['expired', { ...base, exp: now - 61 }],
    ['expired', { ...base, exp: 'soon' }],
    ['iat in the future', { ...base, iat: now + 120 }],
    ['iat too old', { ...base, iat: now - 700 }],
    ['not yet valid', { ...base, nbf: now + 120 }],
    ['not yet valid', { ...base, nbf: 'x' }],
    ['nonce does not match this sign-in', { ...base, nonce: 'n-2' }],
    ['nonce does not match this sign-in', { ...base, nonce: undefined }],
    ['sub invalid', { ...base, sub: '' }],
    ['sub invalid', { ...base, sub: 'x'.repeat(256) }],
  ])('refuses: %s', async (expected, claims) => {
    expect(await reason(claims)).toBe(`id_token: ${expected}`)
  })

  it('accepts several audiences when azp is the client; clock skew of 60 s both ways', async () => {
    expect(await reason({ ...base, aud: ['client', 'other'], azp: 'client' })).toBe('ok')
    expect(await reason({ ...base, exp: now - 30, iat: now - 100 })).toBe('ok')
    expect(await reason({ ...base, iat: now + 30, nbf: now + 30 })).toBe('ok')
  })

  it('refuses a missing or malformed token, a non-string kid and an unknown key', async () => {
    await expect(verifyIdToken(undefined, fixed, expect0)).rejects.toMatchObject({
      reason: 'id_token: missing',
    })
    await expect(verifyIdToken('a.b.c', fixed, expect0)).rejects.toMatchObject({
      reason: 'id_token: malformed',
    })
    expect(await reason(base, {}, { kid: 7 })).toBe('id_token: kid is not a string')
    expect(await reason(base, {}, { kid: 'k9' })).toBe('id_token: no matching signing key')
    expect(await reason(base, { algorithms: ['ES256'] })).toBe(
      'id_token: bad signature or algorithm',
    )
  })

  it('an issuer function sees the claims', async () => {
    expect(
      await reason(base, {
        issuer: (iss, c) => iss === 'https://idp.test' && c['sub'] === 'user-1',
      }),
    ).toBe('ok')
    expect(await reason(base, { issuer: () => false })).toBe(
      'id_token: iss does not match the provider',
    )
  })
})
