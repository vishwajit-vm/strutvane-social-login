import { describe, expect, it } from 'vitest'
import { MICROSOFT_CONSUMERS_TENANT, resolveConfig } from '../src/config.ts'
import { decodeJwt } from '../src/crypto/jwt.ts'
import type { HttpClient } from '../src/http/client.ts'
import { appleClientSecret, appleUserName } from '../src/providers/apple.ts'
import { primaryEmail } from '../src/providers/github.ts'
import { tenantAccepted } from '../src/providers/microsoft.ts'
import { authorizationUrl, exchangeCode } from '../src/providers/oauth.ts'
import { booleanClaim, displayName, normalizeEmail } from '../src/providers/profile.ts'
import { createDriver, createDrivers } from '../src/providers/registry.ts'
import { appleKey, manualClock } from './helpers.ts'

const T1 = '11111111-2222-4333-8444-555555555555'
const APP = 'https://app.test'

const http = (status: number, body: unknown): HttpClient => ({
  json: async () => ({ status, headers: new Headers(), body }),
})

describe('profile helpers', () => {
  it('normalizes emails and refuses non-emails', () => {
    expect(normalizeEmail(' Ada@Example.COM ')).toBe('ada@example.com')
    expect(normalizeEmail('no-at-sign')).toBeNull()
    expect(normalizeEmail('a@b@c')).toBeNull()
    expect(normalizeEmail('a b@c.d')).toBeNull()
    expect(normalizeEmail('a\u0000@c.d')).toBeNull()
    expect(normalizeEmail(`${'a'.repeat(65)}@c.d`)).toBeNull()
    expect(normalizeEmail(42)).toBeNull()
  })

  it('cleans display names', () => {
    expect(displayName('  Ada\u0000  Lovelace‮ ')).toBe('Ada Lovelace')
    expect(displayName('x'.repeat(300))).toHaveLength(200)
    expect(displayName('\u0000')).toBeNull()
    expect(displayName(null)).toBeNull()
  })

  it('reads string booleans', () => {
    expect(booleanClaim(true)).toBe(true)
    expect(booleanClaim('true')).toBe(true)
    expect(booleanClaim('false')).toBe(false)
    expect(booleanClaim(1)).toBe(false)
  })
})

describe('GitHub', () => {
  it('uses only the primary email, verified only when GitHub says so', () => {
    expect(primaryEmail([{ email: 'A@b.c', primary: true, verified: true }])).toEqual({
      email: 'a@b.c',
      verified: true,
    })
    expect(primaryEmail([{ email: 'a@b.c', primary: true, verified: false }])).toEqual({
      email: 'a@b.c',
      verified: false,
    })
    expect(primaryEmail([{ email: 'a@b.c', primary: false, verified: true }])).toEqual({
      email: null,
      verified: false,
    })
    expect(primaryEmail({ email: 'a@b.c' })).toEqual({ email: null, verified: false })
    expect(primaryEmail([null, 'x'])).toEqual({ email: null, verified: false })
  })

  it('refuses a user without a numeric id, and API errors', async () => {
    const config = resolveConfig(
      { providers: { github: { clientId: 'c', clientSecret: 's' } } },
      APP,
    )
    const settings = config.providers.get('github')
    if (settings === undefined) throw new Error('setup')
    const answers = [
      { status: 200, body: { access_token: 't' } },
      { status: 200, body: { id: 'not-a-number' } },
    ]
    let i = 0
    const driver = createDriver(settings, {
      http: {
        json: async () => ({
          status: answers[i]?.status ?? 500,
          headers: new Headers(),
          body: answers[i++]?.body,
        }),
      },
      now: Date.now,
    })
    await expect(
      driver.complete({ code: 'c', codeVerifier: 'v', nonce: 'n', redirectUri: 'r' }),
    ).rejects.toMatchObject({
      code: 'social_token_invalid',
      reason: 'github user: id missing',
    })
    const unauthorized = createDriver(settings, {
      http: {
        json: async (url) => ({
          status: url.endsWith('/access_token') ? 200 : 401,
          headers: new Headers(),
          body: { access_token: 't' },
        }),
      },
      now: Date.now,
    })
    await expect(
      unauthorized.complete({ code: 'c', codeVerifier: 'v', nonce: 'n', redirectUri: 'r' }),
    ).rejects.toMatchObject({
      reason: 'github user: GitHub answered 401',
    })
    expect(driver.matchesIssuer('anything')).toBe(true)
  })
})

describe('Microsoft tenant rules', () => {
  it.each([
    ['common', T1, true],
    ['common', MICROSOFT_CONSUMERS_TENANT, true],
    ['organizations', T1, true],
    ['organizations', MICROSOFT_CONSUMERS_TENANT, false],
    ['consumers', MICROSOFT_CONSUMERS_TENANT, true],
    ['consumers', T1, false],
    [T1, T1, true],
    [T1, '22222222-2222-4333-8444-555555555555', false],
    ['common', 'not-a-guid', false],
  ])('tenant %s accepts tid %s: %s', (tenant, tid, ok) => {
    expect(tenantAccepted(tenant, tid)).toBe(ok)
  })

  it('checks an RFC 9207 iss against the tenant template', () => {
    const config = resolveConfig(
      { providers: { microsoft: { clientId: 'c', clientSecret: 's' } } },
      APP,
    )
    const settings = config.providers.get('microsoft')
    if (settings === undefined) throw new Error('setup')
    const driver = createDriver(settings, { http: http(500, {}), now: Date.now })
    expect(driver.matchesIssuer(`https://login.microsoftonline.com/${T1}/v2.0`)).toBe(true)
    expect(
      driver.matchesIssuer(`https://login.microsoftonline.com/${MICROSOFT_CONSUMERS_TENANT}/v2.0`),
    ).toBe(false)
    expect(driver.matchesIssuer('https://login.microsoftonline.com/evil/v2.0')).toBe(false)
    expect(driver.matchesIssuer('https://evil.test/x/v2.0')).toBe(false)
    const fixed = resolveConfig(
      {
        providers: {
          microsoft: {
            clientId: 'c',
            clientSecret: 's',
            endpoints: { issuer: 'https://sts.test' },
          },
        },
      },
      APP,
    ).providers.get('microsoft')
    if (fixed === undefined) throw new Error('setup')
    expect(
      createDriver(fixed, { http: http(500, {}), now: Date.now }).matchesIssuer('https://sts.test'),
    ).toBe(true)
  })
})

describe('Apple', () => {
  it('reads the display name from the first-time user field, defensively', () => {
    expect(appleUserName('{"name":{"firstName":"Ada","lastName":"Lovelace"}}')).toBe('Ada Lovelace')
    expect(appleUserName('{"name":{"firstName":"Ada"}}')).toBe('Ada')
    expect(appleUserName('{"name":"x"}')).toBeNull()
    expect(appleUserName('null')).toBeNull()
    expect(appleUserName('{bad')).toBeNull()
    expect(appleUserName(`{"name":{"firstName":"${'x'.repeat(5000)}"}}`)).toBeNull()
    expect(appleUserName(undefined)).toBeNull()
  })

  it('signs a client secret that expires in 5 minutes', () => {
    const { pem } = appleKey()
    const settings = resolveConfig(
      { providers: { apple: { clientId: 'svc', teamId: 'T', keyId: 'K', privateKey: pem } } },
      APP,
    ).providers.get('apple')
    if (settings?.name !== 'apple') throw new Error('setup')
    const clock = manualClock()
    const jwt = decodeJwt(appleClientSecret(settings, clock.now()))
    expect(jwt?.payload).toEqual({
      iss: 'T',
      iat: clock.now() / 1000,
      exp: clock.now() / 1000 + 300,
      aud: 'https://appleid.apple.com',
      sub: 'svc',
    })
  })
})

describe('OAuth helpers', () => {
  it('our parameters override any already in the endpoint URL', () => {
    const url = new URL(
      authorizationUrl('https://idp.test/auth?redirect_uri=https://evil.test&x=1', {
        redirect_uri: 'https://app.test/cb',
        state: 's',
      }),
    )
    expect(url.searchParams.getAll('redirect_uri')).toEqual(['https://app.test/cb'])
    expect(url.searchParams.get('x')).toBe('1')
  })

  const exchange = {
    provider: 'p',
    tokenUrl: 'https://idp.test/token',
    clientId: 'c',
    clientSecret: 's',
    code: 'k',
    redirectUri: 'r',
  }
  it.each([
    [
      400,
      { error: 'invalid_grant' },
      'p token endpoint refused the code (status 400, invalid_grant)',
    ],
    [
      200,
      { error: 'bad_verification_code' },
      'p token endpoint refused the code (status 200, bad_verification_code)',
    ],
    [400, { error: '<script>' }, 'p token endpoint refused the code (status 400, unknown)'],
    [200, ['x'], 'p token endpoint refused the code (status 200, unknown)'],
    [200, { token_type: 'Bearer' }, 'p token response has no access_token'],
  ])('a token answer %s %j is social_token_invalid', async (status, body, reason) => {
    await expect(
      exchangeCode({ http: http(status, body), now: Date.now }, exchange),
    ).rejects.toMatchObject({
      code: 'social_token_invalid',
      reason,
    })
  })

  it('sends PKCE only when there is a verifier', async () => {
    const bodies: string[] = []
    const recording: HttpClient = {
      json: async (_u, init) => {
        bodies.push(String(init.body))
        return { status: 200, headers: new Headers(), body: { access_token: 't' } }
      },
    }
    await exchangeCode({ http: recording, now: Date.now }, exchange)
    await exchangeCode({ http: recording, now: Date.now }, { ...exchange, codeVerifier: 'v' })
    expect(new URLSearchParams(bodies[0]).has('code_verifier')).toBe(false)
    expect(new URLSearchParams(bodies[1]).get('code_verifier')).toBe('v')
    expect(new URLSearchParams(bodies[1]).get('grant_type')).toBe('authorization_code')
  })

  it('builds one driver per enabled provider', () => {
    const config = resolveConfig(
      {
        providers: {
          google: { clientId: 'c', clientSecret: 's' },
          github: { clientId: 'c', clientSecret: 's' },
        },
      },
      APP,
    )
    expect([
      ...createDrivers(config.providers, { http: http(500, {}), now: Date.now }).keys(),
    ]).toEqual(['google', 'github'])
  })
})
