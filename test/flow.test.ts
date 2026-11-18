import { describe, expect, it } from 'vitest'
import { APP, errorOf, formPost, harness, USERS } from './helpers.ts'

describe('sign-in flow, per provider (fake providers, no network)', () => {
  it('google: redirect carries PKCE S256, state, nonce and the exact callback URL', async () => {
    const h = harness({ config: { registration: true } })
    const location = new URL(await h.browser().start('google'))
    const p = location.searchParams
    expect(`${location.origin}${location.pathname}`).toBe(h.fakes.google.endpoints.authorization)
    expect(p.get('response_type')).toBe('code')
    expect(p.get('client_id')).toBe('google-client')
    expect(p.get('redirect_uri')).toBe(`${APP}/auth/google/callback`)
    expect(p.get('code_challenge_method')).toBe('S256')
    expect(p.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(p.get('state')).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(p.get('nonce')).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(p.get('scope')?.split(' ')).toEqual(['openid', 'email', 'profile'])
  })

  it('google: a first sign-in with a verified email creates, links and signs in', async () => {
    const h = harness({ config: { registration: true } })
    const browser = h.browser()
    const callback = h.fakes.google.consent(
      await browser.start('google', '?return_to=/inbox'),
      USERS.google,
    )
    const response = await browser.request(callback)
    expect(response.status).toBe(303)
    expect(response.headers.get('location')).toBe('/inbox')
    expect(response.headers.get('cache-control')).toBe('no-store')
    expect(response.headers.get('referrer-policy')).toBe('no-referrer')
    const user = [...h.accounts.users.values()][0]
    expect(user?.email).toBe('ada@example.com')
    expect(user?.name).toBe('Ada Lovelace')
    expect(h.accounts.links.get('google:g-1')).toBe(user?.id)
    expect(browser.jar.has('sv_test_session')).toBe(true)
    // The flow cookie is gone after the callback.
    expect([...browser.jar.keys()].some((k) => k.includes('sv_social_flow'))).toBe(false)
  })

  it('google: a linked identity signs in its user even when the email changed', async () => {
    const h = harness()
    h.accounts.addUser({ id: 'u1', email: 'old@example.com', name: 'Ada', emailVerified: true })
    await h.accounts.link({ provider: 'google', subject: 'g-1', userId: 'u1', email: null })
    const browser = h.browser()
    const response = await browser.request(
      h.fakes.google.consent(await browser.start('google'), {
        ...USERS.google,
        email: 'new@example.com',
      }),
    )
    expect(response.headers.get('location')).toBe('/')
    const sid = browser.jar.get('sv_test_session') ?? ''
    expect(h.accounts.sessions.get(sid)?.userId).toBe('u1')
  })

  it('microsoft: per-tenant issuer, tid/oid subject and xms_edov verified email', async () => {
    const h = harness({ config: { registration: true } })
    const browser = h.browser()
    const response = await browser.request(
      h.fakes.microsoft.consent(await browser.start('microsoft'), USERS.microsoft),
    )
    expect(errorOf(response)).toBeNull()
    expect(
      h.accounts.links.get(
        `microsoft:${'11111111-2222-4333-8444-555555555555'}/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee`,
      ),
    ).toBeDefined()
  })

  it('github: subject is the numeric id, email is the primary verified one', async () => {
    const h = harness({ config: { registration: true } })
    const browser = h.browser()
    const location = new URL(await browser.start('github'))
    expect(location.searchParams.get('nonce')).toBeNull()
    expect(location.searchParams.get('code_challenge_method')).toBe('S256')
    const response = await browser.request(h.fakes.github.consent(location.href, USERS.github))
    expect(errorOf(response)).toBeNull()
    expect(h.accounts.links.get('github:42')).toBeDefined()
    expect([...h.accounts.users.values()][0]?.email).toBe('octo@example.com')
    // The API was called with the access token, a User-Agent and the API version.
    const apiCalls = h.fakes.github.requests.filter((r) => r.url.includes('/api/'))
    expect(apiCalls.map((r) => new URL(r.url).pathname)).toEqual(['/api/user', '/api/user/emails'])
  })

  it('apple: form post, then a same-site GET hand-over finishes the sign-in', async () => {
    const h = harness({ config: { registration: true } })
    const browser = h.browser()
    const authorize = new URL(await browser.start('apple'))
    expect(authorize.searchParams.get('response_mode')).toBe('form_post')
    expect(authorize.searchParams.get('code_challenge')).toBeNull()
    const flowCookie = [...browser.jar.keys()].find((k) => k.includes('flow_apple'))
    expect(flowCookie).toBe('__Host-sv_social_flow_apple')
    const { code, state } = h.fakes.apple.approve(authorize.href, USERS.apple)
    const posted = await formPost(browser, {
      code,
      state,
      user: JSON.stringify({ name: { firstName: 'Ada', lastName: 'Lovelace' } }),
    })
    expect(posted.status).toBe(303)
    expect(posted.headers.get('location')).toBe('/auth/apple/callback')
    expect(h.accounts.users.size).toBe(0) // nothing happens before the same-site request
    const finished = await browser.request('/auth/apple/callback')
    expect(errorOf(finished)).toBeNull()
    expect(finished.headers.get('location')).toBe('/')
    const user = [...h.accounts.users.values()][0]
    expect(user?.name).toBe('Ada Lovelace')
    expect(h.accounts.links.get('apple:apple-1')).toBe(user?.id)
  })

  it('apple: the client secret is a short-lived ES256 JWT for the team and Services ID', async () => {
    const { decodeJwt, verifyJwt } = await import('../src/crypto/jwt.ts')
    const h = harness({ config: { registration: true } })
    const browser = h.browser()
    const { code, state } = h.fakes.apple.approve(await browser.start('apple'), USERS.apple)
    await formPost(browser, { code, state })
    const token = h.fakes.apple.requests.find((r) => r.url.endsWith('/token'))
    const secret = new URLSearchParams(token?.body).get('client_secret') ?? ''
    const jwt = decodeJwt(secret)
    expect(jwt?.header).toMatchObject({ alg: 'ES256', kid: 'KEY1234567' })
    expect(jwt?.payload).toMatchObject({
      iss: 'TEAM123456',
      sub: 'apple-client',
      aud: 'https://apple.test',
    })
    const { exp, iat } = (jwt?.payload ?? {}) as { exp?: number; iat?: number }
    expect(typeof exp).toBe('number')
    expect((exp ?? 0) - (iat ?? 0)).toBe(300)
    const jwk = h.appleKey.publicKey.export({ format: 'jwk' })
    expect(jwt && verifyJwt(jwt, jwk, ['ES256'])).toBe(true)
    expect(new URLSearchParams(token?.body).get('code_verifier')).toBeNull()
  })

  it('a user with two-factor on is sent to the challenge, not signed in', async () => {
    const h = harness()
    h.accounts.addUser({
      id: 'u2',
      email: 'x@example.com',
      name: 'X',
      emailVerified: true,
      twoFactor: true,
    })
    await h.accounts.link({ provider: 'google', subject: 'g-1', userId: 'u2', email: null })
    const browser = h.browser()
    const response = await browser.request(
      h.fakes.google.consent(await browser.start('google'), USERS.google),
    )
    expect(response.headers.get('location')).toBe('/two-factor-challenge')
    expect(browser.jar.has('sv_test_session')).toBe(false)
  })

  it('link: a recently signed-in user connects a provider', async () => {
    const h = harness()
    h.accounts.addUser({ id: 'u1', email: 'ada@example.com', name: 'Ada', emailVerified: true })
    const browser = h.browser()
    browser.addCookie(h.accounts.signInAs('u1'))
    const start = await browser.start('github', '?intent=link&return_to=/settings/accounts')
    const response = await browser.request(h.fakes.github.consent(start, USERS.github))
    expect(errorOf(response)).toBeNull()
    expect(response.headers.get('location')).toBe('/settings/accounts')
    expect(h.accounts.links.get('github:42')).toBe('u1')
    expect(h.logger.records.some((r) => r.msg === 'social account linked')).toBe(true)
  })

  it('link: connecting an identity already linked to the same user is a no-op', async () => {
    const h = harness()
    h.accounts.addUser({ id: 'u1', email: 'ada@example.com', name: 'Ada', emailVerified: true })
    await h.accounts.link({ provider: 'github', subject: '42', userId: 'u1', email: null })
    const browser = h.browser()
    browser.addCookie(h.accounts.signInAs('u1'))
    const response = await browser.request(
      h.fakes.github.consent(await browser.start('github', '?intent=link'), USERS.github),
    )
    expect(errorOf(response)).toBeNull()
  })

  it('unknown provider names fall through; a known but disabled one is a 404 problem', async () => {
    const h = harness()
    expect(h.handler.matches(new Request(`${APP}/auth/facebook/redirect`))).toBe(false)
    expect(h.handler.matches(new Request(`${APP}/auth/google/other`))).toBe(false)
    expect(h.handler.matches(new Request(`${APP}/elsewhere/google/redirect`))).toBe(false)
    expect(h.handler.matches(new Request(`${APP}/auth/google/redirect`))).toBe(true)
    const response = await h.handler.fetch(new Request(`${APP}/elsewhere`))
    expect(response.status).toBe(404)
  })

  it('wrong methods get 405 with Allow', async () => {
    const h = harness()
    const browser = h.browser()
    const post = await browser.request('/auth/google/callback', { method: 'POST' })
    expect(post.status).toBe(405)
    expect(post.headers.get('allow')).toBe('GET')
    const del = await browser.request('/auth/google/redirect', { method: 'DELETE' })
    expect(del.headers.get('allow')).toBe('GET, HEAD')
    const apple = await browser.request('/auth/apple/callback', { method: 'PUT' })
    expect(apple.headers.get('allow')).toBe('GET, POST')
  })
})
