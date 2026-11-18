/** Failure scenarios of the handler: each one fails closed with a known code and a log line. */
import { describe, expect, it } from 'vitest'
import { APP, errorOf, harness, USERS } from './helpers.ts'

describe('failure scenarios', () => {
  it('no account contract bound: social_accounts_unavailable', async () => {
    const h = harness({ accounts: null })
    const browser = h.browser()
    const response = await browser.request(
      h.fakes.google.consent(await browser.start('google'), USERS.google),
    )
    expect(errorOf(response)).toBe('social_accounts_unavailable')
    expect(errorOf(await h.browser().request('/auth/github/redirect?intent=link'))).toBe(
      'social_accounts_unavailable',
    )
  })

  it('the identity system throwing: internal_error, logged as an error without details', async () => {
    const h = harness({
      accounts: {
        ...harness().accounts,
        findByIdentity: async () => {
          throw new Error('connection refused to db.internal:5432 password=hunter2')
        },
      },
    })
    const browser = h.browser()
    const response = await browser.request(
      h.fakes.google.consent(await browser.start('google'), USERS.google),
    )
    expect(errorOf(response)).toBe('internal_error')
    const record = h.logger.records.at(-1)
    expect(record?.level).toBe('error')
    expect(JSON.stringify(record)).not.toContain('hunter2')
  })

  it('a non-Error throw is still contained', async () => {
    const h = harness({
      accounts: {
        ...harness().accounts,
        findByIdentity: async () => {
          throw 'boom'
        },
      },
    })
    const browser = h.browser()
    const response = await browser.request(
      h.fakes.google.consent(await browser.start('google'), USERS.google),
    )
    expect(errorOf(response)).toBe('internal_error')
    expect(h.logger.records.at(-1)?.fields['error']).toBe('string')
  })

  it('the provider being down: social_provider_unavailable', async () => {
    let down = false
    const h = harness({
      wrapFetch: (inner) => async (url, init) => {
        if (down) throw new TypeError('fetch failed')
        return inner(url, init)
      },
    })
    const browser = h.browser()
    const callback = h.fakes.google.consent(await browser.start('google'), USERS.google)
    down = true
    expect(errorOf(await browser.request(callback))).toBe('social_provider_unavailable')
  })

  it('a key rotation at the provider is picked up (unknown kid → one refetch)', async () => {
    const h = harness({ config: { registration: true } })
    const b1 = h.browser()
    expect(
      errorOf(await b1.request(h.fakes.google.consent(await b1.start('google'), USERS.google))),
    ).toBeNull()
    h.fakes.google.rotateKeys()
    h.clock.advance(61_000)
    const b2 = h.browser()
    expect(
      errorOf(await b2.request(h.fakes.google.consent(await b2.start('google'), USERS.google))),
    ).toBeNull()
    expect(h.fakes.google.jwksFetches()).toBe(2)
  })

  it('a callback without a code is a provider error', async () => {
    const h = harness()
    const browser = h.browser()
    const url = new URL(h.fakes.google.consent(await browser.start('google'), USERS.google))
    url.searchParams.set('code', '')
    expect(errorOf(await browser.request(url.href))).toBe('social_provider_error')
  })

  it('oversized parameters are refused', async () => {
    const h = harness()
    const browser = h.browser()
    await browser.start('google')
    expect(
      errorOf(await browser.request(`/auth/google/callback?state=${'x'.repeat(3000)}&code=c`)),
    ).toBe('social_state_invalid')
  })

  it('disabled: nothing matches and fetch answers 404', async () => {
    const h = harness({ config: { enabled: false } })
    const request = new Request(`${APP}/auth/google/redirect`)
    expect(h.handler.matches(request)).toBe(false)
    expect((await h.handler.fetch(request)).status).toBe(404)
  })

  it('a provider that is configured off answers a 404 problem with its code', async () => {
    const h = harness({ providers: { github: { enabled: false } } })
    const response = await h.handler.fetch(new Request(`${APP}/auth/github/redirect`))
    expect(response.status).toBe(404)
    expect(response.headers.get('content-type')).toBe('application/problem+json')
    expect(await response.json()).toMatchObject({ code: 'social_provider_unknown' })
  })

  it('HEAD on redirect behaves like GET', async () => {
    const h = harness()
    const response = await h.handler.fetch(
      new Request(`${APP}/auth/google/redirect`, { method: 'HEAD' }),
    )
    expect(response.status).toBe(302)
  })

  it('on plain-http localhost: no __Host- prefix and no Secure flag', async () => {
    const h = harness({ appUrl: 'http://localhost:3000', providers: { apple: { enabled: false } } })
    const response = await h.handler.fetch(
      new Request('http://localhost:3000/auth/google/redirect'),
    )
    const cookie = response.headers.getSetCookie()[0] ?? ''
    expect(cookie).toMatch(/^sv_social_flow_google=/)
    expect(cookie).not.toContain('Secure')
    expect(new URL(response.headers.get('location') ?? '').searchParams.get('redirect_uri')).toBe(
      'http://localhost:3000/auth/google/callback',
    )
  })

  it('a custom path and redirects are honoured', async () => {
    const h = harness({
      config: { path: '/oauth', redirects: { home: '/home', failure: '/signin' } },
    })
    const ok = await h.handler.fetch(new Request(`${APP}/oauth/google/redirect`))
    expect(ok.status).toBe(302)
    const failed = await h.handler.fetch(new Request(`${APP}/oauth/google/callback?state=x&code=y`))
    expect(new URL(failed.headers.get('location') ?? '', APP).pathname).toBe('/signin')
    expect(h.handler.matches(new Request(`${APP}/auth/google/redirect`))).toBe(false)
  })
})
