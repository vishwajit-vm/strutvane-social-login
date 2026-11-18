/**
 * Attack-style tests (hub docs/13 §14): each `describe` is one attack class from the threat model
 * in the README, and each test is one way of trying it.
 */
import { describe, expect, it } from 'vitest'
import { cookieName, openFlow, sealFlow } from '../src/flow/state.ts'
import { memorySocialAccounts } from '../src/testing/index.ts'
import {
  APP,
  Browser,
  errorOf,
  formPost,
  harness,
  MS_OTHER_TENANT,
  MS_TENANT,
  USERS,
} from './helpers.ts'

describe('CSRF via state (login CSRF, forged callbacks)', () => {
  it('a callback without the flow cookie (started in another browser) is refused', async () => {
    const h = harness({ config: { registration: true } })
    const attacker = h.browser()
    const callback = h.fakes.google.consent(await attacker.start('google'), USERS.google)
    const victim = h.browser()
    expect(errorOf(await victim.request(callback))).toBe('social_state_invalid')
    expect(h.accounts.users.size).toBe(0)
  })

  it('a callback whose state does not match this browser’s flow is refused', async () => {
    const h = harness({ config: { registration: true } })
    const victim = h.browser()
    await victim.start('google')
    const attacker = h.browser()
    const callback = h.fakes.google.consent(await attacker.start('google'), USERS.google)
    expect(errorOf(await victim.request(callback))).toBe('social_state_invalid')
  })

  it('a missing state is refused', async () => {
    const h = harness()
    const browser = h.browser()
    const url = new URL(h.fakes.google.consent(await browser.start('google'), USERS.google))
    url.searchParams.delete('state')
    expect(errorOf(await browser.request(url.href))).toBe('social_state_invalid')
  })

  it('repeated parameters (parameter pollution) are refused', async () => {
    const h = harness()
    const browser = h.browser()
    const url = new URL(h.fakes.google.consent(await browser.start('google'), USERS.google))
    url.searchParams.append('code', 'second')
    expect(errorOf(await browser.request(url.href))).toBe('social_state_invalid')
  })

  it('a tampered or forged flow cookie does not open', async () => {
    const h = harness()
    const browser = h.browser()
    const callback = h.fakes.google.consent(await browser.start('google'), USERS.google)
    const name = cookieName('flow', 'google', true)
    const value = browser.jar.get(name) ?? ''
    browser.jar.set(name, `${value.slice(0, -4)}AAAA`)
    expect(errorOf(await browser.request(callback))).toBe('social_state_invalid')
  })

  it('a validly sealed cookie whose content is not a flow object is refused (no crash)', async () => {
    const h = harness()
    const browser = h.browser()
    const callback = h.fakes.google.consent(await browser.start('google'), USERS.google)
    for (const content of ['null', '[]', '"x"', '{}', '{"v":1,"provider":"google"}']) {
      browser.jar.set(cookieName('flow', 'google', true), h.sealer.seal('flow:google', content))
      expect(errorOf(await browser.request(callback))).toBe('social_state_invalid')
    }
  })

  it('an expired flow (over 10 minutes) is refused', async () => {
    const h = harness()
    const browser = h.browser()
    const start = await browser.start('google')
    h.clock.advance(10 * 60_000 + 1)
    // The fake's code would also have expired; the flow check comes first.
    expect(errorOf(await browser.request(h.fakes.google.consent(start, USERS.google)))).toBe(
      'social_state_invalid',
    )
  })

  it('the flow cookie is HttpOnly, Secure, __Host- and Lax (None only for Apple)', async () => {
    const h = harness()
    const google = await h.handler.fetch(new Request(`${APP}/auth/google/redirect`))
    const cookie = google.headers.getSetCookie()[0] ?? ''
    expect(cookie).toMatch(/^__Host-sv_social_flow_google=/)
    expect(cookie).toContain('HttpOnly')
    expect(cookie).toContain('Secure')
    expect(cookie).toContain('Path=/')
    expect(cookie).toContain('SameSite=Lax')
    expect(cookie).not.toContain('Domain=')
    const apple = await h.handler.fetch(new Request(`${APP}/auth/apple/redirect`))
    expect(apple.headers.getSetCookie()[0]).toContain('SameSite=None')
  })
})

describe('authorization code injection', () => {
  it('an attacker’s code pasted into the victim’s callback fails PKCE (and the nonce)', async () => {
    const h = harness({ config: { registration: true } })
    const victim = h.browser()
    const victimStart = new URL(await victim.start('github'))
    const attacker = h.browser()
    // The attacker gets a code for their own account in their own flow…
    const attackerCode = new URL(
      h.fakes.github.consent(await attacker.start('github'), { ...USERS.github, githubId: 666 }),
    ).searchParams.get('code')
    // …and injects it with the victim's state.
    const injected = new URL(`${APP}/auth/github/callback`)
    injected.searchParams.set('code', attackerCode ?? '')
    injected.searchParams.set('state', victimStart.searchParams.get('state') ?? '')
    expect(errorOf(await victim.request(injected.href))).toBe('social_token_invalid')
    expect(h.accounts.links.size).toBe(0)
  })

  it('apple (no PKCE): the injected code yields an ID token with the wrong nonce', async () => {
    const h = harness({ config: { registration: true } })
    const victim = h.browser()
    const victimState = new URL(await victim.start('apple')).searchParams.get('state') ?? ''
    const attacker = h.browser()
    const { code } = h.fakes.apple.approve(await attacker.start('apple'), {
      sub: 'evil',
      email: 'e@x.test',
      emailVerified: true,
    })
    const posted = await formPost(victim, { code, state: victimState })
    expect(errorOf(posted)).toBe('social_token_invalid')
  })

  it('a code is single use at the provider (replayed code → invalid_grant)', async () => {
    const h = harness({ config: { registration: true } })
    const browser = h.browser()
    const callback = h.fakes.google.consent(await browser.start('google'), USERS.google)
    expect(errorOf(await browser.request(callback))).toBeNull()
    // The same code again, inside a fresh, valid flow of another browser:
    const second = h.browser()
    await second.start('google')
    const flow = openFlow(
      h.sealer,
      'google',
      second.jar.get(cookieName('flow', 'google', true)),
      h.clock.now(),
    )
    const replay = new URL(`${APP}/auth/google/callback`)
    replay.searchParams.set('code', new URL(callback).searchParams.get('code') ?? '')
    replay.searchParams.set('state', flow?.state ?? '')
    expect(errorOf(await second.request(replay.href))).toBe('social_token_invalid')
  })
})

describe('nonce and state replay', () => {
  it('replaying the same callback (same cookie, same URL) is refused the second time', async () => {
    const h = harness({ config: { registration: true } })
    const browser = h.browser()
    const callback = h.fakes.google.consent(await browser.start('google'), USERS.google)
    const savedFlow = browser.jar.get(cookieName('flow', 'google', true)) ?? ''
    expect(errorOf(await browser.request(callback))).toBeNull()
    browser.jar.set(cookieName('flow', 'google', true), savedFlow)
    expect(errorOf(await browser.request(callback))).toBe('social_state_invalid')
  })

  it('an ID token minted for another sign-in (other nonce) is refused', async () => {
    const h = harness({
      config: { registration: true },
      fake: { google: { idTokenClaims: (c) => ({ ...c, nonce: 'someone-elses-nonce' }) } },
    })
    const browser = h.browser()
    const response = await browser.request(
      h.fakes.google.consent(await browser.start('google'), USERS.google),
    )
    expect(errorOf(response)).toBe('social_token_invalid')
    expect(h.logger.records.at(-1)?.fields['reason']).toBe(
      'id_token: nonce does not match this sign-in',
    )
  })

  it('an ID token without a nonce is refused', async () => {
    const h = harness({
      fake: {
        google: {
          idTokenClaims: ({ nonce: _drop, ...rest }) => rest,
        },
      },
    })
    const browser = h.browser()
    const response = await browser.request(
      h.fakes.google.consent(await browser.start('google'), USERS.google),
    )
    expect(errorOf(response)).toBe('social_token_invalid')
  })

  it('an Apple hand-over cookie works once', async () => {
    const h = harness({ config: { registration: true } })
    const browser = h.browser()
    const { code, state } = h.fakes.apple.approve(await browser.start('apple'), USERS.apple)
    await formPost(browser, { code, state })
    const handoff = browser.jar.get(cookieName('handoff', 'apple', true)) ?? ''
    expect(errorOf(await browser.request('/auth/apple/callback'))).toBeNull()
    browser.jar.set(cookieName('handoff', 'apple', true), handoff)
    expect(errorOf(await browser.request('/auth/apple/callback'))).toBe('social_state_invalid')
  })

  it('an Apple hand-over older than 2 minutes is refused', async () => {
    const h = harness({ config: { registration: true } })
    const browser = h.browser()
    const { code, state } = h.fakes.apple.approve(await browser.start('apple'), USERS.apple)
    await formPost(browser, { code, state })
    h.clock.advance(2 * 60_000 + 1)
    expect(errorOf(await browser.request('/auth/apple/callback'))).toBe('social_state_invalid')
  })
})

describe('mix-up attacks', () => {
  it('an RFC 9207 iss parameter naming another issuer is refused', async () => {
    const h = harness()
    const browser = h.browser()
    const callback = h.fakes.google.consent(await browser.start('google'), USERS.google, {
      iss: 'https://attacker.test',
    })
    expect(errorOf(await browser.request(callback))).toBe('social_issuer_mismatch')
  })

  it('the right iss parameter passes', async () => {
    const h = harness({ config: { registration: true } })
    const browser = h.browser()
    const callback = h.fakes.google.consent(await browser.start('google'), USERS.google, {
      iss: 'https://google.test',
    })
    expect(errorOf(await browser.request(callback))).toBeNull()
  })

  it('a Google flow cannot be completed at the GitHub callback', async () => {
    const h = harness()
    const browser = h.browser()
    const callback = new URL(h.fakes.google.consent(await browser.start('google'), USERS.google))
    const moved = new URL(`${APP}/auth/github/callback${callback.search}`)
    expect(errorOf(await browser.request(moved.href))).toBe('social_state_invalid')
  })

  it('a Google flow cookie sealed for google does not open as github', async () => {
    const h = harness()
    const sealed = sealFlow(h.sealer, {
      provider: 'google',
      state: 's',
      nonce: 'n',
      verifier: 'v',
      returnTo: '/',
      intent: 'login',
      userId: null,
      issuedAt: h.clock.now(),
    })
    expect(openFlow(h.sealer, 'github', sealed, h.clock.now())).toBeUndefined()
    expect(openFlow(h.sealer, 'google', sealed, h.clock.now())?.state).toBe('s')
  })

  it('an ID token from another issuer is refused', async () => {
    const h = harness({
      fake: { google: { idTokenClaims: (c) => ({ ...c, iss: 'https://evil.test' }) } },
    })
    const browser = h.browser()
    expect(
      errorOf(
        await browser.request(h.fakes.google.consent(await browser.start('google'), USERS.google)),
      ),
    ).toBe('social_token_invalid')
  })

  it('an ID token for another client (aud) is refused', async () => {
    const h = harness({ fake: { google: { idTokenClaims: (c) => ({ ...c, aud: 'other-app' }) } } })
    const browser = h.browser()
    expect(
      errorOf(
        await browser.request(h.fakes.google.consent(await browser.start('google'), USERS.google)),
      ),
    ).toBe('social_token_invalid')
  })

  it('microsoft: a token whose iss names another tenant than its tid is refused', async () => {
    const h = harness({ config: { registration: true } })
    const browser = h.browser()
    const user = {
      ...USERS.microsoft,
      claims: { ...USERS.microsoft.claims, iss: `https://ms.test/${MS_OTHER_TENANT}/v2.0` },
    }
    expect(
      errorOf(
        await browser.request(h.fakes.microsoft.consent(await browser.start('microsoft'), user)),
      ),
    ).toBe('social_token_invalid')
  })

  it('microsoft: allowedTenants refuses other tenants; organizations refuses personal accounts', async () => {
    const other = '22222222-2222-4333-8444-555555555555'
    const h = harness({ providers: { microsoft: { allowedTenants: [other] } } })
    const browser = h.browser()
    expect(
      errorOf(
        await browser.request(
          h.fakes.microsoft.consent(await browser.start('microsoft'), USERS.microsoft),
        ),
      ),
    ).toBe('social_tenant_not_allowed')

    const personal = '9188040d-6c67-4c5b-b112-36a304b66dad'
    const h2 = harness()
    const b2 = h2.browser()
    const msa = {
      ...USERS.microsoft,
      claims: { ...USERS.microsoft.claims, tid: personal, iss: `https://ms.test/${personal}/v2.0` },
    }
    expect(
      errorOf(await b2.request(h2.fakes.microsoft.consent(await b2.start('microsoft'), msa))),
    ).toBe('social_token_invalid')
    expect(MS_TENANT).not.toBe(personal)
  })
})

describe('open redirect through the return URL', () => {
  const evil = [
    'https://evil.test/',
    '//evil.test',
    '/\\evil.test',
    '\\\\evil.test',
    '/%2F%2Fevil.test',
    '/%252F%252Fevil.test',
    'javascript:alert(1)',
    ' /x',
    '/x\r\nSet-Cookie: a=b',
    `${APP}.evil.test/`,
  ]
  for (const target of evil) {
    it(`return_to=${JSON.stringify(target)} lands on the home page`, async () => {
      const h = harness({ config: { registration: true } })
      const browser = h.browser()
      const start = await browser.start('google', `?return_to=${encodeURIComponent(target)}`)
      const response = await browser.request(h.fakes.google.consent(start, USERS.google))
      expect(response.headers.get('location')).toBe('/')
    })
  }

  it('a same-app path with a query is kept', async () => {
    const h = harness({ config: { registration: true } })
    const browser = h.browser()
    const start = await browser.start('google', `?return_to=${encodeURIComponent('/a/b?c=1')}`)
    const response = await browser.request(h.fakes.google.consent(start, USERS.google))
    expect(response.headers.get('location')).toBe('/a/b?c=1')
  })

  it('an identity side redirect to another site is ignored', async () => {
    const base = memorySocialAccounts()
    base.addUser({ id: 'u1', email: 'a@b.test', name: 'A', emailVerified: true })
    await base.link({ provider: 'google', subject: 'g-1', userId: 'u1', email: null })
    const h = harness({
      accounts: { ...base, signIn: async () => ({ redirectTo: 'https://evil.test/' }) },
    })
    const browser = h.browser()
    const response = await browser.request(
      h.fakes.google.consent(await browser.start('google'), USERS.google),
    )
    expect(response.headers.get('location')).toBe('/')
  })

  it('the failure redirect carries only a known code and the provider', async () => {
    const h = harness()
    const browser = h.browser()
    const response = await browser.request(
      '/auth/google/callback?error=<script>&error_description=pwned',
    )
    const location = new URL(response.headers.get('location') ?? '', APP)
    expect(location.pathname).toBe('/login')
    expect([...location.searchParams.keys()]).toEqual(['error', 'provider'])
    expect(location.searchParams.get('error')).toBe('social_provider_error')
  })
})

describe('unverified-email account takeover', () => {
  it('never links a sign-in to an existing account by email, even a verified one', async () => {
    const h = harness({ config: { registration: true } })
    h.accounts.addUser({ id: 'victim', email: 'ada@example.com', name: 'Ada', emailVerified: true })
    const browser = h.browser()
    const response = await browser.request(
      h.fakes.google.consent(await browser.start('google'), USERS.google),
    )
    expect(errorOf(response)).toBe('social_account_exists')
    expect(h.accounts.links.size).toBe(0)
    expect(browser.jar.has('sv_test_session')).toBe(false)
  })

  it('microsoft without xms_edov: the email is unverified, nothing is created or looked up', async () => {
    const base = memorySocialAccounts()
    base.addUser({ id: 'victim', email: 'ada@contoso.test', name: 'Ada', emailVerified: true })
    let lookedUp = false
    const spy = {
      ...base,
      findByEmail: async (email: string) => {
        lookedUp = true
        return base.findByEmail(email)
      },
    }
    const h = harness({ config: { registration: true }, accounts: spy })
    const user = { ...USERS.microsoft, claims: { ...USERS.microsoft.claims, xms_edov: false } }
    const browser = h.browser()
    const response = await browser.request(
      h.fakes.microsoft.consent(await browser.start('microsoft'), user),
    )
    expect(errorOf(response)).toBe('social_email_unverified')
    expect(lookedUp).toBe(false)
    expect(base.links.size).toBe(0)
  })

  it('google with email_verified false cannot create an account', async () => {
    const h = harness({ config: { registration: true } })
    const browser = h.browser()
    const response = await browser.request(
      h.fakes.google.consent(await browser.start('google'), {
        ...USERS.google,
        emailVerified: false,
      }),
    )
    expect(errorOf(response)).toBe('social_email_unverified')
    expect(h.accounts.users.size).toBe(0)
  })

  it('github: an unverified primary email (or only a public profile email) is not used', async () => {
    const h = harness({ config: { registration: true } })
    const browser = h.browser()
    const user = {
      ...USERS.github,
      githubEmails: [
        { email: 'victim@example.com', primary: true, verified: false },
        { email: 'mine@example.com', primary: false, verified: true },
      ],
    }
    const response = await browser.request(
      h.fakes.github.consent(await browser.start('github'), user),
    )
    expect(errorOf(response)).toBe('social_email_unverified')
  })

  it('registration off: a new verified email is refused', async () => {
    const h = harness()
    const browser = h.browser()
    const response = await browser.request(
      h.fakes.google.consent(await browser.start('google'), USERS.google),
    )
    expect(errorOf(response)).toBe('social_registration_closed')
  })

  it('google allowedDomains checks the hd claim, not the email domain', async () => {
    const h = harness({
      config: { registration: true },
      providers: { google: { allowedDomains: ['example.com'] } },
    })
    const browser = h.browser()
    const start = await browser.start('google')
    expect(new URL(start).searchParams.get('hd')).toBe('example.com')
    // A consumer account with an example.com email but no hd claim:
    expect(errorOf(await browser.request(h.fakes.google.consent(start, USERS.google)))).toBe(
      'social_domain_not_allowed',
    )
    const b2 = h.browser()
    const ok = await b2.request(
      h.fakes.google.consent(await b2.start('google'), {
        ...USERS.google,
        claims: { hd: 'example.com' },
      }),
    )
    expect(errorOf(ok)).toBeNull()
  })
})

describe('linking needs a fresh re-authentication by the same user', () => {
  const setup = () => {
    const h = harness()
    h.accounts.addUser({ id: 'u1', email: 'ada@example.com', name: 'Ada', emailVerified: true })
    h.accounts.addUser({ id: 'u2', email: 'bob@example.com', name: 'Bob', emailVerified: true })
    return h
  }

  it('a guest cannot start a link flow', async () => {
    const h = setup()
    const response = await h.browser().request('/auth/github/redirect?intent=link')
    expect(errorOf(response)).toBe('social_reauth_required')
  })

  it('a sign-in older than reauthMinutes cannot start or finish a link', async () => {
    const h = setup()
    const browser = h.browser()
    browser.addCookie(h.accounts.signInAs('u1', h.clock.now() - 11 * 60_000))
    expect(errorOf(await browser.request('/auth/github/redirect?intent=link'))).toBe(
      'social_reauth_required',
    )

    // Fresh enough at the start, too old by the callback (reauthMinutes: 1).
    const strict = harness({ config: { reauthMinutes: 1 } })
    strict.accounts.addUser({
      id: 'u1',
      email: 'ada@example.com',
      name: 'Ada',
      emailVerified: true,
    })
    const b2 = strict.browser()
    b2.addCookie(strict.accounts.signInAs('u1'))
    strict.clock.advance(30_000)
    const start = await b2.start('github', '?intent=link')
    strict.clock.advance(31_000)
    expect(errorOf(await b2.request(strict.fakes.github.consent(start, USERS.github)))).toBe(
      'social_reauth_required',
    )
    expect(strict.accounts.links.size).toBe(0)
  })

  it('the session switching to another user mid-flow is refused', async () => {
    const h = setup()
    const browser = h.browser()
    browser.addCookie(h.accounts.signInAs('u1'))
    const start = await browser.start('github', '?intent=link')
    browser.addCookie(h.accounts.signInAs('u2'))
    expect(errorOf(await browser.request(h.fakes.github.consent(start, USERS.github)))).toBe(
      'social_reauth_required',
    )
  })

  it('signing out mid-flow is refused', async () => {
    const h = setup()
    const browser = h.browser()
    browser.addCookie(h.accounts.signInAs('u1'))
    const start = await browser.start('github', '?intent=link')
    browser.jar.delete('sv_test_session')
    expect(errorOf(await browser.request(h.fakes.github.consent(start, USERS.github)))).toBe(
      'social_reauth_required',
    )
  })

  it('an identity linked to someone else cannot be linked again', async () => {
    const h = setup()
    await h.accounts.link({ provider: 'github', subject: '42', userId: 'u2', email: null })
    const browser = h.browser()
    browser.addCookie(h.accounts.signInAs('u1'))
    const start = await browser.start('github', '?intent=link')
    expect(errorOf(await browser.request(h.fakes.github.consent(start, USERS.github)))).toBe(
      'social_identity_in_use',
    )
  })

  it('apple link: the session is checked on the same-site hand-over, not the cross-site post', async () => {
    const h = setup()
    const browser = h.browser()
    browser.addCookie(h.accounts.signInAs('u1'))
    const { code, state } = h.fakes.apple.approve(
      await browser.start('apple', '?intent=link'),
      USERS.apple,
    )
    // The cross-site POST carries no Lax session cookie; the flow still verifies.
    const session = browser.jar.get('sv_test_session') ?? ''
    browser.jar.delete('sv_test_session')
    const posted = await formPost(browser, { code, state })
    expect(errorOf(posted)).toBeNull()
    browser.jar.set('sv_test_session', session)
    const done = await browser.request('/auth/apple/callback')
    expect(errorOf(done)).toBeNull()
    expect(h.accounts.links.get('apple:apple-1')).toBe('u1')
  })
})

describe('tokens, codes and secrets never reach logs or responses', () => {
  it('nothing secret appears in any log record or redirect, on success or failure', async () => {
    const h = harness({ config: { registration: true } })
    const secrets: string[] = []
    for (const provider of ['google', 'github', 'microsoft'] as const) {
      const browser = h.browser()
      const callback = new URL(
        h.fakes[provider].consent(await browser.start(provider), USERS[provider]),
      )
      secrets.push(
        callback.searchParams.get('code') ?? '',
        callback.searchParams.get('state') ?? '',
      )
      secrets.push(...browser.jar.values())
      await browser.request(callback.href)
      // Replay to produce failure logs too.
      await h.browser().request(callback.href)
    }
    for (const fake of Object.values(h.fakes))
      for (const request of fake.requests)
        for (const value of new URLSearchParams(request.body).values()) secrets.push(value)
    const logged = JSON.stringify(h.logger.records)
    for (const secret of secrets.filter((s) => s.length >= 8)) expect(logged).not.toContain(secret)
    expect(logged).not.toMatch(/eyJ[A-Za-z0-9_-]{10,}/) // no JWTs
    expect(logged).not.toMatch(/@/) // no emails
    expect(logged).toContain('social sign-in')
  })

  it('the client secret is sent only to the token endpoint', async () => {
    const h = harness({ config: { registration: true } })
    const browser = h.browser()
    await browser.request(h.fakes.github.consent(await browser.start('github'), USERS.github))
    for (const request of h.fakes.github.requests) {
      const leaks = request.body.includes('gh-secret') || request.url.includes('gh-secret')
      expect(leaks).toBe(request.url.endsWith('/token'))
    }
  })

  it('the authorization URL carries no secret', async () => {
    const h = harness()
    for (const provider of ['google', 'github', 'microsoft', 'apple'] as const) {
      const location = await h.browser().start(provider)
      expect(location).not.toMatch(/secret|BEGIN|TEAM123456/)
    }
  })
})

describe('Apple form post hardening', () => {
  it('a non-form body, or one over 64 KiB, is refused', async () => {
    const h = harness()
    const browser = h.browser()
    await browser.start('apple')
    const json = await browser.request('/auth/apple/callback', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    })
    expect(errorOf(json)).toBe('social_provider_error')
    const big = await formPost(browser, { pad: 'x'.repeat(70 * 1024) })
    expect(errorOf(big)).toBe('social_provider_error')
  })

  it('a GET to the Apple callback with query parameters is not a hand-over', async () => {
    const h = harness()
    const browser = new Browser(h.handler)
    expect(errorOf(await browser.request('/auth/apple/callback?code=x&state=y'))).toBe(
      'social_state_invalid',
    )
  })

  it('the provider’s error post ends the flow without detail', async () => {
    const h = harness()
    const browser = h.browser()
    await browser.start('apple')
    const response = await formPost(browser, { error: 'user_cancelled_authorize', state: 'x' })
    expect(errorOf(response)).toBe('social_provider_error')
    expect(h.logger.records.at(-1)?.fields['reason']).toContain('user_cancelled_authorize')
  })
})
