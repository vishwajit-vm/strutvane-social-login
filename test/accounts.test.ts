import { describe, expect, it } from 'vitest'
import { resolveAccount } from '../src/accounts/resolve.ts'
import type { SocialAccounts } from '../src/accounts.ts'
import { isSocialLoginErrorCode, SOCIAL_LOGIN_ERRORS, SocialLoginError } from '../src/errors.ts'
import { cacheReplayGuard, memoryReplayGuard } from '../src/flow/replay.ts'
import type { SocialProfile } from '../src/providers/types.ts'
import { memorySocialAccounts } from '../src/testing/index.ts'
import { socialLoginUrl } from '../src/url.ts'
import { manualClock } from './helpers.ts'

const profile: SocialProfile = {
  provider: 'google',
  subject: 's1',
  email: 'ada@example.com',
  emailVerified: true,
  name: null,
}
const request = new Request('https://app.test/auth/google/callback')

const run = (accounts: SocialAccounts, over: Partial<Parameters<typeof resolveAccount>[0]> = {}) =>
  resolveAccount({
    profile,
    intent: 'login',
    flowUserId: null,
    request,
    accounts,
    registration: true,
    reauthMs: 600_000,
    now: Date.now(),
    ...over,
  })

describe('account rules (races and edge cases)', () => {
  it('a new account without a display name is named after the email', async () => {
    const accounts = memorySocialAccounts()
    const outcome = await run(accounts)
    expect(outcome).toMatchObject({ kind: 'signed_in', created: true })
    expect([...accounts.users.values()][0]?.name).toBe('ada')
  })

  it('a concurrent sign-up taking the email is account_exists, never a link', async () => {
    const accounts = { ...memorySocialAccounts(), createUser: async () => undefined }
    await expect(run(accounts)).rejects.toMatchObject({ code: 'social_account_exists' })
  })

  it('a concurrent link of the same identity is identity_in_use', async () => {
    const accounts = { ...memorySocialAccounts(), link: async () => 'conflict' as const }
    await expect(run(accounts)).rejects.toMatchObject({ code: 'social_identity_in_use' })
    const base = memorySocialAccounts()
    base.addUser({ id: 'u1', email: 'x@y.z', name: 'X', emailVerified: true })
    const cookie = base.signInAs('u1')
    const linking = { ...base, link: async () => 'conflict' as const }
    await expect(
      run(linking, {
        intent: 'link',
        flowUserId: 'u1',
        request: new Request('https://app.test/', { headers: { cookie } }),
      }),
    ).rejects.toMatchObject({ code: 'social_identity_in_use' })
  })

  it('an identity system reporting already_linked on link is fine', async () => {
    const base = memorySocialAccounts()
    base.addUser({ id: 'u1', email: 'x@y.z', name: 'X', emailVerified: true })
    const cookie = base.signInAs('u1')
    const outcome = await run(
      { ...base, link: async () => 'already_linked' as const },
      {
        intent: 'link',
        flowUserId: 'u1',
        request: new Request('https://app.test/', { headers: { cookie } }),
      },
    )
    expect(outcome).toEqual({ kind: 'linked', userId: 'u1', alreadyLinked: true })
  })

  it('a link flow without a recorded user is refused', async () => {
    const base = memorySocialAccounts()
    base.addUser({ id: 'u1', email: 'x@y.z', name: 'X', emailVerified: true })
    const cookie = base.signInAs('u1')
    await expect(
      run(base, {
        intent: 'link',
        flowUserId: null,
        request: new Request('https://app.test/', { headers: { cookie } }),
      }),
    ).rejects.toMatchObject({ code: 'social_reauth_required' })
  })

  it('no email at all is social_email_unverified', async () => {
    await expect(
      run(memorySocialAccounts(), { profile: { ...profile, email: null } }),
    ).rejects.toMatchObject({
      code: 'social_email_unverified',
    })
  })
})

describe('memory account store (the reference implementation)', () => {
  it('matches emails case-insensitively, refuses duplicates and reports link results', async () => {
    const accounts = memorySocialAccounts()
    accounts.addUser({ id: 'u1', email: 'Ada@Example.com', name: 'Ada', emailVerified: true })
    expect(await accounts.findByEmail('ada@example.COM')).toEqual({ id: 'u1' })
    expect(await accounts.findByEmail('nobody@example.com')).toBeUndefined()
    expect(
      await accounts.createUser({ email: 'ADA@example.com', name: 'x', emailVerified: true }),
    ).toBeUndefined()
    const id = { provider: 'github', subject: '1' }
    expect(await accounts.findByIdentity(id)).toBeUndefined()
    expect(await accounts.link({ ...id, userId: 'u1', email: null })).toBe('linked')
    expect(await accounts.link({ ...id, userId: 'u1', email: null })).toBe('already_linked')
    expect(await accounts.link({ ...id, userId: 'u2', email: null })).toBe('conflict')
    expect(await accounts.findByIdentity(id)).toEqual({ id: 'u1' })
  })

  it('sessions: signInAs and signIn issue fresh ids; unknown cookies are guests', async () => {
    const clock = manualClock()
    const accounts = memorySocialAccounts({ now: clock.now })
    accounts.addUser({ id: 'u1', email: 'a@b.c', name: 'A', emailVerified: true })
    const cookie = accounts.signInAs('u1', 5)
    expect(await accounts.currentUser(new Request('https://x/', { headers: { cookie } }))).toEqual({
      id: 'u1',
      authenticatedAt: 5,
    })
    expect(
      await accounts.currentUser(
        new Request('https://x/', { headers: { cookie: 'sv_test_session=nope' } }),
      ),
    ).toBeNull()
    expect(await accounts.currentUser(new Request('https://x/'))).toBeNull()
    const a = await accounts.signIn({
      userId: 'u1',
      provider: 'google',
      request: new Request('https://x/', { headers: { cookie } }),
    })
    const issued = a.headers?.getSetCookie()[0] ?? ''
    expect(issued).not.toContain(cookie.split('=')[1])
    expect(accounts.sessions.size).toBe(2)
  })
})

describe('replay guards', () => {
  it('memory: claims once, frees after the TTL, and fails closed when full', async () => {
    const clock = manualClock()
    const guard = memoryReplayGuard({ now: clock.now, maxEntries: 2 })
    expect(await guard.claim('a', 10)).toBe(true)
    expect(await guard.claim('a', 10)).toBe(false)
    expect(await guard.claim('b', 10)).toBe(true)
    expect(await guard.claim('c', 10)).toBe(false) // full of live entries
    clock.advance(10_001)
    expect(await guard.claim('c', 10)).toBe(true) // expired ones were dropped
    expect(await guard.claim('a', 10)).toBe(true)
  })

  it('memory: default clock and size work', async () => {
    const guard = memoryReplayGuard()
    expect(await guard.claim('x', 1)).toBe(true)
    expect(await guard.claim('x', 1)).toBe(false)
  })

  it('cache: uses atomic add on a hashed key, never the raw value', async () => {
    const keys: string[] = []
    const store = new Map<string, unknown>()
    const guard = cacheReplayGuard({
      add: async (key, value) => {
        keys.push(key)
        if (store.has(key)) return false
        store.set(key, value)
        return true
      },
    })
    expect(await guard.claim('secret-state', 60)).toBe(true)
    expect(await guard.claim('secret-state', 60)).toBe(false)
    expect(keys[0]).toMatch(/^social_login:once:[A-Za-z0-9_-]{43}$/)
    expect(keys.join()).not.toContain('secret-state')
  })
})

describe('errors and links', () => {
  it('every code is lowercase snake_case with a status and title', () => {
    for (const d of SOCIAL_LOGIN_ERRORS) {
      expect(d.code).toMatch(/^social_[a-z_]+$/)
      expect(d.status).toBeGreaterThanOrEqual(400)
      expect(d.title.length).toBeGreaterThan(5)
      expect(d.owner).toBe('@strutvane/social-login')
      expect(isSocialLoginErrorCode(d.code)).toBe(true)
    }
    expect(isSocialLoginErrorCode('internal_error')).toBe(false)
  })

  it('SocialLoginError carries the registered status and a log-safe reason', () => {
    const error = new SocialLoginError('social_reauth_required', 'why', { cause: new Error('x') })
    expect(error.status).toBe(401)
    expect(error.reason).toBe('why')
    expect(error.cause).toBeInstanceOf(Error)
    expect(new SocialLoginError('social_provider_unavailable', 'r').status).toBe(503)
  })

  it('socialLoginUrl builds redirect paths', () => {
    expect(socialLoginUrl('google')).toBe('/auth/google/redirect')
    expect(socialLoginUrl('google', { returnTo: '/dashboard' })).toBe(
      '/auth/google/redirect?return_to=%2Fdashboard',
    )
    expect(socialLoginUrl('github', { intent: 'link', path: '/oauth' })).toBe(
      '/oauth/github/redirect?intent=link',
    )
    expect(socialLoginUrl('apple', { intent: 'login' })).toBe('/auth/apple/redirect')
  })
})
