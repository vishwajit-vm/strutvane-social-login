/** Every parser of untrusted input, fuzzed: it never throws (except where documented) and fails closed. */
import { randomBytes } from 'node:crypto'
import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import { resolveConfig, SocialLoginConfigError } from '../src/config.ts'
import { decodeJwt } from '../src/crypto/jwt.ts'
import { keySealer } from '../src/crypto/sealer.ts'
import { isSocialLoginErrorCode } from '../src/errors.ts'
import { openFlow, openHandOff } from '../src/flow/state.ts'
import { readCookie } from '../src/http/cookies.ts'
import { appleUserName } from '../src/providers/apple.ts'
import { primaryEmail } from '../src/providers/github.ts'
import { displayName, normalizeEmail } from '../src/providers/profile.ts'
import { APP, harness } from './helpers.ts'

const runs = { numRuns: 300 }

describe('parsers never throw on hostile input', () => {
  it('decodeJwt', () => {
    fc.assert(
      fc.property(fc.oneof(fc.string(), fc.stringMatching(/^[A-Za-z0-9_.-]{0,200}$/)), (s) => {
        decodeJwt(s)
      }),
      runs,
    )
  })

  it('flow and hand-over cookies (including validly sealed garbage)', () => {
    const sealer = keySealer(randomBytes(32))
    fc.assert(
      fc.property(fc.string(), fc.jsonValue(), (raw, json) => {
        expect(openFlow(sealer, 'google', raw, Date.now())).toBeUndefined()
        expect(openHandOff(sealer, 'apple', raw, Date.now())).toBeUndefined()
        const sealedFlow = sealer.seal('flow:google', JSON.stringify(json))
        const sealedHand = sealer.seal('handoff:apple', JSON.stringify(json))
        expect(openFlow(sealer, 'google', sealedFlow, Date.now())).toBeUndefined()
        expect(openHandOff(sealer, 'apple', sealedHand, Date.now())).toBeUndefined()
      }),
      runs,
    )
  })

  it('cookies, emails, names, GitHub email lists and Apple user fields', () => {
    fc.assert(
      fc.property(fc.string(), fc.jsonValue(), (s, json) => {
        readCookie(s, 'n')
        normalizeEmail(s)
        displayName(s)
        appleUserName(s)
        primaryEmail(json)
      }),
      runs,
    )
  })

  it('config: only SocialLoginConfigError, never anything else', () => {
    fc.assert(
      fc.property(fc.jsonValue(), fc.string(), (raw, url) => {
        for (const appUrl of [url, APP]) {
          try {
            resolveConfig(raw, appUrl)
          } catch (error) {
            expect(error).toBeInstanceOf(SocialLoginConfigError)
          }
        }
      }),
      runs,
    )
  })
})

describe('the handler never throws and only ever redirects to this app', () => {
  it('random callback queries and form posts', async () => {
    const h = harness()
    const browser = h.browser()
    await browser.start('google')
    await fc.assert(
      fc.asyncProperty(
        fc.dictionary(fc.constantFrom('code', 'state', 'error', 'iss', 'user', 'x'), fc.string(), {
          maxKeys: 5,
        }),
        fc.constantFrom('google', 'github', 'microsoft', 'apple'),
        fc.boolean(),
        async (params, provider, post) => {
          const query = new URLSearchParams(params).toString()
          const response = post
            ? await h.handler.fetch(
                new Request(`${APP}/auth/${provider}/callback`, {
                  method: 'POST',
                  headers: {
                    'content-type': 'application/x-www-form-urlencoded',
                    cookie: browser.cookieHeader(),
                  },
                  body: query,
                }),
              )
            : await h.handler.fetch(
                new Request(`${APP}/auth/${provider}/callback?${query}`, {
                  headers: { cookie: browser.cookieHeader() },
                }),
              )
          if (response.status === 405) return
          expect(response.status).toBe(303)
          const location = new URL(response.headers.get('location') ?? '', APP)
          expect(location.origin).toBe(APP)
          const code = location.searchParams.get('error') ?? ''
          expect(isSocialLoginErrorCode(code) || code === 'internal_error').toBe(true)
        },
      ),
      { numRuns: 150 },
    )
  })

  it('random return_to values never leave the app', async () => {
    const h = harness()
    await fc.assert(
      fc.asyncProperty(fc.string(), async (target) => {
        const response = await h.handler.fetch(
          new Request(`${APP}/auth/google/redirect?return_to=${encodeURIComponent(target)}`),
        )
        expect(response.status).toBe(302)
        const cookie = (response.headers.getSetCookie()[0] ?? '').split(';')[0] ?? ''
        const flow = openFlow(
          h.sealer,
          'google',
          cookie.slice(cookie.indexOf('=') + 1),
          h.clock.now(),
        )
        const landing = new URL(flow?.returnTo ?? 'https://broken.test', APP)
        expect(landing.origin).toBe(APP)
        expect(flow?.returnTo.startsWith('//')).toBe(false)
      }),
      { numRuns: 200 },
    )
  })
})
