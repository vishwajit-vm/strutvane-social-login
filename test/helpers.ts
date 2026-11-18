/**
 * Test harness: the Web handler wired to one fake provider per real driver (no network), the
 * in-memory account store, a manual clock, a recording logger and a tiny browser with a cookie jar.
 */
import { generateKeyPairSync, randomBytes } from 'node:crypto'
import type { SocialAccounts } from '../src/accounts.ts'
import { resolveConfig, type SocialLoginConfig } from '../src/config.ts'
import { keySealer, type Sealer } from '../src/crypto/sealer.ts'
import { memoryReplayGuard, type ReplayGuard } from '../src/flow/replay.ts'
import {
  createSocialLoginHandler,
  type SocialLogger,
  type SocialLoginHandler,
} from '../src/handler.ts'
import { createHttpClient, type FetchLike } from '../src/http/client.ts'
import { createDrivers } from '../src/providers/registry.ts'
import type { ProviderName } from '../src/providers/types.ts'
import {
  createFakeOidcProvider,
  type FakeOidcProvider,
  type FakeProviderOptions,
  type MemorySocialAccounts,
  memorySocialAccounts,
} from '../src/testing/index.ts'

export const APP = 'https://app.test'
export const MS_TENANT = '11111111-2222-4333-8444-555555555555'
export const MS_OTHER_TENANT = '99999999-2222-4333-8444-555555555555'

/** A manual clock starting at a fixed instant. */
export function manualClock(start = Date.UTC(2026, 10, 18, 12, 0, 0)) {
  let t = start
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms
    },
  }
}

export interface LogRecord {
  readonly level: 'info' | 'warn' | 'error'
  readonly msg: string
  readonly fields: Readonly<Record<string, unknown>>
}

/** A logger that keeps everything (to prove nothing secret is logged). */
export function recordingLogger(): SocialLogger & { readonly records: LogRecord[] } {
  const records: LogRecord[] = []
  const at =
    (level: LogRecord['level']) =>
    (msg: string, fields: Readonly<Record<string, unknown>> = {}) => {
      records.push({ level, msg, fields })
    }
  return { records, info: at('info'), warn: at('warn'), error: at('error') }
}

/** An Apple-style `.p8` key. */
export function appleKey(): { pem: string; publicKey: import('node:crypto').KeyObject } {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  return { pem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(), publicKey }
}

export interface HarnessOptions {
  readonly config?: Omit<SocialLoginConfig, 'providers'>
  readonly appUrl?: string
  /** Per-provider fake options (e.g. `idTokenClaims`). */
  readonly fake?: Partial<Record<ProviderName, Partial<FakeProviderOptions>>>
  /** Per-provider config extras (allowedDomains, tenant…). */
  readonly providers?: Partial<Record<ProviderName, Readonly<Record<string, unknown>>>>
  /** Replace the account store (e.g. a failing one). */
  readonly accounts?: SocialAccounts | null
  readonly replay?: ReplayGuard
  /** Wrap the outbound fetch (to inject failures). */
  readonly wrapFetch?: (inner: FetchLike) => FetchLike
}

export interface Harness {
  readonly handler: SocialLoginHandler
  readonly fakes: Readonly<Record<ProviderName, FakeOidcProvider>>
  readonly accounts: MemorySocialAccounts
  readonly logger: ReturnType<typeof recordingLogger>
  readonly clock: ReturnType<typeof manualClock>
  readonly sealer: Sealer
  readonly appleKey: ReturnType<typeof appleKey>
  /** A browser with an empty cookie jar. */
  browser(): Browser
}

/** Build the harness with all four providers enabled. */
export function harness(options: HarnessOptions = {}): Harness {
  const clock = manualClock()
  const logger = recordingLogger()
  const accounts = memorySocialAccounts({ now: clock.now })
  const key = appleKey()
  const fake = (name: ProviderName, issuer: string, extra: Partial<FakeProviderOptions> = {}) =>
    createFakeOidcProvider({
      clientId: `${name}-client`,
      issuer,
      now: clock.now,
      ...extra,
      ...options.fake?.[name],
    })
  const fakes: Record<ProviderName, FakeOidcProvider> = {
    google: fake('google', 'https://google.test', { clientSecret: 'google-secret' }),
    microsoft: fake('microsoft', 'https://ms.test', { clientSecret: 'ms-secret' }),
    github: fake('github', 'https://github.test', { clientSecret: 'gh-secret' }),
    apple: fake('apple', 'https://apple.test'),
  }
  const routes: FetchLike = async (url, init) => {
    const host = new URL(url).host
    const target = Object.values(fakes).find((f) => new URL(f.issuer).host === host)
    if (target === undefined) throw new TypeError(`no fake for ${url}`)
    return target.fetch(url, init)
  }
  const outbound = options.wrapFetch ? options.wrapFetch(routes) : routes
  const ep = (f: FakeOidcProvider, issuer = f.issuer) => ({ ...f.endpoints, issuer })
  const config = resolveConfig(
    {
      ...options.config,
      providers: {
        google: {
          clientId: 'google-client',
          clientSecret: 'google-secret',
          endpoints: ep(fakes.google),
          ...options.providers?.google,
        },
        microsoft: {
          clientId: 'microsoft-client',
          clientSecret: 'ms-secret',
          tenant: 'organizations',
          endpoints: ep(fakes.microsoft, 'https://ms.test/{tenantid}/v2.0'),
          ...options.providers?.microsoft,
        },
        github: {
          clientId: 'github-client',
          clientSecret: 'gh-secret',
          endpoints: ep(fakes.github, ''),
          ...options.providers?.github,
        },
        apple: {
          clientId: 'apple-client',
          teamId: 'TEAM123456',
          keyId: 'KEY1234567',
          privateKey: key.pem,
          endpoints: ep(fakes.apple),
          ...options.providers?.apple,
        },
      },
    },
    options.appUrl ?? APP,
  )
  const sealer = keySealer(randomBytes(32))
  const handler = createSocialLoginHandler({
    config,
    drivers: createDrivers(config.providers, {
      http: createHttpClient({ fetch: outbound }),
      now: clock.now,
    }),
    sealer,
    replay: options.replay ?? memoryReplayGuard({ now: clock.now }),
    accounts: () => (options.accounts === null ? undefined : (options.accounts ?? accounts)),
    logger,
    now: clock.now,
  })
  return {
    handler,
    fakes,
    accounts,
    logger,
    clock,
    sealer,
    appleKey: key,
    browser: () => new Browser(handler),
  }
}

/** A browser: a cookie jar in front of the handler. */
export class Browser {
  readonly jar = new Map<string, string>()
  readonly #handler: SocialLoginHandler
  constructor(handler: SocialLoginHandler) {
    this.#handler = handler
  }

  cookieHeader(): string {
    return [...this.jar].map(([k, v]) => `${k}=${v}`).join('; ')
  }

  /** Add a raw `Cookie` pair (e.g. a session from `accounts.signInAs`). */
  addCookie(pair: string): void {
    const eq = pair.indexOf('=')
    this.jar.set(pair.slice(0, eq), pair.slice(eq + 1))
  }

  async request(url: string, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers)
    if (this.jar.size > 0 && !headers.has('cookie')) headers.set('cookie', this.cookieHeader())
    const response = await this.#handler.fetch(new Request(new URL(url, APP), { ...init, headers }))
    for (const cookie of response.headers.getSetCookie()) {
      const [pair = ''] = cookie.split(';')
      const eq = pair.indexOf('=')
      const name = pair.slice(0, eq)
      const value = pair.slice(eq + 1)
      if (/Max-Age=0/i.test(cookie) || value === '') this.jar.delete(name)
      else this.jar.set(name, value)
    }
    return response
  }

  /** `GET {path}/{provider}/redirect` and return the provider URL. */
  async start(provider: ProviderName, query = ''): Promise<string> {
    const response = await this.request(`/auth/${provider}/redirect${query}`)
    const location = response.headers.get('location')
    if (response.status !== 302 || location === null)
      throw new Error(`start failed: ${response.status} ${location ?? ''}`)
    return location
  }
}

/** The `error` query parameter of a failure redirect. */
export function errorOf(response: Response): string | null {
  const location = response.headers.get('location')
  if (location === null) return null
  return new URL(location, APP).searchParams.get('error')
}

/** Apple-style form post of `fields` to the callback. */
export function formPost(browser: Browser, fields: Readonly<Record<string, string>>) {
  return browser.request('/auth/apple/callback', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields).toString(),
  })
}

/** The default verified users per provider. */
export const USERS = {
  google: { sub: 'g-1', email: 'Ada@Example.com', emailVerified: true, name: 'Ada Lovelace' },
  microsoft: {
    sub: 'ms-sub',
    email: 'ada@contoso.test',
    name: 'Ada',
    claims: {
      iss: `https://ms.test/${MS_TENANT}/v2.0`,
      tid: MS_TENANT,
      oid: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
      xms_edov: true,
    },
  },
  github: {
    sub: 'octo',
    name: 'Octo Cat',
    githubId: 42,
    githubEmails: [
      { email: 'octo@example.com', primary: true, verified: true },
      { email: 'other@example.com', primary: false, verified: true },
    ],
  },
  apple: { sub: 'apple-1', email: 'relay@privaterelay.appleid.test', emailVerified: true },
} as const
