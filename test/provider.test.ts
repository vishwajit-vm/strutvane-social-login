/**
 * The provider on the framework's real kernel (`createApp`, container, hooks, error registry):
 * only public framework subpaths, exactly as an app wires it.
 */
import { randomBytes } from 'node:crypto'
import { CacheManagerToken, EncrypterToken } from '@strutvane/framework'
import {
  HTTP_HOOKS,
  type HttpRequestHookPayload,
  type LogFields,
  type Logger,
} from '@strutvane/framework/contracts'
import {
  createApp,
  defineProvider,
  ErrorRegistryToken,
  HooksToken,
  LoggerToken,
  type Provider,
} from '@strutvane/framework/core'
import { describe, expect, it } from 'vitest'
import { SocialAccountsToken } from '../src/accounts.ts'
import { createSocialLoginProvider, HOOK_NAME } from '../src/provider.ts'
import { createFakeOidcProvider, memorySocialAccounts } from '../src/testing/index.ts'

const APP_KEY = `base64:${randomBytes(32).toString('base64')}`

interface Captured {
  level: string
  msg: string
  fields: LogFields | undefined
}

function capturingLogger(out: Captured[]): Logger {
  const at = (level: string) => (msg: string, fields?: LogFields) => {
    out.push({ level, msg, fields })
  }
  const logger: Logger = {
    trace: at('trace'),
    debug: at('debug'),
    info: at('info'),
    warn: at('warn'),
    error: at('error'),
    fatal: at('fatal'),
    child: () => logger,
    isLevelEnabled: () => true,
    flush: async () => undefined,
  }
  return logger
}

function setup(
  options: {
    settings?: Record<string, unknown>
    bind?: (app: Parameters<Provider['register']>[0]) => void
    env?: Record<string, string | undefined>
  } = {},
) {
  const idp = createFakeOidcProvider({
    clientId: 'gid',
    clientSecret: 'gsecret',
    issuer: 'https://google.test',
  })
  const logs: Captured[] = []
  const accounts = memorySocialAccounts()
  const testing = defineProvider({
    name: 'test-bindings',
    register(app) {
      app.container.value(LoggerToken, capturingLogger(logs))
      if (options.bind) options.bind(app)
      else app.container.value(SocialAccountsToken, accounts)
    },
  })
  const app = createApp({
    config: {
      app: { url: 'https://app.test', key: APP_KEY, env: 'testing' },
      socialLogin: {
        registration: true,
        providers: {
          google: { clientId: 'gid', clientSecret: 'gsecret', endpoints: { ...idp.endpoints } },
          github: { clientId: '', clientSecret: '' },
        },
      },
      ...options.settings,
    },
    providers: [testing, createSocialLoginProvider({ fetch: idp.fetch, env: options.env ?? {} })],
  })
  const run = async (url: string, cookie?: string) => {
    const payload: HttpRequestHookPayload = {
      request: new Request(url, cookie === undefined ? {} : { headers: { cookie } }),
      actor: null,
      tenant: undefined,
    }
    return (await app.make(HooksToken).run(HTTP_HOOKS.request, payload)) as HttpRequestHookPayload
  }
  return { app, idp, logs, accounts, run }
}

describe('provider on the framework kernel', () => {
  it('serves a full sign-in through http.onRequest', async () => {
    const { app, idp, accounts, run } = setup()
    await app.boot()
    const start = await run('https://app.test/auth/google/redirect?return_to=/home')
    const location = start.response?.headers.get('location') ?? ''
    const cookie = (start.response?.headers.getSetCookie()[0] ?? '').split(';')[0] ?? ''
    const callback = await run(
      idp.consent(location, { sub: 's', email: 'a@b.test', emailVerified: true }),
      cookie,
    )
    expect(callback.response?.status).toBe(303)
    expect(callback.response?.headers.get('location')).toBe('/home')
    expect(accounts.links.get('google:s')).toBeDefined()
    expect(app.make(HooksToken).order(HTTP_HOOKS.request)).toEqual([HOOK_NAME])
  })

  it('passes every other request through untouched', async () => {
    const { app, run } = setup()
    await app.boot()
    expect((await run('https://app.test/api/v1/users')).response).toBeUndefined()
    expect((await run('https://app.test/auth/login')).response).toBeUndefined()
  })

  it('registers its error codes and warns about skipped providers', async () => {
    const { app, logs } = setup()
    await app.boot()
    expect(app.make(ErrorRegistryToken).get('social_state_invalid')?.status).toBe(400)
    expect(logs.some((l) => l.level === 'warn' && l.fields?.['provider'] === 'github')).toBe(true)
  })

  it('warns when nothing is bound to SocialAccountsToken, and sign-ins then fail closed', async () => {
    const { app, logs, idp, run } = setup({ bind: () => undefined })
    await app.boot()
    expect(logs.some((l) => l.msg.includes('SocialAccountsToken'))).toBe(true)
    const start = await run('https://app.test/auth/google/redirect')
    const cookie = (start.response?.headers.getSetCookie()[0] ?? '').split(';')[0] ?? ''
    const callback = await run(
      idp.consent(start.response?.headers.get('location') ?? '', {
        sub: 's',
        email: 'a@b.test',
        emailVerified: true,
      }),
      cookie,
    )
    expect(callback.response?.headers.get('location')).toContain(
      'error=social_accounts_unavailable',
    )
  })

  it('fails the boot on a bad setting, naming it', async () => {
    const { app } = setup({ settings: { socialLogin: { reauthMinutes: 0 } } })
    await expect(app.boot()).rejects.toThrow(/reauthMinutes/)
  })

  it('fails the boot without an encrypter or a valid APP_KEY', async () => {
    const { app } = setup({ settings: { app: { url: 'https://app.test' } } })
    await expect(app.boot()).rejects.toThrow(/APP_KEY/)
  })

  it('takes APP_URL and APP_KEY from the environment when config has none', async () => {
    const { app, run } = setup({
      settings: { app: {} },
      env: { APP_URL: 'https://env.test', APP_KEY, APP_ENV: 'local' },
    })
    await app.boot()
    const start = await run('https://env.test/auth/google/redirect')
    expect(
      new URL(start.response?.headers.get('location') ?? '').searchParams.get('redirect_uri'),
    ).toBe('https://env.test/auth/google/callback')
  })

  it('uses the framework encrypter and cache when they are bound', async () => {
    const purposes: string[] = []
    const added: string[] = []
    const { app, run, logs } = setup({
      settings: { app: { url: 'https://app.test', env: 'production' } },
      bind: (a) => {
        a.container.value(SocialAccountsToken, memorySocialAccounts())
        a.container.value(EncrypterToken, {
          encryptString: (p: string, o?: { purpose?: string }) => {
            purposes.push(o?.purpose ?? '')
            return Buffer.from(p).toString('base64url')
          },
          decryptString: (p: string) => Buffer.from(p, 'base64url').toString(),
        } as never)
        a.container.value(CacheManagerToken, {
          defaultStore: 'memory',
          storeNames: ['memory'],
          store: () => ({
            add: async (key: string) => {
              added.push(key)
              return true
            },
          }),
        } as never)
      },
    })
    await app.boot()
    await run('https://app.test/auth/google/redirect')
    expect(purposes).toEqual(['strutvane.social-login.flow:google'])
    expect(logs.some((l) => l.msg.includes('per process'))).toBe(false)
    await run('https://app.test/auth/google/callback?state=x&code=y')
    expect(added).toEqual([])
  })

  it('warns outside local/testing when no cache is bound', async () => {
    const { app, logs } = setup({
      settings: { app: { url: 'https://app.test', key: APP_KEY, env: 'production' } },
    })
    await app.boot()
    expect(logs.some((l) => l.msg.includes('per process'))).toBe(true)
  })

  it('enabled: false registers no hook', async () => {
    const { app } = setup({ settings: { socialLogin: { enabled: false } } })
    await app.boot()
    expect(app.make(HooksToken).order(HTTP_HOOKS.request)).toEqual([])
  })

  it('the default export is a ready provider', async () => {
    const mod = await import('../src/provider.ts')
    expect(mod.default.name).toBe('@strutvane/social-login')
  })
})
