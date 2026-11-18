import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { defaultEndpoints, resolveConfig, SocialLoginConfigError } from '../src/config.ts'
import { appleKey } from './helpers.ts'

const APP = 'https://app.example.com'
const google = { clientId: 'id', clientSecret: 'secret' }

const settingOf = (fn: () => unknown): string => {
  try {
    fn()
    return 'no error'
  } catch (error) {
    return error instanceof SocialLoginConfigError ? error.setting : `unexpected: ${String(error)}`
  }
}

describe('config/social-login.ts', () => {
  it('has safe defaults: registration off, /auth, 10 minutes, / and /login', () => {
    const config = resolveConfig(undefined, APP)
    expect(config).toMatchObject({
      enabled: true,
      path: '/auth',
      registration: false,
      reauthMs: 600_000,
      home: '/',
      failure: '/login',
      appOrigin: APP,
      secure: true,
    })
    expect(config.providers.size).toBe(0)
  })

  it('resolves providers with default scopes, endpoints and exact callback URLs', () => {
    const config = resolveConfig(
      {
        path: '/oauth',
        providers: {
          google: {
            ...google,
            scopes: ['https://www.googleapis.com/auth/calendar.readonly', 'email'],
          },
        },
      },
      `${APP}/ignored/path`,
    )
    const g = config.providers.get('google')
    expect(g?.redirectUri).toBe(`${APP}/oauth/google/callback`)
    expect(g?.scopes).toEqual([
      'openid',
      'email',
      'profile',
      'https://www.googleapis.com/auth/calendar.readonly',
    ])
    expect(g?.endpoints).toEqual(defaultEndpoints('google'))
  })

  it('skips a provider whose credentials are all empty (installer default), and turned-off ones', () => {
    const config = resolveConfig(
      {
        providers: {
          google: { clientId: '', clientSecret: undefined },
          github: { ...google, enabled: false },
        },
      },
      APP,
    )
    expect(config.providers.size).toBe(0)
    expect(config.skipped).toEqual(['google'])
  })

  it.each([
    ['providers.google.clientSecret', { providers: { google: { clientId: 'id' } } }],
    ['providers.google.clientId', { providers: { google: { clientSecret: 's' } } }],
    ['providers.facebook', { providers: { facebook: google } }],
    ['providers.google', { providers: { google: 'x' } }],
    ['providers.google.clientId', { providers: { google: { clientId: 5, clientSecret: 's' } } }],
    ['providers.google.enabled', { providers: { google: { ...google, enabled: 'yes' } } }],
    ['providers.google.scopes', { providers: { google: { ...google, scopes: 'openid' } } }],
    ['providers.google.scopes[0]', { providers: { google: { ...google, scopes: ['a b'] } } }],
    [
      'providers.google.allowedDomains[0]',
      { providers: { google: { ...google, allowedDomains: ['Example.com'] } } },
    ],
    ['providers.google.endpoints', { providers: { google: { ...google, endpoints: 'x' } } }],
    [
      'providers.google.endpoints.token',
      { providers: { google: { ...google, endpoints: { token: 'http://idp.example/token' } } } },
    ],
    [
      'providers.google.endpoints.token',
      { providers: { google: { ...google, endpoints: { token: 'not a url' } } } },
    ],
    [
      'providers.google.endpoints.token',
      { providers: { google: { ...google, endpoints: { token: 'https://u:p@idp.example/' } } } },
    ],
    [
      'providers.microsoft.tenant',
      { providers: { microsoft: { ...google, tenant: 'contoso.onmicrosoft.com' } } },
    ],
    [
      'providers.microsoft.allowedTenants[0]',
      { providers: { microsoft: { ...google, allowedTenants: ['x'] } } },
    ],
    [
      'providers.microsoft.allowedTenants',
      {
        providers: {
          microsoft: {
            ...google,
            tenant: '11111111-2222-4333-8444-555555555555',
            allowedTenants: ['22222222-2222-4333-8444-555555555555'],
          },
        },
      },
    ],
    [
      'providers.apple.privateKey',
      { providers: { apple: { clientId: 'a', teamId: 't', keyId: 'k', privateKey: 'nope' } } },
    ],
    [
      'providers.apple.teamId',
      { providers: { apple: { clientId: 'a', keyId: 'k', privateKey: 'p' } } },
    ],
    ['path', { path: 'auth' }],
    ['path', { path: '/auth/' }],
    ['path', { path: '/a b' }],
    ['reauthMinutes', { reauthMinutes: 0 }],
    ['reauthMinutes', { reauthMinutes: 61 }],
    ['reauthMinutes', { reauthMinutes: 1.5 }],
    ['redirects', { redirects: [] }],
    ['redirects.home', { redirects: { home: 'https://evil.test/' } }],
    ['redirects.failure', { redirects: { failure: '//evil.test' } }],
    ['registration', { registration: 'yes' }],
    ['enabled', { enabled: 1 }],
    ['providers', { providers: [] }],
    ['(root)', 'x'],
  ])('refuses %s', (setting, raw) => {
    expect(settingOf(() => resolveConfig(raw, APP))).toBe(setting)
  })

  it('needs an https APP_URL, except on loopback', () => {
    expect(settingOf(() => resolveConfig({}, 'http://app.example.com'))).toBe('APP_URL')
    expect(settingOf(() => resolveConfig({}, 'ftp://app.example.com'))).toBe('APP_URL')
    expect(settingOf(() => resolveConfig({}, 'not a url'))).toBe('APP_URL')
    const local = resolveConfig({}, 'http://localhost:3000')
    expect(local.secure).toBe(false)
    expect(
      resolveConfig(
        { providers: { google: { ...google, endpoints: { token: 'http://127.0.0.1:9/token' } } } },
        APP,
      ).providers.get('google')?.endpoints.token,
    ).toBe('http://127.0.0.1:9/token')
  })

  it('Apple needs https and an EC P-256 key; \\n in .env is accepted', () => {
    const { pem } = appleKey()
    const apple = {
      clientId: 'svc',
      teamId: 'T',
      keyId: 'K',
      privateKey: pem.replaceAll('\n', '\\n'),
    }
    expect(resolveConfig({ providers: { apple } }, APP).providers.get('apple')?.name).toBe('apple')
    expect(settingOf(() => resolveConfig({ providers: { apple } }, 'http://localhost:3000'))).toBe(
      'providers.apple',
    )
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
      .privateKey.export({ format: 'pem', type: 'pkcs8' })
      .toString()
    expect(
      settingOf(() => resolveConfig({ providers: { apple: { ...apple, privateKey: rsa } } }, APP)),
    ).toBe('providers.apple.privateKey')
  })

  it('Microsoft: default organizations endpoints; a tenant id narrows them', () => {
    const m = resolveConfig({ providers: { microsoft: google } }, APP).providers.get('microsoft')
    expect(m?.endpoints.authorization).toBe(
      'https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize',
    )
    expect(m?.endpoints.issuer).toBe('https://login.microsoftonline.com/{tenantid}/v2.0')
    const t = '11111111-2222-4333-8444-555555555555'
    const single = resolveConfig(
      { providers: { microsoft: { ...google, tenant: t, allowedTenants: [t] } } },
      APP,
    )
    expect(single.providers.get('microsoft')?.endpoints.jwks).toBe(
      `https://login.microsoftonline.com/${t}/discovery/v2.0/keys`,
    )
  })

  it('endpoint overrides keep an issuer string as is (it is compared, not fetched)', () => {
    const g = resolveConfig(
      { providers: { google: { ...google, endpoints: { issuer: 'accounts.google.com' } } } },
      APP,
    )
    expect(g.providers.get('google')?.endpoints.issuer).toBe('accounts.google.com')
    expect(defaultEndpoints('github').api).toBe('https://api.github.com')
    expect(defaultEndpoints('apple').issuer).toBe('https://appleid.apple.com')
  })

  it('the error message names the file, the setting and the fix', () => {
    try {
      resolveConfig({ reauthMinutes: 0 }, APP)
    } catch (error) {
      expect(String(error)).toContain(
        'config/social-login.ts: reauthMinutes: must be a whole number from 1 to 60',
      )
    }
  })
})
