/**
 * `config/social-login.ts` (key `socialLogin`): what the app writes, and the checked, resolved
 * form the provider runs on.
 *
 * Every setting is validated at boot, and a wrong one stops the boot with a message naming the
 * setting and how to fix it: a typo in a security setting must never silently weaken it (an
 * unknown Microsoft tenant, a redirect to another site, an `http` callback in production). The one
 * deliberate exception is a provider whose credentials are still empty, which the installer
 * leaves for the developer to fill in: it is skipped with a warning instead of stopping
 * development.
 *
 * @module
 */
import { createPrivateKey, type KeyObject } from 'node:crypto'
import { safeRedirectTarget } from '@strutvane/framework'
import { PROVIDER_NAMES, type ProviderName } from './providers/types.ts'

/** Endpoint overrides (a self-hosted test provider, a sovereign cloud). Each must be `https`. */
export interface EndpointOverrides {
  readonly authorization?: string
  readonly token?: string
  readonly jwks?: string
  readonly issuer?: string
  /** GitHub only: the REST API base (`https://api.github.com`). */
  readonly api?: string
}

interface BaseProviderConfig {
  /** Turn the provider off without deleting its settings. Default `true`. */
  readonly enabled?: boolean
  readonly clientId?: string
  /** Extra scopes (the defaults below are always requested). */
  readonly scopes?: readonly string[]
  readonly endpoints?: EndpointOverrides
}

/** Google (OpenID Connect). */
export interface GoogleConfig extends BaseProviderConfig {
  readonly clientSecret?: string
  /** Only Google Workspace accounts of these domains (the `hd` claim) may sign in. Default: any. */
  readonly allowedDomains?: readonly string[]
}

/** Microsoft identity platform v2 (OpenID Connect). */
export interface MicrosoftConfig extends BaseProviderConfig {
  readonly clientSecret?: string
  /**
   * `common` (any work, school or personal account), `organizations` (work and school only),
   * `consumers` (personal only), or one tenant's id (a GUID). Default `organizations`.
   */
  readonly tenant?: string
  /** With a multi-tenant `tenant`: only these tenant ids may sign in. Default: any. */
  readonly allowedTenants?: readonly string[]
}

/** GitHub (OAuth 2.0; no ID token, emails from the API). */
export interface GitHubConfig extends BaseProviderConfig {
  readonly clientSecret?: string
}

/** Sign in with Apple (OpenID Connect, form post, client secret signed with your key). */
export interface AppleConfig extends BaseProviderConfig {
  /** Your Apple Developer team id. */
  readonly teamId?: string
  /** The id of the Sign in with Apple private key. */
  readonly keyId?: string
  /** The `.p8` private key (PEM). A `\n` written as two characters is accepted (from `.env`). */
  readonly privateKey?: string
}

/** Everything `config/social-login.ts` may contain. */
export interface SocialLoginConfig {
  /** Serve the social sign-in routes at all. Default `true`. */
  readonly enabled?: boolean
  /** Route prefix: `{path}/{provider}/redirect` and `{path}/{provider}/callback`. Default `/auth`. */
  readonly path?: string
  /**
   * Create a new account when someone signs in with a provider for the first time (verified email
   * only). Default `false`, matching `@strutvane/auth`'s invite-only default.
   */
  readonly registration?: boolean
  /** How recent a sign-in or password confirmation must be to link a provider. 1–60, default 10. */
  readonly reauthMinutes?: number
  /** Where the browser goes after sign-in (`home`) or a failure (`failure`, gets `?error=<code>`). */
  readonly redirects?: { readonly home?: string; readonly failure?: string }
  readonly providers?: {
    readonly google?: GoogleConfig
    readonly microsoft?: MicrosoftConfig
    readonly github?: GitHubConfig
    readonly apple?: AppleConfig
  }
}

/** A provider's endpoints after defaults and overrides. */
export interface ResolvedEndpoints {
  readonly authorization: string
  readonly token: string
  readonly jwks: string
  readonly issuer: string
  readonly api: string
}

interface ResolvedBase {
  readonly clientId: string
  readonly scopes: readonly string[]
  readonly redirectUri: string
}

/** One enabled, fully configured provider. */
export type ResolvedProvider =
  | (ResolvedBase & {
      readonly name: 'google'
      readonly clientSecret: string
      readonly allowedDomains: readonly string[]
      readonly endpoints: ResolvedEndpoints
    })
  | (ResolvedBase & {
      readonly name: 'microsoft'
      readonly clientSecret: string
      readonly tenant: string
      readonly allowedTenants: readonly string[]
      readonly endpoints: ResolvedEndpoints
    })
  | (ResolvedBase & {
      readonly name: 'github'
      readonly clientSecret: string
      readonly endpoints: ResolvedEndpoints
    })
  | (ResolvedBase & {
      readonly name: 'apple'
      readonly teamId: string
      readonly keyId: string
      readonly privateKey: KeyObject
      readonly endpoints: ResolvedEndpoints
    })

/** The checked configuration. */
export interface ResolvedConfig {
  readonly enabled: boolean
  readonly path: string
  readonly registration: boolean
  readonly reauthMs: number
  readonly home: string
  readonly failure: string
  /** The app's origin (`https://app.example.com`). */
  readonly appOrigin: string
  /** Whether cookies get `Secure` and the `__Host-` prefix (an `https` app URL). */
  readonly secure: boolean
  readonly providers: ReadonlyMap<ProviderName, ResolvedProvider>
  /** Providers listed but skipped because their credentials are empty (for a boot warning). */
  readonly skipped: readonly ProviderName[]
}

/** A setting that can't be used. The message names it and says how to fix it. */
export class SocialLoginConfigError extends Error {
  /** The setting's path, e.g. `providers.microsoft.tenant`. */
  readonly setting: string
  constructor(setting: string, message: string) {
    super(`config/social-login.ts: ${setting}: ${message}`)
    this.name = 'SocialLoginConfigError'
    this.setting = setting
  }
}

/** Microsoft's personal-accounts tenant (`consumers`). */
export const MICROSOFT_CONSUMERS_TENANT = '9188040d-6c67-4c5b-b112-36a304b66dad'

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const MICROSOFT_KEYWORDS = new Set(['common', 'organizations', 'consumers'])
const PATH = /^\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/
/** RFC 6749 §3.3 scope-token. */
const SCOPE = /^[\x21\x23-\x5B\x5D-\x7E]{1,128}$/
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]'])

const DEFAULT_SCOPES: Readonly<Record<ProviderName, readonly string[]>> = {
  google: ['openid', 'email', 'profile'],
  microsoft: ['openid', 'email', 'profile'],
  github: ['read:user', 'user:email'],
  apple: ['name', 'email'],
}

/** The providers' published endpoints (dated 2026-11-18; see the README for sources). */
export function defaultEndpoints(name: ProviderName, tenant = 'organizations'): ResolvedEndpoints {
  switch (name) {
    case 'google':
      return {
        authorization: 'https://accounts.google.com/o/oauth2/v2/auth',
        token: 'https://oauth2.googleapis.com/token',
        jwks: 'https://www.googleapis.com/oauth2/v3/certs',
        issuer: 'https://accounts.google.com',
        api: '',
      }
    case 'microsoft':
      return {
        authorization: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
        token: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
        jwks: `https://login.microsoftonline.com/${tenant}/discovery/v2.0/keys`,
        // `{tenantid}` is replaced with the token's own `tid` when validating (providers/microsoft.ts).
        issuer: 'https://login.microsoftonline.com/{tenantid}/v2.0',
        api: '',
      }
    case 'github':
      return {
        authorization: 'https://github.com/login/oauth/authorize',
        token: 'https://github.com/login/oauth/access_token',
        jwks: '',
        issuer: '',
        api: 'https://api.github.com',
      }
    case 'apple':
      return {
        authorization: 'https://appleid.apple.com/auth/authorize',
        token: 'https://appleid.apple.com/auth/token',
        jwks: 'https://appleid.apple.com/auth/keys',
        issuer: 'https://appleid.apple.com',
        api: '',
      }
  }
}

const isObject = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

/** A trimmed non-empty string, `undefined` for absent/empty, or an error for any other type. */
function optionalString(value: unknown, setting: string): string | undefined {
  if (value === undefined || value === null) return undefined
  if (typeof value !== 'string') throw new SocialLoginConfigError(setting, 'must be a string')
  const trimmed = value.trim()
  return trimmed === '' ? undefined : trimmed
}

function bool(value: unknown, fallback: boolean, setting: string): boolean {
  if (value === undefined) return fallback
  if (typeof value !== 'boolean') throw new SocialLoginConfigError(setting, 'must be true or false')
  return value
}

function stringList(
  value: unknown,
  setting: string,
  check: (item: string) => boolean,
  hint: string,
): readonly string[] {
  if (value === undefined) return []
  if (!Array.isArray(value)) throw new SocialLoginConfigError(setting, 'must be a list of strings')
  return value.map((item, i) => {
    if (typeof item !== 'string' || !check(item))
      throw new SocialLoginConfigError(`${setting}[${i}]`, hint)
    return item
  })
}

/** An endpoint must be `https` (plain `http` only on a loopback host, for local test providers). */
function endpoint(value: unknown, fallback: string, setting: string): string {
  const given = optionalString(value, setting)
  if (given === undefined) return fallback
  let url: URL
  try {
    url = new URL(given)
  } catch {
    throw new SocialLoginConfigError(setting, 'must be an absolute URL')
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && LOOPBACK.has(url.hostname)))
    throw new SocialLoginConfigError(setting, 'must use https')
  if (url.username !== '' || url.password !== '')
    throw new SocialLoginConfigError(setting, 'must not contain credentials')
  return url.href
}

function endpoints(
  given: unknown,
  name: ProviderName,
  tenant: string | undefined,
  setting: string,
): ResolvedEndpoints {
  const base = defaultEndpoints(name, tenant)
  if (given === undefined) return base
  if (!isObject(given)) throw new SocialLoginConfigError(setting, 'must be an object')
  return {
    authorization: endpoint(given['authorization'], base.authorization, `${setting}.authorization`),
    token: endpoint(given['token'], base.token, `${setting}.token`),
    jwks: endpoint(given['jwks'], base.jwks, `${setting}.jwks`),
    // An issuer is an identifier, compared exactly; it is not fetched.
    issuer: optionalString(given['issuer'], `${setting}.issuer`) ?? base.issuer,
    api: endpoint(given['api'], base.api, `${setting}.api`),
  }
}

/** Read a `.p8` key; `\n` typed as two characters in `.env` is turned into a newline. */
function applePrivateKey(pem: string, setting: string): KeyObject {
  try {
    const key = createPrivateKey({ key: pem.replaceAll('\\n', '\n'), format: 'pem' })
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1')
      throw new Error('not P-256')
    return key
  } catch {
    throw new SocialLoginConfigError(
      setting,
      'is not a Sign in with Apple key: paste the whole .p8 file (an EC P-256 PEM key)',
    )
  }
}

/** Resolve one provider; `undefined` when it is off or its credentials are still empty. */
function resolveProvider(
  name: ProviderName,
  raw: unknown,
  redirectBase: string,
  secure: boolean,
  skipped: ProviderName[],
): ResolvedProvider | undefined {
  const at = `providers.${name}`
  if (raw === undefined) return undefined
  if (!isObject(raw)) throw new SocialLoginConfigError(at, 'must be an object')
  if (!bool(raw['enabled'], true, `${at}.enabled`)) return undefined
  const clientId = optionalString(raw['clientId'], `${at}.clientId`)
  const secretKeys = name === 'apple' ? ['teamId', 'keyId', 'privateKey'] : ['clientSecret']
  const secrets = secretKeys.map((k) => optionalString(raw[k], `${at}.${k}`))
  if (clientId === undefined && secrets.every((s) => s === undefined)) {
    skipped.push(name)
    return undefined
  }
  if (clientId === undefined)
    throw new SocialLoginConfigError(
      `${at}.clientId`,
      'is empty while the other credentials are set',
    )
  secretKeys.forEach((k, i) => {
    if (secrets[i] === undefined)
      throw new SocialLoginConfigError(
        `${at}.${k}`,
        'is empty: set it in .env or turn the provider off',
      )
  })
  const scopes = [
    ...new Set([
      ...DEFAULT_SCOPES[name],
      ...stringList(raw['scopes'], `${at}.scopes`, (s) => SCOPE.test(s), 'is not a valid scope'),
    ]),
  ]
  const redirectUri = `${redirectBase}/${name}/callback`
  const base = { clientId, scopes, redirectUri }
  switch (name) {
    case 'google':
      return {
        ...base,
        name,
        clientSecret: secrets[0] ?? '',
        allowedDomains: stringList(
          raw['allowedDomains'],
          `${at}.allowedDomains`,
          (d) => DOMAIN.test(d),
          'must be a lower-case domain name like example.com',
        ),
        endpoints: endpoints(raw['endpoints'], name, undefined, `${at}.endpoints`),
      }
    case 'microsoft': {
      const tenant = optionalString(raw['tenant'], `${at}.tenant`) ?? 'organizations'
      if (!MICROSOFT_KEYWORDS.has(tenant) && !GUID.test(tenant))
        throw new SocialLoginConfigError(
          `${at}.tenant`,
          'must be common, organizations, consumers or a tenant id (a lower-case GUID)',
        )
      const allowedTenants = stringList(
        raw['allowedTenants'],
        `${at}.allowedTenants`,
        (t) => GUID.test(t),
        'must be a tenant id (a lower-case GUID)',
      )
      if (GUID.test(tenant) && allowedTenants.some((t) => t !== tenant))
        throw new SocialLoginConfigError(
          `${at}.allowedTenants`,
          `lists another tenant than the single tenant ${tenant}`,
        )
      return {
        ...base,
        name,
        clientSecret: secrets[0] ?? '',
        tenant,
        allowedTenants,
        endpoints: endpoints(raw['endpoints'], name, tenant, `${at}.endpoints`),
      }
    }
    case 'github':
      return {
        ...base,
        name,
        clientSecret: secrets[0] ?? '',
        endpoints: endpoints(raw['endpoints'], name, undefined, `${at}.endpoints`),
      }
    case 'apple':
      // Apple posts the callback cross-site, which only works with a `SameSite=None; Secure`
      // flow cookie, and Apple itself refuses non-https return URLs.
      if (!secure) throw new SocialLoginConfigError(at, 'Sign in with Apple needs an https APP_URL')
      return {
        ...base,
        name,
        teamId: secrets[0] ?? '',
        keyId: secrets[1] ?? '',
        privateKey: applePrivateKey(secrets[2] ?? '', `${at}.privateKey`),
        endpoints: endpoints(raw['endpoints'], name, undefined, `${at}.endpoints`),
      }
  }
}

/**
 * Check and resolve the config. `appUrl` is the app's public URL (`APP_URL`).
 *
 * @example
 * const config = resolveConfig({ providers: { google: { clientId, clientSecret } } }, 'https://app.example.com')
 */
export function resolveConfig(raw: unknown, appUrl: string): ResolvedConfig {
  const cfg = raw ?? {}
  if (!isObject(cfg)) throw new SocialLoginConfigError('(root)', 'must be an object')
  let app: URL
  try {
    app = new URL(appUrl)
  } catch {
    throw new SocialLoginConfigError('APP_URL', 'must be an absolute http(s) URL')
  }
  if (app.protocol !== 'https:' && app.protocol !== 'http:')
    throw new SocialLoginConfigError('APP_URL', 'must be an absolute http(s) URL')
  const secure = app.protocol === 'https:'
  if (!secure && !LOOPBACK.has(app.hostname))
    throw new SocialLoginConfigError(
      'APP_URL',
      'must use https: providers send authorization codes to it (plain http is allowed only for localhost)',
    )

  const path = optionalString(cfg['path'], 'path') ?? '/auth'
  if (!PATH.test(path))
    throw new SocialLoginConfigError('path', 'must look like /auth (letters, digits, -, _ and /)')

  const reauth = cfg['reauthMinutes'] ?? 10
  if (typeof reauth !== 'number' || !Number.isInteger(reauth) || reauth < 1 || reauth > 60)
    throw new SocialLoginConfigError('reauthMinutes', 'must be a whole number from 1 to 60')

  const redirects = cfg['redirects'] ?? {}
  if (!isObject(redirects)) throw new SocialLoginConfigError('redirects', 'must be an object')
  const local = (value: unknown, fallback: string, setting: string): string => {
    const given = optionalString(value, setting) ?? fallback
    const safe = safeRedirectTarget(given, app.origin)
    if (safe === undefined)
      throw new SocialLoginConfigError(setting, 'must be a path on this app, like /dashboard')
    return safe
  }

  const providersRaw = cfg['providers'] ?? {}
  if (!isObject(providersRaw)) throw new SocialLoginConfigError('providers', 'must be an object')
  for (const key of Object.keys(providersRaw))
    if (!PROVIDER_NAMES.includes(key as ProviderName))
      throw new SocialLoginConfigError(
        `providers.${key}`,
        `is not a provider this package knows (${PROVIDER_NAMES.join(', ')})`,
      )

  const redirectBase = `${app.origin}${path}`
  const skipped: ProviderName[] = []
  const providers = new Map<ProviderName, ResolvedProvider>()
  for (const name of PROVIDER_NAMES) {
    const resolved = resolveProvider(name, providersRaw[name], redirectBase, secure, skipped)
    if (resolved !== undefined) providers.set(name, resolved)
  }

  return {
    enabled: bool(cfg['enabled'], true, 'enabled'),
    path,
    registration: bool(cfg['registration'], false, 'registration'),
    reauthMs: reauth * 60_000,
    home: local(redirects['home'], '/', 'redirects.home'),
    failure: local(redirects['failure'], '/login', 'redirects.failure'),
    appOrigin: app.origin,
    secure,
    providers,
    skipped,
  }
}
