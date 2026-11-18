/**
 * `@strutvane/social-login/provider`: the provider an app lists in `bootstrap/providers.ts` (the
 * installer adds it). It serves the social sign-in routes through the framework's public seams
 * only (integration map: container tokens and hooks), never through another package:
 *
 * - **`http.onRequest`** (handler `socialLogin.routes`, after `auth.identity`): requests for
 *   `{path}/{provider}/redirect` and `{path}/{provider}/callback` are answered here; every other
 *   request passes through untouched.
 * - **`SocialAccountsToken`**: the account contract (`accounts.ts`), bound by the app (or, later,
 *   by the identity package). Unbound: every callback fails closed with
 *   `social_accounts_unavailable`, and the boot logs a warning.
 * - **`EncrypterToken`** seals the flow cookie with the app's keys (rotation included); without
 *   it, a key derived from `APP_KEY`. Neither: the boot fails.
 * - **`CacheManagerToken`**: the default cache store makes `state` single-use across processes;
 *   without it, an in-process guard (one process only; a warning outside `local`).
 * - **`LoggerToken`**: logs go through the framework logger (redacting), child `social-login`.
 * - **`ErrorRegistryToken`**: registers this package's error codes.
 *
 * Settings come from `config/social-login.ts` (key `socialLogin`; the installer writes both),
 * checked at boot (`config.ts`): a wrong setting stops the boot with a message naming it.
 *
 * @module
 */
import { CacheManagerToken, EncrypterToken } from '@strutvane/framework'
import { HTTP_HOOKS, type HttpRequestHookPayload } from '@strutvane/framework/contracts'
import {
  type Application,
  defineProvider,
  ErrorRegistryToken,
  HooksToken,
  LoggerToken,
  type Provider,
} from '@strutvane/framework/core'
import { SocialAccountsToken } from './accounts.ts'
import { resolveConfig, SocialLoginConfigError } from './config.ts'
import { encrypterSealer, keySealer, parseAppKey, type Sealer } from './crypto/sealer.ts'
import { SOCIAL_LOGIN_ERRORS } from './errors.ts'
import { cacheReplayGuard, memoryReplayGuard, type ReplayGuard } from './flow/replay.ts'
import { createSocialLoginHandler } from './handler.ts'
import { createHttpClient, type FetchLike } from './http/client.ts'
import { createDrivers } from './providers/registry.ts'

/** The config key the installer registers `config/social-login.ts` under. */
export const CONFIG_KEY = 'socialLogin'

/** Name of the `http.onRequest` handler, for other packages' ordering hints. */
export const HOOK_NAME = 'socialLogin.routes'

/** Options for {@link createSocialLoginProvider} (mostly for tests). */
export interface SocialLoginProviderOptions {
  /** Outbound `fetch` (the fake provider in tests). Default: the global `fetch`. */
  readonly fetch?: FetchLike
  /** Environment for `APP_URL`, `APP_KEY` and `APP_ENV` fallbacks. Default: `process.env`. */
  readonly env?: Readonly<Record<string, string | undefined>>
  /** Milliseconds since the epoch. Default `Date.now`. */
  readonly now?: () => number
}

const section = (app: Pick<Application, 'settings'>, name: string): unknown =>
  Reflect.get(app.settings, name)

const field = (value: unknown, name: string): string | undefined => {
  if (typeof value !== 'object' || value === null) return undefined
  const v: unknown = Reflect.get(value, name)
  return typeof v === 'string' && v !== '' ? v : undefined
}

/**
 * Create the social login provider (a factory, so every app and test gets fresh state).
 *
 * @example
 * // bootstrap/providers.ts
 * import { createSocialLoginProvider } from '@strutvane/social-login/provider'
 * export default [AppServiceProvider, createSocialLoginProvider()]
 */
export function createSocialLoginProvider(options: SocialLoginProviderOptions = {}): Provider {
  return defineProvider({
    name: '@strutvane/social-login',
    register() {
      // Nothing to bind: SocialAccountsToken is the app's (or the identity package's) to bind.
    },
    boot(app) {
      const registry = app.make(ErrorRegistryToken)
      for (const definition of SOCIAL_LOGIN_ERRORS)
        if (registry.get(definition.code) === undefined) registry.register(definition)

      const env = options.env ?? process.env
      const appSettings = section(app, 'app')
      const appUrl = field(appSettings, 'url') ?? env['APP_URL'] ?? 'http://localhost:3000'
      const appEnv = field(appSettings, 'env') ?? env['APP_ENV'] ?? 'production'
      const config = resolveConfig(section(app, CONFIG_KEY), appUrl)
      const logger = app.make(LoggerToken).child({ module: 'social-login' })
      if (!config.enabled) return

      for (const name of config.skipped)
        logger.warn('social login provider skipped: its credentials are empty', { provider: name })
      if (!app.container.has(SocialAccountsToken))
        logger.warn(
          'social login: nothing is bound to SocialAccountsToken, so every sign-in will fail (see the README)',
        )

      let sealer: Sealer
      if (app.container.has(EncrypterToken)) sealer = encrypterSealer(app.make(EncrypterToken))
      else {
        const key = parseAppKey(field(appSettings, 'key') ?? env['APP_KEY'])
        if (key === undefined)
          throw new SocialLoginConfigError(
            'APP_KEY',
            'is missing or not base64: + 32 bytes; run `node strut key:generate`',
          )
        sealer = keySealer(key)
      }

      let replay: ReplayGuard
      if (app.container.has(CacheManagerToken))
        replay = cacheReplayGuard(app.make(CacheManagerToken).store())
      else {
        replay = memoryReplayGuard(options.now === undefined ? {} : { now: options.now })
        if (appEnv !== 'local' && appEnv !== 'testing')
          logger.warn(
            'social login: no cache is bound, so single-use state is tracked per process only',
          )
      }

      const now = options.now ?? Date.now
      const http = createHttpClient({ fetch: options.fetch ?? ((url, init) => fetch(url, init)) })
      const handler = createSocialLoginHandler({
        config,
        drivers: createDrivers(config.providers, { http, now }),
        sealer,
        replay,
        accounts: () =>
          app.container.has(SocialAccountsToken) ? app.make(SocialAccountsToken) : undefined,
        logger,
        now,
      })

      app.make(HooksToken).on(
        HTTP_HOOKS.request,
        async (payload, control) => {
          const p = payload as HttpRequestHookPayload
          if (!handler.matches(p.request)) return undefined
          control.stop()
          const answered: HttpRequestHookPayload = {
            ...p,
            response: await handler.fetch(p.request),
          }
          return answered
        },
        { name: HOOK_NAME, after: ['auth.identity'] },
      )
    },
  })
}

/** The provider for `bootstrap/providers.ts`. */
const provider: Provider = createSocialLoginProvider()
export default provider
