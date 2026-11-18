/**
 * The social sign-in routes, as a framework-agnostic Web handler (`Request` → `Response`). The
 * provider (`provider.ts`) serves it through the framework's `http.onRequest` hook; tests and
 * other hosts can call it directly.
 *
 * Routes (`{path}` defaults to `/auth`):
 * - `GET {path}/{provider}/redirect?return_to=/somewhere&intent=login|link`: starts a flow (new
 *   `state`, `nonce` and PKCE pair in a sealed, per-provider cookie) and redirects to the provider.
 *   `intent=link` connects the provider to the signed-in user and needs a recent sign-in.
 * - `GET {path}/{provider}/callback`: the provider's redirect back. Checks, in order: no
 *   provider error, no repeated parameters, the flow cookie opens, `state` matches it, an RFC 9207
 *   `iss` (when sent) is this provider's, the `state` was never used before; then redeems the code
 *   (with the PKCE verifier), validates the ID token (with the nonce) and applies the account rules
 *   (`accounts/resolve.ts`).
 * - `POST {path}/apple/callback`: Apple's form post. Verified the same way, then handed to a
 *   same-site `GET {path}/apple/callback` through a 2-minute sealed cookie, because the session
 *   cookie (`SameSite=Lax`) is not sent on a cross-site `POST`.
 *
 * Every outcome is a `303` redirect: to the flow's return path on success, or to the failure page
 * with `?error=<code>` (a code from `errors.ts`, nothing else from the request). Responses are
 * `Cache-Control: no-store` and `Referrer-Policy: no-referrer` (the callback URL holds a code), and
 * the flow cookie is cleared by every callback, successful or not.
 *
 * What is logged: the provider, the outcome code and a reason naming the failed check, plus the
 * user id on success. Never codes, tokens, `state`, nonces, cookies or emails.
 *
 * @module
 */
import { safeRedirectTarget } from '@strutvane/framework'
import type { Logger } from '@strutvane/framework/contracts'
import { resolveAccount } from './accounts/resolve.ts'
import type { SocialAccounts } from './accounts.ts'
import type { ResolvedConfig } from './config.ts'
import { randomToken, safeEqual } from './crypto/encoding.ts'
import { createPkce } from './crypto/pkce.ts'
import type { Sealer } from './crypto/sealer.ts'
import { SocialLoginError } from './errors.ts'
import type { ReplayGuard } from './flow/replay.ts'
import {
  cookieName,
  FLOW_TTL_MS,
  type FlowState,
  HAND_OFF_TTL_MS,
  type Intent,
  openFlow,
  openHandOff,
  sealFlow,
  sealHandOff,
} from './flow/state.ts'
import { readCookie, serializeCookie } from './http/cookies.ts'
import {
  PROVIDER_NAMES,
  type ProviderDriver,
  type ProviderName,
  type SocialProfile,
} from './providers/types.ts'

/** The logger methods the handler uses (the framework `Logger` fits). */
export type SocialLogger = Pick<Logger, 'info' | 'warn' | 'error'>

/** Options for {@link createSocialLoginHandler}. */
export interface SocialLoginHandlerOptions {
  readonly config: ResolvedConfig
  readonly drivers: ReadonlyMap<ProviderName, ProviderDriver>
  readonly sealer: Sealer
  readonly replay: ReplayGuard
  /** The account contract, resolved per request (`undefined` when nothing is bound: fail closed). */
  readonly accounts: () => SocialAccounts | undefined
  readonly logger: SocialLogger
  /** Milliseconds since the epoch. Default `Date.now`. */
  readonly now?: () => number
}

/** The handler. */
export interface SocialLoginHandler {
  /** Is this request for one of the social sign-in routes? */
  matches(request: Request): boolean
  /** Answer it. Never throws. */
  fetch(request: Request): Promise<Response>
}

/** Largest form post accepted from Apple. */
const MAX_FORM_BYTES = 64 * 1024
/** Longest authorization code or `state` accepted. */
const MAX_PARAM = 2048
/** A `state` stays claimed a little longer than a flow lives. */
const REPLAY_TTL_SECONDS = Math.ceil(FLOW_TTL_MS / 1000) + 300

const ROUTE = /^\/([a-z]+)\/(redirect|callback)$/

/** Read a capped `application/x-www-form-urlencoded` body; `undefined` if not one or too big. */
async function readForm(request: Request): Promise<URLSearchParams | undefined> {
  const type = request.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase()
  if (type !== 'application/x-www-form-urlencoded') return undefined
  const reader = request.body?.getReader()
  if (reader === undefined) return new URLSearchParams()
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > MAX_FORM_BYTES) {
      await reader.cancel().catch(() => undefined)
      return undefined
    }
    chunks.push(value)
  }
  return new URLSearchParams(Buffer.concat(chunks).toString('utf8'))
}

/** A single-valued parameter; `null` when absent; `undefined` when repeated or too long. */
function single(params: URLSearchParams, name: string): string | null | undefined {
  const all = params.getAll(name)
  if (all.length === 0) return null
  if (all.length > 1) return undefined
  const value = all[0] ?? ''
  return value.length > MAX_PARAM ? undefined : value
}

/**
 * Create the handler.
 *
 * @example
 * const handler = createSocialLoginHandler({ config, drivers, sealer, replay, accounts: () => accounts, logger })
 * if (handler.matches(request)) return handler.fetch(request)
 */
export function createSocialLoginHandler(options: SocialLoginHandlerOptions): SocialLoginHandler {
  const { config, drivers, sealer, replay, logger } = options
  const now = options.now ?? Date.now
  const secure = config.secure

  const baseHeaders = (): Headers =>
    new Headers({ 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' })

  const redirect = (location: string, headers: Headers = baseHeaders(), status = 303): Response => {
    headers.set('location', location)
    return new Response(null, { status, headers })
  }

  const clear = (headers: Headers, kind: 'flow' | 'handoff', provider: ProviderName): void => {
    headers.append(
      'set-cookie',
      serializeCookie(cookieName(kind, provider, secure), '', {
        maxAge: 0,
        secure,
        sameSite: 'Lax',
      }),
    )
  }

  /** The failure redirect: the code only, nothing from the request. */
  const failure = (
    provider: ProviderName,
    error: unknown,
    headers: Headers = baseHeaders(),
  ): Response => {
    const known = error instanceof SocialLoginError
    const code = known ? error.code : 'internal_error'
    if (known) logger.warn('social login failed', { provider, code, reason: error.reason })
    else
      logger.error('social login failed unexpectedly', {
        provider,
        code,
        error: error instanceof Error ? error.name : typeof error,
      })
    const url = new URL(config.failure, config.appOrigin)
    url.searchParams.set('error', code)
    url.searchParams.set('provider', provider)
    return redirect(`${url.pathname}${url.search}`, headers)
  }

  const accountsOrFail = (): SocialAccounts => {
    const accounts = options.accounts()
    if (accounts === undefined)
      throw new SocialLoginError(
        'social_accounts_unavailable',
        'nothing is bound to SocialAccountsToken',
      )
    return accounts
  }

  /** `GET {path}/{provider}/redirect`. */
  async function start(request: Request, driver: ProviderDriver): Promise<Response> {
    const url = new URL(request.url)
    const returnTo =
      safeRedirectTarget(url.searchParams.get('return_to') ?? '', config.appOrigin) ?? config.home
    const intent: Intent = url.searchParams.get('intent') === 'link' ? 'link' : 'login'
    let userId: string | null = null
    if (intent === 'link') {
      // Checked again at the callback; here it saves a pointless trip to the provider.
      const current = await accountsOrFail().currentUser(request)
      if (current === null || now() - current.authenticatedAt > config.reauthMs)
        throw new SocialLoginError('social_reauth_required', 'link: no recent sign-in at start')
      userId = current.id
    }
    const pkce = createPkce()
    const flow: FlowState = {
      provider: driver.name,
      state: randomToken(),
      nonce: randomToken(),
      verifier: pkce.verifier,
      returnTo,
      intent,
      userId,
      issuedAt: now(),
    }
    const headers = baseHeaders()
    headers.append(
      'set-cookie',
      serializeCookie(cookieName('flow', driver.name, secure), sealFlow(sealer, flow), {
        maxAge: Math.floor(FLOW_TTL_MS / 1000),
        secure,
        // Apple returns with a cross-site POST, which only carries a SameSite=None cookie.
        sameSite: driver.responseMode === 'form_post' ? 'None' : 'Lax',
      }),
    )
    const location = driver.authorizationUrl({
      state: flow.state,
      nonce: flow.nonce,
      codeChallenge: pkce.challenge,
      redirectUri: `${config.appOrigin}${config.path}/${driver.name}/callback`,
    })
    return redirect(location, headers, 302)
  }

  /** The checks shared by both callback kinds; returns the verified profile and the flow. */
  async function verifyCallback(
    request: Request,
    driver: ProviderDriver,
    params: URLSearchParams,
  ): Promise<{
    readonly profile: SocialProfile
    readonly flow: FlowState
    readonly appleUser?: string
  }> {
    const error = single(params, 'error')
    if (error !== null)
      throw new SocialLoginError(
        'social_provider_error',
        `provider returned an error (${error !== undefined && /^[a-z_]{1,64}$/.test(error) ? error : 'unknown'})`,
      )
    const state = single(params, 'state')
    const code = single(params, 'code')
    const iss = single(params, 'iss')
    if (state === undefined || code === undefined || iss === undefined)
      throw new SocialLoginError('social_state_invalid', 'repeated or oversized callback parameter')
    const flow = openFlow(
      sealer,
      driver.name,
      readCookie(request.headers.get('cookie'), cookieName('flow', driver.name, secure)),
      now(),
    )
    if (flow === undefined)
      throw new SocialLoginError('social_state_invalid', 'no valid flow cookie for this provider')
    if (state === null || !safeEqual(state, flow.state))
      throw new SocialLoginError('social_state_invalid', 'state does not match the flow cookie')
    if (iss !== null && !driver.matchesIssuer(iss))
      throw new SocialLoginError('social_issuer_mismatch', 'iss parameter is not this provider')
    if (code === null || code === '')
      throw new SocialLoginError('social_provider_error', 'callback has no code')
    if (!(await replay.claim(flow.state, REPLAY_TTL_SECONDS)))
      throw new SocialLoginError('social_state_invalid', 'state was already used')
    const appleUser = driver.responseMode === 'form_post' ? single(params, 'user') : null
    const profile = await driver.complete({
      code,
      codeVerifier: flow.verifier,
      nonce: flow.nonce,
      redirectUri: `${config.appOrigin}${config.path}/${driver.name}/callback`,
      ...(typeof appleUser === 'string' ? { appleUser } : {}),
    })
    return { profile, flow }
  }

  /** Apply the account rules and build the success redirect. */
  async function finish(
    request: Request,
    profile: SocialProfile,
    intent: Intent,
    flowUserId: string | null,
    returnTo: string,
    headers: Headers,
  ): Promise<Response> {
    const outcome = await resolveAccount({
      profile,
      intent,
      flowUserId,
      request,
      accounts: accountsOrFail(),
      registration: config.registration,
      reauthMs: config.reauthMs,
      now: now(),
    })
    if (outcome.kind === 'linked') {
      logger.info('social account linked', {
        provider: profile.provider,
        userId: outcome.userId,
        alreadyLinked: outcome.alreadyLinked,
      })
      return redirect(returnTo, headers)
    }
    logger.info('social sign-in', {
      provider: profile.provider,
      userId: outcome.userId,
      created: outcome.created,
    })
    outcome.session.headers?.forEach((value, name) => {
      if (name.toLowerCase() !== 'set-cookie') headers.set(name, value)
    })
    for (const cookie of outcome.session.headers?.getSetCookie() ?? [])
      headers.append('set-cookie', cookie)
    const next =
      outcome.session.redirectTo === undefined
        ? returnTo
        : (safeRedirectTarget(outcome.session.redirectTo, config.appOrigin) ?? returnTo)
    return redirect(next, headers)
  }

  /** `GET {path}/{provider}/callback` (and Apple's finishing `GET`). */
  async function callback(request: Request, driver: ProviderDriver): Promise<Response> {
    const headers = baseHeaders()
    clear(headers, 'flow', driver.name)
    try {
      const params = new URL(request.url).searchParams
      if (driver.responseMode === 'form_post') {
        clear(headers, 'handoff', driver.name)
        const handOff = openHandOff(
          sealer,
          driver.name,
          readCookie(request.headers.get('cookie'), cookieName('handoff', driver.name, secure)),
          now(),
        )
        if (handOff === undefined || [...params.keys()].length > 0)
          throw new SocialLoginError('social_state_invalid', 'no valid hand-over for this provider')
        if (!(await replay.claim(`handoff:${handOff.id}`, REPLAY_TTL_SECONDS)))
          throw new SocialLoginError('social_state_invalid', 'hand-over was already used')
        return await finish(
          request,
          handOff.profile,
          handOff.intent,
          handOff.userId,
          handOff.returnTo,
          headers,
        )
      }
      const { profile, flow } = await verifyCallback(request, driver, params)
      return await finish(request, profile, flow.intent, flow.userId, flow.returnTo, headers)
    } catch (error) {
      return failure(driver.name, error, headers)
    }
  }

  /** `POST {path}/apple/callback`: verify, then hand over to the same-site `GET`. */
  async function formPost(request: Request, driver: ProviderDriver): Promise<Response> {
    const headers = baseHeaders()
    clear(headers, 'flow', driver.name)
    try {
      const form = await readForm(request)
      if (form === undefined)
        throw new SocialLoginError(
          'social_provider_error',
          'form post is not a small urlencoded form',
        )
      const { profile, flow } = await verifyCallback(request, driver, form)
      const handOff = sealHandOff(sealer, driver.name, {
        id: randomToken(),
        profile,
        returnTo: flow.returnTo,
        intent: flow.intent,
        userId: flow.userId,
        issuedAt: now(),
      })
      headers.append(
        'set-cookie',
        serializeCookie(cookieName('handoff', driver.name, secure), handOff, {
          maxAge: Math.floor(HAND_OFF_TTL_MS / 1000),
          secure,
          sameSite: 'Lax',
        }),
      )
      return redirect(`${config.path}/${driver.name}/callback`, headers)
    } catch (error) {
      return failure(driver.name, error, headers)
    }
  }

  const route = (request: Request): { provider: ProviderName; action: string } | undefined => {
    const { pathname } = new URL(request.url)
    if (!pathname.startsWith(`${config.path}/`)) return undefined
    const match = ROUTE.exec(pathname.slice(config.path.length))
    const provider = match?.[1]
    const action = match?.[2]
    if (provider === undefined || action === undefined) return undefined
    if (!PROVIDER_NAMES.includes(provider as ProviderName)) return undefined
    return { provider: provider as ProviderName, action }
  }

  return {
    matches: (request) => config.enabled && route(request) !== undefined,
    async fetch(request) {
      const target = route(request)
      if (target === undefined || !config.enabled)
        return new Response(null, { status: 404, headers: baseHeaders() })
      const driver = drivers.get(target.provider)
      const method = request.method.toUpperCase()
      if (driver === undefined) {
        const headers = baseHeaders()
        headers.set('content-type', 'application/problem+json')
        return new Response(
          JSON.stringify({
            type: 'about:blank',
            status: 404,
            title: 'This sign-in provider is not available',
            code: 'social_provider_unknown',
          }),
          { status: 404, headers },
        )
      }
      const allowed =
        target.action === 'redirect'
          ? ['GET', 'HEAD']
          : driver.responseMode === 'form_post'
            ? ['GET', 'POST']
            : ['GET']
      if (!allowed.includes(method)) {
        const headers = baseHeaders()
        headers.set('allow', allowed.join(', '))
        return new Response(null, { status: 405, headers })
      }
      if (target.action === 'callback')
        return method === 'POST' ? formPost(request, driver) : callback(request, driver)
      try {
        return await start(request, driver)
      } catch (error) {
        return failure(driver.name, error)
      }
    },
  }
}
