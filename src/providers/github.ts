/**
 * GitHub (OAuth 2.0 with PKCE; GitHub has no ID token, so there is no nonce or issuer to check).
 *
 * - Identity: the numeric user `id`, as a string. Never the `login`, which users can change and
 *   someone else can then claim.
 * - Email: only from `GET /user/emails`, and only the address marked `primary` **and** `verified`.
 *   The `email` field of `GET /user` is the public profile email, which GitHub does not require
 *   to be verified, so it is never used. No primary verified email: the profile has the primary
 *   email (if any) marked unverified, which can never create or match an account.
 * - API calls send the version header GitHub asks for and a `User-Agent` (required by its API).
 * - Mix-up defence without an issuer: the callback path names the provider, the flow cookie is
 *   per provider, and `state` binds the response to this browser's GitHub request.
 *
 * @module
 */
import type { ResolvedProvider } from '../config.ts'
import { SocialLoginError } from '../errors.ts'
import { asObject } from '../http/client.ts'
import { authorizationUrl, exchangeCode } from './oauth.ts'
import { displayName, normalizeEmail } from './profile.ts'
import type { DriverContext, ProviderDriver } from './types.ts'

type GitHubSettings = Extract<ResolvedProvider, { name: 'github' }>

/** The GitHub REST API version this driver was written against. */
const API_VERSION = '2022-11-28'

/**
 * Pick the primary, verified email from a `GET /user/emails` answer.
 *
 * @example
 * primaryEmail([{ email: 'a@b.c', primary: true, verified: true }]) // { email: 'a@b.c', verified: true }
 */
export function primaryEmail(list: unknown): { email: string | null; verified: boolean } {
  if (!Array.isArray(list)) return { email: null, verified: false }
  const primary = list.map(asObject).find((e) => e?.['primary'] === true)
  const email = normalizeEmail(primary?.['email'])
  return { email, verified: email !== null && primary?.['verified'] === true }
}

/**
 * Create the GitHub driver.
 *
 * @example
 * const github = githubDriver(settings, { http, now: Date.now })
 */
export function githubDriver(settings: GitHubSettings, ctx: DriverContext): ProviderDriver {
  const { endpoints } = settings
  const api = endpoints.api.replace(/\/+$/, '')

  async function get(path: string, accessToken: string, what: string): Promise<unknown> {
    const response = await ctx.http.json(
      `${api}${path}`,
      {
        method: 'GET',
        headers: {
          accept: 'application/vnd.github+json',
          authorization: `Bearer ${accessToken}`,
          'user-agent': 'strutvane-social-login',
          'x-github-api-version': API_VERSION,
        },
      },
      what,
    )
    if (response.status !== 200)
      throw new SocialLoginError(
        'social_token_invalid',
        `${what}: GitHub answered ${response.status}`,
      )
    return response.body
  }

  return {
    name: 'github',
    responseMode: 'query',
    matchesIssuer: (iss) => endpoints.issuer === '' || iss === endpoints.issuer,
    authorizationUrl: (p) =>
      authorizationUrl(endpoints.authorization, {
        response_type: 'code',
        client_id: settings.clientId,
        redirect_uri: p.redirectUri,
        scope: settings.scopes.join(' '),
        state: p.state,
        code_challenge: p.codeChallenge,
        code_challenge_method: 'S256',
        allow_signup: 'true',
      }),
    async complete(input) {
      const tokens = await exchangeCode(ctx, {
        provider: 'github',
        tokenUrl: endpoints.token,
        clientId: settings.clientId,
        clientSecret: settings.clientSecret,
        code: input.code,
        codeVerifier: input.codeVerifier,
        redirectUri: input.redirectUri,
      })
      const accessToken = String(tokens['access_token'])
      const user = asObject(await get('/user', accessToken, 'github user'))
      const id = user?.['id']
      if (typeof id !== 'number' || !Number.isSafeInteger(id) || id <= 0)
        throw new SocialLoginError('social_token_invalid', 'github user: id missing')
      const { email, verified } = primaryEmail(
        await get('/user/emails', accessToken, 'github emails'),
      )
      return {
        provider: 'github',
        subject: String(id),
        email,
        emailVerified: verified,
        name: displayName(user?.['name']) ?? displayName(user?.['login']),
      }
    },
  }
}
