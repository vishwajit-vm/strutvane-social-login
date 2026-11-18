/**
 * The OAuth 2.x pieces every driver shares: building the authorization URL and redeeming the code
 * at the token endpoint (RFC 6749 §4.1, with PKCE per RFC 7636 and OAuth 2.1).
 *
 * @module
 */
import { SocialLoginError } from '../errors.ts'
import { asObject } from '../http/client.ts'
import type { DriverContext } from './types.ts'

/**
 * Build an authorization URL. Existing query parameters of `base` are kept; ours override them,
 * so a crafted endpoint override can't smuggle in a second `redirect_uri` or `state`.
 *
 * @example
 * authorizationUrl('https://accounts.google.com/o/oauth2/v2/auth', { client_id: 'x', state: 's' })
 */
export function authorizationUrl(base: string, params: Readonly<Record<string, string>>): string {
  const url = new URL(base)
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value)
  return url.href
}

/** What {@link exchangeCode} sends. */
export interface CodeExchange {
  readonly provider: string
  readonly tokenUrl: string
  readonly clientId: string
  /** The client secret (Apple: the freshly signed client-secret JWT). */
  readonly clientSecret: string
  readonly code: string
  /** The PKCE verifier; omitted only for a provider that binds the code with the nonce (Apple). */
  readonly codeVerifier?: string
  readonly redirectUri: string
}

/** An OAuth error code is echoed into logs only when it looks like one (`invalid_grant`). */
const ERROR_CODE = /^[a-z_]{1,64}$/

/**
 * Redeem an authorization code. Returns the token response; throws `social_token_invalid` when the
 * provider refuses the code (expired, replayed, wrong PKCE verifier) and
 * `social_provider_unavailable` when it can't be reached.
 *
 * @example
 * const tokens = await exchangeCode(ctx, { provider: 'google', tokenUrl, clientId, clientSecret, code, codeVerifier, redirectUri })
 */
export async function exchangeCode(
  ctx: DriverContext,
  exchange: CodeExchange,
): Promise<Readonly<Record<string, unknown>>> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: exchange.code,
    redirect_uri: exchange.redirectUri,
    client_id: exchange.clientId,
    client_secret: exchange.clientSecret,
  })
  if (exchange.codeVerifier !== undefined) body.set('code_verifier', exchange.codeVerifier)
  const response = await ctx.http.json(
    exchange.tokenUrl,
    {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
    },
    `${exchange.provider} token`,
  )
  const json = asObject(response.body)
  // GitHub answers refused codes with 200 and an `error` member, so check the body too.
  const error = json?.['error']
  if (response.status !== 200 || json === undefined || error !== undefined) {
    const code = typeof error === 'string' && ERROR_CODE.test(error) ? error : 'unknown'
    throw new SocialLoginError(
      'social_token_invalid',
      `${exchange.provider} token endpoint refused the code (status ${response.status}, ${code})`,
    )
  }
  if (typeof json['access_token'] !== 'string' || json['access_token'] === '')
    throw new SocialLoginError(
      'social_token_invalid',
      `${exchange.provider} token response has no access_token`,
    )
  return json
}
