/**
 * Google (OpenID Connect).
 *
 * - Identity: the ID token's `sub`.
 * - Email: verified only when the ID token says `email_verified: true` (Google's own rule).
 * - `allowedDomains`: only Google Workspace accounts whose `hd` (hosted domain) claim is listed.
 *   The email's domain is *not* used for this: a consumer Google account can carry any email.
 * - Issuer: `https://accounts.google.com`, and the legacy `accounts.google.com` Google still
 *   documents for older tokens.
 *
 * @module
 */
import type { ResolvedProvider } from '../config.ts'
import { SocialLoginError } from '../errors.ts'
import { verifyIdToken } from '../oidc/id-token.ts'
import { createJwksCache } from '../oidc/jwks.ts'
import { authorizationUrl, exchangeCode } from './oauth.ts'
import { displayName, normalizeEmail } from './profile.ts'
import type { DriverContext, ProviderDriver } from './types.ts'

type GoogleSettings = Extract<ResolvedProvider, { name: 'google' }>

/**
 * Create the Google driver.
 *
 * @example
 * const google = googleDriver(config.providers.get('google'), { http, now: Date.now })
 */
export function googleDriver(settings: GoogleSettings, ctx: DriverContext): ProviderDriver {
  const { endpoints } = settings
  const jwks = createJwksCache({
    url: endpoints.jwks,
    http: ctx.http,
    now: ctx.now,
    name: 'google',
  })
  const issuers =
    endpoints.issuer === 'https://accounts.google.com'
      ? new Set([endpoints.issuer, 'accounts.google.com'])
      : new Set([endpoints.issuer])
  return {
    name: 'google',
    responseMode: 'query',
    matchesIssuer: (iss) => issuers.has(iss),
    authorizationUrl: (p) =>
      authorizationUrl(endpoints.authorization, {
        response_type: 'code',
        client_id: settings.clientId,
        redirect_uri: p.redirectUri,
        scope: settings.scopes.join(' '),
        state: p.state,
        nonce: p.nonce,
        code_challenge: p.codeChallenge,
        code_challenge_method: 'S256',
        ...(settings.allowedDomains.length === 1 ? { hd: settings.allowedDomains[0] ?? '' } : {}),
      }),
    async complete(input) {
      const tokens = await exchangeCode(ctx, {
        provider: 'google',
        tokenUrl: endpoints.token,
        clientId: settings.clientId,
        clientSecret: settings.clientSecret,
        code: input.code,
        codeVerifier: input.codeVerifier,
        redirectUri: input.redirectUri,
      })
      const claims = await verifyIdToken(tokens['id_token'], jwks, {
        issuer: (iss) => issuers.has(iss),
        clientId: settings.clientId,
        nonce: input.nonce,
        now: ctx.now(),
        algorithms: ['RS256'],
      })
      if (settings.allowedDomains.length > 0) {
        const hd = claims['hd']
        if (typeof hd !== 'string' || !settings.allowedDomains.includes(hd.toLowerCase()))
          throw new SocialLoginError('social_domain_not_allowed', 'google: hd is not allowed')
      }
      const email = normalizeEmail(claims['email'])
      return {
        provider: 'google',
        subject: claims.sub,
        email,
        emailVerified: email !== null && claims['email_verified'] === true,
        name: displayName(claims['name']),
      }
    },
  }
}
