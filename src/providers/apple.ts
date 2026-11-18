/**
 * Sign in with Apple (OpenID Connect).
 *
 * Apple's differences from the others, and how they are handled:
 * - **Form post.** Asking for `name` or `email` makes Apple return with a cross-site `POST`
 *   (`response_mode=form_post`). The handler accepts that POST only on this provider's callback,
 *   reads at most 64 KiB of `application/x-www-form-urlencoded`, and finishes the sign-in on a
 *   follow-up same-site `GET` (see `handler.ts`), where the session cookie is visible.
 * - **Client secret is a JWT** you sign with your Sign in with Apple key (`ES256`, `kid` = key id,
 *   `iss` = team id, `sub` = the Services ID, `aud` = `https://appleid.apple.com`). It is signed
 *   fresh for every code exchange and lives 5 minutes, so a leaked one is useless quickly.
 * - **The ID token comes from the token endpoint**, never from the form post: the posted copy
 *   travelled through the browser and is ignored.
 * - **No PKCE.** Apple's token endpoint documents no `code_verifier` *(unverified whether it
 *   accepts one)*, so the code is bound to this browser's sign-in by the ID token's `nonce`
 *   instead, which OAuth 2.1 §7.5.1 accepts for OpenID Connect clients.
 * - **Email:** Apple verifies the addresses it releases (`email_verified`, sent as a boolean or the
 *   string `"true"`); private relay addresses count as verified too.
 * - **Name:** sent only on the first authorization, in the unsigned `user` form field, so it is
 *   used as a display name and never to identify anyone.
 *
 * @module
 */
import type { ResolvedProvider } from '../config.ts'
import { signJwt } from '../crypto/jwt.ts'
import { verifyIdToken } from '../oidc/id-token.ts'
import { createJwksCache } from '../oidc/jwks.ts'
import { authorizationUrl, exchangeCode } from './oauth.ts'
import { booleanClaim, displayName, normalizeEmail } from './profile.ts'
import type { DriverContext, ProviderDriver } from './types.ts'

type AppleSettings = Extract<ResolvedProvider, { name: 'apple' }>

/** How long a client-secret JWT lives. Apple allows up to six months; minutes are enough. */
const CLIENT_SECRET_SECONDS = 300
const MAX_USER_FIELD = 4096

/**
 * Sign Apple's client-secret JWT.
 *
 * @example
 * appleClientSecret(settings, Date.now())
 */
export function appleClientSecret(settings: AppleSettings, nowMs: number): string {
  const iat = Math.floor(nowMs / 1000)
  return signJwt(
    'ES256',
    settings.privateKey,
    { kid: settings.keyId },
    {
      iss: settings.teamId,
      iat,
      exp: iat + CLIENT_SECRET_SECONDS,
      aud: settings.endpoints.issuer,
      sub: settings.clientId,
    },
  )
}

/**
 * The display name from Apple's `user` form field (`{"name":{"firstName","lastName"}}`), or `null`.
 *
 * @example
 * appleUserName('{"name":{"firstName":"Ada","lastName":"Lovelace"}}') // 'Ada Lovelace'
 */
export function appleUserName(field: string | undefined): string | null {
  if (field === undefined || field.length > MAX_USER_FIELD) return null
  try {
    const value: unknown = JSON.parse(field)
    if (typeof value !== 'object' || value === null) return null
    const name: unknown = Reflect.get(value, 'name')
    if (typeof name !== 'object' || name === null) return null
    const first: unknown = Reflect.get(name, 'firstName')
    const last: unknown = Reflect.get(name, 'lastName')
    return displayName(
      [first, last].filter((part): part is string => typeof part === 'string').join(' '),
    )
  } catch {
    return null
  }
}

/**
 * Create the Apple driver.
 *
 * @example
 * const apple = appleDriver(settings, { http, now: Date.now })
 */
export function appleDriver(settings: AppleSettings, ctx: DriverContext): ProviderDriver {
  const { endpoints } = settings
  const jwks = createJwksCache({ url: endpoints.jwks, http: ctx.http, now: ctx.now, name: 'apple' })
  return {
    name: 'apple',
    responseMode: 'form_post',
    matchesIssuer: (iss) => iss === endpoints.issuer,
    authorizationUrl: (p) =>
      authorizationUrl(endpoints.authorization, {
        response_type: 'code',
        response_mode: 'form_post',
        client_id: settings.clientId,
        redirect_uri: p.redirectUri,
        scope: settings.scopes.join(' '),
        state: p.state,
        nonce: p.nonce,
      }),
    async complete(input) {
      const tokens = await exchangeCode(ctx, {
        provider: 'apple',
        tokenUrl: endpoints.token,
        clientId: settings.clientId,
        clientSecret: appleClientSecret(settings, ctx.now()),
        code: input.code,
        // No code_verifier: see the module note on PKCE. The nonce below binds the code instead.
        redirectUri: input.redirectUri,
      })
      const claims = await verifyIdToken(tokens['id_token'], jwks, {
        issuer: endpoints.issuer,
        clientId: settings.clientId,
        nonce: input.nonce,
        now: ctx.now(),
        algorithms: ['RS256'],
      })
      const email = normalizeEmail(claims['email'])
      return {
        provider: 'apple',
        subject: claims.sub,
        email,
        emailVerified: email !== null && booleanClaim(claims['email_verified']),
        name: appleUserName(input.appleUser),
      }
    },
  }
}
