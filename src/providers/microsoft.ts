/**
 * Microsoft identity platform v2 (OpenID Connect): work and school accounts (Entra ID) and
 * personal Microsoft accounts.
 *
 * Multi-tenant rules (the part that is easy to get wrong):
 * - With `tenant: 'common' | 'organizations' | 'consumers'` the discovery document's issuer is a
 *   template, `https://login.microsoftonline.com/{tenantid}/v2.0`. A token is accepted only when
 *   its `iss` is that template filled with the token's **own** `tid`, and `tid` is a GUID. Checking
 *   against the template, or only the host, would accept a token minted for any tenant's app.
 * - `organizations` refuses personal accounts (the consumers tenant); `consumers` accepts only
 *   them; a single tenant id accepts only that tenant.
 * - `allowedTenants` narrows a multi-tenant app to the listed tenants (`social_tenant_not_allowed`).
 * - Identity: `tid` + `oid` (Microsoft's guidance for a stable user id), as `tid/oid`.
 *
 * Email rule: Microsoft's `email` claim is **not verified** by default. Any tenant admin can put
 * any address there, which is how "nOAuth"-style account takeovers happen. It counts as verified
 * only when the token carries `xms_edov: true` (email domain owner verified), an optional claim
 * the app registration must request. Without it, a Microsoft sign-in can still use an account
 * that is already linked, but never creates one.
 *
 * @module
 */
import { MICROSOFT_CONSUMERS_TENANT, type ResolvedProvider } from '../config.ts'
import { SocialLoginError } from '../errors.ts'
import { verifyIdToken } from '../oidc/id-token.ts'
import { createJwksCache } from '../oidc/jwks.ts'
import { authorizationUrl, exchangeCode } from './oauth.ts'
import { booleanClaim, displayName, normalizeEmail } from './profile.ts'
import type { DriverContext, ProviderDriver } from './types.ts'

type MicrosoftSettings = Extract<ResolvedProvider, { name: 'microsoft' }>

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/** Is this tenant id acceptable for the configured `tenant`? */
export function tenantAccepted(tenant: string, tid: string): boolean {
  if (!GUID.test(tid)) return false
  if (tenant === 'common') return true
  if (tenant === 'organizations') return tid !== MICROSOFT_CONSUMERS_TENANT
  if (tenant === 'consumers') return tid === MICROSOFT_CONSUMERS_TENANT
  return tid === tenant
}

/**
 * Create the Microsoft driver.
 *
 * @example
 * const microsoft = microsoftDriver(settings, { http, now: Date.now })
 */
export function microsoftDriver(settings: MicrosoftSettings, ctx: DriverContext): ProviderDriver {
  const { endpoints } = settings
  const jwks = createJwksCache({
    url: endpoints.jwks,
    http: ctx.http,
    now: ctx.now,
    name: 'microsoft',
  })
  /** The exact issuer for tenant `tid` (the template filled in, or a fixed override). */
  const issuerFor = (tid: string): string => endpoints.issuer.replace('{tenantid}', tid)
  const issuerOk = (iss: string, tid: unknown): boolean =>
    typeof tid === 'string' && tenantAccepted(settings.tenant, tid) && iss === issuerFor(tid)

  return {
    name: 'microsoft',
    responseMode: 'query',
    matchesIssuer(iss) {
      // RFC 9207: the callback's `iss` names the token's tenant; check it against the same rules.
      const [prefix = '', suffix = ''] = endpoints.issuer.split('{tenantid}')
      if (!endpoints.issuer.includes('{tenantid}')) return iss === endpoints.issuer
      if (!iss.startsWith(prefix) || !iss.endsWith(suffix)) return false
      return issuerOk(iss, iss.slice(prefix.length, iss.length - suffix.length))
    },
    authorizationUrl: (p) =>
      authorizationUrl(endpoints.authorization, {
        response_type: 'code',
        response_mode: 'query',
        client_id: settings.clientId,
        redirect_uri: p.redirectUri,
        scope: settings.scopes.join(' '),
        state: p.state,
        nonce: p.nonce,
        code_challenge: p.codeChallenge,
        code_challenge_method: 'S256',
      }),
    async complete(input) {
      const tokens = await exchangeCode(ctx, {
        provider: 'microsoft',
        tokenUrl: endpoints.token,
        clientId: settings.clientId,
        clientSecret: settings.clientSecret,
        code: input.code,
        codeVerifier: input.codeVerifier,
        redirectUri: input.redirectUri,
      })
      const claims = await verifyIdToken(tokens['id_token'], jwks, {
        issuer: (iss, c) => issuerOk(iss, c['tid']),
        clientId: settings.clientId,
        nonce: input.nonce,
        now: ctx.now(),
        algorithms: ['RS256'],
      })
      const tid = String(claims['tid'])
      if (settings.allowedTenants.length > 0 && !settings.allowedTenants.includes(tid))
        throw new SocialLoginError('social_tenant_not_allowed', 'microsoft: tid is not allowed')
      const oid = claims['oid']
      if (typeof oid !== 'string' || !GUID.test(oid.toLowerCase()))
        throw new SocialLoginError('social_token_invalid', 'id_token: oid missing')
      const email = normalizeEmail(claims['email'])
      return {
        provider: 'microsoft',
        subject: `${tid}/${oid.toLowerCase()}`,
        email,
        emailVerified: email !== null && booleanClaim(claims['xms_edov']),
        name: displayName(claims['name']),
      }
    },
  }
}
