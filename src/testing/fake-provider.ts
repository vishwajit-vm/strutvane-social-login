/**
 * A fake OpenID Connect / OAuth 2.0 provider that runs in-process, for tests with **no network**:
 * it is a `fetch` function you hand to the provider (`createSocialLoginProvider({ fetch })`) plus a
 * way to play the user's part at the provider's consent screen.
 *
 * It behaves like a strict real provider, so tests prove the client side does the right thing:
 * - codes are single use, expire after 60 s and are bound to the client, the `redirect_uri` and
 *   (when sent) the PKCE challenge (`S256` only);
 * - ID tokens are signed (`RS256` by default) with a key published at the JWKS endpoint, and carry
 *   the request's `nonce`;
 * - a GitHub-style API (`/user`, `/user/emails`) answers for access tokens it issued.
 *
 * Attack tests reach past that with {@link FakeOidcProvider.mintIdToken} (sign any claims) and the
 * `idTokenClaims` hook (change a token the token endpoint is about to return).
 *
 * @example
 * const idp = createFakeOidcProvider({ clientId: 'app' })
 * const app = createSocialLoginProvider({ fetch: idp.fetch })
 * const callback = idp.consent(locationHeader, { sub: 'u1', email: 'ada@example.com', emailVerified: true })
 *
 * @module
 */
import {
  createHash,
  generateKeyPairSync,
  type JsonWebKey,
  type KeyObject,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto'
import { type JwsAlgorithm, signJwt } from '../crypto/jwt.ts'

/** A user at the fake provider. */
export interface FakeUser {
  readonly sub: string
  readonly email?: string
  readonly emailVerified?: boolean
  readonly name?: string
  /** Extra ID token claims (`hd`, `tid`, `oid`, `xms_edov`, …). */
  readonly claims?: Readonly<Record<string, unknown>>
  /** GitHub-style: the numeric id and the `/user/emails` list. */
  readonly githubId?: number
  readonly githubEmails?: readonly {
    readonly email: string
    readonly primary: boolean
    readonly verified: boolean
  }[]
}

/** Options for {@link createFakeOidcProvider}. */
export interface FakeProviderOptions {
  readonly clientId: string
  /** Checked at the token endpoint when set (Apple-style providers send a JWT instead). */
  readonly clientSecret?: string
  /** Default `https://idp.test`. Endpoints live under it. */
  readonly issuer?: string
  readonly alg?: JwsAlgorithm
  /** Milliseconds since the epoch. Default `Date.now`. */
  readonly now?: () => number
  /** Change the claims of every ID token the token endpoint returns (attack tests). */
  readonly idTokenClaims?: (claims: Record<string, unknown>) => Record<string, unknown>
}

/** One recorded outbound request (for "nothing secret was sent elsewhere" assertions). */
export interface RecordedRequest {
  readonly url: string
  readonly method: string
  readonly body: string
}

/** The fake provider. */
export interface FakeOidcProvider {
  readonly issuer: string
  /** Endpoint overrides for `config/social-login.ts`. */
  readonly endpoints: {
    readonly authorization: string
    readonly token: string
    readonly jwks: string
    readonly issuer: string
    readonly api: string
  }
  /** The outbound `fetch` to give the provider under test. */
  readonly fetch: (input: string, init: RequestInit) => Promise<Response>
  /** Every request the fake received, in order. */
  readonly requests: readonly RecordedRequest[]
  /**
   * Play the user approving the request at `authorizationUrl`: returns the callback URL the
   * provider would redirect to (`code` + `state`, plus `extra` parameters such as `iss`).
   */
  consent(
    authorizationUrl: string,
    user: FakeUser,
    extra?: Readonly<Record<string, string>>,
  ): string
  /** Like {@link consent}, but the authorization parameters only (for form posts). */
  approve(
    authorizationUrl: string,
    user: FakeUser,
  ): { readonly code: string; readonly state: string }
  /** Sign arbitrary ID token claims with the provider's current key. */
  mintIdToken(
    claims: Readonly<Record<string, unknown>>,
    header?: Readonly<Record<string, unknown>>,
  ): string
  /** Publish a new signing key (the old one is no longer in the JWKS). */
  rotateKeys(): void
  /** How many times the JWKS endpoint was fetched. */
  jwksFetches(): number
}

interface IssuedCode {
  readonly clientId: string
  readonly redirectUri: string
  readonly challenge: string | null
  readonly nonce: string | null
  readonly scope: string
  readonly user: FakeUser
  readonly expiresAt: number
  used: boolean
}

function keyPair(alg: JwsAlgorithm): { privateKey: KeyObject; jwk: JsonWebKey; kid: string } {
  const { privateKey, publicKey } =
    alg === 'RS256'
      ? generateKeyPairSync('rsa', { modulusLength: 2048 })
      : generateKeyPairSync('ec', { namedCurve: 'P-256' })
  return {
    privateKey,
    jwk: publicKey.export({ format: 'jwk' }),
    kid: randomBytes(8).toString('hex'),
  }
}

const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'max-age=3600' },
  })

/**
 * Create a fake provider.
 *
 * @example
 * const idp = createFakeOidcProvider({ clientId: 'app', clientSecret: 'secret' })
 */
export function createFakeOidcProvider(options: FakeProviderOptions): FakeOidcProvider {
  const issuer = options.issuer ?? 'https://idp.test'
  const alg = options.alg ?? 'RS256'
  const now = options.now ?? Date.now
  const endpoints = {
    authorization: `${issuer}/authorize`,
    token: `${issuer}/token`,
    jwks: `${issuer}/jwks`,
    issuer,
    api: `${issuer}/api`,
  }
  let key = keyPair(alg)
  let jwksCount = 0
  const codes = new Map<string, IssuedCode>()
  const tokens = new Map<string, FakeUser>()
  const requests: RecordedRequest[] = []

  const mintIdToken = (
    claims: Readonly<Record<string, unknown>>,
    header: Readonly<Record<string, unknown>> = {},
  ): string => signJwt(alg, key.privateKey, { kid: key.kid, ...header }, claims)

  function approve(authorizationUrl: string, user: FakeUser): { code: string; state: string } {
    const url = new URL(authorizationUrl)
    const p = url.searchParams
    if (`${url.origin}${url.pathname}` !== endpoints.authorization)
      throw new Error(`fake provider: not its authorization endpoint: ${url.origin}${url.pathname}`)
    if (p.get('response_type') !== 'code')
      throw new Error('fake provider: response_type must be code')
    if (p.get('client_id') !== options.clientId) throw new Error('fake provider: unknown client_id')
    const method = p.get('code_challenge_method')
    if (p.get('code_challenge') !== null && method !== 'S256')
      throw new Error('fake provider: only S256 PKCE')
    const code = randomBytes(24).toString('base64url')
    codes.set(code, {
      clientId: options.clientId,
      redirectUri: p.get('redirect_uri') ?? '',
      challenge: p.get('code_challenge'),
      nonce: p.get('nonce'),
      scope: p.get('scope') ?? '',
      user,
      expiresAt: now() + 60_000,
      used: false,
    })
    return { code, state: p.get('state') ?? '' }
  }

  function tokenEndpoint(body: URLSearchParams): Response {
    const code = codes.get(body.get('code') ?? '')
    const refuse = () => json({ error: 'invalid_grant' }, 400)
    if (body.get('grant_type') !== 'authorization_code')
      return json({ error: 'unsupported_grant_type' }, 400)
    if (code === undefined || code.used || code.expiresAt < now()) {
      // A replayed code: real providers also revoke what it issued.
      if (code !== undefined) code.used = true
      return refuse()
    }
    code.used = true
    if (body.get('client_id') !== code.clientId) return json({ error: 'invalid_client' }, 401)
    if (options.clientSecret !== undefined && body.get('client_secret') !== options.clientSecret)
      return json({ error: 'invalid_client' }, 401)
    if (body.get('redirect_uri') !== code.redirectUri) return refuse()
    if (code.challenge !== null) {
      const verifier = body.get('code_verifier') ?? ''
      const expected = Buffer.from(code.challenge)
      const actual = Buffer.from(createHash('sha256').update(verifier).digest('base64url'))
      if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return refuse()
    }
    const accessToken = randomBytes(24).toString('base64url')
    tokens.set(accessToken, code.user)
    const out: Record<string, unknown> = { access_token: accessToken, token_type: 'Bearer' }
    if (code.scope.split(' ').includes('openid') || code.nonce !== null) {
      const iat = Math.floor(now() / 1000)
      const base: Record<string, unknown> = {
        iss: issuer,
        sub: code.user.sub,
        aud: code.clientId,
        iat,
        exp: iat + 3600,
        ...(code.nonce === null ? {} : { nonce: code.nonce }),
        ...(code.user.email === undefined ? {} : { email: code.user.email }),
        ...(code.user.emailVerified === undefined
          ? {}
          : { email_verified: code.user.emailVerified }),
        ...(code.user.name === undefined ? {} : { name: code.user.name }),
        ...code.user.claims,
      }
      out['id_token'] = mintIdToken(options.idTokenClaims ? options.idTokenClaims(base) : base)
    }
    return json(out)
  }

  function api(path: string, authorization: string | null): Response {
    const user = tokens.get((authorization ?? '').replace(/^Bearer /, ''))
    if (user === undefined) return json({ message: 'Bad credentials' }, 401)
    if (path === '/user')
      return json({ id: user.githubId ?? 1, login: user.sub, name: user.name ?? null, email: null })
    if (path === '/user/emails') return json(user.githubEmails ?? [])
    return json({ message: 'Not Found' }, 404)
  }

  const fetchFn = async (input: string, init: RequestInit): Promise<Response> => {
    const url = new URL(input)
    const method = (init.method ?? 'GET').toUpperCase()
    const body = typeof init.body === 'string' ? init.body : ''
    requests.push({ url: url.href, method, body })
    const headers = new Headers(init.headers)
    if (url.href === endpoints.token && method === 'POST')
      return tokenEndpoint(new URLSearchParams(body))
    if (url.href === endpoints.jwks && method === 'GET') {
      jwksCount++
      return json({ keys: [{ ...key.jwk, kid: key.kid, use: 'sig', alg }] })
    }
    if (url.href.startsWith(`${endpoints.api}/`) && method === 'GET')
      return api(
        url.pathname.slice(new URL(endpoints.api).pathname.length),
        headers.get('authorization'),
      )
    throw new TypeError(
      `fake provider: no route for ${method} ${url.href} (the test tried the network)`,
    )
  }

  return {
    issuer,
    endpoints,
    fetch: fetchFn,
    requests,
    approve,
    consent(authorizationUrl, user, extra = {}) {
      const { code, state } = approve(authorizationUrl, user)
      const redirect = new URL(new URL(authorizationUrl).searchParams.get('redirect_uri') ?? '')
      redirect.searchParams.set('code', code)
      redirect.searchParams.set('state', state)
      for (const [k, v] of Object.entries(extra)) redirect.searchParams.set(k, v)
      return redirect.href
    },
    mintIdToken,
    rotateKeys() {
      key = keyPair(alg)
    },
    jwksFetches: () => jwksCount,
  }
}
