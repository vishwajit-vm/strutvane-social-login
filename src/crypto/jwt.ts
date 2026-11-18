/**
 * The small part of JOSE this package needs: decode a compact JWS, verify its signature against a
 * JWK, and sign one (Apple's client secret, and the fake provider in `./testing`).
 *
 * Deliberately narrow, because every option a JWT library offers is one more way to get tokens
 * wrong:
 * - **Only asymmetric algorithms on an allow-list** (`RS256`, `ES256` by default). `none` and the
 *   `HS*` family are never accepted, which closes the classic "alg: none" and RSA-key-as-HMAC-secret
 *   attacks.
 * - **The key decides, not the token:** the header's `alg` must match the key's type (and the
 *   key's own `alg`, when it declares one); the key must be a signing key (`use` absent or `sig`).
 * - **No header-supplied keys:** `jwk`, `jku`, `x5u` and `x5c` headers are refused instead of being
 *   followed; keys only ever come from the provider's configured JWKS URL.
 * - **Bounded input:** tokens over 16 KiB and non-object headers or payloads are refused.
 *
 * @module
 */
import { createPublicKey, type JsonWebKey, type KeyObject, sign, verify } from 'node:crypto'
import { base64url, fromBase64url } from './encoding.ts'

/** Algorithms this package can verify and sign. */
export type JwsAlgorithm = 'RS256' | 'ES256'

/** A JSON Web Key as published in a provider's JWKS (only the members this package reads). */
export interface Jwk {
  readonly kty?: unknown
  readonly kid?: unknown
  readonly use?: unknown
  readonly alg?: unknown
  readonly crv?: unknown
  readonly [member: string]: unknown
}

/** A decoded (not yet verified) compact JWS. */
export interface DecodedJwt {
  readonly header: Readonly<Record<string, unknown>>
  readonly payload: Readonly<Record<string, unknown>>
  /** `base64url(header) + '.' + base64url(payload)`: the bytes the signature covers. */
  readonly signingInput: string
  readonly signature: Buffer
}

/** The longest token accepted (real ID tokens are 1–3 KiB). */
export const MAX_JWT_LENGTH: number = 16 * 1024

const REFUSED_HEADERS = ['jwk', 'jku', 'x5u', 'x5c', 'crit'] as const

function parseObject(segment: string): Record<string, unknown> | undefined {
  const bytes = fromBase64url(segment)
  if (bytes === undefined) return undefined
  try {
    const value: unknown = JSON.parse(bytes.toString('utf8'))
    return typeof value === 'object' && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : undefined
  } catch {
    return undefined
  }
}

/**
 * Decode a compact JWS without verifying it. Returns `undefined` for anything malformed.
 *
 * @example
 * const jwt = decodeJwt(idToken)
 * jwt?.header['kid']
 */
export function decodeJwt(token: string): DecodedJwt | undefined {
  if (typeof token !== 'string' || token.length === 0 || token.length > MAX_JWT_LENGTH)
    return undefined
  const parts = token.split('.')
  if (parts.length !== 3) return undefined
  const [h = '', p = '', s = ''] = parts
  const header = parseObject(h)
  const payload = parseObject(p)
  const signature = fromBase64url(s)
  if (header === undefined || payload === undefined || signature === undefined) return undefined
  if (signature.length === 0) return undefined
  return { header, payload, signingInput: `${h}.${p}`, signature }
}

/** Does this key fit this algorithm? */
function keyMatches(alg: JwsAlgorithm, jwk: Jwk): boolean {
  if (jwk.use !== undefined && jwk.use !== 'sig') return false
  if (jwk.alg !== undefined && jwk.alg !== alg) return false
  if (alg === 'RS256') return jwk.kty === 'RSA'
  return jwk.kty === 'EC' && jwk.crv === 'P-256'
}

/**
 * Import a public JWK. Returns `undefined` for a key Node cannot import, or a private key (a JWKS
 * must never carry the `d` member; refusing it keeps a leaked private key from being trusted).
 *
 * @example
 * const key = importJwk({ kty: 'RSA', n, e })
 */
export function importJwk(jwk: Jwk): KeyObject | undefined {
  if (jwk['d'] !== undefined) return undefined
  try {
    const key = createPublicKey({ key: jwk as JsonWebKey, format: 'jwk' })
    return key.type === 'public' ? key : undefined
  } catch {
    return undefined
  }
}

/**
 * Verify a decoded token's signature with `jwk`, accepting only the algorithms in `allowed`.
 *
 * @example
 * verifyJwt(jwt, jwk, ['RS256']) // true or false; never throws
 */
export function verifyJwt(jwt: DecodedJwt, jwk: Jwk, allowed: readonly JwsAlgorithm[]): boolean {
  const alg = jwt.header['alg']
  if (typeof alg !== 'string' || !allowed.includes(alg as JwsAlgorithm)) return false
  if (REFUSED_HEADERS.some((name) => jwt.header[name] !== undefined)) return false
  const algorithm = alg as JwsAlgorithm
  if (!keyMatches(algorithm, jwk)) return false
  const key = importJwk(jwk)
  if (key === undefined) return false
  try {
    const data = Buffer.from(jwt.signingInput, 'utf8')
    if (algorithm === 'RS256') return verify('sha256', data, key, jwt.signature)
    // JOSE's ECDSA signatures are raw r || s (64 bytes for P-256), not DER.
    if (jwt.signature.length !== 64) return false
    return verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, jwt.signature)
  } catch {
    return false
  }
}

/**
 * Sign a compact JWS (for Apple's client secret and test providers).
 *
 * @example
 * signJwt('ES256', privateKey, { kid: 'ABC123' }, { iss: 'TEAMID', sub: 'com.example.web' })
 */
export function signJwt(
  alg: JwsAlgorithm,
  privateKey: KeyObject,
  header: Readonly<Record<string, unknown>>,
  payload: Readonly<Record<string, unknown>>,
): string {
  const input = `${base64url(JSON.stringify({ ...header, alg, typ: 'JWT' }))}.${base64url(JSON.stringify(payload))}`
  const data = Buffer.from(input, 'utf8')
  const signature =
    alg === 'RS256'
      ? sign('sha256', data, privateKey)
      : sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' })
  return `${input}.${base64url(signature)}`
}
