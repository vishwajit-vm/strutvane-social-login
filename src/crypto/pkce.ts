/**
 * PKCE (RFC 7636), required by OAuth 2.1 for every authorization-code flow: the client sends a
 * hash of a one-time secret with the authorization request and the secret itself with the token
 * request, so a stolen authorization code is useless to anyone who doesn't also hold the secret
 * (code injection, OAuth 2.1 §7.5.1). Only `S256` is used; `plain` would defeat the point.
 *
 * @module
 */
import { randomToken, sha256Base64url } from './encoding.ts'

/** A PKCE pair: the verifier stays on the server, the challenge goes to the provider. */
export interface Pkce {
  /** 43 base64url characters (32 random bytes): within RFC 7636's 43–128 range. */
  readonly verifier: string
  /** `BASE64URL(SHA256(verifier))`. */
  readonly challenge: string
  readonly method: 'S256'
}

/**
 * Create a fresh PKCE pair.
 *
 * @example
 * const { verifier, challenge } = createPkce()
 */
export function createPkce(): Pkce {
  const verifier = randomToken(32)
  return { verifier, challenge: sha256Base64url(verifier), method: 'S256' }
}
