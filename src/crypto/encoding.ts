/**
 * Small, dependency-free building blocks: base64url, random tokens, hashing and constant-time
 * comparison. Everything security-relevant in this package goes through these few functions, so
 * there is exactly one place to review how randomness and comparisons are done.
 *
 * @module
 */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'

/** Strict base64url alphabet (no padding), as used by JOSE (RFC 7515 §2) and PKCE (RFC 7636). */
const BASE64URL = /^[A-Za-z0-9_-]*$/

/**
 * Encode bytes (or a UTF-8 string) as unpadded base64url.
 *
 * @example
 * base64url('hi') // 'aGk'
 */
export function base64url(input: Uint8Array | string): string {
  const bytes = typeof input === 'string' ? Buffer.from(input, 'utf8') : Buffer.from(input)
  return bytes.toString('base64url')
}

/**
 * Decode unpadded base64url. Returns `undefined` for anything that is not strict base64url, so a
 * malformed token is refused instead of being decoded leniently (Node's decoder skips bad input).
 *
 * @example
 * fromBase64url('aGk')?.toString() // 'hi'
 */
export function fromBase64url(input: string): Buffer | undefined {
  if (!BASE64URL.test(input) || input.length % 4 === 1) return undefined
  return Buffer.from(input, 'base64url')
}

/**
 * A random, URL-safe token with `bytes` bytes of entropy (default 32: 256 bits). Used for `state`,
 * `nonce` and the PKCE verifier.
 *
 * @example
 * randomToken() // 43 characters
 */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url')
}

/**
 * SHA-256 of a UTF-8 string, as base64url (the PKCE `S256` transform, RFC 7636 §4.2).
 *
 * @example
 * sha256Base64url('verifier')
 */
export function sha256Base64url(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('base64url')
}

/**
 * Compare two strings in constant time with respect to their content. Different lengths return
 * `false` straight away; the length of a random token is not a secret.
 *
 * @example
 * safeEqual(expectedState, receivedState)
 */
export function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8')
  const right = Buffer.from(b, 'utf8')
  if (left.length !== right.length) return false
  return timingSafeEqual(left, right)
}
