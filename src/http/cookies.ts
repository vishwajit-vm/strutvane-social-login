/**
 * Reading and writing the few cookies this package sets. Kept tiny and strict: names are fixed by
 * this package, values are base64url/sealed strings, so nothing needs quoting or decoding.
 *
 * @module
 */

/** Attributes for {@link serializeCookie}. */
export interface CookieAttributes {
  /** Seconds; `0` deletes the cookie. */
  readonly maxAge: number
  readonly secure: boolean
  readonly sameSite: 'Lax' | 'None'
  readonly path?: string
}

/**
 * Read one cookie from a `Cookie` header. The first occurrence wins; a cookie set with a weaker
 * path can't shadow it because `__Host-` names (used on https) pin `Path=/`.
 *
 * @example
 * readCookie('a=1; b=2', 'b') // '2'
 */
export function readCookie(header: string | null, name: string): string | undefined {
  if (header === null || header.length > 16 * 1024) return undefined
  for (const part of header.split(';')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim()
  }
  return undefined
}

/**
 * Build a `Set-Cookie` value. Always `HttpOnly`; `SameSite=None` is only ever sent with `Secure`
 * (browsers drop it otherwise, and it must never travel over plain http).
 *
 * @example
 * serializeCookie('__Host-sv_social_google', sealed, { maxAge: 600, secure: true, sameSite: 'Lax' })
 */
export function serializeCookie(name: string, value: string, attrs: CookieAttributes): string {
  if (attrs.sameSite === 'None' && !attrs.secure)
    throw new TypeError('serializeCookie: SameSite=None needs Secure')
  const parts = [
    `${name}=${value}`,
    `Path=${attrs.path ?? '/'}`,
    `Max-Age=${attrs.maxAge}`,
    'HttpOnly',
    `SameSite=${attrs.sameSite}`,
  ]
  if (attrs.secure) parts.push('Secure')
  return parts.join('; ')
}
