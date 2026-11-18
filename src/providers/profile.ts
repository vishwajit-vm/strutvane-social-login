/**
 * Turning provider claims into profile fields, defensively: providers are trusted for identity,
 * but their free-text fields (names) are user-controlled and end up in the app's UI and database.
 *
 * @module
 */

/** A simple, deliberately strict email shape (one `@`, no spaces or control characters). */
const EMAIL = /^[^\s@\p{Cc}]{1,64}@[^\s@\p{Cc}]{1,255}$/u

/**
 * A trimmed, lower-cased email, or `null` when the claim is missing or not an email.
 *
 * @example
 * normalizeEmail(' Ada@Example.COM ') // 'ada@example.com'
 */
export function normalizeEmail(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const email = value.trim().toLowerCase()
  return email.length <= 320 && EMAIL.test(email) ? email : null
}

/**
 * A display name: control characters removed, whitespace collapsed, at most 200 characters, or
 * `null` when nothing is left.
 *
 * @example
 * displayName('  Ada\u0000 Lovelace ') // 'Ada Lovelace'
 */
export function displayName(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const clean = value
    .replace(/[\p{Cc}\p{Cf}]/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 200)
  return clean === '' ? null : clean
}

/**
 * Read a boolean claim that some providers send as a string (Apple: `"true"`).
 *
 * @example
 * booleanClaim('true') // true
 */
export function booleanClaim(value: unknown): boolean {
  return value === true || value === 'true'
}
