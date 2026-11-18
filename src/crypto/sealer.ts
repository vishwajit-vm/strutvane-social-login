/**
 * Sealing: authenticated encryption for the values this package keeps in the browser between the
 * redirect and the callback (the flow cookie). The browser must neither read them (the PKCE
 * verifier and nonce are secrets) nor change them (the return URL, the linking user), so they are
 * encrypted with AES-256-GCM and bound to a purpose (GCM additional data): a value sealed for
 * `flow:google` never opens as `flow:github`.
 *
 * Two implementations behind one interface:
 * - {@link encrypterSealer}: the framework's `Encrypter` (bound in a Strutvane app), which already
 *   handles `APP_KEY` rotation (`key:rotate`).
 * - {@link keySealer}: a standalone sealer from a 32-byte secret (tests, or an app without the
 *   framework's encrypter). The cipher key is derived with HKDF, never the raw secret.
 *
 * @module
 */
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto'
import { fromBase64url } from './encoding.ts'

/** Encrypts and authenticates short strings, bound to a purpose. */
export interface Sealer {
  /** Encrypt `plaintext` for `purpose`. The output is URL- and cookie-safe. */
  seal(purpose: string, plaintext: string): string
  /** Decrypt a sealed value; `undefined` when it was tampered with, forged or sealed for another purpose. */
  open(purpose: string, sealed: string): string | undefined
}

/** What {@link encrypterSealer} needs from the framework's `Encrypter`. */
export interface EncrypterLike {
  encryptString(plaintext: string, options?: { readonly purpose?: string }): string
  decryptString(payload: string, options?: { readonly purpose?: string }): string
}

const PURPOSE_PREFIX = 'strutvane.social-login.'
const VERSION = 's1'
const IV_BYTES = 12
const TAG_BYTES = 16

/**
 * A sealer backed by the framework's `Encrypter` (`EncrypterToken`).
 *
 * @example
 * const sealer = encrypterSealer(app.make(EncrypterToken))
 */
export function encrypterSealer(encrypter: EncrypterLike): Sealer {
  return {
    seal: (purpose, plaintext) =>
      encrypter.encryptString(plaintext, { purpose: PURPOSE_PREFIX + purpose }),
    open(purpose, sealed) {
      try {
        return encrypter.decryptString(sealed, { purpose: PURPOSE_PREFIX + purpose })
      } catch {
        return undefined
      }
    },
  }
}

/**
 * Parse an `APP_KEY` (`base64:` + 32 random bytes, Laravel's format). Returns `undefined` for
 * anything else: a short or malformed key must stop the boot, never weaken the cipher.
 *
 * @example
 * parseAppKey(`base64:${randomBytes(32).toString('base64')}`)?.length // 32
 */
export function parseAppKey(value: string | undefined): Buffer | undefined {
  if (value === undefined || !value.startsWith('base64:')) return undefined
  const raw = value.slice('base64:'.length)
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(raw)) return undefined
  const key = Buffer.from(raw, 'base64')
  return key.length === 32 ? key : undefined
}

/**
 * A standalone AES-256-GCM sealer. The cipher key is `HKDF-SHA256(secret, info=purpose label)`.
 *
 * @example
 * const sealer = keySealer(randomBytes(32))
 * sealer.open('flow', sealer.seal('flow', 'hi')) // 'hi'
 */
export function keySealer(secret: Uint8Array): Sealer {
  if (secret.length < 32) throw new RangeError('keySealer: the secret must have at least 32 bytes')
  const key = Buffer.from(
    hkdfSync('sha256', secret, Buffer.alloc(0), 'strutvane/social-login/seal/v1', 32),
  )
  return {
    seal(purpose, plaintext) {
      const iv = randomBytes(IV_BYTES)
      const cipher = createCipheriv('aes-256-gcm', key, iv)
      cipher.setAAD(Buffer.from(PURPOSE_PREFIX + purpose, 'utf8'))
      const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
      return `${VERSION}.${Buffer.concat([iv, cipher.getAuthTag(), body]).toString('base64url')}`
    },
    open(purpose, sealed) {
      const [version, payload, extra] = sealed.split('.')
      if (version !== VERSION || payload === undefined || extra !== undefined) return undefined
      const bytes = fromBase64url(payload)
      if (bytes === undefined || bytes.length < IV_BYTES + TAG_BYTES) return undefined
      try {
        const decipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(0, IV_BYTES))
        decipher.setAAD(Buffer.from(PURPOSE_PREFIX + purpose, 'utf8'))
        decipher.setAuthTag(bytes.subarray(IV_BYTES, IV_BYTES + TAG_BYTES))
        return Buffer.concat([
          decipher.update(bytes.subarray(IV_BYTES + TAG_BYTES)),
          decipher.final(),
        ]).toString('utf8')
      } catch {
        return undefined
      }
    },
  }
}
