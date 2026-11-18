import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  base64url,
  fromBase64url,
  randomToken,
  safeEqual,
  sha256Base64url,
} from '../src/crypto/encoding.ts'
import { decodeJwt, importJwk, MAX_JWT_LENGTH, signJwt, verifyJwt } from '../src/crypto/jwt.ts'
import { createPkce } from '../src/crypto/pkce.ts'
import { encrypterSealer, keySealer, parseAppKey } from '../src/crypto/sealer.ts'

const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' })
const rsaJwk = { ...rsa.publicKey.export({ format: 'jwk' }), kid: 'r1' }
const ecJwk = { ...ec.publicKey.export({ format: 'jwk' }), kid: 'e1' }
const seg = (value: unknown) => base64url(JSON.stringify(value))

describe('encoding', () => {
  it('base64url round-trips and refuses non-strict input', () => {
    expect(base64url('hi')).toBe('aGk')
    expect(fromBase64url('aGk')?.toString()).toBe('hi')
    expect(fromBase64url('aGk=')).toBeUndefined()
    expect(fromBase64url('a+b/')).toBeUndefined()
    expect(fromBase64url('a')).toBeUndefined()
    expect(fromBase64url('')?.length).toBe(0)
  })

  it('random tokens are 256-bit base64url and distinct', () => {
    const a = randomToken()
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(randomToken()).not.toBe(a)
    expect(randomToken(16)).toHaveLength(22)
  })

  it('safeEqual compares content and length', () => {
    expect(safeEqual('abc', 'abc')).toBe(true)
    expect(safeEqual('abc', 'abd')).toBe(false)
    expect(safeEqual('abc', 'abcd')).toBe(false)
  })

  it('PKCE challenge is BASE64URL(SHA256(verifier)) with S256 (RFC 7636 appendix B)', () => {
    expect(sha256Base64url('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe(
      'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    )
    const pkce = createPkce()
    expect(pkce.method).toBe('S256')
    expect(pkce.verifier.length).toBeGreaterThanOrEqual(43)
    expect(pkce.challenge).toBe(createHash('sha256').update(pkce.verifier).digest('base64url'))
  })
})

describe('sealer', () => {
  const sealer = keySealer(randomBytes(32))

  it('round-trips and binds the purpose', () => {
    const sealed = sealer.seal('flow:google', 'secret')
    expect(sealed).not.toContain('secret')
    expect(sealer.open('flow:google', sealed)).toBe('secret')
    expect(sealer.open('flow:github', sealed)).toBeUndefined()
  })

  it('refuses tampering, other keys, other versions and garbage', () => {
    const sealed = sealer.seal('p', 'value')
    const flipped = `${sealed.slice(0, -2)}${sealed.endsWith('A') ? 'B' : 'A'}${sealed.slice(-1)}`
    expect(sealer.open('p', flipped)).toBeUndefined()
    expect(keySealer(randomBytes(32)).open('p', sealed)).toBeUndefined()
    expect(sealer.open('p', sealed.replace(/^s1/, 's2'))).toBeUndefined()
    expect(sealer.open('p', `${sealed}.x`)).toBeUndefined()
    expect(sealer.open('p', 's1.')).toBeUndefined()
    expect(sealer.open('p', 's1.***')).toBeUndefined()
    expect(sealer.open('p', 'nonsense')).toBeUndefined()
  })

  it('needs a 32-byte secret', () => {
    expect(() => keySealer(randomBytes(16))).toThrow(RangeError)
  })

  it('wraps the framework Encrypter with a namespaced purpose; failures open as undefined', () => {
    const seen: (string | undefined)[] = []
    const sealer2 = encrypterSealer({
      encryptString: (p, o) => {
        seen.push(o?.purpose)
        return `enc:${o?.purpose}:${p}`
      },
      decryptString: (p, o) => {
        if (!p.startsWith(`enc:${o?.purpose}:`)) throw new Error('DecryptError')
        return p.slice(`enc:${o?.purpose}:`.length)
      },
    })
    const sealed = sealer2.seal('flow:apple', 'x')
    expect(seen).toEqual(['strutvane.social-login.flow:apple'])
    expect(sealer2.open('flow:apple', sealed)).toBe('x')
    expect(sealer2.open('flow:google', sealed)).toBeUndefined()
  })

  it('parses only base64: + 32-byte app keys', () => {
    expect(parseAppKey(`base64:${randomBytes(32).toString('base64')}`)?.length).toBe(32)
    expect(parseAppKey(`base64:${randomBytes(16).toString('base64')}`)).toBeUndefined()
    expect(parseAppKey(randomBytes(32).toString('base64'))).toBeUndefined()
    expect(parseAppKey('base64:not base64!')).toBeUndefined()
    expect(parseAppKey(undefined)).toBeUndefined()
  })
})

describe('JWS', () => {
  it('signs and verifies RS256 and ES256', () => {
    const r = decodeJwt(signJwt('RS256', rsa.privateKey, { kid: 'r1' }, { a: 1 }))
    const e = decodeJwt(signJwt('ES256', ec.privateKey, { kid: 'e1' }, { a: 1 }))
    expect(r && verifyJwt(r, rsaJwk, ['RS256'])).toBe(true)
    expect(e && verifyJwt(e, ecJwk, ['ES256'])).toBe(true)
    expect(e?.signature.length).toBe(64)
  })

  it('refuses algorithms outside the allow-list, alg none and HS256', () => {
    const r = decodeJwt(signJwt('RS256', rsa.privateKey, {}, { a: 1 }))
    expect(r && verifyJwt(r, rsaJwk, ['ES256'])).toBe(false)
    const none = decodeJwt(`${seg({ alg: 'none' })}.${seg({ a: 1 })}.AA`)
    expect(none && verifyJwt(none, rsaJwk, ['RS256'])).toBe(false)
    const hs = decodeJwt(`${seg({ alg: 'HS256' })}.${seg({ a: 1 })}.AAAA`)
    expect(hs && verifyJwt(hs, { kty: 'oct', k: 'AAAA' }, ['RS256'])).toBe(false)
  })

  it('refuses header-supplied keys (jwk, jku, x5u, x5c, crit)', () => {
    for (const header of [
      { jwk: rsaJwk },
      { jku: 'https://evil.test' },
      { x5u: 'x' },
      { x5c: [] },
      { crit: ['b64'] },
    ]) {
      const t = decodeJwt(signJwt('RS256', rsa.privateKey, header, { a: 1 }))
      expect(t && verifyJwt(t, rsaJwk, ['RS256'])).toBe(false)
    }
  })

  it('the key decides: wrong kty, curve, use or alg is refused', () => {
    const r = decodeJwt(signJwt('RS256', rsa.privateKey, {}, { a: 1 }))
    const e = decodeJwt(signJwt('ES256', ec.privateKey, {}, { a: 1 }))
    expect(r && verifyJwt(r, ecJwk, ['RS256', 'ES256'])).toBe(false)
    expect(e && verifyJwt(e, rsaJwk, ['RS256', 'ES256'])).toBe(false)
    expect(r && verifyJwt(r, { ...rsaJwk, use: 'enc' }, ['RS256'])).toBe(false)
    expect(r && verifyJwt(r, { ...rsaJwk, alg: 'RS512' }, ['RS256'])).toBe(false)
    expect(e && verifyJwt(e, { ...ecJwk, crv: 'P-384' }, ['ES256'])).toBe(false)
    expect(r && verifyJwt(r, { ...rsaJwk, use: 'sig', alg: 'RS256' }, ['RS256'])).toBe(true)
  })

  it('refuses a changed payload, a truncated ES256 signature and an unimportable key', () => {
    const token = signJwt('RS256', rsa.privateKey, {}, { a: 1 })
    const [h, , s] = token.split('.')
    const changed = decodeJwt(`${h}.${seg({ a: 2 })}.${s}`)
    expect(changed && verifyJwt(changed, rsaJwk, ['RS256'])).toBe(false)
    const e = signJwt('ES256', ec.privateKey, {}, { a: 1 }).split('.')
    const short = decodeJwt(`${e[0]}.${e[1]}.${base64url(Buffer.alloc(63))}`)
    expect(short && verifyJwt(short, ecJwk, ['ES256'])).toBe(false)
    const r = decodeJwt(token)
    expect(r && verifyJwt(r, { kty: 'RSA', n: 'AA', e: 'AQAB' }, ['RS256'])).toBe(false)
  })

  it('never imports a private JWK as a verification key', () => {
    const priv = rsa.privateKey.export({ format: 'jwk' })
    expect(importJwk(priv)).toBeUndefined()
    expect(importJwk({ kty: 'nope' })).toBeUndefined()
    expect(importJwk(rsaJwk)?.type).toBe('public')
  })

  it('decodes only well-formed compact tokens', () => {
    const good = signJwt('RS256', rsa.privateKey, {}, { a: 1 })
    expect(decodeJwt(good)?.payload).toEqual({ a: 1 })
    expect(decodeJwt('')).toBeUndefined()
    expect(decodeJwt('a.b')).toBeUndefined()
    expect(decodeJwt('a.b.c.d')).toBeUndefined()
    expect(decodeJwt(`${seg([1])}.${seg({})}.AA`)).toBeUndefined()
    expect(decodeJwt(`${seg({})}.${seg('x')}.AA`)).toBeUndefined()
    expect(decodeJwt(`${base64url('{bad')}.${seg({})}.AA`)).toBeUndefined()
    expect(decodeJwt(`${seg({})}.${seg({})}.`)).toBeUndefined()
    expect(decodeJwt(`${seg({})}.${seg({ pad: 'x'.repeat(MAX_JWT_LENGTH) })}.AA`)).toBeUndefined()
    expect(decodeJwt(42 as unknown as string)).toBeUndefined()
  })
})
