import { describe, expect, it } from 'vitest'
import { SocialLoginError } from '../src/errors.ts'
import { asObject, createHttpClient, type FetchLike } from '../src/http/client.ts'
import { readCookie, serializeCookie } from '../src/http/cookies.ts'

const reply =
  (body: ConstructorParameters<typeof Response>[0], init: ResponseInit = {}): FetchLike =>
  async () =>
    new Response(body, init)

describe('outbound HTTP client', () => {
  it('parses JSON objects and arrays; anything else reads as undefined', async () => {
    expect((await createHttpClient({ fetch: reply('{"a":1}') }).json('u', {}, 'x')).body).toEqual({
      a: 1,
    })
    expect((await createHttpClient({ fetch: reply('[1]') }).json('u', {}, 'x')).body).toEqual([1])
    expect(
      (await createHttpClient({ fetch: reply('<html>') }).json('u', {}, 'x')).body,
    ).toBeUndefined()
    expect((await createHttpClient({ fetch: reply(null) }).json('u', {}, 'x')).body).toBeUndefined()
  })

  it('never follows redirects and always sets a timeout', async () => {
    let seen: RequestInit | undefined
    await createHttpClient({
      fetch: async (_u, init) => {
        seen = init
        return new Response('{}')
      },
    }).json('u', { method: 'POST' }, 'x')
    expect(seen?.redirect).toBe('error')
    expect(seen?.signal).toBeInstanceOf(AbortSignal)
    expect(seen?.method).toBe('POST')
  })

  it('a transport failure or timeout is social_provider_unavailable', async () => {
    const failing = createHttpClient({
      fetch: async () => {
        throw new TypeError('fetch failed')
      },
    })
    await expect(failing.json('u', {}, 'x')).rejects.toMatchObject({
      code: 'social_provider_unavailable',
      reason: 'x: request failed',
    })
    const slow = createHttpClient({
      timeoutMs: 20,
      fetch: (_u, init) =>
        new Promise((_resolve, reject) => {
          init.signal?.addEventListener('abort', () => reject(init.signal?.reason))
        }),
    })
    await expect(slow.json('u', {}, 'x')).rejects.toBeInstanceOf(SocialLoginError)
  })

  it('5xx answers are unavailable; 4xx are returned for the caller to judge', async () => {
    await expect(
      createHttpClient({ fetch: reply('{}', { status: 502 }) }).json('u', {}, 'x'),
    ).rejects.toMatchObject({
      code: 'social_provider_unavailable',
    })
    expect(
      (
        await createHttpClient({ fetch: reply('{"error":"invalid_grant"}', { status: 400 }) }).json(
          'u',
          {},
          'x',
        )
      ).status,
    ).toBe(400)
  })

  it('caps the body by Content-Length and while streaming', async () => {
    const declared = createHttpClient({
      maxBytes: 10,
      fetch: reply('{}', { headers: { 'content-length': '11' } }),
    })
    await expect(declared.json('u', {}, 'x')).rejects.toMatchObject({
      reason: 'x: response larger than 10 bytes',
    })
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        for (let i = 0; i < 5; i++) controller.enqueue(new Uint8Array(8))
        controller.close()
      },
    })
    const streamed = createHttpClient({ maxBytes: 16, fetch: reply(stream) })
    await expect(streamed.json('u', {}, 'x')).rejects.toMatchObject({
      code: 'social_provider_unavailable',
    })
  })

  it('a body that fails mid-read is unavailable', async () => {
    const broken = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.error(new Error('reset'))
      },
    })
    await expect(
      createHttpClient({ fetch: reply(broken) }).json('u', {}, 'x'),
    ).rejects.toMatchObject({
      reason: 'x: reading failed',
    })
  })

  it('asObject accepts only plain objects', () => {
    expect(asObject({ a: 1 })).toEqual({ a: 1 })
    expect(asObject([1])).toBeUndefined()
    expect(asObject(null)).toBeUndefined()
    expect(asObject('x')).toBeUndefined()
  })
})

describe('cookies', () => {
  it('reads one cookie by exact name; the first occurrence wins', () => {
    expect(readCookie('a=1; b=2', 'b')).toBe('2')
    expect(readCookie('ab=1; b=2; b=3', 'b')).toBe('2')
    expect(readCookie('junk; b=2', 'b')).toBe('2')
    expect(readCookie('a=1', 'b')).toBeUndefined()
    expect(readCookie(null, 'b')).toBeUndefined()
    expect(readCookie(`b=${'x'.repeat(17 * 1024)}`, 'b')).toBeUndefined()
  })

  it('serializes HttpOnly cookies; SameSite=None requires Secure', () => {
    expect(serializeCookie('n', 'v', { maxAge: 60, secure: true, sameSite: 'Lax' })).toBe(
      'n=v; Path=/; Max-Age=60; HttpOnly; SameSite=Lax; Secure',
    )
    expect(
      serializeCookie('n', 'v', { maxAge: 0, secure: false, sameSite: 'Lax', path: '/auth' }),
    ).toBe('n=v; Path=/auth; Max-Age=0; HttpOnly; SameSite=Lax')
    expect(() => serializeCookie('n', 'v', { maxAge: 1, secure: false, sameSite: 'None' })).toThrow(
      TypeError,
    )
  })
})
