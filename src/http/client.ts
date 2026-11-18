/**
 * Outbound HTTP to the providers (token exchange, JWKS, user info), with the limits every call
 * gets no matter who wrote the driver:
 * - **a timeout** (default 10 s), so a hanging provider can't pile up open sign-in requests;
 * - **no redirects** (`redirect: 'error'`): token and key endpoints never legitimately redirect,
 *   and following one could send the authorization code or client secret somewhere else;
 * - **a response size cap** (default 256 KiB), read as a stream, so a hostile or broken endpoint
 *   can't exhaust memory;
 * - **JSON only**: a body that isn't JSON reads as `undefined`, never half-parsed; callers check
 *   its shape before using it.
 *
 * The `fetch` function is injected, which is how every test runs against the in-process fake
 * provider with no network at all.
 *
 * @module
 */
import { SocialLoginError } from '../errors.ts'

/** The subset of `fetch` the client uses. */
export type FetchLike = (input: string, init: RequestInit) => Promise<Response>

/** Limits for outbound calls. */
export interface HttpClientOptions {
  readonly fetch: FetchLike
  /** Per-call timeout in milliseconds. Default 10 000. */
  readonly timeoutMs?: number
  /** Largest response body accepted, in bytes. Default 256 KiB. */
  readonly maxBytes?: number
}

/** A JSON response from a provider. */
export interface JsonResponse {
  readonly status: number
  readonly headers: Headers
  /** The parsed JSON body (object or array), or `undefined` when it wasn't JSON. */
  readonly body: unknown
}

/** The outbound client the drivers use. */
export interface HttpClient {
  /** Send a request and read a JSON value back. Throws `social_provider_unavailable` on transport failures. */
  json(url: string, init: RequestInit, what: string): Promise<JsonResponse>
}

const DEFAULT_TIMEOUT_MS = 10_000
const DEFAULT_MAX_BYTES = 256 * 1024

/** Read a body as text, stopping (and failing) past `max` bytes. */
async function readCapped(response: Response, max: number): Promise<string | undefined> {
  const declared = Number(response.headers.get('content-length') ?? '0')
  if (Number.isFinite(declared) && declared > max) return undefined
  const reader = response.body?.getReader()
  if (reader === undefined) return ''
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > max) {
      await reader.cancel().catch(() => undefined)
      return undefined
    }
    chunks.push(value)
  }
  return Buffer.concat(chunks).toString('utf8')
}

/**
 * Create the outbound client.
 *
 * @example
 * const http = createHttpClient({ fetch: globalThis.fetch })
 * const { body } = await http.json('https://www.googleapis.com/oauth2/v3/certs', { method: 'GET' }, 'google jwks')
 */
export function createHttpClient(options: HttpClientOptions): HttpClient {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES
  return {
    async json(url, init, what) {
      let response: Response
      try {
        response = await options.fetch(url, {
          ...init,
          redirect: 'error',
          signal: AbortSignal.timeout(timeoutMs),
        })
      } catch (cause) {
        throw new SocialLoginError('social_provider_unavailable', `${what}: request failed`, {
          cause,
        })
      }
      let text: string | undefined
      try {
        text = await readCapped(response, maxBytes)
      } catch (cause) {
        throw new SocialLoginError('social_provider_unavailable', `${what}: reading failed`, {
          cause,
        })
      }
      if (text === undefined)
        throw new SocialLoginError(
          'social_provider_unavailable',
          `${what}: response larger than ${maxBytes} bytes`,
        )
      if (response.status >= 500)
        throw new SocialLoginError(
          'social_provider_unavailable',
          `${what}: provider answered ${response.status}`,
        )
      let body: unknown
      try {
        body = text === '' ? undefined : JSON.parse(text)
      } catch {
        body = undefined
      }
      return { status: response.status, headers: response.headers, body }
    },
  }
}

/**
 * `value` as a plain JSON object, or `undefined`.
 *
 * @example
 * asObject(JSON.parse('{"a":1}'))?.['a'] // 1
 */
export function asObject(value: unknown): Readonly<Record<string, unknown>> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined
}
