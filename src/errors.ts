/**
 * The error codes `@strutvane/social-login` answers with (RFC-0003: stable lowercase `snake_case`
 * codes, titles from a catalog, never hard-coded messages in responses).
 *
 * In the browser flow an error ends as a redirect to the configured failure page with
 * `?error=<code>`, so the app's sign-in screen can show the catalog message. The code is the only
 * thing that leaves the server: never the provider's own error text, which an attacker who crafts
 * the callback URL controls.
 *
 * @module
 */
import { type ErrorDefinition, StrutvaneError } from '@strutvane/framework/core'

/** Every code this package raises. */
export type SocialLoginErrorCode =
  | 'social_provider_unknown'
  | 'social_state_invalid'
  | 'social_issuer_mismatch'
  | 'social_provider_error'
  | 'social_provider_unavailable'
  | 'social_token_invalid'
  | 'social_email_unverified'
  | 'social_domain_not_allowed'
  | 'social_tenant_not_allowed'
  | 'social_account_exists'
  | 'social_identity_in_use'
  | 'social_reauth_required'
  | 'social_registration_closed'
  | 'social_accounts_unavailable'

/** Status and default English title per code (the message catalog's fallback). */
const DEFINITIONS: readonly (readonly [SocialLoginErrorCode, number, string])[] = [
  ['social_provider_unknown', 404, 'This sign-in provider is not available'],
  ['social_state_invalid', 400, 'The sign-in request expired or did not start here. Try again.'],
  ['social_issuer_mismatch', 400, 'The sign-in response came from the wrong provider'],
  ['social_provider_error', 400, 'The provider did not complete the sign-in'],
  ['social_provider_unavailable', 503, 'The sign-in provider is not reachable right now'],
  ['social_token_invalid', 401, 'The sign-in response could not be verified'],
  ['social_email_unverified', 403, 'The provider has not verified this email address'],
  ['social_domain_not_allowed', 403, 'Accounts from this domain cannot sign in here'],
  ['social_tenant_not_allowed', 403, 'Accounts from this organization cannot sign in here'],
  [
    'social_account_exists',
    409,
    'An account with this email already exists. Sign in to it first, then connect this provider.',
  ],
  ['social_identity_in_use', 409, 'This provider account is already connected to another user'],
  ['social_reauth_required', 401, 'Confirm your identity again before connecting a provider'],
  ['social_registration_closed', 403, 'New accounts cannot be created here'],
  ['social_accounts_unavailable', 503, 'Social sign-in is not set up on this server'],
]

/**
 * The definitions the provider registers in the app's error registry at boot (unless something
 * registered the code first).
 *
 * @example
 * for (const d of SOCIAL_LOGIN_ERRORS) if (!registry.get(d.code)) registry.register(d)
 */
export const SOCIAL_LOGIN_ERRORS: readonly ErrorDefinition[] = Object.freeze(
  DEFINITIONS.map(([code, status, title]) =>
    Object.freeze({ code, status, title, owner: '@strutvane/social-login' }),
  ),
)

const STATUS: ReadonlyMap<string, number> = new Map(
  DEFINITIONS.map(([code, status]) => [code, status]),
)

/**
 * A social sign-in failure. `reason` is a developer-facing explanation for logs: it names what
 * failed (`"aud does not contain the client id"`) and never carries tokens, codes, emails or other
 * values from the request.
 *
 * @example
 * throw new SocialLoginError('social_state_invalid', 'state does not match the flow cookie')
 */
export class SocialLoginError extends StrutvaneError {
  override readonly code: SocialLoginErrorCode
  /** Why it failed, for logs. Safe to log. */
  readonly reason: string

  constructor(
    code: SocialLoginErrorCode,
    reason: string,
    options: { readonly cause?: unknown } = {},
  ) {
    super(code, {
      status: STATUS.get(code) ?? 400,
      ...(options.cause === undefined ? {} : { cause: options.cause }),
    })
    this.code = code
    this.reason = reason
  }
}

/**
 * Is `value` one of this package's error codes? Used to keep the `?error=` parameter to known
 * codes only.
 *
 * @example
 * isSocialLoginErrorCode('social_state_invalid') // true
 */
export function isSocialLoginErrorCode(value: string): value is SocialLoginErrorCode {
  return STATUS.has(value)
}
