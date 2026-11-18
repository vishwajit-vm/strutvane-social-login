/**
 * Building sign-in links for buttons ("Sign in with Google") and the account settings page
 * ("Connect GitHub").
 *
 * @module
 */
import type { ProviderName } from './providers/types.ts'

/** Options for {@link socialLoginUrl}. */
export interface SocialLoginUrlOptions {
  /** Where to land afterwards: a path on this app (anything else is replaced by the home page). */
  readonly returnTo?: string
  /** `link` connects the provider to the signed-in user (needs a recent sign-in). Default `login`. */
  readonly intent?: 'login' | 'link'
  /** The routes' prefix (`config/social-login.ts` `path`). Default `/auth`. */
  readonly path?: string
}

/**
 * The path that starts a sign-in (or a link) with `provider`.
 *
 * @example
 * socialLoginUrl('google', { returnTo: '/dashboard' }) // '/auth/google/redirect?return_to=%2Fdashboard'
 * socialLoginUrl('github', { intent: 'link', returnTo: '/settings/accounts' })
 */
export function socialLoginUrl(
  provider: ProviderName,
  options: SocialLoginUrlOptions = {},
): string {
  const params = new URLSearchParams()
  if (options.returnTo !== undefined) params.set('return_to', options.returnTo)
  if (options.intent === 'link') params.set('intent', 'link')
  const query = params.toString()
  return `${options.path ?? '/auth'}/${provider}/redirect${query === '' ? '' : `?${query}`}`
}
