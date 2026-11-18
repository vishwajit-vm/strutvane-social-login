/**
 * What every provider driver implements, and the profile it produces.
 *
 * A driver knows one provider's endpoints and quirks (Apple's form post and JWT client secret,
 * Microsoft's per-tenant issuers, GitHub's separate email API). Everything that is the same for
 * all of them (state, PKCE, nonce, cookies, return URLs, account linking) lives in the handler, so
 * no driver can skip a check.
 *
 * @module
 */
import type { HttpClient } from '../http/client.ts'

/** The providers this package ships. */
export type ProviderName = 'google' | 'microsoft' | 'github' | 'apple'

/** The provider names, in the order the installer offers them. */
export const PROVIDER_NAMES: readonly ProviderName[] = ['google', 'microsoft', 'github', 'apple']

/** Who the provider says signed in. */
export interface SocialProfile {
  readonly provider: ProviderName
  /** The provider's stable user id (`sub`, GitHub's numeric id, Microsoft's `tid/oid`). */
  readonly subject: string
  /** Lower-cased email, or `null` when the provider gave none. */
  readonly email: string | null
  /**
   * Whether the provider vouches that the user controls `email`, by that provider's own rules
   * (see each driver). Only a verified email may create an account.
   */
  readonly emailVerified: boolean
  /** A display name (never used to identify anyone), or `null`. */
  readonly name: string | null
}

/** The values the handler generated for one authorization request. */
export interface AuthorizationParams {
  readonly state: string
  readonly nonce: string
  readonly codeChallenge: string
  readonly redirectUri: string
}

/** What the handler hands a driver to finish a sign-in. */
export interface CompletionInput {
  readonly code: string
  readonly codeVerifier: string
  readonly nonce: string
  readonly redirectUri: string
  /**
   * Apple only: the `user` form field of the first authorization (name and email as typed by the
   * user). Unsigned, so it is used for the display name only, never for identity.
   */
  readonly appleUser?: string
}

/** Shared services every driver gets. */
export interface DriverContext {
  readonly http: HttpClient
  /** Milliseconds since the epoch. */
  readonly now: () => number
}

/** One provider. */
export interface ProviderDriver {
  readonly name: ProviderName
  /** `query` (a GET callback) or `form_post` (Apple: a cross-site POST callback). */
  readonly responseMode: 'query' | 'form_post'
  /**
   * The issuer an RFC 9207 `iss` callback parameter must match when the provider sends one (mix-up
   * defence). `undefined` for providers without an issuer (GitHub).
   */
  matchesIssuer(iss: string): boolean
  /** The provider URL to send the browser to. */
  authorizationUrl(params: AuthorizationParams): string
  /** Exchange the code (with the PKCE verifier) and return the verified profile. */
  complete(input: CompletionInput): Promise<SocialProfile>
}
