/**
 * The account contract: what social sign-in needs from the app's identity system (users, linked
 * provider identities and sessions), and the container token it is resolved under.
 *
 * Why a contract instead of calling `@strutvane/auth`: add-ons never import each other (hub
 * integration map §1). Social sign-in proves *who someone is at Google*; deciding *which user of
 * this app that is* and *starting a session* belongs to the identity system. This package owns
 * the rules in between (see `accounts/resolve.ts`): never auto-link, verified emails only,
 * re-authentication before linking. The identity side only answers the narrow questions below.
 *
 * Today the app binds {@link SocialAccountsToken} (for example, glue code over `@strutvane/auth`'s
 * engine, or the in-memory `memorySocialAccounts()` from `./testing` in tests). The plan is for
 * the contract and token to move into `@strutvane/framework/contracts` so `@strutvane/auth` can
 * provide it directly (an open decision; see NEXT.md).
 *
 * @module
 */
import { type Token, token } from '@strutvane/framework/core'

/** A provider identity: the provider's name and its stable id for the user (`sub`). */
export interface SocialIdentity {
  /** `google`, `microsoft`, `github` or `apple`. */
  readonly provider: string
  /** The provider's stable user id. Never an email address. */
  readonly subject: string
}

/** A user of the app, as far as this package needs to know. */
export interface SocialUserRef {
  readonly id: string
}

/** The user signed in on the current request. */
export interface CurrentUser {
  readonly id: string
  /**
   * When this user last proved who they are (signed in, or confirmed their password), in
   * milliseconds since the epoch. Linking a provider requires this to be recent.
   */
  readonly authenticatedAt: number
}

/** What the identity side does when a sign-in should start a session. */
export interface SignInOutcome {
  /** Headers for the response (normally the session `Set-Cookie`). */
  readonly headers?: Headers
  /**
   * Where to send the browser instead of the return URL, e.g. the two-factor challenge when the
   * user has 2FA on (a provider sign-in never skips the app's own second factor). Must be a path
   * on this app.
   */
  readonly redirectTo?: string
}

/** The result of {@link SocialAccounts.link}. */
export type LinkResult = 'linked' | 'already_linked' | 'conflict'

/**
 * The questions social sign-in asks the identity system. Every method must be safe to call
 * concurrently; `createUser` and `link` must be atomic (a unique constraint, not a read-then-write).
 *
 * @example
 * app.container.value(SocialAccountsToken, memorySocialAccounts())
 */
export interface SocialAccounts {
  /** The user this provider identity is linked to, if any. */
  findByIdentity(identity: SocialIdentity): Promise<SocialUserRef | undefined>
  /** The user who owns this email (compared case-insensitively), if any. */
  findByEmail(email: string): Promise<SocialUserRef | undefined>
  /** The user signed in on this request, or `null` for guests (a pending 2FA sign-in is a guest). */
  currentUser(request: Request): Promise<CurrentUser | null>
  /**
   * Create a user whose email the provider verified, without a password. Returns `undefined` when
   * the email is taken (a concurrent sign-up won the race): the caller then refuses, it never
   * links to that account.
   */
  createUser(input: {
    readonly email: string
    readonly name: string
    readonly emailVerified: true
  }): Promise<SocialUserRef | undefined>
  /**
   * Link a provider identity to a user. `conflict` when the identity is linked to someone else;
   * `already_linked` when it is linked to this user already.
   */
  link(
    input: SocialIdentity & { readonly userId: string; readonly email: string | null },
  ): Promise<LinkResult>
  /**
   * Start a session for `userId` (the browser is redirected right after). Must issue a **new**
   * session id (never adopt one presented on the request: session fixation) and must keep the
   * app's own second factor (return `redirectTo` to its challenge).
   */
  signIn(input: {
    readonly userId: string
    readonly provider: string
    readonly request: Request
  }): Promise<SignInOutcome>
}

/**
 * The container token the provider resolves {@link SocialAccounts} from. Without a binding, every
 * callback answers `social_accounts_unavailable` (fail closed) and the boot logs a warning.
 *
 * @example
 * app.container.singleton(SocialAccountsToken, () => myAccounts)
 */
export const SocialAccountsToken: Token<SocialAccounts> = token<SocialAccounts>(
  'strutvane.social-login.accounts',
)
