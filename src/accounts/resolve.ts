/**
 * Which app user a verified provider profile is, and what happens next. This is where account
 * takeover is prevented, so the rules are few and strict:
 *
 * **Sign in** (`intent: 'login'`):
 * 1. A provider identity that is already linked signs in its user. Nothing else is consulted (an
 *    email change at the provider doesn't move the identity to another account).
 * 2. Otherwise, an email the provider has **not verified** stops here (`social_email_unverified`),
 *    before any lookup by email: an unverified address proves nothing, and looking it up would let
 *    anyone probe which emails have accounts.
 * 3. A verified email that belongs to an existing account is **never linked automatically**
 *    (`social_account_exists`). The owner must sign in to that account first (password, passkey,
 *    email link) and then connect the provider. Auto-linking would hand the account to whoever
 *    controls the email at *any* provider, which is the classic pre-account-takeover.
 * 4. A new verified email creates an account only when `registration` is on
 *    (`social_registration_closed` otherwise), then links the identity and signs in.
 *
 * **Connect** (`intent: 'link'`):
 * 1. The request must be signed in as the **same** user who started the flow, and that user must
 *    have authenticated within `reauthMinutes` (`social_reauth_required`). Starting the flow from
 *    an old, possibly hijacked session is not enough.
 * 2. An identity linked to someone else is refused (`social_identity_in_use`); one already linked
 *    to this user is a no-op.
 *
 * Emails don't need to match when connecting: the user proves both sides themselves.
 *
 * @module
 */
import type { SignInOutcome, SocialAccounts } from '../accounts.ts'
import { SocialLoginError } from '../errors.ts'
import type { Intent } from '../flow/state.ts'
import type { SocialProfile } from '../providers/types.ts'

/** What {@link resolveAccount} needs. */
export interface ResolveInput {
  readonly profile: SocialProfile
  readonly intent: Intent
  /** The user who started a link flow (from the flow cookie). */
  readonly flowUserId: string | null
  readonly request: Request
  readonly accounts: SocialAccounts
  readonly registration: boolean
  /** How recent the user's last authentication must be to link, in ms. */
  readonly reauthMs: number
  /** Milliseconds since the epoch. */
  readonly now: number
}

/** What happened. */
export type ResolveOutcome =
  | {
      readonly kind: 'signed_in'
      readonly userId: string
      /** `true` when the account was created by this sign-in. */
      readonly created: boolean
      readonly session: SignInOutcome
    }
  | { readonly kind: 'linked'; readonly userId: string; readonly alreadyLinked: boolean }

/**
 * Apply the rules above.
 *
 * @example
 * const outcome = await resolveAccount({ profile, intent: 'login', flowUserId: null, request, accounts, registration: false, reauthMs: 600_000, now: Date.now() })
 */
export async function resolveAccount(input: ResolveInput): Promise<ResolveOutcome> {
  const { profile, accounts } = input
  const identity = { provider: profile.provider, subject: profile.subject }

  if (input.intent === 'link') {
    const current = await accounts.currentUser(input.request)
    if (current === null || input.flowUserId === null || current.id !== input.flowUserId)
      throw new SocialLoginError(
        'social_reauth_required',
        'link: not signed in as the user who started it',
      )
    if (!(input.now - current.authenticatedAt <= input.reauthMs))
      throw new SocialLoginError('social_reauth_required', 'link: last authentication too old')
    const owner = await accounts.findByIdentity(identity)
    if (owner !== undefined && owner.id !== current.id)
      throw new SocialLoginError('social_identity_in_use', 'link: identity belongs to another user')
    if (owner !== undefined) return { kind: 'linked', userId: current.id, alreadyLinked: true }
    const result = await accounts.link({ ...identity, userId: current.id, email: profile.email })
    if (result === 'conflict')
      throw new SocialLoginError('social_identity_in_use', 'link: identity linked concurrently')
    return { kind: 'linked', userId: current.id, alreadyLinked: result === 'already_linked' }
  }

  const linked = await accounts.findByIdentity(identity)
  if (linked !== undefined) {
    const session = await accounts.signIn({
      userId: linked.id,
      provider: profile.provider,
      request: input.request,
    })
    return { kind: 'signed_in', userId: linked.id, created: false, session }
  }

  if (profile.email === null || !profile.emailVerified)
    throw new SocialLoginError('social_email_unverified', 'login: no verified email to sign up')
  if ((await accounts.findByEmail(profile.email)) !== undefined)
    throw new SocialLoginError(
      'social_account_exists',
      'login: email belongs to an existing account',
    )
  if (!input.registration)
    throw new SocialLoginError('social_registration_closed', 'login: registration is off')

  const created = await accounts.createUser({
    email: profile.email,
    name: profile.name ?? profile.email.split('@')[0] ?? profile.email,
    emailVerified: true,
  })
  if (created === undefined)
    throw new SocialLoginError('social_account_exists', 'login: email taken concurrently')
  const result = await accounts.link({ ...identity, userId: created.id, email: profile.email })
  if (result === 'conflict')
    throw new SocialLoginError('social_identity_in_use', 'login: identity linked concurrently')
  const session = await accounts.signIn({
    userId: created.id,
    provider: profile.provider,
    request: input.request,
  })
  return { kind: 'signed_in', userId: created.id, created: true, session }
}
