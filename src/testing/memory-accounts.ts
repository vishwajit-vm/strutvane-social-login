/**
 * An in-memory {@link SocialAccounts}: the reference implementation of the account contract, for
 * tests and for trying the package before it is wired to a real identity system.
 *
 * Sessions are a random cookie (`sv_test_session`) mapped to a user and the time they
 * authenticated; {@link MemorySocialAccounts.signInAs} plays a password sign-in, so tests can
 * exercise "link after re-authentication".
 *
 * @module
 */
import { randomBytes } from 'node:crypto'
import type {
  CurrentUser,
  LinkResult,
  SignInOutcome,
  SocialAccounts,
  SocialIdentity,
  SocialUserRef,
} from '../accounts.ts'
import { readCookie } from '../http/cookies.ts'

/** A user in the memory store. */
export interface MemoryUser {
  readonly id: string
  readonly email: string
  readonly name: string
  readonly emailVerified: boolean
  /** Has two-factor on: social sign-in then redirects to the challenge instead of signing in. */
  readonly twoFactor?: boolean
}

/** The memory store, with test helpers. */
export interface MemorySocialAccounts extends SocialAccounts {
  /** Every user. */
  readonly users: ReadonlyMap<string, MemoryUser>
  /** Every link, `provider:subject` → user id. */
  readonly links: ReadonlyMap<string, string>
  /** Sessions issued by `signIn`/`signInAs`, cookie value → session. */
  readonly sessions: ReadonlyMap<
    string,
    { readonly userId: string; readonly authenticatedAt: number }
  >
  /** Add a user (as if they signed up with a password). */
  addUser(user: MemoryUser): MemoryUser
  /** Start a session as if the user signed in with a password at `at`; returns the `Cookie` header. */
  signInAs(userId: string, at?: number): string
}

/** The session cookie name the memory store uses. */
export const MEMORY_SESSION_COOKIE = 'sv_test_session'

/**
 * Create an in-memory account store.
 *
 * @example
 * const accounts = memorySocialAccounts({ now: clock.now })
 * accounts.addUser({ id: 'u1', email: 'ada@example.com', name: 'Ada', emailVerified: true })
 */
export function memorySocialAccounts(
  options: { readonly now?: () => number } = {},
): MemorySocialAccounts {
  const now = options.now ?? Date.now
  const users = new Map<string, MemoryUser>()
  const links = new Map<string, string>()
  const sessions = new Map<string, { userId: string; authenticatedAt: number }>()
  let seq = 0
  const key = (i: SocialIdentity) => `${i.provider}:${i.subject}`
  const byEmail = (email: string) =>
    [...users.values()].find((u) => u.email.toLowerCase() === email.toLowerCase())

  const startSession = (userId: string, at: number): string => {
    const id = randomBytes(18).toString('base64url')
    sessions.set(id, { userId, authenticatedAt: at })
    return id
  }

  return {
    users,
    links,
    sessions,
    addUser(user) {
      users.set(user.id, user)
      return user
    },
    signInAs(userId, at = now()) {
      return `${MEMORY_SESSION_COOKIE}=${startSession(userId, at)}`
    },
    async findByIdentity(identity): Promise<SocialUserRef | undefined> {
      const id = links.get(key(identity))
      return id === undefined ? undefined : { id }
    },
    async findByEmail(email) {
      const user = byEmail(email)
      return user === undefined ? undefined : { id: user.id }
    },
    async currentUser(request): Promise<CurrentUser | null> {
      const sid = readCookie(request.headers.get('cookie'), MEMORY_SESSION_COOKIE)
      const session = sid === undefined ? undefined : sessions.get(sid)
      return session === undefined
        ? null
        : { id: session.userId, authenticatedAt: session.authenticatedAt }
    },
    async createUser(input) {
      if (byEmail(input.email) !== undefined) return undefined
      const user: MemoryUser = {
        id: `user-${++seq}`,
        email: input.email,
        name: input.name,
        emailVerified: input.emailVerified,
      }
      users.set(user.id, user)
      return { id: user.id }
    },
    async link(input): Promise<LinkResult> {
      const k = key(input)
      const owner = links.get(k)
      if (owner === input.userId) return 'already_linked'
      if (owner !== undefined) return 'conflict'
      links.set(k, input.userId)
      return 'linked'
    },
    async signIn(input): Promise<SignInOutcome> {
      if (users.get(input.userId)?.twoFactor === true)
        return { redirectTo: '/two-factor-challenge' }
      const headers = new Headers()
      headers.append(
        'set-cookie',
        `${MEMORY_SESSION_COOKIE}=${startSession(input.userId, now())}; Path=/; HttpOnly; SameSite=Lax`,
      )
      return { headers }
    },
  }
}
