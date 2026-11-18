/**
 * `@strutvane/social-login/testing`: test without the network. A fake OpenID Connect / OAuth
 * provider (`createFakeOidcProvider`) and the in-memory account store (`memorySocialAccounts`),
 * the reference implementation of the account contract.
 *
 * @packageDocumentation
 */
export {
  createFakeOidcProvider,
  type FakeOidcProvider,
  type FakeProviderOptions,
  type FakeUser,
  type RecordedRequest,
} from './fake-provider.ts'
export {
  MEMORY_SESSION_COOKIE,
  type MemorySocialAccounts,
  type MemoryUser,
  memorySocialAccounts,
} from './memory-accounts.ts'
