/**
 * `@strutvane/social-login`: "Sign in with Google / Microsoft / GitHub / Apple" for Strutvane apps
 * (Laravel Socialite for TypeScript).
 *
 * OAuth 2.1 / OpenID Connect authorization code flow with PKCE, `state` and `nonce`; ID tokens
 * validated in full (signature from the provider's cached JWKS, issuer, audience, expiry, nonce);
 * Apple's form post and client-secret JWT; Microsoft's multi-tenant issuer rules; GitHub's
 * verified-email rules; and account linking that never links automatically.
 *
 * Entry points:
 * - this root: the account contract (`SocialAccountsToken`), the Web handler, config, drivers,
 *   errors and `socialLoginUrl` for building sign-in links;
 * - `@strutvane/social-login/provider`: the provider for `bootstrap/providers.ts`;
 * - `@strutvane/social-login/installer`: `node strut install:social-login`;
 * - `@strutvane/social-login/testing`: a fake provider and an in-memory account store.
 *
 * @packageDocumentation
 */

export { type ResolveInput, type ResolveOutcome, resolveAccount } from './accounts/resolve.ts'
export {
  type CurrentUser,
  type LinkResult,
  type SignInOutcome,
  type SocialAccounts,
  SocialAccountsToken,
  type SocialIdentity,
  type SocialUserRef,
} from './accounts.ts'
export {
  type AppleConfig,
  defaultEndpoints,
  type EndpointOverrides,
  type GitHubConfig,
  type GoogleConfig,
  MICROSOFT_CONSUMERS_TENANT,
  type MicrosoftConfig,
  type ResolvedConfig,
  type ResolvedEndpoints,
  type ResolvedProvider,
  resolveConfig,
  type SocialLoginConfig,
  SocialLoginConfigError,
} from './config.ts'
export { createPkce, type Pkce } from './crypto/pkce.ts'
export {
  type EncrypterLike,
  encrypterSealer,
  keySealer,
  parseAppKey,
  type Sealer,
} from './crypto/sealer.ts'
export {
  isSocialLoginErrorCode,
  SOCIAL_LOGIN_ERRORS,
  SocialLoginError,
  type SocialLoginErrorCode,
} from './errors.ts'
export {
  cacheReplayGuard,
  memoryReplayGuard,
  type ReplayCacheStore,
  type ReplayGuard,
} from './flow/replay.ts'
export { FLOW_TTL_MS, type Intent } from './flow/state.ts'
export {
  createSocialLoginHandler,
  type SocialLogger,
  type SocialLoginHandler,
  type SocialLoginHandlerOptions,
} from './handler.ts'
export {
  createHttpClient,
  type FetchLike,
  type HttpClient,
  type HttpClientOptions,
} from './http/client.ts'
export { type IdTokenClaims, type IdTokenExpectations, verifyIdToken } from './oidc/id-token.ts'
export { createJwksCache, type JwksCache, type JwksCacheOptions } from './oidc/jwks.ts'
export { createDriver, createDrivers } from './providers/registry.ts'
export {
  type AuthorizationParams,
  type CompletionInput,
  type DriverContext,
  PROVIDER_NAMES,
  type ProviderDriver,
  type ProviderName,
  type SocialProfile,
} from './providers/types.ts'
export { type SocialLoginUrlOptions, socialLoginUrl } from './url.ts'
