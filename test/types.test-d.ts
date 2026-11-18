/** Public types: misuse must fail to compile. */
import type { Token } from '@strutvane/framework/core'
import { describe, expectTypeOf, it } from 'vitest'
import {
  type LinkResult,
  type ProviderName,
  type SocialAccounts,
  SocialAccountsToken,
  type SocialLoginConfig,
  SocialLoginError,
  type SocialLoginErrorCode,
  socialLoginUrl,
} from '../src/index.ts'

describe('public types', () => {
  it('providers are a closed set', () => {
    expectTypeOf<ProviderName>().toEqualTypeOf<'google' | 'microsoft' | 'github' | 'apple'>()
    socialLoginUrl('google')
    // @ts-expect-error: not a provider this package ships
    socialLoginUrl('facebook')
    // @ts-expect-error: intent is login or link
    socialLoginUrl('google', { intent: 'admin' })
  })

  it('the token carries the contract type', () => {
    expectTypeOf(SocialAccountsToken).toEqualTypeOf<Token<SocialAccounts>>()
    expectTypeOf<LinkResult>().toEqualTypeOf<'linked' | 'already_linked' | 'conflict'>()
  })

  it('createUser only accepts verified emails', () => {
    type Input = Parameters<SocialAccounts['createUser']>[0]
    const ok: Input = { email: 'a@b.c', name: 'A', emailVerified: true }
    // @ts-expect-error: an unverified email can never create an account
    const bad: Input = { email: 'a@b.c', name: 'A', emailVerified: false }
    expectTypeOf(ok).not.toBeAny()
    expectTypeOf(bad).not.toBeAny()
  })

  it('errors only take known codes', () => {
    new SocialLoginError('social_state_invalid', 'r')
    // @ts-expect-error: unknown code
    new SocialLoginError('state_bad', 'r')
    expectTypeOf<SocialLoginErrorCode>().toExtend<string>()
  })

  it('config keys are checked', () => {
    const config: SocialLoginConfig = {
      providers: { google: { clientId: 'x', clientSecret: 'y' } },
    }
    // @ts-expect-error: unknown provider key
    const bad: SocialLoginConfig = { providers: { facebook: {} } }
    // @ts-expect-error: registration is a boolean
    const bad2: SocialLoginConfig = { registration: 'yes' }
    expectTypeOf(config).not.toBeAny()
    expectTypeOf(bad).not.toBeAny()
    expectTypeOf(bad2).not.toBeAny()
  })
})
