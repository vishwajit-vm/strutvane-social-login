# @strutvane/social-login

**"Sign in with Google / Microsoft / GitHub / Apple" for Strutvane apps**: Laravel Socialite for TypeScript, with the security rules built in instead of left to you.

> **Status: `0.2.0-next.0`, not on npm yet.** Built and tested against `@strutvane/framework` 0.2.0-next.1. See `NEXT.md` and `RELEASE-READINESS.md`.

| | |
|---|---|
| Package | `@strutvane/social-login` |
| Part of | [Strutvane](https://github.com/vishwajit-vm/strutvane), a TypeScript framework for B2B apps in the spirit of Laravel |
| Needs | Node ≥ 24.3, `@strutvane/framework` ^0.2.0-next.0 (peer) |
| License | MIT |

## Install

```bash
node strut install:social-login --providers google,github
```

The installer (one transaction; `--dry-run --diff` previews it):

1. writes `config/social-login.ts` with the providers you chose;
2. lists it in `config/index.ts` (key `socialLogin`);
3. adds `SOCIAL_LOGIN_REGISTRATION=false` and each provider's keys to `.env` and `.env.example`, **empty**: client secrets are never generated or written to `.env.example`;
4. registers `@strutvane/social-login/provider` in `bootstrap/providers.ts`.

Running it twice changes nothing. `node strut remove social-login` reverses steps 2–4 and keeps your config file.

Then, at each provider, register the callback URL `${APP_URL}/auth/<provider>/callback`, and put the credentials in `.env`:

| Provider | `.env` keys | Where |
|---|---|---|
| Google | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Google Cloud console › APIs & Services › Credentials |
| Microsoft | `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`, `MICROSOFT_TENANT` | Microsoft Entra admin center › App registrations |
| GitHub | `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | github.com › Settings › Developer settings › OAuth Apps |
| Apple | `APPLE_CLIENT_ID` (Services ID), `APPLE_TEAM_ID`, `APPLE_KEY_ID`, `APPLE_PRIVATE_KEY` (the `.p8`, `\n` for line breaks) | Apple Developer › Certificates, Identifiers & Profiles |

A provider whose keys are still empty is skipped with a warning, so the app keeps booting while you set them up.

## Use

Two routes per provider (prefix `path`, default `/auth`):

| Route | What it does |
|---|---|
| `GET /auth/{provider}/redirect?return_to=/dashboard` | Starts a sign-in and sends the browser to the provider |
| `GET /auth/{provider}/callback` | Where the provider sends the browser back (Apple: `POST`, then a same-site `GET`) |

Buttons link to the redirect route; `socialLoginUrl` builds it:

```ts
import { socialLoginUrl } from '@strutvane/social-login'

socialLoginUrl('google', { returnTo: '/dashboard' }) // '/auth/google/redirect?return_to=%2Fdashboard'
```

After a sign-in the browser lands on `return_to` (a path on your app; anything else becomes `redirects.home`). After a failure it lands on `redirects.failure` (default `/login`) with `?error=<code>&provider=<name>`. Show the message for that code from your catalog; the codes are listed below.

### Connecting a provider to an existing account

Signing in never links a provider to an existing account by itself. A signed-in user connects one from their settings page, right after signing in or confirming their password:

```ts
socialLoginUrl('github', { intent: 'link', returnTo: '/settings/accounts' })
```

## Connecting your users

Social sign-in proves *who someone is at Google*. Which user of your app that is, and starting the session, belong to your identity system. This package asks it a few narrow questions through one contract, `SocialAccounts`, resolved from `SocialAccountsToken`:

```ts
// app/providers/app.provider.ts
import { SocialAccountsToken } from '@strutvane/social-login'

export class AppServiceProvider extends ServiceProvider {
  override register(app: Application): void {
    app.container.singleton(SocialAccountsToken, () => mySocialAccounts(app))
  }
}
```

| Method | Answers |
|---|---|
| `findByIdentity({ provider, subject })` | the user this provider identity is linked to |
| `findByEmail(email)` | the user who owns this email (case-insensitive) |
| `currentUser(request)` | the signed-in user and when they last authenticated |
| `createUser({ email, name, emailVerified: true })` | a new passwordless user (`undefined` if the email was taken meanwhile) |
| `link({ provider, subject, userId, email })` | `linked`, `already_linked` or `conflict` |
| `signIn({ userId, provider, request })` | session headers, or `redirectTo` (e.g. the two-factor challenge) |

`createUser` and `link` must be atomic (unique constraints), and `signIn` must issue a **new** session id and keep your second factor. Until `@strutvane/auth` provides this contract itself (planned), you write this small adapter over your identity tables; `memorySocialAccounts()` from `@strutvane/social-login/testing` is the reference implementation. Without a binding, every sign-in fails closed with `social_accounts_unavailable` and the boot warns.

## Configuration

```ts
// config/social-login.ts
import { defineConfig } from '@strutvane/framework'

export default defineConfig((env) => ({
  registration: env.boolean('SOCIAL_LOGIN_REGISTRATION', false),
  reauthMinutes: 10,
  redirects: { home: '/', failure: '/login' },
  providers: {
    google: {
      clientId: env.optional('GOOGLE_CLIENT_ID'),
      clientSecret: env.optional('GOOGLE_CLIENT_SECRET'),
      allowedDomains: ['example.com'], // Google Workspace domains (the hd claim); [] = any
    },
    microsoft: {
      clientId: env.optional('MICROSOFT_CLIENT_ID'),
      clientSecret: env.optional('MICROSOFT_CLIENT_SECRET'),
      tenant: env.string('MICROSOFT_TENANT', 'organizations'),
      allowedTenants: [], // tenant ids; [] = any
    },
  },
}))
```

| Setting | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Serve the routes at all |
| `path` | `/auth` | Route prefix |
| `registration` | `false` | Create an account on a first sign-in with a **verified** email (off: invite-only, like `@strutvane/auth`) |
| `reauthMinutes` | `10` (1–60) | How recent a sign-in must be to connect a provider |
| `redirects.home` / `.failure` | `/` / `/login` | Landing pages; must be paths on this app |
| `providers.<name>.scopes` | provider defaults | Extra scopes; the defaults are always requested |
| `providers.<name>.endpoints` | the provider's | Overrides (`https` only), e.g. a sovereign cloud or a test provider |

Every setting is checked at boot. A wrong one (an unknown Microsoft tenant, a redirect to another site, an `http` `APP_URL` outside localhost) stops the boot with a message naming it.

## Security model

| Threat | Defence |
|---|---|
| Login CSRF, forged callbacks | `state` (256 bits) in a sealed, `HttpOnly`, `__Host-` cookie per provider; it must match, and is single use (claimed in the framework cache) |
| Authorization code injection | PKCE `S256` on every provider that supports it; the ID token `nonce` (and for Apple, the nonce alone) binds the code to this browser's sign-in |
| ID token forgery or misuse | Signature from the provider's JWKS (cached by `max-age`, 5 min–24 h; unknown `kid` refetches at most once a minute); `RS256`/`ES256` only (never `none`/`HS*`), no header-supplied keys; exact `iss`, `aud` contains the client id, `azp`, `exp`/`iat`/`nbf` with 60 s skew, `iat` at most 10 min old, `nonce` |
| Replay | `state` and Apple hand-overs are single use; codes are single use at the provider; flows live 10 minutes |
| Mix-up | A callback path per provider; the flow cookie is sealed for one provider; RFC 9207 `iss` is checked when sent; per-provider issuer checks |
| Microsoft multi-tenant | `iss` must be the issuer of the token's **own** `tid`; `organizations` refuses personal accounts; `allowedTenants`; identity is `tid/oid` |
| Account takeover by email | Never auto-link. An unverified email stops before any lookup (no enumeration). A verified email that already has an account is refused (`social_account_exists`): its owner signs in and connects the provider. Microsoft emails count as verified only with `xms_edov`; GitHub only the primary **verified** address from `/user/emails`; Google `email_verified` |
| Linking a hijacked session | Linking needs the same signed-in user at start and callback, authenticated within `reauthMinutes` |
| Open redirect | `return_to` and the identity system's `redirectTo` must resolve to a path on the app (the framework's `safeRedirectTarget`), else home; failures carry only a known code |
| Secrets in logs | Logs (framework logger only) carry the provider, the outcome code, a reason naming the failed check and the user id: never codes, tokens, `state`, nonces, cookies or emails. Responses are `no-store` and `no-referrer` |
| Hostile responses | Outbound calls: 10 s timeout, no redirects, 256 KiB cap; Apple's form post: urlencoded only, 64 KiB cap |

Provider notes, and why:

- **Apple** posts the callback cross-site, which only carries a `SameSite=None; Secure` cookie, so it needs an `https` `APP_URL`. The session cookie (Lax) is not sent on that post, so the verified result is handed to a same-site `GET` in a 2-minute sealed cookie. The client secret is an `ES256` JWT signed per exchange (5 minutes). The name in Apple's `user` field is unsigned: display only.
- **GitHub** has no ID token. Identity is the numeric `id`, never the changeable `login`.
- Endpoints are the providers' published ones as of 2026-11-18 (Google: `accounts.google.com`, Microsoft: `login.microsoftonline.com/{tenant}/v2.0`, GitHub: `github.com/login/oauth`, Apple: `appleid.apple.com`). Whether Apple's token endpoint accepts PKCE is *(unverified)*, so Apple relies on the nonce.

## Error codes

| Code | Status | When |
|---|---|---|
| `social_state_invalid` | 400 | No or expired flow, `state` mismatch, reused `state`, repeated parameters |
| `social_issuer_mismatch` | 400 | The callback's `iss` is not this provider |
| `social_provider_error` | 400 | The provider returned an error (the user cancelled), or no code |
| `social_provider_unavailable` | 503 | The provider could not be reached |
| `social_token_invalid` | 401 | The code was refused or the ID token failed a check |
| `social_email_unverified` | 403 | No verified email to create an account with |
| `social_domain_not_allowed` / `social_tenant_not_allowed` | 403 | `allowedDomains` / `allowedTenants` |
| `social_account_exists` | 409 | An account has this email: sign in, then connect |
| `social_identity_in_use` | 409 | This provider account is connected to another user |
| `social_reauth_required` | 401 | Connecting needs a fresh sign-in by the same user |
| `social_registration_closed` | 403 | New accounts are off |
| `social_accounts_unavailable` | 503 | Nothing bound to `SocialAccountsToken` |
| `social_provider_unknown` | 404 | The provider is not enabled |
| `internal_error` | 500 | The identity system failed (logged as an error) |

## Testing your app

Everything runs offline against a fake provider:

```ts
import { createSocialLoginProvider } from '@strutvane/social-login/provider'
import { createFakeOidcProvider, memorySocialAccounts } from '@strutvane/social-login/testing'

const idp = createFakeOidcProvider({ clientId: 'test-client', clientSecret: 'test-secret' })
// config: providers.google = { clientId: 'test-client', clientSecret: 'test-secret', endpoints: idp.endpoints }
const provider = createSocialLoginProvider({ fetch: idp.fetch })
// after GET /auth/google/redirect answered with a Location:
const callbackUrl = idp.consent(location, { sub: 'u1', email: 'ada@example.com', emailVerified: true })
```

The fake enforces single-use codes, `redirect_uri` and PKCE, signs ID tokens with a key from its JWKS, and serves a GitHub-style `/user` and `/user/emails`.

## Entry points

| Import | What |
|---|---|
| `@strutvane/social-login` | `SocialAccountsToken` and the contract, `socialLoginUrl`, the Web handler, config, drivers, errors |
| `@strutvane/social-login/provider` | The provider for `bootstrap/providers.ts` |
| `@strutvane/social-login/installer` | `node strut install:social-login` |
| `@strutvane/social-login/testing` | `createFakeOidcProvider`, `memorySocialAccounts` |

## How it connects (integration map)

An add-on: it depends only on `@strutvane/framework` (peer) and never imports another add-on. It uses the `http.onRequest` hook (handler `socialLogin.routes`, after `auth.identity`) and container tokens (`SocialAccountsToken`, `EncrypterToken`, `CacheManagerToken`, `LoggerToken`, `ErrorRegistryToken`), and installs itself through `strutvane.installer`.
