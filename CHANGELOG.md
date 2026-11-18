# @strutvane/social-login

## 0.2.0-next.0

### Minor Changes

- **First release: "Sign in with Google / Microsoft / GitHub / Apple" for Strutvane apps (Laravel Socialite for TypeScript), on `@strutvane/framework` 0.2.**
  
  - **Flow:** OAuth 2.1 / OpenID Connect authorization code with PKCE `S256`, `state` and `nonce` in a sealed, per-provider `__Host-` cookie; `state` is single use (framework cache); routes `GET /auth/{provider}/redirect` and `/callback` served through `http.onRequest` (`socialLogin.routes`, after `auth.identity`).
  - **ID tokens:** signature from the provider's cached JWKS (`RS256`/`ES256` only, no header keys, rotation-aware), exact issuer, audience/`azp`, `exp`/`iat`/`nbf` with skew, nonce.
  - **Providers:** Google (`email_verified`, Workspace `hd` allow-list), Microsoft (per-tenant issuer, `organizations`/`consumers`/`common`/tenant id, `allowedTenants`, `tid/oid` identity, emails verified only with `xms_edov`), GitHub (numeric id, primary verified email from `/user/emails`), Apple (form post with a same-site hand-over, `ES256` client-secret JWT, nonce-bound code).
  - **Accounts:** the `SocialAccounts` contract (`SocialAccountsToken`); never auto-links; verified emails only; an existing email is refused with `social_account_exists`; linking (`intent=link`) needs the same user, re-authenticated within `reauthMinutes`; registration off by default.
  - **Errors:** `social_*` codes (RFC-0003), failures redirect to `redirects.failure?error=<code>`; nothing secret is logged.
  - **Installer** (`node strut install:social-login --providers google,github`): `config/social-login.ts`, `config/index.ts` key `socialLogin`, empty `.env`/`.env.example` keys, `bootstrap/providers.ts`; idempotent and reversible.
  - **Testing:** `@strutvane/social-login/testing` with a fake OIDC/OAuth provider and an in-memory account store.
