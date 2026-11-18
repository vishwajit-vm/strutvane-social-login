# CLAUDE.md: Strutvane Social Login (`@strutvane/social-login`)

Project memory for Claude Code in this repository. Keep it short, accurate and current.

## Ecosystem memory (shared by every Strutvane repo)

@.claude/ECOSYSTEM.md

## What this repo is

"Sign in with Google / Microsoft / GitHub / Apple" for Strutvane apps (Laravel Socialite). An **add-on**: depends only on `@strutvane/framework` (peer + dev, `^0.2.0-next.0`) through its public subpaths, never on `@strutvane/auth` or any other add-on. The identity side is reached only through the `SocialAccounts` contract (`SocialAccountsToken`).

## Status

- Branch `v2/social-login`, version `0.2.0-next.0` (Changesets pre mode `next`), not on npm. See `NEXT.md` and `RELEASE-READINESS.md`.
- Dev-depends on the published `@strutvane/framework` 0.2.0-next.1 (lockfile from the registry; `npm ci` works). Never commit `file:`/`link:` specs.
- `.github/workflows` are not here yet: they come from the strutvane-tooling sync.

## Code map

| Path | What |
|---|---|
| `src/handler.ts` | The Web handler: routes, flow cookie, callback checks in order, failure redirects |
| `src/accounts.ts`, `src/accounts/resolve.ts` | The account contract + token; the linking rules (never auto-link) |
| `src/config.ts` | `config/social-login.ts` types and boot-time validation |
| `src/providers/*` | One driver per provider (`google`, `microsoft`, `github`, `apple`), shared `oauth.ts` and `profile.ts` |
| `src/oidc/` | JWKS cache and ID token validation |
| `src/crypto/` | base64url/random/compare, PKCE, sealer (AES-GCM or framework `Encrypter`), minimal JWS |
| `src/flow/` | Flow and hand-over cookies; single-use (`ReplayGuard`) |
| `src/http/` | Outbound client (timeout, no redirects, size cap); cookies |
| `src/provider.ts` | Framework provider: `http.onRequest` (`socialLogin.routes`), tokens, config key `socialLogin` |
| `src/installer.ts`, `src/install/patch.ts` | `node strut install:social-login` |
| `src/testing/` | Fake OIDC/OAuth provider, in-memory accounts (published as `./testing`) |
| `test/` | Flows, attack suites (`attacks.test.ts`), units, fuzz, kernel integration, installer, type tests |

## Commands

- `npm run ci`: Biome → tsc → Vitest with coverage (90/90/85/90) → tsdown.
- R5: `npm pack`, then `npm exec --package=publint@0.3.25 -- publint run <tgz> --strict` and `npm exec --package=@arethetypeswrong/cli@0.18.5 -- attw <tgz> --profile esm-only`.
- Code rules: `node ../tooling/canonical/.github/scripts/check-code-rules.mjs`.

## Gotchas

- Tests never touch the network: drivers get `fetch` from the fake provider; a test that reaches a real URL fails.
- Never log codes, tokens, `state`, nonces, cookies or emails; `test/attacks.test.ts` checks it. Error `reason`s name the failed check only.
- Apple needs an https `APP_URL` (cross-site form post needs `SameSite=None; Secure`).
- Microsoft emails are unverified unless `xms_edov`; never relax that.

## Boundaries (non-negotiable)

- Connections used: hooks (`http.onRequest`), container tokens (`SocialAccountsToken`, `EncrypterToken`, `CacheManagerToken`, `LoggerToken`, `ErrorRegistryToken`, `HooksToken`), installer, HTTP.
- `SocialAccountsToken` is defined here for now; moving the contract into the framework so auth can provide it is an open decision (NEXT.md). Until then, auth must not import this package.
