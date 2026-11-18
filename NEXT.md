# NEXT: social-login v2 (`v2/social-login`), 2026-11-18

Branch `v2/social-login`, from the placeholder `main` (75e7744). Not pushed by this agent (the
coordinator pushed a WIP safety commit, 61110a5). Version `0.2.0-next.0` (pre `next`).

## Done
- Scaffold: canonical files copied from strutvane-tooling (no `.github/` yet: tooling sync).
- Code: OAuth 2.1/OIDC flow (PKCE S256, state, nonce, sealed per-provider `__Host-` cookie,
  single-use state via the framework cache), ID token validation with a JWKS cache, drivers for
  Google, Microsoft (tenant rules, `xms_edov`), GitHub (`/user/emails`), Apple (form post +
  same-site hand-over, ES256 client secret); account rules (never auto-link, verified emails only,
  re-auth to link); provider (`http.onRequest`), installer, `./testing` (fake provider, memory
  accounts).
- Tests: flows, attack suites, units, fuzz (found and fixed: a sealed `null` crashed `openFlow`),
  kernel integration, installer via the devkit, type tests.
- Docs: README (Socialite-style + threat model), CLAUDE.md, CHANGELOG (changeset), this file,
  RELEASE-READINESS rows.

## How it was verified
- Dev-depends on the published `@strutvane/framework` 0.2.0-next.1; lockfile refreshed from the
  registry; `npm ci` clean; `check-deps.mjs` OK.
- `npm run ci` 3x in a row green (Windows, Node 24.21): 247 tests / 13 files, coverage
  97.98/93.73/97.92/98.78 *(agent-reported)*.
- `check-package.mjs` (32 files), publint 0.3.25 --strict, attw 0.18.5 esm-only,
  `npm audit --omit=dev --audit-level=high` (0), `check-code-rules.mjs`.

## Open decisions (project lead)
1. **Where the account contract lives.** `SocialAccounts` + `SocialAccountsToken` are defined in
   this package, so today the *app* binds them. For `@strutvane/auth` to provide them (the normal
   setup) without importing an add-on, the contract and token should move to
   `@strutvane/framework/contracts` + framework tokens (needs an RFC and an integration-map row).
   Auth v2 also needs: an identities table (provider, subject, user), a passwordless user create,
   and a session start for a verified external identity (method `social`, keeping 2FA).
2. **Installer `enhances`.** With auth present, should the installer write glue
   (`app/providers/social-accounts.ts`) over auth's engine? Blocked on (1).
3. **Domain events** (`auth.social.linked`, `…signed_in`) for audit: not emitted yet; need
   integration-map §5 rows.
4. **Unlinking** (`DELETE /auth/{provider}`): not built; needs the contract to grow `unlink`.
5. **Apple PKCE** is *(unverified)*: Apple's docs list no `code_verifier`; the nonce binds the code.
6. **Shared patch helpers:** `src/install/patch.ts` duplicates log-viewer's; move to the devkit.
7. The catalogue entry says `frameworkRange: ^1.0`; this package declares `compat ^0.2.0-next.0`.

## Next
1. Tooling: add the repo to the strutvane-tooling sync manifest (workflows, scripts).
2. R3: `security-reviewer` pass on this package; R6: installer e2e in a skeleton app.
3. Decisions above.
