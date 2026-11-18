# Release readiness

<!--
  Created once by strutvane-tooling (canonical/RELEASE-READINESS.md). This repo owns this file:
  sync never overwrites it. Gates and rules: hub docs/19-production-readiness.md
  (https://github.com/vishwajit-vm/strutvane/blob/main/docs/19-production-readiness.md).

  A version reaches npm `latest` only when every gate below is "pass" with evidence. One row per
  gate: the status (pass / fail / not checked), a link to the evidence (CI run, report or test
  file; never "trust me"), and the date it was checked (YYYY-MM-DD). The coordinator re-runs the
  checks before a gate is accepted; the project lead approves the staged release.
-->

Package: `@strutvane/social-login` · Version: `0.2.0-next.0` (branch `v2/social-login`) · Last reviewed: 2026-11-18

| Gate | What must be true (summary; docs/19 is the source) | Checked by | Status | Evidence | Date |
|---|---|---|---|---|---|
| R1 Code | Strict TS, ESM, lint clean, no `console.` in `src/`, no TODO/FIXME without an issue, TSDoc on every export | CI `verify` (`npm run ci`, `check-code-rules.mjs`) | pass (local) | `npm run ci` lint + tsc strict clean; `check-code-rules.mjs`: no console in src/, no untracked TODO; TSDoc on every export | 2026-11-18 |
| R2 Tests | Green on Node 24 and 26 × Linux, Windows, macOS; coverage ≥ 90/90/85/90; type-level tests; 3 green runs in a row; no unhandled rejections or open handles | CI `verify` matrix and `repeat` job | partial | Local Windows, Node 24.21: `npm run ci` green 3 runs in a row, 247 tests / 13 files + type tests, coverage 97.98/93.73/97.92/98.78 *(agent-reported)*. Linux/macOS and Node 26 need the CI matrix (no workflows yet: tooling sync) | 2026-11-18 |
| R3 Security | Threat model; attack-style tests; parsers fuzzed; review with 0 open critical/high; `npm audit --omit=dev` 0 high/critical; secrets scan clean | `security-reviewer` report; CI `security` job | partial | Threat model in README; attack suites `test/attacks.test.ts` (CSRF/state, code injection, replay, mix-up, open redirect, unverified-email takeover, re-auth for linking, secrets in logs, form-post limits); parsers fuzzed (`test/fuzz.test.ts`; found and fixed a sealed-null crash); `npm audit --omit=dev --audit-level=high`: 0. Needs: `security-reviewer` pass, TruffleHog in CI | 2026-11-18 |
| R4 Resilience | Failure scenarios named and tested; fails closed; idempotent retries; soak test with no growth | Resilience suites; `npm run test:soak` | partial | Failure scenarios tested (`test/handler.test.ts`: provider down, identity system throwing, no account binding, key rotation, outage with stale JWKS); fails closed everywhere. No soak test yet | 2026-11-18 |
| R5 Packaging | publint and attw clean; tarball has no tests, fixtures, secrets or local map paths; exports resolve; `engines.node` ≥ 24.3; one framework copy; LICENSE, README, CHANGELOG; a changeset | CI `package-check` job | pass (local) | `check-package.mjs` OK (32 files), publint 0.3.25 --strict "All good", attw 0.18.5 esm-only exit 0, engines >=24.3, framework peer `^0.2.0-next.0` + dev `0.2.0-next.1` (lockfile from the registry, `check-deps.mjs` OK), LICENSE/README/CHANGELOG, changeset | 2026-11-18 |
| R6 Integration | Installs alone and with every package, in any order, identically; re-install is a no-op; complete `.env.example`; boot fails closed; only the six connections; Northwind Ops green | Hub nightly ecosystem job; installer e2e | partial | Installer through the framework devkit on a skeleton-shaped project: idempotent, reversible, refuses unknown shapes (`test/installer.test.ts`); provider on the real kernel (`test/provider.test.ts`). Needs: e2e in a real skeleton app, the hub nightly job, and auth providing `SocialAccountsToken` (open decision, NEXT.md) | 2026-11-18 |
| R7 Docs | Every public feature documented with tested examples; upgrade guide; packages data, what's-new, versioning table and deprecations updated in the same change | Docs site tests | partial | README (install, use, accounts contract, config, threat model, codes, testing) with the examples exercised by tests; docs-site page not written (other repo) | 2026-11-18 |
| R8 Release | Version per ADR-0020; staged by CI with provenance, approved with 2FA (ADR-0018); right dist-tag; release notes; rollback plan; `versions.json` updated | Release workflow; owner approval | not checked | Version 0.2.0-next.0 via changeset (pre `next`); staging needs CI workflows and owner approval | 2026-11-18 |
| R9 Operations | Logs only through the framework Logger with redaction (ADR-0022); health and readiness checks; no debug tool reachable in production | Tests; `security:check` | pass (local) | Logs only through the framework `LoggerToken` (no console); never codes, tokens, state, nonces, cookies or emails (`test/attacks.test.ts` "tokens, codes and secrets") | 2026-11-18 |
