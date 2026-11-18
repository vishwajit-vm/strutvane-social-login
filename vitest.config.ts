import { defineConfig, mergeConfig } from 'vitest/config'
import { sharedConfig } from './vitest.shared.ts'

// Repo-specific overrides; shared defaults come from strutvane-tooling. Every test runs offline:
// providers are the in-process fake OIDC provider from `src/testing`, never the real network.
export default mergeConfig(
  sharedConfig,
  defineConfig({
    test: {
      testTimeout: 30_000,
      hookTimeout: 30_000,
    },
  }),
)
