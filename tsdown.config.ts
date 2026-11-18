import { defineConfig } from 'tsdown'

// Entry points: the root (drivers, the HTTP handler and the account contract), `./provider` (the
// Strutvane app integration), `./installer` (`node strut install:social-login`) and `./testing`
// (the fake OIDC provider and the in-memory account store). The framework is a peer dependency
// and stays external.
export default defineConfig({
  entry: {
    index: 'src/index.ts',
    provider: 'src/provider.ts',
    installer: 'src/installer.ts',
    testing: 'src/testing/index.ts',
  },
  format: 'esm',
  platform: 'node',
  target: 'node24',
  dts: true,
  sourcemap: true,
  clean: true,
  deps: { neverBundle: [/^@strutvane\/framework/] },
})
