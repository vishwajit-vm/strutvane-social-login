/**
 * The installer through the framework's own devkit runtime, on a temp project shaped like the
 * skeleton: one transaction, idempotent, reversible, never guessing at an unknown file, never
 * writing a secret.
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { checkIdempotent, runInstaller } from '@strutvane/framework/devkit'
import fc from 'fast-check'
import { afterEach, describe, expect, it } from 'vitest'
import {
  addConfigKey,
  addProvider,
  CONFIG_LOCAL,
  PROVIDER_LOCAL,
  PROVIDER_SPECIFIER,
  removeConfigKey,
  removeProvider,
} from '../src/install/patch.ts'
import {
  chosenProviders,
  configTemplate,
  ENV_KEYS,
  INSTALL_PATHS,
  installer,
} from '../src/installer.ts'

const PROVIDERS = `// The service providers that run at boot, in order.
import type { AnyProvider } from '@strutvane/framework'
import { AppServiceProvider } from '../app/providers/app.provider.ts'

const providers: readonly AnyProvider[] = [AppServiceProvider]

export default providers
`

const CONFIG_INDEX = `// Every defineConfig file, keyed by file name.
import type { ConfigFiles } from '@strutvane/framework'
import app from './app.ts'
import logging from './logging.ts'

export default { app, logging } satisfies ConfigFiles
`

const dirs: string[] = []
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true })
})

function project(files: Record<string, string | undefined> = {}): string {
  const dir = mkdtempSync(join(tmpdir(), 'sv-social-app-'))
  dirs.push(dir)
  const all: Record<string, string | undefined> = {
    'bootstrap/providers.ts': PROVIDERS,
    'config/index.ts': CONFIG_INDEX,
    '.env': 'APP_ENV=local\n',
    '.env.example': 'APP_ENV=\n',
    'package.json': '{ "name": "app", "private": true }\n',
    ...files,
  }
  for (const [path, content] of Object.entries(all)) {
    if (content === undefined) continue
    mkdirSync(join(dir, path, '..'), { recursive: true })
    writeFileSync(join(dir, path), content)
  }
  return dir
}

const read = (root: string, path: string): string => readFileSync(join(root, path), 'utf8')

describe('install', () => {
  it('writes config, lists it, adds empty env keys and registers the provider', async () => {
    const root = project()
    const result = await runInstaller(installer, {
      projectRoot: root,
      answers: { providers: 'google,github' },
    })
    expect(result.committed).toBe(true)
    const config = read(root, INSTALL_PATHS.config)
    expect(config).toContain("clientId: env.optional('GOOGLE_CLIENT_ID')")
    expect(config).toContain("env.optional('GITHUB_CLIENT_SECRET')")
    expect(config).not.toContain('APPLE')
    expect(read(root, 'config/index.ts')).toContain(
      `import ${CONFIG_LOCAL} from './social-login.ts'`,
    )
    expect(read(root, 'bootstrap/providers.ts')).toContain(
      `[AppServiceProvider, ${PROVIDER_LOCAL}]`,
    )
    const env = read(root, '.env')
    const example = read(root, '.env.example')
    for (const key of [
      'SOCIAL_LOGIN_REGISTRATION',
      'GOOGLE_CLIENT_ID',
      'GOOGLE_CLIENT_SECRET',
      'GITHUB_CLIENT_ID',
    ]) {
      expect(env).toContain(key)
      expect(example).toContain(key)
    }
    expect(env).toMatch(/^GOOGLE_CLIENT_SECRET=$/m)
    expect(example).toMatch(/^GOOGLE_CLIENT_SECRET=$/m)
    expect(env).not.toContain('MICROSOFT')
    expect(
      result.messages.some((m) => m.message.includes(`${'$'}{APP_URL}/auth/github/callback`)),
    ).toBe(true)
    expect(result.messages.some((m) => m.message.includes('SocialAccountsToken'))).toBe(true)
  })

  it('defaults to google; microsoft gets a tenant default; apple gets its four keys', async () => {
    const root = project()
    await runInstaller(installer, { projectRoot: root })
    expect(read(root, '.env')).toContain('GOOGLE_CLIENT_ID')
    const all = project()
    await runInstaller(installer, {
      projectRoot: all,
      answers: { providers: ['microsoft', 'apple'] },
    })
    const env = read(all, '.env')
    expect(env).toMatch(/^MICROSOFT_TENANT=organizations$/m)
    for (const key of ['APPLE_CLIENT_ID', 'APPLE_TEAM_ID', 'APPLE_KEY_ID', 'APPLE_PRIVATE_KEY'])
      expect(env).toContain(key)
  })

  it('is idempotent', async () => {
    const root = project()
    expect(
      await checkIdempotent(installer, {
        projectRoot: root,
        answers: { providers: 'google,apple' },
      }),
    ).toEqual([])
  })

  it('keeps an existing config file', async () => {
    const root = project({ 'config/social-login.ts': '// mine\n' })
    await runInstaller(installer, { projectRoot: root })
    expect(read(root, INSTALL_PATHS.config)).toBe('// mine\n')
  })

  it('a dry run writes nothing', async () => {
    const root = project()
    const result = await runInstaller(installer, { projectRoot: root, dryRun: true })
    expect(result.changes.length).toBeGreaterThan(0)
    expect(read(root, 'bootstrap/providers.ts')).toBe(PROVIDERS)
  })

  it('never guesses at files it does not recognise; prints the manual step', async () => {
    const root = project({
      'bootstrap/providers.ts': 'export default makeProviders()\n',
      'config/index.ts': 'module.exports = {}\n',
    })
    const result = await runInstaller(installer, { projectRoot: root })
    expect(read(root, 'bootstrap/providers.ts')).toBe('export default makeProviders()\n')
    expect(result.messages.filter((m) => m.level === 'warn')).toHaveLength(2)
  })

  it('missing files: warns; an older app with strutvane.config.ts goes through the devkit patcher', async () => {
    const bare = project({ 'bootstrap/providers.ts': undefined, 'config/index.ts': undefined })
    const result = await runInstaller(installer, { projectRoot: bare })
    expect(result.messages.filter((m) => m.level === 'warn')).toHaveLength(2)
    const legacy = project({
      'bootstrap/providers.ts': undefined,
      'strutvane.config.ts':
        "import { defineConfig } from '@strutvane/framework'\nexport default defineConfig({ providers: [] })\n",
    })
    await runInstaller(installer, { projectRoot: legacy })
    expect(read(legacy, 'strutvane.config.ts')).toContain(PROVIDER_SPECIFIER)
    await runInstaller(installer, { projectRoot: legacy, mode: 'uninstall' })
    expect(read(legacy, 'strutvane.config.ts')).not.toContain(PROVIDER_SPECIFIER)
  })

  it('refuses unknown provider answers', async () => {
    const root = project()
    await expect(
      runInstaller(installer, { projectRoot: root, answers: { providers: 'google,facebook' } }),
    ).rejects.toThrow(/facebook/)
    expect(read(root, 'bootstrap/providers.ts')).toBe(PROVIDERS)
  })
})

describe('uninstall', () => {
  it('reverses the edits and env keys but keeps the config file', async () => {
    const root = project()
    await runInstaller(installer, {
      projectRoot: root,
      answers: { providers: 'google,microsoft,github,apple' },
    })
    const result = await runInstaller(installer, { projectRoot: root, mode: 'uninstall' })
    expect(read(root, 'bootstrap/providers.ts')).toBe(PROVIDERS)
    expect(read(root, 'config/index.ts')).toBe(CONFIG_INDEX)
    for (const key of ENV_KEYS) expect(read(root, '.env')).not.toContain(key)
    expect(read(root, INSTALL_PATHS.config)).toContain('defineConfig')
    expect(result.messages.some((m) => m.message.includes('kept'))).toBe(true)
  })

  it('on a project without the files does nothing harmful', async () => {
    const root = project({ 'bootstrap/providers.ts': undefined, 'config/index.ts': undefined })
    const result = await runInstaller(installer, { projectRoot: root, mode: 'uninstall' })
    expect(result.changes.filter((c) => c.path !== '.env' && c.path !== '.env.example')).toEqual([])
  })
})

describe('answers and template', () => {
  it('parses provider answers', () => {
    expect(chosenProviders({})).toEqual(['google'])
    expect(chosenProviders({ providers: true })).toEqual(['google'])
    expect(chosenProviders({ providers: ' GitHub , apple,' })).toEqual(['github', 'apple'])
    expect(chosenProviders({ providers: ['apple', 'google', 'apple'] })).toEqual([
      'google',
      'apple',
    ])
    expect(chosenProviders({ providers: '' })).toEqual(['google'])
    expect(() => chosenProviders({ providers: 5 })).toThrow(TypeError)
  })

  it('the template only lists the chosen providers and keeps registration off', () => {
    const text = configTemplate(['apple'])
    expect(text).toContain("env.boolean('SOCIAL_LOGIN_REGISTRATION', false)")
    expect(text).toContain('apple: {')
    expect(text).not.toContain('google: {')
  })
})

describe('source patches', () => {
  it('add then remove restores the file byte for byte', () => {
    for (const source of [
      PROVIDERS,
      'const providers = [\n  A,\n  B,\n]\n',
      'const providers = []\n',
    ]) {
      const added = addProvider(source) ?? ''
      expect(added).toContain(PROVIDER_LOCAL)
      expect(addProvider(added)).toBe(added)
      expect(removeProvider(added)).toBe(source)
    }
    const config = addConfigKey(CONFIG_INDEX) ?? ''
    expect(config).toContain(`export default { app, logging, ${CONFIG_LOCAL} }`)
    expect(addConfigKey(config)).toBe(config)
    expect(removeConfigKey(config)).toBe(CONFIG_INDEX)
    expect(removeProvider(PROVIDERS)).toBe(PROVIDERS)
    expect(removeConfigKey(CONFIG_INDEX)).toBe(CONFIG_INDEX)
  })

  it('refuses ambiguous shapes', () => {
    expect(
      addProvider('const providers = [a]\nconst providers2 = [b]\nconst providers = [c]\n'),
    ).toBeUndefined()
    expect(addConfigKey('export default { a: { b } }\n')).toBeUndefined()
  })

  it('round-trips for any simple provider list (property)', () => {
    fc.assert(
      fc.property(
        fc.array(fc.stringMatching(/^[A-Z][A-Za-z]{0,8}$/), { maxLength: 5 }),
        fc.boolean(),
        fc.boolean(),
        (names, multiline, trailing) => {
          const body = multiline
            ? names.length === 0
              ? '\n'
              : `\n${names.map((n, i) => `  ${n}${i < names.length - 1 || trailing ? ',' : ''}`).join('\n')}\n`
            : names.join(', ')
          const source = `import x from 'y'\nconst providers = [${body}]\n`
          const added = addProvider(source)
          return added !== undefined && removeProvider(added) === source
        },
      ),
    )
  })
})
