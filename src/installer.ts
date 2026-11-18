/**
 * `@strutvane/social-login/installer`: what `node strut install:social-login` (and
 * `node strut add social-login`) runs, declared as `strutvane.installer` in package.json
 * (blueprint §3.3). One transaction the framework's devkit previews (`--dry-run --diff`) and
 * commits or rolls back:
 *
 * 1. `config/social-login.ts`: the chosen providers, reading their credentials from `.env` (kept
 *    if it already exists: it is the app's).
 * 2. `config/index.ts`: lists it under the `socialLogin` key.
 * 3. `.env` / `.env.example`: `SOCIAL_LOGIN_REGISTRATION=false` and each chosen provider's keys,
 *    **empty** (client secrets are never generated or written to `.env.example`).
 * 4. `bootstrap/providers.ts`: registers `@strutvane/social-login/provider` (an older app with a
 *    `strutvane.config.ts` gets it through the devkit's config patcher).
 *
 * Routes need no file: the provider serves `/auth/{provider}/redirect` and `/callback` itself.
 * The installer prints the callback URLs to register at each provider, and the one step it can't
 * do: binding `SocialAccountsToken` (see the README).
 *
 * Answers: `providers` (`--providers google,github`, or a list from `npm create strutvane`),
 * default `google`. Nothing here hard-codes another package, install order never changes the
 * result, and a second run changes nothing. `uninstall` reverses steps 2–4 and keeps
 * `config/social-login.ts` (it may hold the developer's edits).
 *
 * @module
 */
import {
  type DevkitInstallContext,
  type DevkitInstaller,
  defineInstaller,
} from '@strutvane/framework/devkit'
import {
  addConfigKey,
  addProvider,
  CONFIG_LOCAL,
  CONFIG_SPECIFIER,
  PROVIDER_LOCAL,
  PROVIDER_SPECIFIER,
  removeConfigKey,
  removeProvider,
} from './install/patch.ts'
import { PROVIDER_NAMES, type ProviderName } from './providers/types.ts'

/** Where the installer writes and edits files, relative to the project root. */
export const INSTALL_PATHS = {
  config: 'config/social-login.ts',
  configIndex: 'config/index.ts',
  providers: 'bootstrap/providers.ts',
  legacyConfig: 'strutvane.config.ts',
} as const

/** The `.env` keys per provider (all empty by default). */
export const PROVIDER_ENV: Readonly<Record<ProviderName, readonly string[]>> = {
  google: ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'],
  microsoft: ['MICROSOFT_CLIENT_ID', 'MICROSOFT_CLIENT_SECRET', 'MICROSOFT_TENANT'],
  github: ['GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET'],
  apple: ['APPLE_CLIENT_ID', 'APPLE_TEAM_ID', 'APPLE_KEY_ID', 'APPLE_PRIVATE_KEY'],
}

/** Every `.env` key the installer may add (what uninstall removes). */
export const ENV_KEYS: readonly string[] = [
  'SOCIAL_LOGIN_REGISTRATION',
  ...PROVIDER_NAMES.flatMap((p) => PROVIDER_ENV[p]),
]

const ENV_COMMENTS: Readonly<Record<string, string>> = {
  GOOGLE_CLIENT_ID:
    'Google OAuth client (console.cloud.google.com > APIs & Services > Credentials).',
  MICROSOFT_CLIENT_ID:
    'Microsoft Entra app registration (entra.microsoft.com > App registrations).',
  MICROSOFT_TENANT:
    'organizations (work/school), common (+ personal), consumers (personal) or one tenant id.',
  GITHUB_CLIENT_ID: 'GitHub OAuth app (github.com/settings/developers).',
  APPLE_CLIENT_ID: 'Sign in with Apple: your Services ID (developer.apple.com > Identifiers).',
  APPLE_PRIVATE_KEY: 'The .p8 key on one line, with \\n for line breaks. Never commit it.',
}

const PROVIDER_BLOCKS: Readonly<Record<ProviderName, string>> = {
  google: `    google: {
      clientId: env.optional('GOOGLE_CLIENT_ID'),
      clientSecret: env.optional('GOOGLE_CLIENT_SECRET'),
      // Only Google Workspace accounts of these domains, e.g. ['example.com']. Empty: any account.
      allowedDomains: [] as string[],
    },`,
  microsoft: `    microsoft: {
      clientId: env.optional('MICROSOFT_CLIENT_ID'),
      clientSecret: env.optional('MICROSOFT_CLIENT_SECRET'),
      tenant: env.string('MICROSOFT_TENANT', 'organizations'),
      // With a multi-tenant \`tenant\`: only these tenant ids. Empty: any tenant.
      allowedTenants: [] as string[],
    },`,
  github: `    github: {
      clientId: env.optional('GITHUB_CLIENT_ID'),
      clientSecret: env.optional('GITHUB_CLIENT_SECRET'),
    },`,
  apple: `    apple: {
      clientId: env.optional('APPLE_CLIENT_ID'),
      teamId: env.optional('APPLE_TEAM_ID'),
      keyId: env.optional('APPLE_KEY_ID'),
      privateKey: env.optional('APPLE_PRIVATE_KEY'),
    },`,
}

/**
 * The `config/social-login.ts` the installer writes for the chosen providers.
 *
 * @example
 * configTemplate(['google', 'github'])
 */
export function configTemplate(providers: readonly ProviderName[]): string {
  return `// Social sign-in (@strutvane/social-login): "Sign in with Google / Microsoft / GitHub / Apple".
// Routes: /auth/{provider}/redirect starts a sign-in, /auth/{provider}/callback finishes it.
// Register this callback URL at each provider: \${APP_URL}/auth/<provider>/callback
//
// Credentials come from .env (never commit them). A provider whose keys are empty is skipped.
// Linking is never automatic: an existing account connects a provider from its settings, after
// a fresh sign-in (redirect with ?intent=link).
import { defineConfig } from '@strutvane/framework'

export default defineConfig((env) => ({
  /** Create an account on a first sign-in with a verified email. Off: invite-only, like auth. */
  registration: env.boolean('SOCIAL_LOGIN_REGISTRATION', false),
  /** Linking a provider needs a sign-in or password confirmation this recent (minutes). */
  reauthMinutes: 10,
  /** After sign-in, and after a failure (the failure page gets ?error=<code>&provider=<name>). */
  redirects: { home: '/', failure: '/login' },
  providers: {
${providers.map((p) => PROVIDER_BLOCKS[p]).join('\n')}
  },
}))
`
}

/**
 * The chosen providers from the answers: a list, or a comma-separated string (`--providers`).
 * Unknown names are refused rather than ignored, so a typo doesn't silently install nothing.
 *
 * @example
 * chosenProviders({ providers: 'google,github' }) // ['google', 'github']
 */
export function chosenProviders(answers: Readonly<Record<string, unknown>>): ProviderName[] {
  const raw = answers['providers']
  const list =
    raw === undefined || raw === true
      ? ['google']
      : typeof raw === 'string'
        ? raw.split(',')
        : Array.isArray(raw)
          ? raw
          : undefined
  if (list === undefined)
    throw new TypeError('--providers must be a comma-separated list, e.g. google,github')
  const names = list.map((n) => String(n).trim().toLowerCase()).filter((n) => n !== '')
  for (const name of names)
    if (!PROVIDER_NAMES.includes(name as ProviderName))
      throw new TypeError(`Unknown provider "${name}". Choose from: ${PROVIDER_NAMES.join(', ')}.`)
  const unique = PROVIDER_NAMES.filter((p) => names.includes(p))
  return unique.length === 0 ? ['google'] : unique
}

async function readIfExists(ctx: DevkitInstallContext, path: string): Promise<string | undefined> {
  return (await ctx.fs.exists(path)) ? ctx.fs.read(path) : undefined
}

/** Step 2: list the config file in `config/index.ts`. */
async function registerConfig(ctx: DevkitInstallContext): Promise<void> {
  const source = await readIfExists(ctx, INSTALL_PATHS.configIndex)
  const manual = `import ${CONFIG_LOCAL} from '${CONFIG_SPECIFIER}', and add ${CONFIG_LOCAL} to the exported object`
  if (source === undefined) {
    ctx.log.warn(
      `${INSTALL_PATHS.configIndex} was not found. To use ${INSTALL_PATHS.config}: ${manual}.`,
    )
    return
  }
  const edited = addConfigKey(source)
  if (edited === undefined) {
    ctx.log.warn(
      `${INSTALL_PATHS.configIndex} has an unexpected shape, so it was not changed: ${manual}.`,
    )
    return
  }
  if (edited !== source) await ctx.fs.write(INSTALL_PATHS.configIndex, edited, { overwrite: true })
}

/** Step 4: register the provider. */
async function registerProvider(ctx: DevkitInstallContext): Promise<void> {
  const manual = `import ${PROVIDER_LOCAL} from '${PROVIDER_SPECIFIER}', and add ${PROVIDER_LOCAL} to your providers`
  const source = await readIfExists(ctx, INSTALL_PATHS.providers)
  if (source !== undefined) {
    const edited = addProvider(source)
    if (edited === undefined) {
      ctx.log.warn(
        `${INSTALL_PATHS.providers} has an unexpected shape, so it was not changed: ${manual}.`,
      )
      return
    }
    if (edited !== source) await ctx.fs.write(INSTALL_PATHS.providers, edited, { overwrite: true })
    return
  }
  if (await ctx.fs.exists(INSTALL_PATHS.legacyConfig)) {
    await ctx.config.registerProvider(PROVIDER_SPECIFIER)
    return
  }
  ctx.log.warn(
    `Neither ${INSTALL_PATHS.providers} nor ${INSTALL_PATHS.legacyConfig} was found: ${manual}.`,
  )
}

/**
 * The installer, loaded by `node strut install:social-login` / `node strut remove social-login`.
 *
 * @example
 * await runInstaller(installer, { projectRoot: '/srv/app', answers: { providers: 'google,github' }, dryRun: true })
 */
export const installer: DevkitInstaller = defineInstaller({
  name: 'social-login',
  description: 'Sign in with Google, Microsoft, GitHub and Apple.',
  async install(ctx: DevkitInstallContext): Promise<void> {
    const providers = chosenProviders(ctx.answers)
    if (!(await ctx.fs.exists(INSTALL_PATHS.config)))
      await ctx.fs.write(INSTALL_PATHS.config, configTemplate(providers))
    await registerConfig(ctx)
    await ctx.env.add('Social login (@strutvane/social-login)', [
      {
        key: 'SOCIAL_LOGIN_REGISTRATION',
        value: 'false',
        comment: 'Create accounts on a first social sign-in (verified emails only).',
      },
      ...providers.flatMap((p) =>
        PROVIDER_ENV[p].map((key) => ({
          key,
          value: key === 'MICROSOFT_TENANT' ? 'organizations' : '',
          ...(ENV_COMMENTS[key] === undefined ? {} : { comment: ENV_COMMENTS[key] }),
        })),
      ),
    ])
    await registerProvider(ctx)
    ctx.log.info(
      `Register these callback URLs at the providers: ${providers.map((p) => `\${APP_URL}/auth/${p}/callback`).join(', ')}`,
    )
    ctx.log.info(
      'Bind SocialAccountsToken in app/providers/app.provider.ts so sign-ins reach your users (README: "Connecting your users").',
    )
  },
  async uninstall(ctx: DevkitInstallContext): Promise<void> {
    const index = await readIfExists(ctx, INSTALL_PATHS.configIndex)
    if (index !== undefined) {
      const edited = removeConfigKey(index)
      if (edited !== index)
        await ctx.fs.write(INSTALL_PATHS.configIndex, edited, { overwrite: true })
    }
    await ctx.env.remove(ENV_KEYS)
    const providers = await readIfExists(ctx, INSTALL_PATHS.providers)
    if (providers !== undefined) {
      const edited = removeProvider(providers)
      if (edited !== providers)
        await ctx.fs.write(INSTALL_PATHS.providers, edited, { overwrite: true })
    } else if (await ctx.fs.exists(INSTALL_PATHS.legacyConfig))
      await ctx.config.unregisterProvider(PROVIDER_SPECIFIER)
    ctx.log.info(`${INSTALL_PATHS.config} was kept (it may hold your edits); delete it if unused.`)
  },
})

export default installer
