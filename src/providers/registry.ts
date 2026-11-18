/**
 * One driver per enabled provider, built from the resolved config.
 *
 * @module
 */
import type { ResolvedProvider } from '../config.ts'
import { appleDriver } from './apple.ts'
import { githubDriver } from './github.ts'
import { googleDriver } from './google.ts'
import { microsoftDriver } from './microsoft.ts'
import type { DriverContext, ProviderDriver, ProviderName } from './types.ts'

/**
 * Create the driver for one resolved provider.
 *
 * @example
 * const driver = createDriver(config.providers.get('github'), { http, now: Date.now })
 */
export function createDriver(settings: ResolvedProvider, ctx: DriverContext): ProviderDriver {
  switch (settings.name) {
    case 'google':
      return googleDriver(settings, ctx)
    case 'microsoft':
      return microsoftDriver(settings, ctx)
    case 'github':
      return githubDriver(settings, ctx)
    case 'apple':
      return appleDriver(settings, ctx)
  }
}

/**
 * Create a driver for every enabled provider.
 *
 * @example
 * const drivers = createDrivers(config.providers, { http, now: Date.now })
 */
export function createDrivers(
  providers: ReadonlyMap<ProviderName, ResolvedProvider>,
  ctx: DriverContext,
): ReadonlyMap<ProviderName, ProviderDriver> {
  return new Map([...providers].map(([name, settings]) => [name, createDriver(settings, ctx)]))
}
