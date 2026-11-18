/**
 * The two small source edits the installer makes in an app (blueprint §3.3: a package installs
 * itself completely), kept pure so they are easy to test:
 *
 * - `bootstrap/providers.ts`: import the social login provider and add it to the `providers` array.
 * - `config/index.ts`: import `config/social-login.ts` and list it under the `socialLogin` key.
 *
 * The same text-level technique as `@strutvane/log-viewer`'s installer (both v2 add-ons need to
 * edit these two skeleton files and the framework's devkit only edits the older
 * `strutvane.config.ts`); moving it into `@strutvane/framework/devkit` is an open item (NEXT.md).
 *
 * Every edit is **text-level and minimal** (one import line, one array or object item), so the
 * developer's formatting and comments stay untouched, and every edit is:
 * - **idempotent:** applying it to an already-edited file returns the file unchanged;
 * - **reversible:** the `remove*` function undoes exactly what the `add*` function added;
 * - **refused on an unknown shape:** when the file doesn't look like the skeleton's (no single
 *   `providers` array, no single `export default { … }` object), the function returns `undefined`
 *   and the installer prints the manual step instead of guessing. Guessing could corrupt a file
 *   the developer wrote by hand.
 *
 * @module
 */

/** The import specifier of the social login provider. */
export const PROVIDER_SPECIFIER = '@strutvane/social-login/provider'
/** The local name the provider is imported as. */
export const PROVIDER_LOCAL = 'socialLoginProvider'
/** The local name (and config key) `config/social-login.ts` is imported as. */
export const CONFIG_LOCAL = 'socialLogin'
/** The config file's path relative to `config/index.ts`. */
export const CONFIG_SPECIFIER = './social-login.ts'

const PROVIDER_IMPORT = `import ${PROVIDER_LOCAL} from '${PROVIDER_SPECIFIER}'`
const CONFIG_IMPORT = `import ${CONFIG_LOCAL} from '${CONFIG_SPECIFIER}'`

/**
 * A top-level import statement, single- or multi-line, up to the end of the line of its module
 * specifier: `import a from 'x'`, `import type {\n  A,\n} from 'x'`, `import 'x'`.
 */
const IMPORT_STATEMENT = /^import\b[^'"]*['"][^'"\n]+['"][^\n]*\n/gm

/** Insert an import line after the last top-level import (or at the top). */
function addImport(source: string, line: string): string {
  const imports = [...source.matchAll(IMPORT_STATEMENT)]
  const last = imports.at(-1)
  if (last === undefined) return `${line}\n${source}`
  const at = last.index + last[0].length
  return `${source.slice(0, at)}${line}\n${source.slice(at)}`
}

/** Remove an exact import line (with its newline). */
function removeImport(source: string, line: string): string {
  return source.replace(`${line}\n`, '')
}

/**
 * Add an item to the end of a bracketed list (`[a, b]` or `{ a, b }`), following its layout:
 * one item per line when the list is multi-line (keeping a trailing comma habit), inline
 * otherwise.
 */
function appendItem(body: string, item: string): string {
  const trimmed = body.trimEnd()
  const tail = body.slice(trimmed.length)
  if (body.includes('\n')) {
    if (trimmed.trim() === '') return `\n  ${item},${tail}`
    const indent = /\n([ \t]*)\S/.exec(body)?.[1] ?? '  '
    // `A,` + `\n  item,` keeps the trailing-comma habit; `A` + `,\n  item` keeps its absence.
    return trimmed.endsWith(',')
      ? `${trimmed}\n${indent}${item},${tail}`
      : `${trimmed},\n${indent}${item}${tail}`
  }
  if (trimmed.trim() === '') return `${item}${body}`
  return trimmed.endsWith(',') ? `${trimmed} ${item},${tail}` : `${trimmed}, ${item}${tail}`
}

/** Remove exactly what {@link appendItem} added (tried from its most to least specific form). */
function dropItem(body: string, item: string): string {
  const end = '(?![\\w$])'
  for (const pattern of [
    `\\n[ \\t]*${item}${end},`,
    `,\\n[ \\t]*${item}${end}`,
    `, ${item}${end}`,
    ` ${item}${end},`,
  ]) {
    const re = new RegExp(pattern)
    if (re.test(body)) return body.replace(re, '')
  }
  return body.trim() === item ? body.replace(item, '') : body
}

/**
 * The `providers` array of `bootstrap/providers.ts`: a flat list (no nested brackets, so an
 * expression like `[a[0]]` is never cut in half).
 */
const PROVIDERS_ARRAY = /(\bconst\s+providers\b[^=]*=\s*\[)([^[\]]*)(\])/g

/** The `export default { … }` object of `config/index.ts`: a flat list of keys. */
const DEFAULT_OBJECT = /(\bexport\s+default\s+\{)([^{}]*)(\})/g

/** Apply `edit` to the body of the single match of `pattern`; `undefined` unless exactly one. */
function editBody(
  source: string,
  pattern: RegExp,
  edit: (body: string) => string,
): string | undefined {
  const matches = [...source.matchAll(pattern)]
  const match = matches[0]
  if (matches.length !== 1 || match === undefined) return undefined
  const [whole, open = '', body = '', close = ''] = match
  return `${source.slice(0, match.index)}${open}${edit(body)}${close}${source.slice(match.index + whole.length)}`
}

/** Does `source` already import `specifier`? */
function imports(source: string, specifier: string): boolean {
  return source.includes(`'${specifier}'`) || source.includes(`"${specifier}"`)
}

/**
 * Register the social login provider in `bootstrap/providers.ts`.
 *
 * @returns the edited source, the same source when it is already registered, or `undefined` when
 *   the file doesn't have exactly one `const providers = [ … ]` array
 *
 * @example
 * addProvider("const providers = [AppServiceProvider]\n")
 */
export function addProvider(source: string): string | undefined {
  if (imports(source, PROVIDER_SPECIFIER)) return source
  const edited = editBody(source, PROVIDERS_ARRAY, (body) => appendItem(body, PROVIDER_LOCAL))
  return edited === undefined ? undefined : addImport(edited, PROVIDER_IMPORT)
}

/**
 * Undo {@link addProvider}. A file without the social login provider is returned unchanged.
 *
 * @example
 * removeProvider(addProvider(source) ?? source) === source
 */
export function removeProvider(source: string): string {
  if (!source.includes(PROVIDER_IMPORT)) return source
  const edited =
    editBody(source, PROVIDERS_ARRAY, (body) => dropItem(body, PROVIDER_LOCAL)) ?? source
  return removeImport(edited, PROVIDER_IMPORT)
}

/**
 * List `config/social-login.ts` in `config/index.ts` under the `socialLogin` key.
 *
 * @returns the edited source, the same source when it is already listed, or `undefined` when the
 *   file doesn't have exactly one `export default { … }` object
 *
 * @example
 * addConfigKey("export default { app, logging } satisfies ConfigFiles\n")
 */
export function addConfigKey(source: string): string | undefined {
  if (imports(source, CONFIG_SPECIFIER)) return source
  const edited = editBody(source, DEFAULT_OBJECT, (body) => appendItem(body, CONFIG_LOCAL))
  return edited === undefined ? undefined : addImport(edited, CONFIG_IMPORT)
}

/**
 * Undo {@link addConfigKey}. A file without the key is returned unchanged.
 *
 * @example
 * removeConfigKey(addConfigKey(source) ?? source) === source
 */
export function removeConfigKey(source: string): string {
  if (!source.includes(CONFIG_IMPORT)) return source
  const edited = editBody(source, DEFAULT_OBJECT, (body) => dropItem(body, CONFIG_LOCAL)) ?? source
  return removeImport(edited, CONFIG_IMPORT)
}
