/**
 * Mount configuration for `reparse-escape-guard`.
 *
 * Cordis validates the declared {@link Config} schema before {@link resolveConfig}
 * fills defaults, but a caller can bypass the schema (a hand-built plugin object
 * in a test, a programmatic mount), so `resolveConfig` re-checks the closed
 * vocabularies rather than trusting the framework.
 *
 * @module @argszero/cordis-plugin-reparse-escape-guard/config
 */

import z from '@deepseek-ai/schemastery'
import type { ToolPathSpec, ToolPaths } from './operands.js'
import { DEFAULT_PATHS } from './operands.js'

/** What the mount does when it finds an operand whose spelling and resolution disagree. */
export type Mode = 'off' | 'observe' | 'guard'

/** How a guarded call is stopped. */
export type Action = 'deny' | 'ask'

/** Mount configuration as declared to Cordis. */
export interface Config {
  /** `off` does nothing, `observe` reports, `guard` refuses. Default `guard`. */
  readonly mode?: Mode
  /** How a guarded call stops: `deny` (default) refuses it, `ask` defers to the approval service. */
  readonly action?: Action
  /**
   * Extra tool declarations, for tools this package does not ship knowledge of.
   * A tool name maps to the argument fields that hold paths the call **writes**.
   */
  readonly extraWrites?: Record<string, string[]>
  /**
   * Argument fields holding **shell text**, scanned for path-looking words. Off
   * by default: a command line is parsed by a shell, and this plugin is not one
   * (see `shellOperands` for exactly what the scan cannot see).
   */
  readonly shellFields?: Record<string, string[]>
  /** Tool names this mount never inspects. */
  readonly exempt?: string[]
  /** Diagnostics per mount; `0` silences them. Default 5. */
  readonly warnLimit?: number
}

/** The plugin name, used by the mount patch and every diagnostic. */
export const PLUGIN_NAME = 'reparse-escape-guard'

/** The plugin's runtime schema, walked statically by the config catalog. */
export const Config: z<Config> = z.object({
  mode: z.union(['off', 'observe', 'guard'] as const).default('guard'),
  action: z.union(['deny', 'ask'] as const).default('deny'),
  // The dictionaries are declared so a deployment can extend the tool map
  // without a release here: the shipped set is a default, not a closed list.
  extraWrites: z.dict(z.array(z.string())).default({}),
  shellFields: z.dict(z.array(z.string())).default({}),
  exempt: z.array(z.string()).default([]),
  warnLimit: z.number().default(5),
})

/** {@link Config} with every default applied, ready for the waterfall. */
export interface ResolvedConfig {
  readonly mode: Mode
  readonly action: Action
  /** The effective tool map: shipped declarations merged with the configured extras. */
  readonly paths: ToolPaths
  readonly exempt: ReadonlySet<string>
  readonly warnLimit: number
}

const MODES: readonly Mode[] = ['off', 'observe', 'guard']
const ACTIONS: readonly Action[] = ['deny', 'ask']

/** Thrown for a configuration {@link Config} cannot express but a caller can still pass. */
function invalid(detail: string): never {
  throw new Error(`${PLUGIN_NAME}: ${detail}`)
}

/**
 * Assert one field-name list is a list of non-empty strings.
 * @param label - the configuration path being validated, for the message.
 * @param fields - the candidate list.
 * @returns the list, unchanged.
 */
function validateFields(label: string, fields: readonly string[]): readonly string[] {
  if (!Array.isArray(fields)) invalid(`${label} must be an array of argument field names`)
  fields.forEach((field, index) => {
    if (typeof field !== 'string' || field.length === 0) invalid(`${label}[${index}] must be a non-empty argument field name`)
  })
  return fields
}

/**
 * Merge one write declaration into the map built so far.
 *
 * An extra declaration that repeats a field the shipped entry already lists is a
 * no-op rather than an error: a deployment restating a default is a deployment
 * being explicit, and refusing it would make patch order load-bearing.
 * @param paths - the map built so far.
 * @param tool - the tool name being declared.
 * @param fields - the argument fields that tool writes.
 * @returns a new map with the declaration merged in.
 */
function withWrites(paths: ToolPaths, tool: string, fields: readonly string[]): ToolPaths {
  const existing: ToolPathSpec = paths[tool] ?? {}
  return { ...paths, [tool]: { ...existing, writes: [...new Set([...(existing.writes ?? []), ...fields])] } }
}

/**
 * Fill every default so the guard can be reasoned about without Cordis, and
 * reject a configuration the runtime schema cannot express.
 * @param config - mount configuration.
 * @returns the resolved configuration.
 */
export function resolveConfig(config: Config = {}): ResolvedConfig {
  const mode = config.mode ?? 'guard'
  if (!MODES.includes(mode)) invalid(`unknown mode "${String(mode)}"`)
  const action = config.action ?? 'deny'
  if (!ACTIONS.includes(action)) invalid(`unknown action "${String(action)}"`)
  const warnLimit = config.warnLimit ?? 5
  if (!Number.isInteger(warnLimit) || warnLimit < 0) invalid(`warnLimit must be a non-negative integer, saw ${String(warnLimit)}`)

  const exempt = config.exempt ?? []
  exempt.forEach((tool, index) => {
    if (typeof tool !== 'string' || tool.length === 0) invalid(`exempt[${index}] must be a non-empty tool name`)
  })

  let paths: ToolPaths = { ...DEFAULT_PATHS }
  for (const [tool, fields] of Object.entries(config.extraWrites ?? {})) {
    if (tool.length === 0) invalid('extraWrites has an empty tool name')
    paths = withWrites(paths, tool, validateFields(`extraWrites["${tool}"]`, fields))
  }
  for (const [tool, fields] of Object.entries(config.shellFields ?? {})) {
    if (tool.length === 0) invalid('shellFields has an empty tool name')
    validateFields(`shellFields["${tool}"]`, fields)
    const existing: ToolPathSpec = paths[tool] ?? {}
    paths = { ...paths, [tool]: { ...existing, shell: [...new Set([...(existing.shell ?? []), ...fields])] } }
  }

  return { mode, action, paths, exempt: new Set(exempt), warnLimit }
}
