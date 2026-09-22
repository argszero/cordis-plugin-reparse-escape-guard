/**
 * Which parts of a tool call are paths, and which of those the tool may modify.
 *
 * Detection can only judge the operands it is shown, so this module is where the
 * package's reach is decided — and where its honesty about that reach lives.
 * The map it exposes is data, not code, for one reason: the boundary this plugin
 * complements is a *write* boundary. No enforcement dialect
 * (`writableRoots()` is empty under `read-only` and meaningless under
 * `danger-full-access`) restricts reads, so reporting a path a tool only reads
 * would break ordinary work. Which field is read and which is written is a fact
 * about each tool, and it is stated here rather than inferred.
 *
 * Two kinds of extraction, deliberately separated because they carry different
 * guarantees:
 *
 * - {@link declaredOperands} reads a *named argument field*. The value is a path
 *   because the tool's own schema says so; nothing is guessed.
 * - {@link shellOperands} reads a *shell command string*, where the same words
 *   are data, arguments, expansions and redirect targets all at once. The scan
 *   is conservative (a token must carry a path separator to be offered at all)
 *   and it is **off by default**: a command line is parsed by a shell, and this
 *   module is not a shell.
 *
 * Whichever way an operand arrives, the verdict is the same and it is not
 * heuristic: {@link detectOperand} reports a path only when an *existing* prefix
 * of it resolves elsewhere. Extraction decides what is looked at; it never
 * decides what is concluded.
 *
 * @module @argszero/cordis-plugin-reparse-escape-guard/operands
 */

/** How one tool's arguments map to paths. */
export interface ToolPathSpec {
  /** Argument fields whose value this call may modify. */
  readonly writes?: readonly string[]
  /** Argument fields holding shell text, scanned for path-looking words. */
  readonly shell?: readonly string[]
  /**
   * An argument field and the values under which the call only reads. Present
   * because a tool's arguments can name a path that the call does not write:
   * `str_replace_editor view` inspects, and inspecting outside the workspace is
   * allowed everywhere.
   */
  readonly readsWhen?: { readonly field: string; readonly values: readonly string[] }
}

/** Tool name → how its arguments name paths. */
export type ToolPaths = Readonly<Record<string, ToolPathSpec>>

/**
 * The shipped tools that modify a path named in their arguments.
 *
 * The fs family writes `file_path` (`write`, `edit`); `str_replace_editor`
 * writes `path` for every command except `view`. The read-only tools are absent
 * on purpose — `read`, `glob` and `grep` name paths too, but reads outside the
 * workspace are legal in every mode, so a guard that reported them would refuse
 * work the harness permits. Shell tools (`bash`, `pwsh`) are absent for the
 * different reason given in {@link shellOperands}: their paths are not fields.
 */
export const DEFAULT_PATHS: ToolPaths = Object.freeze({
  write: { writes: ['file_path'] },
  edit: { writes: ['file_path'] },
  str_replace_editor: { writes: ['path'], readsWhen: { field: 'command', values: ['view'] } },
})

/** Characters that can wrap a path in a command line without being part of it. */
const EDGE_TRIM = /^[`'",]+|[`'",]+$/g

/** Word separators in a command line, including the redirection operators. */
const SHELL_SPLIT = /[\s;|&()<>]+/

/** The string value of one argument field, or `undefined`. */
function argumentString(argumentsValue: unknown, field: string): string | undefined {
  if (typeof argumentsValue !== 'object' || argumentsValue === null || Array.isArray(argumentsValue)) return undefined
  const value = (argumentsValue as Record<string, unknown>)[field]
  return typeof value === 'string' ? value : undefined
}

/**
 * Read the string values of the named fields out of one call's arguments.
 *
 * A field is honoured only when it holds a string or an array of strings; the
 * harness parses arguments losslessly from JSON, so anything else is a shape
 * this plugin did not expect and is left alone rather than coerced.
 *
 * @param argumentsValue - the parsed arguments of one tool call.
 * @param fields - argument field names, as declared for that tool.
 * @returns the path values found, in field order.
 */
export function declaredOperands(argumentsValue: unknown, fields: readonly string[]): string[] {
  if (typeof argumentsValue !== 'object' || argumentsValue === null || Array.isArray(argumentsValue)) return []
  const record = argumentsValue as Record<string, unknown>
  const found: string[] = []
  for (const field of fields) {
    const value = record[field]
    if (typeof value === 'string') found.push(value)
    else if (Array.isArray(value)) {
      for (const member of value) if (typeof member === 'string') found.push(member)
    }
  }
  return found
}

/**
 * Path-looking words in a command line.
 *
 * Deliberately conservative: a token is offered only when it carries a path
 * separator, and a leading `-` (an option) is rejected. Expansion (`$VAR`),
 * globbing, brace spans, here-documents and quoted separators are outside this
 * scan's reach by construction — what it does offer is then judged exactly, so
 * missing a spelling is a miss, never a false report.
 *
 * @param command - the shell text of one call.
 * @returns candidate path operands, in the order they appear.
 */
export function shellOperands(command: string): string[] {
  const found: string[] = []
  for (const raw of command.split(SHELL_SPLIT)) {
    const token = raw.replace(EDGE_TRIM, '')
    if (token === '' || token.startsWith('-')) continue
    // A path signal, not a guess: without a separator the token is a word, and
    // the shell resolves a word against its working directory by rules this
    // module does not implement.
    if (!token.includes('/') && !token.includes('\\')) continue
    found.push(token)
  }
  return found
}

/**
 * The candidate path operands of one call, deduplicated in encounter order.
 *
 * Empty for a call that only reads, and empty for a tool the map does not name:
 * silence is the correct answer for every call this plugin has no business
 * deciding about.
 *
 * @param toolName - the tool being dispatched.
 * @param argumentsValue - its parsed arguments.
 * @param paths - the effective tool map.
 * @returns the operands to judge.
 */
export function collectToolOperands(
  toolName: string,
  argumentsValue: unknown,
  paths: ToolPaths,
): string[] {
  const spec = paths[toolName]
  if (spec === undefined) return []
  if (spec.readsWhen !== undefined
    && spec.readsWhen.values.includes(argumentString(argumentsValue, spec.readsWhen.field) ?? '')) return []

  const seen = new Set<string>()
  const gathered: string[] = []
  const add = (values: readonly string[]): void => {
    for (const value of values) {
      if (seen.has(value)) continue
      seen.add(value)
      gathered.push(value)
    }
  }
  for (const field of spec.writes ?? []) add(declaredOperands(argumentsValue, [field]))
  for (const field of spec.shell ?? []) add(shellOperands(argumentString(argumentsValue, field) ?? ''))
  return gathered
}
