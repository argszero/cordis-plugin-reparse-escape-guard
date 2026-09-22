/**
 * A pre-dispatch guard for writes that leave the granted area through a link.
 *
 * ## The gap
 *
 * Every write confinement in the harness compares a path after canonicalizing
 * it. `@deepseek-ai/dsh-fs-sandbox` re-canonicalizes the target inside
 * `checkedTarget` and requires containment under a `writableRoots(policy)` entry
 * before the mutation is published; the Seatbelt profile allows the same roots.
 * That is the right *enforcement* answer, and it is deliberately blind to how the
 * path got there: `<workspace>/link/out.txt`, where `link` resolves outside,
 * fails the containment test exactly like `../../out.txt` does.
 *
 * The **diagnostic** answer is not the same. A denial that arrives because the
 * model wrote a path it believed was inside the workspace reads to the model as
 * "I may not write here" — so the next attempt is usually the same call with a
 * different name, or the same call again. Nothing in the refusal says *which
 * component* disagreed with the spelling, and by the time the write is refused
 * the string the model produced is no longer attached to the reason. The two
 * reports behind this plugin (#7517, #7298) are about a *Windows junction created
 * inside the workspace* — the same shape, discovered by someone who had to work
 * out from the outside why one path was deletable and another was not.
 *
 * Two facts about the gap are worth stating plainly, because the plugin's whole
 * scope follows from them:
 *
 * 1. **It is a write-boundary problem only.** No enforcement dialect restricts
 *    reads — `writableRoots` returns `[]` for anything that is not
 *    `workspace-write`, and even then it is consulted on mutation paths alone. A
 *    path that alias-resolves outside and is only *read* is legal work, and is
 *    left alone here.
 * 2. **It is not a heuristic.** Nothing about the text of a path decides the
 *    verdict. The operand is resolved the way the kernel resolves it (raw
 *    components, left to right, canonicalizing each existing prefix as it goes —
 *    so `link/../x` reproduces the kernel's answer, not the reader's), and the
 *    finding requires a real prefix on disk that resolves elsewhere.
 *
 * ## What this plugin does
 *
 * It arrives before dispatch, on the public `tools/pre-execute` waterfall, and
 * refuses a call whose written operands read as inside the granted area and
 * resolve outside it. The verdict is computed from the *same* derivation the
 * enforcement layers use — `ctx.sandboxPolicy.resolve()` for the per-call mode
 * and workspace root, and `writableRoots()`/`canonicalPath()` from
 * `@deepseek-ai/dsh-sandbox`, the module that owns them — so this plugin cannot
 * invent a boundary the fence disagrees with.
 *
 * The refusal is a model-visible error result in the shape the registry already
 * produces for a pre-dispatch denial, carrying this plugin's own
 * {@link REPARSE_ESCAPE_BLOCKED} code and a message that names the apparent path,
 * the resolved path and the responsible component.
 *
 * ## The honest limits
 *
 * - **It sees declared operands, not effects.** {@link DEFAULT_PATHS} names the
 *   argument fields the shipped mutating tools carry. Anything reached another
 *   way — a shell command line (unless a deployment opts in through
 *   `shellFields`), a tool a deployment forgot to declare, an editor writing
 *   through its own protocol — is invisible here. That is a miss, never a false
 *   report: the extraction can miss a path, and the judgement is exact about the
 *   paths it is given.
 * - **A call that asks for wider access is left alone.** An escalation argument
 *   means a human is about to be shown exactly what this plugin would have
 *   refused, with the same paths in front of them; refusing first would hide the
 *   request behind a second gate. The cost is stated in the README: a call
 *   carrying the *standing* mode is not strictly wider, needs no approval, and
 *   therefore reaches the fence unchecked by this plugin.
 * - **It does not replace the fence.** Only `workspace-write` produces writable
 *   roots, so under `read-only` and `danger-full-access` this plugin is inert by
 *   construction — and under a composition whose filesystem does not confine at
 *   all, it is the only thing enforcing the declared mode. `mode: observe`
 *   reports instead of refusing.
 *
 * @module @argszero/cordis-plugin-reparse-escape-guard
 */

import type { Context } from '@deepseek-ai/cordis'
import type { PreToolDecision, ToolExecution } from '@deepseek-ai/dsh-tools'
// Type-only: brings the `sandboxPolicy` service augmentation into scope. The
// package is a declared peer because the service is a runtime requirement too.
import type {} from '@deepseek-ai/dsh-sandbox-policy'
import { canonicalPath, writableRoots } from '@deepseek-ai/dsh-sandbox'
import { Config, PLUGIN_NAME, resolveConfig } from './config.js'
import type { ResolvedConfig } from './config.js'
import { detectEscapes } from './detect.js'
import type { EscapeFinding } from './detect.js'
import { collectToolOperands } from './operands.js'
import { REPARSE_ESCAPE_BLOCKED, REPARSE_ESCAPE_NAME, escapeNotice, escapeReason } from './presentation.js'

export { Config, PLUGIN_NAME, resolveConfig }
export * from './detect.js'
export * from './operands.js'
export * from './presentation.js'
export type { Action, Mode, ResolvedConfig } from './config.js'
export type { EscapeFinding } from './detect.js'

/** The plugin name used by the mount patch. */
export const name = PLUGIN_NAME

/**
 * This plugin reads the tool registry's pre-dispatch gate and the sandbox
 * policy's derivation.
 *
 * `sandboxPolicy` is a declared dependency rather than an optional lookup: a
 * composition without it has no boundary this plugin could compare against, and
 * a guard that guessed one would be enforcing a rule nobody wrote.
 */
export const inject = ['tools', 'sandboxPolicy']

/** Whether lexical comparison preserves case, matching the fence's own default. */
const CASE_SENSITIVE = process.platform !== 'win32'

/** The escalation argument a mutating tool advertises when a confining backend is mounted. */
const ESCALATION_FIELD = 'sandbox_permissions'

/**
 * The arguments of one call, when they are a plain object.
 * @param exec - the pending call.
 * @returns the argument record, or `undefined` for any other shape.
 */
function argumentRecord(exec: ToolExecution): Record<string, unknown> | undefined {
  const value = exec.arguments
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined
  return value as Record<string, unknown>
}

/**
 * Register the pre-dispatch guard.
 *
 * Registration order is deliberately the default: this listener only decides
 * whether the call may run at all, delegating every other decision to
 * `next()` — so it composes with the other `tools/pre-execute` listeners
 * (approval gates, monotonic guards) whichever way they are mounted.
 * @param ctx - the Cordis context carrying the `tools` and `sandboxPolicy` services.
 * @param config - mount configuration.
 */
export function apply(ctx: Context, config: Config = {}): void {
  const resolved: ResolvedConfig = resolveConfig(config)
  if (resolved.mode === 'off') return

  let warnings = 0
  const reported = new Set<string>()

  /**
   * Emit one bounded diagnostic, at most once per distinct message.
   * @param message - the diagnostic text.
   */
  const report = (message: string): void => {
    if (message === '') return
    if (resolved.warnLimit === 0 || warnings >= resolved.warnLimit) return
    if (reported.has(message)) return
    reported.add(message)
    warnings += 1
    ctx.logger.warn(`${name}: ${message}`)
  }

  ctx.on('tools/pre-execute', async (exec: ToolExecution, next: () => Promise<PreToolDecision>): Promise<PreToolDecision> => {
    if (resolved.exempt.has(exec.name)) return next()
    const args = argumentRecord(exec)
    if (args === undefined) return next()
    // A call asking for wider access is the approval flow's to gate, and it will
    // show the same paths to the same human; refusing it here would hide the
    // request behind a second, unexplained gate.
    if (args[ESCALATION_FIELD] !== undefined) return next()

    const operands = collectToolOperands(exec.name, args, resolved.paths)
    if (operands.length === 0) return next()

    // The per-call policy: the same call tool-fs makes, from the same service, so
    // the roots here are the roots the fence would compare against.
    const policy = ctx.sandboxPolicy.resolve({ ...exec.agent === undefined ? {} : { session: exec.agent.session } })
    const roots = writableRoots(policy)
    // No writable root means no write boundary (`read-only` denies everything
    // outright; `danger-full-access` fences nothing): there is nothing to escape.
    if (roots.length === 0) return next()

    const findings = detectEscapes(operands, {
      base: canonicalPath(policy.workspaceRoot),
      roots,
      caseSensitive: CASE_SENSITIVE,
    })
    if (findings.length === 0) return next()

    const context = { toolName: exec.name, roots }
    if (resolved.mode === 'observe') {
      report(escapeNotice(context, findings))
      return next()
    }
    return refusal(resolved, context, findings)
  })
}

/**
 * The pre-dispatch decision for a call carrying escaping operands.
 *
 * `deny` is chosen by default because the write would be refused where it lands
 * anyway — asking a human first would promise a permission this seam cannot
 * grant (only the escalation path widens a policy, and that path is skipped
 * above). A deployment that would rather adjudicate each case can mount with
 * `action: 'ask'`; `ask` fails closed when no approval channel is mounted.
 * @param resolved - the resolved mount configuration.
 * @param context - the tool and the roots the operands left.
 * @param findings - the escaping operands.
 * @returns the decision for the registry.
 */
function refusal(
  resolved: ResolvedConfig,
  context: { readonly toolName: string; readonly roots: readonly string[] },
  findings: readonly EscapeFinding[],
): PreToolDecision {
  const reason = escapeReason(context, findings)
  if (resolved.action === 'ask') return { kind: 'ask', reason }
  return { kind: 'deny', reason, info: { name: REPARSE_ESCAPE_NAME, code: REPARSE_ESCAPE_BLOCKED } }
}
