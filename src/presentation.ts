/**
 * The words a guarded call is refused with.
 *
 * A refusal that does not explain itself is a dead end for the model: it retries
 * the same call, or gives up on work that had a legal spelling. So the message
 * carries the three facts the model cannot derive on its own — where the path
 * *appeared* to point, where it *actually* points, and which component is
 * responsible — plus the one thing it can do next.
 *
 * Everything here is a pure function of a finding, so the wording is pinned by
 * test rather than by a snapshot of whatever the guard happened to print.
 *
 * @module @argszero/cordis-plugin-reparse-escape-guard/presentation
 */

import type { EscapeFinding } from './detect.js'

/** The structured error code carried on a denial, for retry/policy code that keys off it. */
export const REPARSE_ESCAPE_BLOCKED = 'REPARSE_ESCAPE_BLOCKED'

/** The error-class name paired with {@link REPARSE_ESCAPE_BLOCKED}. */
export const REPARSE_ESCAPE_NAME = 'ReparseEscapeBlocked'

/** What the refusal names, beyond the findings themselves. */
export interface EscapeContext {
  /** The tool whose call is being refused. */
  readonly toolName: string
  /** The canonical writable roots the resolved path left. */
  readonly roots: readonly string[]
}

/** Maximum findings spelled out in one message; the rest are counted. */
const MAX_RENDERED = 3

/**
 * The line describing where one operand stopped meaning what it says.
 * @param finding - the escaping operand.
 * @returns one line, or the honest admission that the crossing could not be attributed.
 */
function aliasLine(finding: EscapeFinding): string {
  return finding.aliasAt === undefined
    ? '  the crossing component: not attributable from inside this process (an ancestor resolves elsewhere but cannot be inspected)'
    : `  the link:                ${finding.aliasAt}`
}

/**
 * The model-facing refusal: what was refused, why, and what to do instead.
 *
 * The hint names the two legal moves — write to the resolved location, or ask for
 * the wider access the tool advertises — without promising that either will be
 * granted: whether an escalation exists and whether it is approved is the
 * deployment's business, not this seam's.
 * @param context - the tool and the roots the operands left.
 * @param findings - one or more escaping operands, in argument order.
 * @returns the refusal text, without the harness's `Error: ` envelope.
 */
export function escapeReason(context: EscapeContext, findings: readonly EscapeFinding[]): string {
  const shown = findings.slice(0, MAX_RENDERED)
  const rest = findings.length - shown.length
  const blocks = shown.map((finding) => [
    `"${finding.operand}"`,
    `  as written:              ${finding.apparent}  (inside ${finding.apparentRoot})`,
    `  actually resolves to:    ${finding.resolved}  (outside every writable root)`,
    aliasLine(finding),
  ].join('\n'))

  return [
    `refused by reparse-escape-guard: ${findings.length === 1 ? 'this path operand' : `${findings.length} path operands`} of "${context.toolName}" read as inside the write area and resolve outside it.`,
    '',
    ...blocks,
    ...rest > 0 ? [``, `(${rest} further operand${rest === 1 ? '' : 's'} omitted)`] : [],
    '',
    `Nothing was dispatched. Writes are confined to: ${context.roots.length === 0 ? '(no writable root is granted)' : context.roots.join(', ')}.`,
    'A path whose spelling sits inside that area but whose resolution leaves it is refused before the tool runs, because the write would be denied where it lands and the model would have no way to tell which component was responsible.',
    'Either name the resolved location directly, or — where the tool advertises it — request the wider access this call needs (sandbox_permissions with a justification).',
  ].join('\n')
}

/**
 * The one-line diagnostic for a mount that only observes.
 * @param context - the tool and the roots the operands left.
 * @param findings - one or more escaping operands, in argument order.
 * @returns a single log line.
 */
export function escapeNotice(context: EscapeContext, findings: readonly EscapeFinding[]): string {
  const first = findings[0]
  /* v8 ignore next -- callers pass a non-empty result from `detectEscapes`. */
  if (first === undefined) return ''
  const more = findings.length > 1 ? ` (+${findings.length - 1} more)` : ''
  return `would refuse "${context.toolName}": "${first.operand}" reads as inside ${first.apparentRoot} but resolves to ${first.resolved}${more}; dispatching unchanged`
}
