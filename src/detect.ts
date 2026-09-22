/**
 * Whether a path operand names the place it appears to name.
 *
 * The whole package rests on one comparison: a path is reported exactly when it
 * *reads as* sitting inside the granted write area and *actually* resolves
 * outside it. Both sides are built from values the harness already owns —
 * `canonicalPath()` and `writableRoots()` from `@deepseek-ai/dsh-sandbox`, the
 * same derivation the Seatbelt profile and the in-process filesystem fence use —
 * so this package cannot invent a boundary the enforcement layers disagree with.
 *
 * Two properties are load-bearing and are pinned by test:
 *
 * 1. **A finding requires a real alias on disk.** The verdict is not a guess
 *    about text: resolution walks the spelling component by component and only
 *    reports when an *existing* prefix resolves elsewhere. No amount of
 *    quoting, casing or punctuation can manufacture one.
 * 2. **A path that merely reads as outside is never reported.** Reads are not
 *    restricted by any enforcement dialect, and neither is a write whose
 *    destination was outside from the start. The finding is the lie, not the
 *    destination: a path that reads as inside and lands outside.
 *
 * ## Why the walk is not `realpath(spelling)`
 *
 * There are two different questions about a spelling, and answering both with
 * one `realpath` call gets one of them wrong:
 *
 * - *Where does it land?* — the kernel's answer, component by component from the
 *   root, following each link as it goes. `realpath` gives this, and the
 *   `link/../x` case is why the walk must not pre-collapse `..`: lexical
 *   collapsing says `<ws>/x`, while the kernel follows `link` out of the
 *   workspace first and never comes back.
 * - *Where did the author think it landed?* — the same walk **stopped at the
 *   point it first coincides with a writable root**. That is the reading this
 *   package compares the kernel's answer against, and it has to be computed
 *   rather than assumed, because the *root itself* has more than one spelling on
 *   a real host: on darwin `/var` is a link to `/private/var`, so
 *   `/var/folders/…/ws/link/out.txt` and `/private/var/folders/…/ws/link/out.txt`
 *   name the same directory, and only the second starts with the canonical root
 *   text. A comparator that canonicalized the target but not the operand's own
 *   path would call the first one "outside" and miss the escape it contains.
 *
 * So one walk produces both readings: it carries the canonical cursor forward
 * (the kernel's answer), and it records the cursor at the depth where the path
 * first entered a writable root (the author's reading, with the remaining
 * components re-appended untouched).
 *
 * @module @argszero/cordis-plugin-reparse-escape-guard/detect
 */

import { existsSync } from 'node:fs'
import { isAbsolute, join, parse, sep } from 'node:path'
import { canonicalPath } from '@deepseek-ai/dsh-sandbox'

/** A path operand that reads as inside a writable root and resolves outside every one. */
export interface EscapeFinding {
  /** The operand exactly as the tool received it. */
  readonly operand: string
  /**
   * The operand as read from inside the workspace: the walk's cursor at the depth
   * it first entered a writable root, with the remaining components appended.
   * Deliberately not lexically collapsed — it preserves the reading that produced
   * the call, which is what makes the report explainable.
   */
  readonly apparent: string
  /** Where the operand actually lands, with every existing component resolved. */
  readonly resolved: string
  /** The writable root {@link apparent} sits under. */
  readonly apparentRoot: string
  /**
   * The first component at or below the workspace whose own resolution leaves
   * every writable root — the link that carries the operand out. Absent when the
   * walk cannot attribute the difference (for example when the crossing component
   * is a mount point the process cannot inspect).
   */
  readonly aliasAt?: string
}

/** Inputs one detection run needs; the roots and base are canonical already. */
export interface DetectOptions {
  /** Canonical directory a relative operand resolves against (the workspace root). */
  readonly base: string
  /** Canonical writable roots, as `writableRoots(policy)` returns them. */
  readonly roots: readonly string[]
  /** Whether lexical comparison preserves case. */
  readonly caseSensitive: boolean
}

/**
 * Whether `path` is `root` or lies beneath it, comparing canonical spellings.
 *
 * The shape mirrors the filesystem fence's own lexical test (`isLexicallyUnder`
 * in `@deepseek-ai/dsh-fs-sandbox`, including its trailing-separator prefix so
 * that `/ws-other` is not read as a child of `/ws`). The difference is
 * deliberate: that fence must also fall back to filesystem identity, because it
 * is handed spellings that may alias one root (`/tmp` against `/private/tmp` on
 * darwin, 8.3 names on Windows). Here **both sides are already canonical** —
 * the roots come from `writableRoots()`, which canonicalizes, and every path
 * this module produces comes from `canonicalPath()` — so identity comparison
 * would add nothing while inheriting that fallback's blind spot on filesystems
 * that report `ino === 0` for every file.
 *
 * @param path - canonical target.
 * @param root - canonical root.
 * @param caseSensitive - whether comparison preserves case.
 * @returns whether the target is the root or beneath it.
 */
export function isUnder(path: string, root: string, caseSensitive: boolean): boolean {
  const target = caseSensitive ? path : path.toLowerCase()
  const base = caseSensitive ? root : root.toLowerCase()
  if (target === base) return true
  const prefix = base.endsWith(sep) ? base : base + sep
  return target.startsWith(prefix)
}

/**
 * The canonical root a canonical path sits under.
 * @param path - canonical path to place.
 * @param roots - canonical writable roots.
 * @param caseSensitive - whether comparison preserves case.
 * @returns the first matching root, or `undefined` when the path is outside all of them.
 */
export function rootOf(path: string, roots: readonly string[], caseSensitive: boolean): string | undefined {
  return roots.find((root) => isUnder(path, root, caseSensitive))
}

/** Append one path component without collapsing anything. */
function descend(cursor: string, component: string): string {
  return cursor.endsWith(sep) ? cursor + component : cursor + sep + component
}

/**
 * Append components without collapsing anything.
 *
 * Not `join`: the "as read" path must keep the components the author wrote, so
 * that a report can show the reading that produced the call rather than a
 * normalized form the author never typed.
 * @param base - the path to extend.
 * @param parts - the components to append, in order.
 * @returns the extended path.
 */
function appendAll(base: string, parts: readonly string[]): string {
  let extended = base
  for (const part of parts) extended = descend(extended, part)
  return extended
}

/**
 * The absolute spelling of an operand: what the kernel is handed.
 *
 * Concatenation, not `join`: a relative operand must stay relative to the base
 * for the walk to see its components, and collapsing `..` here is exactly the
 * transformation that hides the interesting case.
 * @param operand - the operand as received.
 * @param base - canonical directory it resolves against.
 * @returns the spelling to walk.
 */
function absoluteSpelling(operand: string, base: string): string {
  if (isAbsolute(operand)) return operand
  return base.endsWith(sep) ? base + operand : base + sep + operand
}

/** One completed walk: the kernel's answer plus the reading it is compared against. */
interface Walk {
  readonly apparent: string | undefined
  readonly apparentRoot: string | undefined
  readonly resolved: string
  readonly aliasAt: string | undefined
}

/**
 * Walk one spelling the way the kernel does, recording both readings.
 *
 * The cursor is advanced through the *canonical* chain, so a component is always
 * looked up in the directory the kernel would actually be in — which is what
 * makes `link/../x` resolve to the link's parent and not to the spelling's. A
 * component that does not exist stops the walk: nothing below it can alias, and
 * the remaining components are appended as text (the same treatment the fence's
 * own ancestor walk gives a not-yet-created path).
 *
 * @param operand - the operand as received.
 * @param options - base, canonical roots, and case convention.
 * @returns the readings, with `apparent` present only when the path entered a root.
 */
function walk(operand: string, options: DetectOptions): Walk {
  const { base, roots, caseSensitive } = options
  const spelling = absoluteSpelling(operand, base)
  const { root: volume } = parse(spelling)
  const parts = spelling.slice(volume.length).split(sep).filter((part) => part !== '')

  let cursor = canonicalPath(volume)
  let apparent: string | undefined
  let apparentRoot: string | undefined
  // How many components the walk had consumed when it first entered a root: the
  // reading re-appends everything after that point, consumed or not, because the
  // `..` and link components in between are exactly what the spelling said.
  let apparentDepth = 0
  let aliasAt: string | undefined
  let consumed = 0

  while (consumed < parts.length) {
    const part = parts[consumed]
    /* v8 ignore next -- consumed is bounded by the loop condition above. */
    if (part === undefined) break
    const candidate = descend(cursor, part)
    if (!existsSync(candidate)) break
    const resolvedHere = canonicalPath(candidate)
    if (apparentRoot !== undefined && aliasAt === undefined && rootOf(resolvedHere, roots, caseSensitive) === undefined) {
      // At or below the workspace, this component stopped pointing where it sits.
      aliasAt = candidate
    }
    if (apparentRoot === undefined) {
      const entered = rootOf(resolvedHere, roots, caseSensitive)
      if (entered !== undefined) {
        apparent = resolvedHere
        apparentRoot = entered
        apparentDepth = consumed + 1
      }
    }
    cursor = resolvedHere
    consumed += 1
  }

  const rest = parts.slice(consumed)
  return {
    apparent: apparent === undefined ? undefined : appendAll(apparent, parts.slice(apparentDepth)),
    apparentRoot,
    resolved: join(cursor, ...rest),
    aliasAt,
  }
}

/**
 * Decide whether one operand lies about where it points.
 *
 * @param operand - the path as the tool received it.
 * @param options - base, canonical roots, and case convention.
 * @returns the finding, or `undefined` when the operand is innocent.
 */
export function detectOperand(operand: string, options: DetectOptions): EscapeFinding | undefined {
  // An empty path is the calling tool's schema error to report, not a path to
  // judge; refusing it here would replace a specific diagnosis with a vague one.
  if (operand.trim() === '') return undefined
  const found = walk(operand, options)
  const { apparent, apparentRoot, resolved, aliasAt } = found
  // Never reading as inside a writable root: nothing to report. An ordinary
  // out-of-bounds destination is the enforcement layers' business, and an
  // out-of-bounds *read* is legal everywhere.
  if (apparent === undefined || apparentRoot === undefined) return undefined
  // Reads as inside and lands inside: the spelling and the filesystem agree.
  if (rootOf(resolved, options.roots, options.caseSensitive) !== undefined) return undefined
  return {
    operand,
    apparent,
    resolved,
    apparentRoot,
    ...aliasAt === undefined ? {} : { aliasAt },
  }
}

/**
 * Every operand of one call that leaves the granted write area by alias.
 * @param operands - candidate path operands, in tool-argument order.
 * @param options - base, canonical roots, and case convention.
 * @returns one finding per escaping operand, in the order supplied.
 */
export function detectEscapes(operands: readonly string[], options: DetectOptions): EscapeFinding[] {
  const findings: EscapeFinding[] = []
  for (const operand of operands) {
    const finding = detectOperand(operand, options)
    if (finding !== undefined) findings.push(finding)
  }
  return findings
}
