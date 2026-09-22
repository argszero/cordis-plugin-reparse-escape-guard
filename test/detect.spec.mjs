/**
 * The judgement itself, asserted as properties rather than as text.
 *
 * Nothing here mounts a context: these are the questions `detectOperand` answers
 * about one string and one filesystem, and they are worth pinning separately
 * because every one of them is a way the guard could become wrong in a
 * direction that no end-to-end test would notice — reporting a legal write
 * (breaking ordinary work) or missing an escape (making the plugin decorative).
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, sep } from 'node:path'
import { canonicalPath } from '@deepseek-ai/dsh-sandbox'
import {
  DEFAULT_PATHS,
  collectToolOperands,
  declaredOperands,
  detectEscapes,
  detectOperand,
  escapeReason,
  isUnder,
  resolveConfig,
  rootOf,
  shellOperands,
} from '../lib/index.js'

const CASE_SENSITIVE = process.platform !== 'win32'
const OUTSIDE = '/etc'

/** A workspace on disk with one link out and one plain directory. */
function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'reparse-detect-'))
  mkdirSync(join(root, 'real'))
  writeFileSync(join(root, 'real', 'inside.txt'), 'inside\n')
  symlinkSync(OUTSIDE, join(root, 'link'))
  symlinkSync(join(root, 'real'), join(root, 'shortcut'))
  // The root's *canonical* spelling is what the policy derives; the fixture is
  // created through `tmpdir()`, whose spelling may itself differ (darwin's
  // `/var` against `/private/var`).
  const options = { base: canonicalPath(root), roots: [canonicalPath(root)], caseSensitive: CASE_SENSITIVE }
  return { root, options, dispose: () => { rmSync(root, { recursive: true, force: true }) } }
}

test('isUnder is a path relation, not a string prefix', () => {
  assert.equal(isUnder('/ws', '/ws', true), true)
  assert.equal(isUnder('/ws/a', '/ws', true), true)
  // The trailing-separator prefix the fence also uses: a sibling that merely
  // starts with the same characters is not a child.
  assert.equal(isUnder('/ws-other/a', '/ws', true), false)
  assert.equal(isUnder('/ws-other', '/ws', true), false)
  assert.equal(isUnder('/WS/a', '/ws', false), true, 'case-insensitive comparison folds both sides')
  assert.equal(isUnder('/WS/a', '/ws', true), false)
  assert.equal(rootOf('/ws/a', ['/other', '/ws'], true), '/ws')
  assert.equal(rootOf('/elsewhere', ['/other', '/ws'], true), undefined)
})

test('a write through a link below the workspace that leaves it is a finding', () => {
  const { root, options, dispose } = fixture()
  try {
    const finding = detectOperand(join(root, 'link', 'out.txt'), options)
    assert.ok(finding, 'the call reads as inside and lands outside')
    assert.equal(finding.apparentRoot, options.roots[0])
    // The walk's cursor is canonical, so the component it names is too — the same
    // file the operand reached, in the terms the policy and the fence use.
    assert.equal(finding.aliasAt, join(canonicalPath(root), 'link'), 'the link that carries it out')
    assert.equal(finding.resolved, join(canonicalPath(OUTSIDE), 'out.txt'))
  } finally { dispose() }
})

test('a path that was outside from the start is not a finding', () => {
  const { root, options, dispose } = fixture()
  try {
    assert.equal(detectOperand(join(root, '..', 'elsewhere.txt'), options), undefined)
    assert.equal(detectOperand('/etc/hosts', options), undefined)
    // Reading as inside but landing *inside* is the ordinary case.
    assert.equal(detectOperand(join(root, 'real', 'inside.txt'), options), undefined)
    // A link that stays within the granted area is not an escape either.
    assert.equal(detectOperand(join(root, 'shortcut', 'inside.txt'), options), undefined)
  } finally { dispose() }
})

test('a missing tail does not hide an escape above it', () => {
  const { root, options, dispose } = fixture()
  try {
    const finding = detectOperand(join(root, 'link', 'not', 'created', 'yet.txt'), options)
    assert.ok(finding, 'nothing below the missing component can alias, but the link still exists')
    assert.equal(finding.aliasAt, join(canonicalPath(root), 'link'))
    assert.equal(finding.resolved, join(canonicalPath(OUTSIDE), 'not', 'created', 'yet.txt'))
  } finally { dispose() }
})

test('the walk follows the kernel, so `link/../x` is judged from where the link points', () => {
  const { root, options, dispose } = fixture()
  try {
    // Built by concatenation on purpose: `join()` collapses `..` lexically, and
    // that collapsing is the very thing this case exists to rule out.
    const spelling = [root, 'link', '..', 'out.txt'].join(sep)
    const finding = detectOperand(spelling, options)
    assert.ok(finding, 'lexical collapsing would call this `<workspace>/out.txt`, which is a different file')
    // `/etc/..` is the link's parent (`/private`), not the workspace's, and
    // `out.txt` does not exist there, so the walk stops one level short.
    assert.equal(finding.resolved, join(dirname(canonicalPath(OUTSIDE)), 'out.txt'))
    assert.equal(finding.aliasAt, join(canonicalPath(root), 'link'))
    assert.equal(finding.apparent, [canonicalPath(root), 'link', '..', 'out.txt'].join(sep),
      'the reading keeps the components the caller wrote, uncollapsed')
  } finally { dispose() }
})

test('an empty operand is the calling tool\'s error, not a path to judge', () => {
  const { options, dispose } = fixture()
  try {
    assert.equal(detectOperand('', options), undefined)
    assert.equal(detectOperand('   ', options), undefined)
  } finally { dispose() }
})

test('every escaping operand is reported, in argument order', () => {
  const { root, options, dispose } = fixture()
  try {
    const findings = detectEscapes([join(root, 'link', 'a.txt'), join(root, 'real', 'inside.txt'), '/etc/hosts', join(root, 'link', 'b.txt')], options)
    assert.deepEqual(findings.map((finding) => finding.operand), [join(root, 'link', 'a.txt'), join(root, 'link', 'b.txt')])
  } finally { dispose() }
})

test('the operand\'s own spelling may alias the root, and that is not the finding', { skip: process.platform !== 'darwin' }, () => {
  // darwin: `/var` is a link to `/private/var`. A caller writing the uncanonical
  // spelling of its own workspace must not be reported for the alias *above* the
  // root — only for an alias below it. Comparing a canonicalized target against
  // an uncollapsed operand (or the reverse) gets one of these two wrong.
  const { root, options, dispose } = fixture()
  try {
    assert.equal(detectOperand(join(root, 'real', 'inside.txt'), options), undefined,
      'the same workspace under the spelling mkdtemp returned is still inside')
    const finding = detectOperand(join(root, 'link', 'out.txt'), options)
    assert.ok(finding, 'and the escape below the root is still found through that spelling')
    assert.equal(finding.aliasAt, join(canonicalPath(root), 'link'), 'the alias above the root is never blamed')
  } finally { dispose() }
})

test('the finding renders the three facts a model cannot derive', () => {
  const { root, options, dispose } = fixture()
  try {
    const findings = detectEscapes([join(root, 'link', 'out.txt')], options)
    const message = escapeReason({ toolName: 'write', roots: options.roots }, findings)
    assert.ok(message.includes(join(root, 'link', 'out.txt')), 'the operand as written')
    assert.ok(message.includes(join(canonicalPath(OUTSIDE), 'out.txt')), 'where it lands')
    assert.ok(message.includes(join(root, 'link')), 'the component responsible')
    assert.ok(message.includes(options.roots[0]), 'and the granted area')
  } finally { dispose() }
})

test('a crossing that cannot be attributed says so instead of guessing', () => {
  const { root, dispose } = fixture()
  try {
    // A root that is not an ancestor of the operand at all: the walk enters no
    // root, so there is nothing to report and nothing to attribute.
    assert.equal(detectOperand(join(root, 'link', 'out.txt'), {
      base: canonicalPath(root),
      roots: [root],
      caseSensitive: CASE_SENSITIVE,
    }), undefined, 'root not canonical: the operand never reads as inside it')
  } finally { dispose() }
})

test('the shipped tool map names written paths only', () => {
  assert.deepEqual(Object.keys(DEFAULT_PATHS).sort(), ['edit', 'str_replace_editor', 'write'])
  // `read`/`glob`/`grep` are absent on purpose: reads outside the workspace are
  // legal in every mode, so a guard that reported them would refuse legal work.
  for (const readOnly of ['read', 'glob', 'grep', 'bash', 'pwsh']) {
    assert.equal(DEFAULT_PATHS[readOnly], undefined, `${readOnly} must not be declared as a write`)
  }
})

test('operand extraction reads fields, not heuristics', () => {
  assert.deepEqual(declaredOperands({ file_path: '/ws/a' }, ['file_path']), ['/ws/a'])
  assert.deepEqual(declaredOperands({ file_path: ['/ws/a', '/ws/b'] }, ['file_path']), ['/ws/a', '/ws/b'])
  assert.deepEqual(declaredOperands({ file_path: 7 }, ['file_path']), [], 'a non-string is not coerced')
  assert.deepEqual(declaredOperands('nonsense', ['file_path']), [])

  // The editor's `view` command inspects; every other command writes.
  assert.deepEqual(collectToolOperands('str_replace_editor', { command: 'view', path: '/ws/link/x' }, DEFAULT_PATHS), [])
  assert.deepEqual(collectToolOperands('str_replace_editor', { command: 'create', path: '/ws/link/x' }, DEFAULT_PATHS), ['/ws/link/x'])
  // Unknown tools are silent rather than guessed at.
  assert.deepEqual(collectToolOperands('mcp__server__apply', { destination: '/ws/link/x' }, DEFAULT_PATHS), [])
})

test('the shell scan is conservative on purpose', () => {
  // It is opt-in, and it only offers words that carry a path separator.
  assert.deepEqual(shellOperands('cat /ws/out.txt'), ['/ws/out.txt'])
  assert.deepEqual(shellOperands('rm /ws/link/out.txt > /ws/log'), ['/ws/link/out.txt', '/ws/log'])
  assert.deepEqual(shellOperands('echo hello'), [], 'a bare word is not a path')
  assert.deepEqual(shellOperands('grep --include=/ws/x foo'), [], 'an option is not a path')
  assert.deepEqual(shellOperands('cat "$OUT/out.txt"'), ['$OUT/out.txt'], 'an expansion is offered as written; resolution then decides')
})

test('the resolved mount configuration merges the shipped map with extras', () => {
  const config = resolveConfig({ extraWrites: { apply_patch: ['target'] }, shellFields: { bash: ['command'] } })
  assert.deepEqual(config.paths.apply_patch.writes, ['target'])
  assert.deepEqual(config.paths.bash.shell, ['command'])
  assert.deepEqual(config.paths.write.writes, ['file_path'], 'shipped declarations survive')
  assert.equal(config.mode, 'guard', 'defaults are the guard')
  assert.equal(config.action, 'deny')
  // Configurations that the schema cannot express are refused here too, so a
  // caller that bypassed the schema still cannot mount a half-built guard.
  assert.throws(() => resolveConfig({ shellFields: { '': ['command'] } }), /empty tool name/)
})
