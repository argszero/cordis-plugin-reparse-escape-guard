/**
 * Wiring tests against a real Cordis context, a real `ToolRuntime`, the real
 * `tools/pre-execute` waterfall, and the real `SandboxPolicyService` — no
 * hand-built registry and no stubbed seam.
 *
 * The control arm is what makes the rest evidence: with the plugin unmounted,
 * the same call reaches the same tool body and writes what it was told to write.
 * The plugin's whole claim is that a mount can refuse it *before* dispatch, with
 * a reason that names the component responsible.
 *
 * The suite pins these separately, because they fail independently:
 *
 *  - **the control arm** — unmounted, an alias write is dispatched;
 *  - **the finding is a lie, not a destination** — a write to a path that reads
 *    as outside was already outside the plugin's remit and stays dispatched;
 *  - **reads through the same alias are left alone** — no enforcement dialect
 *    restricts reads, so reporting them would refuse legal work;
 *  - **the refusal carries the three facts a model cannot derive** (apparent
 *    path, resolved path, responsible link) under this plugin's own code;
 *  - **the configured ways out work**: `observe` reports without refusing,
 *    `exempt` skips a tool, an escalation argument goes to the approval flow;
 *  - **the fixture is real** — the symlink on disk is what produces the finding,
 *    so removing it makes the same call legal again.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime, { defineContentToolFixture } from '@deepseek-ai/dsh-tools'
import SessionProjectionRegistry from '@deepseek-ai/dsh-session-projection'
import SandboxPolicyService from '@deepseek-ai/dsh-sandbox-policy'
import * as plugin from '../lib/index.js'

/** A directory outside every writable root, used as the alias destination. */
const OUTSIDE = '/etc'

const text = (value) => [{ type: 'text', text: value }]

/**
 * The plugin as a mount supplies it: the module's own export shape, schema
 * included, so cordis validates the configuration exactly as a real profile
 * mount does.
 */
const mountSpec = () => ({ name: plugin.name, inject: plugin.inject, Config: plugin.Config, apply: plugin.apply })

/**
 * A workspace on disk with one symlink pointing outside it.
 *
 * `/etc` is the destination on purpose: the alias only has to *resolve* outside
 * for the finding to exist, and using a directory that already exists keeps the
 * fixture from needing a writable location beyond the workspace.
 * @returns the workspace root and a teardown.
 */
function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'reparse-escape-'))
  mkdirSync(join(root, 'real'))
  writeFileSync(join(root, 'real', 'inside.txt'), 'inside\n')
  symlinkSync(OUTSIDE, join(root, 'link'))
  return { root, dispose: () => { rmSync(root, { recursive: true, force: true }) } }
}

/**
 * Mount the registry, the projection registry, the policy service, an optional
 * pre-execute observer, the plugin, and the fixture tools.
 * @param workspace - the workspace root the policy is configured with.
 * @param config - plugin mount configuration.
 * @param options - `mounted: false` leaves the plugin out (the control arm).
 */
async function mount(workspace, config = {}, options = {}) {
  const ctx = new Context()
  // `ToolRuntime` injects `systemPrompt`, so a mount without it never loads the
  // registry and every `ctx.tools` read below would be a TypeError.
  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime)
  await ctx.plugin(SessionProjectionRegistry)
  await ctx.plugin(SandboxPolicyService, { mode: 'workspace-write', workspaceRoot: workspace })
  const warnings = []
  // `levels.default` must admit WARN: cordis drops a message below the
  // exporter's level and the root logger defaults to INFO.
  ctx.logger.exporter({
    levels: { default: 3 },
    export: (message) => { if (message.type === 'warn') warnings.push(message.args.map(String).join(' ')) },
  })
  if (options.mounted !== false) {
    await ctx.plugin(mountSpec(), config)
  }
  return { ctx, warnings }
}

/** Register a fixture tool that records every dispatch it receives. */
function writer(ctx, name, field, ran) {
  ctx.tools.register(defineContentToolFixture({
    name,
    description: `fixture tool that records its ${field} argument`,
    parameters: { [field]: { type: 'string' } },
    execute(args) {
      ran.push(args[field])
      return Promise.resolve(text(`wrote ${args[field]}`))
    },
  }))
}

const run = (ctx, name, args) => ctx.tools.execute({
  callId: 'c1',
  name,
  arguments: args,
  signal: new AbortController().signal,
})

const code = (result) => result?.error?.info?.code
const body = (result) => result?.content?.map((block) => block.text).join('\n') ?? ''

test('unmounted, a write through an in-workspace alias is dispatched', async () => {
  const { root, dispose } = fixture()
  try {
    const ran = []
    const { ctx } = await mount(root, {}, { mounted: false })
    writer(ctx, 'write', 'file_path', ran)
    const result = await run(ctx, 'write', { file_path: join(root, 'link', 'out.txt') })
    assert.deepEqual(ran, [join(root, 'link', 'out.txt')], 'the tool body ran: nothing refuses this call')
    assert.ok(!result.isError, 'and the result is the tool\'s own')
  } finally { dispose() }
})

test('mounted, the same call is refused before dispatch with the three facts', async () => {
  const { root, dispose } = fixture()
  try {
    const ran = []
    const { ctx } = await mount(root)
    writer(ctx, 'write', 'file_path', ran)
    const operand = join(root, 'link', 'out.txt')
    const result = await run(ctx, 'write', { file_path: operand })

    assert.deepEqual(ran, [], 'the tool body never ran')
    assert.ok(result.isError, 'the refusal is an error result')
    assert.equal(code(result), plugin.REPARSE_ESCAPE_BLOCKED)

    const message = body(result)
    assert.ok(message.includes(operand), 'the message quotes the operand as written')
    assert.ok(message.includes(join(root, 'link')), 'and names the link that leaves the workspace')
    assert.ok(message.includes(join(OUTSIDE === '/etc' ? '/private/etc' : OUTSIDE, 'out.txt')) || message.includes('/etc/out.txt'),
      `and the resolved location; saw: ${message}`)
    assert.ok(message.includes(root), 'and the root it appeared to sit under')
  } finally { dispose() }
})

test('a path that merely reads as outside is none of this plugin\'s business', async () => {
  const { root, dispose } = fixture()
  try {
    const ran = []
    const { ctx } = await mount(root)
    writer(ctx, 'write', 'file_path', ran)
    // Outside the workspace lexically, with no alias involved: the fence's
    // business, not a lie about where the path points.
    const result = await run(ctx, 'write', { file_path: join(root, '..', 'elsewhere.txt') })
    assert.deepEqual(ran, [join(root, '..', 'elsewhere.txt')], 'dispatched unchanged')
    assert.ok(!result.isError)
  } finally { dispose() }
})

test('reads through the same alias are dispatched, because no dialect restricts reads', async () => {
  const { root, dispose } = fixture()
  try {
    const ran = []
    const { ctx } = await mount(root)
    writer(ctx, 'read', 'file_path', ran)
    writer(ctx, 'str_replace_editor', 'path', ran)
    const escaped = join(root, 'link', 'out.txt')

    const read = await run(ctx, 'read', { file_path: escaped })
    // `view` inspects rather than writes, which is what the shipped editor's own
    // schema says; the same path under an editing command is not.
    const view = await run(ctx, 'str_replace_editor', { command: 'view', path: escaped })
    assert.deepEqual(ran, [escaped, escaped], 'both calls reached their bodies')
    assert.ok(!read.isError && !view.isError)
  } finally { dispose() }
})

test('the editor\'s writing commands are guarded on the same path', async () => {
  const { root, dispose } = fixture()
  try {
    const ran = []
    const { ctx } = await mount(root)
    writer(ctx, 'str_replace_editor', 'path', ran)
    const result = await run(ctx, 'str_replace_editor', { command: 'str_replace', path: join(root, 'link', 'out.txt') })
    assert.deepEqual(ran, [])
    assert.equal(code(result), plugin.REPARSE_ESCAPE_BLOCKED)
  } finally { dispose() }
})

test('a path inside the workspace with no alias is dispatched', async () => {
  const { root, dispose } = fixture()
  try {
    const ran = []
    const { ctx } = await mount(root)
    writer(ctx, 'write', 'file_path', ran)
    const inside = join(root, 'real', 'inside.txt')
    const result = await run(ctx, 'write', { file_path: inside })
    assert.deepEqual(ran, [inside])
    assert.ok(!result.isError)
  } finally { dispose() }
})

test('removing the alias makes the same call legal again', async () => {
  const { root, dispose } = fixture()
  try {
    const ran = []
    const { ctx } = await mount(root)
    writer(ctx, 'write', 'file_path', ran)
    const operand = join(root, 'link', 'out.txt')
    assert.equal(code(await run(ctx, 'write', { file_path: operand })), plugin.REPARSE_ESCAPE_BLOCKED)
    // The finding came from the filesystem, not from the text of the path.
    rmSync(join(root, 'link'), { force: true })
    const result = await run(ctx, 'write', { file_path: operand })
    assert.ok(!result.isError, 'no alias on disk, no finding')
    assert.deepEqual(ran, [operand])
  } finally { dispose() }
})

test("observe reports the finding and dispatches anyway", async () => {
  const { root, dispose } = fixture()
  try {
    const ran = []
    const { ctx, warnings } = await mount(root, { mode: 'observe' })
    writer(ctx, 'write', 'file_path', ran)
    const result = await run(ctx, 'write', { file_path: join(root, 'link', 'out.txt') })
    assert.ok(!result.isError, 'observe never refuses')
    assert.equal(ran.length, 1, 'the call was dispatched')
    assert.equal(warnings.length, 1, `one diagnostic; saw ${JSON.stringify(warnings)}`)
    assert.ok(warnings[0].includes('would refuse'), warnings[0])
  } finally { dispose() }
})

test('mode off registers nothing', async () => {
  const { root, dispose } = fixture()
  try {
    const ran = []
    const { ctx } = await mount(root, { mode: 'off' })
    writer(ctx, 'write', 'file_path', ran)
    const result = await run(ctx, 'write', { file_path: join(root, 'link', 'out.txt') })
    assert.ok(!result.isError)
    assert.deepEqual(ran, [join(root, 'link', 'out.txt')])
  } finally { dispose() }
})

test('an exempt tool is never inspected', async () => {
  const { root, dispose } = fixture()
  try {
    const ran = []
    const { ctx } = await mount(root, { exempt: ['write'] })
    writer(ctx, 'write', 'file_path', ran)
    const result = await run(ctx, 'write', { file_path: join(root, 'link', 'out.txt') })
    assert.ok(!result.isError)
    assert.equal(ran.length, 1)
  } finally { dispose() }
})

test('a call asking for wider access is left to the approval flow', async () => {
  const { root, dispose } = fixture()
  try {
    const ran = []
    const { ctx } = await mount(root)
    writer(ctx, 'write', 'file_path', ran)
    const result = await run(ctx, 'write', {
      file_path: join(root, 'link', 'out.txt'),
      sandbox_permissions: 'danger-full-access',
      justification: 'the fixture asks for the wider mode explicitly',
    })
    assert.ok(!result.isError, 'the second gate stays out of the escalation path')
    assert.equal(ran.length, 1)
  } finally { dispose() }
})

test('ask defers to the approval service, and fails closed without one', async () => {
  const { root, dispose } = fixture()
  try {
    const ran = []
    const { ctx } = await mount(root, { action: 'ask' })
    writer(ctx, 'write', 'file_path', ran)
    const result = await run(ctx, 'write', { file_path: join(root, 'link', 'out.txt') })
    assert.deepEqual(ran, [], 'no approval service is mounted, so the call does not run')
    assert.ok(result.isError, 'and the outcome is a refusal, not a dispatch')
    // The registry turns an unanswered `ask` into a denial carrying the same
    // reason but no structured info, so `ask` is distinguishable from this
    // plugin's own `deny`: only the latter is stamped with its code.
    assert.equal(code(result), undefined, 'the refusal is the approval flow\'s, not a direct denial')
    assert.ok(body(result).includes('refused by reparse-escape-guard'), 'and it still explains itself')
  } finally { dispose() }
})

test('a mode other than workspace-write grants no roots, so nothing is inspected', async () => {
  const { root, dispose } = fixture()
  try {
    const ran = []
    const ctx = new Context()
    await ctx.plugin(SystemPrompt)
    await ctx.plugin(ToolRuntime)
    await ctx.plugin(SessionProjectionRegistry)
    await ctx.plugin(SandboxPolicyService, { mode: 'danger-full-access', workspaceRoot: root })
    await ctx.plugin(mountSpec(), {})
    writer(ctx, 'write', 'file_path', ran)
    const result = await run(ctx, 'write', { file_path: join(root, 'link', 'out.txt') })
    assert.ok(!result.isError, 'there is no write boundary to escape')
    assert.equal(ran.length, 1)
  } finally { dispose() }
})

test('an unusable configuration is refused, by the schema and by the guard', async () => {
  const { root, dispose } = fixture()
  try {
    // A real mount hands cordis the module's own schema, so a closed vocabulary
    // is enforced before `apply` ever runs.
    await assert.rejects(
      () => mount(root, { mode: 'sometimes' }),
      /invalid config:[\s\S]*mode expected/,
    )
    // A caller that bypasses the schema (a hand-built plugin object) gets the
    // same refusal from the guard, which re-checks rather than trusting the
    // framework it did not go through.
    assert.throws(() => plugin.resolveConfig({ mode: 'sometimes' }), /reparse-escape-guard: unknown mode/)
    assert.throws(() => plugin.resolveConfig({ action: 'maybe' }), /unknown action/)
    assert.throws(() => plugin.resolveConfig({ warnLimit: -1 }), /non-negative integer/)
    assert.throws(() => plugin.resolveConfig({ extraWrites: { write: [''] } }), /non-empty argument field name/)
    assert.throws(() => plugin.resolveConfig({ extraWrites: { '': ['file_path'] } }), /empty tool name/)
    assert.throws(() => plugin.resolveConfig({ shellFields: { bash: [''] } }), /non-empty argument field name/)
  } finally { dispose() }
})
