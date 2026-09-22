/**
 * The guard and the fence, on one call.
 *
 * This is the evidence the plugin's premise rests on: the *enforcement* answer
 * for an alias write already exists — `@deepseek-ai/dsh-fs-sandbox` re-canonicalizes
 * the target and refuses anything outside `writableRoots(policy)` — and the
 * plugin's claim is narrower than "nothing stops this". It is that the model is
 * told *why*, before dispatch, instead of reading a denial that says only "denied
 * under workspace-write mode" about a path it believed was inside the workspace.
 *
 * So the same operand is put to both halves of a real composition:
 *
 *  - the real confining filesystem refuses the mutation (and there is no way to
 *    make it explain itself — its message is a fixed marker);
 *  - the guard refuses the *dispatch*, with the apparent path, the resolved path
 *    and the link that carries the operand out.
 *
 * A guard that disagreed with the fence in either direction would be worse than
 * no guard: refusing writes the fence would allow, or reporting escapes the fence
 * would deny on a path the model meant. Both are checked here, on the same
 * fixture, through the same policy service.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime, { defineContentToolFixture } from '@deepseek-ai/dsh-tools'
import SessionProjectionRegistry from '@deepseek-ai/dsh-session-projection'
import SandboxPolicyService from '@deepseek-ai/dsh-sandbox-policy'
import SandboxedFileSystem from '@deepseek-ai/dsh-fs-sandbox'
import { canonicalPath } from '@deepseek-ai/dsh-sandbox'
import * as plugin from '../lib/index.js'

const OUTSIDE = '/etc'

/** A workspace on disk with one link out of it. */
function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'reparse-fence-'))
  mkdirSync(join(root, 'real'))
  symlinkSync(OUTSIDE, join(root, 'link'))
  return { root, dispose: () => { rmSync(root, { recursive: true, force: true }) } }
}

/**
 * Compose the real filesystem, the real policy service, and the real tool
 * registry, with the plugin mounted.
 * @param workspace - the configured workspace root.
 */
async function compose(workspace) {
  const ctx = new Context()
  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime)
  await ctx.plugin(SessionProjectionRegistry)
  await ctx.plugin(SandboxPolicyService, { mode: 'workspace-write', workspaceRoot: workspace })
  await ctx.plugin(SandboxedFileSystem, { cwd: workspace })
  await ctx.plugin({ name: plugin.name, inject: plugin.inject, Config: plugin.Config, apply: plugin.apply }, {})
  return ctx
}

test('the fence refuses an alias write, and the guard says why first', async () => {
  const { root, dispose } = fixture()
  try {
    const ctx = await compose(root)
    const operand = join(root, 'link', 'out.txt')

    // Half one: the enforcement layer, asked directly. It refuses, and its
    // message is the fixed marker — nothing in it names the link, because the
    // fence never saw the operand as anything but a canonical target.
    const target = await ctx.fs.resolve(operand, { cwd: root })
    const refusal = await ctx.fs.writeText(target, 'written through the link\n')
      .then(() => undefined, (error) => error)
    assert.ok(refusal, 'the fence refuses this mutation')
    assert.match(String(refusal.message), /denied under workspace-write mode/)
    assert.equal(refusal.code, 'FS_SANDBOX_DENIED')

    // Half two: the guard, on the same call. Same verdict, different sentence.
    const ran = []
    ctx.tools.register(defineContentToolFixture({
      name: 'write',
      description: 'fixture write tool',
      parameters: { file_path: { type: 'string' } },
      execute(args) { ran.push(args.file_path); return Promise.resolve([{ type: 'text', text: 'wrote' }]) },
    }))
    const result = await ctx.tools.execute({
      callId: 'c1', name: 'write', arguments: { file_path: operand }, signal: new AbortController().signal,
    })
    assert.deepEqual(ran, [], 'refused before dispatch')
    assert.equal(result.error.info.code, plugin.REPARSE_ESCAPE_BLOCKED)
    const message = result.content.map((block) => block.text).join('\n')
    assert.ok(message.includes(join(canonicalPath(root), 'link')), 'the guard names the link the fence could not')
    assert.ok(message.includes(canonicalPath(OUTSIDE)), 'and where the operand actually lands')
  } finally { dispose() }
})

test('the fence allows an in-workspace write, and the guard leaves that call alone', async () => {
  const { root, dispose } = fixture()
  try {
    const ctx = await compose(root)
    const inside = join(root, 'real', 'written.txt')
    const target = await ctx.fs.resolve(inside, { cwd: root })
    await ctx.fs.writeText(target, 'ordinary write\n')
    assert.equal(readFileSync(inside, 'utf8'), 'ordinary write\n', 'the fence allowed it')

    const ran = []
    ctx.tools.register(defineContentToolFixture({
      name: 'write',
      description: 'fixture write tool',
      parameters: { file_path: { type: 'string' } },
      execute(args) { ran.push(args.file_path); return Promise.resolve([{ type: 'text', text: 'wrote' }]) },
    }))
    const result = await ctx.tools.execute({
      callId: 'c1', name: 'write', arguments: { file_path: inside }, signal: new AbortController().signal,
    })
    assert.ok(!result.isError, 'the guard does not add a second gate to legal work')
    assert.deepEqual(ran, [inside])
  } finally { dispose() }
})
