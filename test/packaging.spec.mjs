/**
 * Packaging guard: the published artifact must declare every bare specifier it
 * imports, must not declare packages it never imports, and must actually
 * **contain** the modules its entry point imports.
 *
 * Both directions of the declaration rule have bitten these plugins before (the
 * same guard runs in `cordis-plugin-tool-deadline-guard`, `session-trigger`,
 * `search-budget` and `credential-rotate`):
 *
 * - A value import left in `peerDependencies`-only (or, worse,
 *   `devDependencies`-only) resolves fine on the publishing machine — the
 *   workspace is right there — and fails for a consumer with
 *   `ERR_MODULE_NOT_FOUND`. `npm i <name>` in an empty directory is the only
 *   shape that catches it, and it only catches it after the release.
 * - A dependency kept after the import is gone is invisible until someone audits
 *   the tarball, and it silently widens the install closure.
 *
 * The third, added here after this package shipped a broken `0.1.0`: **a `files`
 * field that names the entry point and not its siblings**. `"lib/index.js"`
 * publishes one module of five, and every one of the other four is a relative
 * import of the entry. Nothing on the publishing machine notices, because `lib/`
 * is right there — the failure only appears in the consumer's
 * `node_modules/<name>/lib/index.js`. So the guard now reads the *actual* pack
 * list (npm's own matcher, not a re-implementation of it) and asserts two
 * closures agree: every module the build emits is shipped, and every relative
 * import reachable from the shipped entry resolves to a shipped file.
 *
 * This package has one type-only import that is nonetheless a real requirement:
 * `@deepseek-ai/dsh-sandbox-policy` supplies the `sandboxPolicy` service the
 * guard reads, so it belongs in `peerDependencies` even though nothing survives
 * into `lib/`. That is a declaration of a runtime need, not an artifact of the
 * scan — hence a peer rather than a dependency.
 *
 * `node:test` walks the same directory as the behaviour suite, so `npm test`
 * cannot pass without it — and the build runs first, so `lib/` is present.
 */

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const manifest = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))

/** Every file under `dir` whose name ends with one of `extensions`. */
function walk(dir, extensions, found = []) {
  if (!existsSync(dir)) return found
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) walk(path, extensions, found)
    else if (extensions.some((extension) => entry.name.endsWith(extension))) found.push(path)
  }
  return found
}

/**
 * Bare specifiers reached by `import`/`export from`, dynamic `import()`, and
 * `require()` in one source text.
 *
 * Relative and absolute targets are not packages; `node:` builtins are not
 * installable. Both are dropped here rather than filtered per call site.
 */
function bareSpecifiers(source) {
  const specifiers = new Set()
  const patterns = [
    /(?:^|[\s;{])(?:import|export)\s[^'"]*?from\s*['"]([^'"]+)['"]/g,
    /(?:^|[\s;(=])(?:import|require)\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /(?:^|[\s;{])import\s*['"]([^'"]+)['"]/g,
  ]
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) specifiers.add(match[1])
  }
  return [...specifiers].filter((specifier) => {
    if (specifier.startsWith('.') || specifier.startsWith('/')) return false
    if (specifier.startsWith('node:')) return false
    return true
  })
}

/** The package a specifier resolves to: `@scope/name` or `name`, subpath dropped. */
function packageOf(specifier) {
  const segments = specifier.split('/')
  return specifier.startsWith('@') ? segments.slice(0, 2).join('/') : segments[0]
}

const runtimeDeclared = new Set([
  ...Object.keys(manifest.dependencies ?? {}),
  ...Object.keys(manifest.peerDependencies ?? {}),
])
const devDeclared = new Set(Object.keys(manifest.devDependencies ?? {}))

const sourceFiles = [...walk(join(ROOT, 'src'), ['.ts']), ...walk(join(ROOT, 'lib'), ['.js'])]
const imported = new Set()
for (const file of sourceFiles) {
  for (const specifier of bareSpecifiers(readFileSync(file, 'utf8'))) imported.add(packageOf(specifier))
}

/** Every module the build emits, as paths relative to the package root. */
const emitted = walk(join(ROOT, 'lib'), ['.js', '.d.ts']).map((file) =>
  file.slice(ROOT.length + 1).split('\\').join('/'),
)

/**
 * The paths npm would actually publish.
 *
 * Deliberately npm's own matcher rather than a re-implementation of `files`
 * glob semantics (where `lib/**\/*.js` must also match `lib/index.js`): a
 * hand-written matcher that is subtly wrong here would be a guard that agrees
 * with the bug. `npm pack --dry-run` does not contact the registry and does not
 * run `prepublishOnly` (that stays a publish-time hook), and `--ignore-scripts`
 * keeps even `prepare` out of the way.
 */
function packedPaths() {
  const args = ['pack', '--dry-run', '--json', '--ignore-scripts']
  const npmCli = process.env.npm_execpath
  const stdout = npmCli
    ? execFileSync(process.execPath, [npmCli, ...args], { cwd: ROOT, encoding: 'utf8' })
    : execFileSync('npm', args, { cwd: ROOT, encoding: 'utf8' })
  const [entry] = JSON.parse(stdout)
  return new Set(entry.files.map((file) => file.path))
}

/**
 * Relative imports reachable from a shipped module, followed transitively —
 * the same walk the consumer's loader will do at import time.
 */
function reachableRelativeImports(shipped, from) {
  const visited = new Set()
  const missing = []
  const queue = [from]
  while (queue.length > 0) {
    const current = queue.pop()
    if (visited.has(current)) continue
    visited.add(current)
    const source = readFileSync(join(ROOT, current), 'utf8')
    for (const specifier of [...source.matchAll(/from\s*['"](\.[^'"]+)['"]/g)].map((match) => match[1])) {
      const target = resolve(dirname(join(ROOT, current)), specifier).slice(ROOT.length + 1).split('\\').join('/')
      if (!shipped.has(target)) missing.push({ from: current, specifier, target })
      else queue.push(target)
    }
  }
  return { visited: [...visited], missing }
}

test('the guard has something to guard', () => {
  // A walk that silently finds nothing would make both assertions below vacuous.
  assert.ok(sourceFiles.some((file) => file.endsWith(join('src', 'index.ts'))), 'src/index.ts must be scanned')
  assert.ok(sourceFiles.some((file) => file.endsWith(join('lib', 'index.js'))), 'lib/index.js must be built and scanned')
  assert.ok(imported.size >= 3, `expected several bare imports, saw ${imported.size}`)
})

test('every bare import in the published artifact is a runtime dependency', () => {
  const undeclared = [...imported].filter((name) => !runtimeDeclared.has(name))
  assert.deepEqual(
    undeclared,
    [],
    `these packages are imported by the shipped code but declared only in devDependencies (or nowhere): ${undeclared.join(', ')}`
      + ' — a consumer installing this package by name gets ERR_MODULE_NOT_FOUND',
  )
})

test('no runtime dependency is declared without being imported', () => {
  const unused = [...runtimeDeclared].filter((name) => !imported.has(name))
  assert.deepEqual(unused, [], `declared but never imported by shipped code: ${unused.join(', ')}`)
})

test('test-only packages stay out of the runtime closure', () => {
  const leaked = [...devDeclared].filter((name) => runtimeDeclared.has(name))
  // cordis and the dsh packages are deliberately both: peers for consumers, dev
  // dependencies so this repository can build and test itself.
  const allowed = new Set(Object.keys(manifest.peerDependencies ?? {}))
  assert.deepEqual(
    leaked.filter((name) => !allowed.has(name)),
    [],
    `a devDependency also declared as a runtime dependency: ${leaked.join(', ')}`,
  )
})

test('the shipped file list carries the manifest the harness reads', () => {
  // `dsh.bundle.patch` is how a profile finds the mount entry; shipping the
  // package without it makes the published artifact unusable.
  assert.equal(manifest.dsh.bundle.patch, './cordis.patch.yml')
  assert.ok(manifest.files.some((entry) => entry === 'cordis.patch.yml' || entry.startsWith('cordis')), 'the patch file must be in `files`')
  assert.ok(existsSync(join(ROOT, 'cordis.patch.yml')), 'and must exist')
})

test('the pack list ships every module the build emits', () => {
  // `0.1.0` published `files: ["lib/index.js"]` — one module of five, with the
  // other four imported by the entry. This is the assertion that was missing.
  const shipped = packedPaths()
  const withheld = emitted.filter((path) => !shipped.has(path))
  assert.deepEqual(
    withheld,
    [],
    `built but not published (fix the \`files\` field, not this test): ${withheld.join(', ')}`,
  )
  assert.ok(shipped.has('lib/index.js'), 'the entry point must be shipped')
  assert.ok(shipped.size > 4, `the pack list looks too small to be real: ${[...shipped].join(', ')}`)
})

test('every relative import of a shipped module resolves inside the tarball', () => {
  // The consumer-visible shape of the same bug: an install that resolves the
  // entry and then dies on its first sibling import.
  const shipped = packedPaths()
  const { visited, missing } = reachableRelativeImports(shipped, 'lib/index.js')
  assert.deepEqual(
    missing,
    [],
    `a shipped module imports a file the tarball does not contain: ${missing
      .map((entry) => `${entry.from} -> ${entry.specifier}`)
      .join('; ')}`,
  )
  assert.ok(visited.length >= 5, `expected the entry's whole module graph, walked ${visited.length}: ${visited.join(', ')}`)
})
