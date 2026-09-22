# @argszero/cordis-plugin-reparse-escape-guard

A pre-dispatch guard for `deepseek-harness` (`dsh`) writes whose path leaves the
granted write area through a link.

The harness already *enforces* this: `@deepseek-ai/dsh-fs-sandbox` re-canonicalizes
every mutation target and refuses anything outside `writableRoots(policy)`. What it
does not do is *explain* it. `<workspace>/link/out.txt`, where `link` resolves
outside, fails containment exactly like `../../out.txt` does, so the model reads
"file access denied under workspace-write mode" about a path it believed was inside
the workspace — and tries again with a different name. This plugin refuses the call
**before dispatch**, with the three facts the model cannot derive: where the path
reads as pointing, where it actually lands, and which component is responsible.

Reported as discussions
[#7517](https://github.com/deepseek-ai/deepseek-harness/discussions/7517) and
[#7298](https://github.com/deepseek-ai/deepseek-harness/discussions/7298) (both
about a junction created inside a workspace on Windows — the same shape: an alias
the enforcement layer resolves and the author did not).

## The gap, precisely

Two questions can be asked about one spelling, and the harness only answers the
first:

| question | answer | who answers it today |
|---|---|---|
| Where does this path land? | the kernel's walk — component by component, following each link as it goes | `realpath` in `dsh-fs-local` / `checkedTarget` in `dsh-fs-sandbox` |
| Where did the author think it lands? | the same walk, **stopped where it first enters a writable root** | nobody |

The second reading is what makes a refusal explainable, and it cannot be assumed
from the first. Two traps make it a real computation rather than a string prefix:

- **`link/../x`.** Lexical collapsing says `<workspace>/x`; the kernel follows
  `link` out of the workspace first and never comes back. A comparison that
  collapses `..` before resolving the link is wrong about a path a shell would
  resolve correctly.
- **The root itself has more than one spelling.** On darwin `/var` is a link to
  `/private/var`, so `/var/folders/…/ws/link/out.txt` and
  `/private/var/folders/…/ws/link/out.txt` name the same directory — and only the
  second begins with the canonical root text that `writableRoots()` derives.
  Comparing a canonicalized target against an uncollapsed operand (or the reverse)
  gets one of these two cases wrong, and they fail in opposite directions: one
  misses escapes, the other blames a legal write.

So the plugin walks once and records both readings: the canonical cursor (what the
kernel will do) and the cursor at the depth the path first entered a writable root,
with the remaining components re-appended untouched (what the author said).

## What it does

Mounted on the public **`tools/pre-execute`** waterfall, for each call that writes
a named path operand:

1. extracts the operands from the tool's declared arguments (never from text
   heuristics — see [Tools and fields](#tools-and-fields));
2. resolves the per-call policy through `ctx.sandboxPolicy.resolve({ session })` —
   the same service call `tool-fs` makes — and derives the roots with
   `writableRoots()`, the module that owns the derivation, so the guard cannot
   invent a boundary the fence disagrees with;
3. walks each operand; if it reads as inside a root and lands outside every one,
   the call is refused with `REPARSE_ESCAPE_BLOCKED`;
4. otherwise delegates to `next()`, unchanged.

The refusal is a model-visible error result in the shape the registry already
produces for a pre-dispatch denial:

```
Error: refused by reparse-escape-guard: this path operand of "write" reads as inside the write area and resolves outside it.

"/ws/link/out.txt"
  as written:              /private/var/…/ws/link/out.txt  (inside /private/var/…/ws)
  actually resolves to:    /private/etc/out.txt  (outside every writable root)
  the link:                /private/var/…/ws/link

Nothing was dispatched. Writes are confined to: /private/var/…/ws, /tmp, /private/var/folders/…/T.
A path whose spelling sits inside that area but whose resolution leaves it is refused before the tool runs, …
Either name the resolved location directly, or — where the tool advertises it — request the wider access this call needs (sandbox_permissions with a justification).
```

## Install

```sh
npm install @argszero/cordis-plugin-reparse-escape-guard
```

The package ships a bundle patch; a profile picks it up by adding it as a bundle, or
by inserting the row yourself:

```yaml
- insert:
    - id: reparse-escape-guard
      name: '@argszero/cordis-plugin-reparse-escape-guard'
```

## Configuration

| field | default | meaning |
|---|---|---|
| `mode` | `guard` | `guard` refuses, `observe` reports a diagnostic and dispatches, `off` does nothing |
| `action` | `deny` | how a guarded call stops: `deny` directly, or `ask` through the approval service (which fails closed when none is mounted) |
| `extraWrites` | `{}` | tool name → argument fields that hold paths the call **writes**, for tools this package does not ship knowledge of |
| `shellFields` | `{}` | tool name → argument fields holding **shell text**, scanned for path-looking words (opt-in; see below) |
| `exempt` | `[]` | tool names this mount never inspects |
| `warnLimit` | `5` | diagnostics per mount; `0` silences them |

`ask` is offered because some deployments want a human in the loop for every
crossing; note that the harness cannot make the *write* succeed on the strength of
that approval — only an escalation grant widens the policy — so `deny` is the
default, and the message says what to do instead.

### Tools and fields

| tool | fields judged | notes |
|---|---|---|
| `write` | `file_path` | |
| `edit` | `file_path` | |
| `str_replace_editor` | `path` | except `command: view`, which inspects rather than writes |
| any other | — | silent; declare it with `extraWrites` if it writes a named path |

`read`, `glob` and `grep` are deliberately absent. No enforcement dialect restricts
reads — `writableRoots()` returns `[]` for anything that is not `workspace-write`,
and even then it is consulted on mutation paths alone — so a guard that reported a
read through an alias would refuse work the harness permits.

## What it does not do

- **It does not see effects, only declared operands.** A path reached any other way
  — a shell command line (unless a deployment opts in through `shellFields`), a
  tool nobody declared, an editor writing through its own protocol — is invisible
  here. That is a *miss*, never a false report: extraction can miss a path, and the
  judgement is exact about the paths it is handed.
- **It does not replace the fence.** Under `read-only` and `danger-full-access`
  there are no writable roots, so the plugin is inert by construction. In a
  composition whose filesystem does not confine at all, it is the only thing
  enforcing the declared mode — mount it with `mode: observe` if that is not what
  you want.
- **It leaves escalations alone.** A call carrying `sandbox_permissions` is handed
  to the approval flow, which shows the same paths to the same human; refusing it
  here would hide the request behind a second, unexplained gate. The cost: a call
  carrying the *standing* mode is not strictly wider, needs no approval, and
  therefore reaches the fence without this plugin's verdict — the write is still
  refused, just with the fence's sentence rather than this one.
- **It does not race the filesystem.** The verdict is computed from the filesystem
  at pre-dispatch time; a link swapped between the check and the write is the
  fence's problem, and the fence re-canonicalizes at the moment of publication.
- **It is not a sandbox.** It never reaches outside the process, never writes, and
  has no opinion about anything except whether a call's own path operands mean what
  they say.

## Development

```sh
npm install
npm test           # tsc, then the node:test suites
python3 mutations.py   # break each claim in lib/ and require the suite to go red
```

The suites are:

- `test/detect.spec.mjs` — the judgement as properties: the walk's kernel fidelity
  (`link/../x`), the root-spelling case, what is *not* a finding, and the operand
  extraction.
- `test/guard.spec.mjs` — a real Cordis context, a real `ToolRuntime`, a real
  `tools/pre-execute` waterfall and a real `SandboxPolicyService`, with an unmounted
  **control arm** that shows the same call being dispatched when nothing guards it.
- `test/fence.spec.mjs` — the same operand put to the real confining filesystem and
  to the guard, showing they agree on the verdict and differ only in diagnosis.
- `test/packaging.spec.mjs` — the published artifact declares exactly the bare
  specifiers it imports (both directions), and the actual npm pack list contains
  every module the build emits plus every relative import reachable from the
  entry point. This one was earned: `0.1.0` shipped with `files: ["lib/index.js"]`
  and installed broken, which is why the guard now reads npm's own pack list
  instead of trusting the manifest's intent.

## Compatibility

Built and tested against the `dsh` 0.1.7 alpha line
(`@deepseek-ai/dsh-tools` / `dsh-sandbox` / `dsh-sandbox-policy`
`0.1.7-alpha.2`), and declaring the 0.1.2 → 0.1.7 prerelease lines as peers. Public
APIs are pre-stable; the plugin uses only `tools/pre-execute`, `ctx.sandboxPolicy`
and the `@deepseek-ai/dsh-sandbox` root exports.

## License

MIT
