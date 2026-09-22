"""Mutation harness for cordis-plugin-reparse-escape-guard.

Each mutation breaks one claim the suite makes, in the BUILT output (never in
src), and the suite must go red. A mutation whose suite stays green is a claim no
test actually holds — which is the only way to tell a suite that checks the guard
from a suite that merely runs it.

Run:  python3 mutations.py
"""
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
NODE = '/Users/argszero/.asdf/installs/nodejs/26.5.0/bin/node'

# (label, file, needle, replacement)
MUTATIONS = [
    ('a call asking for wider access is refused instead of being handed to the approval flow',
     'lib/index.js',
     "        if (args[ESCALATION_FIELD] !== undefined)\n            return next();",
     "        if (false)\n            return next();"),
    ('exempt is ignored',
     'lib/index.js',
     "        if (resolved.exempt.has(exec.name))\n            return next();",
     "        if (false)\n            return next();"),
    ('observe refuses instead of reporting',
     'lib/index.js',
     "        if (resolved.mode === 'observe') {",
     "        if (false) {"),
    ('every write is judged, including ones that never read as inside (false positives)',
     'lib/detect.js',
     "    if (apparent === undefined || apparentRoot === undefined)\n        return undefined;",
     "    if (false)\n        return undefined;"),
    ('a path that lands inside a root is reported anyway',
     'lib/detect.js',
     "    if (rootOf(resolved, options.roots, options.caseSensitive) !== undefined)\n        return undefined;",
     "    if (false)\n        return undefined;"),
    ('the responsible component is never named',
     'lib/detect.js',
     "        if (apparentRoot !== undefined && aliasAt === undefined && rootOf(resolvedHere, roots, caseSensitive) === undefined) {",
     "        if (false) {"),
    ('the walk advances the spelling instead of the kernel resolution, so `link/../x` looks contained',
     'lib/detect.js',
     "        cursor = resolvedHere;",
     "        cursor = candidate;"),
    ('reads are judged like writes (the editor\'s view command becomes an escape)',
     'lib/operands.js',
     "    if (spec.readsWhen !== undefined\n        && spec.readsWhen.values.includes(argumentString(argumentsValue, spec.readsWhen.field) ?? ''))\n        return [];",
     "    if (false)\n        return [];"),
    ('the shell scan offers every word instead of only path-looking ones',
     'lib/operands.js',
     "        if (!token.includes('/') && !token.includes('\\\\'))\n            continue;",
     "        if (false)\n            continue;"),
    ('the refusal never says where the path actually lands',
     'lib/presentation.js',
     "        `  actually resolves to:    ${finding.resolved}  (outside every writable root)`,\n",
     ""),
]


def run_suite():
    completed = subprocess.run(
        [NODE, '--test', 'test/guard.spec.mjs', 'test/detect.spec.mjs'],
        cwd=ROOT, capture_output=True, text=True, timeout=900,
    )
    return completed.returncode


def main():
    baseline = run_suite()
    if baseline != 0:
        print('baseline suite is already red; fix that before mutating')
        return 1
    print('baseline: green\n')

    survivors = []
    for label, relative, needle, replacement in MUTATIONS:
        path = os.path.join(ROOT, relative)
        original = open(path, encoding='utf-8').read()
        if needle not in original:
            print(f'!! needle not found for: {label} ({relative})')
            survivors.append(label)
            continue
        backup = path + '.orig'
        shutil.copyfile(path, backup)
        try:
            open(path, 'w', encoding='utf-8').write(original.replace(needle, replacement, 1))
            code = run_suite()
        finally:
            shutil.move(backup, path)
        status = 'red' if code != 0 else 'GREEN (survived)'
        print(f'{status:18} {label}')
        if code == 0:
            survivors.append(label)

    print(f'\n{len(MUTATIONS) - len(survivors)}/{len(MUTATIONS)} mutations killed')
    for label in survivors:
        print(f'  survived: {label}')
    return 1 if survivors else 0


if __name__ == '__main__':
    sys.exit(main())
