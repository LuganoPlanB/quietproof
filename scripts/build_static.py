#!/usr/bin/env python3
"""Package a static website with matched WASM, corresponding sources and licenses."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


def archive_sources(root, output, additions=()):
    names = set(git(root, 'ls-files', '-z').strip('\0').split('\0')) | set(additions)
    files = {}
    with output.open('wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=0, filename='') as compressed:
        with tarfile.open(fileobj=compressed, mode='w|') as bundle:
            for name in sorted(names):
                if not name or name.endswith('.org') or name.startswith('.gestalt/'):
                    continue
                path = root / name
                if path.is_symlink():
                    target = os.readlink(path)
                    if not path.resolve().is_relative_to(root.resolve()):
                        raise ValueError(f'Corresponding source symlink escapes repository: {name}')
                    info = tarfile.TarInfo(name)
                    info.type = tarfile.SYMTYPE
                    info.linkname = target
                    info.mode = 0o777
                    bundle.addfile(info)
                    files[name] = {'symlink': target}
                    continue
                if not path.is_file():
                    entry = git(root, 'ls-files', '--stage', '--', name)
                    if entry.startswith('160000 '):
                        files[name] = {'gitlink': entry.split()[1], 'included': False,
                                       'scope': 'Unused upstream reference submodule; configured build uses committed sources'}
                        continue
                    raise ValueError(f'Corresponding source missing: {name}')
                data = path.read_bytes()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                bundle.addfile(info, io.BytesIO(data))
                files[name] = hashlib.sha256(data).hexdigest()
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cross-work', type=Path, required=True)
    parser.add_argument('--sdk-source', type=Path, required=True)
    parser.add_argument('--theme-source', type=Path, default=ROOT.parent / 'vite-theme')
    parser.add_argument('--base', default='/')
    parser.add_argument('--allow-dirty', action='store_true', help='Local review only; record exact dirty sources')
    parser.add_argument('--source-addition', action='append', default=[], help='Explicit new local source path for review builds')
    args = parser.parse_args()
    if not re.fullmatch(r'/(?:[A-Za-z0-9_-]+/)*', args.base):
        parser.error('base must be / or slash-delimited simple path segments ending in /')
    for name in args.source_addition:
        if Path(name).is_absolute() or '..' in Path(name).parts or name.endswith('.org') or name.startswith('.gestalt/'):
            parser.error('source additions must be repository-relative deliverable files')
    pins = json.loads((ROOT / 'scripts/build-pins.json').read_text())
    sdk, theme = args.sdk_source.resolve(), args.theme_source.resolve()
    if (ROOT / 'node_modules/lugano-planb-vite-theme').resolve() != theme:
        parser.error('installed theme must resolve to the pinned theme source; run npm ci with the sibling checkout')
    for directory, expected in [(sdk, pins['longfellowCommit']), (theme, pins['themeCommit'])]:
        if git(directory, 'rev-parse', 'HEAD') != expected or git(directory, 'diff', 'HEAD', '--'):
            parser.error(f'Expected clean pinned dependency: {directory}')
    dirty = bool(git(ROOT, 'diff', 'HEAD', '--')) or bool(args.source_addition)
    if dirty and not args.allow_dirty:
        parser.error('release builds require clean tracked sources; --allow-dirty is local-review only')
    cross = args.cross_work.resolve()
    provenance = json.loads((cross / 'build-provenance.json').read_text())
    wasm = cross / 'quietproof-build/quietproof.wasm'
    if provenance['pins'] != pins or provenance['reactorSha256'] != sha(wasm):
        parser.error('reactor provenance/pins mismatch; rebuild WASM')
    if not args.allow_dirty and provenance['verifiedArchive'] != pins:
        parser.error('release builds require a checksum-verified installation from install_wasi.py')
    for name, digest in provenance['sourceFiles'].items():
        if sha(ROOT / name) != digest:
            parser.error(f'reactor source changed: {name}; rebuild WASM')
    environment = dict(os.environ, DOCS_BASE=args.base, QUIETPROOF_WASM=str(wasm), TZ='UTC', LC_ALL='C',
                       SOURCE_DATE_EPOCH=git(ROOT, 'show', '-s', '--format=%ct', 'HEAD'))
    subprocess.run(['npm', 'run', 'docs:build'], cwd=ROOT, env=environment, check=True)
    output = ROOT / 'docs/.vitepress/dist'
    # Remove a local development copy if present. Only the SHA256-named reactor
    # is part of a release; public/wasm is ignored and absent in clean CI.
    legacy = output / 'wasm/quietproof.wasm'
    legacy.unlink(missing_ok=True)
    notices = output / 'sources'
    notices.mkdir()
    sources = {
        'quietproof': archive_sources(ROOT, notices / 'quietproof.tar.gz', args.source_addition),
        'longfellow-zk': archive_sources(sdk, notices / 'longfellow-zk.tar.gz'),
        'vite-theme': archive_sources(theme, notices / 'vite-theme.tar.gz'),
    }
    (notices / 'source-manifest.json').write_text(json.dumps(sources, sort_keys=True, indent=2) + '\n')
    licenses = output / 'licenses'
    licenses.mkdir()
    shutil.copyfile(ROOT / 'COPYING', licenses / 'quietproof-GPL-3.0.txt')
    shutil.copyfile(sdk / 'LICENSE', licenses / 'longfellow-GPL-3.0.txt')
    shutil.copyfile(ROOT / 'LICENSES/Apache-2.0.txt', licenses / 'inherited-Apache-2.0.txt')
    theme_permission = ROOT / 'LICENSES/Plan-B-theme-permission.txt'
    shutil.copyfile(theme_permission, licenses / theme_permission.name)
    # Include licenses for the full locked JS dependency graph, including build
    # tools. This over-includes build-only notices rather than omitting runtime code.
    packages = json.loads((ROOT / 'package-lock.json').read_text())['packages']
    dependencies = []
    for name, metadata in sorted(packages.items()):
        if not name.startswith('node_modules/') or metadata.get('link'):
            continue
        directory = ROOT / name
        files = [p for p in sorted(directory.iterdir()) if p.is_file() and
                 re.match(r'^(licen[cs]e|copying|notice)([.\-_]|$)', p.name, re.I)] if directory.is_dir() else []
        entry = {'package': name, 'version': metadata.get('version'), 'license': metadata.get('license'), 'notices': []}
        for path in files:
            target = licenses / (name.replace('/', '__') + '__' + path.name)
            shutil.copyfile(path, target)
            entry['notices'].append(target.name)
        # npm omits platform-specific optional packages; retain their lock data.
        entry['installed'] = directory.is_dir()
        dependencies.append(entry)
    (licenses / 'dependencies.json').write_text(json.dumps(dependencies, sort_keys=True, indent=2) + '\n')
    (output / 'SOURCE-NOTICE.txt').write_text(
        'QuietProof: Copyright (C) 2026 Plan B Foundation; GPL-3.0-or-later.\n'
        'Dyne Longfellow ZK distribution: GPL-3.0; see licenses/longfellow-GPL-3.0.txt.\n'
        'Original upstream file copyright/license notices are preserved in the source archives.\n'
        'Corresponding sources and build scripts: sources/*.tar.gz and source-manifest.json.\n'
        'JavaScript/theme dependency notices: licenses/dependencies.json and bundled license texts.\n'
        'Plan B theme: owner-confirmed permission for this QuietProof deliverable (2026-10-28); see licenses/Plan-B-theme-permission.txt. Third-party licenses remain applicable.\n'
        'Toolchain archive, SHA256, source identities and compiler: build-provenance.json.\n'
        'WASI SDK distribution and source: https://github.com/WebAssembly/wasi-sdk/releases/tag/wasi-sdk-34\n'
        'This artifact needs a static HTTP host only; no runtime Node, RPC, keys or prover.\n')
    record = {'schema': 1, 'sourceCommit': git(ROOT, 'rev-parse', 'HEAD'), 'dirtyReviewBuild': dirty,
              'sourceDateEpoch': environment['SOURCE_DATE_EPOCH'], 'base': args.base,
              'packageLockSha256': sha(ROOT / 'package-lock.json'),
              'themeLicense': 'No license identifier declared in pinned theme package metadata; scoped owner authorization is recorded separately',
              'themePermission': {'basis': 'Project owner confirmation, 2026-10-28',
                                  'scope': 'Use of the owner\'s Plan B theme in this QuietProof deliverable',
                                  'themeCommit': pins['themeCommit'],
                                  'notice': 'licenses/' + theme_permission.name,
                                  'noticeSha256': sha(theme_permission)},
              'node': subprocess.check_output(['node', '--version'], text=True).strip(),
              'wasm': provenance, 'sourceManifestSha256': sha(notices / 'source-manifest.json')}
    (output / 'build-provenance.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    files = {str(p.relative_to(output)): sha(p) for p in sorted(output.rglob('*')) if p.is_file()}
    (output / 'asset-manifest.json').write_text(json.dumps(files, sort_keys=True, indent=2) + '\n')
    print(f'Static artifact: {output}; {len(files)} hashed files; base={args.base}; dirtyReviewBuild={dirty}')


if __name__ == '__main__':
    main()
