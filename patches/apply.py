#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Apply the pinned Honor deltas to clean source projects. Never commit or push."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import os

HERE = Path(__file__).resolve().parent


def git(path, *args, **kwargs):
    return subprocess.check_output(['git', '-C', str(path), *args], **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    projects = json.loads((HERE / 'series.json').read_text())['projects']
    prepared = []
    # Validate the whole series before changing any real index/worktree.
    for project in projects:
        root = (args.source / project['path']).resolve()
        root.relative_to(args.source.resolve())
        patch = HERE / project['patch']
        data = patch.read_bytes()
        if hashlib.sha256(data).hexdigest() != project['patch_sha256']:
            raise RuntimeError('Patch digest mismatch: ' + project['path'])
        if git(root, 'rev-parse', 'HEAD').decode().strip() != project['base_revision']:
            raise RuntimeError('Wrong base: ' + project['path'])
        if git(root, 'status', '--porcelain', '--untracked-files=all').strip():
            raise RuntimeError('Dirty project: ' + project['path'])
        with tempfile.TemporaryDirectory() as temporary:
            env = dict(os.environ, GIT_INDEX_FILE=str(Path(temporary) / 'index'))
            git(root, 'read-tree', 'HEAD', env=env)
            git(root, 'apply', '--cached', '--binary', '-', input=data, env=env)
            tree = git(root, 'write-tree', env=env).decode().strip()
            if tree != project['tree']:
                raise RuntimeError('Target tree mismatch: ' + project['path'])
        prepared.append((project, root, data))
    print('CHECK_OK: %d exact project trees' % len(prepared), flush=True)
    if args.apply:
        for project, root, data in prepared:
            git(root, 'apply', '--index', '--binary', '-', input=data)
            if git(root, 'write-tree').decode().strip() != project['tree']:
                raise RuntimeError('STOP: applied tree mismatch; inspect ' + project['path'])
        print('APPLY_OK: changes staged for review; no commit or push')


if __name__ == '__main__':
    main()
