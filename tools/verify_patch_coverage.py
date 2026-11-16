#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify every maintained patch is present in the actual build workspace."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args], capture_output=True,
                            text=True, env=dict(os.environ, GIT_OPTIONAL_LOCKS='0'))
    if result.returncode:
        raise ValueError('Source project is not an accessible Git worktree')
    return result.stdout.strip()


def verify(source, series):
    source, series = Path(source).resolve(), Path(series).resolve()
    projects = json.loads(series.read_text())['projects']
    paths = [row['path'] for row in projects]
    if not projects or len(set(paths)) != len(paths):
        raise ValueError('Maintained project inventory is empty or duplicated')
    verified = []
    for row in projects:
        relative = Path(row['path'])
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Invalid maintained project path')
        root = (source / relative).resolve()
        try:
            root.relative_to(source)
            if not root.is_dir() or Path(git(root, 'rev-parse', '--show-toplevel')).resolve() != root:
                raise ValueError('Missing actual project worktree')
            if git(root, 'status', '--porcelain', '--untracked-files=all'):
                raise ValueError('Dirty source worktree')
            patch = (series.parent / row['patch']).resolve()
            patch.relative_to(series.parent)
            if hashlib.sha256(patch.read_bytes()).hexdigest() != row['patch_sha256']:
                raise ValueError('Maintained patch digest mismatch')
            actual = git(root, 'rev-parse', 'HEAD^{tree}')
            if actual != row['tree']:
                raise ValueError('Actual source tree differs from maintained target')
            if row.get('target_snapshot_tree', actual) != actual:
                raise ValueError('Target snapshot tree disagrees with maintained target')
        except (ValueError, OSError, KeyError) as error:
            raise ValueError(row['path'] + ': ' + str(error)) from error
        verified.append({'path': row['path'], 'tree': actual})
    return verified


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True,
                        help='Actual mounted workspace used by the compiler')
    parser.add_argument('--series', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'patches/series.json')
    args = parser.parse_args()
    try:
        projects = verify(args.source, args.series)
    except (ValueError, OSError, KeyError) as error:
        print('PATCH_COVERAGE_FAIL: ' + str(error), file=sys.stderr)
        return 1
    print(json.dumps({'status': 'PATCH_COVERAGE_OK', 'project_count': len(projects),
                      'projects': projects}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
