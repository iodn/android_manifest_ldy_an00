#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check required assets against this release's committed byte manifest."""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def check(directory, first_install):
    manifest = json.loads((HERE.parent / 'release/RC3/release.json').read_text())
    required = {'RC3-first-install-files.zip', 'fastboot-linux-x86_64.zip'}
    selected = [row for row in manifest['assets']
                if not first_install or row['file'] in required]
    if first_install and {row['file'] for row in selected} != required:
        raise ValueError('Incomplete first-install release manifest')
    for row in selected:
        path = directory / row['file']
        if path.is_symlink() or path.stat().st_size != row['bytes']:
            raise ValueError('Wrong asset size/type: ' + row['file'])
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if digest != row['sha256']:
            raise ValueError('Wrong asset hash: ' + row['file'])
        print('VERIFIED ' + row['file'])
    return len(selected)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--first-install', action='store_true')
    args = parser.parse_args()
    print('ASSETS_OK:', check(args.directory, args.first_install))
