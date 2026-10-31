#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Test retained filesystem input binding with the qualified extracted stock tree."""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from package import verify_auxiliary_tree


def main():
    source = Path(sys.argv[1])
    expected = json.loads(Path(__file__).with_name('auxiliary-files.json').read_text())
    verify_auxiliary_tree(source, expected)
    checks = 1
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory) / 'tree'
        root.mkdir()
        for row in expected:
            path = root / row['path']
            if row['type'] == 'directory':
                path.mkdir(parents=True, exist_ok=True)
            elif row['type'] == 'file':
                shutil.copy2(source / row['path'], path)
            else:
                path.symlink_to(row['target'])

        def refuse():
            try:
                verify_auxiliary_tree(root, expected)
            except ValueError:
                return
            raise AssertionError('Modified retained input was accepted')

        verify_auxiliary_tree(root, expected)
        checks += 1
        for row in expected:
            if row['type'] != 'file':
                continue
            path = root / row['path']
            original = path.read_bytes()
            stamp = path.stat()
            changed = bytes([original[0] ^ 1]) + original[1:]
            path.write_bytes(changed)
            os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            assert path.stat().st_size == len(original)
            assert path.stat().st_mtime_ns == stamp.st_mtime_ns
            refuse()
            checks += 1
            path.write_bytes(original)
            os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        load = root / 'lib/modules/modules.load'
        original = load.read_bytes()
        load.unlink()
        refuse()
        checks += 1
        outside = Path(directory) / 'same-content'
        outside.write_bytes(original)
        load.symlink_to(outside)
        refuse()
        checks += 1
        load.unlink()
        load.write_bytes(original)
        extra = root / 'lib/modules/unexpected.txt'
        extra.write_text('extra')
        refuse()
        checks += 1
        extra.unlink()
        verify_auxiliary_tree(root, expected)
        checks += 1
    print('AUXILIARY_TREE_BINDING_PASS checks=' + str(checks))


if __name__ == '__main__':
    main()
