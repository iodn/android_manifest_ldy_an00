#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read/hash the exact stock113 install profile in main-LK. Never flash or reboot."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
FASTBOOT_SHA = '0c0d34c5276bf6d08920820413de810dc13fb191102fc8426ab0b32f5e02da4e'
POST_SUPER_SHA = 'f60bbab98932c49cab21cd9fed159653ec041e1242bc2197f6b34f69e4026be4'


def profile(phase):
    result = json.loads((HERE / 'stock113-partitions.json').read_text())
    if phase == 'after':
        result['super']['sha256'] = POST_SUPER_SHA
        for slot in 'ab':
            result['vbmeta_' + slot]['sha256'] = (
                'f880dc6de759168d537cb596c18ae3ec001a231d97712bbc4a94ec52debbc9d0')
            result['vbmeta_system_' + slot]['sha256'] = (
                '0e2f5a79d1dcbbfbf280808a625becac58d409b7a90969f69c5f8d61e024028b')
    return result


def getvar(output, variable):
    values = [line[len(variable) + 2:] for line in output.splitlines()
              if line.startswith(variable + ': ')]
    if len(values) != 1 or not values[0]:
        raise ValueError('Missing/ambiguous fastboot variable: ' + variable)
    return values[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--fastboot', type=Path, required=True)
    parser.add_argument('--phase', choices=['before', 'after'], required=True)
    parser.add_argument('--reports', type=Path, required=True)
    parser.add_argument('--backup-dir', type=Path)
    args = parser.parse_args()
    if (args.phase == 'before') != (args.backup_dir is not None):
        parser.error('before requires a new backup-dir; after does not take one')
    with args.fastboot.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != FASTBOOT_SHA:
            raise ValueError('Use the exact qualified fastboot binary')
    rows = profile(args.phase)
    if args.backup_dir:
        args.backup_dir.parent.mkdir(parents=True, exist_ok=True)
        if shutil.disk_usage(args.backup_dir.parent).free < sum(r['bytes'] for r in rows.values()) + 1073741824:
            raise ValueError('Insufficient backup disk space; need about 20 GB free')
        args.backup_dir.mkdir(mode=0o700)
    args.reports.mkdir(mode=0o700, parents=True)
    command = [str(args.fastboot.resolve()), '-s', args.serial]
    for name, expected in [('serialno', args.serial), ('product', 'k6993v1_64'),
                           ('is-userspace', 'no'), ('current-slot', 'a'), ('secure', 'yes')]:
        reply = subprocess.run(command + ['getvar', name], capture_output=True,
                               text=True, timeout=15, check=True)
        if getvar(reply.stdout + reply.stderr, name) != expected:
            raise ValueError('Unsupported fastboot state: ' + name)
    lock = subprocess.run(command + ['oem', 'lock-state', 'info'], capture_output=True,
                          text=True, timeout=15, check=True)
    if 'FB LockState: UNLOCKED' not in lock.stdout + lock.stderr:
        raise ValueError('Qualified fastboot gate is not open')
    for index, (name, row) in enumerate(rows.items(), 1):
        print('Read-only check %d/%d: %s' % (index, len(rows), name), flush=True)
        receipt = args.reports / (name + '.json')
        read = [sys.executable, '-B', str(HERE / 'hash_readonly.py'),
                '--serial', args.serial, '--partition', name, '--sha256', row['sha256'],
                '--receipt', str(receipt), '--execute-read-only']
        if args.backup_dir:
            read += ['--backup', str(args.backup_dir / (name + '.img'))]
        # No automatic retry, second reader, restore or reboot on any exception.
        subprocess.run(read, check=True, timeout=1900)
        observed = json.loads(receipt.read_text())
        if not (observed['terminal'] and observed['returncode'] == 0
                and observed['sha256'] == row['sha256'] and observed['bytes'] == row['bytes']):
            raise ValueError('STOP: terminal readback receipt mismatch')
    result = {'phase': args.phase, 'partitions_verified': len(rows),
              'status': 'EXACT_READBACK_PROFILE_PASS', 'flash_performed': False,
              'reboot_performed': False, 'public_hardware_installer_qualified': False}
    (args.reports / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
