#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare fixed-stock113 first-install files on the host. Does not access USB."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

SUPER = 17574133760
SYSTEM_START = 1048576
SYSTEM_WINDOW = 4345298944
BLOCK = 4096
PIECE = 60 * 1024 * 1024
SYSTEM_SHA = '32a0183ea9b7381da70585e0d7596183b1d80e39b0be18dc27233114cd465c84'
TAIL_SHA = '7083963accb4b408f2665a6c0f446bbe45b0dc2acd08137f32126d8559bfe758'
CHILD_SHA = '5091739fedb2111f1e7308ba5bfa570e7c5ef841191bc1e1c200535640774f58'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def sparse(path, offset, data):
    if offset % BLOCK or len(data) % BLOCK or offset + len(data) > SUPER:
        raise ValueError('Invalid overlay geometry')
    # DONT_CARE describes untouched bytes, never a request to erase them.
    with path.open('xb') as stream:
        stream.write(struct.pack('<I4H4I', 0xed26ff3a, 1, 0, 28, 12,
                                 BLOCK, SUPER // BLOCK, 3, 0))
        stream.write(struct.pack('<2H2I', 0xcac3, 0, offset // BLOCK, 12))
        stream.write(struct.pack('<2H2I', 0xcac1, 0, len(data) // BLOCK, len(data) + 12))
        stream.write(data)
        stream.write(struct.pack('<2H2I', 0xcac3, 0,
                                 (SUPER - offset - len(data)) // BLOCK, 12))
    return dict(file=path.name, bytes=path.stat().st_size, sha256=digest(path),
                write_start=offset, write_bytes=len(data))


def build(release, output):
    image = release / 'system.img'
    tail = release / 'stock113-system-tail.bin'
    child = release / 'vbmeta_system.img'
    if image.stat().st_size != 1991360512 or digest(image) != SYSTEM_SHA:
        raise ValueError('Wrong RC3 system image')
    if tail.stat().st_size != BLOCK or digest(tail) != TAIL_SHA:
        raise ValueError('Wrong stock113 tail block')
    if child.stat().st_size != BLOCK or digest(child) != CHILD_SHA:
        raise ValueError('Wrong RC3 child vbmeta')
    with image.open('rb') as stream:
        stream.seek(-64, 2)
        footer = stream.read(64)
    if footer[:4] != b'AVBf':
        raise ValueError('Missing signed image footer')
    output.mkdir(exist_ok=False)
    records = []
    with image.open('rb') as stream:
        offset = SYSTEM_START
        while data := stream.read(PIECE):
            records.append(sparse(output / ('system-%03d.sparse' % len(records)), offset, data))
            offset += len(data)
    patched = tail.read_bytes()[:-64] + footer
    records.append(sparse(output / 'system-footer.sparse',
                          SYSTEM_START + SYSTEM_WINDOW - BLOCK, patched))
    padded = output / 'vbmeta_system.full-1MiB.img'
    padded.write_bytes(child.read_bytes() + bytes(1048576 - BLOCK))
    report = dict(
        status='HOST_PREPARED_FRESH_STOCK_RC3_TRIAL_PENDING',
        supported_model='LDY-AN00', stock_version='10.0.0.113(C00E100R101P1)',
        userdata_bytes=489917775872, metadata_bytes=67108864,
        logical_sector_bytes=4096,
        super_bytes=SUPER, system_a_start=SYSTEM_START, system_a_bytes=SYSTEM_WINDOW,
        required_stock_super_sha256='0e169c2af2efa2aa24e26218ab7c2514ec4620140feb70b8e2e5db7b11cb668f',
        expected_post_install_super_sha256='f60bbab98932c49cab21cd9fed159653ec041e1242bc2197f6b34f69e4026be4',
        untouched_ranges_preserved=True, writes_lp_metadata=False,
        system_sha256=SYSTEM_SHA, child_full_sha256=digest(padded),
        footer_block_sha256=hashlib.sha256(patched).hexdigest(), pieces=records,
        reboot_performed=False, phone_access=False,
    )
    (output / 'install-files.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    from build_first_install import build as build_first_install
    parser = argparse.ArgumentParser(description='Prepare the complete signed-image first-install packet; host only.')
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--stock-super-gzip', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--build-number', required=True)
    parser.add_argument('--kernel-contract', type=Path, required=True)
    parser.add_argument('--kernel-contract-sha256', required=True)
    args = parser.parse_args()
    result = build_first_install(args.inputs, args.stock_super_gzip, args.output,
        args.build_number, args.kernel_contract, args.kernel_contract_sha256)
    print(json.dumps(result, indent=2))
