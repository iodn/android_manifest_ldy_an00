#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify signed first-install packets or retained diagnostic overlays; host files only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def decode(path):
    with path.open('rb') as stream:
        header = stream.read(28)
        magic, major, minor, hs, cs, block, blocks, count, crc = struct.unpack('<I4H4I', header)
        if (magic, major, minor, hs, cs, block, blocks, count, crc) != (
                0xed26ff3a, 1, 0, 28, 12, 4096, 17574133760 // 4096, 3, 0):
            raise ValueError('Wrong sparse header')
        offset = 0
        writes = []
        for _ in range(count):
            kind, reserved, size, encoded = struct.unpack('<2H2I', stream.read(12))
            if reserved != 0:
                raise ValueError('Reserved sparse field')
            if kind == 0xcac1 and encoded == 12 + size * block:
                data = stream.read(size * block)
                if len(data) != size * block:
                    raise ValueError('Truncated raw data')
                writes.append((offset, data))
            elif kind != 0xcac3 or encoded != 12:
                raise ValueError('Unexpected sparse operation')
            offset += size * block
        if stream.read(1) or offset != blocks * block or len(writes) != 1:
            raise ValueError('Wrong sparse coverage')
        return writes[0]


def verify(release, packet):
    if (packet / 'installer.json').exists():
        # The public packet is authenticated before trusting any path or image identity.
        from first_install import authenticate, validate_packet
        manifest = authenticate(packet)
        before, after = validate_packet(packet, manifest)
        if release is not None:
            image = release / 'system.img'
            if image.stat().st_size != manifest['system_bytes'] or sha(image) != manifest['system_sha256']:
                raise ValueError('Maintainer system input differs from the signed installer')
        return {'status': 'SIGNED_FIRST_INSTALL_PACKET_VERIFIED',
                'format_version': manifest['format_version'], 'build_number': manifest['build_number'],
                'verified_partitions': len(after), 'physical_writes': len(manifest['images']) - 2,
                'phone_access': False, 'hardware_trial_verified': False}
    # Retained diagnostic overlay format, not the current public installer.
    manifest = json.loads((packet / 'install-files.json').read_text())
    expected = '32a0183ea9b7381da70585e0d7596183b1d80e39b0be18dc27233114cd465c84'
    image = release / 'system.img' if release else None
    if image is not None and sha(image) != expected:
        raise ValueError('Wrong RC3 system input')
    rows = manifest['pieces']
    prefix = hashlib.sha256()
    position = 1048576
    for row in rows[:-1]:
        path = packet / row['file']
        if sha(path) != row['sha256'] or path.stat().st_size != row['bytes']:
            raise ValueError('Sparse file identity mismatch')
        offset, data = decode(path)
        if offset != position or offset != row['write_start'] or len(data) != row['write_bytes']:
            raise ValueError('Noncontiguous or incorrect prefix')
        prefix.update(data)
        position += len(data)
    if position != 1048576 + 1991360512 or prefix.hexdigest() != expected:
        raise ValueError('Reconstructed system does not match release')
    footer_row = rows[-1]
    footer_file = packet / footer_row['file']
    if sha(footer_file) != footer_row['sha256']:
        raise ValueError('Footer piece identity mismatch')
    offset, data = decode(footer_file)
    if offset != 4346343424 or hashlib.sha256(data).hexdigest() != 'b95263bc4125550f34618b2e6c39f238f0c3f0644df7e5c90619e9ef716560da':
        raise ValueError('Footer does not match the hardware-tested correction')
    if image is not None:
        with image.open('rb') as stream:
            stream.seek(-64, 2)
            footer = stream.read(64)
        original_tail = (release / 'stock113-system-tail.bin').read_bytes()
        if data != original_tail[:-64] + footer:
            raise ValueError('Footer correction changes unexpected bytes')
    child = packet / 'vbmeta_system.full-1MiB.img'
    if sha(child) != '0e2f5a79d1dcbbfbf280808a625becac58d409b7a90969f69c5f8d61e024028b':
        raise ValueError('Wrong padded child')
    return {'status': 'HOST_OVERLAY_VERIFIED_HARDWARE_TRIAL_PENDING',
            'numbered_pieces': len(rows) - 1, 'footer_piece': 1,
            'prefix_sha256': prefix.hexdigest(), 'phone_access': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', type=Path, help='Optional maintainer raw-image cross-check')
    parser.add_argument('--packet', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.release, args.packet), indent=2))
