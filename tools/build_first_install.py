#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare an LDY-AN00 first-install directory; no signing, USB or publication."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import zipfile

from prepare_install import sparse, SYSTEM_START, SYSTEM_WINDOW, SUPER, TAIL_SHA
from first_install import FASTBOOT_SHA, PARENT_SHA, validate_packet

HERE = Path(__file__).resolve().parent
PIECE = 8 * 1024 * 1024


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def overlay_hash(baseline, system, footer, total, start, window, chunk=4 * 1024 * 1024):
    """Hash all original bytes and exactly the two declared replacement ranges."""
    system.seek(0, 2)
    size = system.tell()
    system.seek(0)
    if size > window - len(footer):
        raise ValueError('System prefix would overlap the fixed logical footer')
    old, new = hashlib.sha256(), hashlib.sha256()
    position = 0
    footer_start = start + window - len(footer)
    while data := baseline.read(chunk):
        if position + len(data) > total:
            raise ValueError('Baseline exceeds the declared partition')
        old.update(data)
        replaced = bytearray(data)
        lo, hi = max(position, start), min(position + len(data), start + size)
        if lo < hi:
            system.seek(lo - start)
            block = system.read(hi - lo)
            if len(block) != hi - lo:
                raise ValueError('Truncated system input')
            replaced[lo - position:hi - position] = block
        lo, hi = max(position, footer_start), min(position + len(data), footer_start + len(footer))
        if lo < hi:
            replaced[lo - position:hi - position] = footer[lo - footer_start:hi - footer_start]
        new.update(replaced)
        position += len(data)
    if position != total:
        raise ValueError('Truncated baseline')
    return old.hexdigest(), new.hexdigest()


def build(inputs, baseline_gzip, output, build_number):
    image, child, parent = [inputs / n for n in ('system.img', 'vbmeta_system.img', 'vbmeta-owner.flags0.img')]
    tail = inputs / 'stock113-system-tail.bin'
    if (not 0 < image.stat().st_size <= SYSTEM_WINDOW - 4096 or image.stat().st_size % 4096
            or child.stat().st_size != 4096 or child.read_bytes()[:4] != b'AVB0'
            or sha(parent) != PARENT_SHA or sha(tail) != TAIL_SHA):
        raise ValueError('Unqualified image inputs')
    with image.open('rb') as stream:
        stream.seek(-64, 2)
        footer = stream.read(64)
    if footer[:4] != b'AVBf':
        raise ValueError('Missing signed-system footer')
    output.mkdir(mode=0o700)
    (output / 'payload').mkdir()
    (output / 'tools').mkdir()
    profile = json.loads((HERE / 'stock113-partitions.json').read_text())
    after = {n: dict(r) for n, r in profile.items()}
    pieces = []
    with image.open('rb') as stream:
        offset = SYSTEM_START
        while data := stream.read(PIECE):
            name = 'payload/system-%03d.sparse' % len(pieces)
            sparse(output / name, offset, data)
            pieces.append(name)
            offset += len(data)
    patched_tail = tail.read_bytes()[:-64] + footer
    footer_name = 'payload/system-footer.sparse'
    sparse(output / footer_name, SYSTEM_START + SYSTEM_WINDOW - 4096, patched_tail)
    child_name, parent_name = 'payload/vbmeta_system.full.img', 'payload/vbmeta-parent.full.img'
    (output / child_name).write_bytes(child.read_bytes() + bytes(1048576 - 4096))
    shutil.copyfile(parent, output / parent_name)
    images = {n: parent_name if n in ('vbmeta_a', 'vbmeta_b') else child_name
              for n in ('vbmeta_a', 'vbmeta_b', 'vbmeta_system_a', 'vbmeta_system_b')}
    for n in ('userdata', 'metadata'):
        name = 'payload/' + n + '.sparse'
        shutil.copyfile(inputs / (n + '.original.sparse'), output / name)
        images[n] = name
    shutil.copyfile(inputs / 'ota.x509.pem', output / 'ota.x509.pem')
    for name in ('first_install.py', 'prepare_layout.py', 'check_partitions.py', 'hash_readonly.py', 'verify_install.py', 'stock113-partitions.json'):
        shutil.copyfile(HERE / name, output / 'tools' / name)
    shutil.copyfile(HERE.parent / 'flash.sh', output / 'flash.sh')
    (output / 'flash.sh').chmod(0o755)
    with zipfile.ZipFile(inputs / 'fastboot-linux-x86_64.zip') as archive:
        for name in archive.namelist():
            if name == 'platform-tools-ldy/fastboot' or name.startswith('platform-tools-ldy/licenses/'):
                destination = output / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(name) as reader, destination.open('xb') as writer:
                    shutil.copyfileobj(reader, writer)
    fastboot = 'platform-tools-ldy/fastboot'
    (output / fastboot).chmod(0o755)
    if sha(output / fastboot) != FASTBOOT_SHA:
        raise ValueError('Wrong qualified fastboot binary')
    print('Deriving the full-super readback hash from the verified stock stream...', flush=True)
    with gzip.open(baseline_gzip, 'rb') as baseline, image.open('rb') as source:
        original_sha, new_sha = overlay_hash(baseline, source, patched_tail, SUPER, SYSTEM_START, SYSTEM_WINDOW)
    if original_sha != profile['super']['sha256']:
        raise ValueError('Full stock-super baseline mismatch')
    after['super']['sha256'] = new_sha
    for n in ('vbmeta_a', 'vbmeta_b'):
        after[n]['sha256'] = sha(output / parent_name)
    for n in ('vbmeta_system_a', 'vbmeta_system_b'):
        after[n]['sha256'] = sha(output / child_name)
    readme = f'''# LineageOS first installation for HONOR LDY-AN00

Unofficial LineageOS 24.0 / Android 17 for HONOR LDY-AN00.

## Requirements

- HONOR LDY-AN00 with the verified 512 GB partition layout.
- Installed stock firmware 10.0.0.113(C00E100R101P1).
- The qualified LK patch installed and boot-tested on both slots.
- Existing root on stock Android for the small read-only GPT/layout check.
- ADB installed, USB debugging authorized, and the trusted root broker available.
- The supported stock partition baseline and a selected boot slot marked successful.
- The installer preserves the selected slot; A or B is supported.
- Linux x86_64, Python 3.11 or newer, OpenSSL and PyUSB (`python3-usb` on Debian/Ubuntu).
- At least 22 GB of free host storage for verified recovery backups.

Other storage capacities and stock firmware versions have not been validated
and are not supported by this package. The storage requirement describes the
verified partition layout, not an Android capacity limit. This package retains
Honor's kernel and vendor firmware; an unlocked bootloader alone does not establish
compatibility. Do not bypass layout/hash checks or downgrade solely to match them.

Installation erases user data. Save personal files first. Keep the phone powered
and connected until the installer completes. A stock system must match the exact
supported baseline; this first-install package is not an OTA update.

## Install

1. Extract the complete ZIP and open a terminal in this folder.
2. Connect the intended phone, with USB debugging authorized, then run:

```bash
python3 tools/prepare_layout.py --root-broker /data/local/tmp/su
adb reboot bootloader
bash flash.sh
```

3. Confirm `LAYOUT_VERIFIED` before entering fastboot. The root broker above is
   the one from the documented unlock procedure; use its actual path if different.
   If ADB itself is already root, omit `--root-broker /data/local/tmp/su`.
   The receipt expires after one hour and is specific to the selected device/slot.
4. Read the confirmation and type `INSTALL` to accept data erasure.
5. Wait for `INSTALL_VERIFIED` and the automatic reboot. Complete Android setup.

The full `super` readbacks are deliberately thorough and can take about 30 minutes
each on this bootloader. A long pause at `Verifying ... super` is expected. Keep
the phone connected and wait for verification to finish.

The layout step reads 28 KiB of GPT data and partition sizes; it never writes to
the phone or creates a firmware backup. Do not publish the generated `layout.json`
or device journals: they contain device identifiers.

The installer checks the package signature, image hashes, device state and full
stock partitions. It saves only the five OS partitions that it changes and verifies
written OS partitions before formatting user data. It preserves LK, kernel,
vendor firmware and calibration/security partitions.

## Reuse an existing stock backup

Keep one verified stock recovery set. If it already has a `RECOVERY.json`
verification receipt, reuse it instead of capturing the same partitions again:

```bash
bash flash.sh --stock-backup /path/to/stock-backup
```

This explicitly trusts the earlier backup verification. The installer checks the
saved receipt and file sizes/timestamps; it does not rehash those backup files.
The phone's complete partition hashes are still read and checked before writing.
A backup recorded by a completed installation is reused automatically. Otherwise,
the five OS partitions being replaced are saved once for recovery; unchanged
boot-chain partitions are checked without creating copies. Missing or changed
files cause a stop instead of an automatic replacement backup.

## If installation stops

Keep the phone connected in its current mode. Do not retry, reboot, switch slots
or delete the state journal to bypass a failure. The printed journal directory
contains the operation receipts and any newly created recovery inputs needed to inspect the
state. Automatic rollback is deliberately not performed after an unknown result.

This is a firmware-specific procedure. An interruption can leave the OS
unbootable. Keep the backups until successful boot and later OTA testing.

## Release identity

OTA certificate DER SHA-256:
`46fc26697072341a414473390b5a313b1385d09d058562985d8d1acbc8a3d06c`.
The manifest signature authenticates the packaged files. Private signing keys
are never included. This unofficial build retains the stock kernel/vendor;
its Android system patch level does not update those retained components.
'''
    (output / 'README.md').write_text(readme)
    files = {str(p.relative_to(output)): {'bytes': p.stat().st_size, 'sha256': sha(p)}
             for p in sorted(output.rglob('*')) if p.is_file()}
    manifest = {'format_version': 1, 'model': 'LDY-AN00', 'firmware': '10.0.0.113(C00E100R101P1)',
                'build_number': build_number, 'geometry': {'super': SUPER, 'userdata': 489917775872,
                    'metadata': 67108864, 'misc': 2097152}, 'before': profile, 'after': after,
                'files': files, 'fastboot': fastboot, 'system_pieces': pieces, 'footer_piece': footer_name,
                'system_bytes': image.stat().st_size, 'system_sha256': sha(image), 'images': images}
    validate_packet(output, manifest)
    (output / 'installer.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    return {'status': 'HOST_PACKET_PREPARED_MANIFEST_SIGNATURE_PENDING', 'pieces': len(pieces),
            'expected_full_super_sha256': new_sha, 'phone_actions': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--stock-super-gzip', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--build-number', required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.inputs, args.stock_super_gzip, args.output, args.build_number), indent=2))
