#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read the LDY-AN00 layout through existing Android root; never reboot or write the phone."""
import argparse
import base64
import json
from pathlib import Path
import re
import shlex
import struct
import subprocess
import time
import zlib

GEOMETRY = {'super': 17574133760, 'userdata': 489917775872,
            'metadata': 67108864, 'misc': 2097152}
BEGIN, END = 'LDY_LAYOUT_BEGIN_V1', 'LDY_LAYOUT_END_V1'
SCRIPT = """printf '\n%s\n' LDY_LAYOUT_BEGIN_V1
id -u
getprop ro.product.model
getprop ro.boot.slot_suffix
cat /proc/sys/kernel/random/boot_id
for part in super userdata metadata misc; do
 readlink -f /dev/block/by-name/$part
 blockdev --getsize64 /dev/block/by-name/$part
done
blockdev --getss /dev/block/sdc
dd if=/dev/block/sdc bs=4096 count=7 2>/dev/null | base64
printf '%s\n' LDY_LAYOUT_END_V1
"""


def parse_capture(data):
    lines = data.decode('utf-8').replace('\r', '').splitlines()
    if lines.count(BEGIN) != 1 or lines.count(END) != 1:
        raise ValueError('Missing or ambiguous root layout response')
    start, end = lines.index(BEGIN), lines.index(END)
    fields = lines[start + 1:end]
    if len(fields) < 14 or fields[0] != '0' or fields[1] != 'LDY-AN00':
        raise ValueError('Expected existing root on HONOR LDY-AN00')
    if fields[2] not in ('_a', '_b') or not re.fullmatch(r'[0-9a-f-]{36}', fields[3]):
        raise ValueError('Invalid Android slot or boot identity')
    geometry, aliases = {}, {}
    for i, name in enumerate(GEOMETRY):
        alias, value = fields[4 + i * 2:6 + i * 2]
        if not re.fullmatch(r'/dev/block/sdc[0-9]+', alias) or not value.isdecimal():
            raise ValueError('Unexpected block-device alias or size: ' + name)
        geometry[name] = int(value)
        aliases[name] = alias
    if geometry != GEOMETRY or fields[12] != '4096':
        raise ValueError('Unsupported device storage geometry')
    raw = base64.b64decode(''.join(fields[13:]), validate=True)
    if len(raw) != 7 * 4096:
        raise ValueError('Wrong GPT capture length')
    header = raw[4096:8192]
    if header[:8] != b'EFI PART':
        raise ValueError('Missing GPT header')
    size = struct.unpack_from('<I', header, 12)[0]
    if not 92 <= size <= 4096:
        raise ValueError('Unsupported GPT header length')
    copy = bytearray(header[:size])
    expected_crc = struct.unpack_from('<I', copy, 16)[0]
    copy[16:20] = bytes(4)
    if zlib.crc32(copy) & 0xffffffff != expected_crc:
        raise ValueError('GPT header CRC mismatch')
    lba, count, entry_size, crc = struct.unpack_from('<QIII', header, 72)
    if lba != 2 or not 0 < count <= 192 or entry_size != 128:
        raise ValueError('Unsupported GPT entry geometry')
    entries = raw[lba * 4096:lba * 4096 + count * entry_size]
    if len(entries) != count * entry_size or zlib.crc32(entries) & 0xffffffff != crc:
        raise ValueError('GPT entry-array CRC mismatch')
    found = {}
    for i in range(count):
        entry = entries[i * entry_size:(i + 1) * entry_size]
        if entry[:16] == bytes(16):
            continue
        name = entry[56:128].decode('utf-16le').split('\0', 1)[0]
        if name in GEOMETRY:
            if aliases[name] != '/dev/block/sdc' + str(i + 1):
                raise ValueError('GPT and by-name alias disagree: ' + name)
            first, last = struct.unpack_from('<QQ', entry, 32)
            if name in found or last < first or (last - first + 1) * 4096 != geometry[name]:
                raise ValueError('GPT and block-device size disagree: ' + name)
            found[name] = {'first_lba': first, 'last_lba': last, 'bytes': geometry[name]}
    if set(found) != set(GEOMETRY):
        raise ValueError('GPT is missing required partitions')
    ranges = sorted((r['first_lba'], r['last_lba']) for r in found.values())
    if any(left[1] >= right[0] for left, right in zip(ranges, ranges[1:])):
        raise ValueError('Overlapping target GPT partitions')
    return {'model': fields[1], 'slot': fields[2][1:], 'boot_id': fields[3],
            'geometry': geometry, 'partitions': found, 'gpt_crcs_valid': True}


def check_receipt(receipt, serial, geometry, now=None):
    now = time.time() if now is None else now
    stamp = receipt.get('captured_at')
    if (receipt.get('format_version') != 1 or receipt.get('serial') != serial
            or not isinstance(stamp, int) or not -60 <= now - stamp <= 3600):
        raise ValueError('Wrong device or stale Android layout receipt; prepare a fresh layout')
    result = parse_capture(base64.b64decode(receipt['capture_base64'], validate=True))
    if result['geometry'] != geometry:
        raise ValueError('Layout receipt differs from release geometry')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial')
    parser.add_argument('--root-broker', help='Existing trusted root broker, for example /data/local/tmp/su')
    parser.add_argument('--output', type=Path, default=Path(__file__).resolve().parent.parent / 'layout.json')
    args = parser.parse_args()
    rows = subprocess.check_output(['adb', 'devices'], text=True, timeout=15).splitlines()[1:]
    devices = [r.split()[0] for r in rows if len(r.split()) >= 2 and r.split()[1] == 'device']
    if len(devices) != 1 or (args.serial and args.serial != devices[0]):
        raise ValueError('Connect exactly one intended Android phone with authorized USB debugging')
    serial = devices[0]
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,80}', serial):
        raise ValueError('Invalid device serial')
    if args.root_broker:
        if not re.fullmatch(r'/[A-Za-z0-9_./-]+', args.root_broker):
            raise ValueError('Invalid existing root-broker path')
        # GhostLock brokers an interactive shell. Run the capture in one
        # noninteractive child so parent prompts cannot split the data frame.
        command = shlex.join([args.root_broker, '-c', shlex.join(['sh', '-c', SCRIPT])])
    else:
        command = shlex.join(['sh', '-c', SCRIPT])
    data = subprocess.check_output(['adb', '-s', serial, 'exec-out', command], timeout=45)
    receipt = {'format_version': 1, 'serial': serial, 'captured_at': int(time.time()),
               'capture_base64': base64.b64encode(data).decode('ascii')}
    result = check_receipt(receipt, serial, GEOMETRY)
    # This small per-session receipt replaces itself; it is not another firmware backup.
    with args.output.open('w') as stream:
        json.dump(receipt, stream, indent=2)
        stream.write('\n')
    print('LAYOUT_VERIFIED', result['model'], 'slot=' + result['slot'])
    print('Layout receipt: ' + str(args.output))
    print('Now run adb reboot bootloader, followed by bash flash.sh.')


if __name__ == '__main__':
    main()
