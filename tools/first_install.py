#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Install one authenticated LDY-AN00 stock113 release through main-LK fastboot."""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import time
import zlib

from check_partitions import FASTBOOT_SHA, getvar
from hash_readonly import START, TRAILER
from verify_install import decode

CERT_SHA = '46fc26697072341a414473390b5a313b1385d09d058562985d8d1acbc8a3d06c'
PARENT_SHA = 'f880dc6de759168d537cb596c18ae3ec001a231d97712bbc4a94ec52debbc9d0'
SUPER = 17574133760
START_SYSTEM = 1048576
SYSTEM_WINDOW = 4345298944
HERE = Path(__file__).resolve().parent


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def atomic_json(path, value):
    temporary = path.with_name(path.name + '.tmp')
    with temporary.open('w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def checked_file(root, name, row):
    relative = PurePosixPath(name)
    if (relative.is_absolute() or '..' in relative.parts or '\\' in name
            or not name or name != relative.as_posix()):
        raise ValueError('Unsafe package filename')
    path = root / name
    if (not path.resolve().is_relative_to(root.resolve()) or path.is_symlink()
            or not path.is_file() or path.stat().st_size != row['bytes']
            or sha(path) != row['sha256']):
        raise ValueError('Package file failed verification: ' + name)
    return path


def authenticate(root):
    cert = root / 'ota.x509.pem'
    data = cert.read_bytes()
    body = re.findall(rb'-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----', data, re.S)
    if len(body) != 1:
        raise ValueError('Expected one release certificate')
    der = base64.b64decode(re.sub(rb'\s', b'', body[0]), validate=True)
    if hashlib.sha256(der).hexdigest() != CERT_SHA:
        raise ValueError('Release certificate differs from the project identity')
    pub = subprocess.check_output(['openssl', 'x509', '-in', str(cert), '-pubkey', '-noout'])
    # /dev/stdin supplies only the public key; no private key belongs in an installer.
    subprocess.run(['openssl', 'dgst', '-sha256', '-verify', '/dev/stdin',
                    '-signature', str(root / 'installer.json.sig'), str(root / 'installer.json')],
                   input=pub, check=True, capture_output=True)
    return json.loads((root / 'installer.json').read_text())


def validate_packet(root, manifest):
    baseline = json.loads((HERE / 'stock113-partitions.json').read_text())
    if (manifest['format_version'] != 1 or manifest['model'] != 'LDY-AN00'
            or manifest['firmware'] != '10.0.0.113(C00E100R101P1)'
            or manifest['before'] != baseline):
        raise ValueError('Unsupported first-install profile')
    for name, row in manifest['files'].items():
        checked_file(root, name, row)
    if manifest['files'][manifest['fastboot']]['sha256'] != FASTBOOT_SHA:
        raise ValueError('Unqualified fastboot binary')
    after = manifest['after']
    if set(after) != set(baseline):
        raise ValueError('Post-install partition set differs')
    writable = {'super', 'vbmeta_a', 'vbmeta_b', 'vbmeta_system_a', 'vbmeta_system_b'}
    for name, row in after.items():
        if row['bytes'] != baseline[name]['bytes'] or not re.fullmatch('[0-9a-f]{64}', row['sha256']):
            raise ValueError('Invalid post-install partition identity')
        if name not in writable and row != baseline[name]:
            raise ValueError('Installer would change a retained partition')
    if (after['vbmeta_a']['sha256'] != PARENT_SHA or after['vbmeta_b']['sha256'] != PARENT_SHA
            or after['vbmeta_system_a'] != after['vbmeta_system_b']):
        raise ValueError('Unqualified parent/child metadata')
    position, digest = START_SYSTEM, hashlib.sha256()
    for name in manifest['system_pieces']:
        if manifest['files'][name]['bytes'] > 8 * 1024 * 1024 + 64:
            raise ValueError('Sparse upload exceeds the qualified piece limit')
        offset, data = decode(root / name)
        if offset != position or not data or len(data) > 8 * 1024 * 1024:
            raise ValueError('Noncontiguous system overlay')
        digest.update(data)
        position += len(data)
    if (position != START_SYSTEM + manifest['system_bytes']
            or not 0 < manifest['system_bytes'] <= SYSTEM_WINDOW
            or digest.hexdigest() != manifest['system_sha256']):
        raise ValueError('Reconstructed system image differs from the signed release')
    offset, footer = decode(root / manifest['footer_piece'])
    if (offset != START_SYSTEM + SYSTEM_WINDOW - 4096 or len(footer) != 4096
            or footer[-64:-60] != b'AVBf'):
        raise ValueError('Wrong logical-system footer placement')
    images = manifest['images']
    if set(images) != {'vbmeta_a', 'vbmeta_b', 'vbmeta_system_a', 'vbmeta_system_b', 'userdata', 'metadata'}:
        raise ValueError('Unqualified image write set')
    for partition, expected in {
        'userdata': 'c56829494610a5b534a815fb01323a772af4a08bd3f86f66268530e680de217d',
        'metadata': '2f8f105f8b830bfac31c7e91404f827b95a4d80024110df8f731b3856ad989f0',
    }.items():
        if manifest['files'][images[partition]]['sha256'] != expected:
            raise ValueError('Unqualified empty filesystem image: ' + partition)
    for name in writable - {'super'}:
        row = manifest['files'][images[name]]
        if row != after[name]:
            raise ValueError('Metadata image differs from its post-install identity')
    if manifest['geometry'] != {'super': SUPER, 'userdata': 489917775872, 'metadata': 67108864, 'misc': 2097152}:
        raise ValueError('Unsupported storage geometry')
    return baseline, after


def check_misc(payload):
    if len(payload) != 2097152:
        raise ValueError('Wrong misc partition size')
    record = payload[2048:2080]
    if (record[4:8] != b'BCAB' or record[8:12] != b'\x01\x02\0\0'
            or record[:4] != b'_a\0\0'
            or zlib.crc32(record[:28]) & 0xffffffff != int.from_bytes(record[28:32], 'little')):
        raise ValueError('Unsupported boot-control record, pending merge or invalid CRC')
    if not record[12] & 0x80 or not record[12] & 0x0f:
        raise ValueError('Running A slot is not successful and bootable')
    virtual = payload[32768:32832]
    if virtual not in (bytes(64), b'\xff' * 64):
        if (virtual[0] not in (1, 2) or int.from_bytes(virtual[1:5], 'little') != 0x56740ab0
                or virtual[5] != 0 or virtual[6] not in (0, 1)):
            raise ValueError('Snapshot/merge state is active or unsupported')
    command = payload[:32].split(b'\0', 1)[0]
    if command not in (b'', b'bootonce-bootloader'):
        raise ValueError('Pending recovery/update boot command')
    return {'crc_valid': True, 'successful_slot_a': True, 'merge_status': 0}


def capture_misc(serial):
    import usb.core
    import usb.util
    devices = [d for d in usb.core.find(find_all=True, idVendor=0x18d1, idProduct=0xd00d)
               if d.serial_number == serial]
    if len(devices) != 1:
        raise ValueError('Expected exactly one exact-serial main-LK USB device')
    dev = devices[0]
    interfaces = [i for i in dev.get_active_configuration()
                  if (i.bInterfaceClass, i.bInterfaceSubClass, i.bInterfaceProtocol) == (255, 66, 3)]
    if len(interfaces) != 1:
        raise ValueError('Expected a unique fastboot interface')
    intf = interfaces[0]
    incoming = [e for e in intf if usb.util.endpoint_type(e.bmAttributes) == 2
                and usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN]
    outgoing = [e for e in intf if usb.util.endpoint_type(e.bmAttributes) == 2
                and usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT]
    if len(incoming) != 1 or len(outgoing) != 1:
        raise ValueError('Expected unique bulk endpoints')
    claimed = False
    try:
        usb.util.claim_interface(dev, intf.bInterfaceNumber)
        claimed = True
        try:
            pending = incoming[0].read(65536, timeout=500)
        except usb.core.USBTimeoutError:
            pending = b''
        if len(pending):
            raise ValueError('Pending USB data; no misc read sent')
        cmd = b'oem dump-storage misc\0'
        if outgoing[0].write(cmd, timeout=5000) != len(cmd):
            raise ValueError('Misc command completion unknown')
        size = len(START) + 2097152 + len(TRAILER)
        wire = bytearray()
        deadline = time.monotonic() + 120
        while len(wire) < size:
            if time.monotonic() > deadline:
                raise TimeoutError('Misc read completion unknown')
            wire.extend(incoming[0].read(65536, timeout=5000))
            if len(wire) > size:
                raise ValueError('Excess misc frame bytes')
        try:
            tail = incoming[0].read(65536, timeout=500)
        except usb.core.USBTimeoutError:
            tail = b''
        if len(tail) or not wire.startswith(START) or not wire.endswith(TRAILER):
            raise ValueError('Misc framing/final status mismatch')
        return bytes(wire[len(START):-len(TRAILER)])
    finally:
        try:
            if claimed:
                usb.util.release_interface(dev, intf.bInterfaceNumber)
        finally:
            usb.util.dispose_resources(dev)


class Installer:
    def __init__(self, root, manifest, serial, directory, state_file):
        self.root, self.m, self.serial, self.directory, self.state_file = root, manifest, serial, directory, state_file
        self.fastboot = [str(root / manifest['fastboot']), '-s', serial]
        self.sequence = 0

    def state(self, phase, **values):
        atomic_json(self.state_file, dict(phase=phase, directory=str(self.directory), **values))

    def command(self, args):
        self.sequence += 1
        self.state('OPERATION_PENDING', operation=args, number=self.sequence)
        result = subprocess.run(self.fastboot + args, capture_output=True, text=True, timeout=180)
        atomic_json(self.directory / ('command-%03d.json' % self.sequence),
                    {'args': args, 'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
        result.check_returncode()
        output = result.stdout + result.stderr
        if args[0] in ('flash', 'erase'):
            verb = 'Writing' if args[0] == 'flash' else 'Erasing'
            if 'FAILED' in output or not re.search(verb + r'[^\n]*OKAY', output):
                raise ValueError('Missing successful fastboot write/erase receipt')
        self.state('OPERATION_COMPLETE', operation=args, number=self.sequence)
        return result.stdout + result.stderr

    def inspect(self):
        print('Checking supported device, storage geometry and update state...', flush=True)
        for name, expected in [('serialno', self.serial), ('product', 'k6993v1_64'),
                               ('is-userspace', 'no'), ('current-slot', 'a'), ('secure', 'yes')]:
            if getvar(self.command(['getvar', name]), name) != expected:
                raise ValueError('Unsupported fastboot state: ' + name)
        if 'FB LockState: UNLOCKED' not in self.command(['oem', 'lock-state', 'info']):
            raise ValueError('Patched LK fastboot gate is not open')
        for name, size in self.m['geometry'].items():
            observed = getvar(self.command(['getvar', 'partition-size:' + name]), 'partition-size:' + name)
            if int(observed, 16) != size:
                raise ValueError('Unsupported partition size: ' + name)
        if int(getvar(self.command(['getvar', 'max-download-size']), 'max-download-size'), 16) < 8 * 1024 * 1024 + 64:
            raise ValueError('Fastboot download limit too small')
        self.state('MISC_READ_PENDING')
        misc = capture_misc(self.serial)
        result = check_misc(misc)
        (self.directory / 'misc-before.img').write_bytes(misc)
        atomic_json(self.directory / 'boot-control.json', result)
        self.state('MISC_VERIFIED')

    def readback(self, phase, profile, backup=False):
        reports = self.directory / phase
        reports.mkdir()
        for index, (name, row) in enumerate(profile.items(), 1):
            print(('Backing up' if backup else 'Verifying') + ' %d/%d: %s (%d bytes)' % (index, len(profile), name, row['bytes']), flush=True)
            self.state('READBACK_PENDING', partition=name, read_phase=phase)
            receipt = reports / (name + '.json')
            argv = [sys.executable, '-B', str(HERE / 'hash_readonly.py'), '--serial', self.serial,
                    '--partition', name, '--sha256', row['sha256'], '--receipt', str(receipt), '--execute-read-only']
            if backup:
                argv += ['--backup', str(reports / (name + '.img'))]
            with (reports / (name + '.log')).open('x') as log:
                subprocess.run(argv, check=True, timeout=1900, stdout=log, stderr=subprocess.STDOUT)
            result = json.loads(receipt.read_text())
            if not (result['terminal'] and result['returncode'] == 0 and result['bytes'] == row['bytes'] and result['sha256'] == row['sha256']):
                raise ValueError('Incomplete or wrong partition readback: ' + name)
            self.state('READBACK_COMPLETE', partition=name, read_phase=phase)

    def flash(self, partition, name):
        print('Writing %s: %s' % (partition, Path(name).name), flush=True)
        path = checked_file(self.root, name, self.m['files'][name])
        self.command(['flash', partition, str(path)])

    def install(self, before, after):
        self.inspect()
        self.readback('before', before, backup=True)
        for name in [*self.m['system_pieces'], self.m['footer_piece']]:
            self.flash('super', name)
        for partition in ('vbmeta_system_a', 'vbmeta_system_b', 'vbmeta_a', 'vbmeta_b'):
            self.flash(partition, self.m['images'][partition])
        self.readback('after-system', after)
        for partition in ('userdata', 'metadata'):
            print('Formatting ' + partition + '...', flush=True)
            self.command(['erase', partition])
            self.flash(partition, self.m['images'][partition])
        retained = {n: r for n, r in after.items() if n not in ('super', 'vbmeta_a', 'vbmeta_b', 'vbmeta_system_a', 'vbmeta_system_b')}
        self.readback('after-format', retained)
        self.state('COMPLETE', build=self.m['build_number'], data_erased=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, default=HERE.parent)
    parser.add_argument('--serial')
    parser.add_argument('--backup-dir', type=Path)
    parser.add_argument('--yes-erase-userdata', action='store_true')
    parser.add_argument('--reboot', action='store_true')
    args = parser.parse_args()
    root = args.package.resolve()
    manifest = authenticate(root)
    before, after = validate_packet(root, manifest)
    fastboot = root / manifest['fastboot']
    devices = subprocess.check_output([str(fastboot), 'devices'], text=True, timeout=15).splitlines()
    serials = [line.split()[0] for line in devices if line.strip()]
    if len(serials) != 1 or (args.serial and args.serial != serials[0]):
        raise ValueError('Connect exactly one intended phone in bootloader fastboot')
    serial = serials[0]
    if not re.fullmatch('[A-Za-z0-9._-]{1,80}', serial):
        raise ValueError('Invalid USB serial')
    state_dir = Path(os.environ.get('XDG_STATE_HOME', str(Path.home() / '.local/state'))) / 'lineageos-ldy_an00'
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = (state_dir / (serial + '.lock')).open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    state_file = state_dir / (serial + '.json')
    if state_file.exists() and json.loads(state_file.read_text())['phase'] != 'COMPLETE':
        raise ValueError('Previous installation is incomplete; inspect its journal before another operation')
    directory = args.backup_dir or state_dir / (serial + '-' + time.strftime('%Y%m%dT%H%M%S'))
    directory.parent.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(directory.parent).free < sum(x['bytes'] for x in before.values()) + 1073741824:
        raise ValueError('Insufficient space for verified recovery backups; allow at least 22 GB')
    if not args.yes_erase_userdata:
        answer = input('This installs LineageOS and ERASES ALL USER DATA. Type INSTALL to continue: ')
        if answer != 'INSTALL':
            raise ValueError('Installation cancelled before any partition operation')
    directory.mkdir(mode=0o700)
    installer = Installer(root, manifest, serial, directory, state_file)
    installer.state('STARTED', build=manifest['build_number'])
    try:
        installer.install(before, after)
        print('INSTALL_VERIFIED', manifest['build_number'])
        if args.reboot:
            installer.command(['reboot'])
            installer.state('COMPLETE', build=manifest['build_number'], data_erased=True, reboot_requested=True)
    except BaseException:
        print('STOP: installation did not complete. Do not retry or reboot blindly. Journal: ' + str(directory), file=sys.stderr)
        raise


if __name__ == '__main__':
    main()
