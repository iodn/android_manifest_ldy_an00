#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One exact main-LK storage read, streamed to hashes only; never flash admission."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import time

PARTITIONS = {'vbmeta_system_a': 1048576, 'vbmeta_system_b': 1048576, 'super': 17574133760, 'boot_a': 67108864, 'boot_b': 67108864, 'init_boot_a': 8388608, 'init_boot_b': 8388608, 'vendor_boot_a': 100663296, 'vendor_boot_b': 100663296, 'dtbo_a': 25165824, 'dtbo_b': 25165824, 'recovery_ramdisk_a': 67108864, 'recovery_ramdisk_b': 67108864, 'recovery_vbmeta_a': 1048576, 'recovery_vbmeta_b': 1048576, 'vbmeta_a': 1048576, 'vbmeta_b': 1048576, 'lk_a': 16777216, 'lk_b': 16777216}
START = b'INFOread data begin, please wait......DUMPSTART'
TRAILER = b'DUMPENDOKAY'
CHUNK = 65536
DEADLINE_SECONDS = 1800


class WireError(ValueError):
    pass


class DigestMismatch(ValueError):
    pass


class StreamVerifier:
    """Length-delimited binary payload: marker-like payload bytes are ordinary data."""
    def __init__(self, size, expected_sha256, backup=None):
        if size <= 0 or not re.fullmatch(r'[0-9a-fA-F]{64}', expected_sha256):
            raise ValueError('positive size and exact expected SHA-256 required')
        self.size, self.expected = size, expected_sha256.lower()
        self.count = 0
        self.backup = backup
        self.payload_hash = hashlib.sha256()
        self.wire_hash = hashlib.sha256()

    @property
    def expected_bytes(self):
        return len(START) + self.size + len(TRAILER)

    @property
    def complete(self):
        return self.count == self.expected_bytes

    def feed(self, data):
        view = memoryview(data)
        if self.count + len(view) > self.expected_bytes:
            raise WireError('excess frame bytes')
        offset = 0
        while offset < len(view):
            if self.count < len(START):
                end = min(len(view), offset + len(START) - self.count)
                if view[offset:end] != START[self.count:self.count + end - offset]:
                    raise WireError('start framing mismatch')
            elif self.count < len(START) + self.size:
                end = min(len(view), offset + len(START) + self.size - self.count)
                self.payload_hash.update(view[offset:end])
                if self.backup is not None and self.backup.write(view[offset:end]) != end - offset:
                    raise OSError("Short host backup write")
            else:
                pos = self.count - len(START) - self.size
                end = min(len(view), offset + len(TRAILER) - pos)
                if view[offset:end] != TRAILER[pos:pos + end - offset]:
                    raise WireError('end framing/final status mismatch')
            self.wire_hash.update(view[offset:end])
            self.count += end - offset
            offset = end

    def finish(self):
        if not self.complete:
            raise WireError('short frame')
        actual = self.payload_hash.hexdigest()
        if actual != self.expected:
            raise DigestMismatch('payload digest mismatch: ' + actual)
        return {'bytes': self.size, 'sha256': actual,
                'wire_bytes': self.count, 'wire_sha256': self.wire_hash.hexdigest(),
                'final_status': 'OKAY'}


def read_once(partition, expected, result, serial, backup=None):
    # Lazy imports ensure parser tests/imports/help never discover a USB device.
    import usb.core
    import usb.util

    parser = StreamVerifier(PARTITIONS[partition], expected, backup)
    devices = [d for d in usb.core.find(find_all=True, idVendor=0x18d1, idProduct=0xd00d)
               if d.serial_number == serial]
    if len(devices) != 1:
        raise RuntimeError('expected exactly one exact-serial USB device')
    dev = devices[0]
    claimed = False
    try:
        interfaces = [i for i in dev.get_active_configuration()
                      if (i.bInterfaceClass, i.bInterfaceSubClass,
                          i.bInterfaceProtocol) == (255, 66, 3)]
        if len(interfaces) != 1:
            raise RuntimeError('expected unique fastboot interface')
        intf = interfaces[0]
        incoming = [e for e in intf if usb.util.endpoint_type(e.bmAttributes) == 2
                    and usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN]
        outgoing = [e for e in intf if usb.util.endpoint_type(e.bmAttributes) == 2
                    and usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT]
        if len(incoming) != 1 or len(outgoing) != 1:
            raise RuntimeError('expected unique bulk endpoints')
        usb.util.claim_interface(dev, intf.bInterfaceNumber)
        claimed = True
        try:
            pending = incoming[0].read(CHUNK, timeout=500)
        except usb.core.USBTimeoutError:
            pending = b''
        if len(pending):
            raise RuntimeError('pending pre-command bytes; no command sent')
        command = ('oem dump-storage ' + partition).encode('ascii') + b'\0'
        # Mark ambiguous BEFORE write: a failed write can still reach the device.
        result['command_may_have_been_sent'] = True
        if outgoing[0].write(command, timeout=5000) != len(command):
            raise RuntimeError('short command transfer; completion unknown')
        deadline = time.monotonic() + DEADLINE_SECONDS
        while not parser.complete:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('total read deadline; completion unknown')
            data = incoming[0].read(CHUNK, timeout=max(1, min(5000, int(remaining * 1000))))
            # A USB ZLP ends a transfer, not necessarily the command's data stream.
            # Empty input is a parser no-op; the same total deadline still applies.
            parser.feed(data)
        # The expected OKAY is inside the frame. Probe once for queued excess.
        try:
            tail = incoming[0].read(CHUNK, timeout=500)
        except usb.core.USBTimeoutError:
            tail = b''
        if len(tail):
            raise WireError('pending post-frame bytes')
        result['read_frame_complete_and_tail_quiet'] = True
        result['observed_sha256'] = parser.payload_hash.hexdigest()
        result['wire_bytes'] = parser.count
        result['wire_sha256'] = parser.wire_hash.hexdigest()
        result.update(parser.finish())
    finally:
        # Never reset, set configuration/alternate, detach, retry or send another command.
        try:
            if claimed:
                usb.util.release_interface(dev, intf.bInterfaceNumber)
        finally:
            usb.util.dispose_resources(dev)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--serial', required=True)
    ap.add_argument('--backup', type=Path, help='Optional verified host backup; partial file remains on failure')
    ap.add_argument('--partition', choices=tuple(PARTITIONS), required=True)
    ap.add_argument('--sha256', required=True)
    ap.add_argument('--receipt', type=Path, required=True)
    ap.add_argument('--execute-read-only', action='store_true', required=True)
    args = ap.parse_args()
    if not re.fullmatch(r'[0-9a-fA-F]{64}', args.sha256):
        ap.error('expected SHA-256 must be exactly 64 hex characters')
    if not re.fullmatch('[A-Za-z0-9._-]{1,80}', args.serial):
        ap.error('serial must be the exact device USB serial')
    result = {'serial': args.serial, 'usb_id': '18d1:d00d', 'interface': [255, 66, 3],
              'partition': args.partition, 'expected_bytes': PARTITIONS[args.partition],
              'expected_sha256': args.sha256.lower(), 'terminal': False,
              'status': 'UNKNOWN_UNTIL_TERMINAL_RECEIPT',
              'command_may_have_been_sent': True, 'flash_admission': False,
              'automatic_retry_permitted': False}
    # Exclusive creation protects other receipts. Initial durable UNKNOWN handles process death.
    with args.receipt.open('x') as receipt:
        json.dump(result, receipt, indent=2)
        receipt.flush()
        os.fsync(receipt.fileno())
        directory = os.open(args.receipt.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        result['command_may_have_been_sent'] = False
        try:
            if args.backup is None:
                read_once(args.partition, args.sha256, result, args.serial)
            else:
                partial = args.backup.with_name(args.backup.name + '.partial')
                fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as backup:
                    read_once(args.partition, args.sha256, result, args.serial, backup)
                    backup.flush()
                    os.fsync(backup.fileno())
                os.link(partial, args.backup)
                partial.unlink()
                result['verified_backup'] = str(args.backup)
            result['status'], code = 'READ_ONLY_HASH_MATCH_NOT_FLASH_ADMISSION', 0
        except DigestMismatch as error:
            result['error'] = str(error)
            result['status'], code = 'READ_ONLY_COMPLETE_HASH_MISMATCH_NOT_FLASH_ADMISSION', 3
        except Exception as error:
            result['error'] = type(error).__name__ + ': ' + str(error)
            if result['command_may_have_been_sent']:
                result['status'], code = 'UNKNOWN_STOP_NO_SECOND_COMMAND', 4
            else:
                result['status'], code = 'REJECTED_BEFORE_STORAGE_COMMAND', 2
        result['terminal'], result['returncode'] = True, code
        receipt.seek(0)
        json.dump(result, receipt, indent=2)
        receipt.write('\n')
        receipt.truncate()
        receipt.flush()
        os.fsync(receipt.fileno())
    print(json.dumps(result))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
