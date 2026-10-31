# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import sys
import types
import unittest
from unittest.mock import patch
import zlib

import first_install as install


def misc(record_change=None, virtual=None, command=b''):
    payload = bytearray(2097152)
    record = bytearray.fromhex('5f6100004243414201020000ff007f00000000000000000000000000d302e26e')
    if record_change:
        record_change(record)
        record[28:] = (zlib.crc32(record[:28]) & 0xffffffff).to_bytes(4, 'little')
    payload[2048:2080] = record
    if virtual is not None:
        payload[32768:32832] = virtual
    payload[:len(command)] = command
    return bytes(payload)


def virtual(status=0, version=2):
    return bytes([version]) + (0x56740ab0).to_bytes(4, 'little') + bytes([status, 0]) + bytes(57)


class FakeInstaller(install.Installer):
    def __init__(self, fail=None):
        self.events = []
        self.fail = fail
        self.stock_backup = None
        self.m = {'build_number': 'TEST', 'system_pieces': ['piece-0', 'piece-1'], 'footer_piece': 'footer',
                  'images': {n: n + '.img' for n in ('vbmeta_a', 'vbmeta_b', 'vbmeta_system_a', 'vbmeta_system_b', 'userdata', 'metadata')}}

    def event(self, value):
        self.events.append(value)
        if self.fail == value:
            raise RuntimeError('Injected failure')

    def inspect(self):
        self.event(('inspect',))

    def readback(self, phase, profile, backup=False):
        self.event(('readback', phase, backup))

    def flash(self, partition, name):
        self.event(('flash', partition, name))

    def command(self, args):
        self.event(tuple(args))

    def state(self, phase, **values):
        self.event(('state', phase))


class BootControlTests(unittest.TestCase):
    def test_supported_idle_records(self):
        for data in (misc(), misc(virtual=virtual()), misc(virtual=b'\xff' * 64)):
            self.assertEqual(install.check_misc(data)['merge_status'], 0)

    def test_crc_corruption_stops(self):
        data = bytearray(misc())
        data[2060] ^= 1
        with self.assertRaisesRegex(ValueError, 'CRC'):
            install.check_misc(data)

    def test_pending_boot_control_merge_stops_even_with_valid_crc(self):
        with self.assertRaisesRegex(ValueError, 'pending merge'):
            install.check_misc(misc(lambda r: r.__setitem__(9, r[9] | 0x40)))

    def test_all_pending_virtual_merge_states_stop(self):
        for status in (1, 2, 3, 4, 255):
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, 'Snapshot/merge'):
                install.check_misc(misc(virtual=virtual(status)))

    def test_unknown_virtual_message_version_stops(self):
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            install.check_misc(misc(virtual=virtual(version=17)))

    def test_unsuccessful_running_slot_stops(self):
        with self.assertRaisesRegex(ValueError, 'successful'):
            install.check_misc(misc(lambda r: r.__setitem__(12, r[12] & 0x7f)))

    def test_unknown_slot_suffix_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'boot-control'):
            install.check_misc(misc(lambda r: r.__setitem__(1, ord('x'))))

    def test_successful_b_is_supported_without_requiring_successful_a(self):
        def change(record):
            record[12] = 7
            record[14] = 0x9f
        result = install.check_misc(misc(change, virtual=virtual()), 'b')
        self.assertEqual(result['selected_slot'], 'b')
        self.assertTrue(result['selected_slot_successful'])

    def test_unsuccessful_selected_b_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'successful'):
            install.check_misc(misc(), 'b')

    def test_unknown_selected_slot_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unknown selected'):
            install.check_misc(misc(), 'c')

    def test_pending_recovery_command_stops(self):
        with self.assertRaisesRegex(ValueError, 'recovery/update'):
            install.check_misc(misc(command=b'boot-recovery'))

    def test_truncated_misc_stops(self):
        with self.assertRaisesRegex(ValueError, 'size'):
            install.check_misc(misc()[:-1])


class PackageTests(unittest.TestCase):
    def test_path_traversal_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            install.checked_file(Path('/unused'), '../payload.img', {'bytes': 1, 'sha256': '0' * 64})

    def test_symlink_is_not_accepted_as_a_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'image').write_bytes(b'x')
            (root / 'alias').symlink_to(root / 'image')
            row = {'bytes': 1, 'sha256': hashlib.sha256(b'x').hexdigest()}
            with self.assertRaisesRegex(ValueError, 'verification'):
                install.checked_file(root, 'alias', row)

    def test_corrupted_payload_stops(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'image').write_bytes(b'x')
            with self.assertRaisesRegex(ValueError, 'verification'):
                install.checked_file(root, 'image', {'bytes': 1, 'sha256': '0' * 64})

    def test_zero_exit_does_not_override_failed_fastboot_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            obj = install.Installer(root, {'fastboot': 'fastboot'}, 'TEST', root, root / 'state.json')
            result = subprocess.CompletedProcess([], 0, '', "Writing 'super' FAILED\n")
            with patch.object(install.subprocess, 'run', return_value=result), self.assertRaisesRegex(ValueError, 'receipt'):
                obj.command(['flash', 'super', 'piece'])


class LayoutAdmissionTests(unittest.TestCase):
    def test_valid_layout_replaces_unpublished_size_getvars(self):
        from test_prepare_layout import receipt
        import prepare_layout
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            obj = install.Installer(root, {'fastboot': 'fastboot', 'geometry': prepare_layout.GEOMETRY}, 'TEST', root, root / 'state.json')
            obj.layout = receipt()
            queries = []
            def command(args):
                queries.append(args)
                values = {'serialno': 'TEST', 'product': 'k6993v1_64', 'is-userspace': 'no',
                          'secure': 'yes', 'current-slot': 'b', 'max-download-size': '0x8000000'}
                return (args[1] + ': ' + values[args[1]] + '\n') if args[0] == 'getvar' else 'FB LockState: UNLOCKED'
            obj.command = command
            def change(r): r[14] = 0x9f
            with patch('prepare_layout.time.time', return_value=10001), patch.object(install, 'capture_misc', return_value=misc(change)):
                obj.inspect()
            self.assertFalse(any('partition-size:' in str(q) for q in queries))
            self.assertTrue((root / 'layout-verified.json').exists())

class BackupReuseTests(unittest.TestCase):
    def make_backup(self, root):
        profile = {n: {'bytes': 5, 'sha256': 'a' * 64} for n in install.MUTABLE}
        rows = {}
        for n in install.MUTABLE:
            p = root / (n + '.img.gz')
            p.write_bytes(b'saved')
            rows[n] = {'file': p.name, 'stored_bytes': 5,
                       'mtime_seconds': int(p.stat().st_mtime), 'identity': profile[n]}
        (root / 'RECOVERY.json').write_text(json.dumps({'format_version': 1, 'model': 'LDY-AN00', 'partitions': rows}))
        return profile

    def test_unchanged_verified_set_is_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            profile = self.make_backup(root)
            self.assertEqual(set(install.check_stock_backup(root, profile)['partitions']), install.MUTABLE)

    def test_missing_changed_wrong_or_unsafe_backup_is_rejected(self):
        for mutation in ('missing', 'changed', 'wrong_hash', 'unsafe', 'missing_partition'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                profile = self.make_backup(root)
                p = root / 'super.img.gz'
                receipt = json.loads((root / 'RECOVERY.json').read_text())
                if mutation == 'missing': p.unlink()
                elif mutation == 'changed': p.write_bytes(b'changed')
                elif mutation == 'wrong_hash': receipt['partitions']['super']['identity']['sha256'] = 'b' * 64
                elif mutation == 'unsafe': receipt['partitions']['super']['file'] = '../super.img.gz'
                else: del receipt['partitions']['super']
                (root / 'RECOVERY.json').write_text(json.dumps(receipt))
                with self.assertRaises(ValueError): install.check_stock_backup(root, profile)


class TransactionTests(unittest.TestCase):
    def run_failure(self, failure):
        obj = FakeInstaller(fail=failure)
        with self.assertRaises(RuntimeError):
            obj.install({'super': {}}, {'super': {}, 'lk_a': {}})
        self.assertNotIn(('reboot',), obj.events)
        self.assertNotIn(('state', 'COMPLETE'), obj.events)
        return obj.events

    def test_existing_backup_is_reused_with_full_device_hash_checks(self):
        obj = FakeInstaller()
        obj.stock_backup = Path('/existing-stock')
        with patch.object(install, 'check_stock_backup') as check:
            obj.install({'super': {}}, {'super': {}, 'lk_a': {}})
        check.assert_called_once_with(obj.stock_backup, {'super': {}}, install.MUTABLE)
        self.assertIn(('readback', 'before', False), obj.events)
        self.assertNotIn(('readback', 'before', True), obj.events)

    def test_changed_existing_backup_prevents_all_writes(self):
        obj = FakeInstaller()
        obj.stock_backup = Path('/existing-stock')
        with patch.object(install, 'check_stock_backup', side_effect=ValueError('changed')):
            with self.assertRaisesRegex(ValueError, 'changed'):
                obj.install({'super': {}}, {'super': {}})
        self.assertFalse(any(e[0] in ('flash', 'erase') for e in obj.events))

    def test_inspection_failure_prevents_all_writes(self):
        self.assertEqual(self.run_failure(('inspect',)), [('inspect',)])

    def test_incomplete_backups_prevent_all_writes(self):
        events = self.run_failure(('readback', 'before', True))
        self.assertFalse(any(e[0] in ('flash', 'erase') for e in events))

    def test_failed_piece_stops_without_retry_or_data_erase(self):
        event = ('flash', 'super', 'piece-1')
        events = self.run_failure(event)
        self.assertEqual(events[-1], event)
        self.assertEqual(events.count(event), 1)
        self.assertFalse(any(e[0] == 'erase' for e in events))

    def test_wrong_postwrite_hash_prevents_data_erase(self):
        events = self.run_failure(('readback', 'after-system', False))
        self.assertFalse(any(e[0] == 'erase' for e in events))

    def test_erase_failure_prevents_following_flash_or_second_erase(self):
        events = self.run_failure(('erase', 'userdata'))
        self.assertEqual(events[-1], ('erase', 'userdata'))
        self.assertNotIn(('erase', 'metadata'), events)

    def test_complete_flow_preserves_boot_chain_and_checks_before_wipe(self):
        obj = FakeInstaller()
        obj.install({'super': {}}, {'super': {}, 'lk_a': {}})
        self.assertLess(obj.events.index(('readback', 'after-system', False)), obj.events.index(('erase', 'userdata')))
        targets = {e[1] for e in obj.events if e[0] == 'flash'}
        self.assertEqual(targets, {'super', 'vbmeta_a', 'vbmeta_b', 'vbmeta_system_a', 'vbmeta_system_b', 'userdata', 'metadata'})
        self.assertEqual(obj.events[-1], ('state', 'COMPLETE'))
        self.assertNotIn(('reboot',), obj.events)


class MiscWireTests(unittest.TestCase):
    def capture(self, frame, stale=b'', tail=b''):
        class UsbTimeout(Exception):
            pass
        state = {'writes': [], 'released': 0, 'reads': 0}
        class Incoming:
            bEndpointAddress = 0x81
            bmAttributes = 2
            def read(self, size, timeout):
                state['reads'] += 1
                if state['reads'] == 1:
                    if stale:
                        return stale
                    raise UsbTimeout()
                if frame[0]:
                    data, frame[0] = frame[0][:size], frame[0][size:]
                    return data
                if tail:
                    return tail
                raise UsbTimeout()
        class Outgoing:
            bEndpointAddress = 1
            bmAttributes = 2
            def write(self, data, timeout):
                state['writes'].append(data)
                return len(data)
        class Interface(list):
            bInterfaceClass, bInterfaceSubClass, bInterfaceProtocol, bInterfaceNumber = 255, 66, 3, 0
        interface = Interface([Incoming(), Outgoing()])
        dev = types.SimpleNamespace(serial_number='TEST', get_active_configuration=lambda: [interface])
        usb = types.ModuleType('usb')
        usb.__path__ = []
        usb.core = types.ModuleType('usb.core')
        usb.core.find = lambda **kw: [dev]
        usb.core.USBTimeoutError = UsbTimeout
        usb.util = types.ModuleType('usb.util')
        usb.util.ENDPOINT_IN, usb.util.ENDPOINT_OUT = 0x80, 0
        usb.util.endpoint_type = lambda value: value & 3
        usb.util.endpoint_direction = lambda value: value & 0x80
        usb.util.claim_interface = lambda *a: None
        def release(*args):
            state['released'] += 1
        usb.util.release_interface = release
        usb.util.dispose_resources = lambda *a: None
        modules = {'usb': usb, 'usb.core': usb.core, 'usb.util': usb.util}
        return modules, state

    def test_valid_frame_sends_one_read_only_command(self):
        payload = misc()
        modules, state = self.capture([install.START + payload + install.TRAILER])
        with patch.dict(sys.modules, modules):
            self.assertEqual(install.capture_misc('TEST'), payload)
        self.assertEqual(state['writes'], [b'oem dump-storage misc\0'])
        self.assertEqual(state['released'], 1)

    def test_metadata_size_uses_one_exact_framed_read_without_saving_payload(self):
        payload = bytes(67108864)
        modules, state = self.capture([install.START + payload + install.TRAILER])
        with patch.dict(sys.modules, modules):
            self.assertEqual(len(install.capture_control_partition('TEST', 'metadata')), len(payload))
        self.assertEqual(state['writes'], [b'oem dump-storage metadata\0'])
        self.assertEqual(state['released'], 1)

    def test_unknown_control_partition_is_rejected_before_usb_access(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported control'):
            install.capture_control_partition('TEST', 'unknown')

    def test_stale_usb_input_prevents_command(self):
        modules, state = self.capture([b''], stale=b'previous response')
        with patch.dict(sys.modules, modules), self.assertRaisesRegex(ValueError, 'Pending USB'):
            install.capture_misc('TEST')
        self.assertEqual(state['writes'], [])

    def test_failed_terminal_response_stops_without_retry(self):
        modules, state = self.capture([install.START + misc() + b'DUMPENDFAIL'])
        with patch.dict(sys.modules, modules), self.assertRaisesRegex(ValueError, 'final status'):
            install.capture_misc('TEST')
        self.assertEqual(len(state['writes']), 1)

    def test_queued_tail_is_rejected_without_another_command(self):
        modules, state = self.capture([install.START + misc() + install.TRAILER], tail=b'excess')
        with patch.dict(sys.modules, modules), self.assertRaisesRegex(ValueError, 'framing'):
            install.capture_misc('TEST')
        self.assertEqual(len(state['writes']), 1)


if __name__ == '__main__':
    unittest.main()
