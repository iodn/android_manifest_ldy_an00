# SPDX-License-Identifier: Apache-2.0
"""Bounded host-only protocol tests; fixtures are not bootable firmware."""
import copy
import hashlib
import io
import json
import os
import sys
import types
from contextlib import ExitStack
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import first_install as install
import first_install_cohort as cohort
from prepare_install import sparse
from test_first_install import FakeInstaller, misc
from verify_install import decode


class BaselineLkTests(unittest.TestCase):
    def test_format2_keeps_the_exact_existing_lk_on_both_slots(self):
        original = json.loads((install.HERE / 'stock113-partitions.json').read_text())
        result = cohort.baseline(original)
        for slot in 'ab':
            self.assertEqual(result['lk_' + slot], {'bytes': 16777216,
                'sha256': '7d8762ef876b29542e66d0e717cd9af253602b3d86e93e7780ef5c2eb3686eae'})
            self.assertNotIn('lk_' + slot, cohort.MUTABLE)
            self.assertEqual(original['lk_' + slot]['sha256'],
                'a6a1ab4b6c55053887a0a18a52723bb48514a42bc45a507087ded09917385d81')
        self.assertEqual(install.mutable_partitions({'format_version': 1}), install.MUTABLE)


class RangeTests(unittest.TestCase):
    def test_all_untouched_bytes_and_three_ranges(self):
        baseline = bytes(range(251)) * 140
        replacements = [(4096, b'S' * 4096), (16384, b'F' * 4096), (24576, b'D' * 8192)]
        expected = bytearray(baseline)
        for offset, data in replacements:
            expected[offset:offset + len(data)] = data
        for chunk in (1, 513, 4096, 4097, 65536):
            old, new = cohort.overlay_ranges_hash(io.BytesIO(baseline),
                [(offset, io.BytesIO(data)) for offset, data in replacements], len(baseline), chunk)
            self.assertEqual(old, hashlib.sha256(baseline).hexdigest())
            self.assertEqual(new, hashlib.sha256(expected).hexdigest())

    def test_overlap_negative_and_overflow_are_rejected(self):
        for ranges in ([(0, b'1234'), (3, b'56')], [(-1, b'x')], [(99, b'xx')], [(1, b'')]):
            with self.subTest(ranges=ranges), self.assertRaises(ValueError):
                cohort.overlay_ranges_hash(io.BytesIO(bytes(100)), [(p, io.BytesIO(b)) for p, b in ranges], 100)

    def test_truncated_or_overlong_baseline_stops(self):
        for size in (99, 101):
            with self.assertRaises(ValueError):
                cohort.overlay_ranges_hash(io.BytesIO(bytes(size)), [(10, io.BytesIO(b'x'))], 100)


class CohortPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.files, cls.logical = {}, {}
        sizes = {'boot': 67108864, 'recovery_ramdisk': 67108864,
                 'vbmeta': 1048576, 'recovery_vbmeta': 1048576,
                 'vbmeta_system': 1048576, 'vbmeta_system_dlkm': 1048576, 'system_dlkm': 8192}
        for name, size in sizes.items():
            p = cls.root / (name + '.img')
            with p.open('wb') as f:
                f.truncate(size)
                f.write(name.encode())
            cls.logical[name] = p.name
            cls.files[p.name] = {'bytes': size, 'sha256': cohort.digest(p)}
        cls.contract = {'schema_version': 1, 'inputs': [dict(partition=n, file=n + '.img',
            file_bytes=sizes[n], partition_bytes=sizes[n], payload_new_partition_bytes=sizes[n],
            sha256=cls.files[cls.logical[n]]['sha256']) for n in ('boot', 'system_dlkm', 'vbmeta_system_dlkm')]}
        (cls.root / 'contract.json').write_text(json.dumps(cls.contract))
        cls.files['contract.json'] = {'bytes': (cls.root / 'contract.json').stat().st_size,
                                     'sha256': cohort.digest(cls.root / 'contract.json')}
        cls.system = b'S' * (8192 - 64) + b'AVBf' + bytes(60)
        sparse(cls.root / 'system.sparse', 1048576, cls.system)
        cls.footer = b'F' * (4096 - 64) + cls.system[-64:]
        sparse(cls.root / 'footer.sparse', 1048576 + 4345298944 - 4096, cls.footer)
        sparse(cls.root / 'dlkm.sparse', cohort.DLKM_START, (cls.root / cls.logical['system_dlkm']).read_bytes())
        for n in ('system.sparse', 'footer.sparse', 'dlkm.sparse'):
            cls.files[n] = {'bytes': (cls.root / n).stat().st_size, 'sha256': cohort.digest(cls.root / n)}
        cls.original = json.loads((install.HERE / 'stock113-partitions.json').read_text())
        cls.before = cohort.baseline(cls.original)
        cls.after = copy.deepcopy(cls.before)
        cls.images = {name + '_' + slot: cls.logical[name] for name in cohort.PHYSICAL for slot in 'ab'}
        for name, file in cls.images.items():
            cls.after[name] = dict(cls.files[file])
        cls.after['super']['sha256'] = '1' * 64
        cls.files['userdata'] = {'bytes': 1, 'sha256': 'c56829494610a5b534a815fb01323a772af4a08bd3f86f66268530e680de217d'}
        cls.files['metadata'] = {'bytes': 1, 'sha256': '2f8f105f8b830bfac31c7e91404f827b95a4d80024110df8f731b3856ad989f0'}
        cls.images.update(userdata='userdata', metadata='metadata')
        cls.manifest = dict(format_version=2, model='LDY-AN00', firmware='10.0.0.113(C00E100R101P1)',
            files=cls.files, images=cls.images, before=cls.before, after=cls.after, cohort_images=cls.logical,
            kernel_contract='contract.json', system_pieces=['system.sparse'], footer_piece='footer.sparse',
            dlkm_pieces=['dlkm.sparse'], system_bytes=len(cls.system), system_sha256=hashlib.sha256(cls.system).hexdigest(),
            geometry={'super': cohort.SUPER, 'userdata': 489917775872, 'metadata': 67108864, 'misc': 2097152})

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def validate(self, manifest=None):
        def checked(root, name, row):
            # Existing checked_file tests cover payload authentication; filesystem constants are
            # not real formatter images in this metadata-only packet fixture.
            return root / name
        with patch.multiple(cohort, DLKM_BYTES=8192,
                MAIN_PARENT=self.files[self.logical['vbmeta']]['sha256'],
                RECOVERY_PARENT=self.files[self.logical['recovery_vbmeta']]['sha256'],
                RECOVERY_RAMDISK=self.files[self.logical['recovery_ramdisk']]['sha256']):
            return cohort.validate(self.root, manifest or self.manifest, self.original, checked, decode)

    def test_complete_cohort_packet_is_accepted(self):
        before, after = self.validate()
        self.assertEqual(before, self.before)
        self.assertEqual(after, self.after)

    def test_every_missing_physical_image_is_rejected(self):
        for name in cohort.MUTABLE - {'super'}:
            m = copy.deepcopy(self.manifest); del m['images'][name]
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'write set'):
                self.validate(m)

    def test_old_or_unknown_lk_is_not_a_format2_baseline(self):
        for value in ('a6a1ab4b6c55053887a0a18a52723bb48514a42bc45a507087ded09917385d81', 'f' * 64):
            m = copy.deepcopy(self.manifest)
            for slot in 'ab': m['before']['lk_' + slot]['sha256'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'baseline'):
                self.validate(m)

    def test_after_cannot_replace_the_retained_lk_with_old_patch(self):
        m = copy.deepcopy(self.manifest)
        for slot in 'ab':
            m['after']['lk_' + slot]['sha256'] = 'a6a1ab4b6c55053887a0a18a52723bb48514a42bc45a507087ded09917385d81'
        with self.assertRaisesRegex(ValueError, 'retained'):
            self.validate(m)

    def test_incomplete_cohort_logical_set_is_rejected(self):
        m = copy.deepcopy(self.manifest); del m['cohort_images']['boot']
        with self.assertRaisesRegex(ValueError, 'artifact set'):
            self.validate(m)

    def test_changed_retained_lk_and_vendor_boot_rejected(self):
        for name in ('lk_a', 'lk_b', 'vendor_boot_a', 'init_boot_b', 'dtbo_a'):
            m = copy.deepcopy(self.manifest); m['after'][name]['sha256'] = 'f' * 64
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'retained'):
                self.validate(m)

    def test_swapped_slot_image_identity_rejected(self):
        m = copy.deepcopy(self.manifest); m['images']['boot_b'] = self.logical['recovery_ramdisk']
        with self.assertRaisesRegex(ValueError, 'cohort mismatch'):
            self.validate(m)

    def test_wrong_system_digest_and_empty_dlkm_rejected(self):
        for key, value in [('system_sha256', 'f' * 64), ('dlkm_pieces', [])]:
            m = copy.deepcopy(self.manifest); m[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(m)

    def test_dlkm_cannot_reuse_the_system_range(self):
        m = copy.deepcopy(self.manifest); m['dlkm_pieces'] = ['system.sparse']
        with self.assertRaisesRegex(ValueError, 'Noncontiguous'):
            self.validate(m)

    def test_contract_hash_mismatch_rejected(self):
        paths = {name: self.root / file for name, file in self.logical.items()}
        for name in ('boot', 'system_dlkm', 'vbmeta_system_dlkm'):
            c = copy.deepcopy(self.contract)
            next(row for row in c['inputs'] if row['partition'] == name)['sha256'] = 'f' * 64
            with self.subTest(name=name), patch.object(cohort, 'DLKM_BYTES', 8192), self.assertRaisesRegex(ValueError, 'cohort image mismatch'):
                cohort.contract_images(c, paths)

    def test_wrong_golden_recovery_rejected(self):
        paths = {name: self.root / file for name, file in self.logical.items()}
        with patch.object(cohort, 'DLKM_BYTES', 8192), self.assertRaisesRegex(ValueError, 'tested boot/recovery cohort'):
            cohort.contract_images(self.contract, paths)


class TransactionTests(unittest.TestCase):
    def obj(self, fail=None):
        obj = FakeInstaller(fail=fail)
        obj.m.update(format_version=2, dlkm_pieces=['dlkm-0', 'dlkm-1'])
        obj.m['images'].update({name + '_' + slot: name + '.img' for name in cohort.PHYSICAL for slot in 'ab'})
        return obj

    def test_full_payload_children_before_parents_and_no_lk_write(self):
        obj = self.obj(); obj.install({'super': {}}, {'super': {}, 'lk_a': {}})
        written = [e[1] for e in obj.events if e[0] == 'flash']
        self.assertEqual(written[:5], ['super'] * 5)
        self.assertEqual(written[5:-2], [p for p, _ in cohort.physical_plan(obj.m['images'])])
        self.assertFalse(any(name.startswith(('lk_', 'vendor_')) for name in written))
        first_parent = min(written.index(name) for name in ('vbmeta_a', 'vbmeta_b', 'recovery_vbmeta_a', 'recovery_vbmeta_b'))
        self.assertTrue(all(written.index(name) < first_parent for name in
            ('boot_a', 'boot_b', 'recovery_ramdisk_a', 'recovery_ramdisk_b', 'vbmeta_system_dlkm_a', 'vbmeta_system_dlkm_b')))
        self.assertNotIn(('reboot',), obj.events)

    def test_every_new_flash_failure_stops_before_format_or_reboot(self):
        normal = self.obj(); normal.install({'super': {}}, {'super': {}, 'lk_a': {}})
        for failure in [e for e in normal.events if e[0] == 'flash' and e[1] not in ('userdata', 'metadata')]:
            obj = self.obj(failure)
            with self.subTest(failure=failure), self.assertRaises(RuntimeError):
                obj.install({'super': {}}, {'super': {}, 'lk_a': {}})
            self.assertFalse(any(e[0] in ('erase', 'reboot') for e in obj.events))
            self.assertNotIn(('state', 'COMPLETE'), obj.events)

    def test_failed_postwrite_hash_stops_before_data_format(self):
        obj = self.obj(('readback', 'after-system', False))
        with self.assertRaises(RuntimeError): obj.install({'super': {}}, {'super': {}, 'lk_a': {}})
        self.assertNotIn(('erase', 'userdata'), obj.events)


class DownloadGateTests(unittest.TestCase):
    def inspect(self, limit, wrong_gpt=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = dict(format_version=2, fastboot='fastboot', geometry={},
                images={'boot_a': 'boot.img'}, files={'boot.img': {'bytes': 67108864}})
            obj = install.Installer(root, manifest, 'TEST', root, root / 'state.json')
            layout = {'slot': 'a', 'cohort_partitions': {n: {'first_lba': a, 'last_lba': b,
                'bytes': (b - a + 1) * 4096} for n, (a, b) in cohort.GPT.items()}}
            if wrong_gpt: layout['cohort_partitions']['boot_a']['first_lba'] += 1
            obj.layout = {}
            def command(args):
                if args[0] == 'oem': return 'FB LockState: UNLOCKED'
                value = {'serialno': 'TEST', 'product': 'k6993v1_64', 'is-userspace': 'no',
                    'secure': 'yes', 'current-slot': 'a', 'max-download-size': hex(limit)}[args[1]]
                return args[1] + ': ' + value + '\n'
            obj.command = command
            with patch.object(install, 'check_receipt', return_value=layout), \
                 patch.object(install, 'capture_misc', return_value=misc()):
                obj.inspect()

    def test_upload_limit_must_fit_the_complete_raw_kernel(self):
        with self.assertRaisesRegex(ValueError, 'download limit'):
            self.inspect(67108863)
        self.inspect(67108864)

    def test_matching_size_but_shifted_gpt_start_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'GPT layout'):
            self.inspect(134217728, wrong_gpt=True)


class RebootChoiceTests(unittest.TestCase):
    def run_main(self, flags, version=2):
        events = []
        class Spy:
            def __init__(self, *args): pass
            def state(self, *args, **kwargs): pass
            def install(self, *args): events.append(('install',))
            def command(self, args): events.append(tuple(args))
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary); (root / 'layout.json').write_text('{}')
            original_open = Path.open
            def opened(path, *args, **kwargs):
                stream = original_open(path, *args, **kwargs)
                if path.suffix == '.lock':
                    stack.callback(stream.close)  # Model the CLI process lifetime explicitly.
                return stream
            stack.enter_context(patch.object(Path, 'open', opened))
            usb = types.ModuleType('usb'); usb.__path__ = []
            usb.core = types.ModuleType('usb.core'); usb.util = types.ModuleType('usb.util')
            stack.enter_context(patch.dict(sys.modules, {'usb': usb, 'usb.core': usb.core, 'usb.util': usb.util}))
            stack.enter_context(patch.dict(os.environ, {'XDG_STATE_HOME': str(root / 'state')}))
            stack.enter_context(patch.object(sys, 'argv', ['first_install.py', '--package', str(root),
                '--stock-backup', str(root / 'existing'), '--yes-erase-userdata', *flags]))
            stack.enter_context(patch.object(install, 'authenticate', return_value=dict(
                format_version=version, fastboot='fastboot', geometry={}, build_number='TEST')))
            stack.enter_context(patch.object(install, 'validate_packet', return_value=({}, {})))
            stack.enter_context(patch.object(install, 'check_receipt', return_value={}))
            stack.enter_context(patch.object(install, 'check_stock_backup'))
            stack.enter_context(patch.object(install.subprocess, 'check_output', return_value='TEST fastboot\n'))
            stack.enter_context(patch.object(install, 'Installer', Spy))
            install.main()
        return events

    def test_recovery_first_overrides_default_wrapper_android_reboot(self):
        events = self.run_main(['--reboot', '--reboot-recovery'])
        self.assertEqual(events, [('install',), ('reboot', 'recovery')])
        self.assertNotIn(('reboot',), events)

    def test_default_android_option_and_no_reboot_remain_supported(self):
        self.assertEqual(self.run_main(['--reboot'], version=1), [('install',), ('reboot',)])
        self.assertEqual(self.run_main([]), [('install',)])

    def test_old_format_cannot_offer_lineage_recovery_first(self):
        with self.assertRaisesRegex(ValueError, 'complete Lineage Recovery cohort'):
            self.run_main(['--reboot-recovery'], version=1)


if __name__ == '__main__':
    unittest.main()
