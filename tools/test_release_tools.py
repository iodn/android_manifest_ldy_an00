# SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile

import validate_ota_vendor_retention as retention

HERE = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


feed = module('make_feed')
prepare = module('prepare_install')
verify = module('verify_install')
partitions = module('check_partitions')


class ReleaseChecks(unittest.TestCase):
    def test_empty_getvar_is_not_treated_as_supported(self):
        with self.assertRaisesRegex(ValueError, 'Missing'):
            partitions.getvar('partition-size:super: \n', 'partition-size:super')

    def test_postwrite_profile_changes_only_planned_objects(self):
        before, after = partitions.profile('before'), partitions.profile('after')
        changed = {name for name in before if before[name] != after[name]}
        self.assertEqual(changed, {'super', 'vbmeta_a', 'vbmeta_b',
                                   'vbmeta_system_a', 'vbmeta_system_b'})
        self.assertEqual(len(before), 19)

    def package(self, path, device='ldy_an00'):
        metadata = dict(**{'ota-type': 'AB', 'pre-device': device,
                           'post-timestamp': '1793098709', 'post-sdk-level': '37',
                           'post-security-patch-level': '2026-10-01',
                           'ota-property-files': 'payload.bin:100:200'})
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('META-INF/com/android/metadata',
                             '\n'.join(k + '=' + v for k, v in metadata.items()))
            archive.writestr('payload_properties.txt', 'FILE_HASH=a\nMETADATA_HASH=b\n')
            manifest = retention.metadata.DeltaArchiveManifest()
            for name in ['system', 'vbmeta_system']:
                manifest.partitions.add().partition_name = name
            manifest.partial_update = True
            group = manifest.dynamic_partition_metadata.groups.add()
            group.name = retention.GROUP_NAME
            group.size = retention.GROUP_BYTES
            group.partition_names.append('system')
            raw = manifest.SerializeToString()
            archive.writestr('payload.bin', struct.pack('>4sQQI', b'CrAU', 2, len(raw), 0) + raw)

    def test_feed_matches_shipped_updater_protocol(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'update.zip'
            self.package(path)
            result = feed.entry(path, 'https://example.org/update.zip')
            self.assertEqual(result[0]['datetime'], 1793098709)
            self.assertEqual(result[0]['files'][0]['os_sdk_level'], 37)
            self.assertEqual(result[0]['files'][0]['size'], path.stat().st_size)
            self.assertNotIn('response', result[0])

    def test_feed_rejects_vendor_update(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'vendor.zip'
            self.package(path)
            with zipfile.ZipFile(path) as archive:
                members = {name: archive.read(name) for name in archive.namelist()}
            raw = members['payload.bin'][24:]
            manifest = retention.metadata.DeltaArchiveManifest()
            manifest.ParseFromString(raw)
            manifest.partitions.add().partition_name = 'vendor'
            raw = manifest.SerializeToString()
            members['payload.bin'] = struct.pack('>4sQQI', b'CrAU', 2, len(raw), 0) + raw
            with zipfile.ZipFile(path, 'w') as archive:
                for name, content in members.items():
                    archive.writestr(name, content)
            with self.assertRaisesRegex(retention.AdmissionError, 'exactly system'):
                feed.entry(path, 'https://example.org/vendor.zip')

    def test_feed_rejects_postinstall_hooks_before_hashing(self):
        from unittest.mock import patch
        for index in [0, 1]:
            for run, hook in [(True, ''), (True, 'bin/postinstall'),
                              (False, 'bin/postinstall')]:
                with self.subTest(partition=index, run=run, hook=hook):
                    with tempfile.TemporaryDirectory() as temporary:
                        path = Path(temporary) / 'hook.zip'
                        self.package(path)
                        with zipfile.ZipFile(path) as archive:
                            members = {name: archive.read(name) for name in archive.namelist()}
                        manifest = retention.metadata.DeltaArchiveManifest()
                        manifest.ParseFromString(members['payload.bin'][24:])
                        manifest.partitions[index].run_postinstall = run
                        manifest.partitions[index].postinstall_path = hook
                        raw = manifest.SerializeToString()
                        members['payload.bin'] = struct.pack('>4sQQI', b'CrAU', 2, len(raw), 0) + raw
                        with zipfile.ZipFile(path, 'w') as archive:
                            for name, content in members.items():
                                archive.writestr(name, content)
                        with patch.object(feed.hashlib, 'file_digest',
                                          side_effect=AssertionError('hashed refused package')):
                            with self.assertRaisesRegex(retention.AdmissionError,
                                                        'postinstall hooks'):
                                feed.entry(path, 'https://example.org/hook.zip')

    def test_feed_rejects_missing_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'missing.zip'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('payload_properties.txt', 'FILE_HASH=a')
            with self.assertRaisesRegex(retention.AdmissionError, 'exactly one'):
                feed.entry(path, 'https://example.org/missing.zip')

    def test_feed_rejects_other_model(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'wrong.zip'
            self.package(path, 'other_device')
            with self.assertRaisesRegex(ValueError, 'device'):
                feed.entry(path, 'https://example.org/update.zip')

    def test_feed_refuses_local_asset_url(self):
        with self.assertRaisesRegex(ValueError, 'HTTPS'):
            feed.entry(Path('missing.zip'), 'file:///tmp/update.zip')

    def test_overlay_writes_only_declared_range(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'overlay.sparse'
            prepare.sparse(path, 1048576, b'X' * 4096)
            offset, data = verify.decode(path)
            self.assertEqual(offset, 1048576)
            self.assertEqual(data, b'X' * 4096)

    def test_overlay_rejects_erase_fill_operation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'overlay.sparse'
            prepare.sparse(path, 1048576, b'X' * 4096)
            raw = bytearray(path.read_bytes())
            struct.pack_into('<H', raw, 28, 0xcac2)
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'operation'):
                verify.decode(path)

    def test_overlay_rejects_trailing_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'overlay.sparse'
            prepare.sparse(path, 1048576, b'X' * 4096)
            with path.open('ab') as stream:
                stream.write(b'garbage')
            with self.assertRaisesRegex(ValueError, 'coverage'):
                verify.decode(path)

    def test_wrong_system_stops_before_creating_packet(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'system.img').write_bytes(b'wrong')
            target = root / 'packet'
            with self.assertRaisesRegex(ValueError, 'system image'):
                prepare.build(root, target)
            self.assertFalse(target.exists())


if __name__ == '__main__':
    unittest.main()
