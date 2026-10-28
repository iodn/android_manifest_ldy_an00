# SPDX-License-Identifier: Apache-2.0
import base64
import json
import struct
import unittest
import zlib
from unittest.mock import patch
import prepare_layout as layout


def capture():
    rows = {'misc': (1, 8, 519), 'metadata': (29, 252672, 269055),
            'super': (131, 792576, 5083135), 'userdata': (133, 5345280, 124954111)}
    raw = bytearray(28672)
    entries = bytearray(160 * 128)
    for name, (number, first, last) in rows.items():
        e = bytearray(128)
        e[:16] = bytes([1]) * 16
        struct.pack_into('<QQ', e, 32, first, last)
        encoded = name.encode('utf-16le')
        e[56:56 + len(encoded)] = encoded
        entries[(number - 1) * 128:number * 128] = e
    header = bytearray(4096)
    header[:8] = b'EFI PART'
    struct.pack_into('<II', header, 8, 0x10000, 92)
    struct.pack_into('<QIII', header, 72, 2, 160, 128, zlib.crc32(entries) & 0xffffffff)
    struct.pack_into('<I', header, 16, zlib.crc32(header[:92]) & 0xffffffff)
    raw[4096:8192] = header
    raw[8192:] = entries
    fields = [layout.BEGIN, '0', 'LDY-AN00', '_b', '12345678-1234-1234-1234-123456789abc']
    for name, size in layout.GEOMETRY.items():
        fields += ['/dev/block/sdc' + str(rows[name][0]), str(size)]
    fields += ['4096', base64.b64encode(raw).decode(), layout.END]
    return ('\n'.join(fields) + '\n').encode()


def receipt(data=None):
    return {'format_version': 1, 'serial': 'TEST', 'captured_at': 10000,
            'capture_base64': base64.b64encode(capture() if data is None else data).decode()}


class LayoutTests(unittest.TestCase):
    def test_fresh_receipt_and_gpt_agree(self):
        result = layout.check_receipt(receipt(), 'TEST', layout.GEOMETRY, now=10001)
        self.assertEqual(result['geometry'], layout.GEOMETRY)
        self.assertEqual(result['slot'], 'b')
        self.assertTrue(result['gpt_crcs_valid'])

    def test_existing_broker_prompts_outside_the_unique_frame_are_ignored(self):
        self.assertEqual(layout.parse_capture(b'HNLDY-M:/ #\n' + capture() + b'HNLDY-M:/ #')['slot'], 'b')

    def test_wrong_serial_expired_future_and_geometry_refused(self):
        for serial, now, geo in [('OTHER', 10001, layout.GEOMETRY), ('TEST', 13601, layout.GEOMETRY),
                                 ('TEST', 9900, layout.GEOMETRY), ('TEST', 10001, {})]:
            with self.subTest(serial=serial, now=now), self.assertRaises(ValueError):
                layout.check_receipt(receipt(), serial, geo, now=now)

    def test_missing_root_wrong_model_size_alias_and_duplicate_frame_refused(self):
        data = capture()
        for changed in [data.replace(b'\n0\n', b'\n2000\n', 1), data.replace(b'LDY-AN00', b'OTHER'),
                        data.replace(b'17574133760', b'17574133761'),
                        data.replace(b'/dev/block/sdc131', b'/dev/block/sdc132'),
                        data + layout.BEGIN.encode() + b'\n', data[:-len(layout.END) - 1]]:
            with self.subTest(data=changed[:70]), self.assertRaises(ValueError):
                layout.parse_capture(changed)

    def test_corrupt_gpt_header_entries_and_truncated_capture_refused(self):
        fields = capture().decode().splitlines()
        raw = bytearray(base64.b64decode(fields[-2]))
        for offset in [4096 + 16, 8192 + 56]:
            changed = bytearray(raw)
            changed[offset] ^= 1
            altered = fields[:]
            altered[-2] = base64.b64encode(changed).decode()
            with self.assertRaisesRegex(ValueError, 'CRC'):
                layout.parse_capture(('\n'.join(altered) + '\n').encode())
        fields[-2] = base64.b64encode(raw[:-1]).decode()
        with self.assertRaisesRegex(ValueError, 'length'):
            layout.parse_capture(('\n'.join(fields) + '\n').encode())


if __name__ == '__main__':
    unittest.main()
