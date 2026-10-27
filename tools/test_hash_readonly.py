# SPDX-License-Identifier: Apache-2.0
"""Host-only protocol tests. No USB imports, device discovery or CLI execution."""
import hashlib
import io
import sys
import tracemalloc
import types
import unittest
from unittest.mock import patch

from hash_readonly import (CHUNK, PARTITIONS, DigestMismatch, START,
                           TRAILER, StreamVerifier, WireError, read_once)


SERIAL = 'SYNTHETIC-TEST-SERIAL'

def framed(payload):
    return START + payload + TRAILER


def verifier(payload):
    return StreamVerifier(len(payload), hashlib.sha256(payload).hexdigest())


class StreamProtocolTests(unittest.TestCase):
    def test_backup_contains_payload_without_wire_markers(self):
        payload = b'\0payload' + START + TRAILER
        backup = io.BytesIO()
        parser = StreamVerifier(len(payload), hashlib.sha256(payload).hexdigest(), backup)
        for byte in framed(payload):
            parser.feed(bytes([byte]))
        parser.finish()
        self.assertEqual(backup.getvalue(), payload)

    def test_known_sha256_vector_and_wire_digest(self):
        p = StreamVerifier(3, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        p.feed(framed(b'abc'))
        r = p.finish()
        self.assertEqual(r['bytes'], 3)
        self.assertEqual(r['wire_sha256'], hashlib.sha256(framed(b'abc')).hexdigest())
        self.assertEqual(r['wire_bytes'], len(framed(b'abc')))

    def test_every_two_fragment_boundary(self):
        payload = bytes(range(256))
        wire = framed(payload)
        for split in range(len(wire) + 1):
            with self.subTest(split=split):
                p = verifier(payload)
                p.feed(wire[:split])
                p.feed(wire[split:])
                self.assertEqual(p.finish()['sha256'], hashlib.sha256(payload).hexdigest())

    def test_single_byte_fragments_and_binary_markers(self):
        payload = b'\0\xff' + START + b'DUMPENDOKAYFAILDATAINFO' + TRAILER + b'\0'
        p = verifier(payload)
        for value in framed(payload):
            p.feed(bytes([value]))
        self.assertEqual(p.finish()['bytes'], len(payload))

    def test_finish_rejects_every_truncation(self):
        payload = b'abcdefgh'
        wire = framed(payload)
        for length in range(len(wire)):
            with self.subTest(length=length):
                p = verifier(payload)
                p.feed(wire[:length])
                with self.assertRaises(WireError):
                    p.finish()

    def test_rejects_corruption_in_each_header_and_trailer_byte(self):
        payload = b'abcd'
        wire = framed(payload)
        positions = list(range(len(START))) + list(range(len(START) + len(payload), len(wire)))
        for position in positions:
            with self.subTest(position=position):
                bad = bytearray(wire)
                bad[position] ^= 1
                with self.assertRaises(WireError):
                    verifier(payload).feed(bad)

    def test_bad_final_status_is_not_success(self):
        payload = b'abcd'
        for status in [b'FAIL', b'INFO', b'DATA', b'okay']:
            with self.subTest(status=status), self.assertRaises(WireError):
                verifier(payload).feed(START + payload + b'DUMPEND' + status)

    def test_rejects_excess_in_same_transfer(self):
        with self.assertRaises(WireError):
            verifier(b'x').feed(framed(b'x') + b'X')

    def test_rejects_excess_after_exact_frame(self):
        p = verifier(b'x')
        p.feed(framed(b'x'))
        with self.assertRaises(WireError):
            p.feed(b'OKAY')

    def test_wrong_digest_rejected_after_complete_valid_framing(self):
        p = verifier(b'abc')
        p.feed(framed(b'abd'))
        self.assertTrue(p.complete)
        with self.assertRaises(DigestMismatch):
            p.finish()

    def test_expected_hash_is_mandatory_and_well_formed(self):
        for digest in ['', '0' * 63, '0' * 65, 'z' * 64, ' ' + '0' * 64]:
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                StreamVerifier(1, digest)

    def test_uppercase_expected_digest(self):
        payload = b'abc'
        p = StreamVerifier(3, hashlib.sha256(payload).hexdigest().upper())
        p.feed(framed(payload))
        self.assertEqual(p.finish()['sha256'], hashlib.sha256(payload).hexdigest())

    def test_incorrect_declared_size_does_not_find_marker_in_payload(self):
        payload = b'x' + TRAILER + b'y'
        p = StreamVerifier(len(payload) + 1, hashlib.sha256(payload).hexdigest())
        with self.assertRaises(WireError):
            p.feed(framed(payload))

    def test_large_stream_has_bounded_parser_memory(self):
        block = b'\0' * 65536
        expected = hashlib.sha256()
        for _ in range(128):
            expected.update(block)
        tracemalloc.start()
        try:
            p = StreamVerifier(128 * len(block), expected.hexdigest())
            p.feed(START)
            for _ in range(128):
                p.feed(block)
            p.feed(TRAILER)
            self.assertEqual(p.finish()['bytes'], 8388608)
            _, peak = tracemalloc.get_traced_memory()
            self.assertLess(peak, 1024 * 1024)
        finally:
            tracemalloc.stop()


class MockTransportTests(unittest.TestCase):
    """Exercise the actual one-command loop with entirely synthetic USB modules."""
    def transport(self, packets):
        class FakeTimeout(Exception):
            pass

        writes, lifecycle = [], []

        class Endpoint:
            bmAttributes = 2

            def __init__(self, address):
                self.bEndpointAddress = address

            def read(self, size, timeout):
                self_outer.assertEqual(size, CHUNK)
                value = packets.pop(0)
                if value is None:
                    raise FakeTimeout('synthetic quiet input')
                self_outer.assertLessEqual(len(value), size)
                return value

            def write(self, data, timeout):
                writes.append(bytes(data))
                return len(data)

        self_outer = self

        class Interface(list):
            bInterfaceClass, bInterfaceSubClass, bInterfaceProtocol = 255, 66, 3
            bInterfaceNumber = 0

        class Device:
            serial_number = SERIAL

            def get_active_configuration(self):
                return [Interface([Endpoint(0x81), Endpoint(0x01)])]

        usb = types.ModuleType('usb')
        core = types.ModuleType('usb.core')
        util = types.ModuleType('usb.util')
        usb.core, usb.util = core, util
        core.USBTimeoutError = FakeTimeout
        core.find = lambda **kwargs: [Device()]
        util.ENDPOINT_IN, util.ENDPOINT_OUT = 0x80, 0
        util.endpoint_type = lambda attributes: attributes & 3
        util.endpoint_direction = lambda address: address & 0x80
        util.claim_interface = lambda device, interface: lifecycle.append('claim')
        util.release_interface = lambda device, interface: lifecycle.append('release')
        util.dispose_resources = lambda device: lifecycle.append('dispose')
        return {'usb': usb, 'usb.core': core, 'usb.util': util}, writes, lifecycle

    def test_zlp_between_transfers_preserves_one_command_and_complete_hash(self):
        payload = b'Z' * PARTITIONS['vbmeta_system_a']
        wire = framed(payload)
        packets = [None, b''] + [wire[i:i + CHUNK] for i in range(0, len(wire), CHUNK)] + [None]
        modules, writes, lifecycle = self.transport(packets)
        result = {'command_may_have_been_sent': False}
        with patch.dict(sys.modules, modules):
            read_once('vbmeta_system_a', hashlib.sha256(payload).hexdigest(), result, SERIAL)
        self.assertEqual(writes, [b'oem dump-storage vbmeta_system_a\0'])
        self.assertEqual(lifecycle, ['claim', 'release', 'dispose'])
        self.assertEqual(packets, [])
        self.assertTrue(result['read_frame_complete_and_tail_quiet'])
        self.assertEqual(result['sha256'], hashlib.sha256(payload).hexdigest())
        self.assertEqual(result['wire_bytes'], len(wire))

    def test_zlp_does_not_extend_total_deadline_or_resend_command(self):
        modules, writes, lifecycle = self.transport([None, b''])
        result = {'command_may_have_been_sent': False}
        with patch.dict(sys.modules, modules), \
                patch('hash_readonly.time.monotonic', side_effect=[0, 0, 1801]):
            with self.assertRaises(TimeoutError):
                read_once('vbmeta_system_a', '0' * 64, result, SERIAL)
        self.assertEqual(writes, [b'oem dump-storage vbmeta_system_a\0'])
        self.assertTrue(result['command_may_have_been_sent'])
        self.assertEqual(lifecycle, ['claim', 'release', 'dispose'])


if __name__ == '__main__':
    unittest.main()
