# SPDX-License-Identifier: Apache-2.0
import base64
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import build_first_install as build
import first_install as install


class OverlayProofTests(unittest.TestCase):
    def test_prefix_and_footer_replace_only_their_declared_ranges(self):
        baseline = bytes(range(251)) * 120
        image = b'SIGNED_IMAGE' * 211
        footer = b'NEW_FOOTER' * 31
        start, window = 4096, 16000
        expected = bytearray(baseline)
        expected[start:start + len(image)] = image
        offset = start + window - len(footer)
        expected[offset:offset + len(footer)] = footer
        for chunk in (1, 513, 4096, 4097, 4 * 1024 * 1024):
            with self.subTest(chunk=chunk):
                old, new = build.overlay_hash(io.BytesIO(baseline), io.BytesIO(image), footer,
                                               len(baseline), start, window, chunk=chunk)
                self.assertEqual(old, hashlib.sha256(baseline).hexdigest())
                self.assertEqual(new, hashlib.sha256(expected).hexdigest())

    def test_footer_overlap_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'overlap'):
            build.overlay_hash(io.BytesIO(bytes(100)), io.BytesIO(bytes(20)), b'footer', 100, 10, 20)

    def test_truncated_stock_stream_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Truncated baseline'):
            build.overlay_hash(io.BytesIO(bytes(99)), io.BytesIO(b'sys'), b'footer', 100, 10, 20)

    def test_overlong_stock_stream_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'exceeds'):
            build.overlay_hash(io.BytesIO(bytes(101)), io.BytesIO(b'sys'), b'footer', 100, 10, 20)


class AuthenticationTests(unittest.TestCase):
    def test_another_certificate_is_rejected_before_openssl_or_usb(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'ota.x509.pem').write_bytes(b'-----BEGIN CERTIFICATE-----\n' +
                base64.b64encode(b'untrusted certificate') + b'\n-----END CERTIFICATE-----\n')
            with patch.object(install.subprocess, 'run') as command, self.assertRaisesRegex(ValueError, 'project identity'):
                install.authenticate(root)
            command.assert_not_called()

    def test_multiple_certificates_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            block = b'-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n'
            (root / 'ota.x509.pem').write_bytes(block * 2)
            with self.assertRaisesRegex(ValueError, 'one release certificate'):
                install.authenticate(root)


if __name__ == '__main__':
    unittest.main()
