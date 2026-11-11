# SPDX-License-Identifier: Apache-2.0
import unittest
from kmi import parse_kmi


class KmiRecognitionTest(unittest.TestCase):
    def test_branded_release(self):
        kernel = b"Linux version 6.12.38-LDY-AN00-android16-5-g70f67f1acd5b-4k\0"
        self.assertEqual(parse_kmi(kernel), "android16-6.12")

    def test_original_gki_release(self):
        self.assertEqual(parse_kmi(b"6.12.38-android16-5-4k\0"), "android16-6.12")

    def test_stripped_release_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_kmi(b"Linux version 6.12.38-LDY-AN00-g2a4c948dcfd1-4k\0")

    def test_terminated_window_required(self):
        for value in [b"6.12.38-android16-5", b"6.12.38-android16-5" + b"x" * 100 + b"\0",
                      b"6.12.38-android16-5\xff\0"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_kmi(value)


if __name__ == "__main__":
    unittest.main()
