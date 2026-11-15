# SPDX-License-Identifier: Apache-2.0
import stat
import struct
import tempfile
import unittest
from pathlib import Path

import init_boot as boot


def entry(name, mode, data=b"", inode=1, links=1):
    return (name, [inode, mode, 123, 456, links, 789, len(data), 8, 9, 10, 11,
                   len(name.encode()) + 1, 0], data)


def elf():
    image = bytearray(128)
    image[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", image, 16, 2, 183, 1, 0x200078, 64, 0, 0,
                     64, 56, 1, 0, 0, 0)
    struct.pack_into("<II6Q", image, 64, 1, 5, 0, 0x200000, 0, 128, 128, 4096)
    return bytes(image)


class InitBootTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        # A reversible codec fixture isolates packaging guards from the real LZ4 tool.
        self.codec = self.root / "codec"
        self.codec.write_text("#!/usr/bin/python3\nimport sys\n"
                              "data=sys.stdin.buffer.read()\n"
                              "magic=bytes.fromhex(\"02214c18\")\n"
                              "sys.stdout.buffer.write(data[4:] if \"-d\" in sys.argv else magic+data)\n")
        self.codec.chmod(0o700)
        self.entries = [entry(".", stat.S_IFDIR | 0o755, inode=1, links=2),
                        entry("init", stat.S_IFREG | 0o750, b"stock init", inode=2),
                        entry("system", stat.S_IFDIR | 0o755, inode=3, links=2),
                        entry("system/bin", stat.S_IFLNK | 0o777, b"/system/bin/toolbox", inode=4),
                        entry("TRAILER!!!", 0, inode=0)]
        self.init = elf()
        self.stock = self.make_stock(self.entries)

    def make_stock(self, entries):
        archive = boot.MAGIC + boot.encode_cpio(entries)
        stock = bytearray(65536)
        stock[:8] = b"ANDROID!"
        struct.pack_into("<I", stock, 12, len(archive))
        struct.pack_into("<I", stock, 20, 1584)
        struct.pack_into("<I", stock, 40, 4)
        stock[256] = 0x5a
        stock[boot.PAGE:boot.PAGE + len(archive)] = archive
        stock[-64:] = b"AVBf" + b"old signed metadata".ljust(60, b"\0")
        return bytes(stock)

    def prepare(self, stock=None, init=None, stock_hash=None, init_hash=None):
        stock = self.stock if stock is None else stock
        init = self.init if init is None else init
        return boot.prepare(stock, stock_hash or boot.digest(stock), init,
                            init_hash or boot.digest(init), self.codec)

    def test_only_init_content_and_size_change(self):
        image, report = self.prepare()
        size = struct.unpack_from("<I", image, 12)[0]
        archive = boot.parse_cpio(image[boot.PAGE + 4:boot.PAGE + size])
        for index, (before, after) in enumerate(zip(self.entries, archive)):
            if index != 1:
                self.assertEqual(before, after)
            else:
                self.assertEqual(before[0], after[0])
                self.assertEqual(after[2], self.init)
                expected = before[1].copy()
                expected[6] = len(self.init)
                self.assertEqual(expected, after[1])
        expected_header = bytearray(self.stock[:boot.PAGE])
        struct.pack_into("<I", expected_header, 12, size)
        self.assertEqual(bytes(expected_header), image[:boot.PAGE])
        self.assertEqual(0, len(image) % boot.PAGE)
        self.assertLess(len(image), len(self.stock))
        self.assertNotIn(b"old signed metadata", image)
        self.assertEqual("UNSIGNED_REQUIRES_AVB_SIGNING", report["status"])
        self.assertFalse(report["avb_copied"])

    def test_rejects_bad_input_hashes(self):
        for hashes in ({"stock_hash": "0" * 64}, {"init_hash": "0" * 64}):
            with self.subTest(hashes=hashes), self.assertRaisesRegex(ValueError, "SHA-256"):
                self.prepare(**hashes)

    def test_rejects_non_init_boot_headers(self):
        for offset, value in ((8, 1), (20, 1580), (40, 3), (1580, 4096), (12, 65536)):
            data = bytearray(self.stock)
            struct.pack_into("<I", data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.prepare(stock=bytes(data))
        with self.assertRaises(ValueError):
            self.prepare(stock=b"ANDROID!")

    def test_rejects_dynamic_and_malformed_elf(self):
        for offset, fmt, value in ((64, "<I", 2), (64, "<I", 3), (18, "<H", 62),
                                   (32, "<Q", 120), (24, "<Q", 0), (96, "<Q", 999)):
            data = bytearray(self.init)
            struct.pack_into(fmt, data, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                self.prepare(init=bytes(data))
        with self.assertRaises(ValueError):
            self.prepare(init=b"not ELF")

    def test_rejects_unsafe_duplicate_and_rooted_inputs(self):
        for name in ("../init", "/init", "a/../init", "a//init", "init.real", "kernelsu.ko"):
            entries = self.entries[:-1] + [entry(name, stat.S_IFREG | 0o600)] + self.entries[-1:]
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.prepare(stock=self.make_stock(entries))
        entries = self.entries[:-1] + [entry("./init", stat.S_IFREG | 0o750)] + self.entries[-1:]
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.prepare(stock=self.make_stock(entries))

    def test_rejects_missing_symlink_or_hardlinked_init(self):
        for mode, links in ((stat.S_IFLNK | 0o777, 1), (stat.S_IFREG | 0o750, 2)):
            entries = list(self.entries)
            entries[1] = entry("init", mode, b"stock", links=links)
            with self.subTest(mode=mode, links=links), self.assertRaisesRegex(ValueError, "regular"):
                self.prepare(stock=self.make_stock(entries))
        with self.assertRaisesRegex(ValueError, "one init"):
            self.prepare(stock=self.make_stock(self.entries[:1] + self.entries[2:]))

    def test_preserves_repeated_identical_directory_with_distinct_inodes(self):
        entries = self.entries[:-1] + [entry("system", stat.S_IFDIR | 0o755, inode=99, links=2)] + self.entries[-1:]
        image, _ = self.prepare(stock=self.make_stock(entries))
        size = struct.unpack_from("<I", image, 12)[0]
        actual = boot.parse_cpio(image[boot.PAGE + 4:boot.PAGE + size])
        self.assertEqual(entries[2], actual[2])
        self.assertEqual(entries[-2], actual[-2])

    def test_rejects_conflicting_duplicate_directory(self):
        original = entry("system", stat.S_IFDIR | 0o755, inode=99, links=2)
        for field in (1, 2, 3, 4, 5, 7, 8, 9, 10, 12):
            name, header, data = original
            header = header.copy()
            header[field] ^= 1
            entries = self.entries[:-1] + [(name, header, data)] + self.entries[-1:]
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "Duplicate"):
                self.prepare(stock=self.make_stock(entries))
        for duplicate in (entry("./system", stat.S_IFDIR | 0o755, links=2),
                          entry("system", stat.S_IFDIR | 0o755, b"unexpected", links=2)):
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                self.prepare(stock=self.make_stock(self.entries[:-1] + [duplicate] + self.entries[-1:]))

    def test_rejects_truncated_or_concatenated_cpio(self):
        raw = boot.encode_cpio(self.entries)
        bad_field = bytearray(raw)
        bad_field[6:14] = b"      -1"
        for damaged in (raw[:50], raw[:115], bytes(bad_field), raw + b"another archive"):
            with self.subTest(length=len(damaged)), self.assertRaises(ValueError):
                boot.parse_cpio(damaged)


if __name__ == "__main__":
    unittest.main()
