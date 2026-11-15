#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Replace stock init_boot first-stage init; output is UNSIGNED for AVB signing."""
import argparse
import hashlib
import json
from pathlib import Path
import stat
import struct
import subprocess

PAGE = 4096
MAGIC = bytes.fromhex("02214c18")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def check_elf(data):
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("Init must be a little-endian ELF64 executable")
    kind, machine, version = struct.unpack_from("<HHI", data, 16)
    entry, phoff = struct.unpack_from("<QQ", data, 24)
    ehsize, phsize, count = struct.unpack_from("<HHH", data, 52)
    if kind not in (2, 3) or machine != 183 or version != 1 or ehsize != 64 or phsize != 56:
        raise ValueError("Invalid AArch64 ELF header")
    if not count or count == 0xffff or phoff < 64 or phoff + count * phsize > len(data):
        raise ValueError("Invalid ELF program-header bounds")
    executable_entry = False
    for offset in range(phoff, phoff + count * phsize, phsize):
        tag, flags, fileoff, address, _, filesz, memsz, _ = struct.unpack_from("<II6Q", data, offset)
        if tag in (2, 3):
            raise ValueError("Init must be static: PT_DYNAMIC/PT_INTERP forbidden")
        if filesz > memsz or fileoff + filesz > len(data) or address + memsz > 2**64:
            raise ValueError("Invalid ELF segment bounds")
        executable_entry |= tag == 1 and bool(flags & 1) and address <= entry < address + filesz
    if not executable_entry:
        raise ValueError("ELF entry is outside an executable load segment")


def parse_cpio(raw):
    entries, names, offset = [], {}, 0
    while True:
        if offset + 110 > len(raw) or raw[offset:offset + 6] != b"070701":
            raise ValueError("Invalid newc header")
        if any(c not in b"0123456789abcdefABCDEF" for c in raw[offset + 6:offset + 110]):
            raise ValueError("Invalid newc field")
        try:
            header = [int(raw[offset + 6 + i * 8:offset + 14 + i * 8], 16) for i in range(13)]
        except ValueError as error:
            raise ValueError("Invalid newc field") from error
        offset += 110
        size, namesize = header[6], header[11]
        if not namesize or offset + namesize > len(raw):
            raise ValueError("Invalid newc name bounds")
        namebytes = raw[offset:offset + namesize]
        if namebytes[-1:] != b"\0" or b"\0" in namebytes[:-1]:
            raise ValueError("Invalid newc name")
        name = namebytes[:-1].decode("utf-8")
        canonical = name[2:] if name.startswith("./") else name
        if (not canonical or canonical.startswith("/") or
                (canonical != "." and any(p in ("", ".", "..") for p in canonical.split("/")))):
            raise ValueError("Unsafe newc path")
        offset = (offset + namesize + 3) & ~3
        if offset + size > len(raw):
            raise ValueError("Invalid newc data bounds")
        data = raw[offset:offset + size]
        offset = (offset + size + 3) & ~3
        if offset > len(raw):
            raise ValueError("Invalid newc padding bounds")
        if canonical in names:
            previous_name, previous_header, previous_data = names[canonical]
            # Stock repeats /dev with a new inode but identical empty directory metadata.
            if (name != previous_name or not stat.S_ISDIR(header[1]) or data or previous_data or
                    header[1:] != previous_header[1:]):
                raise ValueError("Duplicate newc path")
        names[canonical] = (name, header, data)
        entries.append((name, header, data))
        if canonical == "TRAILER!!!":
            if size or any(raw[offset:]):
                raise ValueError("Invalid newc trailer/padding")
            return entries
        if Path(canonical).name in ("kernelsu.ko", "ksu_config", "init.real", "init.vendor.real"):
            raise ValueError("KernelSU input is forbidden")


def encode_cpio(entries):
    raw = bytearray()
    for name, header, data in entries:
        encoded = name.encode() + b"\0"
        raw += b"070701" + b"".join(f"{n:08x}".encode() for n in header) + encoded
        raw += b"\0" * (-len(raw) % 4)
        raw += data
        raw += b"\0" * (-len(raw) % 4)
    raw += b"\0" * (-len(raw) % 512)
    return bytes(raw)


def prepare(stock, stock_sha256, init, init_sha256, lz4):
    if digest(stock) != stock_sha256 or digest(init) != init_sha256:
        raise ValueError("Input SHA-256 mismatch")
    check_elf(init)
    if (len(stock) < PAGE or stock[:8] != b"ANDROID!" or
            struct.unpack_from("<I", stock, 8)[0] != 0 or
            struct.unpack_from("<I", stock, 20)[0] != 1584 or
            struct.unpack_from("<I", stock, 40)[0] != 4 or
            struct.unpack_from("<I", stock, 1580)[0] != 0):
        raise ValueError("Requires Android v4 init_boot with no kernel/signature")
    size = struct.unpack_from("<I", stock, 12)[0]
    if not size or PAGE + size > len(stock) or stock[PAGE:PAGE + 4] != MAGIC:
        raise ValueError("Invalid legacy-LZ4 ramdisk bounds/format")
    tool = Path(lz4).resolve()
    tool_hash = digest(tool.read_bytes())

    def codec(arguments, data):
        result = subprocess.run([str(tool), *arguments], input=data, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=True)
        if digest(tool.read_bytes()) != tool_hash:
            raise ValueError("LZ4 executable changed")
        return result.stdout

    original = parse_cpio(codec(["-d", "-c", "-"], stock[PAGE:PAGE + size]))
    found = [i for i, (name, _, _) in enumerate(original) if name.removeprefix("./") == "init"]
    if len(found) != 1:
        raise ValueError("Stock ramdisk must contain one init")
    index = found[0]
    name, header, previous = original[index]
    if not stat.S_ISREG(header[1]) or header[4] != 1:
        raise ValueError("Stock init must be a regular file without hard links")
    updated = list(original)
    new_header = header.copy()
    new_header[6] = len(init)
    updated[index] = (name, new_header, init)
    archive = encode_cpio(updated)
    compressed = codec(["-l", "-9", "-c", "-"], archive)
    if compressed[:4] != MAGIC or parse_cpio(codec(["-d", "-c", "-"], compressed)) != updated:
        raise ValueError("Ramdisk round-trip mismatch")
    if any(a != b for i, (a, b) in enumerate(zip(original, updated)) if i != index):
        raise ValueError("Unexpected ramdisk entry change")
    page = bytearray(stock[:PAGE])
    struct.pack_into("<I", page, 12, len(compressed))
    image = bytes(page) + compressed
    image += b"\0" * (-len(image) % PAGE)
    if len(image) >= len(stock):
        raise ValueError("No partition space remains for AVB signing")
    return image, dict(status="UNSIGNED_REQUIRES_AVB_SIGNING", stock_sha256=digest(stock),
                      init_sha256=digest(init), previous_init_sha256=digest(previous),
                      lz4_sha256=tool_hash, output_sha256=digest(image), output_bytes=len(image),
                      ramdisk_bytes=len(compressed), changed_entry=name,
                      preserved_entries=len(original) - 1, avb_copied=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("stock-image", "init", "lz4", "output", "report"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("stock-sha256", "init-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.report.exists() or args.output.resolve() == args.report.resolve():
        raise ValueError("Output/report must be distinct new files")
    image, report = prepare(args.stock_image.read_bytes(), args.stock_sha256,
                            args.init.read_bytes(), args.init_sha256, args.lz4)
    with args.output.open("xb") as stream:
        stream.write(image)
    with args.report.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
