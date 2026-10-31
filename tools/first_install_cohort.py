#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The qualified stock113 physical ranges and complete owned-kernel install set."""
import hashlib
import json
from pathlib import Path
import re

SUPER = 17574133760
DLKM_START, DLKM_BYTES = 5587861504, 33554432
QUALIFIED_LK = "7d8762ef876b29542e66d0e717cd9af253602b3d86e93e7780ef5c2eb3686eae"
OLD_DLKM_CHILD = "b8ef25359e63010a91f06649f086c5bf795b584b78ca9cdb9138aa9b8e693f58"
MAIN_PARENT = "257ee73bed1174d6599ff8090a6b51269cb13da490d409dbb72d4d779ae14b8d"
RECOVERY_PARENT = "7c2849602675243c89917a15ae9dbab1f7d1bf0138e6a28db284aeb9fe7389c9"
RECOVERY_RAMDISK = "8b7fb0fb794de758e13d7800cff6428165a2d5cc9efb837849a21dd080e39a6a"
PHYSICAL = ("boot", "recovery_ramdisk", "vbmeta_system", "vbmeta_system_dlkm", "vbmeta", "recovery_vbmeta")
LOGICAL = set(PHYSICAL) | {"system_dlkm"}
MUTABLE = {"super"} | {name + "_" + slot for name in PHYSICAL for slot in "ab"}
# Original stock GPT, CRC-checked against the retained original device backup.
GPT = {
    "boot_a": (402944, 419327), "boot_b": (601600, 617983),
    "recovery_ramdisk_a": (277248, 293631), "recovery_ramdisk_b": (475136, 491519),
    "vbmeta_a": (269056, 269311), "vbmeta_b": (466944, 467199),
    "recovery_vbmeta_a": (269312, 269567), "recovery_vbmeta_b": (467200, 467455),
    "vbmeta_system_a": (269568, 269823), "vbmeta_system_b": (467456, 467711),
    "vbmeta_system_dlkm_a": (271616, 271871), "vbmeta_system_dlkm_b": (469504, 469759),
}


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def baseline(profile):
    result = {name: dict(row) for name, row in profile.items()}
    for slot in "ab":
        result["lk_" + slot] = {"bytes": 16777216, "sha256": QUALIFIED_LK}
        result["vbmeta_system_dlkm_" + slot] = {"bytes": 1048576, "sha256": OLD_DLKM_CHILD}
    return result


def contract_images(contract, paths):
    need(contract.get("schema_version") == 1, "Unsupported kernel contract")
    inputs = contract.get("inputs", [])
    expected = {"boot": 67108864, "system_dlkm": DLKM_BYTES, "vbmeta_system_dlkm": 1048576}
    need(len(inputs) == 3 and {row["partition"] for row in inputs} == set(expected), "Wrong owned kernel cohort")
    for row in inputs:
        name = row["partition"]
        need(row["file"] == name + ".img" and row["file_bytes"] == row["partition_bytes"] ==
             row["payload_new_partition_bytes"] == expected[name], "Wrong cohort partition size")
        path = paths[name]
        need(path.stat().st_size == expected[name] and digest(path) == row["sha256"], "Kernel cohort image mismatch: " + name)
    for name, expected_sha in (("vbmeta", MAIN_PARENT), ("recovery_vbmeta", RECOVERY_PARENT),
                               ("recovery_ramdisk", RECOVERY_RAMDISK)):
        need(digest(paths[name]) == expected_sha, "Wrong tested boot/recovery cohort: " + name)
        need(paths[name].stat().st_size == (67108864 if name == "recovery_ramdisk" else 1048576), "Wrong physical image length")
    need(paths["vbmeta_system"].stat().st_size in (4096, 1048576), "Wrong system child size")


def physical_plan(images):
    # All payloads and children are complete before either verification parent is replaced.
    return [(name + "_" + slot, images[name + "_" + slot]) for name in PHYSICAL for slot in "ab"]


def validate(root, manifest, original, checked_file, decode):
    before = baseline(original)
    need(manifest["model"] == "LDY-AN00" and manifest["firmware"] == "10.0.0.113(C00E100R101P1)"
         and manifest["before"] == before, "Unsupported full-cohort first-install baseline")
    files = manifest["files"]
    for name, row in files.items():
        checked_file(root, name, row)
    images = manifest["images"]
    need(set(images) == (MUTABLE - {"super"}) | {"userdata", "metadata"}, "Wrong full-cohort physical write set")
    logical = manifest["cohort_images"]
    need(set(logical) == LOGICAL, "Incomplete full-cohort artifact set")
    paths = {name: checked_file(root, file, files[file]) for name, file in logical.items()}
    contract_path = manifest["kernel_contract"]
    contract = json.loads(checked_file(root, contract_path, files[contract_path]).read_text())
    contract_images(contract, paths)
    after = manifest["after"]
    need(set(after) == set(before), "Post-install physical partition set differs")
    for name, row in after.items():
        need(row["bytes"] == before[name]["bytes"] and re.fullmatch("[0-9a-f]{64}", row["sha256"]), "Invalid post-install identity")
        if name not in MUTABLE:
            need(row == before[name], "Installer changes a retained partition: " + name)
    for name in PHYSICAL:
        for slot in "ab":
            partition = name + "_" + slot
            need(images[partition] == logical[name] and files[images[partition]] == after[partition], "Physical image/cohort mismatch")
    system_start, system_window = 1048576, 4345298944
    for names, start, size, expected_sha in (
        (manifest["system_pieces"], system_start, manifest["system_bytes"], manifest["system_sha256"]),
        (manifest["dlkm_pieces"], DLKM_START, DLKM_BYTES, files[logical["system_dlkm"]]["sha256"]),
    ):
        need(0 < size <= (system_window - 4096 if start == system_start else DLKM_BYTES), "Overlay range exceeds its stock extent")
        position, digest_stream = start, hashlib.sha256()
        need(bool(names), "Missing sparse overlay pieces")
        for name in names:
            need(files[name]["bytes"] <= 8 * 1024 * 1024 + 64, "Sparse upload exceeds qualified bound")
            offset, data = decode(root / name)
            need(offset == position and 0 < len(data) <= 8 * 1024 * 1024, "Noncontiguous cohort overlay")
            digest_stream.update(data); position += len(data)
        need(position == start + size and digest_stream.hexdigest() == expected_sha, "Cohort sparse reconstruction mismatch")
    offset, footer = decode(root / manifest["footer_piece"])
    need(offset == system_start + system_window - 4096 and len(footer) == 4096 and footer[-64:-60] == b"AVBf", "Wrong fixed system footer")
    _, final_system_piece = decode(root / manifest["system_pieces"][-1])
    need(footer[-64:] == final_system_piece[-64:], "Logical footer differs from signed system")
    for name, expected in {
        "userdata": "c56829494610a5b534a815fb01323a772af4a08bd3f86f66268530e680de217d",
        "metadata": "2f8f105f8b830bfac31c7e91404f827b95a4d80024110df8f731b3856ad989f0",
    }.items():
        need(files[images[name]]["sha256"] == expected, "Unqualified empty filesystem image")
    need(manifest["geometry"] == {"super": SUPER, "userdata": 489917775872, "metadata": 67108864, "misc": 2097152}, "Unsupported storage geometry")
    return before, after


def overlay_ranges_hash(baseline_stream, ranges, total, chunk=4 * 1024 * 1024):
    """Stream the original and patched hashes without allocating another full super image."""
    ordered = sorted(ranges, key=lambda row: row[0])
    previous = 0
    for offset, source in ordered:
        source.seek(0, 2); size = source.tell(); source.seek(0)
        need(size > 0 and offset >= previous and offset + size <= total, "Overlapping/out-of-range super overlay")
        previous = offset + size
    old, new, position = hashlib.sha256(), hashlib.sha256(), 0
    while data := baseline_stream.read(chunk):
        need(position + len(data) <= total, "Baseline exceeds declared super size")
        old.update(data); patched = bytearray(data)
        for offset, source in ordered:
            source.seek(0, 2); size = source.tell()
            lo, hi = max(position, offset), min(position + len(data), offset + size)
            if lo < hi:
                source.seek(lo - offset); replacement = source.read(hi - lo)
                need(len(replacement) == hi - lo, "Truncated cohort overlay")
                patched[lo - position:hi - position] = replacement
        new.update(patched); position += len(data)
    need(position == total, "Truncated stock super baseline")
    return old.hexdigest(), new.hexdigest()
