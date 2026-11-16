#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Authenticate the explicitly reviewed twenty-part OTA before feed generation."""
import hashlib
import json
from pathlib import Path
import re
import struct
import zipfile

from kernel_cohort import entryhash, names
from validate_ota_kernel_cohort import authenticate_zip_payload, need, pinned, sha
from validate_ota_vendor_migration import validate
from vendor_migration import PARTS, RAW, verify_hardware

AVB_PARTS = set(PARTS) - set(RAW) - {"dtbo"}
ROOT_CHILDREN = {
    "boot", "init_boot", "vendor_boot", "vbmeta_system", "vbmeta_system_dlkm",
    "vbmeta_vendor", "vbmeta_vendor_dlkm", "vbmeta_odm", "vbmeta_odm_dlkm",
}


def evidence(admission):
    refs = [admission[key] for key in (
        "cohort", "target_files", "hardware_avb_proof", "final_avb_proof",
        "kernel_qualification")]
    need(admission["verification_transcripts"], "Missing AVB verification transcripts")
    refs += admission["verification_transcripts"]
    for row in refs:
        pinned(row)
    contract, paths = verify_hardware(
        admission["cohort"]["path"], admission["cohort_directory"])
    hardware = {r["partition"]: r for r in contract["inputs"]}
    proof = json.loads(Path(admission["hardware_avb_proof"]["path"]).read_text())
    need(proof["status"] ==
         "PASS_CURRENT18_HARDWARE_INPUT_HASHES_AVAILABLE_AVB_SIGNATURES_CONTENT_AND_CHAIN_KEYS",
         "Hardware AVB verification incomplete")
    need(proof["contract_sha256"] == admission["cohort"]["sha256"]
         and set(proof["parts"]) == set(hardware), "Hardware AVB proof cohort differs")
    for name, row in hardware.items():
        checked = proof["parts"][name]
        need(checked["sha256"] == row["sha256"] and checked["bytes"] == row["file_bytes"],
             "Hardware AVB proof image differs: " + name)
        if name in AVB_PARTS:
            need(checked.get("signature_verified") is True,
                 "Hardware signature not verified: " + name)
    final = json.loads(Path(admission["final_avb_proof"]["path"]).read_text())
    need(final["status"] == "FINAL_MIGRATION_AVB_SIGNATURES_CONTENT_AND_AVAILABLE_CHAIN_KEYS_PASS"
         and final["root_flags_unchanged"] is True, "Final AVB verification incomplete")
    need(set(final["parts"]) == AVB_PARTS
         and set(final["raw_oem_signed_parts"]) == set(RAW), "Final AVB scope differs")
    for name, row in final["parts"].items():
        need(row["signature_verified"] is True and row["rollback_index"] == 0
             and row["flags"] == (1 if name in ("vbmeta", "recovery_vbmeta") else 0),
             "Unexpected AVB signature/flags/index: " + name)
    need(set(final["parts"]["vbmeta"]["chain_children_checked"]) == ROOT_CHILDREN,
         "Final AVB parent chain differs")
    need(set(final["parts"]["recovery_vbmeta"]["chain_children_checked"]) ==
         {"boot", "vendor_boot"}, "Final Recovery parent chain differs")
    qualification = json.loads(Path(admission["kernel_qualification"]["path"]).read_text())
    need(qualification["all_checks_pass"] is True
         and qualification["kernel_release"] == contract["kernel_release"],
         "Kernel qualification differs from cohort")
    kernel = qualification["artifacts"]["Image.lz4"]
    pinned(kernel)
    refs.append(kernel)
    with paths["boot"].open("rb") as boot:
        header = boot.read(4096)
        need(header[:8] == b"ANDROID!" and struct.unpack_from("<I", header, 40)[0] == 4,
             "Unsupported qualified boot header")
        size = struct.unpack_from("<I", header, 8)[0]
        need(size == kernel["bytes"], "Qualified boot kernel size differs")
        digest = hashlib.sha256()
        remaining = size
        while remaining:
            data = boot.read(min(1024 * 1024, remaining))
            need(data, "Truncated qualified boot kernel")
            digest.update(data)
            remaining -= len(data)
        need(digest.hexdigest() == kernel["sha256"], "Qualified boot kernel differs")
    target = Path(admission["target_files"]["path"])
    with zipfile.ZipFile(target) as archive:
        names(archive)
        need(archive.read("META/kernel_version.txt").decode().strip() == contract["kernel_release"],
             "Signed target kernel version differs")
        for name, row in hardware.items():
            member = "IMAGES/" + name + ".img"
            need(archive.getinfo(member).file_size == row["file_bytes"]
                 and entryhash(archive, member) == row["sha256"],
                 "Signed target hardware differs: " + name)
    return contract, refs


def validate_zip(package, admission_path, expected_sha256):
    admission_path, package = Path(admission_path), Path(package)
    need(re.fullmatch("[0-9a-f]{64}", expected_sha256) is not None,
         "Expected admission SHA256 required")
    need(sha(admission_path) == expected_sha256, "Vendor admission hash differs")
    admission = json.loads(admission_path.read_text())
    need(admission["schema"] == "ldy-vendor-migration-ota-feed-v1",
         "Unknown vendor feed admission schema")
    before = sha(package)
    need(before == admission["ota_sha256"], "OTA differs from vendor admission")
    _, refs = evidence(admission)
    crypto = authenticate_zip_payload(package, admission)
    result = validate(package, admission["target_files"]["path"],
                      admission["build_number"], admission["build_epoch"],
                      admission["platform_spl"])
    need(sha(package) == before, "OTA changed during vendor admission")
    need(sha(admission_path) == expected_sha256, "Vendor admission changed during verification")
    for row in refs + admission["verifier_dependencies"] + [
        admission["certificate"], admission["signature_verifier"], admission["delta_generator"]
    ]:
        pinned(row)
    # Recheck exact regular hardware images after external verifier execution.
    verify_hardware(admission["cohort"]["path"], admission["cohort_directory"])
    result.update(**crypto, status="OTA_VENDOR_MIGRATION_COHORT_AUTHENTICATED",
                  ota_sha256=before, admission_sha256=expected_sha256,
                  scope="Authenticated exact twenty-part full replacements, six logical partitions "
                        "and pinned kernel/vendor/modem/AVB evidence. No publishing, installation "
                        "or hardware qualification is performed.")
    return result
