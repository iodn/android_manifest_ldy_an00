#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Authenticate the explicitly pinned owned-kernel OTA before feed generation."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import zipfile

from first_install import CERT_SHA
from kernel_cohort import cohort
import validate_ota_vendor_retention as retention


def need(condition, message):
    if not condition:
        raise retention.AdmissionError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pinned(row):
    path = Path(row["path"])
    need(path.is_file() and not path.is_symlink(), "Pinned input must be regular")
    need(path.stat().st_size == row["bytes"] and sha(path) == row["sha256"],
         "Pinned input differs")
    return path


def validate_zip(package, admission_path, expected_sha256):
    """The external admission hash is supplied by the release reviewer, not the ZIP."""
    admission_path = Path(admission_path)
    need(re.fullmatch("[0-9a-f]{64}", expected_sha256) is not None,
         "Expected admission SHA256 required")
    need(sha(admission_path) == expected_sha256, "Kernel admission hash differs")
    admission = json.loads(admission_path.read_text())
    need(admission["schema"] == "ldy-kernel-ota-feed-v1", "Unknown admission schema")
    package = Path(package)
    package_before = sha(package)
    need(package_before == admission["ota_sha256"], "OTA differs from admission")
    contract_path = pinned(admission["cohort"])
    contract, paths = cohort(contract_path, admission["cohort"]["sha256"],
                             admission["cohort_directory"])
    images = {row["partition"]: {"bytes": row["file_bytes"], "sha256": row["sha256"]}
              for row in contract["inputs"]}

    # This is a separately reviewed cryptographic verification receipt, never a
    # partition allowlist derived from the package itself.
    proof_path = pinned(admission["avb_proof"])
    proof = json.loads(proof_path.read_text())
    need(proof["schema"] == "ldy-owned-kernel-avb-chain-v1",
         "Unknown retained-parent AVB proof schema")
    need(proof["cohort_sha256"] == admission["cohort"]["sha256"]
         and proof["images"] == images, "AVB proof belongs to another cohort")
    need(proof["retained_parent"]["unchanged"] is True
         and proof["retained_parent"]["chains_verified"] is True,
         "Retained-parent chain not verified")
    # Independently rehash every reviewed chain input/parent and cryptographic
    # transcript; the admission pin is the review authority for these facts.
    need(bool(proof["verified_inputs"]) and bool(proof["verification_transcripts"]),
         "Missing AVB verification evidence")
    for row in proof["verified_inputs"] + proof["verification_transcripts"]:
        pinned(row)
    verified_hashes = {row["sha256"] for row in proof["verified_inputs"]}
    need({row["sha256"] for row in images.values()} <= verified_hashes,
         "AVB verification did not bind all kernel images")
    pinned(proof["retained_parent"]["image"])
    need(proof["retained_parent"]["image"]["sha256"] in verified_hashes,
         "Retained parent absent from AVB verification inputs")
    need(set(proof["image_signature_verified"]) == set(images)
         and all(value is True for value in proof["image_signature_verified"].values()),
         "Kernel image signatures not verified")

    cert = pinned(admission["certificate"])
    der = subprocess.check_output(["openssl", "x509", "-in", str(cert), "-outform", "DER"])
    need(hashlib.sha256(der).hexdigest() == CERT_SHA, "Wrong release certificate")
    verifier = pinned(admission["signature_verifier"])
    delta = pinned(admission["delta_generator"])
    need(bool(admission["verifier_dependencies"]), "Missing verifier dependency pins")
    dependencies = [pinned(row) for row in admission["verifier_dependencies"]]
    need((verifier.parent / "common.py").resolve() in {p.resolve() for p in dependencies},
         "Official verifier common.py dependency must be pinned")
    env = dict(os.environ)
    env.pop("PYTHONOPTIMIZE", None)  # Official verifier uses security assertions.
    env["PATH"] = str(delta.parent) + os.pathsep + env.get("PATH", "")
    need(delta.name == "delta_generator" and os.access(delta, os.X_OK)
         and Path(shutil.which("delta_generator", path=env["PATH"]) or "").resolve()
         == delta.resolve(), "Official payload verifier resolves to another executable")
    # Official verifier authenticates BOTH whole-ZIP and payload/metadata signatures.
    result = subprocess.run([sys.executable, str(verifier), str(cert), str(package)],
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    need(result.returncode == 0, "Official OTA/payload signature verification failed")

    signature_output_sha256 = hashlib.sha256(result.stdout + result.stderr).hexdigest()
    result = retention.validate_zip(package, kernel_images=images)
    with zipfile.ZipFile(package) as archive:
        for name in ["payload.bin", "payload_properties.txt", "META-INF/com/android/metadata"]:
            entries = [row for row in archive.infolist() if row.filename == name]
            need(len(entries) == 1 and not entries[0].is_dir()
                 and not entries[0].flag_bits & 1, "Duplicate/invalid critical OTA ZIP entry")
        props_raw = archive.read("payload_properties.txt").decode()
        props = {}
        for line in props_raw.splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            need(key not in props, "Duplicate payload property")
            props[key] = value
        payload_entry = archive.getinfo("payload.bin")
        with archive.open(payload_entry) as stream:
            header = retention.read_exact(stream, 24)
            _, _, manifest_size, signature_size = struct.unpack(">4sQQI", header)
            metadata_size = 24 + manifest_size
            digest = hashlib.sha256()
            prefix = hashlib.sha256()
            digest.update(header)
            prefix.update(header)
            remaining = metadata_size - 24
            while remaining:
                data = retention.read_exact(stream, min(1024 * 1024, remaining))
                digest.update(data)
                prefix.update(data)
                remaining -= len(data)
            for data in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(data)
        need(int(props["FILE_SIZE"]) == payload_entry.file_size
             and base64.b64decode(props["FILE_HASH"], validate=True) == digest.digest(),
             "Whole payload property hash/size differs")
        need(int(props["METADATA_SIZE"]) == metadata_size
             and base64.b64decode(props["METADATA_HASH"], validate=True) == prefix.digest(),
             "Payload metadata property hash/size differs")
    need(sha(package) == package_before, "OTA changed during admission")
    need(sha(admission_path) == expected_sha256, "Admission changed during verification")
    # Re-run the existing image file gate after external verification.
    cohort(contract_path, admission["cohort"]["sha256"], admission["cohort_directory"])
    for row in (proof["verified_inputs"] + proof["verification_transcripts"]
                + admission["verifier_dependencies"]
                + [admission["certificate"], admission["signature_verifier"],
                   admission["delta_generator"], admission["avb_proof"]]):
        pinned(row)
    result.update(signature_output_sha256=signature_output_sha256, status="OTA_OWNED_KERNEL_COHORT_AUTHENTICATED",
                  ota_sha256=package_before, admission_sha256=expected_sha256,
                  ota_certificate_der_sha256=CERT_SHA,
                  metadata_file_bytes=metadata_size + signature_size,
                  scope="Authenticated exact FIVE payload/cohort and externally reviewed AVB "
                        "chain evidence. No device installation, runtime, addon survival or "
                        "OEM boot trust guarantee.")
    return result

