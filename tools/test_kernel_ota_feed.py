# SPDX-License-Identifier: Apache-2.0
"""Synthetic unit controls; external crypto verifier is mocked, never a release proof."""
import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import make_feed
import validate_ota_kernel_cohort as kernel
import validate_ota_vendor_retention as retention


def digest(data):
    return hashlib.sha256(data).hexdigest()


class KernelFeedChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / "images"
        self.directory.mkdir()
        rows = []
        for name in ["boot", "system_dlkm", "vbmeta_system_dlkm"]:
            data = (name + " fixture").encode()
            (self.directory / (name + ".img")).write_bytes(data)
            rows.append(dict(partition=name, file=name + ".img", file_bytes=len(data),
                             partition_bytes=len(data), payload_new_partition_bytes=len(data),
                             sha256=digest(data)))
        self.contract = self.root / "contract.json"
        self.contract.write_text(json.dumps(dict(schema_version=1, inputs=rows)))
        self.images = {r["partition"]: dict(bytes=r["file_bytes"], sha256=r["sha256"])
                       for r in rows}
        self.manifest = retention.metadata.DeltaArchiveManifest()
        for name in ["boot", "system", "system_dlkm", "vbmeta_system", "vbmeta_system_dlkm"]:
            part = self.manifest.partitions.add(partition_name=name)
            if name == "system":
                part.run_postinstall = True
                part.postinstall_path = "system/bin/otapreopt_script"
                part.filesystem_type = "ext4"
                part.postinstall_optional = True
            if name in self.images:
                part.new_partition_info.size = self.images[name]["bytes"]
                part.new_partition_info.hash = bytes.fromhex(self.images[name]["sha256"])
        self.manifest.partial_update = True
        group = self.manifest.dynamic_partition_metadata.groups.add()
        group.name, group.size = retention.GROUP_NAME, retention.GROUP_BYTES
        group.partition_names.extend(["system", "system_dlkm"])

    def payload(self):
        raw = self.manifest.SerializeToString()
        return struct.pack(">4sQQI", b"CrAU", 2, len(raw), 3) + raw + b"sig" + b"data"

    def validate(self):
        data = self.payload()
        return retention.validate_stream(io.BytesIO(data), len(data), kernel_images=self.images)

    def test_exact_five_and_actual_hash_join(self):
        self.assertEqual(set(self.validate()["partitions"]),
                         set(self.images) | {"system", "vbmeta_system"})

    def test_default_still_refuses_kernel_payload(self):
        data = self.payload()
        with self.assertRaises(retention.AdmissionError):
            retention.validate_stream(io.BytesIO(data), len(data))

    def test_every_unowned_partition_refused(self):
        for name in ["vendor_boot", "init_boot", "lk", "vendor", "odm", "recovery", "vbmeta",
                     "metadata", "persist"]:
            with self.subTest(name=name):
                self.manifest.partitions[-1].partition_name = name
                with self.assertRaises(retention.AdmissionError):
                    self.validate()
        self.manifest.partitions[-1].partition_name = "vbmeta_system_dlkm"

    def test_duplicate_missing_kernel_and_wrong_group_refused(self):
        original = copy.deepcopy(self.manifest)
        for mutation in ["duplicate", "missing", "geometry", "membership", "partial"]:
            with self.subTest(mutation=mutation):
                self.manifest.CopyFrom(original)
                if mutation == "duplicate":
                    self.manifest.partitions.add().CopyFrom(self.manifest.partitions[0])
                elif mutation == "missing":
                    del self.manifest.partitions[0]
                elif mutation == "geometry":
                    self.manifest.dynamic_partition_metadata.groups[0].size -= 1
                elif mutation == "membership":
                    self.manifest.dynamic_partition_metadata.groups[0].partition_names.append("vendor")
                else:
                    self.manifest.partial_update = False
                with self.assertRaises(retention.AdmissionError):
                    self.validate()

    def test_hash_size_and_missing_info_refused_for_all_three(self):
        for part in self.manifest.partitions:
            if part.partition_name not in self.images:
                continue
            old = copy.deepcopy(part)
            for change in ["hash", "size", "missing"]:
                with self.subTest(partition=part.partition_name, change=change):
                    part.CopyFrom(old)
                    if change == "hash":
                        part.new_partition_info.hash = b"\0" * 32
                    elif change == "size":
                        part.new_partition_info.size += 1
                    else:
                        part.ClearField("new_partition_info")
                    with self.assertRaises(retention.AdmissionError):
                        self.validate()
            part.CopyFrom(old)

    def test_absent_postinstall_refused_in_kernel_mode(self):
        system = next(p for p in self.manifest.partitions if p.partition_name == "system")
        system.run_postinstall = False
        system.postinstall_path = ""
        with self.assertRaisesRegex(retention.AdmissionError, "retain reviewed"):
            self.validate()

    def test_unreviewed_postinstall_refused(self):
        self.manifest.partitions[0].run_postinstall = True
        self.manifest.partitions[0].postinstall_path = "evil"
        with self.assertRaises(retention.AdmissionError):
            self.validate()

    def pin(self, path):
        return dict(path=str(path), bytes=path.stat().st_size, sha256=digest(path.read_bytes()))

    def fixture(self):
        package = self.root / "update.zip"
        payload = self.payload()
        size = 24 + len(self.manifest.SerializeToString())
        props = dict(FILE_SIZE=str(len(payload)), FILE_HASH=base64.b64encode(hashlib.sha256(payload).digest()).decode(),
                     METADATA_SIZE=str(size), METADATA_HASH=base64.b64encode(hashlib.sha256(payload[:size]).digest()).decode())
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("payload.bin", payload)
            archive.writestr("payload_properties.txt", "\n".join(k + "=" + v for k, v in props.items()))
            archive.writestr("META-INF/com/android/metadata",
                             "ota-type=AB\npre-device=ldy_an00\npost-timestamp=1795000000\n"
                             "post-sdk-level=37\npost-security-patch-level=2026-11-01\n"
                             "ota-property-files=payload.bin:0:1\n")
        aux = {}
        for name in ["parent", "avb-transcript", "certificate", "verifier", "delta_generator", "common.py"]:
            path = self.root / name
            path.write_bytes((name + " fixture").encode())
            if name == "delta_generator":
                path.chmod(0o700)
            aux[name] = self.pin(path)
        proof = dict(schema="ldy-owned-kernel-avb-chain-v1", cohort_sha256=digest(self.contract.read_bytes()),
                     images=self.images, retained_parent=dict(unchanged=True, chains_verified=True, image=aux["parent"]),
                     verified_inputs=[self.pin(p) for p in self.directory.iterdir()] + [aux["parent"]],
                     verification_transcripts=[aux["avb-transcript"]],
                     image_signature_verified={p: True for p in self.images})
        proof_path = self.root / "avb.json"
        proof_path.write_text(json.dumps(proof))
        admission = dict(schema="ldy-kernel-ota-feed-v1", ota_sha256=digest(package.read_bytes()),
                         cohort=self.pin(self.contract), cohort_directory=str(self.directory),
                         avb_proof=self.pin(proof_path), certificate=aux["certificate"],
                         signature_verifier=aux["verifier"], delta_generator=aux["delta_generator"],
                         verifier_dependencies=[aux["common.py"]])
        path = self.root / "admission.json"
        path.write_text(json.dumps(admission))
        return package, path, admission, proof_path, proof

    def authenticated_unit(self, package, path):
        # Boundary doubles do not claim actual RSA/AVB verification.
        with patch.object(kernel, "CERT_SHA", digest(b"test DER")), \
             patch.object(kernel.subprocess, "check_output", return_value=b"test DER"), \
             patch.object(kernel.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"verified", b"")):
            return kernel.validate_zip(package, path, digest(path.read_bytes()))

    def test_reviewed_unit_path_includes_full_metadata_signature(self):
        package, path, _, _, _ = self.fixture()
        result = self.authenticated_unit(package, path)
        self.assertEqual(result["metadata_file_bytes"], 24 + len(self.manifest.SerializeToString()) + 3)

    def test_admission_pin_cannot_be_taken_from_zip(self):
        package, path, _, _, _ = self.fixture()
        with self.assertRaisesRegex(retention.AdmissionError, "admission hash"):
            kernel.validate_zip(package, path, "0" * 64)

    def test_changed_cohort_file_refused(self):
        package, path, _, _, _ = self.fixture()
        (self.directory / "boot.img").write_bytes(b"tamper")
        with self.assertRaises(ValueError):
            self.authenticated_unit(package, path)

    def test_wrong_cert_and_failed_official_verifier_refused(self):
        package, path, _, _, _ = self.fixture()
        with patch.object(kernel.subprocess, "check_output", return_value=b"wrong DER"):
            with self.assertRaisesRegex(retention.AdmissionError, "certificate"):
                kernel.validate_zip(package, path, digest(path.read_bytes()))
        with patch.object(kernel, "CERT_SHA", digest(b"test DER")), \
             patch.object(kernel.subprocess, "check_output", return_value=b"test DER"), \
             patch.object(kernel.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", b"bad")):
            with self.assertRaisesRegex(retention.AdmissionError, "signature verification failed"):
                kernel.validate_zip(package, path, digest(path.read_bytes()))

    def test_wrong_or_unverified_avb_cohort_refused(self):
        package, path, admission, proof_path, proof = self.fixture()
        for key in ["images", "signatures", "parent", "transcript"]:
            with self.subTest(key=key):
                bad = copy.deepcopy(proof)
                if key == "images":
                    bad["images"]["boot"]["sha256"] = "0" * 64
                elif key == "signatures":
                    bad["image_signature_verified"]["boot"] = False
                elif key == "parent":
                    bad["retained_parent"]["chains_verified"] = False
                else:
                    bad["verification_transcripts"] = []
                proof_path.write_text(json.dumps(bad))
                admission["avb_proof"] = self.pin(proof_path)
                path.write_text(json.dumps(admission))
                with self.assertRaises(retention.AdmissionError):
                    self.authenticated_unit(package, path)

    def test_changed_payload_properties_refused_even_after_unit_crypto_boundary(self):
        package, path, admission, _, _ = self.fixture()
        with zipfile.ZipFile(package) as archive:
            contents = {n: archive.read(n) for n in archive.namelist()}
        contents["payload_properties.txt"] = contents["payload_properties.txt"].replace(b"FILE_SIZE=", b"FILE_SIZE=9")
        with zipfile.ZipFile(package, "w") as archive:
            for name, data in contents.items():
                archive.writestr(name, data)
        admission["ota_sha256"] = digest(package.read_bytes())
        path.write_text(json.dumps(admission))
        with self.assertRaises(retention.AdmissionError):
            self.authenticated_unit(package, path)

    def test_feed_rejects_package_change_after_authenticated_return(self):
        package, path, _, _, _ = self.fixture()
        before = digest(package.read_bytes())
        def authenticated_then_changed(*args):
            with package.open("ab") as stream:
                stream.write(b"changed after validator")
            return {"ota_sha256": before}
        with patch.object(kernel, "validate_zip", side_effect=authenticated_then_changed):
            with self.assertRaisesRegex(ValueError, "changed after authenticated"):
                make_feed.entry(package, "https://example.org/OTA.zip",
                                kernel_admission=path, kernel_admission_sha256="0" * 64)

    def test_duplicate_critical_metadata_refused(self):
        package, path, admission, _, _ = self.fixture()
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(package, "a") as archive:
                archive.writestr("payload_properties.txt", "duplicate")
        admission["ota_sha256"] = digest(package.read_bytes())
        path.write_text(json.dumps(admission))
        with self.assertRaisesRegex(retention.AdmissionError, "critical OTA ZIP entry"):
            self.authenticated_unit(package, path)

    def test_feed_requires_both_external_admission_arguments(self):
        for kwargs in [dict(kernel_admission=self.root / "x"),
                       dict(kernel_admission_sha256="0" * 64)]:
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ValueError, "together"):
                make_feed.entry(self.root / "absent.zip", "https://example.org/OTA.zip", **kwargs)


if __name__ == "__main__":
    unittest.main()

