# SPDX-License-Identifier: Apache-2.0
"""Synthetic evidence and mocked crypto boundary; never a release proof."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import make_feed
import update_metadata_pb2 as pb
import validate_ota_vendor_feed as vendor
from vendor_migration import PARTS, DYNAMIC


def digest(data):
    return hashlib.sha256(data).hexdigest()


class VendorFeedTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / "hardware"
        self.directory.mkdir()
        self.kernel = self.root / "Image.lz4"
        self.kernel.write_bytes(b"qualified-kernel")
        self.images = {}
        for name in PARTS:
            data = (name.encode() + bytes(4096))[:4096]
            if name == "boot":
                header = bytearray(4096)
                header[:8] = b"ANDROID!"
                struct.pack_into("<I", header, 8, self.kernel.stat().st_size)
                struct.pack_into("<I", header, 40, 4)
                data = bytes(header) + self.kernel.read_bytes()
                data += bytes((-len(data)) % 4096)
            self.images[name] = data
        rows = []
        for name in set(PARTS) - {"system", "vbmeta_system"}:
            path = self.directory / (name + ".img")
            path.write_bytes(self.images[name])
            rows.append(dict(partition=name, file=path.name, file_bytes=len(self.images[name]),
                             sha256=digest(self.images[name])))
        self.contract = self.root / "contract.json"
        self.write(self.contract, dict(schema="ldy-stock11-hardware-inputs-v1",
                                      kernel_release="6.12.58-qualified", inputs=rows))
        self.target = self.root / "signed-target.zip"
        with zipfile.ZipFile(self.target, "w") as z:
            z.writestr("META/ab_partitions.txt", "\n".join(PARTS))
            z.writestr("META/kernel_version.txt", "6.12.58-qualified")
            for name, data in self.images.items():
                z.writestr("IMAGES/" + name + ".img", data)
        self.hardware_proof = self.root / "hardware-avb.json"
        self.proof = dict(status="PASS_CURRENT18_HARDWARE_INPUT_HASHES_AVAILABLE_AVB_SIGNATURES_CONTENT_AND_CHAIN_KEYS",
                          contract_sha256=digest(self.contract.read_bytes()),
                          parts={r["partition"]: dict(sha256=r["sha256"], bytes=r["file_bytes"],
                                                     signature_verified=True) for r in rows})
        self.write(self.hardware_proof, self.proof)
        self.final_proof = self.root / "final-avb.json"
        self.final = dict(status="FINAL_MIGRATION_AVB_SIGNATURES_CONTENT_AND_AVAILABLE_CHAIN_KEYS_PASS",
                          root_flags_unchanged=True, raw_oem_signed_parts=["modem", "mcf_ota"],
                          parts={name: dict(signature_verified=True, rollback_index=0,
                                            flags=1 if name in ("vbmeta", "recovery_vbmeta") else 0)
                                 for name in vendor.AVB_PARTS})
        self.final["parts"]["vbmeta"]["chain_children_checked"] = sorted(vendor.ROOT_CHILDREN)
        self.final["parts"]["recovery_vbmeta"]["chain_children_checked"] = ["boot", "vendor_boot"]
        self.write(self.final_proof, self.final)
        self.qualification = self.root / "qualification.json"
        self.q = dict(all_checks_pass=True, kernel_release="6.12.58-qualified",
                      artifacts={"Image.lz4": self.pin(self.kernel)})
        self.write(self.qualification, self.q)
        self.transcript = self.root / "avb.log"
        self.transcript.write_text("synthetic external verification transcript")
        self.package = self.root / "update.zip"
        manifest = pb.DeltaArchiveManifest(block_size=4096, partial_update=False,
                                          max_timestamp=42, signatures_size=3)
        d = manifest.dynamic_partition_metadata
        d.snapshot_enabled = True
        d.vabc_enabled = False
        group = d.groups.add(name="qti_dynamic_partitions", size=17569939456)
        group.partition_names.extend(DYNAMIC.split())
        data = bytearray()
        for name in PARTS:
            image = self.images[name]
            p = manifest.partitions.add(partition_name=name, version="42")
            p.new_partition_info.size = len(image)
            p.new_partition_info.hash = bytes.fromhex(digest(image))
            op = p.operations.add(type=pb.InstallOperation.REPLACE, data_offset=len(data),
                                  data_length=len(image), data_sha256_hash=bytes.fromhex(digest(image)))
            op.dst_extents.add(start_block=0, num_blocks=len(image) // 4096)
            if name == "system":
                p.run_postinstall = True
                p.postinstall_path = "system/bin/otapreopt_script"
                p.filesystem_type = "ext4"
                p.postinstall_optional = True
            data.extend(image)
        manifest.signatures_offset = len(data)
        raw = manifest.SerializeToString()
        payload = struct.pack(">4sQQI", b"CrAU", 2, len(raw), 3) + raw + b"sig" + data + b"sig"
        with zipfile.ZipFile(self.package, "w") as z:
            z.writestr("payload.bin", payload, compress_type=zipfile.ZIP_STORED)
            z.writestr("payload_properties.txt", "FILE_HASH=fixture\nMETADATA_HASH=fixture\n")
            z.writestr("META-INF/com/android/metadata",
                       "ota-type=AB\npre-device=ldy_an00\npost-build-incremental=test42\n"
                       "post-timestamp=42\npost-sdk-level=37\npost-security-patch-level=2026-11-01\n"
                       "ota-property-files=payload.bin:0:1\n")
        self.admission = dict(schema="ldy-vendor-migration-ota-feed-v1", payload_mode="full",
            ota_sha256=digest(self.package.read_bytes()), target_files=self.pin(self.target),
            cohort=self.pin(self.contract), cohort_directory=str(self.directory),
            hardware_avb_proof=self.pin(self.hardware_proof), final_avb_proof=self.pin(self.final_proof),
            kernel_qualification=self.pin(self.qualification),
            verification_transcripts=[self.pin(self.transcript)],
            build_number="test42", build_epoch=42, platform_spl="2026-11-01",
            verifier_dependencies=[], certificate=self.pin(self.transcript),
            signature_verifier=self.pin(self.transcript), delta_generator=self.pin(self.transcript))
        self.path = self.root / "admission.json"

    def pin(self, path):
        return dict(path=str(path), bytes=path.stat().st_size, sha256=digest(path.read_bytes()))

    def write(self, path, data):
        path.write_text(json.dumps(data))

    def admit(self):
        self.write(self.path, self.admission)
        with patch.object(vendor, "authenticate_zip_payload", return_value=dict(
                signature_output_sha256="mock-crypto", metadata_file_bytes=123,
                ota_certificate_der_sha256="mock-certificate")):
            return vendor.validate_zip(self.package, self.path, digest(self.path.read_bytes()))

    def test_exact_twenty_and_six_logical_full_replacement(self):
        result = self.admit()
        self.assertEqual(len(result["partitions"]), 20)
        self.assertEqual(result["status"], "OTA_VENDOR_MIGRATION_COHORT_AUTHENTICATED")

    def test_twenty_part_feed_requires_explicit_full_mode(self):
        self.admission.pop("payload_mode")
        with self.assertRaisesRegex(ValueError,"explicit full payload mode"):
            self.admit()

    def test_partial_twenty_payload_rejected_even_with_full_admission(self):
        with zipfile.ZipFile(self.package) as z:
            entries={n:z.read(n) for n in z.namelist()}
        payload=entries["payload.bin"]
        magic,version,length,signature=struct.unpack(">4sQQI",payload[:24])
        manifest=pb.DeltaArchiveManifest();manifest.ParseFromString(payload[24:24+length])
        manifest.partial_update=True
        raw=manifest.SerializeToString()
        entries["payload.bin"]=struct.pack(">4sQQI",magic,version,len(raw),signature)+raw+payload[24+length:]
        with zipfile.ZipFile(self.package,"w") as z:
            for name,data in entries.items():z.writestr(name,data)
        self.admission["ota_sha256"]=digest(self.package.read_bytes())
        with self.assertRaisesRegex(ValueError,"full/partial-update identity"):
            self.admit()

    def test_untrusted_admission_digest(self):
        self.write(self.path, self.admission)
        with self.assertRaisesRegex(ValueError, "admission hash"):
            vendor.validate_zip(self.package, self.path, "0" * 64)

    def test_hardware_change_rejected(self):
        with (self.directory / "modem.img").open("ab") as stream:
            stream.write(b"changed")
        with self.assertRaisesRegex(ValueError, "Hardware input mismatch"):
            self.admit()

    def test_signed_target_hardware_change_rejected_after_new_pin(self):
        with zipfile.ZipFile(self.target) as old:
            contents = {n: old.read(n) for n in old.namelist()}
        contents["IMAGES/modem.img"] = b"changed"
        with zipfile.ZipFile(self.target, "w") as z:
            for name, data in contents.items():
                z.writestr(name, data)
        self.admission["target_files"] = self.pin(self.target)
        with self.assertRaisesRegex(ValueError, "Signed target hardware differs"):
            self.admit()

    def test_avb_signature_and_scope_required(self):
        self.final["parts"]["vbmeta"]["signature_verified"] = False
        self.write(self.final_proof, self.final)
        self.admission["final_avb_proof"] = self.pin(self.final_proof)
        with self.assertRaisesRegex(ValueError, "AVB signature"):
            self.admit()

    def test_kernel_qualification_matches_actual_boot_payload(self):
        self.q["artifacts"]["Image.lz4"]["sha256"] = "0" * 64
        self.write(self.qualification, self.q)
        self.admission["kernel_qualification"] = self.pin(self.qualification)
        with self.assertRaisesRegex(ValueError, "Pinned input"):
            self.admit()

    def test_different_qualified_kernel_cannot_authorize_boot(self):
        self.kernel.write_bytes(b"x" * self.kernel.stat().st_size)
        self.q["artifacts"]["Image.lz4"] = self.pin(self.kernel)
        self.write(self.qualification, self.q)
        self.admission["kernel_qualification"] = self.pin(self.qualification)
        with self.assertRaisesRegex(ValueError, "Qualified boot kernel differs"):
            self.admit()

    def test_raw_modem_proof_hash_must_match_contract(self):
        self.proof["parts"]["modem"]["sha256"] = "0" * 64
        self.write(self.hardware_proof, self.proof)
        self.admission["hardware_avb_proof"] = self.pin(self.hardware_proof)
        with self.assertRaisesRegex(ValueError, "proof image differs"):
            self.admit()

    def test_parent_flags_and_complete_chain_required(self):
        original = json.loads(json.dumps(self.final))
        for change in ("flags", "recovery-flags", "chain", "recovery-chain", "extra"):
            with self.subTest(change=change):
                self.final = json.loads(json.dumps(original))
                if change == "flags":
                    self.final["parts"]["vbmeta"]["flags"] = 0
                elif change == "recovery-flags":
                    self.final["parts"]["recovery_vbmeta"]["flags"] = 0
                elif change == "recovery-chain":
                    self.final["parts"]["recovery_vbmeta"]["chain_children_checked"].remove("boot")
                elif change == "chain":
                    self.final["parts"]["vbmeta"]["chain_children_checked"].remove("vendor_boot")
                else:
                    self.final["parts"]["lk"] = dict(signature_verified=True, flags=0, rollback_index=0)
                self.write(self.final_proof, self.final)
                self.admission["final_avb_proof"] = self.pin(self.final_proof)
                with self.assertRaises(ValueError):
                    self.admit()

    def test_official_signature_failure_propagates(self):
        self.write(self.path, self.admission)
        with patch.object(vendor, "authenticate_zip_payload", side_effect=ValueError("signature failed")):
            with self.assertRaisesRegex(ValueError, "signature failed"):
                vendor.validate_zip(self.package, self.path, digest(self.path.read_bytes()))

    def test_default_two_mode_still_rejects_twenty(self):
        with self.assertRaises(ValueError):
            make_feed.entry(self.package, "https://example.org/update.zip")

    def test_feed_explicit_vendor_mode_and_native_shape(self):
        self.write(self.path, self.admission)
        with patch.object(vendor, "validate_zip", return_value={"ota_sha256": digest(self.package.read_bytes())}):
            result = make_feed.entry(self.package, "https://example.org/update.zip",
                vendor_admission=self.path, vendor_admission_sha256=digest(self.path.read_bytes()))
        self.assertEqual(result[0]["files"][0]["filename"], "update.zip")
        self.assertEqual(result[0]["datetime"], 42)
        self.assertEqual(result[0]["type"], "UNOFFICIAL")

    def test_partial_or_mixed_mode_arguments_refused(self):
        for kwargs in [dict(vendor_admission=self.path),
                       dict(vendor_admission_sha256="0" * 64),
                       dict(vendor_admission=self.path, vendor_admission_sha256="0" * 64,
                            kernel_admission=self.path, kernel_admission_sha256="0" * 64)]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                make_feed.entry(self.package, "https://example.org/update.zip", **kwargs)

    def test_feed_package_change_after_authentication_refused(self):
        before = digest(self.package.read_bytes())
        def mutate(*args):
            with self.package.open("ab") as stream:
                stream.write(b"changed")
            return {"ota_sha256": before}
        with patch.object(vendor, "validate_zip", side_effect=mutate):
            with self.assertRaisesRegex(ValueError, "changed after authenticated"):
                make_feed.entry(self.package, "https://example.org/update.zip",
                    vendor_admission=self.path, vendor_admission_sha256="0" * 64)


class GitHubAssetLimitTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.package = Path(self.temp.name) / "sparse.zip"

    def size(self, value):
        # Sparse stat-only fixtures allocate no multi-gigabyte package data.
        with self.package.open("wb") as stream:
            stream.truncate(value)

    def test_github_boundary_is_strictly_below_two_gib(self):
        url = "https://github.com/iodn/android_manifest_ldy_an00/releases/download/test/update.zip"
        self.size(make_feed.GITHUB_ASSET_LIMIT - 1)
        make_feed.validate_release_asset_size(self.package, url)
        for size in (make_feed.GITHUB_ASSET_LIMIT, 2560128465):
            self.size(size)
            with self.subTest(size=size), self.assertRaisesRegex(ValueError, "smaller than 2 GiB"):
                make_feed.validate_release_asset_size(self.package, url)

    def test_oversized_github_feed_refused_before_crypto(self):
        self.size(2560128465)
        with patch.object(vendor, "validate_zip") as authenticate:
            with self.assertRaisesRegex(ValueError, "smaller than 2 GiB"):
                make_feed.entry(self.package, "https://github.com/iodn/repo/releases/download/v/update.zip",
                    vendor_admission=Path("not-read"), vendor_admission_sha256="0" * 64)
            authenticate.assert_not_called()

    def test_external_host_does_not_inherit_github_limit(self):
        self.size(2560128465)
        make_feed.validate_release_asset_size(self.package, "https://updates.example.org/update.zip")


if __name__ == "__main__":
    unittest.main()
