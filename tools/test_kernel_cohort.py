# SPDX-License-Identifier: Apache-2.0
"""Portable metadata regression fixtures; no signing or image tools required."""
import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import kernel_cohort as cohort


class KernelCohortTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        rows = []
        for name in ("boot", "system_dlkm", "vbmeta_system_dlkm"):
            data = ("fixture-" + name).encode()
            (self.inputs / (name + ".img")).write_bytes(data)
            rows.append(dict(partition=name, file=name + ".img",
                             file_bytes=len(data), partition_bytes=len(data),
                             payload_new_partition_bytes=len(data),
                             sha256=hashlib.sha256(data).hexdigest(),
                             layout=dict(avb_original_image_bytes=len(data))))
        self.config = b"CONFIG_FIXTURE=y\n"
        self.release = "6.12.38-android16-5-maybe-dirty-4k"
        self.contract = self.root / "contract.json"
        self.contract.write_text(json.dumps(dict(
            schema_version=1, inputs=rows, kernel_provenance=dict(
                release=self.release,
                config_sha256=hashlib.sha256(self.config).hexdigest()))))
        self.contract_sha = cohort.sha(self.contract)
        dynamic = dict(super_partition_size="17574133760",
                       super_qti_dynamic_partitions_group_size="17569939456",
                       dynamic_partition_list="system system_dlkm",
                       super_qti_dynamic_partitions_partition_list="system system_dlkm",
                       virtual_ab_cow_version="3", virtual_ab_compression_method="none")
        misc = dict(dynamic, avb_vbmeta_system="system",
                    avb_boot_rollback_index_location="1",
                    avb_vbmeta_system_dlkm="system_dlkm",
                    avb_vbmeta_system_dlkm_rollback_index_location="28",
                    avb_custom_vbmeta_images_partition_list="system_dlkm")
        self.entries = {
            "META/misc_info.txt": cohort.encode(misc),
            "META/dynamic_partitions_info.txt": cohort.encode(dynamic),
            "META/ab_partitions.txt": ("\n".join(cohort.FIVE) + "\n").encode(),
            "META/kernel_version.txt": self.release.encode(),
            "META/kernel_configs.txt": self.config,
            "SYSTEM/build.prop": b"ro.build.id=CP2A\n",
            "SYSTEM/product/etc/build.prop": (
                "ro.product.build.id=CP2A\nro.vendor.build.ab_ota_partitions="
                + ",".join(cohort.FIVE) + "\n").encode(),
            "SYSTEM/system_ext/etc/build.prop": b"ro.system_ext.build.id=CP2A\n",
            "BOOT/cmdline": b"fixture",
            "BOOT/pagesize": b"4096",
            "IMAGES/system.img": b"fixture-system",
            "IMAGES/vbmeta_system.img": b"fixture-child",
            "IMAGES/vbmeta.img": b"fixture-diagnostic-main",
            "META/apkcerts.txt": b"fixture-owner-alias",
        }
        for row in rows:
            self.entries["IMAGES/" + row["file"]] = (self.inputs / row["file"]).read_bytes()

    def write(self, name, entries):
        path = self.root / name
        with zipfile.ZipFile(path, "w") as archive:
            for key, value in entries.items():
                archive.writestr(key, value)
        return path

    def project(self):
        source = self.write("source.zip", self.entries)
        projected = self.root / "projected.zip"
        proof = cohort.project(source, cohort.sha(source), projected, self.contract,
                               self.contract_sha, self.inputs)
        return projected, proof

    def test_partition_build_ids_and_projection_preserve_shipping_properties(self):
        projected, proof = self.project()
        with zipfile.ZipFile(projected) as archive:
            for key in self.entries:
                if key.endswith("build.prop"):
                    self.assertEqual(archive.read(key), self.entries[key])
            self.assertFalse(any(key.startswith("BOOT/") for key in archive.namelist()))
            self.assertEqual(archive.read("META/ab_partitions.txt").split(),
                             [b"system", b"vbmeta_system"])
        self.assertIn("META/apkcerts.txt", proof["unchanged_entries"])

    def test_full_release_required_without_rewriting(self):
        for release in (b"6.12.38", self.release.encode() + b"\n"):
            with self.subTest(release=release):
                source = self.write("wrong-release.zip",
                                    dict(self.entries, **{"META/kernel_version.txt": release}))
                with self.assertRaisesRegex(ValueError, "Kernel version"):
                    cohort.project(source, cohort.sha(source), self.root / "wrong-out.zip",
                                   self.contract, self.contract_sha, self.inputs)

    def test_two_part_shipping_property_rejected(self):
        key = "SYSTEM/product/etc/build.prop"
        self.entries[key] = self.entries[key].replace(
            ",".join(cohort.FIVE).encode(), b"system,vbmeta_system")
        with self.assertRaisesRegex(ValueError, "Shipping AB"):
            self.project()

    def test_assembly_preserves_signed_metadata_and_all_five_images(self):
        projected, proof = self.project()
        receipt = self.root / "projection.json"
        receipt.write_text(json.dumps(proof))
        with zipfile.ZipFile(projected) as archive:
            signed = {key: archive.read(key) for key in archive.namelist()}
        misc = cohort.parse(signed["META/misc_info.txt"])
        misc.update(avb_vbmeta_system_key_path=cohort.OWNER,
                    avb_vbmeta_system_algorithm="SHA256_RSA4096",
                    avb_vbmeta_system_rollback_index_location="2",
                    avb_system_add_hashtree_footer_args="signed-owner-footer")
        signed["META/misc_info.txt"] = cohort.encode(misc)
        signed["META/care_map.pb"] = b"old-map"
        signed["IMAGES/system.img"] = b"new-signed-system"
        signed["IMAGES/vbmeta_system.img"] = b"new-signed-child"
        source = self.write("signed-model.zip", signed)
        output = self.root / "assembled.zip"
        # Care-map binary generation is covered by separate official-tool tests.
        with patch.object(cohort, "generate", return_value=(
                b"fresh-map", b"ro.system_dlkm.build.fingerprint=fixture\n",
                {"partitions": ["system", "system_dlkm"]})):
            result = cohort.assemble(source, cohort.sha(source), receipt,
                                     cohort.sha(receipt), output, self.contract,
                                     self.contract_sha, self.inputs, {})
        with zipfile.ZipFile(output) as archive:
            self.assertEqual({key for key in archive.namelist()
                              if key.startswith("IMAGES/")},
                             {"IMAGES/" + part + ".img" for part in cohort.FIVE})
            final = cohort.parse(archive.read("META/misc_info.txt"))
            self.assertEqual(final["avb_system_add_hashtree_footer_args"],
                             "signed-owner-footer")
            self.assertEqual(final["avb_vbmeta_system_key_path"], cohort.OWNER)
            self.assertEqual(archive.read("META/care_map.pb"), b"fresh-map")
            for key, value in signed.items():
                if key not in result["mutated_entries"]:
                    self.assertEqual(archive.read(key), value)
            for part in cohort.TWO:
                self.assertEqual(archive.read("IMAGES/" + part + ".img"),
                                 signed["IMAGES/" + part + ".img"])
            for part in set(cohort.FIVE) - set(cohort.TWO):
                self.assertEqual(archive.read("IMAGES/" + part + ".img"),
                                 (self.inputs / (part + ".img")).read_bytes())


if __name__ == "__main__":
    unittest.main()
