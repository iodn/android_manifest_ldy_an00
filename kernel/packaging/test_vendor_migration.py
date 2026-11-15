# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
import vendor_migration as v

class MigrationTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.cohort=self.root/"cohort"
        self.cohort.mkdir()
        self.rows=[]
        for p in set(v.PARTS)-set(v.TWO):
            data=p.encode()
            (self.cohort/(p+".img")).write_bytes(data)
            self.rows.append(dict(file=p+".img",partition=p,file_bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
        self.contract=self.root/"contract.json"
        self.contract.write_text(json.dumps(dict(schema="ldy-stock11-hardware-inputs-v1",kernel_release="test-kernel",inputs=self.rows)))
        self.content=self.root/"content"
        for part in ("vendor","odm"):
            (self.content/part/"etc/vintf").mkdir(parents=True)
            (self.content/part/"build.prop").write_text("ro.build.version.security_patch=2026-10-01\n")
            (self.content/part/"etc/vintf/manifest.xml").write_text("<manifest/>")
        self.misc=dict(super_partition_size="17574133760",super_qti_dynamic_partitions_group_size="17569939456",virtual_ab="true",virtual_ab_compression="false",avb_vbmeta_system="system",avb_vbmeta_system_key_path="public-test-key",avb_vbmeta_system_rollback_index_location="2",avb_custom_vbmeta_images_partition_list="system_dlkm",avb_boot_key_path="public-test-key",avb_boot_rollback_index_location="1",avb_vbmeta_system_dlkm_key_path="public-test-key")
        self.misc.update({k:v.DYNAMIC for k in v.LISTS})
        self.entries={n:v.encode(self.misc) for n in v.META}
        self.entries.update({"META/ab_partitions.txt":("\n".join(v.PARTS)+"\n").encode(),"META/kernel_version.txt":b"test-kernel","SYSTEM/build.prop":("ro.build.id=test\nro.vendor.build.ab_ota_partitions="+",".join(v.PARTS)+"\n").encode(),"SYSTEM/app/Keep/Keep.apk":b"compiled apk","META/care_map.pb":b"stale"})
        self.entries.update({"IMAGES/"+p+".img":p.encode() for p in v.PARTS})
        self.source=self.root/"source.zip"
        self.out=self.root/"project.zip"
    def write_source(self):
        with zipfile.ZipFile(self.source,"w") as z:
            for n,data in self.entries.items():z.writestr(n,data)
    def project(self):
        self.write_source()
        return v.project(self.source,self.out,self.contract,self.cohort,self.content)
    def test_accept_only_property_line_ending_normalization(self):
        original=b"ro.vendor.flag=1\r\n"
        digest=hashlib.sha256(original).hexdigest()
        self.assertEqual(v.immutable_metadata(original,b"ro.vendor.flag=1\n\n",
                                             "VENDOR/build.prop",digest),original)
        with self.assertRaisesRegex(ValueError,"Immutable OEM metadata changed"):
            v.immutable_metadata(original,b"ro.vendor.flag=0\n","VENDOR/build.prop",digest)

    def test_xml_metadata_must_remain_byte_exact(self):
        original=b"<manifest/>\r\n"
        with self.assertRaisesRegex(ValueError,"Immutable OEM metadata changed"):
            v.immutable_metadata(original,b"<manifest/>\n","VENDOR/etc/vintf/manifest.xml",
                                 hashlib.sha256(original).hexdigest())

    def test_original_metadata_hash_is_checked(self):
        with self.assertRaisesRegex(ValueError,"Original OEM metadata changed"):
            v.immutable_metadata(b"a=1\n",b"a=1\n","VENDOR/build.prop","0"*64)

    def test_projection_preserves_system_and_shipping_scope(self):
        receipt=self.project()
        with zipfile.ZipFile(self.out) as z:
            self.assertEqual(z.read("SYSTEM/app/Keep/Keep.apk"),b"compiled apk")
            self.assertEqual(z.read("SYSTEM/build.prop"),self.entries["SYSTEM/build.prop"])
            self.assertEqual(z.read("META/ab_partitions.txt"),b"system\nvbmeta_system\n")
            self.assertNotIn("IMAGES/vendor.img",z.namelist())
            self.assertEqual(z.read("VENDOR/etc/vintf/manifest.xml"),b"<manifest/>")
        self.assertEqual(receipt["original_dynamic"]["dynamic_partition_list"],v.DYNAMIC)
    def test_accepts_actual_make_sorted_metadata(self):
        self.entries["META/ab_partitions.txt"]=("\n".join(sorted(v.PARTS))+"\n").encode()
        self.misc["dynamic_partition_list"]=" ".join(sorted(v.DYNAMIC.split()))
        for name in v.META:self.entries[name]=v.encode(self.misc)
        self.project()
    def test_rejects_duplicate_compiler_partition(self):
        self.entries["META/ab_partitions.txt"]+=b"boot\n"
        with self.assertRaisesRegex(ValueError,"Compiler AB scope"):self.project()
    def test_reject_corrupt_input(self):
        (self.cohort/"boot.img").write_bytes(b"wrong")
        with self.assertRaisesRegex(ValueError,"Hardware input mismatch"):self.project()
    def test_reject_extra_partition(self):
        (self.cohort/"lk.img").write_bytes(b"forbidden")
        with self.assertRaisesRegex(ValueError,"Unexpected cohort member"):self.project()
    def test_reject_wrong_shipping_list(self):
        self.entries["SYSTEM/build.prop"]=b"ro.build.id=test\nro.vendor.build.ab_ota_partitions=boot,system\n"
        with self.assertRaisesRegex(ValueError,"Shipping AB"):self.project()
    def test_reject_geometry_change(self):
        self.misc["super_partition_size"]="1"
        self.entries[v.META[0]]=v.encode(self.misc)
        with self.assertRaisesRegex(ValueError,"super geometry"):self.project()
    def test_reject_missing_partition(self):
        del self.entries["IMAGES/recovery_vbmeta.img"]
        with self.assertRaisesRegex(ValueError,"Missing compiler"):self.project()
    def test_assembly_preserves_exact_hardware(self):
        receipt=self.project()
        receipt_path=self.root/"receipt.json"
        receipt_path.write_text(json.dumps(receipt))
        signed=self.root/"signed.zip"
        with zipfile.ZipFile(self.out) as a,zipfile.ZipFile(signed,"w") as b:
            for n in a.namelist():
                data=a.read(n)
                if n==v.META[0]:
                    m=v.parse(data);m["avb_vbmeta_system_key_path"]="/keys/avb/vbmeta-system.pem";data=v.encode(m)
                if n=="VENDOR/build.prop":data+=b"\n"
                b.writestr(n,data)
        tools=self.root/"tools.json";tools.write_text("{}")
        out=self.root/"assembled.zip"
        with patch.object(v,"generate_migration_caremap",return_value=(b"new caremap",{name+"/etc/build.prop":b"module props" for name in ("SYSTEM_DLKM","VENDOR_DLKM","ODM_DLKM")},{"test":True})):
            v.assemble(signed,out,self.contract,self.cohort,receipt_path,tools)
        with zipfile.ZipFile(out) as z:
            for row in self.rows:self.assertEqual(z.read("IMAGES/"+row["file"]),row["partition"].encode())
            self.assertEqual(tuple(z.read("META/ab_partitions.txt").decode().split()),v.PARTS)
            self.assertEqual(z.read("META/care_map.pb"),b"new caremap")
            self.assertEqual(z.read("VENDOR/build.prop"),(self.content/"vendor/build.prop").read_bytes())
    def test_reject_immutable_vendor_metadata_mutation(self):
        receipt=self.project()
        receipt_path=self.root/"receipt.json";receipt_path.write_text(json.dumps(receipt))
        with zipfile.ZipFile(self.out,"a") as z:
            z.writestr("VENDOR/etc/vintf/manifest.xml",b"bad")
        tools=self.root/"tools.json";tools.write_text("{}")
        with self.assertRaisesRegex(ValueError,"Duplicate ZIP entry"):
            v.assemble(self.out,self.root/"bad.zip",self.contract,self.cohort,receipt_path,tools)

if __name__=="__main__":unittest.main()
