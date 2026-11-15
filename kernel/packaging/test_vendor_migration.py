# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
import struct
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
        self.entries.update({"RADIO/"+p+".img":p.encode() for p in v.RAW})
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

    def test_odm_identity_comes_from_authenticated_image_fields(self):
        header=bytearray(4096)
        struct.pack_into("<I",header,1024,0xe0f5e1e2);header[1036]=12
        struct.pack_into("<Q",header,1048,15)
        value=v.odm_identity_metadata(b"vendor.feature=1\r\n",header,"signed/fingerprint",10,20)
        self.assertIn(b"ro.odm.build.date.utc=15\n",value)
        self.assertIn(b"ro.odm.build.fingerprint=signed/fingerprint\n",value)
        for minimum,maximum in [(16,20),(10,14)]:
            with self.assertRaisesRegex(ValueError,"timestamp outside"):
                v.odm_identity_metadata(b"vendor.feature=1\n",header,"signed/fingerprint",minimum,maximum)
        with self.assertRaisesRegex(ValueError,"identity already exists"):
            v.odm_identity_metadata(b"ro.odm.build.date.utc=15\n",header,"signed/fingerprint",10,20)
        header[1024]=0
        with self.assertRaisesRegex(ValueError,"Invalid ODM EROFS"):
            v.odm_identity_metadata(b"a=1\n",header,"signed/fingerprint",10,20)

    def test_projection_preserves_system_and_shipping_scope(self):
        receipt=self.project()
        with zipfile.ZipFile(self.out) as z:
            self.assertEqual(z.read("SYSTEM/app/Keep/Keep.apk"),b"compiled apk")
            self.assertEqual(z.read("SYSTEM/build.prop"),self.entries["SYSTEM/build.prop"])
            self.assertEqual(z.read("META/ab_partitions.txt"),b"system\nvbmeta_system\n")
            self.assertNotIn("IMAGES/vendor.img",z.namelist())
            self.assertFalse(any(name.startswith("RADIO/") for name in z.namelist()))
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
    def test_physical_baseband_scope_does_not_expand_dynamic_ownership(self):
        self.assertEqual(len(v.PARTS),20)
        self.assertEqual(set(v.RAW),{"modem","mcf_ota"})
        self.assertEqual(set(v.DYNAMIC.split()),
                         {"system","system_dlkm","vendor","vendor_dlkm","odm","odm_dlkm"})
        self.assertFalse(set(v.PARTS).intersection(
            {"lk","preloader","tee","nvram","nvdata","nvcfg","md_sec"}))

    def test_reject_missing_raw_cohort_input(self):
        for part in v.RAW:
            with self.subTest(part=part):
                path=self.cohort/(part+".img");data=path.read_bytes();path.unlink()
                with self.assertRaisesRegex(ValueError,"Hardware input must be regular"):
                    self.project()
                path.write_bytes(data)

    def test_reject_raw_cohort_bytes_change(self):
        for part in v.RAW:
            with self.subTest(part=part):
                path=self.cohort/(part+".img");data=path.read_bytes()
                path.write_bytes(bytes([data[0]^1])+data[1:])
                with self.assertRaisesRegex(ValueError,"Hardware input mismatch"):
                    self.project()
                path.write_bytes(data)

    def test_reject_raw_contract_partition_substitution(self):
        contract=json.loads(self.contract.read_text())
        next(row for row in contract["inputs"] if row["partition"]=="modem")["partition"]="nvram"
        self.contract.write_text(json.dumps(contract))
        with self.assertRaisesRegex(ValueError,"Wrong hardware partition set"):
            self.project()

    def test_reject_raw_dynamic_ownership(self):
        self.misc["dynamic_partition_list"]+=" modem"
        self.entries[v.META[0]]=v.encode(self.misc)
        with self.assertRaisesRegex(ValueError,"Unexpected dynamic ownership"):
            self.project()

    def test_reject_missing_raw_radio_or_changed_compiler_bytes(self):
        for part in v.RAW:
            name="RADIO/"+part+".img";data=self.entries.pop(name)
            with self.subTest(part=part,case="missing"):
                with self.assertRaisesRegex(ValueError,"Missing raw RADIO"):
                    self.project()
            self.entries[name]=b"changed"
            with self.subTest(part=part,case="changed"):
                with self.assertRaisesRegex(ValueError,"Raw compiler image mismatch"):
                    self.project()
            self.entries[name]=data

    def test_reject_raw_avb_signing_configuration(self):
        self.misc["avb_modem_key_path"]="must-not-sign"
        self.entries[v.META[0]]=v.encode(self.misc)
        with self.assertRaisesRegex(ValueError,"Raw partition must not have AVB"):
            self.project()

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
        with patch.object(v,"generate_migration_caremap",return_value=(b"new caremap",{name+"/etc/build.prop":b"module props" for name in ("SYSTEM_DLKM","VENDOR_DLKM","ODM_DLKM","ODM")},{"test":True})):
            v.assemble(signed,out,self.contract,self.cohort,receipt_path,tools)
        with zipfile.ZipFile(out) as z:
            for row in self.rows:self.assertEqual(z.read("IMAGES/"+row["file"]),row["partition"].encode())
            self.assertEqual({n for n in z.namelist() if n.startswith("RADIO/")},
                             {"RADIO/"+p+".img" for p in v.RAW})
            for p in v.RAW:
                self.assertEqual(z.read("RADIO/"+p+".img"),p.encode())
            misc=v.parse(z.read(v.META[0]))
            self.assertEqual(misc["partial_ota_update_partitions_list"]," ".join(v.PARTS))
            self.assertFalse(any(k.startswith(("avb_modem_","avb_mcf_ota_")) for k in misc))
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
