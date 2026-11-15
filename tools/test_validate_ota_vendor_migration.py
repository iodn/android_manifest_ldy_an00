# SPDX-License-Identifier: Apache-2.0
import hashlib
import unittest
import update_metadata_pb2 as pb
import validate_ota_vendor_migration as v

class PayloadTest(unittest.TestCase):
    def setUp(self):
        self.m=pb.DeltaArchiveManifest(block_size=4096,partial_update=True,max_timestamp=42,signatures_offset=1000)
        d=self.m.dynamic_partition_metadata;d.snapshot_enabled=True;d.vabc_enabled=False
        g=d.groups.add(name="qti_dynamic_partitions",size=17569939456)
        g.partition_names.extend(v.DYNAMIC.split())
        self.expected={}
        for i,name in enumerate(v.PARTS):
            p=self.m.partitions.add(partition_name=name,version="42")
            digest=hashlib.sha256(name.encode()).digest()
            p.new_partition_info.size=4096;p.new_partition_info.hash=digest
            op=p.operations.add(type=pb.InstallOperation.REPLACE,data_offset=i,data_length=1,data_sha256_hash=hashlib.sha256(b"x").digest())
            op.dst_extents.add(start_block=0,num_blocks=1)
            self.expected[name]={"bytes":4096,"sha256":digest.hex()}
            if name=="system":
                p.run_postinstall=True;p.postinstall_path="system/bin/otapreopt_script";p.filesystem_type="ext4";p.postinstall_optional=True
    def check(self):
        return v.validate_manifest(self.m,self.expected,42)
    def test_valid_exact_migration(self):
        self.assertEqual(len(self.check()),18)
    def test_metadata_order_has_no_semantic_effect(self):
        rows=list(self.m.partitions);del self.m.partitions[:];self.m.partitions.extend(reversed(rows))
        self.check()
    def test_unknown_partition_rejected(self):
        self.m.partitions[0].partition_name="lk"
        with self.assertRaisesRegex(ValueError,"partition set"):self.check()
    def test_duplicate_partition_rejected(self):
        self.m.partitions.add().CopyFrom(self.m.partitions[0])
        with self.assertRaisesRegex(ValueError,"partition set"):self.check()
    def test_hash_mismatch_rejected(self):
        self.m.partitions[0].new_partition_info.hash=b"x"*32
        with self.assertRaisesRegex(ValueError,"target mismatch"):self.check()
    def test_source_operation_rejected(self):
        self.m.partitions[0].operations[0].type=pb.InstallOperation.SOURCE_COPY
        with self.assertRaisesRegex(ValueError,"Source-dependent"):self.check()
    def test_missing_block_rejected(self):
        self.m.partitions[0].operations[0].dst_extents[0].start_block=1
        with self.assertRaisesRegex(ValueError,"missing target block"):self.check()
    def test_compressed_snapshots_rejected(self):
        self.m.dynamic_partition_metadata.vabc_enabled=True
        with self.assertRaisesRegex(ValueError,"snapshot implementation"):self.check()
    def test_unreviewed_postinstall_rejected(self):
        self.m.partitions[0].run_postinstall=True;self.m.partitions[0].postinstall_path="do-anything"
        with self.assertRaisesRegex(ValueError,"postinstall hooks"):self.check()
    def test_missing_module_timestamp_rejected(self):
        next(p for p in self.m.partitions if p.partition_name=="vendor_dlkm").ClearField("version")
        with self.assertRaisesRegex(ValueError,"partition timestamp"):self.check()
    def test_out_of_bounds_data_rejected(self):
        self.m.partitions[0].operations[0].data_length=1001
        with self.assertRaisesRegex(ValueError,"outside authenticated"):self.check()

if __name__=="__main__":unittest.main()
