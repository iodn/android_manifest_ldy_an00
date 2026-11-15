#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check the explicit stock11 migration payload against its signed target files.
Cryptographic OTA verification is a separate required official-tool gate.
"""
import argparse
import hashlib
import json
import struct
import sys
import zipfile
from pathlib import Path
import update_metadata_pb2 as pb
from kernel_cohort import names, need, parse
from postinstall_policy import validate_partition
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"kernel/packaging"))
from vendor_migration import PARTS, DYNAMIC

def validate_manifest(m, expected, epoch):
    need(m.IsInitialized(), "Uninitialized payload protobuf")
    need(m.block_size==4096, "Unexpected payload block size")
    need(m.partial_update and m.max_timestamp==epoch, "Wrong partial-update identity")
    need(sorted(p.partition_name for p in m.partitions)==sorted(PARTS), "Unexpected payload partition set")
    d=m.dynamic_partition_metadata
    need(d.snapshot_enabled and not d.vabc_enabled, "Wrong snapshot implementation")
    need(len(d.groups)==1, "Wrong dynamic group count")
    g=d.groups[0]
    need(g.name=="qti_dynamic_partitions" and g.size==17569939456 and sorted(g.partition_names)==sorted(DYNAMIC.split()), "Wrong dynamic group")
    result=[]
    for part in m.partitions:
        name=part.partition_name
        validate_partition(part)
        if name=="system":
            need(part.run_postinstall, "Missing system add-on postinstall")
        if name in ("boot","system","system_dlkm","vendor","vendor_dlkm","odm","odm_dlkm"):
            need(part.HasField("version") and part.version.isdecimal() and int(part.version)>0,
                "Missing/invalid partial OTA partition timestamp: "+name)
        info=part.new_partition_info
        need(info.size==expected[name]["bytes"] and info.hash.hex()==expected[name]["sha256"], "Payload target mismatch: "+name)
        need(not part.HasField("old_partition_info"), "Migration must be a complete partition replacement")
        extents=[]
        for op in part.operations:
            kind=pb.InstallOperation.Type.Name(op.type)
            need(kind in ("REPLACE","REPLACE_BZ","REPLACE_XZ","REPLACE_ZSTD","REPLACE_LZ4","ZERO"), "Source-dependent/unsupported migration operation: "+kind)
            need(not op.src_extents, "Source extents in full replacement")
            if kind=="ZERO":
                need(op.data_length==0, "ZERO carries unexpected data")
            else:
                need(op.data_length>0 and len(op.data_sha256_hash)==32, "Missing operation data authentication")
                need(op.data_offset+op.data_length<=m.signatures_offset, "Operation data outside authenticated payload data")
            need(op.dst_extents, "Missing target extents")
            for ex in op.dst_extents:
                need(ex.num_blocks>0, "Empty target extent")
                extents.append((ex.start_block,ex.start_block+ex.num_blocks))
        end=0
        for begin,stop in sorted(extents):
            need(begin==end, "Overlapping/missing target block: "+name)
            end=stop
        need(end*4096==info.size, "Incomplete partition replacement: "+name)
        result.append(dict(partition=name,bytes=info.size,sha256=info.hash.hex(),operations=len(part.operations)))
    return result

def validate(ota,target,number,epoch,spl):
    with zipfile.ZipFile(target) as z:
        names(z)
        need(sorted(z.read("META/ab_partitions.txt").decode().split())==sorted(PARTS),"Signed target-files scope mismatch")
        expected={}
        for part in PARTS:
            n="IMAGES/"+part+".img"
            with z.open(n) as f:
                expected[part]={"bytes":z.getinfo(n).file_size,"sha256":hashlib.file_digest(f,"sha256").hexdigest()}
    with zipfile.ZipFile(ota) as z:
        names(z)
        meta=parse(z.read("META-INF/com/android/metadata"))
        for k,v in {"ota-type":"AB","pre-device":"ldy_an00","post-build-incremental":number,"post-timestamp":str(epoch),"post-security-patch-level":spl}.items():
            need(meta.get(k)==v,"Wrong OTA identity field: "+k)
        need(meta.get("ota-wipe","no") in ("no","false"),"OTA requests data wipe")
        need("ota-downgrade" not in meta,"OTA permits downgrade")
        entry=z.getinfo("payload.bin")
        need(entry.compress_type==zipfile.ZIP_STORED and not entry.flag_bits&1,"Payload must stream without ZIP compression/encryption")
        with z.open(entry) as f:
            header=f.read(24)
            need(len(header)==24,"Truncated payload header")
            magic,version,length,signature=struct.unpack(">4sQQI",header)
            need(magic==b"CrAU" and version==2 and 0<length<=16*1024*1024 and signature>0,"Unsupported/unsigned payload metadata")
            raw=f.read(length);need(len(raw)==length,"Truncated payload manifest")
        m=pb.DeltaArchiveManifest();m.ParseFromString(raw)
        need(m.HasField("signatures_offset") and m.signatures_offset>0,"Missing payload signatures")
        need(24+length+signature+m.signatures_offset+m.signatures_size==entry.file_size,"Wrong signed payload boundaries")
        parts=validate_manifest(m,expected,epoch)
    return dict(status="MIGRATION_PAYLOAD_STRUCTURE_AND_EXACT_IMAGE_HASHES_OK",partitions=parts,build_number=number,build_epoch=epoch,platform_spl=spl,preserves_lk=True,phone_actions=False,scope="Requires separate official ZIP/payload signature verification, AVB proof and live layout gate before installation.")

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ("ota","target-files","build-number","build-epoch","platform-spl","report"):
        p.add_argument("--"+n,required=True)
    a=p.parse_args()
    result=validate(a.ota,a.target_files,a.build_number,int(a.build_epoch),a.platform_spl)
    Path(a.report).write_text(json.dumps(result,indent=2)+"\n")
    print(result["status"])
if __name__=="__main__":main()
