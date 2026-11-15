#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Assemble coherent LDY-AN00 AVB parents and retain the matched raw radio images."""
from pathlib import Path
import argparse,json,sys,importlib.util,hashlib,subprocess,collections,shutil

def copy_raw(source,destination,expected):
 with Path(source).open("rb") as stream:actual=hashlib.file_digest(stream,"sha256").hexdigest()
 if actual!=expected:raise ValueError("Raw radio input hash mismatch")
 if Path(destination).exists():raise ValueError("Refusing to overwrite raw radio image")
 shutil.copyfile(source,destination)
 with Path(destination).open("rb") as stream:copied=hashlib.file_digest(stream,"sha256").hexdigest()
 if copied!=expected:raise ValueError("Raw radio copy mismatch")
 return {"sha256":copied,"bytes":Path(destination).stat().st_size,"resigned":False}

def update_chain_keys(avb,descriptors,public_key):
 changed=[]
 for descriptor in descriptors:
  if isinstance(descriptor,avb.AvbChainPartitionDescriptor) and descriptor.partition_name in (
      "vbmeta_vendor_dlkm","vendor_boot","init_boot"):
   if descriptor.public_key!=public_key:changed.append(descriptor.partition_name)
   descriptor.public_key=public_key
 return changed

def main():
 if not __debug__:raise RuntimeError("Optimized Python is not supported")
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ("workspace","package","parents","key","public-key","modem-image","mcf-ota-image"):
  parser.add_argument("--"+name,type=Path,required=True)
 for name in ("modem-sha256","mcf-ota-sha256"):parser.add_argument("--"+name,required=True)
 args=parser.parse_args()
 P=args.package;I=P/"images";W=args.workspace
 AVB=W/"external/avb/avbtool.py";KEY=args.key
 if not I.is_dir() or not (P/"work").is_dir():raise ValueError("Run child packaging first")
 spec=importlib.util.spec_from_file_location("avb",AVB);a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
 parents=args.parents
 def parse(data):
  if data[:4]!=b"AVB0":
   ft=a.AvbFooter(data[-64:]);data=data[ft.vbmeta_offset:ft.vbmeta_offset+ft.vbmeta_size]
  h=a.AvbVBMetaHeader(data[:256]);assert a.verify_vbmeta_signature(h,data)
  pos=256+h.authentication_data_block_size;ds=a.parse_descriptors(data[pos+h.descriptors_offset:pos+h.descriptors_offset+h.descriptors_size])
  pub=data[pos+h.public_key_offset:pos+h.public_key_offset+h.public_key_size]
  return h,ds,pub
 pub=args.public_key.read_bytes()
 # Changes to parent chain keys are explicit and limited to the modified vendor components and first-stage loader.
 reports={}
 for name in ("vbmeta.img","recovery_vbmeta.img"):
  old,ds,oldpub=parse((parents/name).read_bytes());assert oldpub==pub and old.flags==1
  changed=update_chain_keys(a,ds,pub)
  # All unmodified replacement children still authenticate under the retained OEM chain keys.
  for d in ds:
   if not isinstance(d,a.AvbChainPartitionDescriptor):continue
   target=I/(d.partition_name+".img")
   if target.is_file():
    child,child_ds,child_pub=parse(target.read_bytes());assert child_pub==d.public_key,(name,d.partition_name)
    assert child.rollback_index==0,(name,d.partition_name,"rollback counter")
  encoded=b"".join(d.encode() for d in ds)
  stub=a.AvbVBMetaHeader();stub.algorithm_type=0;stub.authentication_data_block_size=0;stub.auxiliary_data_block_size=(len(encoded)+63)//64*64;stub.descriptors_offset=0;stub.descriptors_size=len(encoded);stub.public_key_offset=0;stub.public_key_size=0
  holder=P/"work"/(name+".descriptor-source");holder.write_bytes(stub.encode()+encoded.ljust(stub.auxiliary_data_block_size,b"\0"))
  out=I/name
  assert not out.exists(),"Refusing to overwrite parent image"
  cmd=[sys.executable,str(AVB),"make_vbmeta_image","--output",str(out),"--padding_size","1048576","--algorithm","SHA256_RSA4096","--key",str(KEY),"--flags",str(old.flags),"--rollback_index",str(old.rollback_index),"--rollback_index_location",str(old.rollback_index_location),"--include_descriptors_from_image",str(holder)]
  subprocess.run(cmd,check=True)
  new,actual,newpub=parse(out.read_bytes())
  assert newpub==pub and len(out.read_bytes())==1048576
  assert collections.Counter(d.encode() for d in actual)==collections.Counter(d.encode() for d in ds)
  for f in ("flags","rollback_index","rollback_index_location","algorithm_type","required_libavb_version_major","required_libavb_version_minor","release_string"):
   assert getattr(old,f)==getattr(new,f),(name,f,getattr(old,f),getattr(new,f))
  reports[name]={"source_sha256":hashlib.sha256((parents/name).read_bytes()).hexdigest(),"chain_keys_updated":changed,"descriptor_count":len(ds),"flags":new.flags,"rollback_index":new.rollback_index,"sha256":hashlib.sha256(out.read_bytes()).hexdigest()}
 raw={}
 for name,source,expected in (("modem",args.modem_image,args.modem_sha256),
                              ("mcf_ota",args.mcf_ota_image,args.mcf_ota_sha256)):
  raw[name]=copy_raw(source,I/(name+".img"),expected)
 (P/"parents.json").write_text(json.dumps({"parents":reports,"raw_radio":raw,
  "lk_included":False,"preloader_included":False,"recovery_ramdisk_replaced":False,
  "root_flags_changed":False,"root_rollback_counters_changed":False,
  "hardware_qualification_required":True},indent=2)+"\n")
 print(json.dumps(reports,indent=2))

if __name__=="__main__":main()
