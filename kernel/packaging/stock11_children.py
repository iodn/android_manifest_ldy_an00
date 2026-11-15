#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Package the matched LDY-AN00 kernel, modules and qualified first-stage loader."""
from pathlib import Path
import argparse,sys,os,json,struct,hashlib,shutil,subprocess,stat,re,importlib.util
import erofs_metadata as meta
from init_boot import parse_cpio,encode_cpio,prepare as prepare_init_boot
from kmi import parse_kmi

LEGACY_INIT_SHA256="25f59c2e9a78b2918164cfca72a4ca7b25f226a491ba33b07018c28063e0c20f"
OVERRIDES={
 "vendor_dlkm/lib/modules/bluetooth.ko",
 "vendor_dlkm/lib/modules/netfs.ko",
 "vendor_ramdisk/lib/modules/rfkill.ko",
 "vendor_ramdisk/lib/modules/libarc4.ko",
}

def check_file(path,expected):
 with Path(path).open("rb") as stream:actual=hashlib.file_digest(stream,"sha256").hexdigest()
 if actual!=expected:raise ValueError("Input hash mismatch: "+Path(path).name)

def verify_stock_inputs(root,manifest):
 rows=json.loads(Path(manifest).read_text())
 wanted={"dtbo","system_dlkm","vendor_dlkm","vendor_boot","vendor","odm","odm_dlkm"}
 selected=[row for row in rows if row["partition"] in wanted]
 if len(selected)!=len(wanted) or {row["partition"] for row in selected}!=wanted:
  raise ValueError("Stock image inventory mismatch")
 for row in selected:
  path=Path(root)/"images"/(row["partition"]+".img")
  if path.stat().st_size!=row["bytes"]:raise ValueError("Stock image size mismatch")
  check_file(path,row["sha256"])
 return {row["partition"]:row for row in selected}

def verify_kernel_receipt(workspace,dist,receipt):
 proof=json.loads(Path(receipt).read_text())
 release=(Path(dist)/"include/config/kernel.release").read_text().strip()
 if release!=proof["kernel_release"] or not release.startswith("6.12.58-LDY-AN00-android16-6-"):
  raise ValueError("Kernel release differs from the qualified .58 recipe")
 identity=subprocess.check_output(["git","-C",str(Path(workspace)/"common"),"rev-parse","HEAD","HEAD^{tree}"],text=True).splitlines()
 if identity!=[proof["source_commit"],proof["source_tree"]] or subprocess.check_output(
     ["git","-C",str(Path(workspace)/"common"),"status","--porcelain"],text=True):
  raise ValueError("Kernel source identity differs from the qualified recipe")
 artifacts=proof["reference_artifacts"]
 if set(artifacts)!={"Image","Image.lz4","vmlinux","kernel_aarch64_dot_config","Module.symvers"}:
  raise ValueError("Kernel artifact receipt is incomplete")
 for name,row in artifacts.items():
  path=Path(dist)/name
  if path.stat().st_size!=row["bytes"]:raise ValueError("Kernel artifact size mismatch")
  check_file(path,row["sha256"])

def extract_tree(image,destination,tool,expected):
 # Decode authenticated image bytes, never reuse an external extracted tree.
 check_file(image,expected)
 if Path(destination).exists():raise ValueError("Extraction destination must be new")
 subprocess.run([str(tool),"--extract="+str(destination),"--no-preserve","--no-xattrs",
                 str(image)],check=True)
 check_file(image,expected)
 if not Path(destination).is_dir() or Path(destination).is_symlink():
  raise ValueError("Invalid extracted filesystem root")

def verify_overrides(directory):
 actual={str(p.relative_to(directory)) for p in Path(directory).rglob("*") if p.is_file()}
 if actual!=OVERRIDES:raise ValueError("Requires the exact four reviewed module overrides")

def replace_vendor_modules(raw,directory,abi):
 entries=parse_cpio(raw);updated=[];replaced=[]
 for name,header,data in entries:
  canonical=name.removeprefix("./")
  key="vendor_ramdisk/"+canonical
  if key in OVERRIDES:
   if hashlib.sha256(data).hexdigest()!=abi[key]["sha256"]:
    raise ValueError("Stock ramdisk module mismatch: "+canonical)
   data=(Path(directory)/key).read_bytes();header=header.copy();header[6]=len(data)
   replaced.append(name)
  updated.append((name,header,data))
 if {name.removeprefix("./") for name in replaced}!={"lib/modules/rfkill.ko","lib/modules/libarc4.ko"} or len(replaced)!=2:
  raise ValueError("Vendor ramdisk replacement scope mismatch")
 archive=encode_cpio(updated)
 if parse_cpio(archive)!=updated:raise ValueError("Vendor ramdisk round-trip mismatch")
 return archive,replaced

def main():
 if not __debug__:raise RuntimeError("Optimized Python is not supported")
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ("workspace","stock-root","stock-manifest","stock-boot","stock-init-boot",
              "first-stage-init","module-abi","module-overrides","kernel-provenance","key","output"):
  parser.add_argument("--"+name,type=Path,required=True)
 for name in ("stock-boot-sha256","stock-init-boot-sha256"):
  parser.add_argument("--"+name,required=True)
 args=parser.parse_args()
 W=args.workspace;S=args.stock_root;B=W/"bazel-bin/common/kernel_aarch64"
 T=W/"prebuilts/kernel-build-tools/linux-x86/bin";KEY=args.key;AVB=W/"external/avb/avbtool.py"
 verify_kernel_receipt(W,B,args.kernel_provenance)
 if parse_kmi((B/"Image").read_bytes())!="android16-6.12":
  raise ValueError("Unexpected kernel KMI")
 P=args.output;P.mkdir();WORK=P/"work";WORK.mkdir();IM=P/"images";IM.mkdir()
 (P/"avbtool").symlink_to(AVB);os.environ["PATH"]=str(P)+":"+str(T)+":"+os.environ["PATH"]
 spec=importlib.util.spec_from_file_location("avb",AVB);avb=importlib.util.module_from_spec(spec);spec.loader.exec_module(avb)
 stock_inputs=verify_stock_inputs(S,args.stock_manifest)
 check_file(args.stock_boot,args.stock_boot_sha256)
 check_file(args.stock_init_boot,args.stock_init_boot_sha256)
 check_file(args.first_stage_init,LEGACY_INIT_SHA256)
 verify_overrides(args.module_overrides)
 def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
 def run(*args):subprocess.run([str(x) for x in args],check=True)
 def align(n,a=4096):return (n+a-1)//a*a
 def vbmeta(path):
  with path.open("rb") as f:
   if f.read(4)==b"AVB0":f.seek(0)
   else:
    f.seek(-64,2);footer=avb.AvbFooter(f.read(64));f.seek(footer.vbmeta_offset)
   h=avb.AvbVBMetaHeader(f.read(256));f.seek(-256,1);blob=f.read(256+h.authentication_data_block_size+h.auxiliary_data_block_size)
  assert avb.verify_vbmeta_signature(h,blob),path
  offset=256+h.authentication_data_block_size+h.descriptors_offset
  ds=avb.parse_descriptors(blob[offset:offset+h.descriptors_size])
  return h,ds,blob
 def properties(ds):
  out=[]
  for d in ds:
   if isinstance(d,avb.AvbPropertyDescriptor):out.extend(["--prop",d.key+":"+d.value.decode()])
  return out
 def hash_sign(path,stock,name,size):
  h,ds,_=vbmeta(stock);hd=next(d for d in ds if isinstance(d,avb.AvbHashDescriptor));assert hd.partition_name==name
  run(sys.executable,AVB,"add_hash_footer","--image",path,"--partition_name",name,"--partition_size",size,"--algorithm","SHA256_RSA4096","--key",KEY,"--hash_algorithm",hd.hash_algorithm,"--salt",hd.salt.hex(),"--rollback_index",h.rollback_index,"--rollback_index_location",h.rollback_index_location,"--flags",h.flags,*properties(ds))
  run(sys.executable,AVB,"verify_image","--image",path,"--key",KEY)
 # Own kernel, with the same reviewed GKI certificate mechanism as the current release.
 sys.path.insert(0,str(W/"tools/mkbootimg"))
 from gki.certify_bootimg import add_certificate
 boot=IM/"boot.img";stockboot=args.stock_boot
 ramdisk=WORK/"empty-ramdisk";ramdisk.write_bytes(b"")
 run(sys.executable,W/"tools/mkbootimg/mkbootimg.py","--header_version","4","--kernel",B/"Image.lz4","--ramdisk",ramdisk,"--cmdline","","--output",boot)
 assert boot.read_bytes()[12:4096]==stockboot.read_bytes()[12:4096],"Stock boot header layout changed"
 release=(B/"include/config/kernel.release").read_text().strip()
 add_certificate(str(boot),"SHA256_RSA4096",str(KEY),["--prop","ARCH:arm64","--prop","BRANCH:","--prop","KERNEL_RELEASE:"+release])
 hash_sign(boot,stockboot,"boot",67108864)
 # Rebuild only the module filesystems that carry our signed replacements.
 stock_abi=json.loads(args.module_abi.read_text())
 built={p.name:p for p in B.rglob("*.ko") if "unstripped" not in p.relative_to(B).parts}
 for relative in OVERRIDES:check_file(args.module_overrides/relative,sha(built[Path(relative).name]))
 def build_dlkm(name):
  original=S/"images"/(name+".img");expected=meta.metadata(original);tree=WORK/(name+"-tree")
  extract_tree(original,tree,T/"fsck.erofs",stock_inputs[name]["sha256"])
  changes=[]
  for p in tree.rglob("*.ko"):
   rel=str(p.relative_to(tree));key=name+"/"+rel
   replace=(name=="system_dlkm") or (args.module_overrides/key).is_file()
   if not replace:continue
   assert sha(p)==stock_abi[key]["sha256"]
   src=built[p.name];shutil.copyfile(src,p);changes.append({"path":rel,"source":str(src.relative_to(B)),"sha256":sha(p)})
  assert len(changes)==(104 if name=="system_dlkm" else 2)
  for row in expected["inodes"]:
   path=tree/row["path"];assert set(row["xattrs"])=={"security.selinux"}
   if not path.is_symlink():os.chmod(path,stat.S_IMODE(row["mode"]))
   stamp=row["mtime"]*10**9+row["mtime_nsec"];os.utime(path,ns=(stamp,stamp),follow_symlinks=False)
  fsconfig=WORK/(name+"-fs-config");fsconfig.write_text("".join((name+"/"+x["path"] if x["path"] else "/")+" "+str(x["uid"])+" "+str(x["gid"])+" "+format(stat.S_IMODE(x["mode"]),"o")+"\n" for x in expected["inodes"]))
  contexts=WORK/(name+"-contexts");contexts.write_text("".join(re.escape("/"+name+("/"+x["path"] if x["path"] else ""))+" "+bytes.fromhex(x["xattrs"]["security.selinux"]).rstrip(b"\0").decode()+"\n" for x in expected["inodes"]))
  image=IM/(name+".img")
  run(T/"mkfs.erofs","-b4096","-zlz4hc,level=9","-T"+str(expected["build_time"]),"-U"+expected["uuid"],"--mount-point=/"+name,"--file-contexts="+str(contexts),"--fs-config-file="+str(fsconfig),image,tree)
  assert meta.metadata(image)["inodes"]==expected["inodes"],"Filesystem ownership/labels/mode/times changed"
  h,ds,_=vbmeta(original);hd=next(d for d in ds if isinstance(d,avb.AvbHashtreeDescriptor));assert hd.partition_name==name
  child=IM/("vbmeta_"+name+".img")
  run(sys.executable,AVB,"add_hashtree_footer","--image",image,"--partition_name",name,"--partition_size",original.stat().st_size,"--algorithm","SHA256_RSA4096","--key",KEY,"--hash_algorithm",hd.hash_algorithm,"--salt",hd.salt.hex(),"--fec_num_roots",hd.fec_num_roots,"--rollback_index",h.rollback_index,"--flags",h.flags,*properties(ds),"--output_vbmeta_image",child)
  child.write_bytes(child.read_bytes().ljust(1048576,b"\0"))
  run(sys.executable,AVB,"verify_image","--image",image,"--key",KEY)
  run(sys.executable,AVB,"verify_image","--image",child,"--key",KEY)
  return changes
 changes={n:build_dlkm(n) for n in ("system_dlkm","vendor_dlkm")}
 # Preserve the stock CPIO metadata and all vendor_boot fields other than ramdisk size.
 orig=S/"images/vendor_boot.img";data=orig.read_bytes();assert data[:8]==b"VNDRBOOT" and struct.unpack_from("<I",data,8)[0]==4
 page=struct.unpack_from("<I",data,12)[0];rs=struct.unpack_from("<I",data,24)[0];dtbs=struct.unpack_from("<I",data,2100)[0];ts,count,esize,bs=struct.unpack_from("<IIII",data,2112)
 assert page==4096 and count==1 and esize>=108 and ts==esize
 ro=align(2128,page);dto=ro+align(rs,page);to=dto+align(dtbs,page);bo=to+align(ts,page)
 assert bo+bs<=len(data) and ro+rs<=len(data) and to+ts<=len(data)
 compressed=WORK/"vendor-ramdisk.lz4";compressed.write_bytes(data[ro:ro+rs])
 raw=subprocess.check_output([str(T/"lz4"),"-d","-c",str(compressed)])
 cpio,replaced=replace_vendor_modules(raw,args.module_overrides,stock_abi)
 newraw=WORK/"vendor-ramdisk.cpio";newraw.write_bytes(cpio);newcompressed=WORK/"vendor-ramdisk-new.lz4"
 with newcompressed.open("wb") as f:subprocess.run([str(T/"lz4"),"-l","-12","-c",str(newraw)],stdout=f,check=True)
 assert subprocess.check_output([str(T/"lz4"),"-d","-c",str(newcompressed)])==cpio
 newdata=newcompressed.read_bytes();head=bytearray(data[:ro]);struct.pack_into("<I",head,24,len(newdata))
 table=bytearray(data[to:to+ts]);old_entry_size,offset=struct.unpack_from("<II",table);assert offset==0 and old_entry_size==rs
 struct.pack_into("<I",table,0,len(newdata))
 vboot=IM/"vendor_boot.img";prefix=bytearray(head)
 for section in (newdata,data[dto:dto+dtbs],table,data[bo:bo+bs]):prefix.extend(section);prefix.extend(b"\0"*((-len(prefix))%page))
 vboot.write_bytes(prefix);hash_sign(vboot,orig,"vendor_boot",100663296)
 # Keep the original RSA-authenticated metadata for unmodified logical vendor partitions.
 for name in ("vendor","odm","odm_dlkm"):
  original=S/"images"/(name+".img");h,ds,blob=vbmeta(original);child=IM/("vbmeta_"+name+".img");child.write_bytes(blob.ljust(1048576,b"\0"))
  (IM/(name+".img")).symlink_to(original)
  run(sys.executable,AVB,"verify_image","--image",child)
 # The stock117 first-stage loader cannot mount writable kernel snapshots.
 # Retain the qualified stock113 loader, preserving every other stock117 ramdisk entry.
 unsigned,init_report=prepare_init_boot(args.stock_init_boot.read_bytes(),args.stock_init_boot_sha256,
                                      args.first_stage_init.read_bytes(),LEGACY_INIT_SHA256,T/"lz4")
 init_boot=IM/"init_boot.img";init_boot.write_bytes(unsigned)
 hash_sign(init_boot,args.stock_init_boot,"init_boot",8388608)
 shutil.copyfile(S/"images/dtbo.img",IM/"dtbo.img")
 result={"kernel_release":release,"first_stage_init":init_report,"module_abi_sha256":sha(args.module_abi),"stock_manifest_sha256":sha(args.stock_manifest),"kernel_provenance_sha256":sha(args.kernel_provenance),"changed_module_paths":changes,"vendor_ramdisk_replacements":replaced,"images":{p.name:{"bytes":p.stat().st_size,"sha256":sha(p),"retained_stock":p.is_symlink()} for p in sorted(IM.iterdir())},"phone_written":False,"lk_included":False,"status":"CHILD_IMAGES_CREATED_PARENT_AND_OTA_INTEGRATION_PENDING"}
 (P/"children.json").write_text(json.dumps(result,indent=2)+"\n")
 print("HARDWARE_CHILD_IMAGES_READY",len(result["images"]))


if __name__=="__main__":main()
