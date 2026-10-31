#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Project and assemble the supported LDY-AN00 kernel cohort target files."""
import argparse,copy,hashlib,json,shutil,stat,tempfile,zipfile
from pathlib import Path,PurePosixPath
from kernel_caremap import generate
from postinstall_policy import validate_config as validate_postinstall_config

FIVE=("boot","system","system_dlkm","vbmeta_system","vbmeta_system_dlkm")
TWO=("system","vbmeta_system")
DYNAMIC=("system","system_dlkm")
GROUP="super_qti_dynamic_partitions_partition_list"
LISTS=("dynamic_partition_list",GROUP)
META=("META/misc_info.txt","META/dynamic_partitions_info.txt")
DERIVED={"META/care_map.pb","META/care_map.txt","META/vbmeta_digest.txt"}
OWNER="/keys/avb/vbmeta-system.pem"

def need(ok,why):
    if not ok:raise ValueError(why)

def sha(path):
    with Path(path).open("rb") as stream:return hashlib.file_digest(stream,"sha256").hexdigest()

def digest(data):return hashlib.sha256(data).hexdigest()

def info(path):
    path=Path(path);return dict(path=str(path),bytes=path.stat().st_size,sha256=sha(path))

def parse(data):
    rows={}
    for line in data.decode().splitlines():
        if not line or line.startswith("#"):continue
        key,sep,value=line.partition("=")
        need(sep and key not in rows,"Malformed/duplicate property: "+key)
        rows[key]=value
    return rows

def encode(rows):return ("\n".join(k+"="+v for k,v in sorted(rows.items()))+"\n").encode()

def names(z):
    items=z.infolist();result={i.filename:i for i in items}
    need(len(items)==len(result),"Duplicate ZIP entry")
    for n in result:
        p=PurePosixPath(n)
        need(not p.is_absolute() and ".." not in p.parts,"Unsafe ZIP path")
    return result

def props(z):
    result={}
    for n in z.namelist():
        if n.startswith(("SYSTEM/","PRODUCT/","SYSTEM_EXT/")) and n.endswith("build.prop"):
            result[n]=parse(z.read(n))
    return result

def shipping_five(z):
    rows=props(z);seen=False
    for p in rows.values():
        for key in ("ro.vendor.build.ab_ota_partitions","ro.product.ab_ota_partitions"):
            if key in p:
                need(tuple(p[key].replace(","," ").split())==FIVE,"Shipping AB property is not five-part")
                seen|=key=="ro.vendor.build.ab_ota_partitions"
    need(seen,"Missing real shipping vendor AB property")
    need(rows.get("SYSTEM/build.prop",{}).get("ro.build.id"),"Legacy/unknown system build-ID digest semantics")
    return {n:digest(z.read(n)) for n in rows}

def cohort(contract,expected,directory):
    need(sha(contract)==expected,"Contract hash mismatch")
    c=json.loads(Path(contract).read_text());d=Path(directory)
    rows=c["inputs"]
    need(c["schema_version"]==1 and len(rows)==3 and {r["partition"] for r in rows}==set(FIVE)-set(TWO),"Wrong cohort shape")
    need({p.name for p in d.iterdir()}=={r["file"] for r in rows},"Cohort directory must contain exactly three files")
    result={}
    for r in rows:
        need(r["file"]==r["partition"]+".img","Unexpected cohort filename")
        p=d/r["file"]
        need(p.is_file() and not p.is_symlink(),"Cohort file must be regular, not symlink")
        need(p.stat().st_size==r["file_bytes"]==r["partition_bytes"]==r["payload_new_partition_bytes"],"Cohort size mismatch")
        need(sha(p)==r["sha256"],"Cohort image hash mismatch")
        result[r["partition"]]=p
    return c,result

def kernel(z,c):
    need(z.read("META/kernel_version.txt")==c["kernel_provenance"]["release"].encode(),"Kernel version mismatch")
    need(digest(z.read("META/kernel_configs.txt"))==c["kernel_provenance"]["config_sha256"],"Kernel config mismatch")

def geometry(m,dynamic):
    need(m.get("super_partition_size")=="17574133760","Unexpected super size")
    need(m.get("super_qti_dynamic_partitions_group_size")=="17569939456","Unexpected dynamic group")
    for key in LISTS:need(tuple(m[key].split())==tuple(dynamic),"Unexpected dynamic ownership")
    need(m.get("virtual_ab_cow_version")=="3" and m.get("virtual_ab_compression_method")=="none","COW contract changed")

def variants(entries,allow_known=False):
    for n,i in entries.items():
        if n.startswith(("BOOTABLE_IMAGES/","PREBUILT_IMAGES/")) and not i.is_dir():
            need(allow_known and n.split("/",1)[1]=="boot.img","Unexpected boot variant")
        if n.startswith(("BOOT/","INIT_BOOT/","VENDOR_BOOT/","RECOVERY/","SYSTEM_DLKM/")):
            need(i.is_dir() or (allow_known and n in ("BOOT/cmdline","BOOT/pagesize","BOOT/base") and
                 stat.S_IFMT(i.external_attr>>16) in (0,stat.S_IFREG) and i.file_size<=4096),
                 "Unexpected source tree for frozen firmware: "+n)

def structural_key(k):
    return k in ("no_boot","boot_images","boot_size","building_boot_image",
                 "building_system_dlkm_image") or k.startswith(("avb_boot_","avb_system_dlkm_",
                 "avb_vbmeta_system_dlkm_","system_dlkm_"))

def projected_misc(m):
    out={k:v for k,v in m.items() if not structural_key(k)}
    children=m.get("avb_custom_vbmeta_images_partition_list","").split()
    need(not set(children)-{"system_dlkm"},"Unexpected custom vbmeta child")
    out.pop("avb_custom_vbmeta_images_partition_list",None)
    out["no_boot"]="true"
    out["partial_ota_update_partitions_list"]=" ".join(TWO)
    for key in LISTS:out[key]="system"
    return out

def copyzip(source,dest,replacements,removed,files=None):
    need(not Path(dest).exists(),"Output already exists")
    files=files or {}
    try:
        with zipfile.ZipFile(source) as src,zipfile.ZipFile(dest,"w",allowZip64=True) as dst:
            index=names(src)
            for n,i in index.items():
                if n in removed or n in replacements or n in files:continue
                with src.open(i) as a,dst.open(copy.copy(i),"w",force_zip64=True) as b:
                    shutil.copyfileobj(a,b,1024*1024)
            for n,data in replacements.items():
                i=copy.copy(index[n]) if n in index else zipfile.ZipInfo(n,(2009,1,1,0,0,0))
                if n not in index:i.external_attr=(stat.S_IFREG|0o644)<<16
                dst.writestr(i,data)
            for n,path in files.items():
                i=zipfile.ZipInfo(n,(2009,1,1,0,0,0));i.external_attr=(stat.S_IFREG|0o644)<<16
                with Path(path).open("rb") as a,dst.open(i,"w",force_zip64=True) as b:
                    shutil.copyfileobj(a,b,1024*1024)
    except BaseException:
        Path(dest).unlink(missing_ok=True);raise

def entryhash(z,n):
    with z.open(n) as f:return hashlib.file_digest(f,"sha256").hexdigest()

def preserved(before,after,mutated):
    checks={}
    with zipfile.ZipFile(before) as a,zipfile.ZipFile(after) as b:
        x,y=names(a),names(b)
        need(set(x)-mutated==set(y)-mutated,"Unapproved entry-set change")
        for n in set(x)-mutated:
            need(x[n].external_attr==y[n].external_attr,"Entry permission/type changed: "+n)
            h=entryhash(a,n);need(h==entryhash(b,n),"Payload changed: "+n);checks[n]=h
    return checks

def project(source,expected,out,contract,contract_sha,directory):
    need(sha(source)==expected,"Compiler archive hash mismatch")
    c,fixed=cohort(contract,contract_sha,directory)
    with zipfile.ZipFile(source) as z:
        ix=names(z);shipping_five(z);kernel(z,c);variants(ix,True)
        need(tuple(z.read("META/ab_partitions.txt").decode().split())==FIVE,"Compiler META AB list")
        m,d=(parse(z.read(n)) for n in META)
        geometry(m,DYNAMIC);geometry(d,DYNAMIC)
        need(m.get("avb_vbmeta_system")=="system","System child must own system only")
        need(m.get("avb_vbmeta_system_dlkm")=="system_dlkm" and
             m.get("avb_vbmeta_system_dlkm_rollback_index_location")=="28","Dedicated DLKM child contract")
        need(m.get("avb_boot_rollback_index_location")=="1","Boot chain location")
        images={n for n in ix if n.startswith("IMAGES/") and n.endswith(".img")}
        need(images=={"IMAGES/"+p+".img" for p in FIVE}|{"IMAGES/vbmeta.img"},"Unexpected compiler images")
        need(entryhash(z,"IMAGES/system_dlkm.img")==sha(fixed["system_dlkm"]),"Compiler DLKM differs from cohort")
        prefix=next(r["layout"]["avb_original_image_bytes"] for r in c["inputs"] if r["partition"]=="boot")
        with fixed["boot"].open("rb") as f:boot_prefix=f.read(prefix)
        for n in ix:
            if n in ("IMAGES/boot.img","BOOTABLE_IMAGES/boot.img","PREBUILT_IMAGES/boot.img"):
                need(ix[n].file_size==fixed["boot"].stat().st_size,"Compiler boot partition size differs from cohort")
                with z.open(n) as f:need(f.read(prefix)==boot_prefix,"Compiler boot payload differs from cohort")
        if "META/postinstall_config.txt" in ix:
            validate_postinstall_config(parse(z.read("META/postinstall_config.txt")))
        removed={n for n in ix if n in DERIVED or n.startswith(("BOOTABLE_IMAGES/","PREBUILT_IMAGES/","BOOT/","INIT_BOOT/","VENDOR_BOOT/","RECOVERY/")) or
                 n in {"IMAGES/"+p+".img" for p in fixed} or
                 n.startswith("IMAGES/") and n.endswith(".map")}
        replacements={META[0]:encode(projected_misc(m)),META[1]:encode({k:("system" if k in LISTS else v) for k,v in d.items()}),
                      "META/ab_partitions.txt":("\n".join(TWO)+"\n").encode()}
    copyzip(source,out,replacements,removed)
    keep=preserved(source,out,set(replacements)|removed)
    return dict(status="SIGNER_PROJECTION_ONLY_NOT_SHIPPING_TARGETFILES",source=info(source),
        projection=info(out),contract_sha256=contract_sha,original_misc=m,original_dynamic=d,
        unchanged_entries=keep,removed=sorted(removed),replaced=sorted(replacements))

def assemble(signed,expected,projection_receipt,projection_sha,out,contract,contract_sha,directory,tools):
    need(sha(signed)==expected,"Signed archive hash mismatch")
    c,fixed=cohort(contract,contract_sha,directory)
    need(sha(projection_receipt)==projection_sha,"Projection receipt hash mismatch")
    proof=json.loads(Path(projection_receipt).read_text())
    need(proof["status"]=="SIGNER_PROJECTION_ONLY_NOT_SHIPPING_TARGETFILES" and
         proof["contract_sha256"]==contract_sha,"Projection receipt contract")
    with zipfile.ZipFile(signed) as z:
        ix=names(z);shipping_five(z);kernel(z,c);variants(ix)
        need(tuple(z.read("META/ab_partitions.txt").decode().split())==TWO,"Signed projection AB list")
        if "META/postinstall_config.txt" in ix:
            validate_postinstall_config(parse(z.read("META/postinstall_config.txt")))
        need("META/care_map.pb" in ix and z.getinfo("META/care_map.pb").file_size>0,"Missing signed-system care map")
        need({n for n in ix if n.startswith("IMAGES/") and n.endswith(".img")}==
             {"IMAGES/system.img","IMAGES/vbmeta_system.img","IMAGES/vbmeta.img"},"Unexpected signed projection images")
        m,d=(parse(z.read(n)) for n in META)
        geometry(m,("system",));geometry(d,("system",))
        need(m.get("avb_vbmeta_system")=="system" and m.get("avb_vbmeta_system_key_path")==OWNER and
             m.get("avb_vbmeta_system_rollback_index_location")=="2" and
             m.get("avb_vbmeta_system_algorithm")=="SHA256_RSA4096","Signed system owner metadata")
        original=proof["original_misc"];geometry(original,DYNAMIC)
        final=dict(m)
        for key in LISTS:final[key]=original[key];d[key]=proof["original_dynamic"][key]
        final.update(no_boot="false",boot_images="boot.img",boot_size=str(next(r["partition_bytes"] for r in c["inputs"] if r["partition"]=="boot")),
          building_system_dlkm_image="false",system_dlkm_size="33554432",system_dlkm_fs_type="erofs",
          partial_ota_update_partitions_list=" ".join(FIVE),avb_custom_vbmeta_images_partition_list="system_dlkm",
          avb_boot_algorithm="SHA256_RSA4096",avb_boot_key_path=OWNER,avb_boot_rollback_index="0",
          avb_boot_rollback_index_location="1",avb_system_dlkm_hashtree_enable="true",
          avb_system_dlkm_algorithm="SHA256_RSA4096",avb_system_dlkm_key_path=OWNER,
          avb_vbmeta_system_dlkm="system_dlkm",avb_vbmeta_system_dlkm_algorithm="SHA256_RSA4096",
          avb_vbmeta_system_dlkm_key_path=OWNER,avb_vbmeta_system_dlkm_rollback_index="0",
          avb_vbmeta_system_dlkm_rollback_index_location="28",avb_vbmeta_system_dlkm_args="--flags 0")
        need(not any(k.startswith(("avb_boot_","avb_system_dlkm_","avb_vbmeta_system_dlkm_"))
                     for k in m),"Unexpected cohort generation fields in signed projection")
        removed={n for n in ix if n in DERIVED or n=="IMAGES/vbmeta.img" or n.startswith("IMAGES/") and n.endswith(".map")}
        with tempfile.TemporaryDirectory(prefix="five-caremap-") as tmp:
            tmp=Path(tmp);system=tmp/"system.img"
            with z.open("IMAGES/system.img") as a,system.open("wb") as b:shutil.copyfileobj(a,b,1024*1024)
            care,dlkmprop,careproof=generate(system,fixed["system_dlkm"],props(z),tools,tmp)
            need(care,"Official care map missing")
            replacements={META[0]:encode(final),META[1]:encode(d),"META/ab_partitions.txt":("\n".join(FIVE)+"\n").encode(),
                          "META/care_map.pb":care,"SYSTEM_DLKM/etc/build.prop":dlkmprop}
            copyzip(signed,out,replacements,removed,{"IMAGES/"+p+".img":v for p,v in fixed.items()})
    mutated=set(replacements)|removed|{"IMAGES/"+p+".img" for p in fixed}
    keep=preserved(signed,out,mutated)
    with zipfile.ZipFile(out) as z:
        need({n for n in names(z) if n.startswith("IMAGES/") and n.endswith(".img")}==
             {"IMAGES/"+p+".img" for p in FIVE},"Final image set")
        imagehash={p:entryhash(z,"IMAGES/"+p+".img") for p in FIVE}
        for p,path in fixed.items():need(imagehash[p]==sha(path),"Fixed cohort image changed")
        with zipfile.ZipFile(signed) as before:
            for p in TWO:need(imagehash[p]==entryhash(before,"IMAGES/"+p+".img"),"Signed OS image changed")
    return dict(status="FIVE_PART_ASSEMBLED_NOT_CRYPTO_OR_DEPLOYMENT_ADMISSION",signed=info(signed),output=info(out),
      images=imagehash,unchanged_signed_entries=keep,mutated_entries=sorted(mutated),care_map=careproof,
      no_add_missing_or_image_builder=True,derived_vbmeta_digest="Removed projected diagnostic MAIN digest; real ro.build.id required",
      retained_parents_not_payload=True,contract_sha256=contract_sha)

def main():
    p=argparse.ArgumentParser();p.add_argument("mode",choices=("project","assemble"))
    for n in ("input","expected-sha256","output","contract","contract-sha256","cohort-dir","receipt"):p.add_argument("--"+n,required=True)
    p.add_argument("--projection-receipt");p.add_argument("--projection-receipt-sha256");p.add_argument("--tools")
    a=p.parse_args()
    need(not Path(a.receipt).exists(),"Receipt already exists")
    if a.mode=="project":r=project(a.input,a.expected_sha256,a.output,a.contract,a.contract_sha256,a.cohort_dir)
    else:
        need(a.projection_receipt and a.projection_receipt_sha256 and a.tools,"Assembly requires receipt and pinned tools")
        r=assemble(a.input,a.expected_sha256,a.projection_receipt,a.projection_receipt_sha256,a.output,a.contract,a.contract_sha256,a.cohort_dir,json.loads(Path(a.tools).read_text()))
    Path(a.receipt).write_text(json.dumps(r,indent=2)+"\n")
if __name__=="__main__":main()
