#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit target-files projection and assembly for the stock11 hardware trial."""
import argparse
import hashlib
import json
import logging
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from kernel_cohort import copyzip, encode, entryhash, info, names, need, parse, props, sha
from kernel_caremap import generate, check, functions

PARTS = tuple("boot init_boot vendor_boot dtbo system system_dlkm vendor vendor_dlkm odm odm_dlkm vbmeta vbmeta_system vbmeta_system_dlkm vbmeta_vendor vbmeta_vendor_dlkm vbmeta_odm vbmeta_odm_dlkm recovery_vbmeta".split())
DYNAMIC = "system system_dlkm vendor vendor_dlkm odm odm_dlkm"
LISTS = ("dynamic_partition_list", "super_qti_dynamic_partitions_partition_list")
META = ("META/misc_info.txt", "META/dynamic_partitions_info.txt")
TWO = ("system", "vbmeta_system")
DERIVED = {"META/care_map.pb", "META/care_map.txt", "META/vbmeta_digest.txt"}
PREFIXES = ("BOOT/", "INIT_BOOT/", "VENDOR_BOOT/", "RECOVERY/", "BOOTABLE_IMAGES/", "PREBUILT_IMAGES/", "RADIO/", "VENDOR/", "ODM/", "VENDOR_DLKM/", "ODM_DLKM/", "SYSTEM_DLKM/")

def verify_hardware(contract, directory):
    c = json.loads(Path(contract).read_text())
    need(c["schema"] == "ldy-stock11-hardware-inputs-v1", "Wrong hardware contract")
    expected = set(PARTS) - set(TWO)
    need(len(c["inputs"]) == len(expected), "Unexpected hardware input count")
    need({r["partition"] for r in c["inputs"]} == expected, "Wrong hardware partition set")
    result = {}
    for row in c["inputs"]:
        need(row["file"] == row["partition"] + ".img", "Unexpected hardware filename")
        p = Path(directory) / row["file"]
        need(p.is_file() and not p.is_symlink(), "Hardware input must be regular")
        need(p.stat().st_size == row["file_bytes"] and sha(p) == row["sha256"], "Hardware input mismatch: " + row["partition"])
        result[row["partition"]] = p
    need({p.name for p in Path(directory).iterdir()} == {r["file"] for r in c["inputs"]}, "Unexpected cohort member")
    return c, result

def check_metadata(m):
    need(m["super_partition_size"] == "17574133760", "Unexpected super geometry")
    need(m["super_qti_dynamic_partitions_group_size"] == "17569939456", "Unexpected group geometry")
    need(m["virtual_ab"] == "true" and m.get("virtual_ab_compression", "false") == "false", "Wrong snapshot policy")
    for key in LISTS:
        need(sorted(m[key].split()) == sorted(DYNAMIC.split()), "Unexpected dynamic ownership")

def project(source, out, contract, directory, content):
    c, hardware = verify_hardware(contract, directory)
    additions = {}
    for partition in ("vendor", "odm"):
        root = Path(content) / partition
        selected = [p for p in root.rglob("*") if p.is_file() and (str(p.relative_to(root)) in ("build.prop", "etc/build.prop") or str(p.relative_to(root)).startswith("etc/vintf/"))]
        need(selected, "Missing actual vendor compatibility metadata")
        for p in selected:
            additions[partition.upper() + "/" + str(p.relative_to(root))] = p
    with zipfile.ZipFile(source) as z:
        ix = names(z)
        need(sorted(z.read("META/ab_partitions.txt").decode().split()) == sorted(PARTS), "Compiler AB scope mismatch")
        m, d = (parse(z.read(n)) for n in META)
        original_dynamic = dict(d)
        check_metadata(m)
        for key in LISTS:
            need(sorted(d[key].split()) == sorted(DYNAMIC.split()), "Dynamic metadata disagrees")
        shipping = [x["ro.vendor.build.ab_ota_partitions"] for x in props(z).values() if "ro.vendor.build.ab_ota_partitions" in x]
        need(shipping and all(tuple(x.split(",")) == PARTS for x in shipping), "Shipping AB scope mismatch")
        need(z.read("META/kernel_version.txt").decode().strip() == c["kernel_release"], "Kernel identity mismatch")
        for partition in PARTS:
            need(any(n in ix for n in ("IMAGES/" + partition + ".img", "RADIO/" + partition + ".img")), "Missing compiler partition: " + partition)
        removed = {n for n in ix if n in DERIVED or n.startswith(PREFIXES) or n.startswith("IMAGES/") and n not in ("IMAGES/system.img", "IMAGES/vbmeta_system.img", "IMAGES/vbmeta.img")}
        signed_meta = {}
        frozen = set(PARTS) - set(TWO) - {"vbmeta"}
        for key, value in m.items():
            if key == "avb_custom_vbmeta_images_partition_list" or key in ("boot_images", "boot_size"):
                continue
            if any(key == "building_" + p + "_image" or key.startswith((p + "_", "avb_" + p + "_")) for p in frozen):
                continue
            signed_meta[key] = value
        signed_meta.update(no_boot="true", partial_ota_update_partitions_list=" ".join(TWO))
        for key in LISTS:
            signed_meta[key] = "system"
            d[key] = "system"
        replacements = {META[0]: encode(signed_meta), META[1]: encode(d), "META/ab_partitions.txt": b"system\nvbmeta_system\n"}
        # Actual immutable vendor metadata is supplied for VINTF checks, never OEM APKs.
        copyzip(source, out, replacements, removed, additions)
    return dict(status="SYSTEM_SIGNING_PROJECTION_NOT_INSTALLABLE", source=info(source), output=info(out), contract_sha256=sha(contract), original_misc=m, original_dynamic=original_dynamic, vendor_metadata={n:sha(p) for n,p in additions.items()})

def generate_migration_caremap(system, hardware, system_props, tools, temp):
    _, dlkmprop, proof = generate(system, hardware["system_dlkm"], system_props, tools, temp)
    paths = {k:check(v) for k,v in tools.items()}
    extra = ("vendor", "odm", "vendor_dlkm", "odm_dlkm")
    env = dict(os=os, tempfile=tempfile, sparse_img=sys.modules["sparse_img"],
        avbtool=sys.modules["avbtool"], rangelib=sys.modules["rangelib"],
        logger=logging.getLogger(__name__), PARTITIONS_WITH_CARE_MAP=extra)
    functions(paths["common"], {"IsSparseImage"}, env)
    functions(paths["add_img"], {"ParseAvbFooter", "GetCareMap"}, env)
    build_properties = {"SYSTEM_DLKM/etc/build.prop":dlkmprop}
    text = (temp / "care_map.parsed.txt").read_text().splitlines()
    avb = sys.modules["avbtool"]
    for part in extra:
        image = hardware[part]
        before = sha(image)
        pair = env["GetCareMap"](part, str(image))
        need(pair and pair[1], "Missing hardware care-map range")
        handle = avb.ImageHandler(str(image), read_only=True)
        _, _, descriptors, _ = avb.Avb()._parse_image(handle)
        properties = {d.key:d.value for d in descriptors if isinstance(d,avb.AvbPropertyDescriptor)}
        key = "com.android.build." + part + ".fingerprint"
        need(key in properties, "Missing signed hardware fingerprint")
        value = properties[key].decode()
        need(value and "\n" not in value, "Malformed signed hardware fingerprint")
        runtime_key = "ro." + part + ".build.fingerprint"
        if part.endswith("_dlkm"):
            extract = temp / part
            command = [str(paths["fsck.erofs"]),"--extract="+str(extract),
                "--no-preserve","--no-xattrs",str(image)]
            subprocess.run(command,check=True,capture_output=True)
            prop = extract / "etc/build.prop"
            need(prop.is_file() and not prop.is_symlink(), "Missing exact module build properties")
            raw = prop.read_bytes()
            actual_props = parse(raw)
            need(actual_props.get(runtime_key) == value, "Module fingerprint disagrees with signed AVB")
            need(actual_props.get("ro."+part+".build.date.utc","").isdecimal(),
                "Missing actual module partition timestamp")
            build_properties[part.upper()+"/etc/build.prop"] = raw
        text += pair + [runtime_key, value]
        need(sha(image) == before, "Care-map changed hardware image")
        proof["partitions"].append(dict(partition=part, ranges=pair[1],
            property=runtime_key, fingerprint=value, image_sha256=before,
            identity_source="signed AVB property descriptor"))
    text = "\n".join(text)
    source = temp / "care_map_all.txt"
    binary = temp / "care_map_all.pb"
    parsed = temp / "care_map_all.parsed.txt"
    source.write_text(text)
    for args in ([str(paths["generator"]),str(source),str(binary)],
                 [str(paths["generator"]),"--parse_proto",str(binary),str(parsed)]):
        subprocess.run(args, check=True, capture_output=True)
    need(binary.stat().st_size > 0 and parsed.read_text() == text,
         "Six-part care-map roundtrip failed")
    proof["sha256"] = sha(binary)
    proof["scope"] = "Official footer-bounded ranges for all six updated logical partitions; existing system properties and signed hardware fingerprints."
    return binary.read_bytes(), build_properties, proof

def immutable_metadata(original, signed, name, digest):
    need(hashlib.sha256(original).hexdigest() == digest, "Original OEM metadata changed")
    if original != signed:
        normalize = lambda raw: raw.replace(b"\r\n", b"\n").rstrip(b"\n")
        need(name.endswith("/build.prop") and normalize(original) == normalize(signed),
             "Immutable OEM metadata changed: " + name)
    return original

def assemble(source, out, contract, directory, receipt, tools):
    c, hardware = verify_hardware(contract, directory)
    proof = json.loads(Path(receipt).read_text())
    need(proof["status"] == "SYSTEM_SIGNING_PROJECTION_NOT_INSTALLABLE" and proof["contract_sha256"] == sha(contract), "Wrong projection proof")
    with zipfile.ZipFile(source) as z, tempfile.TemporaryDirectory(prefix="vendor-migration-caremap-") as temp:
        ix = names(z)
        need(tuple(z.read("META/ab_partitions.txt").decode().split()) == TWO, "Signed projection AB mismatch")
        need({n for n in ix if n.startswith("IMAGES/") and n.endswith(".img")} == {"IMAGES/system.img", "IMAGES/vbmeta_system.img", "IMAGES/vbmeta.img"}, "Unexpected signed projection images")
        m = parse(z.read(META[0]))
        need(m["avb_vbmeta_system_key_path"] == "/keys/avb/vbmeta-system.pem" and m["avb_vbmeta_system_rollback_index_location"] == "2", "Wrong signed system identity")
        original = proof["output"]
        need(info(original["path"]) == original, "Original signing projection changed")
        with zipfile.ZipFile(original["path"]) as projected:
            names(projected)
            metadata = {n:immutable_metadata(projected.read(n), z.read(n), n, digest)
                        for n,digest in proof["vendor_metadata"].items()}
        final = dict(proof["original_misc"])
        for key, value in m.items():
            if key.startswith(("avb_system_", "avb_vbmeta_system_")):
                final[key] = value
        final.update(kernel_only_boot_ota="true", partial_ota_update_partitions_list=" ".join(PARTS))
        for part in ("boot", "system_dlkm", "vbmeta_system_dlkm"):
            key = "avb_" + part + "_key_path"
            if key in final:
                final[key] = "/keys/avb/vbmeta-system.pem"
        check_metadata(final)
        temp = Path(temp)
        system = temp / "system.img"
        with z.open("IMAGES/system.img") as a, system.open("wb") as b:
            import shutil
            shutil.copyfileobj(a, b, 1024 * 1024)
        care, module_props, careproof = generate_migration_caremap(system, hardware, props(z), json.loads(Path(tools).read_text()), temp)
        need(set(module_props) == {"SYSTEM_DLKM/etc/build.prop", "VENDOR_DLKM/etc/build.prop", "ODM_DLKM/etc/build.prop"}, "Missing actual module version metadata")
        replacements = {META[0]:encode(final), META[1]:encode(proof["original_dynamic"]), "META/ab_partitions.txt":("\n".join(PARTS)+"\n").encode(), "META/care_map.pb":care, **module_props, **metadata}
        removed = DERIVED | {"IMAGES/vbmeta.img"}
        copyzip(source, out, replacements, removed, {"IMAGES/"+p+".img":f for p,f in hardware.items()})
    with zipfile.ZipFile(out) as z:
        need({n for n in names(z) if n.startswith("IMAGES/") and n.endswith(".img")} == {"IMAGES/"+p+".img" for p in PARTS}, "Final image set mismatch")
        for p,f in hardware.items():
            need(entryhash(z, "IMAGES/"+p+".img") == sha(f), "Hardware image changed during assembly")
        for n in ("IMAGES/system.img", "IMAGES/vbmeta_system.img"):
            with zipfile.ZipFile(source) as before:
                need(entryhash(z,n)==entryhash(before,n), "Signed system changed")
    return dict(status="ASSEMBLED_NOT_HARDWARE_QUALIFIED", input=info(source), output=info(out), parts=PARTS, kernel_release=c["kernel_release"], caremap=careproof, preserves=["lk", "preloader", "tee", "modem", "recovery_ramdisk"])

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("project","assemble"))
    for n in ("input","output","contract","cohort-dir","report"):
        p.add_argument("--"+n, required=True)
    p.add_argument("--content")
    p.add_argument("--projection-receipt")
    p.add_argument("--caremap-tools")
    a=p.parse_args()
    if a.mode=="project":
        need(a.content, "Project requires --content")
        result=project(a.input,a.output,a.contract,a.cohort_dir,a.content)
    else:
        need(a.projection_receipt and a.caremap_tools, "Assembly requires receipt and caremap tools")
        result=assemble(a.input,a.output,a.contract,a.cohort_dir,a.projection_receipt,a.caremap_tools)
    Path(a.report).write_text(json.dumps(result,indent=2)+"\n")

if __name__=="__main__":
    main()
