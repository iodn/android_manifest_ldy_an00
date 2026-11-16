#!/usr/bin/env python3
"""Replace only Recovery's public OTA certificate before child AVB signing."""
import argparse, hashlib, io, json, struct, subprocess, zipfile
from pathlib import Path
import stat, ssl
# SPDX-License-Identifier: Apache-2.0
AB_PROPERTIES = ["ro.vendor.build.ab_ota_partitions", "ro.product.ab_ota_partitions"]
CANONICAL_PROPERTIES = ["prop.default", "system/product/etc/build.prop"]
PARTITIONS = "boot,init_boot,vendor_boot,dtbo,system,system_dlkm,vendor,vendor_dlkm,odm,odm_dlkm,vbmeta,vbmeta_system,vbmeta_system_dlkm,vbmeta_vendor,vbmeta_vendor_dlkm,vbmeta_odm,vbmeta_odm_dlkm,recovery_vbmeta,modem,mcf_ota"
TARGET = "system/etc/security/otacerts.zip"
def require(ok, why):
    if not ok:
        raise ValueError(why)
def digest(data):
    return hashlib.sha256(data).hexdigest()
def records(data):
    out = []
    off = 0
    while True:
        start = off
        require(data[off:off+6] == b"070701", "Unsupported CPIO format")
        values = [int(data[off+6+i*8:off+14+i*8],16) for i in range(13)]
        n, size = values[11], values[6]
        namebytes = data[off+110:off+110+n]
        require(len(namebytes)==n and namebytes.endswith(b"\0"), "Invalid CPIO name")
        name = namebytes[:-1].decode().removeprefix("./")
        require(not name.startswith("/") and ".." not in name.split("/"), "Unsafe CPIO path")
        body = (off+110+n+3)&~3
        end = (body+size+3)&~3
        require(end <= len(data), "Truncated CPIO record")
        out.append((name,values,data[start:body],data[body:body+size],data[start:end]))
        off = end
        if name == "TRAILER!!!":
            require(not any(data[off:]), "Nonzero data after CPIO trailer")
            require(len({row[0] for row in out})==len(out), "Duplicate CPIO record")
            return out,data[off:]
def sha(p):
    with Path(p).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()

def pin(row):
    require(sha(row["path"]) == row["sha256"], "Pinned input changed: " + row["path"])

def properties(data):
    result = {}
    for line in data.decode().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            require(k not in AB_PROPERTIES or k not in result or result[k] == v, "Conflicting AB property")
            result[k] = v
    return result

def check_image(data, lz4):
    require(data[:8] == b"ANDROID!", "Not Android image")
    kernel, length, osword, header = struct.unpack_from("<4I", data, 8)
    require(kernel == 0 and header == 1584 and osword == 536871324, "Header compatibility changed")
    require(struct.unpack_from("<I", data, 40)[0] == 4 and not any(data[44:1584]), "Header v4/cmdline/signature contract changed")
    prefix = (4096 + length + 4095) // 4096 * 4096
    require(len(data) == prefix, "Unsigned image includes padding/footer or is truncated")
    ramdisk = data[4096:4096+length]
    require(ramdisk[:4] == bytes.fromhex("02214c18"), "Ramdisk not legacy LZ4")
    unpacked = subprocess.run([lz4, "-dc"], input=ramdisk, capture_output=True, check=True).stdout
    entries = {row[0]:(row[1][1],row[3]) for row in records(unpacked)[0]}
    checks = {}
    for name in CANONICAL_PROPERTIES:
        require(name in entries and stat.S_ISREG(entries[name][0]), "Missing canonical regular property file: " + name)
        props = properties(entries[name][1])
        if name == "prop.default":
            require("ro.odm.build.date.utc" not in props, "Synthetic unbuilt ODM timestamp remains")
        for key in AB_PROPERTIES:
            require(len(props.get(key, "").split(",")) == 20 and set(props.get(key, "").split(",")) == set(PARTITIONS.split(",")), "Wrong effective AB scope: " + name + ":" + key)
        checks[name] = hashlib.sha256(entries[name][1]).hexdigest()
    require(entries.get("product", (0,b""))[1] == b"/system/product" and stat.S_ISLNK(entries["product"][0]), "Canonical product symlink differs")
    return ramdisk, checks

def owner_zip(cert):
    buf = io.BytesIO()
    info = zipfile.ZipInfo("ota.x509.pem",(1980,1,1,0,0,0))
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    info.compress_type = zipfile.ZIP_STORED
    with zipfile.ZipFile(buf,"w") as z:
        z.writestr(info,cert)
    return buf.getvalue()
def replace(data, cert, build_epoch=None, unbuilt_odm=False):
    old, tail = records(data)
    targets=[row for row in old if row[0]==TARGET]
    require(len(targets)==1, "Exactly one OTA trust file required")
    changes={TARGET:owner_zip(cert)}
    odm_receipt={"removed":False}
    if build_epoch is not None:
        require(unbuilt_odm is True, "Unbuilt ODM proof required")
        defaults=[row for row in old if row[0]=="prop.default"]
        require(len(defaults)==1, "Canonical prop.default required")
        lines=defaults[0][3].splitlines(keepends=True)
        matches=[line for line in lines if line.rstrip(b"\r\n").startswith(b"ro.odm.build.date.utc=")]
        require(len(matches)<=1, "Duplicate synthetic ODM property")
        if matches:
            expected=b"ro.odm.build.date.utc="+str(build_epoch).encode()
            require(matches[0].rstrip(b"\r\n")==expected, "Unexpected ODM timestamp; preserve genuine values")
            changes["prop.default"]=b"".join(line for line in lines if line is not matches[0])
            odm_receipt={"removed":True,"removed_line":expected.decode(),"build_epoch":build_epoch,"build_odm_image":False,"original_prop_default_sha256":digest(defaults[0][3]),"final_prop_default_sha256":digest(changes["prop.default"])}
    encoded=[]
    for row in old:
        if row[0] not in changes:
            encoded.append(row[4]);continue
        require(row[1][1]&0o170000==0o100000 and row[1][4]==1, "Changed file must be unshared regular file")
        content=changes[row[0]]
        header=bytearray(row[2]);header[54:62]=f"{len(content):08x}".encode()
        encoded.append(bytes(header)+content+bytes((-len(content))%4))
    new=b"".join(encoded)+tail
    after,newtail=records(new)
    require(newtail==tail and len(old)==len(after), "CPIO structure changed")
    for before,now in zip(old,after):
        require(before[0]==now[0], "CPIO record order changed")
        if before[0] not in changes:
            require(before[4]==now[4], "Unrelated CPIO record changed")
        else:
            expected=list(before[1]);expected[6]=len(changes[before[0]])
            require(now[1]==expected and now[2][:54]==before[2][:54] and now[2][62:]==before[2][62:], "Changed file metadata changed")
            require(now[3]==changes[before[0]], "Changed content mismatch")
    trust=next(row[3] for row in after if row[0]==TARGET)
    with zipfile.ZipFile(io.BytesIO(trust)) as z:
        require(z.namelist()==["ota.x509.pem"] and z.read("ota.x509.pem")==cert, "Owner-only trust verification failed")
    return new,old,after,odm_receipt
def finalize(data, cert, lz4, build_epoch=None, unbuilt_odm=False):
    require(data[:8]==b"ANDROID!" and len(data)>=4096,"Invalid unsigned image")
    kernel,n,osword,header=struct.unpack_from("<4I",data,8)
    require(kernel==0 and osword==536871324 and header==1584 and struct.unpack_from("<I",data,40)[0]==4 and not any(data[44:1584]),"Recovery header contract changed")
    require(len(data)==(4096+n+4095)//4096*4096,"Image already signed/padded or truncated")
    ramdisk=data[4096:4096+n]
    require(ramdisk[:4]==bytes.fromhex("02214c18"),"Not legacy LZ4")
    raw=subprocess.run([lz4,"-dc"],input=ramdisk,capture_output=True,check=True).stdout
    replaced,before,after,odm_receipt=replace(raw,cert,build_epoch,unbuilt_odm)
    compressed=subprocess.run([lz4,"-l","-12","-c"],input=replaced,capture_output=True,check=True).stdout
    require(compressed[:4]==bytes.fromhex("02214c18"),"Compressor changed format")
    require(subprocess.run([lz4,"-dc"],input=compressed,capture_output=True,check=True).stdout==replaced,"Compression roundtrip failed")
    headerbytes=bytearray(data[:4096])
    struct.pack_into("<I",headerbytes,12,len(compressed))
    result=bytes(headerbytes)+compressed
    result+=bytes((-len(result))%4096)
    require(result[:12]==data[:12] and result[16:4096]==data[16:4096],"Header changed outside ramdisk size")
    proof={"changed_cpio_entries":(["prop.default",TARGET] if odm_receipt["removed"] else [TARGET]),"odm_correction":odm_receipt,"cpio_records":len(before),"original_trust_sha256":digest(next(r[3] for r in before if r[0]==TARGET)),"owner_trust_sha256":digest(next(r[3] for r in after if r[0]==TARGET)),"all_other_record_bytes_and_order_unchanged":True,"header_changed_fields":["ramdisk_size"]}
    return result,proof
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--unsigned",required=True)
    ap.add_argument("--unsigned-sha256",required=True)
    ap.add_argument("--output",required=True)
    ap.add_argument("--owner-cert",required=True)
    ap.add_argument("--owner-cert-sha256",required=True)
    ap.add_argument("--lz4",required=True)
    ap.add_argument("--lz4-sha256",required=True)
    ap.add_argument("--build-gate",required=True)
    ap.add_argument("--build-gate-sha256",required=True)
    args=ap.parse_args()
    p=Path(args.unsigned);out=Path(args.output)
    require(not p.is_symlink() and sha(p)==args.unsigned_sha256,"Unsigned SHA256 mismatch")
    require(not out.exists(),"Output exists; refuse overwrite")
    pin({"path":args.owner_cert,"sha256":args.owner_cert_sha256})
    pin({"path":args.lz4,"sha256":args.lz4_sha256})
    cert=Path(args.owner_cert).read_bytes()
    owner_der_sha256=digest(ssl.PEM_cert_to_DER_cert(cert.decode()))
    require(owner_der_sha256=="46fc26697072341a414473390b5a313b1385d09d058562985d8d1acbc8a3d06c","Certificate is not the release owner")
    gatepath=Path(args.build_gate)
    require(sha(gatepath)==args.build_gate_sha256,"Build gate SHA256 mismatch")
    gate=json.loads(gatepath.read_text())
    require(gate.get("status")=="UNSIGNED_NOT_INSTALLABLE","Unexpected unsigned admission status")
    for key in ["configuration","source_preflight","source_postflight"]:
        pin(gate[key])
    configuration=json.loads(Path(gate["configuration"]["path"]).read_text())
    require(configuration.get("build_odm_image") is False and configuration.get("build_epoch")==1794793815,"Configuration does not prove unbuilt ODM")
    require(gate.get("build_odm_image") is False and gate.get("build_epoch")==1794793815 and gate.get("unsigned_sha256")==args.unsigned_sha256,"Unbuilt ODM gate not bound to this Recovery")
    result,proof=finalize(p.read_bytes(),cert,args.lz4,gate["build_epoch"],True)
    proof["build_gate_sha256"]=args.build_gate_sha256
    check_image(result,args.lz4)
    out.write_bytes(result)
    require(sha(p)==args.unsigned_sha256,"Unsigned source changed")
    proof.update(status="PUBLIC_OWNER_TRUST_FINALIZATION_PASS",source_unsigned_sha256=args.unsigned_sha256,finalized_unsigned_sha256=digest(result),finalized_unsigned_bytes=len(result),owner_certificate_sha256=digest(cert),owner_certificate_der_sha256=owner_der_sha256,signing_performed=False,phone_actions=False)
    out.with_suffix(out.suffix+".trust.json").write_text(json.dumps(proof,indent=2)+"\n")
    print(json.dumps(proof,indent=2))
if __name__=="__main__":
    main()
