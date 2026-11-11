#!/usr/bin/env python3
"""Read payload metadata only. This checks cohort retention, not signatures or installability."""
import hashlib
import json
import struct
import sys
import zipfile
from pathlib import Path
from google.protobuf.message import DecodeError
import update_metadata_pb2 as metadata
from postinstall_policy import validate_partition as validate_postinstall_partition

MAX_MANIFEST = 16 * 1024 * 1024
MAX_METADATA_SIGNATURE = 1024 * 1024
EXPECTED_PARTITIONS = {"system", "vbmeta_system"}
GROUP_NAME = "qti_dynamic_partitions"
GROUP_BYTES = 17569939456

class AdmissionError(ValueError):
    pass

def read_exact(stream, count):
    data = stream.read(count)
    if len(data) != count:
        raise AdmissionError("truncated payload metadata")
    return data

def validate_stream(stream, payload_size, *, kernel_images=None):
    header = read_exact(stream, 24)
    magic, major, manifest_size, signature_size = struct.unpack(">4sQQI", header)
    if magic != b"CrAU" or major != 2:
        raise AdmissionError("unsupported payload magic/version")
    if not 0 < manifest_size <= MAX_MANIFEST:
        raise AdmissionError("manifest size out of bounds")
    if signature_size > MAX_METADATA_SIGNATURE:
        raise AdmissionError("metadata signature size out of bounds")
    if 24 + manifest_size + signature_size > payload_size:
        raise AdmissionError("metadata exceeds payload size")
    raw = read_exact(stream, manifest_size)
    manifest = metadata.DeltaArchiveManifest()
    try:
        manifest.ParseFromString(raw)
    except DecodeError as error:
        raise AdmissionError("malformed manifest protobuf") from error
    if not manifest.IsInitialized():
        raise AdmissionError("uninitialized manifest protobuf")
    names = [item.partition_name for item in manifest.partitions]
    expected = EXPECTED_PARTITIONS
    dynamic = ["system"]
    if kernel_images is not None:
        if set(kernel_images) != {"boot", "system_dlkm", "vbmeta_system_dlkm"}:
            raise AdmissionError("exactly three trusted kernel images required")
        expected = expected | set(kernel_images)
        dynamic = ["system", "system_dlkm"]
    if len(names) != len(expected) or set(names) != expected:
        raise AdmissionError("payload must update exactly " + ", ".join(sorted(expected)))
    if kernel_images is not None:
        for partition in manifest.partitions:
            if partition.partition_name not in kernel_images:
                continue
            image = kernel_images[partition.partition_name]
            info = partition.new_partition_info
            if (not partition.HasField("new_partition_info")
                    or not info.HasField("size") or not info.HasField("hash")
                    or info.size != image["bytes"]
                    or info.hash.hex() != image["sha256"]):
                raise AdmissionError("payload kernel image hash/size differs from trusted cohort")
    if kernel_images is not None:
        system = next(p for p in manifest.partitions if p.partition_name == "system")
        if (not system.run_postinstall or not system.postinstall_path
                or not system.postinstall_optional):
            raise AdmissionError("owned-kernel OTA must retain reviewed system postinstall")
    for partition in manifest.partitions:
        try:
            validate_postinstall_partition(partition)
        except ValueError as error:
            raise AdmissionError(str(error)) from error
    if not manifest.HasField("partial_update") or not manifest.partial_update:
        raise AdmissionError("partial_update must explicitly be true")
    if not manifest.HasField("dynamic_partition_metadata"):
        raise AdmissionError("missing dynamic partition metadata")
    groups = manifest.dynamic_partition_metadata.groups
    if len(groups) != 1:
        raise AdmissionError("exactly one owned dynamic group required")
    group = groups[0]
    if (group.name != GROUP_NAME or group.size != GROUP_BYTES
            or list(group.partition_names) != dynamic):
        raise AdmissionError("dynamic group geometry/membership differs")
    return {
        "status": "OTA_VENDOR_COHORT_RETENTION_METADATA_OK",
        "payload_bytes": payload_size,
        "bytes_read": 24 + manifest_size,
        "manifest_bytes": manifest_size,
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "metadata_signature_bytes": signature_size,
        "partitions": names,
        "partial_update": True,
        "dynamic_group": {"name": group.name, "bytes": group.size,
                          "partitions": list(group.partition_names)},
        "scope": "Metadata admission only. Does not authenticate ZIP/payload signatures, "
                 "verify operation contents, validate source cohort, or prove installation safe."
    }

def validate_zip(path, *, kernel_images=None):
    with zipfile.ZipFile(path) as archive:
        entries = [entry for entry in archive.infolist() if entry.filename == "payload.bin"]
        if len(entries) != 1:
            raise AdmissionError("exactly one payload.bin entry required")
        entry = entries[0]
        if entry.flag_bits & 1 or entry.is_dir():
            raise AdmissionError("encrypted/directory payload refused")
        with archive.open(entry) as stream:
            return validate_stream(stream, entry.file_size, kernel_images=kernel_images)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate_ota_vendor_retention.py OTA_ZIP")
    try:
        print(json.dumps(validate_zip(Path(sys.argv[1])), indent=2))
    except (AdmissionError, OSError, zipfile.BadZipFile, NotImplementedError) as error:
        raise SystemExit("OTA_VENDOR_COHORT_RETENTION_REFUSED: " + str(error))
