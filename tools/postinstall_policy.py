# SPDX-License-Identifier: Apache-2.0
"""The only reviewed writable-system A/B postinstall entry for LDY-AN00."""
EXPECTED = {
    "RUN_POSTINSTALL_system": "true",
    "POSTINSTALL_PATH_system": "system/bin/otapreopt_script",
    "FILESYSTEM_TYPE_system": "ext4",
    "POSTINSTALL_OPTIONAL_system": "true",
}


def validate_config(rows):
    if rows and rows != EXPECTED:
        raise ValueError("postinstall hooks differ from the reviewed system configuration")


def validate_partition(partition):
    if not partition.run_postinstall and not partition.postinstall_path:
        return
    if (partition.partition_name != "system" or not partition.run_postinstall
            or partition.postinstall_path != EXPECTED["POSTINSTALL_PATH_system"]
            or partition.filesystem_type != "ext4" or not partition.postinstall_optional):
        raise ValueError("postinstall hooks differ from the reviewed system configuration")
