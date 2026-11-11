# SPDX-License-Identifier: Apache-2.0
"""KernelSU v3.3.1 boot-kernel KMI recognition, without installing root."""
import re


def parse_kmi(kernel):
    """Match the official byte scan, 100-byte window and NUL-terminated UTF-8."""
    pattern = re.compile(r"(\d+\.\d+)(?:\S+)?(android\d+)")
    for index in range(max(0, len(kernel) - 3)):
        word = kernel[index:index + 4]
        if (word[1] != ord(".") or not ord("0") <= word[2] <= ord("9")
                or not (word[0] == ord("5") and ord("0") <= word[3] <= ord("9")
                        or ord("6") <= word[0] <= ord("9"))):
            continue
        candidate = kernel[index:index + 100]
        end = candidate.find(b"\0")
        if end < 0:
            continue
        try:
            value = candidate[:end].decode("utf-8")
        except UnicodeDecodeError:
            continue
        match = pattern.search(value)
        if match:
            return match[2] + "-" + match[1]
    raise ValueError("Kernel does not advertise a recognizable GKI interface")
