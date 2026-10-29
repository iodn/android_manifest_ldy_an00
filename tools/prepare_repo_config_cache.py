#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare the pinned repo cache adapter for read-only Android builds."""
import argparse
import hashlib
from pathlib import Path

SOURCE_SHA256 = "88be33b16cd211a9a37a98a115c1ab54d041031f90e2a324d1cd8ce94d4f34e8"
ADAPTER_SHA256 = "b2405d5f9f4a69c8ef538ce658560a97ecacae885d3e9ef60ba7989b424ec562"
CACHE_REDIRECT = """        # Host recipe overlay: keep config reads read-only; cache under private OUT.
        out_dir = os.environ.get("OUT_DIR")
        if out_dir:
            self._json = os.path.join(
                out_dir, ".repo-json-cache2",
                hashlib.sha256(os.path.abspath(self.file).encode()).hexdigest() + ".json",
            )

"""


def build_adapter(raw):
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        raise ValueError("Unsupported repo git_config.py; review before updating the adapter")
    text = raw.decode("utf-8")
    text = text.replace("import http.client\n", "import http.client\nimport hashlib\n", 1)
    text = text.replace("    def ClearCache(self):", CACHE_REDIRECT + "    def ClearCache(self):", 1)
    adapted = text.encode("utf-8")
    if hashlib.sha256(adapted).hexdigest() != ADAPTER_SHA256:
        raise ValueError("Generated repo cache adapter does not match its reviewed hash")
    return adapted


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (args.source.resolve() == args.output.resolve()
            or (args.output.exists() and args.source.samefile(args.output))):
        parser.error("Output must not replace the original repo source")
    adapted = build_adapter(args.source.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(adapted)
    print("REPO_CONFIG_CACHE_ADAPTER_OK", ADAPTER_SHA256)


if __name__ == "__main__":
    main()
