#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Run from a pinned Kleaf workspace with common at the recorded upstream commit.
set -eu
if [ "${1:-}" = --help ]; then
    cat <<'EOF'
Create the pinned 6.12.58 Kleaf workspace:
  repo init -u https://github.com/iodn/android_manifest_ldy_an00 -b main -m kernel/candidates/6.12.58/manifest.xml
  repo sync -c
  .repo/manifests/kernel/candidates/6.12.58/build.sh

Run this script from the workspace root. It builds the kernel and modules;
coordinated image packaging and final OTA qualification are separate steps.
Reset protection is included by default and tested on LDY-AN00 with the matching
MagicOS 11.0.0.117 stack. Legacy migration and fresh installation are separate.
Use LDY_AN00_RESET_GUARD=0 to reproduce the unprotected baseline kernel.
Set LDY_AN00_RESET_GUARD=1 in the matching Android product build too.
EOF
    exit 0
fi
recipe=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
reset_guard=${LDY_AN00_RESET_GUARD:-1}
case "$reset_guard" in
    0|1) ;;
    *) echo "LDY_AN00_RESET_GUARD must be 0 or 1" >&2; exit 2 ;;
esac
base=a0924fec0959b69501d49bdbfefe8a13f53033c4
head=fd92206bcd0a2bd86ecf8343a8e7e81e86a1c483
if [ "$(git -C common rev-parse HEAD)" = "$base" ]; then
    python3 "$recipe/../../replay.py" common "$recipe/series.json"
fi
if [ "$reset_guard" = 1 ]; then
    if [ "$(git -C common rev-parse HEAD)" = "$head" ]; then
        python3 "$recipe/../../replay.py" common "$recipe/optional-reset-guard.json"
    fi
    head=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["head"])' "$recipe/optional-reset-guard.json")
fi
test "$(git -C common rev-parse HEAD)" = "$head"
test -z "$(git -C common status --porcelain)"
export SOURCE_DATE_EPOCH=1794719700
exec common/scripts/build-ldy-an00.sh
