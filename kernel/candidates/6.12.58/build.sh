#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Run from a pinned Kleaf workspace with common at the recorded upstream commit.
set -eu
recipe=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
base=a0924fec0959b69501d49bdbfefe8a13f53033c4
head=fd92206bcd0a2bd86ecf8343a8e7e81e86a1c483
if [ "$(git -C common rev-parse HEAD)" = "$base" ]; then
    python3 "$recipe/../../replay.py" common "$recipe/series.json"
fi
if [ "${LDY_AN00_RESET_GUARD:-0}" = 1 ]; then
    if [ "$(git -C common rev-parse HEAD)" = "$head" ]; then
        python3 "$recipe/../../replay.py" common "$recipe/optional-reset-guard.json"
    fi
    head=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["head"])' "$recipe/optional-reset-guard.json")
fi
test "$(git -C common rev-parse HEAD)" = "$head"
test -z "$(git -C common status --porcelain)"
export SOURCE_DATE_EPOCH=1794719700
exec common/scripts/build-ldy-an00.sh
