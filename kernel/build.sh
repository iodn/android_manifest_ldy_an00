#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Run in the pinned Kleaf workspace after repo sync; pass this directory as argument.
set -eu
recipe=$(CDPATH= cd -- "${1:?Usage: build.sh /path/to/kernel-recipe}" && pwd)
base=df70442655d4c7b1802ba29a52d1698a4d6cbf6d
head=d8eddc5fb80b3061efc6541dda5ca97315374f0a
current=$(git -C common rev-parse HEAD)
if [ "$current" = "$base" ]; then
    test -z "$(git -C common status --porcelain)"
    git -C common -c user.name=iodn -c user.email=iodn@users.noreply.github.com \
        -c commit.gpgSign=false am --committer-date-is-author-date "$recipe"/patches/000[1-5]-*.patch
fi
if [ "$(git -C common rev-parse HEAD)" = "275da71428d7cc471f576284038a050191339c65" ]; then
    test -z "$(git -C common status --porcelain)"
    git -C common -c user.name="LineageOS build automation" \
        -c user.email=lineage-build@localhost -c commit.gpgSign=false \
        am --committer-date-is-author-date "$recipe"/patches/0006-*.patch
fi
if [ "$(git -C common rev-parse HEAD)" = "2a4c948dcfd1f78c8e1d8222787501eb3b1da5c5" ]; then
    test -z "$(git -C common status --porcelain)"
    git -C common -c user.name=iodn -c user.email=114117719+iodn@users.noreply.github.com \
        -c commit.gpgSign=false am --committer-date-is-author-date "$recipe"/patches/0007-*.patch
fi
if [ "$(git -C common rev-parse HEAD)" = "70f67f1acd5b4871106fb7e9e945fd8bd764816a" ]; then
    python3 "$recipe/replay.py" common "$recipe/patches/security-20261114.json"
fi
# Apply the standard kernel hardening default independently of the reset guard.
if [ "$(git -C common rev-parse HEAD)" = "$head" ]; then
    python3 "$recipe/replay.py" common "$recipe/patches/security-defaults-20261115.json"
fi
head=d8bf79b03e8bcbd109856645137c3d9f73866d90
# The reset guard stays opt-in until its device trial and full kernel qualification pass.
if [ "${LDY_AN00_RESET_GUARD:-0}" = 1 ]; then
    if [ "$(git -C common rev-parse HEAD)" = "$head" ]; then
        python3 "$recipe/replay.py" common "$recipe/patches/locked-reset-20261115.json"
    fi
    head=acdabf942f39cb4e7aaf37fa4fe7659350b924b4
    export SOURCE_DATE_EPOCH=1794703819
else
    export SOURCE_DATE_EPOCH=1794703819
fi
test "$(git -C common rev-parse HEAD)" = "$head"
test -z "$(git -C common status --porcelain)"
exec common/scripts/build-ldy-an00.sh
