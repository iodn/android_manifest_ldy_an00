#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Run in the pinned Kleaf workspace after repo sync; pass this directory as argument.
set -eu
recipe=$(CDPATH= cd -- "${1:?Usage: build.sh /path/to/kernel-recipe}" && pwd)
base=df70442655d4c7b1802ba29a52d1698a4d6cbf6d
head=275da71428d7cc471f576284038a050191339c65
current=$(git -C common rev-parse HEAD)
if [ "$current" = "$base" ]; then
    test -z "$(git -C common status --porcelain)"
    git -C common -c user.name=iodn -c user.email=iodn@users.noreply.github.com \
        -c commit.gpgSign=false am --committer-date-is-author-date "$recipe"/patches/*.patch
fi
test "$(git -C common rev-parse HEAD)" = "$head"
test -z "$(git -C common status --porcelain)"
export SOURCE_DATE_EPOCH=1793405844
exec common/scripts/build-ldy-an00.sh
