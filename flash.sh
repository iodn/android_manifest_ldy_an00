#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")"
if [[ ! -f installer.json ]]; then
    echo 'Use flash.sh from the complete signed first-install package.' >&2
    exit 2
fi
command -v python3 >/dev/null
command -v openssl >/dev/null
exec python3 -B tools/first_install.py --reboot "$@"
