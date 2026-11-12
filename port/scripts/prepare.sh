#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
TREE=${1:?Usage: prepare.sh /path/to/new-or-matching/openwrt-checkout}
PORT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PIN=$(python3 "$PORT/tools/project_paths.py" --field openwrt-commit)
PROXY=${TYFZA1_PROXY:-${http_proxy:-}}
if [ ! -e "$TREE/.git" ]; then
    git init "$TREE"
    git -C "$TREE" remote add origin https://github.com/openwrt/openwrt.git
    git -C "$TREE" -c http.proxy="$PROXY" fetch --depth=1 origin "$PIN"
    git -C "$TREE" checkout -b codex/tyfza1-native FETCH_HEAD
fi
test "$(git -C "$TREE" rev-parse HEAD)" = "$PIN" || {
    echo "Existing checkout differs from sources.lock.json; refusing to reset it." >&2
    exit 1
}
git -C "$TREE" show -s --format='%H %cI %s'
