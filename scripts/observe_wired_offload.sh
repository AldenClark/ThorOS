#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Compatibility entry point; the standalone collector is observe_tyfza1_datapath.sh.
# Copy the collector alone, or keep both scripts together. Preserve this entry
# point's ten-second default without maintaining a second divergent collector.
set -eu
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
collector="$script_dir/observe_tyfza1_datapath.sh"
if [ ! -r "$collector" ]; then
    echo 'Missing observe_tyfza1_datapath.sh; copy and run that standalone collector instead.' >&2
    exit 1
fi
case "${1:-}" in
    ''|--*|-h) exec sh "$collector" 10 "$@" ;;
    *) exec sh "$collector" "$@" ;;
esac
