#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Host execution of production functions from the fully prepared kernel tree.
set -euo pipefail
project=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
if (( $# != 1 )); then
    printf 'Usage: bash scripts/check_flowtable_contracts.sh /path/to/prepared/linux\n' >&2
    exit 2
fi
kernel=$(CDPATH='' cd -- "$1" && pwd -P)
cd "$project"
# This gate runs in an independent clean CI job, not after prebuild. Several
# production-function oracles write evidence into these project directories.
mkdir -p artifacts logs
for test in fe_flow_parser fe_cookie_index fe_pppoe_cleanup \
            flowtable_bridge_move flowtable_bridge_ageing flowtable_software_ageing \
            flowtable_work_lifetime flowtable_bridge_policy flowtable_partial_offload \
            flowtable_direct_route l2_policy_noop ppp_channel_generation \
            ppp_flow_policy flowtable_mtu_lifetime flowtable_timeout_order \
            flowtable_initial_publication; do
    python3 "scripts/test_$test.py" --kernel "$kernel"
done
