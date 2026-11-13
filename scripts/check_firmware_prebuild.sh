#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Single source of truth for the early firmware/PR regression gate.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
mkdir -p artifacts logs

python3 scripts/test_runtime_trim.py
python3 scripts/test_lan_probe_isolation.py
python3 scripts/test_lan_async.py
python3 scripts/test_qspi_poll.py
python3 scripts/test_lan_pm_mapping.py
python3 scripts/test_lan_link_mode.py
python3 scripts/test_fe_lan_lifecycle.py
python3 scripts/test_fe_cache_slot_zero.py
python3 scripts/test_fe_cache_snapshot.py
python3 scripts/test_itu_cpu_path.py
python3 scripts/test_pon_fe_stop.py
python3 scripts/test_itu_pppoe_datapath.py
python3 scripts/test_bridge_learning.py
python3 scripts/test_qm_cached_epp.py
python3 scripts/test_dma_tx_fastpath.py
python3 scripts/test_ni_adaptive_timer.py
python3 scripts/test_rx_checksum_policy.py
python3 scripts/test_fe_flow_release.py
python3 scripts/test_release_uboot_archive.py
