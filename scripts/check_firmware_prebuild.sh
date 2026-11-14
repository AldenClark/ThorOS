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
python3 scripts/test_fe_hash_collision.py
python3 scripts/test_fe_source_cam_timeout.py
python3 scripts/test_fe_destination_timeout.py
python3 scripts/test_fe_destination_status.py
python3 scripts/test_fe_fdb_domain.py
python3 scripts/test_fe_window_idle.py
python3 scripts/test_l2_table_transactions.py
python3 scripts/test_l2_hardware_recipe.py
python3 scripts/test_l2_policy_races.py
python3 scripts/test_l2_parent_id.py
python3 scripts/test_l2_switch_lifecycle.py
python3 scripts/test_l2_switch_control.py
python3 scripts/test_l2_switch_worker.py
python3 scripts/test_l2_switch_fdb.py
python3 scripts/test_l2_switch_topology.py
python3 scripts/test_l2_bridge_eligibility.py
python3 scripts/test_fe_observe.py
python3 scripts/test_fe_callback_lifecycle.py
python3 scripts/test_fe_teardown_quarantine.py
python3 scripts/test_ni_fe_engine_lifecycle.py
python3 scripts/test_nand_upgrade_write_errors.py
python3 scripts/test_fe_cache_snapshot.py
python3 scripts/test_itu_cpu_path.py
python3 scripts/test_pon_fe_stop.py
python3 scripts/test_pon_table_staging.py
python3 scripts/test_pon_reconfigure_guard.py
python3 scripts/test_pon_data_path.py
python3 scripts/test_omci_compatibility.py
python3 scripts/test_itu_pppoe_datapath.py
python3 scripts/test_bridge_learning.py
python3 scripts/test_fe_evto.py
python3 scripts/test_qm_cached_epp.py
python3 scripts/test_qm_rx_bounds.py
python3 scripts/test_qm_switch_rx.py
python3 scripts/test_qm_table_staging.py
python3 scripts/test_qm_refill_credit.py
python3 scripts/test_dma_tx_fastpath.py
python3 scripts/test_ni_adaptive_timer.py
python3 scripts/test_rx_checksum_policy.py
python3 scripts/test_rx_shutdown.py
python3 scripts/test_fe_interface_capacity.py
python3 scripts/test_fe_flow_release.py
python3 scripts/test_release_uboot_archive.py
python3 scripts/test_datapath_observer.py
python3 scripts/test_firmware_build_info.py
