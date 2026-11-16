#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Single source of truth for the early firmware/PR regression gate.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
mkdir -p artifacts logs

python3 scripts/test_runtime_trim.py
python3 scripts/test_lan_probe_isolation.py
python3 scripts/test_gpio_readback.py
python3 scripts/test_lan_async.py
python3 scripts/test_qspi_poll.py
python3 scripts/test_lan_pm_mapping.py
python3 scripts/test_ni_mib_evidence.py
python3 scripts/test_lan_link_mode.py
python3 scripts/test_fe_lan_lifecycle.py --mutants
python3 scripts/test_fe_route_fallback.py
python3 scripts/test_fe_cache_slot_zero.py
python3 scripts/test_fe_hash_collision.py --mutants
python3 scripts/test_fe_source_cam_timeout.py
python3 scripts/test_fe_destination_timeout.py
python3 scripts/test_fe_destination_status.py
python3 scripts/test_fe_fdb_domain.py
python3 scripts/test_fe_fdb_shared_owner.py
python3 scripts/test_fe_fdb_cold_lifecycle.py --mutants
python3 scripts/test_fe_window_idle.py
python3 scripts/test_ni_oam_owner.py
python3 scripts/test_l2_table_transactions.py
python3 scripts/test_l2_resources.py --mutants --sanitize
python3 scripts/test_l2_owner.py --mutants --sanitize
python3 scripts/test_l2_domain.py --mutants --sanitize
python3 scripts/test_l2_hardware_recipe.py
python3 scripts/test_l2_port_policy.py
python3 scripts/test_l2qm_baseline.py
python3 scripts/test_l2_es_cold.py
python3 scripts/test_fabric_baseline.py
python3 scripts/test_fabric_modes.py --mutants
python3 scripts/test_pon_cold_handoff.py
python3 scripts/test_pon_probe_unwind.py --mutants
python3 scripts/test_pon_transactions.py --case address --case epon-policy --mutants
python3 scripts/test_pon_dma_owner.py --mutants
python3 scripts/test_ni_cold_handoff.py --mutants
python3 scripts/test_l2_policy_races.py
python3 scripts/test_l2_parent_id.py
python3 scripts/test_l2_switch_lifecycle.py
python3 scripts/test_l2_switch_control.py
python3 scripts/test_l2_switch_worker.py
python3 scripts/test_l2_switch_fdb.py
python3 scripts/test_l2_fdb_preflight.py
python3 scripts/test_l2_switch_topology.py
python3 scripts/test_l2_vlan_control.py
python3 scripts/test_l2_effective_ageing.py
python3 scripts/test_l2_evidence.py
python3 scripts/test_l2_bridge_eligibility.py
python3 scripts/test_l2_vlan_feedback.py --mutants
python3 scripts/test_l2_static_fdb.py --sanitize --mutants
python3 scripts/test_fe_observe.py
python3 scripts/test_l3_evidence.py
python3 scripts/test_fe_diagnostic_budget.py
python3 scripts/test_fe_callback_lifecycle.py
python3 scripts/test_fe_teardown_quarantine.py
python3 scripts/test_ni_fe_engine_lifecycle.py --mutants
python3 scripts/test_nand_upgrade_write_errors.py
python3 scripts/test_fe_cache_snapshot.py
python3 scripts/test_itu_cpu_path.py
python3 scripts/test_pon_fe_stop.py
python3 scripts/test_pon_table_staging.py
python3 scripts/test_pon_reconfigure_guard.py
python3 scripts/test_gpon_queue_recovery.py
python3 scripts/test_pon_data_path.py
python3 scripts/test_pon_pdc_map.py --mutants
python3 scripts/test_omci_compatibility.py
python3 scripts/test_itu_pppoe_datapath.py
python3 scripts/test_bridge_learning.py
python3 scripts/test_fe_evto.py
python3 scripts/test_fe_evto_dependencies.py
python3 scripts/test_qm_cached_epp.py
python3 scripts/test_qm_rx_bounds.py
python3 scripts/test_qm_switch_rx.py
python3 scripts/test_qm_rx_fairness.py --mutants
python3 scripts/test_mcast_observe.py --mutants
python3 scripts/test_mcast_runtime.py --mutants
python3 scripts/test_mcast_dispatch.py
python3 scripts/test_qm_mcast_copy.py --mutants
python3 scripts/test_mdb_offload.py --mutants
python3 scripts/test_fe_mdb.py --mutants
python3 scripts/test_qm_table_staging.py
python3 scripts/test_qm_refill_credit.py --mutants
python3 scripts/test_qm_startup_faults.py --mutants
python3 scripts/test_qm_resources.py --mutants
python3 scripts/test_dma_tx_fastpath.py
python3 scripts/test_xram_tx_copy.py --mutants
python3 scripts/test_ni_adaptive_timer.py
python3 scripts/test_ni_timer_deadlines.py --mutants
python3 scripts/test_rx_checksum_policy.py
python3 scripts/test_rx_shutdown.py
python3 scripts/test_fe_interface_capacity.py
python3 scripts/test_fe_mtu.py
python3 scripts/test_fe_flow_release.py
python3 scripts/test_fe_flow_stats.py
python3 scripts/test_fe_age_batch.py --mutants
python3 scripts/test_fe_activity_cache.py --mutants
python3 scripts/test_fe_allocation.py --mutants
python3 scripts/test_fe_cleanup_isolation.py
# Encapsulation and PPP namespace oracles require the complete applied Linux
# tree and run in check_flowtable_contracts.sh, after kernel object compilation.
python3 scripts/test_release_uboot_archive.py
python3 scripts/test_datapath_observer.py
python3 scripts/test_datapath_summary.py
python3 scripts/test_tm_summary.py
python3 scripts/test_firmware_build_info.py
