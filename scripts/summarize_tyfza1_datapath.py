#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Summarize two passive snapshots without inventing ASIC hit/throughput proof.

No network access, subprocesses, driver access, or writes. Reads at most 2 MiB.
Rates are a range bounded by the non-atomic snapshot sampling windows. Counter
decrease, boot change and topology/lifecycle differences invalidate comparison;
absence of such evidence cannot prove there was no intervening reset or ABA.
"""
import argparse
import json
import re
from decimal import Decimal, InvalidOperation
from pathlib import Path


MAX_BYTES = 2 * 1024 * 1024
MAX_COUNTER = (1 << 64) - 1
BOOT_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
# An empty value still occupies its key: a truncated duplicate must not make
# a preceding, apparently valid field win silently.
TOKEN = re.compile(r"(?<!\S)([a-zA-Z_][a-zA-Z0-9_]*)=([^\s]*)")
LIFECYCLE = ("base_ready", "dma_exposed", "engine_poisoned", "host_active", "reboot_required")
MIB_COUNTERS = ("rx_bytes", "tx_bytes", "rx_uc", "rx_mc", "rx_bc", "tx_uc", "tx_mc", "tx_bc")
MAX_MIB_AGE_NS = 3_000_000_000
QM_EQ_GAUGES = ("pending", "peak")
QM_EQ_COUNTERS = ("retries", "returned", "full_stalls")
QM_EQ_FAULT_COUNTERS = ("bad_credit", "bad_ready")
MC_RX_COUNTERS = ("mc_rx_hdr_bum", "mc_rx_source27", "mc_rx_source27_cpu",
                  "mc_rx_source27_ptp", "mc_rx_source27_pol", "mc_rx_source27_mirror")
TM_CONFIGS = ('tm_clear_control', 'bm_control', 'buffer_config', 'eq_config', 'private_config',
              'es_control', 'es_lan0', 'es_lan1', 'es_lan2', 'es_lan3', 'es_lan4',
              'es_l3wan10', 'es_oam12', 'es_l3lan13', 'te_control', 'fc_control',
              'te_pm_control', 'ni_internal', 'ni_demux0', 'ni_demux1', 'ni_demux2',
              'ni_demux3', 'ni_deep0', 'ni_deep1', 'ni_deep2', 'ni_deep3', 'lpb_map')
TM_STATUSES = ('tm_init', 'te_pm_init', 'fc_status', 'es_ready', 'es_pending0', 'es_pending1',
               'es_pending2', 'es_pending3', 'es_ok0', 'es_ok1', 'es_ok2', 'es_ok3',
               'es_port_ok', 'es_arb', 'buffer_free')
# Additive schema-1 extension: older captures remain usable with their smaller
# observation set. A partial extension is corruption, not an old firmware.
TM_BUFFER_CONFIGS = ('eq_weight', 'fe_backpressure', 'private_profile1',
                     'private_profile2', 'private_profile3', 'private_select0', 'private_select1')
TM_BUFFER_STATUSES = ('private_empty_ports', 'eq_free', *(f'cos{i}_bufcnt' for i in range(8)))
TM_BM_COUNTERS = ('bm_rx', 'bm_tx', 'bm_sb_drop', 'bm_hdr_drop', 'bm_te_drop',
                  'bm_err_drop', 'bm_nobuf_drop')
TM_TE_COUNTERS = ('te_pol_drop', 'te_tail_drop', 'te_wred_y_drop', 'te_wred_g_drop')
FAILURE_MARKER = re.compile(r"(?:probe_(?:failed|skipped|unavailable)|read_failed|read_empty|read_truncated|truncated|skipped)=")
L2_HW_REASONS = ('ok', 'requires-existing-svl', 'priority-fdb-key', 'tpid-profile',
                 'cpu-egress-edit', 'queue-baseline', 'lan-source-map', 'foreign-source-alias',
                 'aging-timebase', 'foreign-classifier', 'foreign-learning', 'special-profile-capacity',
                 'mac-limit-io', 'table-io', 'shared-command-busy', 'pipeline-drain-timeout',
                 'native-mtu-baseline', 'control-packet-classification',
                 'port-policy-transaction', 'isolation-baseline', 'redirect-baseline',
                 'admission-readback', 'ivl-parser-consumer-unverified')
COLD_STAGES = ('none', 'global_snapshot', 'select_family', 'write_receive_gates',
               'receive_gate_readback', 'PDC_FIFO_drain', 'final_verify', 'ready',
               'clock_precondition')
COLD_GATES = ((0x088c, 1, 'EPON_1G'), (0x10b4, 1 << 7, 'EPON_10G'),
              (0x6114, 1 << 1, 'GPON'), (0x4004, 3, 'XGPON'))
INSTALL_STAGES = ('none', 'port', 'format', 'unicast', 'engine', 'policy', 'link', 'cookie',
                  'fdb_mode', 'hash_collision', 'hash_capacity', 'allocate', 'source_mac', 'destination_mac',
                  'interface', 'mtu', 'counter', 'publish')
LEGACY_INSTALL_STAGES = tuple(stage for stage in INSTALL_STAGES if stage != 'fdb_mode')
FDB_MODE_REASONS = ('ready', 'fabric_unready', 'owner_unready', 'owner_fault',
                    'window_busy', 'info_init', 'cmd_disabled', 'read_error')
FDB_MODE_COUNTERS = tuple(f'fdb_mode_{reason}' for reason in FDB_MODE_REASONS)
ADMISSION_CATEGORIES = ('install_unavailable', 'install_duplicate', 'install_collision',
                        'install_unsupported', 'install_no_space', 'install_no_memory',
                        'install_io', 'install_other')
ADMISSION_REJECTIONS = ('reject_unspecified', 'reject_keys', 'reject_meta', 'reject_control',
                        'reject_protocol', 'reject_vlan', 'reject_action', 'reject_nat',
                        'reject_port', 'reject_pon', 'reject_other_ingress')
ADMISSION_COUNTERS = ('requests', 'parse_rejected', 'install_succeeded', 'install_failed',
                      *ADMISSION_REJECTIONS, *ADMISSION_CATEGORIES,
                      *(f'stage_{stage}_failed' for stage in INSTALL_STAGES))
FLOW_NUMBERS = ('lease', 'hash', 'input_hw', 'output_hw', 'ipv6', 'protocol', 'installed',
                'published', 'deleting', 'counted', 'counter', 'samples', 'sample_age_ms',
                'age_hits', 'l3_bytes', 'packets')
FLOW_BOOLEANS = ('ipv6', 'installed', 'published', 'deleting', 'counted')
L2_COMPLETED_NUMBERS = ('l2_completed_valid', 'l2_completed_serial', 'l2_completed_generation',
                        'l2_current_generation', 'l2_completed_reason', 'l2_completed_hw_reason',
                        'l2_completed_armed', 'l2_cpu_fdb_count', 'l2_preflight_done',
                        'l2_worker_busy', 'l2_worker_skips', 'l2_pending_reason')
L2_COMPLETED_MASKS = ('l2_completed_ports', 'l2_completed_route_ports',
                      'l2_completed_route_eligible_ports')
L2_COMPLETED_ERRORS = ('l2_completed_error', 'l2_preflight_error', 'l2_pending_error')
L2_HW_RAW = ('l2_hw_vlan_mode', 'l2_hw_hash_control', 'l2_hw_aging', 'l2_hw_packet_length',
             'l2_hw_tpid0', 'l2_hw_tpid1', 'l2_hw_tpid2', 'l2_hw_tpid3', 'l2_hw_oversize_allow',
             'l2_hw_source_port', 'l2_hw_source_logical', 'l2_hw_learning_port', 'l2_hw_learning_profile')


def fields(lines):
    result = {}
    for line in lines:
        for key, value in TOKEN.findall(line):
            if key in result:
                # Repeated state/probe keys are ambiguous, never last-wins.
                result[key] = None
            else:
                result[key] = value
    return result


def sections(text):
    snapshots = {"before": {}, "after": {}}
    current = None
    section = None
    for line in text.splitlines():
        if line in ("[snapshot_before]", "[snapshot_after]"):
            current = line[10:-1]
            if snapshots[current]:
                raise ValueError("duplicate snapshot")
            section = "header"
            snapshots[current][section] = []
        elif line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            if current is not None:
                if section in snapshots[current]:
                    raise ValueError("duplicate section")
                snapshots[current][section] = []
        elif current is not None and section is not None:
            snapshots[current][section].append(line)
    return snapshots


def number(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,20}", value):
        return None
    result = int(value)
    return result if result <= MAX_COUNTER else None


def register(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:0x[0-9a-fA-F]{1,8}|[0-9]{1,10})", value):
        return None
    result = int(value, 16 if value.startswith("0x") else 10)
    return result if result <= 0xFFFFFFFF else None


def signed32(value):
    if not isinstance(value, str) or not re.fullmatch(r'-?[0-9]{1,10}', value):
        return None
    result = int(value)
    return result if -(1 << 31) <= result < (1 << 31) else None


def uptime(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,12}(?:\.[0-9]{1,6})?", value):
        return None
    try:
        return Decimal(value)
    except InvalidOperation:
        return None


def faulty(lines):
    # A killed printf producer may leave no newline before the shell appends
    # its failure marker. Detect these specific markers even glued to a value;
    # normal fields such as master_ifindex=unavailable are not probe failures.
    return any(FAILURE_MARKER.search(line) or line.lstrip().startswith("unavailable") for line in lines)


def clocks(snapshots):
    if any(faulty(snapshots[which].get(part, []))
           for which in ("before", "after") for part in ("sample_begin", "sample_end")):
        return {"valid": False, "reason": "sample_clock_probe_incomplete"}
    rows = [fields(snapshots[which].get(part, []))
            for which in ("before", "after") for part in ("sample_begin", "sample_end")]
    times = [uptime(row.get("uptime")) for row in rows]
    ids = [row.get("boot_id") for row in rows]
    if any(not isinstance(identity, str) or not BOOT_ID.fullmatch(identity) for identity in ids):
        return {"valid": False, "reason": "boot_identity_missing_or_invalid"}
    if len(set(ids)) != 1:
        return {"valid": False, "reason": "boot_changed"}
    if any(time is None for time in times):
        return {"valid": False, "reason": "monotonic_clock_missing_or_invalid"}
    b0, b1, a0, a1 = times
    if not b0 <= b1 < a0 <= a1:
        return {"valid": False, "reason": "overlapping_or_non_monotonic_samples"}
    # Linux /proc/uptime truncates to centiseconds. Expand the bounds rather
    # than claiming a precision which the collector never observed.
    quantum = Decimal("0.01")
    if a0 - b1 <= quantum:
        return {"valid": False, "reason": "clock_resolution_insufficient_for_rate_bounds"}
    return {"valid": True, "min_seconds": float(a0 - b1 - quantum), "max_seconds": float(a1 - b0 + quantum),
            "uptime_quantization_seconds": float(quantum),
            "before_capture_seconds": float(b1 - b0), "after_capture_seconds": float(a1 - a0)}


def delta(before, after, window):
    a, b = number(before), number(after)
    if a is None or b is None:
        return {"valid": False, "reason": "counter_missing_or_invalid"}
    if b < a:
        return {"valid": False, "reason": "counter_decreased_reset_or_wrap_not_guessed"}
    difference = b - a
    # Python integers retain exact 64-bit deltas; floating point is used only
    # for descriptive rates, not subtraction of large cumulative counters.
    return {"valid": True, "delta": difference,
            "per_second_min": difference / window["max_seconds"],
            "per_second_max": difference / window["min_seconds"]}


def qm_buffer_pressure(before, after, window):
    """New passive EQ4/5 return pressure; no register writes or ASIC claims.

    Old firmware omits this extension entirely. Partially captured extensions
    are invalid. Pending and high-water are gauges, not drop counters/rates.
    """
    keys = [f"refill_eq{eq}_{name}" for eq in (4, 5)
            for name in QM_EQ_GAUGES + QM_EQ_COUNTERS]
    extensions = [f"refill_eq{eq}_{name}" for eq in (4, 5) for name in QM_EQ_FAULT_COUNTERS]
    extensions += [f"voq{voq}_yields" for voq in range(8)] + ["next_voq"]
    # An orphaned new-format field is evidence of a partial capture, not
    # evidence that an old firmware omitted the entire optional interface.
    if not any(key in before or key in after for key in keys + extensions):
        return {"valid": False, "reason": "per_EQ_refill_evidence_unavailable"}
    if any(number(before.get(key)) is None or number(after.get(key)) is None for key in keys):
        return {"valid": False, "reason": "per_EQ_refill_evidence_incomplete"}
    result = {"valid": True, "eq": {}}
    for eq in (4, 5):
        prefix = f"refill_eq{eq}_"
        gauges = {name: {"before": int(before[prefix + name]),
                         "after": int(after[prefix + name])} for name in QM_EQ_GAUGES}
        if any(gauges[name][which] > 512 for name in QM_EQ_GAUGES
               for which in ("before", "after")):
            return {"valid": False, "reason": "refill_pool_capacity_exceeded"}
        counters = {name: delta(before[prefix + name], after[prefix + name], window)
                    for name in QM_EQ_COUNTERS}
        if not all(value["valid"] for value in counters.values()):
            return {"valid": False, "reason": "per_EQ_refill_counter_reset_or_invalid"}
        result["eq"][f"eq{eq}"] = {"gauges": gauges, "counters": counters}
    # Each additive extension is checked separately. An R8 capture still has
    # valid refill evidence even though it predates MMIO/fair-service counters.
    result["refill_faults"] = qm_refill_faults(before, after, window)
    result["voq_service"] = qm_voq_service(before, after, window)
    return result


def qm_refill_faults(before, after, window):
    keys = [f"refill_eq{eq}_{name}" for eq in (4, 5) for name in QM_EQ_FAULT_COUNTERS]
    if not any(key in before or key in after for key in keys):
        return {"valid": False, "reason": "refill_mmio_evidence_unavailable"}
    if any(number(before.get(key)) is None or number(after.get(key)) is None for key in keys):
        return {"valid": False, "reason": "refill_mmio_evidence_incomplete"}
    result = {"valid": True, "eq": {}}
    for eq in (4, 5):
        counters = {name: delta(before[f"refill_eq{eq}_{name}"],
                                after[f"refill_eq{eq}_{name}"], window)
                    for name in QM_EQ_FAULT_COUNTERS}
        if not all(value["valid"] for value in counters.values()):
            return {"valid": False, "reason": "refill_mmio_counter_reset_or_invalid"}
        result["eq"][f"eq{eq}"] = counters
    return result


def qm_voq_service(before, after, window):
    keys = [f"voq{voq}_yields" for voq in range(8)]
    if not any(key in before or key in after for key in (*keys, "next_voq")):
        return {"valid": False, "reason": "voq_service_evidence_unavailable"}
    if any(number(before.get(key)) is None or number(after.get(key)) is None
           for key in (*keys, "next_voq")):
        return {"valid": False, "reason": "voq_service_evidence_incomplete"}
    next_voq = {"before": int(before["next_voq"]), "after": int(after["next_voq"])}
    if any(value > 7 for value in next_voq.values()):
        return {"valid": False, "reason": "voq_cursor_out_of_range"}
    counters = {key: delta(before[key], after[key], window) for key in keys}
    if not all(value["valid"] for value in counters.values()):
        return {"valid": False, "reason": "voq_service_counter_reset_or_invalid"}
    return {"valid": True, "next_voq": next_voq, "yields": counters,
            "note": "Service-quantum yields are not drops or proof of hardware forwarding."}


def qm_mcast_observation(before, after, window):
    """Observed HeaderA patterns, never original-source or replicated-set proof."""
    keys = (*MC_RX_COUNTERS, "mc_rx_last_header", "mc_rx_forwarding_proven")
    if not any(key in before or key in after for key in keys):
        return {"valid": False, "reason": "multicast_metadata_evidence_unavailable"}
    if any(number(snapshot.get(key)) is None for snapshot in (before, after)
           for key in MC_RX_COUNTERS):
        return {"valid": False, "reason": "multicast_metadata_evidence_incomplete"}
    if any(snapshot.get("mc_rx_forwarding_proven") != "0" for snapshot in (before, after)):
        return {"valid": False, "reason": "unverified_multicast_forwarding_claim"}
    raw = [snapshot.get("mc_rx_last_header") for snapshot in (before, after)]
    if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{16}", value)
           for value in raw):
        return {"valid": False, "reason": "multicast_metadata_header_incomplete"}
    counters = {key: delta(before[key], after[key], window) for key in MC_RX_COUNTERS}
    if not all(value["valid"] for value in counters.values()):
        return {"valid": False, "reason": "multicast_metadata_counter_reset_or_invalid"}
    return {"valid": True, "observed_counters": counters, "hardware_forwarding_proven": False,
            "last_candidate_header_raw": {"before": raw[0].lower(), "after": raw[1].lower()},
            "note": "HeaderA fields are overloaded; source27, CPU format, token and mirror do not prove "
                    "replication, original ingress, group membership, generation or drain. The last "
                    "header may predate this window; the counters are not an atomic snapshot."}


def netdev(lines):
    devices = {}
    if faulty(lines):
        return devices
    for line in lines:
        if ":" not in line:
            continue
        name, values = line.split(":", 1)
        name = name.strip()
        values = values.split()
        if len(values) != 16 or any(number(value) is None for value in values):
            continue
        if name in devices:
            devices[name] = None
        else:
            devices[name] = {"rx_bytes": values[0], "rx_packets": values[1],
                             "rx_errors": values[2], "rx_dropped": values[3],
                             "tx_bytes": values[8], "tx_packets": values[9],
                             "tx_errors": values[10], "tx_dropped": values[11]}
    return devices


def links(lines):
    result = {}
    if faulty(lines):
        return result
    for line in lines:
        row = fields([line])
        name = row.pop("dev", None)
        if name is not None and len(name) <= 15 and re.fullmatch(r"[A-Za-z0-9_.+-]+", name):
            result[name] = None if name in result else row
    return result


def select_state(snapshot, name, keys):
    lines = snapshot.get(name, [])
    if faulty(lines):
        return {}
    raw = fields(lines)
    result = {}
    for key in keys:
        value = raw.get(key)
        if isinstance(value, str) and re.fullmatch(r"(?:-?[0-9]{1,20}|0x[0-9a-fA-F]{1,16})", value):
            result[key] = value
    return result


def select_fe_state(snapshot, keys):
    lines = snapshot.get('fe', [])
    raw = fields(lines)
    # A trylock refusal is a valid unavailable response, not a zero verdict.
    # R11 collectors may omit availability; keep that legacy format usable.
    available = not faulty(lines) and ('available' not in raw or raw.get('available') == '1')
    result = select_state(snapshot, 'fe', keys) if available else {}
    if 'available' in raw:
        result['fe_state_available'] = available
        if not available:
            result['fe_state_reason'] = ('busy' if raw.get('available') == '0' and
                raw.get('reason') == 'busy' and raw.get('retryable') == '1' else 'unavailable_or_invalid')
    resources = snapshot.get('l2_resources', [])
    if resources and not faulty(resources):
        raw_resources = fields(resources)
        expected = {'schema': '1', 'available': '1', 'cached': '1', 'mmio_reads': '0', 'mmio_writes': '0'}
        if all(raw_resources.get(key) == value for key, value in expected.items()):
            extra = select_state(snapshot, 'l2_resources', keys)
            legacy = raw if available else {}
            for key in keys:
                if key not in raw_resources:
                    continue
                if key in legacy and legacy[key] != raw_resources[key]:
                    result.pop(key, None)
                elif key in extra:
                    result[key] = extra[key]
                else:
                    result.pop(key, None)
    if not available:
        return result
    if 'l2_hw_reason_name' not in raw:
        return result
    reason = number(raw.get('l2_hw_reason'))
    expected = L2_HW_REASONS[reason] if reason is not None and reason < len(L2_HW_REASONS) else None
    # R11 has no sampling-validity field. R12 explicitly distinguishes a
    # zero-initialized enum from a real preflight sample; zero is not HW OK.
    if 'l2_hw_valid' in raw:
        if raw.get('l2_hw_valid') == '0':
            expected = 'not-sampled'
        elif raw.get('l2_hw_valid') != '1':
            expected = None
    # Do not echo arbitrary probe strings, addresses, or mismatched enum labels.
    result['l2_hw_reason_name_valid'] = expected is not None and raw.get('l2_hw_reason_name') == expected
    if result['l2_hw_reason_name_valid']:
        result['l2_hw_reason_name'] = expected
    return result


def l2_completed_sample(snapshot):
    lines = snapshot.get('l2_evidence', [])
    invalid = lambda reason: {'valid': False, 'reason': reason, 'hardware_forwarding_proven': False}
    if not lines or faulty(lines):
        return invalid('L2_completed_record_missing_or_incomplete')
    raw = fields(lines)
    if raw.get('l2_completed_valid') == '0':
        return {'valid': True, 'completed': False, 'hw_reason_name': 'not-sampled',
                'hardware_forwarding_proven': False}
    if raw.get('l2_completed_valid') != '1':
        return invalid('L2_completed_record_missing_or_invalid')
    record = {key: number(raw.get(key)) for key in L2_COMPLETED_NUMBERS}
    record.update({key: register(raw.get(key)) for key in L2_COMPLETED_MASKS})
    record.update({key: signed32(raw.get(key)) for key in L2_COMPLETED_ERRORS})
    if (any(value is None for value in record.values()) or not record['l2_completed_serial'] or
            any(record[key] > 1 for key in ('l2_completed_armed', 'l2_preflight_done', 'l2_worker_busy')) or
            any(record[key] > 31 for key in L2_COMPLETED_MASKS) or
            record['l2_completed_hw_reason'] >= len(L2_HW_REASONS)):
        return invalid('L2_completed_record_missing_or_invalid')
    result = {'valid': True, 'completed': True, 'record': record,
            'current_epoch': record['l2_completed_generation'] == record['l2_current_generation'],
            'hw_reason_name': L2_HW_REASONS[record['l2_completed_hw_reason']]
                              if record['l2_preflight_done'] else 'not-sampled',
            'hardware_forwarding_proven': False,
            'note': 'Last completed transaction, not an atomic live gate or hardware-hit proof.'}
    if any(key in raw for key in L2_HW_RAW):
        observed = {key: register(raw.get(key)) for key in L2_HW_RAW}
        result['raw_configuration'] = ({'valid': False, 'reason': 'L2_raw_configuration_incomplete'}
            if any(value is None for value in observed.values()) else
            {'valid': True, 'sampled': bool(record['l2_preflight_done']), 'registers': observed})
    return result


def mce_sample(snapshot):
    lines = snapshot.get('l2_evidence', [])
    invalid = lambda reason: {'valid': False, 'reason': reason, 'hardware_forwarding_proven': False}
    if not lines or faulty(lines):
        return invalid('MCE_cached_preflight_missing_or_incomplete')
    raw = fields(lines)
    if raw.get('mce_preflight') == 'not-attempted' and raw.get('mce_sample_valid') == '0x0':
        return invalid('MCE_preflight_not_attempted')
    if raw.get('mce_preflight') != 'cached' or raw.get('mce_cold_handoff_verified') != '0':
        return invalid('unsupported_MCE_cached_preflight')
    keys = ('mce_missing_contracts', 'mce_sample_valid', 'mce_cold_reads', 'mce_cold_register',
            'mce_cold_value', 'mce_xram_cfg', 'mce_stg0_ctrl', 'mce_hash_ini', 'mce_cache_ini',
            'mce_cold_control', 'mce_capacity_fallbacks', 'mce_unpublished_aborts')
    record = {key: register(raw.get(key)) for key in keys}
    if any(value is None for value in record.values()) or record['mce_sample_valid'] > 31:
        return invalid('MCE_cached_preflight_partial_or_invalid')
    return {'valid': True, 'cached': True, 'record': record,
            'all_registers_sampled': record['mce_sample_valid'] == 31,
            'hardware_forwarding_proven': False, 'handoff_verified': False,
            'note': 'Raw inherited configuration, not empty-table, ownership or retirement proof.'}


def mce_inherited_sample(snapshot):
    """R13 optional live *direct* CSR probe, independent of MCE cold owner.

    This is not the cold-time snapshot. Never join its words with a previously
    completed L2 transaction or infer producer quiescence from a stable value.
    R11/R12 captures legitimately lack this optional diagnostic section.
    """
    lines = snapshot.get('mce_inherited', [])
    invalid = lambda reason: {'valid': False, 'reason': reason, 'hardware_forwarding_proven': False}
    if lines == ['skipped=requires_details;raw_MCE_internal_configuration']:
        return invalid('MCE_live_direct_probe_requires_explicit_details')
    if not lines or faulty(lines):
        return invalid('MCE_live_direct_probe_missing_or_incomplete')
    raw = fields(lines)
    if raw.get('schema') == '1' and raw.get('available') == '0':
        return invalid('MCE_live_direct_probe_busy' if raw.get('reason') == 'busy'
                       else 'MCE_live_direct_probe_unavailable')
    expected = {'schema': '1', 'available': '1', 'scope': 'runtime_direct',
                'clock': 'monotonic', 'mmio_reads': '5', 'mmio_writes': '0',
                'atomic_snapshot': '0', 'clock_verified': '0',
                'handoff_verified': '0', 'retirement_verified': '0'}
    if any(raw.get(key) != value for key, value in expected.items()):
        return invalid('unsupported_MCE_live_direct_schema')
    numbers = ('begin_ns', 'end_ns', 'instance_ns', 'engine_ready', 'fabric_ready',
               'mce_owner', 'owner_generation_valid', 'owner_generation', 'sample_reads')
    words = ('missing_contracts', 'sample_valid', 'bad_register', 'bad_value',
             'xram_cfg', 'stg0_ctrl', 'hash_ini', 'cache_ini', 'mce_control')
    record = {key: number(raw.get(key)) for key in numbers}
    record.update({key: register(raw.get(key)) for key in words})
    record['sample_error'] = signed32(raw.get('sample_error'))
    if (any(value is None for value in record.values()) or
            not 0 < record['instance_ns'] <= record['begin_ns'] <= record['end_ns'] or
            record['sample_reads'] != 5 or
            record['sample_valid'] > 31 or record['missing_contracts'] != 31 or
            any(record[key] > 1 for key in ('engine_ready', 'fabric_ready', 'mce_owner',
                                           'owner_generation_valid')) or
            record['engine_ready'] != 1 or
            (record['owner_generation_valid'] == 0 and record['owner_generation'] != 0) or
            (record['owner_generation_valid'] == 1 and record['owner_generation'] == 0) or
            record['sample_error'] not in (0, -5) or
            (record['sample_error'] == 0) != (record['sample_valid'] == 31) or
            (record['sample_error'] == 0 and (record['bad_register'] or record['bad_value']))):
        return invalid('MCE_live_direct_probe_partial_or_invalid')
    offsets = (0xaa28, 0x3400, 0x3834, 0x38a0, 0xaa60)
    actual = (record['xram_cfg'], record['stg0_ctrl'], record['hash_ini'],
              record['cache_ini'], record['mce_control'])
    observed_mask = sum(1 << index for index, value in enumerate(actual)
                        if value != 0xffffffff)
    if record['sample_valid'] != observed_mask:
        return invalid('MCE_live_direct_validity_mask_mismatch')
    if record['sample_error'] == -5:
        first_error = next((offset for offset, value in zip(offsets, actual)
                            if value == 0xffffffff), None)
        if record['bad_register'] != first_error or record['bad_value'] != 0xffffffff:
            return invalid('MCE_live_direct_error_location_mismatch')
    return {'valid': True, 'runtime_direct_only': True, 'record': record,
            'all_registers_sampled': record['sample_valid'] == 31,
            'hardware_forwarding_proven': False, 'handoff_verified': False,
            'retirement_verified': False,
            'note': 'Live, sequential direct CSR reads without command transactions or ownership; never cold handoff/retirement proof.'}


def admission_sample(snapshot):
    lines = snapshot.get('l3_admission', [])
    invalid = lambda reason: {'valid': False, 'reason': reason, 'counts_are_packets': False}
    if not lines or faulty(lines):
        return invalid('L3_admission_missing_or_incomplete')
    raw = fields(lines)
    if raw.get('schema') == '1' and raw.get('available') == '0':
        return invalid('L3_admission_busy' if raw.get('reason') == 'busy' else 'L3_admission_unavailable')
    expected = {'schema': '1', 'available': '1', 'cached': '1', 'mmio_reads': '0',
                'mmio_writes': '0', 'counts_are_packets': '0'}
    if any(raw.get(key) != value for key, value in expected.items()):
        return invalid('unsupported_L3_admission_schema')
    # R13 adds an explicit pre-reservation stage and diagnostics. R11/R12
    # captures have neither; a partially populated R13 record is invalid.
    fdb_extension_keys = (*FDB_MODE_COUNTERS, 'fdb_mode_last_reason',
                          'fdb_mode_last_error', 'fdb_mode_last_control_sampled',
                          'fdb_mode_last_control')
    fdb_extended = any(key in raw for key in fdb_extension_keys)
    active_stages = INSTALL_STAGES if fdb_extended else LEGACY_INSTALL_STAGES
    if fdb_extended and any(key not in raw for key in fdb_extension_keys):
        return invalid('L3_fdb_mode_extension_partial')
    if not fdb_extended and 'stage_fdb_mode_failed' in raw:
        return invalid('L3_fdb_mode_extension_partial')
    required = tuple(key for key in ADMISSION_COUNTERS if key != 'stage_fdb_mode_failed' or fdb_extended)
    counters = {key: number(raw.get(key)) for key in required}
    if not fdb_extended:
        counters['stage_fdb_mode_failed'] = 0
    last = {'request': number(raw.get('last_failure_request')),
            'errno': signed32(raw.get('last_failure_errno')),
            'rollback_errno': signed32(raw.get('last_rollback_errno'))}
    stage = raw.get('last_failure_stage')
    if (any(value is None for value in (*counters.values(), *last.values())) or
            stage not in active_stages):
        return invalid('L3_admission_values_missing_or_invalid')
    fdb_mode = None
    if fdb_extended:
        fdb_mode = {key: number(raw.get(key)) for key in FDB_MODE_COUNTERS}
        fdb_mode['last_reason'] = raw.get('fdb_mode_last_reason')
        fdb_mode['last_error'] = signed32(raw.get('fdb_mode_last_error'))
        fdb_mode['last_control_sampled'] = number(raw.get('fdb_mode_last_control_sampled'))
        fdb_mode['last_control'] = register(raw.get('fdb_mode_last_control'))
        if (any(value is None for value in fdb_mode.values()) or
                fdb_mode['last_reason'] not in FDB_MODE_REASONS or
                fdb_mode['last_control_sampled'] not in (0, 1) or
                fdb_mode['last_error'] > 0 or
                (fdb_mode['last_control_sampled'] == 0 and fdb_mode['last_control'] != 0) or
                (fdb_mode['last_reason'] == 'ready' and fdb_mode['last_error'] != 0)):
            return invalid('L3_fdb_mode_extension_invalid')
    if (last['request'] > counters['requests'] or last['errno'] > 0 or last['rollback_errno'] > 0 or
            sum(counters[key] for key in ADMISSION_REJECTIONS) != counters['parse_rejected'] or
            sum(counters[key] for key in ADMISSION_CATEGORIES) != counters['install_failed'] or
            sum(counters[f'stage_{stage}_failed'] for stage in active_stages) != counters['install_failed'] or
            counters['parse_rejected'] + counters['install_succeeded'] + counters['install_failed'] != counters['requests']):
        return invalid('L3_admission_inconsistent_counts')
    if ((counters['install_failed'] and (not last['request'] or not last['errno'])) or
            (not counters['install_failed'] and (any(last.values()) or stage != 'none'))):
        return invalid('L3_admission_inconsistent_last_failure')
    last['stage'] = stage
    return {'valid': True, 'cached': True, 'counts_are_packets': False, 'counters': counters,
            'fdb_mode': fdb_mode,
            'last_failure': last, 'hardware_forwarding_proven': False,
            'note': 'Cumulative rule admission callbacks, not packet hits. No cross-instance delta is inferred.'}


def flow_sample(snapshot):
    """Decode bounded privacy-safe leases, never the legacy tuple dump."""
    lines = [line.strip() for line in snapshot.get('l3_flows', []) if line.strip()]
    invalid = lambda reason: {'valid': False, 'reason': reason}
    if not lines:
        return invalid('L3_flow_evidence_missing_or_incomplete')
    # The producer's final truncated=0/1 is coverage metadata, unlike a
    # collector read_truncated/probe_failed marker. Only this exact footer
    # may contain it; glued error markers and duplicate keys still fail.
    footer = fields(lines[-1:])
    footer_shape = re.fullmatch(r'emitted=[0-9]{1,2}\s+truncated=[01]', lines[-1]) is not None
    if footer_shape:
        checked = lines[:-1]
    else:
        checked = lines
    if faulty(checked):
        return invalid('L3_flow_evidence_missing_or_incomplete')
    header_lines = []
    row_lines = []
    for line in lines[:-1]:
        if line.startswith('lease='):
            row_lines.append(line)
        elif row_lines:
            return invalid('L3_flow_record_order_invalid')
        else:
            header_lines.append(line)
    header = fields(header_lines if len(lines) > 1 else lines)
    if header.get('schema') == '1' and header.get('available') == '0':
        return invalid('L3_flow_evidence_busy' if header.get('reason') == 'busy' else 'L3_flow_evidence_unavailable')
    expected = {'schema': '1', 'available': '1', 'cached': '1', 'mmio_reads': '0', 'mmio_writes': '0',
                'identity': 'lease_since_fe_creation', 'max_records': '16', 'sampled_by': 'flow_stats'}
    instance = number(header.get('instance_ns'))
    if any(header.get(key) != value for key, value in expected.items()) or not instance:
        return invalid('unsupported_L3_flow_schema_or_instance')
    emitted = number(footer.get('emitted'))
    if (not footer_shape or set(footer) != {'emitted', 'truncated'} or footer.get('truncated') not in ('0', '1') or
            emitted is None or emitted > 16 or emitted != len(row_lines)):
        return invalid('L3_flow_footer_missing_or_invalid')
    rows = {}
    for line in row_lines:
        raw = fields([line])
        row = {key: number(raw.get(key)) for key in FLOW_NUMBERS}
        row['sample_errno'] = signed32(raw.get('sample_errno'))
        if (any(value is None for value in row.values()) or not row['lease'] or
                any(row[key] > 1 for key in FLOW_BOOLEANS) or row['hash'] >= 65536 or
                any(row[key] > 63 for key in ('input_hw', 'output_hw')) or
                row['protocol'] > 255 or row['counter'] >= 32 or row['sample_errno'] > 0 or
                any(row[key] > 0xffffffff for key in ('samples', 'sample_age_ms', 'age_hits'))):
            return invalid('L3_flow_record_missing_or_invalid')
        if row['lease'] in rows:
            return invalid('L3_flow_duplicate_lease')
        if (not row['counted'] and (row['l3_bytes'] or row['packets']) or
                not row['samples'] and row['sample_age_ms']):
            return invalid('L3_flow_record_inconsistent')
        # Row/header namespaces cannot be overlaid to conceal corruption.
        if any(key in raw for key in (*expected, 'instance_ns', 'emitted', 'truncated')):
            return invalid('L3_flow_record_shadows_metadata')
        rows[row['lease']] = row
    return {'valid': True, 'instance_ns': instance, 'coverage_complete': footer['truncated'] == '0',
            'emitted': emitted, 'rows': rows}


def flow_observations(before, after, window, lifecycle_ok):
    b, a = flow_sample(before), flow_sample(after)
    result = {'before': b, 'after': a, 'hardware_forwarding_proven': False, 'rates_available': False,
              'note': 'Opaque boot/FE-instance/lease identity, never hash or counter-slot identity. '
                      'sample_age_ms is time since the last stats attempt, not last traffic; zero with '
                      'samples=0 is not a fresh observation. age_hits counts positive activity samples, '
                      'not packets. Cached increments are not throughput or complete hardware-forwarding proof.'}
    if not b['valid'] or not a['valid']:
        result.update(valid=False, reason='L3_flow_endpoint_missing_or_invalid')
        return result
    result['coverage_complete'] = b['coverage_complete'] and a['coverage_complete']
    if not window['valid']:
        result.update(valid=False, reason='invalid_clock_or_boot_window')
        return result
    if b['instance_ns'] != a['instance_ns']:
        result.update(valid=False, reason='FE_instance_changed_no_cross_instance_comparison')
        return result
    if not lifecycle_ok:
        result.update(valid=False, reason='NI_lifecycle_not_stable_ready_at_endpoints')
        return result
    result.update(valid=True, reason='cached_flow_observations_only' if result['coverage_complete']
                  else 'cached_flow_observations_partial_coverage', leases={})
    for lease in sorted(set(b['rows']) | set(a['rows'])):
        old, new = b['rows'].get(lease), a['rows'].get(lease)
        item = {'valid': False}
        reason = None
        if old is None or new is None:
            reason = 'lease_not_observed_in_both_snapshots'
        elif any(old[key] != new[key] for key in ('hash', 'input_hw', 'output_hw', 'ipv6', 'protocol', 'counted', 'counter')):
            reason = 'lease_resource_identity_changed'
        elif any(not row['installed'] or not row['published'] or row['deleting'] for row in (old, new)):
            reason = 'lease_not_live_at_both_endpoints'
        elif any(row['sample_errno'] for row in (old, new)):
            reason = 'stats_attempt_failed_old_cache_not_reused'
        elif not old['samples'] or new['samples'] <= old['samples']:
            reason = 'successful_sample_not_advanced_or_reset'
        elif any(new[key] < old[key] for key in ('age_hits', 'l3_bytes', 'packets')):
            reason = 'cached_counter_decreased_reset_or_wrap_not_guessed'
        if reason:
            item['reason'] = reason
        else:
            item.update(valid=True, successful_samples=new['samples'] - old['samples'],
                        positive_activity_samples=new['age_hits'] - old['age_hits'],
                        sample_age_ms={'before': old['sample_age_ms'], 'after': new['sample_age_ms']},
                        sample_times_verified=False)
            if new['counted']:
                item['observed_increments'] = {key: new[key] - old[key] for key in ('l3_bytes', 'packets')}
            else:
                item['packet_totals_available'] = False
        result['leases'][str(lease)] = item
    return result


def cold_sample(snapshot):
    """Decode a historical probe record; never infer a live gate or L2 hit.

    provider_ready/engine_poisoned are current flags accompanying the cached
    record. A valid record is not proof of a new power cycle, nor proof that
    a gate remains shut after the normal PON owner reopens it.
    """
    lines = snapshot.get('cold_bootstrap', [])
    invalid = lambda reason: {'valid': False, 'historical': True, 'reason': reason}
    if not lines or faulty(lines):
        return invalid('cold_record_missing_or_incomplete')
    raw = fields(lines)
    if any(raw.get(key) != '1' for key in ('schema', 'cached', 'historical')):
        return invalid('unsupported_cold_record_schema')
    bools = ('requested', 'attempted', 'managed', 'provider_ready', 'engine_poisoned',
             'pon_snapshot_ready', 'pon_pdc_active')
    registers = ('pon_gated_mask', 'pon_fifo', 'pon_control', 'pon_epon_control',
                 'pon_gpon_control', 'pon_refused_register', 'pon_refused_value')
    record = {key: number(raw.get(key)) for key in (*bools, 'pon_stage', 'pon_fifo_polls')}
    record.update({key: register(raw.get(key)) for key in registers})
    record.update({key: signed32(raw.get(key)) for key in ('result', 'pon_error')})
    if (any(value is None for value in record.values()) or
            any(record[key] > 1 for key in bools) or record['pon_stage'] >= len(COLD_STAGES) or
            record['pon_gated_mask'] > 15 or record['pon_fifo_polls'] > 0xffffffff):
        return invalid('cold_record_missing_or_invalid_value')
    if ((record['pon_snapshot_ready'] and (record['pon_stage'] != 7 or record['pon_error'])) or
            (record['pon_gated_mask'] and not record['pon_pdc_active']) or
            (record['managed'] and (not record['requested'] or not record['attempted'] or
                                   record['result'] or not record['pon_snapshot_ready']))):
        return invalid('cold_record_inconsistent_state')

    clock_names = ('pon_clock_guard', 'pon_clock_required', 'pon_clock_samples',
                   'pon_clock_valid', 'pon_clock_ready', 'pon_clock_first', 'pon_clock_last')
    clock_extension = None
    if any(key in raw for key in clock_names):
        clock_extension = {key: number(raw.get(key)) for key in
                           ('pon_clock_samples', 'pon_clock_valid', 'pon_clock_ready')}
        clock_extension.update({key: register(raw.get(key)) for key in
                                ('pon_clock_required', 'pon_clock_first', 'pon_clock_last')})
        clock_extension['guard'] = raw.get('pon_clock_guard')
        if (any(value is None for value in clock_extension.values()) or
                clock_extension['guard'] != 'xgpon_only' or
                clock_extension['pon_clock_required'] not in (0, 0x1c00) or
                clock_extension['pon_clock_valid'] not in (0, 1) or
                clock_extension['pon_clock_ready'] not in (0, 1) or
                (clock_extension['pon_clock_samples'] == 0 and
                 any(clock_extension[key] for key in ('pon_clock_valid', 'pon_clock_ready',
                        'pon_clock_first', 'pon_clock_last'))) or
                (clock_extension['pon_clock_samples'] > 0 and
                 (clock_extension['pon_clock_required'] != 0x1c00 or
                  not (record['pon_control'] & (1 << 2)) or
                  clock_extension['pon_clock_valid'] !=
                  (clock_extension['pon_clock_last'] != 0xffffffff))) or
                (clock_extension['pon_clock_required'] == 0x1c00 and
                 not (record['pon_gated_mask'] & 0x8)) or
                (clock_extension['pon_clock_ready'] !=
                 (clock_extension['pon_clock_valid'] == 1 and
                  (clock_extension['pon_clock_last'] & 0x1c00) == 0x1c00)) or
                (record['pon_stage'] == 8 and
                 (clock_extension['pon_clock_required'] != 0x1c00 or
                  clock_extension['pon_clock_ready'] or
                  record['pon_refused_register'] not in (0xa060, 0xf4320094) or
                  record['pon_error'] not in (-11, -5)))):
            return invalid('cold_clock_extension_partial_or_invalid')
    elif record['pon_stage'] == 8:
        return invalid('cold_clock_extension_missing')

    gate_fields = tuple(f'pon_gate{i}_{part}' for i in range(4)
                        for part in ('before', 'requested', 'readback'))
    gate_masks = ('pon_gate_written_mask', 'pon_gate_sampled_mask')
    gate_counts = ('pon_gate_polls', 'pon_gate_stable')
    extension = None
    if any(key in raw for key in (*gate_fields, *gate_masks, *gate_counts)):
        extension = {key: register(raw.get(key)) for key in (*gate_fields, *gate_masks)}
        extension.update({key: number(raw.get(key)) for key in gate_counts})
        if (any(value is None for value in extension.values()) or
                any(extension[key] > 0xffffffff for key in gate_counts)):
            return invalid('cold_gate_extension_partial_or_invalid')
        selected = record['pon_gated_mask']
        sampled, written = (extension[key] for key in ('pon_gate_sampled_mask', 'pon_gate_written_mask'))
        if (sampled & ~selected or written & ~sampled or
                extension['pon_gate_stable'] > min(3, extension['pon_gate_polls'])):
            return invalid('cold_gate_extension_inconsistent')
        for i, (_, mask, _) in enumerate(COLD_GATES):
            before = extension[f'pon_gate{i}_before']
            requested = extension[f'pon_gate{i}_requested']
            readback = extension[f'pon_gate{i}_readback']
            # R12 refuses inherited XG reset/flush commands before forming
            # an RMW request. It legitimately records sampled but unwritten
            # with requested=0, rather than replaying command bits.
            command_refused = (i == 3 and before & 0xc0000000 and before != 0xffffffff and
                               record['pon_stage'] == 3 and record['pon_error'] == -16 and
                               not written & (1 << i) and requested == 0)
            if ((not sampled & (1 << i) and (before or requested or readback)) or
                    (sampled & (1 << i) and before != 0xffffffff and not command_refused and
                     requested != (before & ~mask))):
                return invalid('cold_gate_extension_inconsistent')
            if written & (1 << i) and (before == 0xffffffff or not (before & mask) or
                    requested != (before & ~mask)):
                return invalid('cold_gate_extension_inconsistent')
            if (record['pon_snapshot_ready'] and selected & (1 << i) and
                    (before == 0xffffffff or extension[f'pon_gate{i}_readback'] & mask or
                     bool(written & (1 << i)) != bool(before & mask))):
                return invalid('cold_gate_extension_inconsistent')
        if record['pon_snapshot_ready'] and (sampled != selected or
                extension['pon_gate_stable'] != (3 if selected else 0) or
                (not selected and extension['pon_gate_polls'])):
            return invalid('cold_gate_extension_inconsistent')

    if record['managed']:
        diagnosis = 'cold_baseline_prepared_not_runtime_L2_proof'
    elif not record['requested']:
        diagnosis = 'cold_handoff_not_requested'
    elif not record['attempted']:
        diagnosis = 'cold_handoff_not_attempted'
    elif record['pon_stage'] == 8 and record['pon_error'] in (-11, -5):
        diagnosis = ('clock_guard_refused_before_receive_gate_write'
                     if not extension or not extension['pon_gate_written_mask']
                     else 'clock_guard_lost_during_cold_handoff')
    elif record['pon_error'] and record['pon_stage'] == 4 and not record['pon_fifo_polls']:
        diagnosis = 'receive_gate_readback_refused_before_FIFO'
    elif record['pon_error']:
        diagnosis = 'PON_quiesce_or_reverification_refused'
    else:
        diagnosis = 'fabric_or_resource_preparation_not_managed'
    result = {'valid': True, 'historical': True, 'power_cycle_proven': False,
              'live_RX_state_proven': False, 'runtime_native_L2_proven': False,
              'reason': diagnosis, 'stage_name': COLD_STAGES[record['pon_stage']],
              'record': record, 'gate_extension_present': extension is not None}
    if extension is not None:
        result['gate_observations'] = extension
    result['clock_extension_present'] = clock_extension is not None
    if clock_extension is not None:
        result['clock_observations'] = clock_extension
        result['clock_ready_proven'] = False  # cached CKRDY bits are not a MAC gate ACK
    result['pon_cached_observations'] = pon_cached_observations(raw)
    if record['pon_error']:
        for address, mask, family in COLD_GATES:
            if record['pon_refused_register'] == address:
                result['refused_receive_gate'] = {'family': family, 'register': address, 'mask': mask,
                                                  'last_gate_bits': record['pon_refused_value'] & mask}
    return result


def pon_cached_observations(raw):
    """Optional R12 historical ordering/clock samples, not readiness bits."""
    prefixes = ('pon_before_', 'pon_after_')
    registers = ('sampled', 'valid', 'refused_register', 'refused_value', 'control', 'epon', 'gpon',
                 'psds_mode', 'psds_status', 'psds_gbox', 'pdc_control')
    masks = ('pon_gate_closed_mask', 'pon_gate_reopened_mask', 'pon_gate_changed_mask')
    counts = tuple(f'pon_gate{i}_{part}' for i in range(4) for part in ('first_closed_poll', 'changes'))
    keys = (*masks, *counts, 'pon_observation_schema', 'pon_clock_observation_only',
            *(prefix + suffix for prefix in prefixes for suffix in (*registers, 'stable', 'error')))
    invalid = lambda reason: {'valid': False, 'reason': reason}
    if not any(key in raw for key in keys):
        return invalid('PON_cached_observations_unavailable')
    if raw.get('pon_observation_schema') != '1' or raw.get('pon_clock_observation_only') != '1':
        return invalid('unsupported_PON_observation_schema')
    values = {key: register(raw.get(key)) for key in masks}
    values.update({key: number(raw.get(key)) for key in counts})
    for prefix in prefixes:
        values.update({prefix + key: register(raw.get(prefix + key)) for key in registers})
        values[prefix + 'stable'] = number(raw.get(prefix + 'stable'))
        values[prefix + 'error'] = signed32(raw.get(prefix + 'error'))
    if (any(value is None for value in values.values()) or any(values[key] > 15 for key in masks) or
            any(values[key] > 0xffffffff for key in counts)):
        return invalid('PON_observation_extension_partial_or_invalid')
    for prefix in prefixes:
        if (values[prefix + 'sampled'] > 127 or values[prefix + 'valid'] & ~values[prefix + 'sampled'] or
                values[prefix + 'stable'] > 1 or values[prefix + 'error'] > 0):
            return invalid('PON_observation_extension_inconsistent')
    return {'valid': True, 'historical': True, 'clock_ready_proven': False,
            'register_observations': values,
            'note': 'Before/after cached observations of one cold attempt, not live PON status or a clock/retirement ACK.'}


def mib_sample(snapshot):
    lines = [line for line in snapshot.get("lan_mib_evidence", []) if line.strip()]
    if not lines or faulty(lines):
        return None, {}, "cached_MIB_export_missing_or_incomplete"
    header = fields(lines[:1])
    expected = {"schema": "1", "cached": "1", "raw": "1", "reset_tracking": "0",
                "l2_attribution": "0", "atomic_hardware_snapshot": "0", "clock": "boottime",
                "read_opcode": "0", "counter_mode_verified": "0"}
    if any(header.get(key) != value for key, value in expected.items()):
        return None, {}, "unsupported_cached_MIB_schema"
    captured = number(header.get("capture_ns"))
    if captured is None:
        return None, {}, "MIB_capture_clock_missing"
    begin = uptime(fields(snapshot.get("sample_begin", [])).get("uptime"))
    end = uptime(fields(snapshot.get("sample_end", [])).get("uptime"))
    # /proc/uptime truncates to centiseconds; a getter near that boundary may
    # be up to 10 ms later than the displayed sample_end. No wall-clock mixing.
    if begin is None or end is None or not begin * 1_000_000_000 <= captured < (end + Decimal("0.01")) * 1_000_000_000:
        return None, {}, "MIB_capture_outside_snapshot_clock_window"
    ports = {}
    mask = register(header.get("registered_mask"))
    if mask is None or mask > 31:
        return None, {}, "invalid_registered_port_mask"
    for line in lines[1:]:
        row = fields([line])
        port = number(row.get("port"))
        if port is None or port > 4 or port in ports:
            return None, {}, "invalid_or_duplicate_physical_port"
        if row.get("registered") != str((mask >> port) & 1):
            return None, {}, "registered_port_mask_mismatch"
        ports[port] = row
    if set(ports) != set(range(5)):
        return None, {}, "physical_port_samples_missing"
    return captured, ports, None


def mib_topology_reason(before, after, port, index):
    lb, la = (links(snapshot.get("wired_link_state", [])) for snapshot in (before, after))
    matches = [[row for row in listing.values() if row and number(row.get("ifindex")) == index]
               for listing in (lb, la)]
    if any(len(rows) != 1 for rows in matches):
        return "physical_port_link_mapping_missing_or_ambiguous"
    b, a = matches[0][0], matches[1][0]
    if any(number(row.get("dev_port")) != port for row in (b, a)):
        return "physical_port_dev_port_mapping_mismatch"
    if b != a:
        return "physical_port_link_or_bridge_policy_changed"
    if any(number(b.get(key)) is None for key in ("iflink", "mtu")):
        return "physical_port_link_identity_missing"
    return None


def mib_observations(before, after, lifecycle_ok):
    cb, mb, eb = mib_sample(before)
    ca, ma, ea = mib_sample(after)
    if eb or ea:
        return {"valid": False, "reason": eb or ea}
    if not lifecycle_ok:
        return {"valid": False, "reason": "NI_lifecycle_not_stable_ready_at_endpoints"}
    output = {}
    for port in sorted(set(mb) | set(ma)):
        b, a = mb.get(port), ma.get(port)
        reason = None
        if not b or not a:
            reason = "port_sample_missing"
        elif any(row.get(key) != "1" for row in (b, a) for key in ("registered", "valid")):
            reason = "port_not_registered_or_sample_not_valid"
        elif any(row.get("error") != "0" for row in (b, a)):
            reason = "last_MIB_read_failed_old_cache_not_reused"
        elif any(number(row.get("ifindex")) in (None, 0) for row in (b, a)) or b.get("ifindex") != a.get("ifindex"):
            reason = "physical_port_interface_identity_missing_or_changed"
        elif mib_topology_reason(before, after, port, int(a["ifindex"])):
            reason = mib_topology_reason(before, after, port, int(a["ifindex"]))
        elif any(register(row.get(key)) is None for row in (b, a) for key in ("config_begin", "config_end")):
            reason = "MIB_configuration_missing_or_invalid"
        elif any(register(row.get("config_begin")) != register(row.get("config_end")) for row in (b, a)) or register(b.get("config_begin")) != register(a.get("config_begin")):
            reason = "MIB_configuration_changed"
        else:
            sb, sa = number(b.get("seq")), number(a.get("seq"))
            ab, aa = number(b.get("attempts")), number(a.get("attempts"))
            times = [number(row.get(key)) for row in (b, a) for key in ("begin_ns", "end_ns")]
            if sb is None or sa is None or sb == 0 or sa <= sb:
                reason = "MIB_sample_not_advanced_or_sequence_reset"
            elif ab is None or aa is None or ab < sb or aa < sa or aa <= ab:
                reason = "MIB_attempt_sequence_inconsistent"
            elif any(value is None for value in times):
                reason = "MIB_sample_clock_missing"
            elif any(number(row.get("attempt_" + key)) != number(row.get(key))
                     for row in (b, a) for key in ("begin_ns", "end_ns")):
                reason = "MIB_successful_attempt_clock_mismatch"
            else:
                b0, b1, a0, a1 = times
                if not b0 <= b1 <= cb < a0 <= a1 <= ca:
                    reason = "MIB_sample_clock_not_ordered_or_old_after_sample"
                elif cb - b1 > MAX_MIB_AGE_NS or ca - a1 > MAX_MIB_AGE_NS:
                    reason = "cached_MIB_older_than_3_seconds"
                elif any(number(row.get(key)) is None or number(row.get(key)) >
                         (MAX_COUNTER if key.endswith("bytes") else 0xFFFFFFFF)
                         for row in (b, a) for key in MIB_COUNTERS):
                    reason = "raw_MAC_counter_missing_or_out_of_range"
        if reason:
            output[str(port)] = {"valid": False, "reason": reason}
            continue
        sample_window = {"min_seconds": (a0 - b1) / 1_000_000_000,
                         "max_seconds": (a1 - b0) / 1_000_000_000}
        # READ_ONLY opcode and stable GLB_STATIC do not establish precedence
        # over the SDK's global clear-on-read mode. Preserve useful evidence,
        # but never turn unverified raw values into cumulative MAC Mbps.
        output[str(port)] = {"valid": False, "raw_observations_valid": True,
                             "reason": "counter_continuity_unverified", "rates_available": False,
                             "ifindex": int(a["ifindex"]), "sample_window": sample_window,
                             "before_sample": {"begin_ns": b0, "end_ns": b1, "capture_ns": cb,
                                               "seq": sb, "config_raw": b["config_begin"]},
                             "after_sample": {"begin_ns": a0, "end_ns": a1, "capture_ns": ca,
                                              "seq": sa, "config_raw": a["config_begin"]},
                             "before": {key: b[key] for key in MIB_COUNTERS},
                             "after": {key: a[key] for key in MIB_COUNTERS}}
    return output


def tm_sample(snapshot, active):
    lines = [line for line in snapshot.get('fabric_evidence', []) if line.strip()]
    if not lines or faulty(lines):
        return None, 'fabric_cache_missing_or_incomplete'
    if active and faulty(snapshot.get('fabric_sample', [])):
        return None, 'last_fabric_capture_failed_old_cache_not_reused'
    # Header and register metadata share one namespace. A later duplicate
    # valid/schema/epoch flag (including an empty one) invalidates the record.
    header = fields([line for line in lines if not line.startswith('counter=')])
    expected = {'schema': '1', 'cached': '1', 'clock': 'boottime', 'global': '1',
                'atomic_hardware_snapshot': '0', 'hardware_reset_verified': '0',
                'te_direct_mode_verified': '0', 'valid': '1'}
    if any(header.get(key) != value for key, value in expected.items()):
        return None, 'unsupported_or_invalid_fabric_cache'
    timing = {key: number(header.get(key)) for key in
              ('capture_ns', 'seq', 'epoch', 'owner_generation', 'current_owner_generation',
               'begin_ns', 'end_ns', 'delta_valid', 'epoch_reason')}
    if any(value is None for value in timing.values()) or not timing['seq'] or not timing['epoch']:
        return None, 'fabric_metadata_missing_or_invalid'
    if active:
        trigger = fields(snapshot.get('fabric_sample', []))
        trigger_seq, trigger_epoch = number(trigger.get('seq')), number(trigger.get('epoch'))
        if (trigger.get('schema') != '1' or trigger.get('valid') != '1' or
                trigger.get('sampled') not in ('0', '1') or not trigger_seq or
                trigger_epoch != timing['epoch'] or trigger_seq > timing['seq']):
            return None, 'active_fabric_capture_ack_missing_or_mismatched'
    if timing['delta_valid'] > 1 or timing['epoch_reason'] > 7:
        return None, 'fabric_metadata_missing_or_invalid'
    if timing['owner_generation'] != timing['current_owner_generation']:
        return None, 'fabric_owner_changed_after_sample'
    if not timing['begin_ns'] <= timing['end_ns'] <= timing['capture_ns']:
        return None, 'fabric_sample_clock_invalid'
    if timing['capture_ns'] - timing['begin_ns'] > MAX_MIB_AGE_NS:
        return None, 'cached_fabric_older_than_3_seconds'
    begin = uptime(fields(snapshot.get('sample_begin', [])).get('uptime'))
    end = uptime(fields(snapshot.get('sample_end', [])).get('uptime'))
    if begin is None or end is None or not begin * 1_000_000_000 <= timing['capture_ns'] < (end + Decimal('0.01')) * 1_000_000_000:
        return None, 'fabric_capture_outside_snapshot_clock_window'
    metadata = header
    if (metadata.get('contract') != 'partial' or metadata.get('tm_te_baseline_verified') != '0' or
            metadata.get('wan_arb_readback') != '0'):
        return None, 'unsupported_fabric_contract'
    configuration = {key: register(metadata.get(key)) for key in TM_CONFIGS}
    status = {key: register(metadata.get(key)) for key in TM_STATUSES}
    if any(value is None for value in (*configuration.values(), *status.values())):
        return None, 'fabric_register_snapshot_missing_or_invalid'
    if any(key in metadata for key in (*TM_BUFFER_CONFIGS, *TM_BUFFER_STATUSES)):
        extension = {key: register(metadata.get(key)) for key in (*TM_BUFFER_CONFIGS, *TM_BUFFER_STATUSES)}
        if any(value is None for value in extension.values()):
            return None, 'fabric_buffer_extension_partial_or_invalid'
        configuration.update({key: extension[key] for key in TM_BUFFER_CONFIGS})
        status.update({key: extension[key] for key in TM_BUFFER_STATUSES})
    clear = configuration['tm_clear_control'] >> 31
    if metadata.get('bm_clear_on_read') != str(clear):
        return None, 'fabric_counter_mode_mismatch'
    counters = {}
    for line in lines[1:]:
        if not line.startswith('counter='):
            continue
        row = fields([line])
        name = row.get('counter')
        if name not in TM_BM_COUNTERS + TM_TE_COUNTERS or name in counters:
            return None, 'fabric_counter_duplicate_or_unknown'
        if any(key in header or key not in ('counter', 'raw', 'observed', 'mode') for key in row):
            return None, 'fabric_counter_shadows_metadata'
        raw = number(row.get('raw'))
        mode = ('read_clear' if clear else 'cumulative') if name in TM_BM_COUNTERS else 'unknown'
        if raw is None or raw > 0xffffffff or row.get('mode') != mode:
            return None, 'fabric_counter_value_or_mode_invalid'
        counters[name] = {'raw': raw, 'mode': mode}
        if name in TM_BM_COUNTERS:
            observed = number(row.get('observed'))
            if observed is None:
                return None, 'fabric_observed_counter_missing'
            counters[name]['observed'] = observed
        elif 'observed' in row:
            return None, 'unverified_TE_counter_must_not_have_total'
    if set(counters) != set(TM_BM_COUNTERS + TM_TE_COUNTERS):
        return None, 'fabric_counters_missing'
    return {'timing': timing, 'configuration': configuration, 'status': status, 'counters': counters}, None


def tm_observations(before, after, lifecycle_ok, active):
    b, eb = tm_sample(before, active)
    a, ea = tm_sample(after, active)
    if eb or ea:
        return {'valid': False, 'reason': eb or ea}
    result = {'raw_observations_valid': True, 'hardware_drop_attribution': False,
              'hardware_reset_verified': False, 'rates_available': False,
              'scope': 'global_fabric_not_per_flow_or_per_LAN', 'before': b, 'after': a}
    reason = None
    if not lifecycle_ok:
        reason = 'NI_lifecycle_not_stable_ready_at_endpoints'
    elif b['timing']['owner_generation'] != a['timing']['owner_generation']:
        reason = 'fabric_owner_epoch_changed'
    elif a['timing']['seq'] <= b['timing']['seq'] or a['timing']['begin_ns'] <= b['timing']['end_ns']:
        reason = 'fabric_sample_not_advanced_or_overlapping'
    elif b['timing']['epoch'] != a['timing']['epoch']:
        reason = 'fabric_observed_epoch_changed'
    elif b['configuration'] != a['configuration']:
        reason = 'fabric_configuration_changed'
    elif a['timing']['delta_valid'] != 1 or a['timing']['epoch_reason'] != 0:
        reason = 'fabric_interval_unusable'
    elif any(a['counters'][key]['observed'] < b['counters'][key]['observed'] for key in TM_BM_COUNTERS):
        reason = 'fabric_observed_counter_decreased'
    if reason:
        result.update(valid=False, reason=reason)
        return result
    # These are only increments collected by the single software owner under
    # the SDK BM mode, NOT proof of silicon reset continuity or drop attribution.
    # Never difference direct TE registers using the unrelated PM-memory flag.
    result.update(valid=True, reason='observed_BM_increments_only_hardware_continuity_unverified',
                  bm_observed_increments={key: a['counters'][key]['observed'] - b['counters'][key]['observed']
                                          for key in TM_BM_COUNTERS},
                  te_note='raw_only_direct_register_clear_mode_unverified')
    return result


def summarize(text):
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise ValueError("capture exceeds 2 MiB")
    if not text.startswith("schema=tyfza1-datapath-v3 "):
        raise ValueError("expected tyfza1-datapath-v3 capture")
    snapshots = sections(text)
    window = clocks(snapshots)
    header = fields(text.splitlines()[:1])
    mode = header.get("mode")
    result = {"schema": "tyfza1-datapath-summary-v1", "clock_window": window,
              "capture_mode": mode if mode in ("passive", "active_diagnostics") else "unknown",
              "hardware_forwarding_proven": False,
              "notes": ["No measured ASIC hit rate or LAN forwarding throughput is inferred.",
                        "Linux netdev and QM CPU counters describe host traffic, not ASIC LAN MIBs.",
                        "Two non-atomic observations cannot exclude intervening resets or policy ABA.",
                        "FE observations compare only same-boot FE-instance/lease records; hash and counter slots are not identity.",
                        "MAC raw observations have unverified counter mode; no MAC delta or rate is calculated.",
                        "Cold-bootstrap records are historical, not proof of a new power cycle or current RX gates."],
              "states": {}, "qm_cpu": {}, "qm_buffer": {}, "qm_multicast": {},
              "netdev_host": {}, "physical_mac_cached": {}, "fabric_cached": {},
              "cold_bootstrap_history": {}, "l2_completed": {}, "mce_cached": {},
              "l3_admission": {}, "l3_flows_cached": {}, "mce_inherited": {}}
    fe_keys = ("l2_requested", "l2_active", "l2_reason", "l2_hw_reason", "l2_hw_valid", "l2_worker_busy", "l2_error", "l2_ports",
               "l2_bum_hardware", "l2_vlan_hardware", "l2_mdb_hardware", "l2_multibridge_hardware",
               "l2_route_policy_allowed", "l2_flow_allowed", "l2_local_target", "l2_rx_gate_verified",
               "l2_route_eligible_ports", "l2_native_route_policy_allowed",
               "naptv6_configured", "action_bits", "cache_entries", "cache_action_bits",
               "action_mode_runtime_change", "mdb_cpu_entries", "mdb_folded_entries",
               "mdb_overlap_cpu", "mdb_capacity_cpu", "mdb_dynamic_rows",
               "l2_learning_ports", "l2_isolated_ports", "l2_static_published",
               "l2_journal_used", "l2_journal_capacity", "l2_journal_quarantined",
               "lan_admission_valid", "lan_cpu_mask",
               "lan_route_mask", "lan_native_l2_mask", "base_ready", "base_failed",
               "full_l3_drain_verified", "route_gate_ready", "route_admitted", "route_gate_verified",
               "eif_rows_used", "retry_flows", "cleanup_backoff_ms", "lan_pon_rules",
               "pon_lan_rules", "lan_lan_route_rules", "rule_counts_are_hits",
               "route_hash_templates_config", "wan_arb_pdpid_config",
               "sdk_wan_arb_pdpid", "wan_arb_board_contract_verified",
               "programming_metadata_is_readback", "route_withdrawals_pending",
               "mce_owner", "mce_contract_ready", "mce_cold_handoff_verified", "mce_error",
               "mce_missing_contracts", "mce_groups", "mce_tokens", "mce_publications", "mce_fallbacks",
               "mce_rx_copies", "mce_rx_rejected", "mce_rx_no_memory", "mdb_owner", "mdb_active",
               "mdb_error", "mdb_register", "mdb_value", "mdb_generation", "mdb_records", "mdb_planned",
               "mdb_used", "mdb_exposed", "mdb_guards", "mdb_guard_exposed", "mdb_window", "mdb_steer",
               "mdb_attempts", "mdb_publications", "mdb_withdrawals", "l2_owner_unavailable",
               "l2_owner_sealed", "l2_owner_ready", "l2_owner_quarantined", "l2_owner_error",
               "l2_owner_reads", "l2_owner_publications", "l2_owner_withdrawals", "l2_owner_aborts", "l2_owner_failures",
               *(f'l2_bank_{bank}_{field}' for bank in range(3)
                 for field in ('capacity', 'leased', 'verified_available')))
    for which, snapshot in snapshots.items():
        result["states"][which] = {"fe": select_fe_state(snapshot, fe_keys),
                                    "ni": select_state(snapshot, "xram_state", LIFECYCLE)}
        result['cold_bootstrap_history'][which] = cold_sample(snapshot)
        result['l2_completed'][which] = l2_completed_sample(snapshot)
        result['mce_cached'][which] = mce_sample(snapshot)
        result['mce_inherited'][which] = mce_inherited_sample(snapshot)
        result['l3_admission'][which] = admission_sample(snapshot)
    before, after = (snapshots[key] for key in ("before", "after"))
    ni_before, ni_after = (result["states"][key]["ni"] for key in ("before", "after"))
    expected = dict(zip(LIFECYCLE, ("1", "1", "0", "1", "0")))
    result['l3_flows_cached'] = flow_observations(before, after, window,
                                                ni_before == expected and ni_after == expected)
    if not window["valid"]:
        result["qm_cpu"] = {"valid": False, "reason": "invalid_clock_window"}
        result["qm_buffer"] = {"valid": False, "reason": "invalid_clock_window"}
        result["qm_multicast"] = {"valid": False, "reason": "invalid_clock_window"}
        result["netdev_host"] = {"valid": False, "reason": "invalid_clock_window"}
        result["physical_mac_cached"] = {"valid": False, "reason": "invalid_clock_window"}
        result["fabric_cached"] = {"valid": False, "reason": "invalid_clock_window"}
        return result

    result["physical_mac_cached"] = mib_observations(before, after, ni_before == expected and ni_after == expected)
    result["fabric_cached"] = tm_observations(before, after, ni_before == expected and ni_after == expected,
                                               mode == 'active_diagnostics')
    if ni_before != expected or ni_after != expected:
        result["qm_cpu"] = {"valid": False, "reason": "NI_lifecycle_not_stable_ready_at_endpoints"}
        result["qm_buffer"] = {"valid": False, "reason": "NI_lifecycle_not_stable_ready_at_endpoints"}
        result["qm_multicast"] = {"valid": False, "reason": "NI_lifecycle_not_stable_ready_at_endpoints"}
    elif any(faulty(snapshot.get("qm_voqs", [])) for snapshot in (before, after)):
        result["qm_cpu"] = {"valid": False, "reason": "QM_sample_incomplete"}
        result["qm_buffer"] = {"valid": False, "reason": "QM_sample_incomplete"}
        result["qm_multicast"] = {"valid": False, "reason": "QM_sample_incomplete"}
    else:
        qb, qa = (fields(snapshot.get("qm_voqs", [])) for snapshot in (before, after))
        result["qm_cpu"] = {key: delta(qb.get(key), qa.get(key), window) for key in
                            ("cpu_bytes", "cpu_packets", "ring_errors", "buffer_errors", "budget_hits")}
        result["qm_buffer"] = qm_buffer_pressure(qb, qa, window)
        result["qm_multicast"] = qm_mcast_observation(qb, qa, window)

    lb, la = (links(snapshot.get("wired_link_state", [])) for snapshot in (before, after))
    nb, na = (netdev(snapshot.get("netdev_counters", [])) for snapshot in (before, after))
    for name in sorted(set(lb) | set(la)):
        # Every exported policy/link field participates, not just ifindex.
        if not lb.get(name) or not la.get(name) or lb[name] != la[name]:
            result["netdev_host"][name] = {"valid": False, "reason": "interface_identity_link_or_topology_changed"}
        elif any(number(lb[name].get(key)) is None for key in ("ifindex", "iflink", "mtu")):
            result["netdev_host"][name] = {"valid": False, "reason": "interface_identity_missing"}
        elif not nb.get(name) or not na.get(name):
            result["netdev_host"][name] = {"valid": False, "reason": "netdev_counter_sample_missing_or_invalid"}
        else:
            result["netdev_host"][name] = {key: delta(nb[name][key], na[name][key], window) for key in nb[name]}
    if not lb and not la:
        result["netdev_host"] = {"valid": False, "reason": "link_samples_missing_or_incomplete"}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    arguments = parser.parse_args()
    try:
        with arguments.capture.open("rb") as stream:
            content = stream.read(MAX_BYTES + 1)
        if len(content) > MAX_BYTES:
            raise ValueError("capture exceeds 2 MiB")
        result = summarize(content.decode("utf-8", errors="strict"))
    except (OSError, UnicodeError, ValueError) as error:
        parser.exit(2, f"Invalid capture: {error}\n")
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
