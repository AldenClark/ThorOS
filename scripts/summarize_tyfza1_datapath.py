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
TOKEN = re.compile(r"(?<!\S)([a-zA-Z_][a-zA-Z0-9_]*)=([^\s]+)")
LIFECYCLE = ("base_ready", "dma_exposed", "engine_poisoned", "host_active", "reboot_required")
MIB_COUNTERS = ("rx_bytes", "tx_bytes", "rx_uc", "rx_mc", "rx_bc", "tx_uc", "tx_mc", "tx_bc")
MAX_MIB_AGE_NS = 3_000_000_000
TM_CONFIGS = ('tm_clear_control', 'bm_control', 'buffer_config', 'eq_config', 'private_config',
              'es_control', 'es_lan0', 'es_lan1', 'es_lan2', 'es_lan3', 'es_lan4',
              'es_l3wan10', 'es_oam12', 'es_l3lan13', 'te_control', 'fc_control',
              'te_pm_control', 'ni_internal', 'ni_demux0', 'ni_demux1', 'ni_demux2',
              'ni_demux3', 'ni_deep0', 'ni_deep1', 'ni_deep2', 'ni_deep3', 'lpb_map')
TM_STATUSES = ('tm_init', 'te_pm_init', 'fc_status', 'es_ready', 'es_pending0', 'es_pending1',
               'es_pending2', 'es_pending3', 'es_ok0', 'es_ok1', 'es_ok2', 'es_ok3',
               'es_port_ok', 'es_arb', 'buffer_free')
TM_BM_COUNTERS = ('bm_rx', 'bm_tx', 'bm_sb_drop', 'bm_hdr_drop', 'bm_te_drop',
                  'bm_err_drop', 'bm_nobuf_drop')
TM_TE_COUNTERS = ('te_pol_drop', 'te_tail_drop', 'te_wred_y_drop', 'te_wred_g_drop')
FAILURE_MARKER = re.compile(r"(?:probe_(?:failed|skipped|unavailable)|read_truncated|truncated|skipped)=")


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
    header = fields(lines[:1])
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
    metadata = fields([line for line in lines[1:] if not line.startswith('counter=')])
    if (metadata.get('contract') != 'partial' or metadata.get('tm_te_baseline_verified') != '0' or
            metadata.get('wan_arb_readback') != '0'):
        return None, 'unsupported_fabric_contract'
    configuration = {key: register(metadata.get(key)) for key in TM_CONFIGS}
    status = {key: register(metadata.get(key)) for key in TM_STATUSES}
    if any(value is None for value in (*configuration.values(), *status.values())):
        return None, 'fabric_register_snapshot_missing_or_invalid'
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
                        "FE rows are not differenced without a stable per-flow/counter generation.",
                        "MAC raw observations have unverified counter mode; no MAC delta or rate is calculated."],
              "states": {}, "qm_cpu": {}, "netdev_host": {}, "physical_mac_cached": {}, "fabric_cached": {}}
    fe_keys = ("l2_requested", "l2_active", "l2_reason", "l2_error", "l2_ports",
               "l2_bum_hardware", "l2_vlan_hardware", "lan_admission_valid", "lan_cpu_mask",
               "lan_route_mask", "lan_native_l2_mask", "base_ready", "base_failed",
               "full_l3_drain_verified", "route_gate_ready", "route_admitted",
               "eif_rows_used", "retry_flows", "cleanup_backoff_ms", "lan_pon_rules",
               "pon_lan_rules", "lan_lan_route_rules", "rule_counts_are_hits",
               "route_hash_templates_config", "wan_arb_pdpid_config",
               "sdk_wan_arb_pdpid", "wan_arb_board_contract_verified",
               "programming_metadata_is_readback")
    for which, snapshot in snapshots.items():
        result["states"][which] = {"fe": select_state(snapshot, "fe", fe_keys),
                                    "ni": select_state(snapshot, "xram_state", LIFECYCLE)}
    if not window["valid"]:
        result["qm_cpu"] = {"valid": False, "reason": "invalid_clock_window"}
        result["netdev_host"] = {"valid": False, "reason": "invalid_clock_window"}
        result["physical_mac_cached"] = {"valid": False, "reason": "invalid_clock_window"}
        result["fabric_cached"] = {"valid": False, "reason": "invalid_clock_window"}
        return result

    before, after = (snapshots[key] for key in ("before", "after"))
    ni_before, ni_after = (result["states"][key]["ni"] for key in ("before", "after"))
    expected = dict(zip(LIFECYCLE, ("1", "1", "0", "1", "0")))
    result["physical_mac_cached"] = mib_observations(before, after, ni_before == expected and ni_after == expected)
    result["fabric_cached"] = tm_observations(before, after, ni_before == expected and ni_after == expected,
                                               mode == 'active_diagnostics')
    if ni_before != expected or ni_after != expected:
        result["qm_cpu"] = {"valid": False, "reason": "NI_lifecycle_not_stable_ready_at_endpoints"}
    elif any(faulty(snapshot.get("qm_voqs", [])) for snapshot in (before, after)):
        result["qm_cpu"] = {"valid": False, "reason": "QM_sample_incomplete"}
    else:
        qb, qa = (fields(snapshot.get("qm_voqs", [])) for snapshot in (before, after))
        result["qm_cpu"] = {key: delta(qb.get(key), qa.get(key), window) for key in
                            ("cpu_bytes", "cpu_packets", "ring_errors", "buffer_errors", "budget_hits")}

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
