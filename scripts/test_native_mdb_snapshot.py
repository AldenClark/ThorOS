#!/usr/bin/env python3
"""Execute the exact MDB API, guard epochs and representative bridge writers.

--kernel is mandatory: the new production file/header must match the overlay,
and writer bodies come from the fully applied kernel, not guessed patch text.
The C substrate provides locks, lists, devices and timers; it does not replace
MDB snapshot/filter decisions. Real guard begin/end and real host join/leave,
MDB add/delete wrappers, group expiry and family delay callbacks are executed.
Other report/router/source/EHT/config entries receive a source-scope audit.

The controlled pthread schedule proves stale-copy rejection against a writer
waiting for multicast_lock and a completed timer event. It does not prove LKMM,
hardware timer expiry, packet replication, or the entire IGMP state machine.
"""

import argparse
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18"
FIXTURES = ROOT / "scripts/fixtures"


def balanced(text, start):
    masked = re.sub(r"/\*.*?\*/|//[^\n]*|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'",
                    lambda match: " " * len(match.group()), text, flags=re.S)
    brace = masked.index("{", start)
    depth = 0
    for index in range(brace, len(masked)):
        depth += (masked[index] == "{") - (masked[index] == "}")
        if not depth:
            return index + 1
    raise AssertionError("unterminated C body")


def function(text, name):
    pattern = (r"(?m)^(?:(?:static|inline)\s+)*(?:void|bool|int|u64|struct\s+net\s*\*)"
               r"\s*" + re.escape(name) + r"\s*\(")
    for match in re.finditer(pattern, text):
        opening = text.find("{", match.end())
        semicolon = text.find(";", match.end())
        if semicolon >= 0 and semicolon < opening:
            continue
        return text[match.start():balanced(text, match.start())] + "\n"
    raise AssertionError(f"missing actual production function: {name}")


def structure(text, name):
    match = re.search(r"(?m)^struct\s+" + re.escape(name) + r"\s*\{", text)
    assert match, name
    return text[match.start():balanced(text, match.start())] + ";\n"


def without_includes(text):
    return re.sub(r"(?m)^#include[^\n]*\n", "", text)


SCOPES = {
    "br_multicast.c": (
        "br_multicast_group_expired", "br_multicast_port_group_expired",
        "br_multicast_group_src_expired", "br_multicast_router_expired",
        "br_multicast_local_router_expired", "br_multicast_querier_expired",
        "br_ip4_multicast_query_delay_expired", "br_ip6_multicast_query_delay_expired",
        "br_multicast_set_has_ipv6_addr", "br_multicast_update_querier",
        "br_multicast_select_own_querier", "br_multicast_port_ctx_deinit",
        "br_multicast_del_port", "br_multicast_enable_port_ctx",
        "br_multicast_disable_port_ctx", "br_multicast_pim",
        "br_ip4_multicast_mrd_rcv", "br_ip6_multicast_mrd_rcv",
        "br_multicast_ipv4_rcv", "br_multicast_ipv6_rcv",
        "br_multicast_ctx_deinit", "br_multicast_open", "br_multicast_stop",
        "br_multicast_toggle_one_vlan", "br_multicast_toggle_vlan_snooping",
        "br_multicast_toggle_global_vlan", "br_multicast_dev_del",
        "br_multicast_set_router", "br_multicast_set_port_router",
        "br_multicast_toggle", "br_multicast_set_querier",
        "br_multicast_set_igmp_version", "br_multicast_set_mld_version",
    ),
    "br_mdb.c": ("__br_mdb_add", "__br_mdb_del", "br_mdb_flush"),
    "br_multicast_eht.c": ("br_multicast_eht_set_entry_expired", "br_multicast_eht_set_expired"),
}


def check_scopes(kernel):
    checked = 0
    for filename, names in SCOPES.items():
        text = (kernel / "net/bridge" / filename).read_text()
        for name in names:
            body = function(text, name)
            fence = body.find("CLASS(rtl9617c_switch_policy, policy)")
            assert fence >= 0, f"missing pre-change fence: {name}"
            lock = body.find("spin_lock")
            if lock >= 0:
                assert fence < lock, f"scope starts after first lock: {name}"
            if name in ("br_multicast_ipv4_rcv", "br_multicast_ipv6_rcv"):
                assert body.find("return 0;") < fence < body.find("switch ("), name
                assert "? brmctx->br->dev : NULL" in body, f"unknown-type no-op lost: {name}"
            checked += 1
    multicast = (kernel / "net/bridge/br_multicast.c").read_text()
    for family in ("ip4", "ip6"):
        assert re.search(r"timer_setup\(&brmctx->" + family +
                         r"_other_query\.delay_timer,\s*br_" + family +
                         r"_multicast_query_delay_expired", multicast)
    for filename, names in {
        "br_multicast.c": ("br_multicast_gc_work", "br_multicast_router",
                           "br_multicast_port_query_expired", "br_multicast_port_group_rexmit",
                           "br_multicast_query_expired"),
        "br_mdb.c": ("br_mdb_get", "br_mdb_notify"),
    }.items():
        text = (kernel / "net/bridge" / filename).read_text()
        for name in names:
            assert "CLASS(rtl9617c_switch_policy" not in function(text, name), name
    private = (kernel / "net/bridge/br_private.h").read_text()
    assert "CLASS(rtl9617c_switch_policy" not in function(private, "br_multicast_set_pg_offload_flags")
    assert "br_rtl9617c_mdb.o" in (kernel / "net/bridge/Makefile").read_text()
    assert "br_multicast_set_has_ipv6_addr(brmctx->br, false);" in multicast
    assert "br_multicast_set_has_ipv6_addr(brmctx->br, true);" in multicast
    return checked


def generate(kernel):
    public = (kernel / "include/linux/if_bridge.h").read_text()
    private = (kernel / "net/bridge/br_private.h").read_text()
    guard_header = (kernel / "include/linux/rtl9617c-switch.h").read_text()
    guard_code = (kernel / "net/core/rtl9617c-switch.c").read_text()
    multicast = (kernel / "net/bridge/br_multicast.c").read_text()
    mdb = (kernel / "net/bridge/br_mdb.c").read_text()
    header = (kernel / "include/linux/rtl9617c-mdb.h").read_text()
    implementation = (kernel / "net/bridge/br_rtl9617c_mdb.c").read_text()
    assert header == (OVERLAY / "include/linux/rtl9617c-mdb.h").read_text(), "kernel MDB header differs from overlay"
    assert implementation == (OVERLAY / "net/bridge/br_rtl9617c_mdb.c").read_text(), "kernel MDB implementation differs from overlay"
    shim = (FIXTURES / "native_mdb_snapshot_shim.h").read_text()
    constants = "\n".join(line for line in public.splitlines() if re.match(r"#define BR_[A-Z_]+\s+BIT\(", line))
    constants += "\n" + "\n".join(line for line in private.splitlines()
                                    if re.match(r"#define (MDB_PG_FLAGS_|BR_SGRP_F_)", line)) + "\n"
    shim = shim.replace("struct net_bridge;", constants + structure(public, "br_ip") + "\nstruct net_bridge;", 1)
    shim = shim.replace("struct net { struct rtl9617c_switch_net PLACEHOLDER; };",
                        structure(guard_header, "rtl9617c_switch_net") +
                        "struct net { struct rtl9617c_switch_net rtl9617c_switch; };")
    guard_functions = ("rtl9617c_switch_net_blocked", "rtl9617c_switch_advance",
                       "rtl9617c_switch_guard_generation", "rtl9617c_switch_guard_blocked",
                       "rtl9617c_switch_policy_begin", "rtl9617c_switch_policy_end")
    shim = shim.replace("/* PRODUCTION_GUARD is inserted here. */",
                        "\n".join(function(guard_code, name) for name in guard_functions))
    helpers = ("br_group_is_l2", "br_multicast_is_star_g", "br_multicast_should_handle_mode",
               "br_multicast_ctx_is_vlan", "br_multicast_ctx_vlan_global_disabled",
               "br_multicast_ctx_vlan_disabled", "br_ip4_multicast_is_router",
               "br_ip6_multicast_is_router", "br_multicast_is_router", "__br_multicast_querier_exists")
    support = "\n".join(function(private, name) for name in helpers)
    host = "\n".join(function(multicast, name) for name in ("br_multicast_host_join", "br_multicast_host_leave"))
    host += function(multicast, "br_multicast_update_querier")
    host += function(multicast, "br_multicast_select_own_querier")
    host += "\n#if CONFIG_IPV6\n" + function(multicast, "br_multicast_set_has_ipv6_addr") + "#endif\n"
    cases = (FIXTURES / "native_mdb_snapshot_cases.c").read_text()
    writers = function(mdb, "__br_mdb_add") + function(mdb, "__br_mdb_del")
    writers += function(multicast, "br_multicast_group_expired")
    writers += function(multicast, "br_ip4_multicast_query_delay_expired")
    writers += "\n#if CONFIG_IPV6\n" + function(multicast, "br_ip6_multicast_query_delay_expired") + "#endif\n"
    cases = cases.replace("/* PRODUCTION_WRITERS are inserted here. */", writers)
    return shim + support + without_includes(header), without_includes(implementation), host + cases


MUTANTS = {
    "missing_final_epoch_check": ("rtl9617c_switch_guard_generation(guard) != generation", "false"),
    "unbounded_walk": ("if (!walk->remaining)", "if (false)"),
    "blocked_port_forwarded": ("if (pg->flags & MDB_PG_FLAGS_BLOCKED)", "if (false)"),
    "wildcard_include_forwarded": ("pg->filter_mode == MCAST_INCLUDE", "false"),
    "unicast_precedence_lost": ("if (READ_ONCE(pg->key.port->flags) & BR_MULTICAST_TO_UNICAST)", "if (false)"),
    "host_membership_lost": ("record.entry.host_joined = mp->host_joined;", "record.entry.host_joined = false;"),
    "source_address_lost": ("source.source.addr = src->addr;", "memset(&source.source.addr, 0, sizeof(source.source.addr));"),
    "expired_copy_authorized": ("copy.has_deadline && time_after_eq(jiffies, copy.earliest_deadline)", "false"),
    "router_families_merged": (".router = { .proto = proto,", ".router = { .proto = htons(ETH_P_IP),"),
    "callback_errors_ignored": ("return err < 0 ? err : -EINVAL;", "return 0;"),
    "vlan_domains_merged": ("if (mp->addr.vid != walk->snapshot->vid)", "if (false)"),
    "failed_header_kept": ("memset(snapshot, 0, sizeof(*snapshot));", "/* stale header kept */"),
    "source_group_collapsed": ("record.key = mp->addr;", "record.key = mp->addr; memset(&record.key.src, 0, sizeof(record.key.src));"),
    "querier_time_dependency_lost": (
        "out->querier_time_dependent = out->query_delay.pending ||\n\t\t(!out->own_querier && out->other_query.pending);",
        "out->querier_time_dependent = false;"),
}


def run_case(directory, source, name, ipv6, expect_success, guard_enabled=1):
    cfile = directory / f"{name}-{ipv6}.c"
    binary = directory / f"{name}-{ipv6}"
    cfile.write_text(source)
    command = [os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra",
               "-Werror", "-Wno-unused-function", "-Wno-unused-parameter", "-pthread",
               "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
               f"-DCONFIG_IPV6={ipv6}", f"-DCONFIG_RTL9617C_SWITCH_GUARD={guard_enabled}",
               str(cfile), "-o", str(binary)]
    if not guard_enabled:
        command.insert(1, "-Wno-unused-variable")
    subprocess.run(command, check=True)
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=1")
    result = subprocess.run([str(binary)], text=True, capture_output=True, env=env, timeout=30)
    if expect_success:
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        print(result.stdout.strip(), flush=True)
    else:
        assert result.returncode, f"surviving mutant: {name}"
        print(f"rejected mutant: {name}", flush=True)
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--mutants", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    scope_count = check_scopes(args.kernel)
    prefix, implementation, suffix = generate(args.kernel)
    results = []
    with tempfile.TemporaryDirectory(prefix="native-mdb-snapshot-") as temporary:
        directory = Path(temporary)
        for ipv6 in (0, 1):
            results.append(run_case(directory, prefix + implementation + suffix, "production", ipv6, True))
        disabled = r'''
int main(void) {
 struct br_rtl9617c_mdb_snapshot output;
 const struct br_rtl9617c_mdb_snapshot zero={};
 memset(&output,0xa5,sizeof(output));
 assert(br_rtl9617c_mdb_snapshot(NULL,0,NULL,0,&output,NULL,NULL)==-EOPNOTSUPP);
 assert(!memcmp(&output,&zero,sizeof(output)));
 puts("native MDB disabled-config stub: PASS"); return 0;
}
'''
        results.append(run_case(directory, prefix + disabled, "disabled", 0, True, guard_enabled=0))
        if args.mutants:
            for name, (old, new) in MUTANTS.items():
                assert implementation.count(old) == 1, (name, implementation.count(old))
                run_case(directory, prefix + implementation.replace(old, new) + suffix, name, 1, False)
            for name in ("__br_mdb_add", "__br_mdb_del", "br_multicast_group_expired",
                         "br_ip4_multicast_query_delay_expired", "br_multicast_update_querier",
                         "br_multicast_select_own_querier", "br_multicast_set_has_ipv6_addr"):
                body = function(suffix, name)
                changed, count = re.subn(r"\tCLASS\(rtl9617c_switch_policy, policy\)\([^\n]*\);\n", "", body)
                assert count == 1, name
                run_case(directory, prefix + implementation + suffix.replace(body, changed),
                         "unfenced_" + name, 1, False)
            body = function(suffix, "br_multicast_update_querier")
            changed = body.replace("\tCLASS(rtl9617c_switch_policy, policy)(brmctx->br->dev);\n", "")
            changed = changed.replace("\n{\n", "\n{\n\tCLASS(rtl9617c_switch_policy, policy)(brmctx->br->dev);\n", 1)
            run_case(directory, prefix + implementation + suffix.replace(body, changed),
                     "unchanged_query_burns_epoch", 1, False)
    report = {"status": "PASS", "source": "actual applied Linux bridge/API/guard functions",
              "production_results": results, "writer_scopes_checked": scope_count,
              "mutants_rejected": len(MUTANTS) + 8 if args.mutants else 0,
              "limits": ["host substrate is not LKMM", "no hardware timer-expiry proof",
                         "no packet replication or full IGMP state-machine claim"]}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    main()
