#!/usr/bin/env python3
"""Run actual FE snapshot-to-CLS-to-MCE publication and rollback bodies.

The host supplies kernel objects/snapshot records and register transport only.
The real FE wrapper, classifier transaction, multicast builder and shared L2
resource owner execute together under ASan/UBSan. A synthetic already-owned
cold MCE is an explicit fixture precondition, NOT proof of ASIC boot/drain.
"""
import argparse
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18"
DRIVER = FILES / "drivers/net/ethernet/realtek"
HEADER = DRIVER / "rtl9617c-fe-mdb.h"


def function(source, name):
    match = re.search(r"^static\s+(?:(?:inline|__maybe_unused)\s+)?(?:unsigned int|int|bool|void|enum fe_switch_reason)\s+"
                      + re.escape(name) + r"\s*\(", source, re.M)
    if match is None:
        raise AssertionError("production function missing: " + name)
    start = source.index("{", match.start())
    end, depth = start + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def helpers():
    fe = (DRIVER / "rtl9617c-fe.c").read_text()
    switch = (DRIVER / "rtl9617c-fe-switch.h").read_text()
    hardware = (DRIVER / "rtl9617c-fe-switch-hw.h").read_text()
    mcast = (DRIVER / "rtl9617c-fe-mcast.h").read_text()
    policy_start = switch.index("enum fe_switch_reason {")
    policy_end = switch.index("/* A pure capability check", policy_start)
    result = switch[policy_start:policy_end]
    for source, name in ((fe, "fe_classifier_default_index"),
                         (switch, "fe_switch_route_plan_validate"),
                         (hardware, "fe_switch_hw_rx_check"),
                         (hardware, "fe_switch_hw_route_closed"),
                         (mcast, "fe_mcast_group"),
                         (mcast, "fe_mcast_publish")):
        result += function(source, name)
    return result


def setup(build):
    (build / "linux").mkdir()
    api = (FILES / "include/linux/rtl9617c-mdb.h").read_text()
    # Keep the real ABI and configuration-dependent prototype, not a local
    # handwritten snapshot or record-layout imitation.
    api = re.sub(r"^#include[^\n]*\n", "", api, flags=re.M)
    (build / "linux/rtl9617c-mdb.h").write_text(api)
    (build / "linux/vmalloc.h").write_text("/* allocation shim in fixture */\n")
    (build / "fe_mdb_host_helpers.h").write_text(helpers())


def run(build, source, label, ipv6=1):
    (build / "rtl9617c-fe-mdb.h").write_text(source)
    executable = build / label
    command = [os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g",
               "-Wall", "-Wextra", "-Werror", "-fno-omit-frame-pointer",
               "-fno-pie", "-no-pie", "-fsanitize=address,undefined",
               "-DCONFIG_IPV6=" + str(ipv6), "-I", str(build), "-I", str(DRIVER),
               str(ROOT / "scripts/fixtures/fe_mdb_cases.c"), "-o", str(executable)]
    subprocess.run(command, check=True)
    environment = dict(os.environ)
    environment["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1"
    return subprocess.run([str(executable)], text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=environment)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mutants", action="store_true")
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    source = HEADER.read_text()
    mutants = {
        "skip-cold-owner": ("if (!fe->mcast || !fe->mcast->state.contract_ready ||",
                            "if (!fe->mcast ||"),
        "ignore-native-profile": ("if (!fe->native_mdb_profile || !fe->enabled || !fe->prepared ||",
                                   "if (!fe->enabled || !fe->prepared ||"),
        "skip-own-querier": ("!family->own_querier ||", ""),
        "skip-querier-deadline": ("family->querier_time_dependent ||", ""),
        "ignore-asm-ssm-overlap": ("if (rtl_mdb_rules_overlap(&plan->entries[j].key, &key))",
                                    "if (0 && rtl_mdb_rules_overlap(&plan->entries[j].key, &key))"),
        "omit-router-override": ("(entry->egress | plan->router[entry->key.ipv6])", "entry->egress"),
        "skip-static-member-check": ("!record->port.permanent ||", ""),
        "skip-source-stability": ("!record->source.user_added ||", ""),
        "discard-withdrawn-owner": (
            "fe->mdb->tcam.exposed || fe->mdb->tcam.prepared ||\n\t\tfe->mdb->tcam.poisoned || fe->mdb->tcam.active ||\n\t\tfe->mdb->tcam.guard_exposed ||",
            "fe->mdb->tcam.poisoned || fe->mdb->tcam.active ||"),
        "no-prefix-withdraw": ("undo = fe_mdb_withdraw(fe);", "undo = 0;"),
        "drop-window-lease": ("fe->mdb->window_retained = true;", "fe->mdb->window_retained = false;"),
        "publish-new-policy-without-drain": ("if (mdb->tcam.exposed && mdb->generation != generation)",
                                              "if (0 && mdb->tcam.exposed && mdb->generation != generation)"),
        "publish-stale-epoch": ("ret = fe_mdb_epoch(guard, generation);\n\tif (ret)\n\t\tgoto rollback;",
                                 "ret = 0;\n\tif (ret)\n\t\tgoto rollback;"),
        "trust-old-guard-ready": ("ret = rtl_mdb_profile_check(&io, &fe->mdb->tcam);\n\tif (ret)\n\t\treturn ret;",
                                   "ret = 0;\n\tif (ret)\n\t\treturn ret;"),
    }
    with tempfile.TemporaryDirectory(prefix="thoros-fe-mdb-") as directory:
        build = Path(directory)
        setup(build)
        for ipv6 in (1, 0):
            result = run(build, source, "native-ipv6-" + str(ipv6), ipv6)
            if result.returncode:
                print(result.stdout, end="")
                print(result.stderr, end="")
                raise SystemExit(result.returncode)
            print(result.stdout, end="")
        if args.mutants:
            for name, (before, after) in mutants.items():
                if source.count(before) != 1:
                    raise SystemExit("mutant anchor drift/ambiguity: " + name)
                result = run(build, source.replace(before, after, 1), name)
                if result.returncode == 0:
                    raise SystemExit("negative control survived: " + name)
                if "Assertion" not in result.stderr and "runtime error" not in result.stderr:
                    print(result.stderr, end="")
                    raise SystemExit("negative control did not fail semantics: " + name)
                print("FE MDB negative control rejected:", name)


if __name__ == "__main__":
    main()
