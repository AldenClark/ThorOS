#!/usr/bin/env python3
"""Execute the production exact-MDB CLS/MCE transaction owner under ASan/UBSan.

Optional --sdk takes the pinned ca-network-drivers checkout (or its aal-77c
directory), compiles the real GPL packed FULL_KEY and mode0 structures and
checks every byte. This is an ABI and transactional oracle, NOT an ASIC packet
forwarding, classifier-priority, multicast lease, or physical retirement proof.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"
HEADER = DRIVER / "rtl9617c-mdb-offload.h"
FIXTURE = ROOT / "scripts/fixtures/mdb_offload_cases.c"
SDK_HASH = "dfc3c36383187301c5df340dec8e609e860fbad5b42e191b6aba16fe6d253fc0"


def sdk_structs(path):
    choices = [path / "include/aal_l3_cls.h",
               path / "aal-77c/include/aal_l3_cls.h",
               path / "ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c/include/aal_l3_cls.h"]
    source = next((p for p in choices if p.is_file()), None)
    if source is None:
        raise SystemExit("--sdk must contain the pinned aal-77c/include/aal_l3_cls.h")
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != SDK_HASH:
        raise SystemExit("pinned aal_l3_cls.h content hash mismatch")
    text = data.decode()
    chunks = ["#define MDB_HAVE_SDK 1\ntypedef unsigned int ca_uint32_t;\n"]
    for name in ("cl_full_key", "cls_fib_mod_0"):
        pattern = r"typedef struct " + name + r"_s\s*\{.*?\}\s*__attribute__\(\(packed\)\)\s*" + name + r"_t;"
        match = re.search(pattern, text, re.S)
        if match is None:
            raise SystemExit("pinned SDK packed structure missing: " + name)
        chunks.append(match.group())
    return "\n".join(chunks)


def run(build, header, sdk, label):
    (build / "rtl9617c-mdb-offload.h").write_text(header)
    (build / "mdb_sdk.h").write_text(sdk)
    executable = build / label
    command = [os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra",
               "-Werror", "-g", "-O1", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
               "-fsanitize=address,undefined", "-I", str(build), "-I", str(DRIVER),
               str(FIXTURE), "-o", str(executable)]
    subprocess.run(command, check=True)
    environment = dict(os.environ)
    # The fixture is static storage only; LeakSanitizer cannot run in the
    # ptrace-backed tool host. Address/undefined behaviour checks stay on.
    environment["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1"
    return subprocess.run([str(executable)], text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=environment)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path)
    parser.add_argument("--mutants", action="store_true")
    args = parser.parse_args()
    native = HEADER.read_text()
    sdk = sdk_structs(args.sdk) if args.sdk else "/* optional external SDK parity disabled */\n"
    mutants = {
        "ipv6-word-order": ("rule->ipv6 ? 3 - i : i", "i"),
        "wildcard-destination": ("rtl_fe_bits_set(k, 61, 9, prefix)",
                                 "rtl_fe_bits_set(k, 61, 9, 0)"),
        "accept-tagged": ("if (rule->vid || (rule->protocol != 6 && rule->protocol != 17))",
                          "if ((rule->protocol != 6 && rule->protocol != 17))"),
        "wrong-fib-row": ("return (slot << 3) | 4U;", "return (slot << 3);"),
        "no-mce-pin": ("ret = dependency->publish(dependency->context, rule->group);", "ret = 0;"),
        "reuse-published": ("if (tcam->exposed || tcam->active || tcam->guard_exposed)", "if (tcam->active)"),
        "accept-overlap": ("return -EEXIST;", "return 0;"),
        "clear-foreign": ("if (!rtl_mdb_words_equal(words, saved, 11) &&",
                          "if (0 && !rtl_mdb_words_equal(words, saved, 11) &&"),
        "forget-exposure": ("tcam->exposed = 1;", "tcam->exposed = 0;"),
        "guard-unicast-hash-escape": ("rtl_fe_bits_set(key, 60, 1, 0);", "rtl_fe_bits_set(key, 60, 1, 1);"),
        "guard-broadcast-hole": ("rtl_fe_bits_set(key, 522, 1, !!which);", "rtl_fe_bits_set(key, 522, 1, 0);"),
        "guard-source-limited": ("rtl_fe_bits_set(key, 335, 17, 0);", "rtl_fe_bits_set(key, 621, 1, 0);\n\trtl_fe_bits_set(key, 335, 17, 0);"),
        "guard-forget-lifetime": ("guard->exposed = tcam->guard_exposed = 1;", "guard->exposed = 1;"),
    }
    with tempfile.TemporaryDirectory(prefix="thoros-mdb-offload-") as directory:
        build = Path(directory)
        result = run(build, native, sdk, "native")
        if result.returncode:
            print(result.stdout, end="")
            print(result.stderr, end="")
            raise SystemExit(result.returncode)
        print(result.stdout, end="")
        if args.mutants:
            for name, (before, after) in mutants.items():
                if before not in native:
                    raise SystemExit("mutant anchor drift: " + name)
                mutated = native.replace(before, after, 1)
                result = run(build, mutated, sdk, name)
                if result.returncode == 0:
                    raise SystemExit("negative control survived: " + name)
                if "Assertion" not in result.stderr and "runtime error" not in result.stderr:
                    print(result.stderr, end="")
                    raise SystemExit("negative control did not fail a semantic oracle: " + name)
                print("MDB negative control rejected:", name)


if __name__ == "__main__":
    main()
