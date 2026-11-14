#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Verify the *scope* of selected BPI SDK-report evidence, without running SDK code.

Inputs are external UTF-8 source files named by the accompanying manifest. This
program makes no network requests, builds no vendor objects and touches no device.
Its findings are source-provenance checks, not proof of ASIC behavior, an SDK
license grant, a complete SDK inventory, or a full-L2 implementation test.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


DEFAULT_MANIFEST = Path(__file__).with_name("rtl9617c-sdk-report-sources.json")
VLAN_STUBS = (
    "create", "destroy", "destroyAll", "portPvid_get", "portPvid_set",
    "port_get", "port_set", "vlanFunctionEnable_get", "fidMode_get", "fidMode_set",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_manifest(manifest):
    require(manifest.get("schema_version") == 1, "unknown manifest schema")
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
                         manifest.get("repository", "")), "invalid repository")
    require(re.fullmatch(r"[0-9a-f]{40}", manifest.get("commit", "")),
            "source reference must be an immutable SHA")
    seen = set()
    for row in manifest["files"]:
        name, path = row["cache_name"], row["path"]
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name),
                "unsafe cache filename")
        require(name not in seen, "duplicate cache filename")
        seen.add(name)
        require(not path.startswith("/") and all(part not in ("", ".", "..")
                    for part in path.split("/")) and
                re.fullmatch(r"[A-Za-z0-9_./-]+", path), "unsafe source path")
        require(isinstance(row["bytes"], int) and row["bytes"] > 0,
                "invalid source size")
        require(re.fullmatch(r"[0-9a-f]{64}", row["sha256"]), "invalid SHA256")
        require(re.fullmatch(r"[0-9a-f]{40}", row["git_blob_sha1"]), "invalid blob SHA")
    require(seen == {
        "target.Makefile", "image.Makefile", "registers.h", "rtl8277c_registers.h",
        "dal_rtl8277c_l2.c", "dal_rtl8277c_vlan.c", "FC.Makefile",
        "rtk_rg_ca8277_asicDriver.c", "rtk_8277c_asicDriver.c",
        "rtk_fc_driver.c", "rtk_fc_mgrTRx.c",
    }, "selected evidence set changed; review its interpretation before updating")


def verify_bytes(data, row):
    require(len(data) == row["bytes"], f"size mismatch: {row.get('cache_name', row['path'])}")
    require(hashlib.sha256(data).hexdigest() == row["sha256"],
            f"SHA256 mismatch: {row['path']}")
    # Git includes the object type and byte length in its blob identity.
    blob = b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    require(hashlib.sha1(blob).hexdigest() == row["git_blob_sha1"],
            f"Git blob mismatch: {row['path']}")
    return data.decode("utf-8")


def check_notice(text, row):
    notice = row["license_evidence"]
    proprietary = "proprietary software of Realtek Semiconductor" in text[:1800]
    if notice.startswith("proprietary-notice"):
        require(proprietary, f"proprietary notice changed: {row['cache_name']}")
        if notice == "proprietary-notice-plus-module-gpl":
            require('MODULE_LICENSE("GPL")' in text, "mixed vendor license evidence changed")
    elif notice == "generated-no-file-license":
        require("THIS FILE WAS AUTOMATICALLY GENERATED" in text[:500],
                "generated-header origin changed")
        require("SPDX-License-Identifier" not in text, "header now has an SPDX notice")
    elif notice == "copyright-only-no-file-license":
        require("Copyright (c) 2022 Realtek.com" in text[:500], "copyright notice changed")
        require("SPDX-License-Identifier" not in text, "file now has an SPDX notice")
    else:
        require(notice == "no-file-license-notice" and not proprietary and
                "SPDX-License-Identifier" not in text, "unexpected license evidence")


def without_comments(text):
    # Preserve strings/character literals when removing comments. This is source
    # inspection of pinned C, not a preprocessor or a generic C parser.
    token = r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    return re.sub(token, lambda match: " " if match[0].startswith(("/*", "//"))
                  else match[0], text, flags=re.S)


def balanced_end(text, start, opening, closing):
    require(text[start] == opening, "internal parser start error")
    depth = 0
    quoted = None
    escaped = False
    for pos in range(start, len(text)):
        char = text[pos]
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quoted:
                quoted = None
            continue
        if char in ("'", '"'):
            quoted = char
        elif char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if not depth:
                return pos
    raise ValueError("unterminated pinned source fragment")


def c_body(text, function):
    text = without_comments(text)
    match = re.search(r"(?m)^" + re.escape(function) + r"\s*\([^;{}]*\)\s*\{", text)
    require(match is not None, f"function definition missing: {function}")
    start = match.end() - 1
    return text[start + 1:balanced_end(text, start, "{", "}")]


def strip_validation(body):
    while True:
        match = re.search(r"\b(?:RT_DBG|RT_INIT_CHK|RT_PARAM_CHK)\s*\(", body)
        if match is None:
            break
        start = match.end() - 1
        end = balanced_end(body, start, "(", ")") + 1
        following = re.match(r"\s*;", body[end:])
        require(following is not None, "validation macro statement changed")
        body = body[:match.start()] + body[end + following.end():]
    return re.sub(r"\s+", "", body)


def check_vlan_stubs(vlan):
    for suffix in VLAN_STUBS:
        function = "dal_rtl8277c_vlan_" + suffix
        require(strip_validation(c_body(vlan, function)) == "returnRT_ERR_OK;",
                f"VLAN source scope changed: {function} is no longer a successful no-op")
    enable = c_body(vlan, "dal_rtl8277c_vlan_vlanFunctionEnable_set")
    require(strip_validation(enable) == "VLAN_FUNC_ENABLE=enable;returnRT_ERR_OK;",
            "VLAN enable setter is no longer software-state-only")


def check_target_selection(sources):
    makefile = sources["FC.Makefile"]
    require("FC_ASICDRVFOLDER = asicDrv" in makefile, "ASIC source directory changed")
    match = re.search(r"else ifeq \(\$\(CONFIG_FC_RTL8277C_SERIES\), y\)(.*?)"
                      r"else ifeq", makefile, flags=re.S)
    require(match is not None and "rtk_8277c_asicDriver.o" in match[1] and
            "rtk_rg_ca8277_asicDriver.o" not in match[1], "77C backend selection changed")
    require("CONFIG_CA8279_SERIES" in sources["rtk_rg_ca8277_asicDriver.c"] and
            "CONFIG_CA8277B_SERIES" in sources["rtk_rg_ca8277_asicDriver.c"],
            "report-linked G3/Venus source scope changed")
    require("SUBTARGETS:=rtl9617c rtl9607f rtl9607c" in sources["target.Makefile"],
            "target declaration changed")
    require(re.search(r"CONFIG_ARCH_REALTEK_TAURUS\).*?rtl8277c_registers.h",
                      sources["registers.h"], flags=re.S), "Taurus register mapping changed")
    require(re.search(r"ifdef CONFIG_ARCH_REALTEK_TAURUS\s+DTS_PREFIX := rtl8277C\s+"
                      r"DTS_COMP_NAME := realtek,taurus", sources["image.Makefile"]),
            "Taurus DTS mapping changed")


def expect_rejected(call, name):
    try:
        call()
    except ValueError:
        return
    raise ValueError(f"provenance checker accepted negative control: {name}")


def negative_controls(sources, raw, manifest):
    # These mutants check the evidence checker, NOT the vendor driver or ASIC.
    row = manifest["files"][0]
    data = raw[row["cache_name"]]
    expect_rejected(lambda: verify_bytes(data + b"\n", row), "changed size")
    expect_rejected(lambda: verify_bytes(bytes([data[0] ^ 1]) + data[1:], row), "changed byte")
    vlan = sources["dal_rtl8277c_vlan.c"]
    needle = c_body(vlan, "dal_rtl8277c_vlan_portPvid_get")
    # Locate by function, so a different earlier return cannot hide a bad test.
    start = vlan.index("dal_rtl8277c_vlan_portPvid_get(rtk_port_t")
    prefix, suffix = vlan[:start], vlan[start:]
    require("return RT_ERR_OK;" in needle, "negative control target changed")
    changed = prefix + suffix.replace("return RT_ERR_OK;",
                                      "*pPvid = 42; return RT_ERR_OK;", 1)
    expect_rejected(lambda: check_vlan_stubs(changed), "output-writing VLAN getter")
    changed = prefix + suffix.replace("return RT_ERR_OK;",
                                      "aal_vlan_write(); return RT_ERR_OK;", 1)
    expect_rejected(lambda: check_vlan_stubs(changed), "hardware-calling VLAN getter")
    altered = dict(sources)
    altered["FC.Makefile"] = sources["FC.Makefile"].replace(
        "/rtk_8277c_asicDriver.o", "/rtk_rg_ca8277_asicDriver.o")
    expect_rejected(lambda: check_target_selection(altered), "wrong-chip backend")
    return 5


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--source-root", type=Path, help="external flat BPI input cache")
    parser.add_argument("--gpl-registers", type=Path, help="independently obtained pinned GP3000 header")
    parser.add_argument("--list", action="store_true", help="print cache name and pinned URL as TSV")
    parser.add_argument("--json", action="store_true", help="emit provenance results as JSON")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    validate_manifest(manifest)
    if args.list:
        base = f"https://raw.githubusercontent.com/{manifest['repository']}/{manifest['commit']}/"
        for row in manifest["files"]:
            print(f"{row['cache_name']}\t{base}{row['path']}")
        return
    require(args.source_root is not None and args.gpl_registers is not None,
            "--source-root and --gpl-registers are required unless --list is used")
    raw, sources = {}, {}
    for row in manifest["files"]:
        name = row["cache_name"]
        raw[name] = (args.source_root / name).read_bytes()
        sources[name] = verify_bytes(raw[name], row)
        check_notice(sources[name], row)
    comparison = args.gpl_registers.read_bytes()
    verify_bytes(comparison, manifest["comparison"])
    require(raw["rtl8277c_registers.h"] == comparison,
            "BPI/GP3000 register headers are no longer byte-identical")
    check_vlan_stubs(sources["dal_rtl8277c_vlan.c"])
    check_target_selection(sources)
    mutants = negative_controls(sources, raw, manifest)
    result = {
        "kind": "source-provenance-not-silicon-test", "repository": manifest["repository"],
        "commit": manifest["commit"], "verified_files": len(raw),
        "verified_bytes": sum(map(len, raw.values())),
        "register_header_relation": "byte-identical-to-pinned-GP3000",
        "vlan_successful_noop_entrypoints": list(VLAN_STUBS),
        "vlan_enable_setter": "software-state-only",
        "rtl8277c_backend": "core/asicDrv/rtk_8277c_asicDriver.c",
        "wrong_chip_report_reference": "core/asicDriver/rtk_rg_ca8277_asicDriver.c",
        "negative_controls_rejected": mutants,
        "hardware_validated": False, "license_grant_determined": False,
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"PASS: {len(raw)} pinned BPI files ({result['verified_bytes']} bytes), "
              "SHA256 + Git blob + notice evidence")
        print(f"PASS: identical register header, {len(VLAN_STUBS)} successful VLAN no-ops, "
              f"77C/G3 source separation, {mutants} rejected evidence-checker mutants")
        print("NOT a hardware-path, license-grant, complete-SDK, or full-L2 validation.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
