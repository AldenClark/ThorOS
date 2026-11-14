#!/usr/bin/env python3
"""Verify retained FE-base readback masks using the pinned RTL77C SDK types.

The mask under test is extracted from production fe.c. The independent oracle
sets actual SDK bitfields, including the format selector in the second default
FIB row. It does not duplicate production offsets or assume that every bit of
the generated 32-bit SRAM DATA register is a defined semantic field.

This checks source contracts only, not ASIC readback, DMA drain or throughput.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"
PIN = "8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0"
GPL_PIN = "5090fbcb6ba743dd7b1314811ef557bad0460147"
INPUTS = {
    "include/aal_l3_cls.h": "dfc3c36383187301c5df340dec8e609e860fbad5b42e191b6aba16fe6d253fc0",
    "include/aal_l3fe.h": "8338ff3845608c7740b1acf3ec258bf4c927187135e5a0f1f616c5c6fc3f1fd5",
}
REG_SHA = "ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0"


def verified(path, digest):
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest, f"SDK SHA256 mismatch: {path}"
    return data.decode()


def declaration(source, start, end):
    begin = source.index(start)
    return source[begin:source.index(end, begin) + len(end)]


def call_arguments(source, prefix):
    """Return actual production call arguments, preserving nested BIT()."""
    begin = source.index(prefix)
    begin = source.index("(", begin) + 1
    arguments, current, depth = [], "", 0
    for char in source[begin:]:
        if char == ")" and not depth:
            return arguments + [current.strip()]
        if char == "," and not depth:
            arguments.append(current.strip())
            current = ""
            continue
        current += char
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
    raise AssertionError(f"unterminated production call: {prefix}")


def make_source(sdk, registers, native):
    cls = declaration(sdk["include/aal_l3_cls.h"], "typedef struct cls_fib_mod_0_s {",
                      "} __attribute__((packed)) cls_fib_mod_0_t;")
    table = declaration(sdk["include/aal_l3_cls.h"], "typedef struct l3_cls_fib_tbl_entry_s {",
                        "} __attribute__((packed)) l3_cls_fib_tbl_entry_t;")
    mask = declaration(native, "static const unsigned int fe_cls_mode0_mask[2][7]", "\n};")
    code = "#include <assert.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n"
    code += '#include "rtl9617c-fe-pipeline.h"\n#define BIT(n) (1U<<(n))\n'
    code += "typedef uint32_t ca_uint32_t;\ntypedef uint32_t ca_uint32;\n"
    code += cls + "\n" + table + "\n" + mask + "\n"
    for name in ("L3FE_STG0_CTRL", "L3FE_STG0_LDPID_MAP"):
        code += declaration(registers, "#define " + name + " ", "#endif /* !__ASSEMBLER__ */") + "\n"
    for name in ("LOW", "MID", "HI"):
        ending = "} L3FE_STG0_LPB_TBL_" + name + "_t;"
        end = sdk["include/aal_l3fe.h"].index(ending) + len(ending)
        start = sdk["include/aal_l3fe.h"].rfind("typedef volatile union {", 0, end)
        code += sdk["include/aal_l3fe.h"][start:end] + "\n"
    for name, prefix in (("stg0", "fe_base_match(fe,0x3400,"),
                         ("map", "fe_base_match(fe,0x3404,")):
        args = call_arguments(native, prefix)
        assert len(args) == 4
        code += f"static const unsigned int native_{name}_mask={args[2]};\n"
        code += f"static const unsigned int native_{name}_expected={args[3]};\n"
    args = call_arguments(native, "fe_base_match(fe,0x3414+i*12+word*4,")
    code += f"static unsigned int native_lpb_mask(unsigned int word) {{return {args[2]};}}\n"
    code += "static void check_cls(void) {\n"
    code += "union {cls_fib_mod_0_t fields;l3_cls_fib_tbl_entry_t table;unsigned int words[7];} first={0};\n"
    code += "union {l3_cls_fib_tbl_entry_t table;unsigned int words[7];} second={0};\n"
    fields = re.findall(r"ca_uint32_t\s+(\w+)\s*:\s*(\d+)\s*;", cls)
    assert fields and sum(int(width) for _, width in fields) == 215
    for name, width in fields:
        if "rsv" not in name and "reserved" not in name:
            code += f"first.fields.{name}=(1U<<{width})-1U;\n"
    # Format bits are defined in both physical rows. The actual SDK mode0
    # payload occupies only the first row; standard defaults read the format
    # selector from row1 (aal_l3_cls.c:4896-4918).
    code += "first.table.fib_format_sel=7;second.table.fib_format_sel=7;\n"
    code += "assert(!memcmp(first.words,fe_cls_mode0_mask[0],sizeof(first.words)));\n"
    code += "assert(!memcmp(second.words,fe_cls_mode0_mask[1],sizeof(second.words)));\n}\n"
    return code + TESTS


TESTS = r'''
static void check_stg0(void)
{
 L3FE_STG0_CTRL_t mask={.wrd=0},expected={.wrd=0};
 mask.bf.lpb_idx_mode=1;
 mask.bf.mru_chk_fail_pkt_l2_lkup_dis=1;
 mask.bf.other_mac_pkt_keep_lspid_en=1;
 mask.bf.use_lspid_ovwr_o_lspid=1;
 mask.bf.keep_lspid_unchange=1;
 expected.bf.mru_chk_fail_pkt_l2_lkup_dis=1;
 expected.bf.other_mac_pkt_keep_lspid_en=1;
 expected.bf.keep_lspid_unchange=1;
 assert(mask.wrd==native_stg0_mask && expected.wrd==native_stg0_expected);
 /* We do not assume that unowned my_mac_fail_pkt_bypass_cls is zero. */
 expected.bf.my_mac_fail_pkt_bypass_cls=1;
 assert((expected.wrd&native_stg0_mask)==native_stg0_expected);
 L3FE_STG0_LDPID_MAP_t mapping={.wrd=0},defined={.wrd=0};
 defined.bf.rule_0=63;defined.bf.lpb_idx_0=3;
 defined.bf.rule_1=63;defined.bf.lpb_idx_1=3;
 defined.bf.rule_2=63;defined.bf.lpb_idx_2=3;defined.bf.lpb_idx_3=3;
 mapping.bf.rule_0=7;mapping.bf.lpb_idx_0=0;
 mapping.bf.rule_1=25;mapping.bf.lpb_idx_1=1;
 mapping.bf.rule_2=24;mapping.bf.lpb_idx_2=2;mapping.bf.lpb_idx_3=3;
 assert(defined.wrd==native_map_mask && mapping.wrd==native_map_expected);
 mapping.bf.rsrvd1=63;
 assert((mapping.wrd&native_map_mask)==native_map_expected);
}
static void check_lpb(void)
{
 L3FE_STG0_LPB_TBL_HI_t hi={.wrd=~0U};
 hi.bf.reserved=0;
 assert(native_lpb_mask(0)==~0U && native_lpb_mask(1)==~0U);
 assert(native_lpb_mask(2)==hi.wrd);
 for(unsigned int direction=0;direction<2;direction++) {
  unsigned int words[3];
  rtl_fe_ingress_lpb(words,direction?7:0,16);
  L3FE_STG0_LPB_TBL_LOW_t lo={.wrd=words[0]};
  L3FE_STG0_LPB_TBL_MID_t mid={.wrd=words[1]};
  hi.wrd=words[2];
  assert((lo.bf.mru_len|(mid.bf.mru_len<<8))==1700);
  assert(mid.bf.t5_ctrl==15 && mid.bf.t1_ctrl==0);
  assert(hi.bf.default_ldpid==16 && hi.bf.lspid==(direction?7U:0U));
  assert(!hi.bf.mac_da_match_en && !hi.bf.special_en);
  rtl_fe_bits_set(words,42,4,1);
  mid.wrd=words[1];
  assert(mid.bf.t1_ctrl==1);
 }
}
int main(void)
{
 _Static_assert(sizeof(l3_cls_fib_tbl_entry_t)==28,"real SDK FIB row width");
 check_cls();check_stg0();check_lpb();
 puts("FE base contract: PASS (SDK semantic masks, mode0 second row, LPB v32, owned STG0/map bits)");
 return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--registers", type=Path, required=True)
    args = parser.parse_args()
    sdk_dir = args.sdk / "ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c"
    sdk = {name: verified(sdk_dir / name, digest) for name, digest in INPUTS.items()}
    registers = verified(args.registers, REG_SHA)
    native = (DRIVER / "rtl9617c-fe.c").read_text()
    mutants = (
        ("0xffffcfffU", "(0xffffcfffU^1U)"),
        ("0xffffcfffU", "(0xffffcfffU^(1U<<12))"),
        ("0x03800000U", "0U"),
    )
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0", UBSAN_OPTIONS="halt_on_error=1")
    with tempfile.TemporaryDirectory(prefix="rtl-fe-base-") as name:
        tmp = Path(name)
        c_file, binary = tmp / "test.c", tmp / "test"
        def run(driver):
            c_file.write_text(make_source(sdk, registers, driver))
            subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                            "-I", str(DRIVER), str(c_file), "-o", str(binary)], check=True)
            return subprocess.run([str(binary)], env=env, text=True, capture_output=True)
        result = run(native)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        print(result.stdout.strip())
        for old, new in mutants:
            assert native.count(old) == 1, f"mutation target drift: {old}"
            result = run(native.replace(old, new))
            assert result.returncode != 0 and "Assertion" in result.stderr, f"surviving mask mutant: {old}"
    print(f"SDK oracle: ca-network-drivers@{PIN}; GPL-for-GP3000@{GPL_PIN}; SHA256 verified")
    print("Mutation check: PASS (omit defined field, include reserved field, ignore second-row format)")


if __name__ == "__main__":
    main()
