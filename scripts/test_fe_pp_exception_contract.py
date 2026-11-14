#!/usr/bin/env python3
"""Check the readonly PP exception admission against pinned public RTL77C SDK.

The oracle compiles the four actual generated register unions and documented
SDK stage-selector constants, independently of the native bit masks. This is
source parity plus fault/admission coverage, not a physical ASIC or drain test.
No SDK source is copied into the product tree or downloaded by this script.
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
    "include/aal_l3_specpkt.h": "3bbef0c9e18b548b7a9732da17b943af8eeed3a7db2f045014e63f59c8e11259",
    "include/aal_port.h": "190e4c0c2ac7e99515162fac8775fb33c5ee605423d3809b09bda85708c99f7e",
}
REG_SHA = "ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0"
REGISTERS = (
    "L3FE_PP_PARSING_ERR_TRAP", "L3FE_PP_PARSING_OVER_VLAN_FWD_CTL",
    "L3FE_PP_DOS_ATK_EVENT_TRAP", "L3FE_PP_DOS_ATK_EVENT_DROP",
)
CONSTANTS = (
    "AAL_L3_SPECPKT_T0_CTRL_L3_LPB_PROC_DISABLE",
    "AAL_L3_SPECPKT_T1_CTRL_BYPASS_MODE", "AAL_L3_SPECPKT_T2_CTRL_BYPASS_HASH",
    "AAL_L3_SPECPKT_T3_CTRL_BYPASS", "AAL_L3_SPECPKT_T4_CTRL_BYPASS",
    "AAL_L3_SPECPKT_T5_CTRL_BYPASS", "AAL_LPORT_CPU_0", "AAL_LPORT_BLACKHOLE",
)


def verified(path, digest):
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest, f"SDK SHA256 mismatch: {path}"
    return data.decode()


def source(sdk, registers):
    code = "#include <assert.h>\n#include <errno.h>\n#include <stdint.h>\n#include <stdio.h>\n"
    code += '#include "rtl9617c-fe-pipeline.h"\ntypedef uint32_t ca_uint32_t;\n'
    for name in REGISTERS:
        match = re.search(r"^#define " + name + r"\s+0x", registers, re.M)
        assert match, name
        end = registers.index("#endif /* !__ASSEMBLER__ */", match.start())
        code += registers[match.start():end] + "#endif /* !__ASSEMBLER__ */\n"
    joined = "\n".join(sdk.values())
    for name in CONSTANTS:
        match = re.search(r"^#define\s+" + name + r"\s+[^\n]+", joined, re.M)
        assert match, name
        code += match[0] + "\n"
    code += "static const unsigned int offsets[]={\n"
    code += ",\n".join(name + "-0xf4300000U" for name in REGISTERS) + "};\n"
    code += "static int expected(unsigned int index,unsigned int word) { switch(index) {\n"
    for index, name in enumerate(REGISTERS):
        code += f"case {index}: {{ {name}_t v={{.wrd=word}}; return "
        code += "(v.bf.rdir_ldpid==AAL_LPORT_CPU_0 || v.bf.rdir_ldpid==AAL_LPORT_BLACKHOLE) && "
        code += "v.bf.keep_orig_pkt && !v.bf.rsrvd1 && "
        code += " && ".join(f"v.bf.t{i}_ctrl=={CONSTANTS[i]}" for i in range(6))
        code += "; }\n"
    code += "default: assert(0);return 0; }}\n" + TESTS
    return code


TESTS = r'''
struct model { unsigned int words[4],reads; };
static unsigned int rd(void *context,unsigned int reg)
{
 struct model *m=context;
 assert(m->reads<4 && reg==offsets[m->reads]);
 return m->words[m->reads++];
}
static void wr(void *context,unsigned int reg,unsigned int value)
{ (void)context;(void)reg;(void)value;assert(!"readonly preflight wrote MMIO"); }
static int indirect(void *context,unsigned int reg,unsigned int value)
{ (void)context;(void)reg;(void)value;assert(!"readonly preflight issued a command");return 0; }
static unsigned int vector(unsigned int port,unsigned int cos,unsigned int flags,
 unsigned int stage,unsigned int selector)
{
 L3FE_PP_PARSING_ERR_TRAP_t v={.wrd=0};
 v.bf.rdir_ldpid=port;v.bf.rdir_cos=cos;v.bf.keep_orig_pkt=flags&1;
 v.bf.rsrvd1=(flags>>1)&1;v.bf.t0_ctrl=(flags>>2)&1;
 v.bf.t1_ctrl=AAL_L3_SPECPKT_T1_CTRL_BYPASS_MODE;
 v.bf.t2_ctrl=AAL_L3_SPECPKT_T2_CTRL_BYPASS_HASH;
 v.bf.t3_ctrl=AAL_L3_SPECPKT_T3_CTRL_BYPASS;
 v.bf.t4_ctrl=AAL_L3_SPECPKT_T4_CTRL_BYPASS;
 v.bf.t5_ctrl=AAL_L3_SPECPKT_T5_CTRL_BYPASS;
 switch(stage) {
 case 1:v.bf.t1_ctrl=selector;break;case 2:v.bf.t2_ctrl=selector;break;
 case 3:v.bf.t3_ctrl=selector;break;case 4:v.bf.t4_ctrl=selector;break;
 case 5:v.bf.t5_ctrl=selector;break;default:break;
 }
 return v.wrd;
}
static unsigned int cases;
static void check_word(unsigned int word)
{
 for(unsigned int i=0;i<4;i++) {
  struct model m={.reads=0};
  struct rtl_dq_io io={.context=&m,.read=rd,.write=wr,.indirect=indirect};
  unsigned int bad_reg=0x12345678,bad_value=0x87654321;
  int safe=expected(i,word),ret;
  for(unsigned int j=0;j<4;j++)m.words[j]=vector(AAL_LPORT_CPU_0,0,5,0,0);
  m.words[i]=word;
  assert(!!rtl_fe_pp_exception_safe(word)==safe);
  ret=rtl_fe_pp_exceptions_check(&io,&bad_reg,&bad_value);
  if(safe) {
   assert(ret==0 && m.reads==4);
   assert(bad_reg==0x12345678 && bad_value==0x87654321);
  } else {
   assert(ret==-EOPNOTSUPP && m.reads==i+1);
   assert(bad_reg==offsets[i] && bad_value==word);
  }
  cases++;
 }
}
int main(void)
{
 uint32_t random_state=0x9617c;
 struct rtl_dq_io io={0};
 unsigned int reg=19,value=20;
 assert(rtl_fe_pp_exceptions_check(NULL,&reg,&value)==-EINVAL);
 assert(rtl_fe_pp_exceptions_check(&io,&reg,&value)==-EINVAL);
 assert(reg==19 && value==20);
 for(unsigned int port=0;port<64;port++)
  for(unsigned int cos=0;cos<8;cos++)
   for(unsigned int flags=0;flags<8;flags++)check_word(vector(port,cos,flags,0,0));
 for(unsigned int port=0;port<64;port++)
  for(unsigned int stage=1;stage<=5;stage++)
   for(unsigned int selector=0;selector<16;selector++)check_word(vector(port,3,5,stage,selector));
 for(unsigned int i=0;i<100000;i++) {
  random_state^=random_state<<13;random_state^=random_state>>17;random_state^=random_state<<5;
  check_word(random_state);
 }
 struct model m={.words={0,0,0,0},.reads=0};
 io.context=&m;io.read=rd;io.write=wr;io.indirect=indirect;
 assert(rtl_fe_pp_exceptions_check(&io,NULL,NULL)==-EOPNOTSUPP && m.reads==1);
 printf("PP exception contract: PASS (%u word/admission cases)\n",cases);
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
    native = (DRIVER / "rtl9617c-fe-pipeline.h").read_text()
    mutants = (
        ("(word&(1U<<9)) && ", ""),
        ("(word>>12)==0xfffffU", "1"),
        ("(destination==16U || destination==31U)", "destination<64U"),
        ("for(i=0;i<sizeof(registers)/sizeof(registers[0]);i++)", "for(i=0;i<3;i++)"),
    )
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0", UBSAN_OPTIONS="halt_on_error=1")
    with tempfile.TemporaryDirectory(prefix="rtl-pp-exception-") as name:
        tmp = Path(name)
        c_file, binary = tmp / "test.c", tmp / "test"
        c_file.write_text(source(sdk, registers))
        def run(header):
            (tmp / "rtl9617c-fe-pipeline.h").write_text(header)
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
            assert result.returncode != 0 and "Assertion" in result.stderr, f"surviving mutant: {old}"
    print(f"SDK oracle: ca-network-drivers@{PIN}; GPL-for-GP3000@{GPL_PIN}; SHA256 verified")
    print("Mutation check: PASS (keep-original, selectors, destination, skipped-register)")


if __name__ == "__main__":
    main()
