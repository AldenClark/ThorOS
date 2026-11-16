#!/usr/bin/env python3
"""Run actual immutable SVL/IVL cold handoffs and rollback in both directions."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"
HEADER = DRIVER / "rtl9617c-fabric.h"


def transport():
    tree = ast.parse((ROOT / "scripts/test_fabric_baseline.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "TEST" for t in node.targets):
            text = ast.literal_eval(node.value).split("int main(void)")[0]
            text = text.replace("assert(m.reg[RTL_L2_VLAN_MODE_CONTROL/4]&1U);",
                                "assert((m.reg[RTL_L2_VLAN_MODE_CONTROL/4]&1U)==expected_mode);")
            return "static unsigned int expected_mode;\n" + text
    raise SystemExit("Missing cold transport")


TEST = r'''
static void start(unsigned int original,unsigned int target,unsigned int boot)
{
 setup(0x87654000);expected_mode=target;
 m.reg[RTL_L2_VLAN_MODE_CONTROL/4]=(m.reg[RTL_L2_VLAN_MODE_CONTROL/4]&~1U)|original;
 m.reg[RTL_L2_FDB_CONTROL/4]=(m.reg[RTL_L2_FDB_CONTROL/4]&~RTL_L2_FDB_CMD_MODE)|
  (boot?RTL_L2_FDB_CMD_MODE:0);
 memcpy(m.original,m.reg,sizeof(m.reg));
}
int main(void)
{
 for(unsigned original=0;original<2;original++)for(unsigned target=0;target<2;target++)
  for(unsigned boot=0;boot<2;boot++)for(unsigned edge=0;edge<3;edge++) {
   struct rtl_fabric f={0};start(original,target,boot);
   m.toggle_at_gate=edge==1;m.toggle_on_scan=edge==2;
   assert(!rtl_fabric_cold_prepare_mode(&io,&f,target));
   assert(f.ready&&!f.poisoned);
   assert((f.vlan_mode&1U)==target&&m.reg[RTL_L2_VLAN_MODE_CONTROL/4]==f.vlan_mode);
   assert((f.vlan_mode&~1U)==(m.original[RTL_L2_VLAN_MODE_CONTROL/4]&~1U));
   assert(m.scans==(original!=target)&&m.vlan_writes==(original!=target));
   command_restored(&f);baseline_preserved(&f);
   unsigned writes=m.writes,reads=m.reads;struct rtl_fabric saved=f;
   assert(rtl_fabric_cold_prepare_mode(&io,&f,!target)==-EBUSY);
   assert(m.writes==writes&&m.reads==reads&&!memcmp(&f,&saved,sizeof(f)));
   assert(!rtl_fabric_cold_prepare_mode(&io,&f,target)&&m.writes==writes);
   cases++;
  }
 for(unsigned original=0;original<2;original++)for(unsigned boot=0;boot<2;boot++)
  for(unsigned inherited=1;inherited<=3;inherited++) {
   struct rtl_fabric f={0};start(original,!original,boot);m.inherited=inherited;
   assert(rtl_fabric_cold_prepare_mode(&io,&f,!original)==-EOPNOTSUPP);
   assert(f.refusal&&!f.ready&&!f.poisoned&&f.inherited_fdb_present);
   assert(m.scans==1&&!m.vlan_writes);
   assert(m.reg[RTL_L2_VLAN_MODE_CONTROL/4]==m.original[RTL_L2_VLAN_MODE_CONTROL/4]);
   command_restored(&f);baseline_preserved(&f);cases++;
  }
 for(unsigned original=0;original<2;original++)for(unsigned boot=0;boot<2;boot++) {
  struct rtl_fabric f={0};start(original,!original,boot);m.scan_timeout=1;
  assert(rtl_fabric_cold_prepare_mode(&io,&f,!original)==-ETIMEDOUT);
  assert(!f.ready&&f.poisoned&&!m.vlan_writes&&fdb_busy());cases++;
  f=(struct rtl_fabric){0};start(original,!original,boot);
  m.drop_reg=RTL_L2_VLAN_MODE_CONTROL;m.drop_occurrence=1;
  assert(rtl_fabric_cold_prepare_mode(&io,&f,!original)==-EIO);
  assert(f.refusal&&!f.ready&&!f.poisoned&&m.vlan_writes==2);
  assert(m.reg[RTL_L2_VLAN_MODE_CONTROL/4]==m.original[RTL_L2_VLAN_MODE_CONTROL/4]);
  command_restored(&f);baseline_preserved(&f);cases++;
  f=(struct rtl_fabric){0};start(original,!original,boot);m.corrupt_frame=1;
  assert(rtl_fabric_cold_prepare_mode(&io,&f,!original)==-EIO);
  assert(f.refusal&&!f.ready&&!f.poisoned&&m.vlan_writes==2);
  assert(m.reg[RTL_L2_VLAN_MODE_CONTROL/4]==m.original[RTL_L2_VLAN_MODE_CONTROL/4]);
  command_restored(&f);baseline_preserved(&f);cases++;
 }
 for(unsigned original=0;original<2;original++) {
  struct rtl_fabric f={0};start(original,1,0);
  assert(!rtl_fabric_cold_prepare(&io,&f));assert(f.vlan_mode&1U);cases++;
 }
 {
  struct rtl_fabric f={0},saved=f;start(1,1,0);
  assert(rtl_fabric_cold_prepare_mode(&io,&f,2)==-EINVAL);
  assert(!m.reads&&!m.writes&&!memcmp(&f,&saved,sizeof(f)));cases++;
 }
 printf("{\"cases\":%u,\"boot_only\":true,\"both_mode_directions\":true}\n",cases);
 return 0;
}
'''


def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run(header):
    with tempfile.TemporaryDirectory(prefix="fabric-modes-") as directory:
        work = Path(directory)
        (work / "linux").mkdir()
        (work / "linux/delay.h").write_text("")
        (work / "linux/errno.h").write_text("#include <asm-generic/errno.h>\n")
        (work / "linux/string.h").write_text("#include <string.h>\n")
        (work / "rtl9617c-fabric.h").write_text(header)
        source = work / "modes.c"
        source.write_text(transport() + TEST)
        binary = work / "modes"
        cmd = [os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
               "-Wno-unused-function", "-I", str(work), "-I", str(DRIVER), str(source), "-o", str(binary)]
        built = subprocess.run(cmd, capture_output=True, text=True)
        if built.returncode:
            raise SystemExit(built.stdout + built.stderr)
        return subprocess.run([str(binary)], capture_output=True, text=True, preexec_fn=no_core)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mutants", action="store_true")
    args = parser.parse_args()
    header = HEADER.read_text()
    fe = (DRIVER / "rtl9617c-fe.c").read_text()
    assert "module_param(native_l2_ivl, bool, 0400);" in fe
    assert "native_l2_ivl?RTL_FABRIC_VLAN_IVL:RTL_FABRIC_VLAN_SVL" in fe
    actual = run(header)
    if actual.returncode:
        raise SystemExit(actual.stdout + actual.stderr)
    result = json.loads(actual.stdout)
    mutations = {
        "scan_only_ivl_to_svl": ("if ((fabric->original_vlan_mode & RTL_L2_VLAN_MODE_SVL) != (unsigned int)mode)", "if (!(fabric->original_vlan_mode & RTL_L2_VLAN_MODE_SVL))"),
        "accept_warm_mode_change": ("return -EBUSY;\n\t\treturn rtl_fabric_check", "return rtl_fabric_check(io, fabric);\n\t\treturn rtl_fabric_check"),
        "ignore_foreign_fdb": ("fabric->inherited_fdb_words[i] = row.words[i];\n\t\t\tret = -EOPNOTSUPP;", "fabric->inherited_fdb_words[i] = row.words[i];\n\t\t\tret = 0;"),
        "lose_cmd_lifetime": ("RTL_L2_FDB_LEARN_DISABLE | RTL_L2_FDB_CMD_MODE))", "RTL_L2_FDB_LEARN_DISABLE))"),
    }
    rejected = []
    if args.mutants:
        for name, (before, after) in mutations.items():
            if header.count(before) != 1:
                raise SystemExit(f"Non-unique mutation: {name}")
            bad = run(header.replace(before, after))
            if not bad.returncode:
                raise SystemExit(f"SURVIVED: {name}")
            rejected.append(name)
    result.update(header_sha256=hashlib.sha256(header.encode()).hexdigest(), mutants_rejected=rejected)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
