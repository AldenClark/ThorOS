#!/usr/bin/env python3
"""Exercise the actual FE-lifetime VLAN/MCE owner, not a Python allocator.

The shared transport is the existing ACCESS/DATA/journal oracle.  Tests cover
cold root discovery, true table writes/publication, immutable dependencies,
capacity, abort and late-completion retention. No wire-drain claim is made.
"""
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
HEADER = DRIVER / "rtl9617c-l2-owner.h"


def transport():
    tree = ast.parse((ROOT / "scripts/test_l2_resources.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "TEST" for t in node.targets):
            return ast.literal_eval(node.value).split("static void geometry_and_capacity(void)")[0]
    raise SystemExit("Missing real table transport")


TEST = r'''
/* Keep Linux's task-pointer macro visible at the production-header boundary.
 * A plain host build used to miss a local variable named `current` here. */
#define current get_current()
#include "rtl9617c-l2-owner.h"
static struct rtl_l2_owner owner;
static unsigned int owner_cases, owner_faults;
static const enum rtl_l2_table map_table[] = { RTL_L2_TBL_VLAN_LAN_INDEX,
 RTL_L2_TBL_VLAN_WAN_S_INDEX, RTL_L2_TBL_VLAN_WAN_C_INDEX };
static void owner_reset(void)
{
 reset(1);memset(&owner,0,sizeof(owner));
 for(unsigned b=0;b<3;b++)for(unsigned v=0;v<4096;v++)
  m.rows[map_table[b]][v][0]=0xa5000000U|((v&127U)<<1);
 for(unsigned i=0;i<256;i++)memset(m.rows[RTL_L2_TBL_MC_VECTOR][i],0,8);
 assert(!rtl_l2_owner_init(&owner,rows,row_index,rtl_l2_journal_index_count(),17));
 assert(rtl_l2_owner_init(&owner,rows,row_index,rtl_l2_journal_index_count(),18)==-EBUSY);
}
static struct rtl_l2_vlan_plan one_vlan(unsigned vid)
{
 struct rtl_l2_vlan_plan p={0};p.count=1;p.vlans[0].vid=vid;
 return p;
}
static void scan_contract(void)
{
 unsigned short index;
 for(unsigned b=0;b<3;b++)for(unsigned f=0;f<128;f++) {
  owner_reset();m.rows[map_table[b]][(f*31)&4095][0]=1U|(f<<1);
  memset(m.rows[RTL_L2_TBL_VLAN_FIB][f],0,8); /* zero but REFERENCED */
  assert(!rtl_l2_owner_vlan_cold_scan(&owner,&io));
  assert(owner.scan_reads==12288);
  assert(rtl_l2_shared_available(&owner.ledger,RTL_L2_SHARED_VLAN_FIB)==127);
  assert(rtl_l2_owner_has(owner.ledger.bank[0].foreign,f));
  assert(!rtl_l2_owner_has(owner.ledger.bank[0].verified_free,f));
  assert(!rtl_l2_owner_reserve(&owner,RTL_L2_SHARED_VLAN_FIB,1,&index));
  assert(index!=f);owner_cases++;
 }
 owner_reset();for(unsigned f=0;f<128;f++)m.rows[map_table[f%3]][4095-f][0]=1U|(f<<1);
 assert(!rtl_l2_owner_vlan_cold_scan(&owner,&io));
 assert(rtl_l2_owner_reserve(&owner,0,1,&index)==-ENOSPC);
 assert(!rtl_l2_owner_retained(&owner));
 unsigned commands=m.command;rtl_l2_owner_seal(&owner);
 assert(rtl_l2_owner_vlan_cold_scan(&owner,&io)==-EBUSY&&m.command==commands);
 owner_reset();m.rows[map_table[0]][1][0]=1U|(19U<<1);
 assert(!rtl_l2_owner_vlan_cold_scan(&owner,&io));
 struct rtl_l2_vlan_plan p=one_vlan(1);
 assert(rtl_l2_owner_vlan_reserve(&owner,&p,&index)==-EADDRINUSE);
 owner_cases+=2;
}
static void cold_faults(void)
{
 for(unsigned b=0;b<3;b++)for(unsigned v=0;v<4096;v+=127) {
  owner_reset();m.error=-ETIMEDOUT;m.fault_at=b*4096+v+1;
  assert(rtl_l2_owner_vlan_cold_scan(&owner,&io)==-ETIMEDOUT);
  assert(owner.ledger.quarantined&&!owner.ready_mask&&m.pending);
  assert(!rtl_l2_shared_available(&owner.ledger,0));
  complete(true);unsigned commands=m.command;
  assert(rtl_l2_owner_vlan_cold_scan(&owner,&io)==-EBUSY&&commands==m.command);
  assert(rtl_l2_owner_retained(&owner));owner_faults++;
 }
 for(unsigned b=0;b<3;b++) {
  owner_reset();m.regs[m.layout[map_table[b]].access/4]=RTL_L2_ACCESS_BUSY;
  assert(rtl_l2_owner_vlan_cold_scan(&owner,&io)==-EBUSY);
  assert(!owner.ready_mask&&owner.ledger.quarantined);owner_faults++;
 }
}
static void vlan_lifecycle(void)
{
 unsigned short fib;
 const unsigned data[2]={0x011f0000U,0};
 owner_reset();assert(!rtl_l2_owner_vlan_cold_scan(&owner,&io));rtl_l2_owner_seal(&owner);
 struct rtl_l2_vlan_plan p=one_vlan(100);
 assert(!rtl_l2_owner_vlan_reserve(&owner,&p,&fib));
 unsigned old_map=m.rows[map_table[0]][100][0],old_reserved=m.rows[RTL_L2_TBL_VLAN_FIB][fib][1]&~1023U;
 unsigned before=m.order_count;
 assert(!rtl_l2_owner_vlan_install(&owner,&io,100,data));
 assert(m.order_count==before+2&&m.order_table[before]==RTL_L2_TBL_VLAN_FIB);
 assert(m.order_table[before+1]==RTL_L2_TBL_VLAN_LAN_INDEX&&m.order_index[before+1]==100);
 assert(m.rows[RTL_L2_TBL_VLAN_FIB][fib][0]==data[0]);
 assert((m.rows[RTL_L2_TBL_VLAN_FIB][fib][1]&~1023U)==old_reserved);
 assert(m.rows[map_table[0]][100][0]==((old_map&~255U)|(fib<<1)|1U));
 assert(owner.active[0][fib]==1&&rtl_l2_owner_has(owner.published[0],fib));
 assert(rtl_l2_owner_vlan_install(&owner,&io,100,data)==-EBUSY);
 assert(!rtl_l2_owner_vlan_retire(&owner,&io,100));
 assert(m.rows[map_table[0]][100][0]==old_map&&!owner.active[0][fib]);
 assert(rtl_l2_shared_leased(&owner.ledger,0)==1&&rtl_l2_owner_retained(&owner));
 assert(rtl_l2_owner_abort(&owner,&io,0,fib)==-EBUSY);
 assert(!rtl_l2_owner_vlan_reserve(&owner,&p,&fib));
 assert(!rtl_l2_owner_vlan_install(&owner,&io,100,data));
 assert(!rtl_l2_owner_vlan_retire(&owner,&io,100));
 assert(rtl_l2_shared_leased(&owner.ledger,0)==1);owner_cases++;
 for(unsigned fault=1;fault<=7;fault++) {
  owner_reset();assert(!rtl_l2_owner_vlan_cold_scan(&owner,&io));
  assert(!rtl_l2_owner_vlan_reserve(&owner,&p,&fib));
  m.error=-ETIMEDOUT;m.fault_at=m.command+fault;
  assert(rtl_l2_owner_vlan_install(&owner,&io,100,data)==-ETIMEDOUT);
  assert(owner.ledger.quarantined&&rtl_l2_shared_leased(&owner.ledger,0)==1);
  assert(m.pending);complete(true);unsigned commands=m.command;
  assert(rtl_l2_owner_abort(&owner,&io,0,fib)<0&&m.command==commands);
  assert(rtl_l2_owner_retained(&owner));owner_faults++;
 }
 owner_reset();assert(!rtl_l2_owner_vlan_cold_scan(&owner,&io));
 assert(!rtl_l2_owner_vlan_reserve(&owner,&p,&fib));
 m.ignore_at=m.command+4;assert(rtl_l2_owner_vlan_install(&owner,&io,100,data)==-EIO);
 assert(owner.ledger.quarantined);owner_faults++;
 owner_reset();assert(!rtl_l2_owner_vlan_cold_scan(&owner,&io));
 struct rtl_l2_vlan_plan full={0};unsigned short indices[128];full.count=128;
 for(unsigned i=0;i<128;i++)full.vlans[i].vid=i+1;
 assert(!rtl_l2_owner_vlan_reserve(&owner,&full,indices));
 p=one_vlan(129);before=m.command;
 assert(rtl_l2_owner_vlan_reserve(&owner,&p,&fib)==-ENOSPC&&m.command==before);
 assert(rtl_l2_shared_leased(&owner.ledger,0)==128);owner_cases++;
}
static void mc_scan(void)
{
 unsigned int foreign[8]={0};unsigned short a,v;
 owner_reset();foreign[0]=1U<<9;
 m.rows[RTL_L2_TBL_MC_VECTOR][9][0]=1U<<3;
 m.rows[RTL_L2_TBL_MC_VECTOR][200][1]=1U<<31; /* even unreferenced vector owns its old action */
 memset(m.rows[RTL_L2_TBL_MC_FIB][3],0,12);
 assert(!rtl_l2_owner_mc_cold_scan(&owner,&io,foreign));
 assert(rtl_l2_shared_available(&owner.ledger,RTL_L2_SHARED_MC_VECTOR)==254);
 assert(rtl_l2_shared_available(&owner.ledger,RTL_L2_SHARED_MC_FIB)==62);
 assert(rtl_l2_owner_has(owner.ledger.bank[1].foreign,3));
 assert(rtl_l2_owner_has(owner.ledger.bank[1].foreign,63));
 assert(!rtl_l2_owner_reserve(&owner,1,1,&a)&&a!=3&&a!=63);
 assert(!rtl_l2_owner_reserve(&owner,2,1,&v)&&v&&v!=9);owner_cases++;
 owner_reset();m.rows[RTL_L2_TBL_MC_VECTOR][0][0]=1;
 assert(rtl_l2_owner_mc_cold_scan(&owner,&io,foreign)==-EOPNOTSUPP);
 assert(!owner.ready_mask&&!rtl_l2_shared_available(&owner.ledger,2));owner_cases++;
 for(unsigned fault=1;fault<=256;fault++) {
  owner_reset();m.error=-ETIMEDOUT;m.fault_at=fault;
  assert(rtl_l2_owner_mc_cold_scan(&owner,&io,foreign)==-ETIMEDOUT);
  assert(!owner.ready_mask&&owner.ledger.quarantined);complete(true);
  assert(!rtl_l2_shared_available(&owner.ledger,1));owner_faults++;
 }
}
static void mc_lifecycle(void)
{
 unsigned int foreign[8]={0},action[3]={0x800000U,16U<<24,0},vec[2]={0};
 unsigned short a,v;
 owner_reset();assert(!rtl_l2_owner_mc_cold_scan(&owner,&io,foreign));rtl_l2_owner_seal(&owner);
 assert(!rtl_l2_owner_reserve(&owner,1,1,&a));assert(!rtl_l2_owner_reserve(&owner,2,1,&v));
 vec[a/32]|=1U<<(a%32);
 assert(rtl_l2_owner_write(&owner,&io,2,v,vec)==-EINVAL); /* no action yet */
 assert(!rtl_l2_owner_write(&owner,&io,1,a,action));
 assert(!rtl_l2_owner_write(&owner,&io,2,v,vec));
 assert(owner.action_vectors[a]==1);
 assert(rtl_l2_owner_abort(&owner,&io,1,a)==-EBUSY);
 assert(!rtl_l2_owner_abort(&owner,&io,2,v));
 assert(!owner.action_vectors[a]);assert(!rtl_l2_owner_abort(&owner,&io,1,a));
 assert(!rtl_l2_owner_retained(&owner));owner_cases++;
 assert(!rtl_l2_owner_reserve(&owner,1,1,&a));assert(!rtl_l2_owner_reserve(&owner,2,1,&v));
 assert(!rtl_l2_owner_write(&owner,&io,1,a,action));assert(!rtl_l2_owner_write(&owner,&io,2,v,vec));
 assert(!rtl_l2_owner_publish(&owner,2,v)); /* BEFORE producer could timeout */
 assert(owner.active[2][v]==1&&owner.active[1][a]==1);
 assert(rtl_l2_owner_has(owner.published[2],v)&&rtl_l2_owner_has(owner.published[1],a));
 assert(!rtl_l2_owner_retire(&owner,2,v));
 assert(!owner.active[2][v]&&!owner.active[1][a]);
 assert(rtl_l2_owner_abort(&owner,&io,2,v)==-EBUSY);
 assert(rtl_l2_owner_abort(&owner,&io,1,a)==-EBUSY);
 assert(rtl_l2_owner_write(&owner,&io,2,v,vec)==-EBUSY&&rtl_l2_owner_retained(&owner));
 assert(rtl_l2_shared_mark(&owner.ledger,2,v,1)==-EBUSY&&owner.ledger.quarantined);owner_cases++;
}
int main(void)
{
 scan_contract();cold_faults();vlan_lifecycle();mc_scan();mc_lifecycle();
 printf("{\"cases\":%u,\"faults\":%u,\"vlan_index_reads_per_scan\":12288,\"owner_bytes\":%zu}\n",owner_cases,owner_faults,sizeof(owner));
 return 0;
}
'''


def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run(header, sanitize=False):
    with tempfile.TemporaryDirectory(prefix="l2-owner-") as directory:
        work = Path(directory)
        (work / "linux").mkdir()
        (work / "linux/errno.h").write_text("#include <asm-generic/errno.h>\n")
        (work / "linux/string.h").write_text("#include <string.h>\n")
        (work / "rtl9617c-l2-owner.h").write_text(header)
        source = work / "owner.c"
        source.write_text(transport() + TEST)
        binary = work / "owner"
        cmd = [os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
               "-Wno-unused-function", "-Wno-unused-variable", "-I", str(work), "-I", str(DRIVER), str(source), "-o", str(binary)]
        if sanitize:
            cmd[1:1] = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie"]
        built = subprocess.run(cmd, capture_output=True, text=True)
        if built.returncode:
            raise SystemExit(built.stdout + built.stderr)
        env = os.environ.copy()
        if sanitize:
            env["ASAN_OPTIONS"] = env.get("ASAN_OPTIONS", "") + ":detect_leaks=0"
        return subprocess.run([str(binary)], capture_output=True, text=True, preexec_fn=no_core, env=env)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sanitize", action="store_true")
    parser.add_argument("--mutants", action="store_true")
    args = parser.parse_args()
    header = HEADER.read_text()
    actual = run(header, args.sanitize)
    if actual.returncode:
        raise SystemExit(actual.stdout + actual.stderr)
    result = json.loads(actual.stdout)
    mutants = {
        "skip_wan_c_references": ("bank < sizeof(maps) / sizeof(maps[0])", "bank < 2"),
        "publish_fibs_without_foreign_refs": ("fib, rtl_l2_owner_has(foreign, fib)", "fib, 0"),
        "allow_runtime_rescan": ("if (owner->sealed || owner->ledger.quarantined ||\n\t    (owner->ready_mask & (1U << RTL_L2_SHARED_VLAN_FIB)))", "if (owner->ledger.quarantined)"),
        "lose_vector_publication": ("rtl_l2_owner_set(owner->published[kind], index);", "/* lost sticky ownership */"),
        "allow_abort_published": ("if (rtl_l2_owner_has(owner->published[kind], index) || owner->active[kind][index] ||", "if (owner->active[kind][index] ||"),
        "forget_vector_action_dependencies": ("owner->action_vectors[action]++;", "(void)0; /* missing dependency */"),
    }
    rejected = []
    if args.mutants:
        for name, (before, after) in mutants.items():
            if header.count(before) != 1:
                raise SystemExit(f"Non-unique mutation {name}")
            bad = run(header.replace(before, after))
            if not bad.returncode:
                raise SystemExit(f"SURVIVED: {name}")
            rejected.append(name)
    result.update(header_sha256=hashlib.sha256(header.encode()).hexdigest(), sanitizers=args.sanitize, mutants_rejected=rejected)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
