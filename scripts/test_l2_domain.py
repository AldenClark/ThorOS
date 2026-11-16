#!/usr/bin/env python3
"""Run the real shared-resource/VLAN/MC compiler under host sanitizers.

No MMIO or board is touched. This checks table geometry, PON/FE ownership
exclusion, domain consistency, reversible preflight and no-edit MCE encoding.
It deliberately does NOT certify BUM copy tagging, CPU de-duplication or
any live multi-bridge/VLAN hardware admission.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"
HEADER = DRIVER / "rtl9617c-l2-domain.h"

TEST = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rtl9617c-l2-domain.h"

static unsigned int cases, claims, rows;

static void resource_test(void)
{
 struct rtl_l2_shared_ledger ledger = {0};
 unsigned int index, prev;
 assert(rtl_l2_shared_init(NULL, 1)==-EINVAL);
 assert(rtl_l2_shared_init(&ledger, 0)==-EINVAL);
 assert(!rtl_l2_shared_init(&ledger, 42));
 assert(rtl_l2_shared_init(&ledger, 43)==-EBUSY);
 assert(ledger.generation==42);
 assert(rtl_l2_shared_capacity((enum rtl_l2_shared_kind)-1)==0);
 assert(rtl_l2_shared_capacity(RTL_L2_SHARED_COUNT)==0);
 assert(rtl_l2_shared_claim(&ledger,RTL_L2_SHARED_VLAN_FIB,&index)==-ENOSPC);
 assert(rtl_l2_shared_claim(&ledger,RTL_L2_SHARED_COUNT,&index)==-EINVAL);
 assert(rtl_l2_shared_mark(&ledger,RTL_L2_SHARED_VLAN_FIB,128,0)==-ERANGE);
 assert(rtl_l2_shared_mark(&ledger,RTL_L2_SHARED_MC_FIB,64,0)==-ERANGE);
 assert(rtl_l2_shared_mark(&ledger,RTL_L2_SHARED_MC_VECTOR,256,0)==-ERANGE);
 assert(rtl_l2_shared_mark(&ledger,RTL_L2_SHARED_VLAN_FIB,0,2)==-EINVAL);
 for(unsigned k=0;k<RTL_L2_SHARED_COUNT;k++) {
  unsigned n=rtl_l2_shared_capacity(k);
  assert(n==(k==0?128U:k==1?64U:256U));
  for(unsigned i=0;i<n;i++) {
   if(i%7==0)assert(!rtl_l2_shared_mark(&ledger,k,i,1));
   else assert(!rtl_l2_shared_mark(&ledger,k,i,0));
  }
  assert(rtl_l2_shared_mark(&ledger,k,0,0)==-EBUSY);
  assert(rtl_l2_shared_mark(&ledger,k,1,1)==-EAGAIN);
  assert(rtl_l2_shared_available(&ledger,k)==n-(n+6)/7-1);
  assert(rtl_l2_shared_mark(&ledger,k,1,0)==-EBUSY);
  for(unsigned i=0;i<n;i++) if(i%7!=0) {
   if(i==1)continue; /* Foreign invalidated the preflight evidence. */
   assert(!rtl_l2_shared_claim(&ledger,k,&index));
   assert(index==i);claims++;
  }
  assert(rtl_l2_shared_claim(&ledger,k,&index)==-ENOSPC);
  assert(rtl_l2_shared_leased(&ledger,k)==n-(n+6)/7-1);
  cases++;
 }
 assert(rtl_l2_shared_release(&ledger,0,1,1)==-EBUSY);
 assert(rtl_l2_shared_release(&ledger,1,0,1)==-EBUSY);
 assert(rtl_l2_shared_release(&ledger,1,1,0)==-EBUSY);
 assert(rtl_l2_shared_leased(&ledger,RTL_L2_SHARED_MC_VECTOR)>0);
 assert(!rtl_l2_shared_release(&ledger,1,1,1));
 for(unsigned k=0;k<RTL_L2_SHARED_COUNT;k++) {
  assert(!rtl_l2_shared_leased(&ledger,k));
  assert(rtl_l2_shared_claim(&ledger,k,&index)==-ENOSPC);
  assert(!rtl_l2_shared_mark(&ledger,k,2,0));
  assert(!rtl_l2_shared_claim(&ledger,k,&index)&&index==2);
  cases++;
 }
 /* A new foreign consumer racing the lease cannot be overwritten or
  * silently forgotten by a second initialization/rollback. */
 prev=rtl_l2_shared_leased(&ledger,RTL_L2_SHARED_MC_FIB);
 assert(prev==1);
 assert(rtl_l2_shared_mark(&ledger,RTL_L2_SHARED_MC_FIB,2,1)==-EBUSY);
 assert(ledger.quarantined);
 assert(rtl_l2_shared_claim(&ledger,RTL_L2_SHARED_MC_FIB,&index)==-EBUSY);
 assert(rtl_l2_shared_release(&ledger,1,1,1)==-EBUSY);
 assert(rtl_l2_shared_init(&ledger,50)==-EBUSY);
 assert(rtl_l2_shared_leased(&ledger,RTL_L2_SHARED_MC_FIB)==prev);
 cases++;
}

static void atomic_group_test(void)
{
 struct rtl_l2_shared_ledger ledger={0};
 unsigned short actions[64],vector=0xeeee,indices[128];
 unsigned int idx;
 assert(!rtl_l2_shared_init(&ledger,77));
 for(unsigned i=0;i<128;i++)assert(!rtl_l2_shared_mark(&ledger,RTL_L2_SHARED_VLAN_FIB,i,0));
 for(unsigned i=0;i<64;i++)assert(!rtl_l2_shared_mark(&ledger,RTL_L2_SHARED_MC_FIB,i,0));
 for(unsigned i=0;i<256;i++)assert(!rtl_l2_shared_mark(&ledger,RTL_L2_SHARED_MC_VECTOR,i,0));
 assert(rtl_l2_shared_mc_group_claim(&ledger,65,&vector,actions)==-EINVAL);
 assert(rtl_l2_shared_mc_group_claim(&ledger,0,&vector,actions)==-EINVAL);
 assert(!rtl_l2_shared_mc_group_claim(&ledger,63,&vector,actions));
 assert(vector==0 && actions[0]==0 && actions[62]==62);
 assert(rtl_l2_shared_leased(&ledger,RTL_L2_SHARED_MC_FIB)==63);
 assert(rtl_l2_shared_mc_group_claim(&ledger,2,&vector,actions)==-ENOSPC);
 assert(rtl_l2_shared_leased(&ledger,RTL_L2_SHARED_MC_FIB)==63);
 assert(rtl_l2_shared_leased(&ledger,RTL_L2_SHARED_MC_VECTOR)==1);
 assert(rtl_l2_shared_claim_many(&ledger,RTL_L2_SHARED_MC_FIB,2,actions)==-ENOSPC);
 assert(!rtl_l2_shared_claim_many(&ledger,RTL_L2_SHARED_MC_FIB,1,actions));
 assert(actions[0]==63);
 assert(rtl_l2_shared_claim(&ledger,RTL_L2_SHARED_MC_FIB,&idx)==-ENOSPC);
 assert(!rtl_l2_shared_claim_many(&ledger,RTL_L2_SHARED_VLAN_FIB,128,indices));
 for(unsigned i=0;i<128;i++)assert(indices[i]==i);
 assert(rtl_l2_shared_claim_many(&ledger,RTL_L2_SHARED_VLAN_FIB,1,indices)==-ENOSPC);
 assert(rtl_l2_shared_claim_many(&ledger,RTL_L2_SHARED_VLAN_FIB,1,NULL)==-EINVAL);
 cases++;
}

static struct rtl_l2_vlan_spec spec(unsigned vid,unsigned bridge,
                  unsigned members,unsigned untagged,unsigned pvid)
{
 return (struct rtl_l2_vlan_spec){
  .vid=vid,.bridge=bridge,.members=members,.untagged=untagged,
  .pvid=pvid,.forwarding=members,.learning=members,
 };
}

static void vlan_test(void)
{
 struct rtl_l2_vlan_plan plan={0},saved;
 struct rtl_l2_vlan_spec v;
 unsigned int out[2],before[2],index,second;
 v=spec(1,1,0x1f,0x1f,0x1f);
 assert(!rtl_l2_vlan_plan_add(&plan,&v));
 assert(plan.count==1 && plan.port_bridge[4]==1 && plan.port_pvid[4]==1);
 saved=plan;
 v=spec(1,2,1,1,1);
 assert(rtl_l2_vlan_plan_add(&plan,&v)==-EADDRINUSE);
 assert(!memcmp(&plan,&saved,sizeof(plan)));
 v=spec(2,2,1,1,1);
 assert(rtl_l2_vlan_plan_add(&plan,&v)==-EADDRINUSE);
 assert(!memcmp(&plan,&saved,sizeof(plan)));
 v=spec(2,1,0x1f,0x1f,1);
 assert(rtl_l2_vlan_plan_add(&plan,&v)==-EADDRINUSE);
 assert(!memcmp(&plan,&saved,sizeof(plan)));
 v=spec(1,1,1,0,0); /* Contradicts the original untagged member. */
 assert(rtl_l2_vlan_plan_add(&plan,&v)==-EINVAL);
 assert(!memcmp(&plan,&saved,sizeof(plan)));
 v=spec(1,1,1,1,1);
 assert(!rtl_l2_vlan_plan_add(&plan,&v)&&plan.count==1);
 plan=(struct rtl_l2_vlan_plan){0};
 v=spec(100,1,1,1,1);
 assert(!rtl_l2_vlan_plan_add(&plan,&v));
 v=spec(100,1,2,2,2);
 assert(!rtl_l2_vlan_plan_add(&plan,&v));
 assert(plan.count==1 && plan.vlans[0].members==3 && plan.vlans[0].pvid==3);
 v=spec(200,2,0x1c,0x1c,0x1c);
 assert(!rtl_l2_vlan_plan_add(&plan,&v));
 assert(plan.count==2 && plan.port_bridge[2]==2);
 saved=plan;
 v=spec(100,2,4,4,4);
 assert(rtl_l2_vlan_plan_add(&plan,&v)==-EADDRINUSE);
 assert(!memcmp(&plan,&saved,sizeof(plan)));
 v=spec(300,2,4,4,4);
 assert(rtl_l2_vlan_plan_add(&plan,&v)==-EADDRINUSE);
 assert(!memcmp(&plan,&saved,sizeof(plan)));
 v=spec(301,2,4,0,0); /* tagged-only trunk is legal */
 assert(!rtl_l2_vlan_plan_add(&plan,&v));
 assert(plan.count==3);
 /* Same wire VID on different bridge domains must be rejected even when
  * physical members are disjoint: the FDB key lacks a bridge namespace. */
 plan=(struct rtl_l2_vlan_plan){0};
 v=spec(77,1,1,1,1);
 assert(!rtl_l2_vlan_plan_add(&plan,&v));
 saved=plan;
 v=spec(77,2,2,2,2);
 assert(rtl_l2_vlan_plan_add(&plan,&v)==-EADDRINUSE);
 assert(!memcmp(&plan,&saved,sizeof(plan)));
 for(unsigned vid=1;vid<4096;vid++) {
  v=spec(vid,1,3,3,0);
  bool valid=vid<4095;
  assert((rtl_l2_vlan_spec_validate(&v)==0)==valid);
  if(!valid)continue;
  before[0]=0xf0f0f0f0;before[1]=0x5a5aaa55;
  v.isolated=1;
  assert(!rtl_l2_vlan_fib_build(&v,vid%1024,before,out));
  assert((out[0]&0xffffU)==3 && ((out[0]>>16)&0xffffU)==3);
  assert((out[1]&1023U)==vid%1024);
  assert((out[1]&~1023U)==(before[1]&~1023U));
  for(unsigned fib=0;fib<128;fib++) {
   unsigned int original=0xdeadbeef;
   assert(!rtl_l2_vlan_index_build(fib,1,original,&index));
   assert((index&255U)==(1U|(fib<<1)));
   assert((index&~255U)==(original&~255U));
   assert(!rtl_l2_vlan_index_build(fib,0,index,&second));
   assert((second&255U)==(fib<<1));
   rows++;
  }
  cases++;
 }
 v=spec(1,1,1,1,1);
 v.members=0;assert(rtl_l2_vlan_spec_validate(&v)==-EINVAL);
 v=spec(1,1,1,1,1);
 v.untagged=2;v.pvid=0;assert(rtl_l2_vlan_spec_validate(&v)==-EINVAL);
 v=spec(1,1,1,0,1);assert(rtl_l2_vlan_spec_validate(&v)==-EINVAL);
 v=spec(1,1,1,1,1);
 v.learning=2;assert(rtl_l2_vlan_spec_validate(&v)==-EINVAL);
 v=spec(1,1,1,1,1);
 assert(rtl_l2_vlan_fib_build(&v,1024,before,out)==-EINVAL);
 assert(rtl_l2_vlan_index_build(128,1,0,&index)==-EINVAL);
 assert(rtl_l2_vlan_index_build(0,2,0,&index)==-EINVAL);
 plan=(struct rtl_l2_vlan_plan){0};
 for(unsigned vid=1;vid<=128;vid++) {
  v=spec(vid,1,3,0,0);
  assert(!rtl_l2_vlan_plan_add(&plan,&v));
 }
 assert(plan.count==128);
 saved=plan;v=spec(129,1,3,0,0);
 assert(rtl_l2_vlan_plan_add(&plan,&v)==-ENOSPC);
 assert(!memcmp(&plan,&saved,sizeof(plan)));
 struct rtl_l2_shared_ledger ledger={0};
 unsigned short indices[128]={0};
 assert(!rtl_l2_shared_init(&ledger,99));
 assert(rtl_l2_vlan_plan_claim(&ledger,&plan,indices)==-ENOSPC);
 for(unsigned i=0;i<127;i++)
  assert(!rtl_l2_shared_mark(&ledger,RTL_L2_SHARED_VLAN_FIB,i,0));
 assert(rtl_l2_vlan_plan_claim(&ledger,&plan,indices)==-ENOSPC);
 assert(!rtl_l2_shared_leased(&ledger,RTL_L2_SHARED_VLAN_FIB));
 assert(!rtl_l2_shared_mark(&ledger,RTL_L2_SHARED_VLAN_FIB,127,1));
 assert(rtl_l2_vlan_plan_claim(&ledger,&plan,indices)==-ENOSPC);
 assert(!rtl_l2_shared_leased(&ledger,RTL_L2_SHARED_VLAN_FIB));
 cases++;
 cases++;
}

static void multicast_test(void)
{
 unsigned int out[3],decoded,vector[2],fwd,previous;
 for(unsigned d=0;d<64;d++)for(unsigned copy=0;copy<2;copy++) {
  out[0]=out[1]=out[2]=0xdeadbeef;
  int ret=rtl_l2_mc_noedit_build(d,1,56,copy,out);
  if(d==16&&!copy) {
   assert(ret==-EOPNOTSUPP && out[0]==0xdeadbeef);
   continue;
  }
  assert(!ret);
  assert(!rtl_l2_field_get(out,RTL_L2_MC_DESTINATION,&decoded)&&decoded==d);
  assert(!rtl_l2_field_get(out,RTL_L2_MC_POLICER_ID,&decoded)&&decoded==56);
  assert(!rtl_l2_field_get(out,RTL_L2_MC_COS_COMMAND,&decoded)&&decoded==1);
  assert(!rtl_l2_field_get(out,RTL_L2_MC_KEEP_ORIGINAL_SOURCE_PORT,&decoded)&&decoded==1);
  /* No S/C VLAN edit, no TTL decrement, no source MAC rewrite. */
  assert(out[0]==(56U<<23));
  assert(out[1]==((d<<24)|(1U<<30)));
  assert(out[2]==(1U<<11));
  cases++;
 }
 assert(rtl_l2_mc_noedit_build(64,1,0,1,out)==-EINVAL);
 assert(rtl_l2_mc_noedit_build(0,2,0,1,out)==-EINVAL);
 assert(rtl_l2_mc_noedit_build(0,0,512,1,out)==-EINVAL);
 assert(rtl_l2_mc_noedit_build(0,0,0,2,out)==-EINVAL);
 assert(rtl_l2_mc_noedit_build(0,0,0,1,NULL)==-EINVAL);
 assert(rtl_l2_mc_vector_build(0,vector)==-EINVAL);
 for(unsigned i=0;i<64;i++) {
  unsigned long long mask=1ULL<<i;
  assert(!rtl_l2_mc_vector_build(mask,vector));
  assert(rtl_l2_bitmap_decode(vector)==mask);
  cases++;
 }
 for(unsigned i=0;i<256;i++) {
  previous=0xffffe000U;
  assert(!rtl_l2_dft_flood_build(i,previous,&fwd));
  assert((fwd&0x1fffU)==((i<<1)|(1U<<12)));
  assert((fwd&~0x1fffU)==(previous&~0x1fffU));
  cases++;
 }
 assert(rtl_l2_dft_flood_build(256,0,&fwd)==-EINVAL);
 assert(rtl_l2_dft_flood_build(0,0,NULL)==-EINVAL);
}

int main(void)
{
 resource_test();atomic_group_test();vlan_test();multicast_test();
 printf("L2 shared-lease/bridge-VLAN/MC recipe: %u cases, %u claims, %u VLAN index rows; host only\n",
        cases,claims,rows);
 return 0;
}
'''


def run(header: str, sanitize: bool) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory(prefix="rtl-l2-domain-") as temp:
        wd = Path(temp)
        (wd / HEADER.name).write_text(header)
        (wd / "test.c").write_text(TEST)
        flags = ["-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror"]
        if sanitize:
            flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                      "-fno-pie", "-no-pie"]
        compilation = subprocess.run(["cc", *flags, "-I", str(wd), "-I", str(DRIVER),
                                      str(wd / "test.c"), "-o", str(wd / "test")],
                                     capture_output=True, text=True)
        if compilation.returncode:
            raise RuntimeError(compilation.stderr)
        return subprocess.run([str(wd / "test")], capture_output=True, text=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mutants", action="store_true")
    parser.add_argument("--sanitize", action="store_true")
    args = parser.parse_args()
    header = HEADER.read_text()
    actual = run(header, args.sanitize)
    if actual.returncode:
        raise SystemExit(actual.stdout + actual.stderr)
    print(actual.stdout.strip())
    if args.mutants:
        mutants = {
            "claim_without_proof": ("!(bank->verified_free[word] & mask)",
                                    "!(bank->verified_free[word] | ~0U)"),
            "release_while_busy": ("!tables_restored || !datapath_drained || !cpu_copies_retired",
                                   "(!tables_restored && !datapath_drained && !cpu_copies_retired)"),
            "allow_cross_bridge_vid": ("plan->vlans[i].bridge != spec->bridge",
                                       "plan->vlans[i].bridge == 0"),
            "allow_untag_outside_member": ("(spec->untagged & ~spec->members)", "0"),
            "mc_copy_without_proof": ("destination == 16 && !cpu_copy_verified",
                                      "destination == 16 && cpu_copy_verified > 1"),
            "mc_tag_edit": ("unsigned int output[3] = { 0 };", "unsigned int output[3] = { 1 };")
        }
        for name, (before, after) in mutants.items():
            if header.count(before) != 1:
                raise SystemExit(f"Nonunique mutation {name}")
            result = run(header.replace(before, after), False)
            if not result.returncode:
                raise SystemExit(f"Survived mutation {name}")
            print(f"rejected mutation {name}")


if __name__ == "__main__":
    main()
