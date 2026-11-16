#!/usr/bin/env python3
"""Exercise native learning/isolation policy and its real MMIO transaction.

Reuses the hardware-recipe transport, not a second policy implementation.
Optional --sdk and --registers compile the pinned SDK membership setter and
register unions as a separate source-contract oracle. No board throughput
or undocumented ASIC pipeline behavior is inferred from these host tests.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

import test_l2_hardware_recipe as recipe


ROOT = Path(__file__).resolve().parents[1]
DRIVERS = recipe.DRIVERS
HW = DRIVERS / "rtl9617c-fe-switch-hw.h"
POLICY = DRIVERS / "rtl9617c-l2-port-policy.h"
SDK_FILES = {
    "aal_port.c": "f71a0ce59fc246739be73b9ab272e5f4a6d3541360ed25ae84b1556818c32e95",
    "aal_arb.c": "99567f3ecc28ce8cedd9770794e19362437c0c37747e80b9d7552233c2461272",
    "include/aal_port.h": "190e4c0c2ac7e99515162fac8775fb33c5ee605423d3809b09bda85708c99f7e",
}

TEST = r'''
static unsigned int pure_cases, sdk_cases;
/*SDK_ORACLE*/

static void pure_matrix(void)
{
 struct rtl_l2_port_policy result = {0};
 for (unsigned int ports=1;ports<32;ports++)
  for(unsigned int learn=0;learn<32;learn++)
   for(unsigned int isolated=0;isolated<32;isolated++) {
    if((learn|isolated)&~ports)continue;
    for(unsigned int target=16;target<=25;target+=9)
     for(unsigned int p=0;p<5;p++) {
      if(!(ports&BIT(p)))continue;
      assert(!rtl_l2_port_policy_build(ports,learn,isolated,p,target,&result));
      assert(result.stp==((learn&BIT(p))?3U:2U));
      for(unsigned int d=0;d<64;d++) {
       bool permitted=d==16 || d==target ||
        (d<5 && d!=p && (ports&BIT(d)) && !((isolated&BIT(p)) && (isolated&BIT(d))));
       assert(!!(result.members[d/32]&BIT(d%32))==permitted);
      }
      pure_cases++;
     }
   }
 struct rtl_l2_port_policy keep={123,{456,789}};
 result=keep;
 assert(rtl_l2_port_policy_build(0,0,0,0,16,&result)==-EINVAL);
 assert(rtl_l2_port_policy_build(32,0,0,0,16,&result)==-EINVAL);
 assert(rtl_l2_port_policy_build(3,4,0,0,16,&result)==-EINVAL);
 assert(rtl_l2_port_policy_build(3,0,4,0,16,&result)==-EINVAL);
 assert(rtl_l2_port_policy_build(3,0,0,5,16,&result)==-EINVAL);
 assert(rtl_l2_port_policy_build(3,0,0,31,16,&result)==-EINVAL);
 assert(rtl_l2_port_policy_build(3,0,0,32,16,&result)==-EINVAL);
 assert(rtl_l2_port_policy_build(3,0,0,2,16,&result)==-EINVAL);
 assert(rtl_l2_port_policy_build(3,0,0,0,0,&result)==-EINVAL);
 assert(rtl_l2_port_policy_build(3,0,0,0,32,&result)==-EINVAL);
 assert(rtl_l2_port_policy_build(3,0,0,0,16,NULL)==-EINVAL);
 assert(!memcmp(&result,&keep,sizeof(result)));
 assert(rtl_l2_port_policy_mc_check(1));
 assert(rtl_l2_port_policy_mc_check(0xa5000001));
 assert(!rtl_l2_port_policy_mc_check(0));
 assert(!rtl_l2_port_policy_mc_check(0xa5000000));
 assert(!rtl_l2_port_policy_mc_check(~0U));
}

static unsigned int begin(unsigned int ports, bool l3)
{
 reset();fe.enabled=fe.prepared=l3;
 model.reg[0x160c/4]=0xa5000001;
 assert(!fe_switch_hw_prepare(&fe,&hw,ports,123,true,true));
 assert(hw.prepared && hw.drained && hw.port_policy_ready);
 assert(hw.local_target==(l3?25U:16U));
 assert(hw.learning_mask==ports && !hw.isolated_mask);
 cpu_only();
 return model.commands;
}

static void check_policy(unsigned int learning, unsigned int isolated)
{
 for(unsigned int p=0;p<5;p++) {
  if(!(hw.ports&BIT(p)))continue;
  assert(fe_switch_hw_field(model.rows[RTL_L2_TBL_ILPB][p],RTL_L2_ILPB_STP)==
         ((learning&BIT(p))?3U:2U));
  for(unsigned int d=0;d<64;d++) {
   bool permitted=d==16 || d==hw.local_target ||
    (d<5 && d!=p && (hw.ports&BIT(d)) && !((isolated&BIT(p)) && (isolated&BIT(d))));
   assert(!!(model.rows[RTL_L2_TBL_PORT_MEMBERSHIP][p][d/32]&BIT(d%32))==permitted);
  }
  /*SDK_CASE*/
 }
 for(unsigned int p=5;p<64;p++)
  assert(!memcmp(model.rows[RTL_L2_TBL_PORT_MEMBERSHIP][p],
                 original.rows[RTL_L2_TBL_PORT_MEMBERSHIP][p],2*sizeof(unsigned int)));
 assert(hw.port_policy_ready && hw.learning_mask==learning && hw.isolated_mask==isolated);
 assert(model.reg[0x160c/4]==0xa5000001); /* never seize shared PON control */
}

static void transactions(void)
{
 static const unsigned int groups[]={31,19,1};
 for(unsigned int l3=0;l3<2;l3++)for(unsigned int g=0;g<ARRAY_SIZE(groups);g++) {
  unsigned int ports=groups[g];begin(ports,l3);unsigned int count=hw.count;
  for(unsigned int learn=0;learn<32;learn++)for(unsigned int isolated=0;isolated<32;isolated++) {
   if((learn|isolated)&~ports)continue;
   assert(!fe_switch_hw_port_policy(&fe,&hw,learn,isolated));
   check_policy(learn,isolated);assert(hw.count==count);cpu_only();cases++;
  }
  assert(fe_switch_hw_arm(&fe,&hw,ports,0,true));
  unsigned int writes=model.writes;
  assert(fe_switch_hw_port_policy(&fe,&hw,0,0)==-EBUSY);
  assert(model.writes==writes); /* a live port cannot be rewritten */
  assert(!fe_switch_hw_drain(&fe,&hw));
  assert(!fe_switch_hw_restore(&fe,&hw));restored();
 }
}

static void zero_age_static_only(void)
{
 /* Execute the exact prepare -> port-policy -> arm sequence used by the
  * worker for Linux hold_time()==0. Neither the bridge-learning flag nor
  * a zero timer with an enabled SA learner may create immortal entries.
  * Preserve the shared hardware divisor and all foreign/PON row owners. */
 for(unsigned int l3=0;l3<2;l3++)for(unsigned int ports=1;ports<32;ports++) {
  reset();fe.enabled=fe.prepared=l3;model.reg[0x160c/4]=0xa5000001;
  assert(!fe_switch_hw_prepare(&fe,&hw,ports,0,true,true));
  assert(model.reg[0x1c04/4]==original.reg[0x1c04/4]);
  assert(!(hw.run_control&BIT(0)) && !(hw.requested_aging&0x7ffffU));
  assert(!fe_switch_hw_port_policy(&fe,&hw,0,0));
  check_policy(0,0);cpu_only();
  assert(fe_switch_hw_arm(&fe,&hw,ports,0,true));
  assert(!(model.reg[0x1c00/4]&BIT(0)));
  assert(model.reg[0x1c04/4]==(original.reg[0x1c04/4]&~0x7ffffU));
  check_policy(0,0);cases++;
  assert(!fe_switch_hw_drain(&fe,&hw));
  assert(!fe_switch_hw_restore(&fe,&hw));restored();
 }
}

static void failed_policy(void)
{
 assert(!hw.port_policy_ready && hw.prepared && hw.globals_owned);
 assert(!fe_switch_hw_arm(&fe,&hw,hw.ports,0,true));
 cpu_only();
}

static void baseline_guards(void)
{
 begin(31,true);
 unsigned int writes=model.writes;
 assert(fe_switch_hw_port_policy(&fe,&hw,32,0)==-EINVAL);
 assert(model.writes==writes);failed_policy();
 assert(!fe_switch_hw_port_policy(&fe,&hw,31,0));
 assert(fe_switch_hw_port_policy(&fe,&hw,0,32)==-EINVAL);
 assert(model.writes>writes);failed_policy();
 for(unsigned int bad=0;bad<2;bad++) {
  begin(31,true);model.reg[0x160c/4]=bad?~0U:0;writes=model.writes;
  assert(fe_switch_hw_port_policy(&fe,&hw,31,3)==-EOPNOTSUPP);
  assert(hw.reason==FE_SW_HW_ISOLATION && model.writes==writes);failed_policy();cases++;
 }
 for(unsigned int kind=0;kind<2;kind++)for(unsigned int p=0;p<32;p++) {
  if(kind && p>=5 && p!=16 && p!=25)continue;
  begin(31,true);writes=model.writes;
  model.rows[kind?RTL_L2_TBL_REDIR_LDPID:RTL_L2_TBL_REDIR_DROP][p][0]=BIT(10);
  assert(fe_switch_hw_port_policy(&fe,&hw,31,3)==-EOPNOTSUPP);
  assert(model.writes==writes && hw.reason==FE_SW_HW_REDIRECT);failed_policy();cases++;
 }
 /* Ordinary bridges and the forwarding subset left by STP need CPU16
  * and all chosen native destinations to remain actual destinations too.
  * No isolation flag is required to reject a redirect into foreign PON. */
 for(unsigned int subset=0;subset<2;subset++)for(unsigned int l3=0;l3<2;l3++)
  for(unsigned int kind=0;kind<2;kind++)for(unsigned int p=0;p<32;p++) {
   unsigned int ports=subset?3U:31U,target=l3?25U:16U;
   if(kind && !(ports&BIT(p)) && p!=16 && p!=target)continue;
   for(unsigned int invalid=0;invalid<2;invalid++) {
    begin(ports,l3);writes=model.writes;
    model.rows[kind?RTL_L2_TBL_REDIR_LDPID:RTL_L2_TBL_REDIR_DROP][p][0]=
     invalid?~0U:BIT(10)|7U;
    assert(fe_switch_hw_port_policy(&fe,&hw,ports,0)==-EOPNOTSUPP);
    assert(model.writes==writes && hw.reason==FE_SW_HW_REDIRECT);failed_policy();cases++;
   }
  }
 for(unsigned int l3=0;l3<2;l3++)for(unsigned int invalid=0;invalid<2;invalid++) {
  reset();fe.enabled=fe.prepared=l3;
  model.rows[RTL_L2_TBL_REDIR_LDPID][16][0]=invalid?~0U:BIT(10)|7U;
  assert(fe_switch_hw_prepare(&fe,&hw,3,123,false,true)==-EOPNOTSUPP);
  assert(!hw.prepared && hw.journal.quarantined && hw.reason==FE_SW_HW_REDIRECT);
  model.rows[RTL_L2_TBL_REDIR_LDPID][16][0]=0;
  assert(!fe_switch_hw_drain(&fe,&hw));
  assert(!fe_switch_hw_restore(&fe,&hw));restored();cases++;
 }
 /* Unrelated LDPID rows do not prevent this domain from using isolation. */
 begin(31,true);model.rows[RTL_L2_TBL_REDIR_LDPID][42][0]=BIT(10)|0x5a;
 assert(!fe_switch_hw_port_policy(&fe,&hw,0,31));check_policy(0,31);cases++;
 /* A missing retained snapshot is an ownership error, not a fresh claim. */
 for(unsigned int table=0;table<2;table++) {
  begin(31,true);
  struct rtl_l2_snapshot *row=fe_switch_hw_snapshot_find(&hw,
   table?RTL_L2_TBL_PORT_MEMBERSHIP:RTL_L2_TBL_ILPB,4);
  assert(row);row->valid=0;writes=model.writes;
  assert(fe_switch_hw_port_policy(&fe,&hw,0,31)==-EIO);
  assert(model.writes==writes);failed_policy();cases++;
 }
 /* No global check is invented for ordinary unicast learning control. */
 begin(31,false);model.reg[0x160c/4]=0;
 assert(!fe_switch_hw_port_policy(&fe,&hw,0,0));
 assert(hw.port_policy_ready && !hw.learning_mask);cases++;
 /* Drift immediately before arm cannot reopen an invalid isolation policy. */
 begin(31,true);assert(!fe_switch_hw_port_policy(&fe,&hw,31,3));
 model.reg[0x160c/4]=0;
 assert(!fe_switch_hw_arm(&fe,&hw,31,0,true));assert(!hw.port_policy_ready);cpu_only();cases++;
}

static void route_policy(void)
{
 /* L3 can remain enabled, but isolated/STP bridge policy may forbid its
  * complete autonomous path, including the reverse PON connector. */
 reset();fe.enabled=fe.prepared=true;model.reg[0x160c/4]=1;
 assert(!fe_switch_hw_prepare(&fe,&hw,31,123,true,false));
 assert(hw.local_target==16 && !hw.route_policy_allowed);
 assert(fe_switch_hw_field(model.rows[RTL_L2_TBL_SPB][hw.special_profile*32+12],
                          RTL_L2_SPB_DESTINATION)==16);
 assert(!fe_switch_hw_port_policy(&fe,&hw,31,3));
 for(unsigned int p=0;p<5;p++)assert(!(model.rows[RTL_L2_TBL_PORT_MEMBERSHIP][p][0]&BIT(25)));
 assert(!fe_switch_hw_arm(&fe,&hw,31,0,true)); /* cannot arm a different policy */
 assert(!fe_switch_hw_arm(&fe,&hw,15,16,false)); /* policy forbids routed ingress */
 assert(fe_switch_hw_arm(&fe,&hw,31,0,false));
 assert(model.route_closed && fe.route_gate_verified && !model.route_arms);cases++;
 assert(!fe_switch_hw_drain(&fe,&hw));
 assert(!fe_switch_hw_restore(&fe,&hw));restored();
 for(unsigned int pending=0;pending<2;pending++) {
  reset();fe.enabled=fe.prepared=true;model.reg[0x160c/4]=1;
  assert(!fe_switch_hw_prepare(&fe,&hw,31,123,true,false));
  fe.pending_withdrawals=pending;model.arm_failure=true;
  assert(!fe_switch_hw_arm(&fe,&hw,31,0,false));
  assert(!model.route_arms && !model.native_writes && !fe.route_gate_verified);cpu_only();cases++;
 }
 /* Native-only with no historical L3 owner is still usable. */
 reset();assert(!fe_switch_hw_prepare(&fe,&hw,31,123,true,false));
 assert(fe_switch_hw_arm(&fe,&hw,31,0,false));assert(!model.route_arms);cases++;
}

static void fault_matrix(void)
{
 unsigned int start=begin(31,true);
 assert(!fe_switch_hw_port_policy(&fe,&hw,0x15,0x0b));
 unsigned int total=model.commands-start;
 for(unsigned int fault=1;fault<=total;fault++) {
  start=begin(31,true);model.fail=start+fault;
  assert(fe_switch_hw_port_policy(&fe,&hw,0x15,0x0b)==-ETIMEDOUT);
  assert(model.pending);failed_policy();
  complete(&model);model.fail=0;
  assert(!fe_switch_hw_drain(&fe,&hw));
  assert(!fe_switch_hw_restore(&fe,&hw));restored();fault_cases++;
 }
 /* A command which reports success but ignores a row write is detected. */
 for(unsigned int t=0;t<2;t++) {
  begin(31,true);model.ignore_write_table=t?RTL_L2_TBL_PORT_MEMBERSHIP:RTL_L2_TBL_ILPB;
  model.ignore_write=true;
  assert(fe_switch_hw_port_policy(&fe,&hw,0,31)==-EIO);failed_policy();
  model.ignore_write=false;assert(!fe_switch_hw_restore(&fe,&hw));restored();fault_cases++;
 }
 /* All-ones/incorrect readback of every policy word must not publish ready. */
 const unsigned int addresses[]={0x11f8,0x11f4,0x11f0,0x11ec,0x11e8,0x157c,0x1578};
 for(unsigned int a=0;a<ARRAY_SIZE(addresses);a++) {
  begin(31,true);model.corrupt_read_address=addresses[a];model.corrupt_read_value=~0U;
  model.corrupt_after_command=model.commands+1;
  assert(fe_switch_hw_port_policy(&fe,&hw,0,31)==-EIO);failed_policy();
  model.corrupt_read_address=0;assert(!fe_switch_hw_restore(&fe,&hw));restored();fault_cases++;
 }
 /* A checker that disappears only after the last indirect transaction is
  * rejected before success; disabling it after success is covered at arm. */
 begin(31,true);model.corrupt_read_address=0x160c;
 model.corrupt_read_value=0;model.corrupt_after_command=model.commands+total;
 assert(fe_switch_hw_port_policy(&fe,&hw,0,31)==-EOPNOTSUPP);failed_policy();fault_cases++;
}

int main(void)
{
 pure_matrix();transactions();zero_age_static_only();baseline_guards();route_policy();fault_matrix();
 printf("{\"pure_mask_cases\":%u,\"transaction_cases\":%u,\"fault_cases\":%u,\"sdk_oracle_cases\":%u}\n",
        pure_cases,cases,fault_cases,sdk_cases);
 return 0;
}
'''

SDK_ORACLE = r'''
typedef unsigned int ca_device_id_t;
typedef unsigned int ca_uint32_t;
typedef unsigned long long ca_uint64_t;
typedef int ca_status_t;
/*SDK_UNIONS*/
/*SDK_STP*/
#define CA_E_OK 0
#define CA_IN
#define L2FE_PLE_PORT_MMSHP_CHK_ACCESS 0x1574U
#define L2FE_PLE_PORT_MMSHP_CHK_DATA1 0x1578U
#define L2FE_PLE_PORT_MMSHP_CHK_DATA0 0x157cU
static unsigned int sdk_source, sdk_words[2];
#define AAL_LPID_CHECK(p) assert((p)<64)
#define __AAL_PORT_LOCK(dev) ((void)(dev))
#define __AAL_PORT_UNLOCK(dev) ((void)(dev))
#define READ_INDIRCT_REG(dev,port,address) do { \
 assert(!(dev) && (address)==0x1574);sdk_source=(port); } while(0)
#define WRITE_INDIRCT_REG(dev,port,address) do { \
 assert(!(dev) && (address)==0x1574 && sdk_source==(port)); } while(0)
#define CA_L2FE_REG_READ(address) sdk_words[((0x157cU-(address))/4)]
#define CA_L2FE_REG_WRITE(value,address) (sdk_words[((0x157cU-(address))/4)]=(value))
/*SDK_SETTER*/
static void sdk_policy_oracle(unsigned int port,unsigned int learning,unsigned int isolated)
{
 L2FE_PP_ILPB_DATA2_t ilpb={.wrd=model.rows[RTL_L2_TBL_ILPB][port][2]};
 assert(ilpb.bf.ilpb_stp_mode==((learning&BIT(port))?
  AAL_STP_STATE_FWD_AND_LEARN:AAL_STP_STATE_FWD_NO_LEARN));
 unsigned long long expected=1ULL<<16|1ULL<<hw.local_target;
 for(unsigned int d=0;d<5;d++)
  if(d!=port && (hw.ports&BIT(d)) && !((isolated&BIT(port))&&(isolated&BIT(d))))expected|=1ULL<<d;
 assert(!sdk_port_membership_set(0,port,expected));
 assert(sdk_source==port);
 assert(sdk_words[0]==model.rows[RTL_L2_TBL_PORT_MEMBERSHIP][port][0]);
 assert(sdk_words[1]==model.rows[RTL_L2_TBL_PORT_MEMBERSHIP][port][1]);
 L2FE_ARB_ARB_CTRL_EXT_t ext={.wrd=RTL_L2_POLICY_MC_MEMBERSHIP_CHECK};
 L2FE_ARB_REDIR_DROP_SRC_CONFIG_TBL_DATA_t drop={.wrd=RTL_L2_POLICY_REDIRECT_ENABLE};
 L2FE_ARB_REDIR_LDPID_CONFIG_TBL_DATA_t redirect={.wrd=RTL_L2_POLICY_REDIRECT_ENABLE};
 assert(ext.bf.mc_pkt_port_mmshp_chk_en && drop.bf.rdir_en && redirect.bf.rdir_en);
 sdk_cases++;
}
'''


def source_for(args):
    base = recipe.TEST.split("\nstatic void recipe(", 1)[0]
    base = base.replace("cases, fault_cases, cold_cases", "cases, fault_cases")
    source = base + TEST
    if not args.sdk:
        return source, False
    if not args.registers:
        raise ValueError("--sdk also requires --registers")
    for name, expected in SDK_FILES.items():
        assert hashlib.sha256((args.sdk / name).read_bytes()).hexdigest() == expected, name
    raw = args.registers.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == recipe.REGISTER_HASH, "Unpinned SDK registers"
    names = ["L2FE_PP_ILPB_DATA2", "L2FE_PLE_PORT_MMSHP_CHK_ACCESS",
             "L2FE_PLE_PORT_MMSHP_CHK_DATA1", "L2FE_PLE_PORT_MMSHP_CHK_DATA0",
             "L2FE_ARB_ARB_CTRL_EXT", "L2FE_ARB_REDIR_DROP_SRC_CONFIG_TBL_DATA",
             "L2FE_ARB_REDIR_LDPID_CONFIG_TBL_DATA"]
    blocks = []
    for name in names:
        match = re.search(r"typedef volatile union \{(?:(?!typedef volatile union).)*?\} " +
                          name + r"_t;", raw.decode(), re.S)
        assert match, name
        blocks.append(match.group())
    header = (args.sdk / "include/aal_port.h").read_text()
    stp = re.search(r"typedef enum \{\s*AAL_STP_STATE_DROP = 0,.*?\} aal_stp_state_t;", header, re.S)
    assert stp
    port = (args.sdk / "aal_port.c").read_text()
    setter = port[port.index("ca_status_t aal_port_mmshp_check_set("):
                  port.index("ca_status_t aal_port_mmshp_check_get(")]
    setter = setter.replace("aal_port_mmshp_check_set", "sdk_port_membership_set")
    arb = (args.sdk / "aal_arb.c").read_text()
    assert "REG_L2FE_FIELD_WRITE(L2FE_ARB_ARB_CTRL_EXT, mc_pkt_port_mmshp_chk_en, 1);" in arb
    oracle = SDK_ORACLE.replace("/*SDK_UNIONS*/", "\n".join(blocks))
    oracle = oracle.replace("/*SDK_STP*/", stp.group()).replace("/*SDK_SETTER*/", setter)
    source = source.replace("/*SDK_ORACLE*/", oracle)
    source = source.replace("/*SDK_CASE*/", "sdk_policy_oracle(p,learning,isolated);")
    return source, True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", type=Path)
    parser.add_argument("--registers", type=Path)
    args = parser.parse_args()
    source, sdk = source_for(args)
    hw, policy = HW.read_text(), POLICY.read_text()
    mutations = {
        "always_learn": (hw, policy.replace("RTL_L2_STP_FORWARD_NO_LEARN;", "RTL_L2_STP_FORWARD_AND_LEARN;", 1)),
        "zero_age_keeps_hardware_aging": (hw.replace("if (ageing)\n\t\thw->run_control |= BIT(0);",
                                                    "if (true)\n\t\thw->run_control |= BIT(0);", 1), policy),
        "symmetric_isolation_misapplied": (hw, policy.replace("if (isolated & (1U << source))", "if (isolated)", 1)),
        "isolated_peers_allowed": (hw, policy.replace("destinations &= ~isolated;", "destinations |= isolated;", 1)),
        "cpu_fallback_removed": (hw, policy.replace("destinations | (1U << RTL_L2_POLICY_CPU) |", "destinations |", 1)),
        "all_ones_checker_accepted": (hw, policy.replace("arb_ext != ~0U &&", "1 &&", 1)),
        "partial_policy_still_ready": (hw.replace("WRITE_ONCE(hw->port_policy_ready, false);", "/* omitted */", 1), policy),
        "arm_accepts_partial_policy": (hw.replace("!READ_ONCE(hw->port_policy_ready) ||", "/* omitted */", 1), policy),
        "ignored_redirects": (hw.replace("if (words[0] & RTL_L2_POLICY_REDIRECT_ENABLE)", "if (false)"), policy),
        "membership_not_verified": (recipe.without_table_verification(hw, "RTL_L2_TBL_PORT_MEMBERSHIP"), policy),
        "stp_not_verified": (recipe.without_table_verification(hw, "RTL_L2_TBL_ILPB"), policy),
        "checker_not_rechecked": (hw.replace("if (isolated_mask &&\n\t    !rtl_l2_port_policy_mc_check(fe_read(fe, RTL_L2_POLICY_ARB_EXT)))", "if (false)", 1), policy),
        "mymac_ignores_route_policy": (hw.replace("hw->route_policy_allowed && fe->enabled && fe->prepared ? 25 : 16", "fe->enabled && fe->prepared ? 25 : 16", 1), policy),
        "gate_failure_ignored": (hw.replace("if (!READ_ONCE(fe->route_gate_verified))", "if (false)", 1), policy),
        "unconditionally_reopen_l3": (hw.replace("if (route_policy_allowed && !withdrawing &&", "if (!withdrawing &&", 1), policy),
    }
    assert all(value != (hw, policy) for value in mutations.values())
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    environment = dict(os.environ)
    environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
    with tempfile.TemporaryDirectory(prefix="thoros-l2-policy-") as temporary:
        build = Path(temporary)
        (build / "linux").mkdir()
        (build / "linux/delay.h").write_text("/* transport delay stub */\n")
        (build / "linux/string.h").write_text("#include <string.h>\n")
        (build / "test.c").write_text(source)
        for name, (hardware, compiler) in [("production", (hw, policy)), *mutations.items()]:
            (build / HW.name).write_text(hardware)
            (build / POLICY.name).write_text(compiler)
            subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-Wno-unused-function", "-O1", "-g", "-fsanitize=address,undefined",
                            "-fno-omit-frame-pointer", "-no-pie", "-I", str(build), "-I", str(DRIVERS),
                            str(build / "test.c"), "-o", str(build / "test")], check=True)
            result = subprocess.run([str(build / "test")], env=environment, capture_output=True, text=True)
            if name == "production":
                assert result.returncode == 0, result.stderr
                evidence = json.loads(result.stdout)
                print(result.stdout.strip())
            else:
                assert result.returncode != 0 and "Assertion" in result.stderr, (name, result.stderr)
    evidence.update({"mutations_rejected": list(mutations), "sdk_contract_verified": sdk,
                     "hardware_header_sha256": hashlib.sha256(HW.read_bytes()).hexdigest(),
                     "port_policy_sha256": hashlib.sha256(POLICY.read_bytes()).hexdigest(),
                     "sanitizers": ["address", "undefined"], "hardware_tested": False})
    (ROOT / "artifacts").mkdir(exist_ok=True)
    (ROOT / "artifacts/l2-port-policy.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"Port-policy self-check: rejected {len(mutations)} faulty implementations")


if __name__ == "__main__":
    main()
