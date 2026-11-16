#!/usr/bin/env python3
"""Run the production immutable MCE builder, cold root audit and CPU decoder.

The oracle performs real ACCESS/DATA transactions and records ordering;
it does not pretend that emulated registers prove ASIC queue retirement.
The bridge/gate lifetime is separately exercised by test_l2_policy_races.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"


def transport():
    tree = ast.parse((ROOT / "scripts/test_l2_resources.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "TEST" for t in node.targets):
            return ast.literal_eval(node.value).split("static void geometry_and_capacity(void)")[0]
    raise AssertionError("missing real table-transport oracle")


def function(source, name):
    found = re.search(r"^(?:static\s+)?(?:int|void|ssize_t)\s+(?:__maybe_unused\s+)?" + name + r"\(", source, re.M)
    if not found:
        raise AssertionError(name)
    start = source.index("{", found.start())
    depth = 1
    end = start + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[found.start():end] + "\n"


SETUP = r'''
#include <stdint.h>
#include "rtl9617c-mcast-cold.h"
static struct rtl_l2_owner owner;
static struct rtl_mcast_state state;
static unsigned test_cases,test_faults;
static int fdb_index;
static unsigned fdb_words[4],direct_writes;
static void cold_write(void *ctx,unsigned reg,unsigned value) {
 if(reg==RTL_MCAST_CONTROL || reg==RTL_L2_FDB_RETURN ||
    (reg<=RTL_L2_FDB_FILTER_WORD0 && reg>=RTL_L2_FDB_FILTER_WORD0-16) ||
    (reg<=RTL_L2_FDB_DATA0 && reg>=RTL_L2_FDB_DATA0-12)) {
  m.regs[reg/4]=value;direct_writes++;return;
 }
 mm_write(ctx,reg,value);
}
static int cold_command(void *ctx,unsigned reg,unsigned value) {
 if(reg!=RTL_L2_FDB_ACCESS)return mm_command(ctx,reg,value);
 unsigned start=(value>>8)&8191;
 assert((value&255)==RTL_L2_FDB_SCAN && (value&RTL_L2_ACCESS_BUSY));
 assert(m.regs[RTL_L2_FDB_CONTROL/4]&(RTL_L2_FDB_CMD_MODE|RTL_L2_FDB_LEARN_DISABLE));
 if(fdb_index>=0 && (unsigned)fdb_index>=start) {
  m.regs[RTL_L2_FDB_RETURN/4]=5U|((unsigned)fdb_index<<4);
  for(unsigned i=0;i<4;i++)m.regs[(RTL_L2_FDB_DATA0-i*4)/4]=fdb_words[i];
 } else m.regs[RTL_L2_FDB_RETURN/4]=15;
 return 0;
}
static const struct rtl_dq_io cold_io={NULL,mm_read,cold_write,cold_command};
static void fresh(void) {
 reset(1);memset(&owner,0,sizeof(owner));memset(&state,0,sizeof(state));
 memset(m.rows,0,sizeof(m.rows));fdb_index=-1;direct_writes=0;
 m.regs[RTL_L2_FDB_CONTROL/4]=RTL_L2_FDB_CMD_MODE|RTL_L2_FDB_LEARN_DISABLE;
 m.regs[RTL_L2_VLAN_MODE_CONTROL/4]=1;
 m.regs[RTL_MCAST_CONTROL/4]=0x0002f0ff;
 m.regs[RTL_MCAST_NI_SOURCE/4]=0x0024009b;
 assert(!rtl_l2_owner_init(&owner,rows,row_index,rtl_l2_journal_index_count(),19));
}
static void ready(void) {
 fresh();assert(!rtl_mcast_cold_prepare(&state,&owner,&cold_io));
 assert(state.contract_ready && owner.ready_mask==RTL_L2_OWNER_MC_READY);
 assert(!(m.regs[RTL_MCAST_CONTROL/4]&RTL_MCAST_COPY_LSPID_TO_POL));
 rtl_l2_owner_seal(&owner);
}
static int group(unsigned long long epoch,unsigned port,unsigned egress,unsigned short *id) {
 return rtl_mcast_group_prepare(&state,&owner,&io,5,epoch,port,port+10,31,0,egress,id);
}
static void handoff_contract(void) {
 const unsigned registers[]={0xaa28,0x3400,0x3834,0x38a0,0xaa60};
 /* These literal addresses are independent of the production probe's
  * array and name the pinned CPUXRAM_CFG/STG0_CTRL/HASH_INI/CACHE_INI/
  * MCE_CTL_REG configuration words, never their adjacent counters. */
 fresh();struct rtl_mcast_handoff observed;
 for(unsigned i=0;i<5;i++)m.regs[registers[i]/4]=0x12345600U+i;
 unsigned commands=m.command,writes=direct_writes;

 /* A read-only observer is allowed to sample the five direct CSR words
  * before any MCE owner or table-command window has been established.
  * Sampling is deliberately not an ownership or retirement ACK. */
 const struct rtl_dq_io read_only={NULL,mm_read,NULL,NULL};
 assert(rtl_mcast_handoff_sample(&observed,&read_only)==0);
 assert(observed.valid_mask==31&&observed.missing==31&&observed.reads==5);
 assert(rtl_mcast_handoff_probe(&observed,&read_only)==-EOPNOTSUPP);
 assert(m.command==commands&&direct_writes==writes);
 assert(rtl_mcast_handoff_probe(&observed,&cold_io)==-EOPNOTSUPP);
 assert(observed.valid_mask==31&&observed.missing==31&&observed.reads==5);
 for(unsigned i=0;i<5;i++)assert(observed.value[i]==0x12345600U+i);
 assert(!observed.bad_register&&!observed.bad_value);
 assert(m.command==commands&&direct_writes==writes);
 /* A failed sample is not a valid zero, and must not suppress other
  * independent samples or clear any unproven retirement contract. */
 for(unsigned failed=0;failed<5;failed++) {
  m.regs[registers[failed]/4]=~0U;
  assert(rtl_mcast_handoff_sample(&observed,&read_only)==-EIO);
  assert(observed.valid_mask==(31U^(1U<<failed))&&observed.missing==31);
  assert(rtl_mcast_handoff_probe(&observed,&cold_io)==-EIO);
  assert(observed.valid_mask==(31U^(1U<<failed))&&observed.missing==31);
  assert(observed.bad_register==registers[failed]&&observed.bad_value==~0U);
  assert(observed.reads==5&&m.command==commands&&direct_writes==writes);
  m.regs[registers[failed]/4]=0x12345600U+failed;
 }
 /* Zero hash/cache values, XRAM TX disabled, a flush request and equal
  * MCE counters do not manufacture a producer or packet-retirement ACK. */
 for(unsigned flush=0;flush<2;flush++)for(unsigned xram=0;xram<2;xram++) {
  for(unsigned i=0;i<5;i++)m.regs[registers[i]/4]=0;
  m.regs[0xaa28/4]=xram<<9;m.regs[0xaa60/4]=flush<<18;
  m.regs[0xaa74/4]=m.regs[0xaa78/4]=1234;
  assert(rtl_mcast_handoff_probe(&observed,&cold_io)==-EOPNOTSUPP);
  assert(observed.valid_mask==31&&observed.missing==31&&!observed.bad_register);
  assert(m.command==commands&&direct_writes==writes);
 }
 assert(rtl_mcast_handoff_probe(NULL,&cold_io)==-EINVAL);
 assert(rtl_mcast_handoff_probe(&observed,NULL)==-EINVAL);
 assert(rtl_mcast_handoff_sample(NULL,&read_only)==-EINVAL);
 assert(rtl_mcast_handoff_sample(&observed,NULL)==-EINVAL);
 test_cases+=21;
}
static void matrix(void) {
 ready();unsigned short ids[5][32]={{0}};
 for(unsigned p=0;p<5;p++)for(unsigned mask=1;mask<32;mask++) {
  if(mask&(1U<<p))continue;
  unsigned short g=0;assert(!group(10,p,mask,&g));assert(g&&g<256);
  ids[p][mask]=g;unsigned t=state.vector[g].token;
  assert(t&&t<512&&state.token[t].ingress==p&&state.token[t].generation==10);
  assert(state.token[t].ingress_ifindex==(int)p+10&&state.token[t].master_ifindex==31);
  unsigned a=state.token[t].action;unsigned long long expected=1ULL<<a;
  assert((m.rows[RTL_L2_TBL_MC_FIB][a][0]>>23)==t);
  assert(m.rows[RTL_L2_TBL_MC_FIB][a][1]==(16U<<24|1U<<30));
  assert(m.rows[RTL_L2_TBL_MC_FIB][a][2]==1U);
  for(unsigned d=0;d<5;d++)if(mask&(1U<<d)) {
   a=state.lan_action[d];expected|=1ULL<<a;
   assert(m.rows[RTL_L2_TBL_MC_FIB][a][0]==0);
   assert(m.rows[RTL_L2_TBL_MC_FIB][a][1]==(d<<24|1U<<30));
   assert(m.rows[RTL_L2_TBL_MC_FIB][a][2]==1);
  }
  assert(rtl_l2_bitmap_decode(m.rows[RTL_L2_TBL_MC_VECTOR][g])==expected);
  assert(!state.token[t].published || state.tokens>=1);
  assert(!rtl_mcast_group_publish(&state,&owner,g));
  assert(state.token[t].published && state.vector[g].published&&state.vector[g].active);
  assert(rtl_l2_owner_has(owner.published[RTL_L2_SHARED_MC_FIB],state.token[t].action));
  unsigned n=m.command;unsigned short again=0;
  assert(!group(10,p,mask,&again)&&again==g&&m.command==n);
  assert(!rtl_mcast_group_publish(&state,&owner,g)&&owner.active[2][g]==1);
  test_cases++;
 }
 assert(state.groups==75&&state.tokens==5&&rtl_l2_shared_leased(&owner.ledger,1)==10);
 unsigned old=ids[0][2],token=state.vector[old].token;
 unsigned before[3];memcpy(before,m.rows[RTL_L2_TBL_MC_FIB][state.token[token].action],12);
 unsigned short g=0;
 assert(!group(11,0,2,&g)&&g!=old&&state.vector[g].token!=token);
 assert(!memcmp(before,m.rows[RTL_L2_TBL_MC_FIB][state.token[token].action],12));
 assert(!rtl_mcast_group_retire(&state,&owner,old)&&!state.vector[old].active);
 assert(state.vector[old].published&&state.token[token].published);
 assert(rtl_l2_owner_abort(&owner,&io,2,old)==-EBUSY);
 assert(rtl_l2_owner_write(&owner,&io,1,state.token[token].action,before)==-EBUSY);
 test_cases+=4;
}
static void bounds_and_exhaustion(void) {
 ready();unsigned short out=1234;
 assert(rtl_mcast_group_prepare(&state,&owner,&io,5,1,0,10,31,1,2,&out)==-EOPNOTSUPP&&out==1234);
 assert(group(1,0,1,&out)==-EINVAL&&out==1234);
 assert(group(1,5,2,&out)==-EINVAL);
 assert(group(1,0,32,&out)==-EINVAL);
 assert(group(1,0,0,&out)==-EOPNOTSUPP);
 unsigned count=0;for(unsigned epoch=1;epoch<100;epoch++) {
  int ret=group(epoch,0,2,&out);
  if(ret) {assert(ret==-ENOSPC);break;}
  assert(!rtl_mcast_group_publish(&state,&owner,out));count++;
 }
 assert(count==59 && state.tokens==59 && rtl_l2_shared_leased(&owner.ledger,1)==64);
 unsigned commands=m.command;assert(group(100,0,2,&out)==-ENOSPC&&m.command==commands);
 test_cases+=7;
}
static void unpublished_abort(void) {
 ready();unsigned short first,second;
 assert(!group(2,0,2,&first));
 assert(!rtl_mcast_abort_unpublished(&state,&owner,&io));
 assert(!state.groups&&!state.tokens&&!state.lan_ready&&!rtl_l2_owner_retained(&owner));
 assert(!group(2,0,2,&first));assert(!rtl_mcast_group_publish(&state,&owner,first));
 unsigned token=state.vector[first].token;
 assert(!group(3,0,2,&second)&&state.vector[second].token!=token);
 assert(!rtl_mcast_abort_unpublished(&state,&owner,&io));
 assert(state.groups==1&&state.tokens==1&&state.lan_ready);
 assert(state.vector[first].published&&state.token[token].published);
 assert(!state.vector[second].allocated&&rtl_l2_owner_retained(&owner));
 assert(!rtl_mcast_group_retire(&state,&owner,first));
 assert(!rtl_mcast_abort_unpublished(&state,&owner,&io));
 assert(state.vector[first].published&&state.token[token].published);
 assert(rtl_l2_owner_has(owner.published[1],state.token[token].action));test_cases+=3;
}
static void capacity_preflight(void) {
 unsigned short claimed[255],out=1234;
 /* A full vector bank must not first install LAN recipes or a CPU token. */
 ready();assert(!rtl_l2_owner_reserve(&owner,2,255,claimed));
 unsigned commands=m.command;
 for(unsigned i=0;i<3;i++)assert(group(1,0,2,&out)==-ENOSPC&&out==1234);
 assert(m.command==commands&&!state.lan_ready&&!state.tokens&&!state.groups);
 assert(!rtl_l2_shared_leased(&owner.ledger,1)&&state.capacity_fallbacks==3);
 /* Five free actions can fit LAN-only, but not a complete new group. */
 ready();assert(!rtl_l2_owner_reserve(&owner,1,59,claimed));commands=m.command;
 assert(group(1,0,2,&out)==-ENOSPC&&m.command==commands);
 assert(!state.lan_ready&&!state.tokens&&!state.groups);
 assert(rtl_l2_shared_leased(&owner.ledger,1)==59);
 /* Exhausted provenance space must also be rejected before any write. */
 ready();memset(state.forbidden_token,0xff,sizeof(state.forbidden_token));commands=m.command;
 assert(group(1,0,2,&out)==-ENOSPC&&m.command==commands);
 assert(!state.lan_ready&&!rtl_l2_shared_leased(&owner.ledger,1));
 /* Reusing the SAME immutable recipe needs no free slot, but a new
  * generation must not consume a token when no vector can follow it. */
 ready();unsigned short existing;assert(!group(1,0,2,&existing));
 assert(!rtl_mcast_group_publish(&state,&owner,existing));
 assert(!rtl_l2_owner_reserve(&owner,2,254,claimed));commands=m.command;
 assert(!group(1,0,2,&out)&&out==existing&&m.command==commands);
 assert(group(2,0,2,&out)==-ENOSPC&&m.command==commands);
 assert(state.tokens==1&&state.groups==1&&rtl_l2_shared_leased(&owner.ledger,1)==6);
 assert(group(0,0,2,&out)==-EINVAL&&m.command==commands);
 unsigned token=state.vector[existing].token;state.vector[existing].token=512;
 assert(rtl_mcast_group_publish(&state,&owner,existing)==-EPERM);
 state.vector[existing].token=token;
 test_cases+=8;
}
static void transaction_faults(void) {
 ready();unsigned before=m.command;unsigned short g;
 assert(!group(1,0,2,&g));unsigned operations=m.command-before;
 for(unsigned fault=1;fault<=operations;fault++) {
  ready();m.error=-ETIMEDOUT;m.fault_at=m.command+fault;
  int ret=group(1,0,2,&g);assert(ret==-ETIMEDOUT && m.pending && owner.ledger.quarantined);
  for(unsigned i=1;i<256;i++)assert(!state.vector[i].published);
  for(unsigned i=1;i<512;i++)assert(!state.token[i].published);
  unsigned stalled=m.command;
  assert(rtl_mcast_abort_unpublished(&state,&owner,&io)==-ETIMEDOUT&&m.command==stalled);
  complete(true);unsigned commands=m.command;
  assert(group(2,0,2,&g)==-EOPNOTSUPP&&m.command==commands);
  assert(rtl_mcast_abort_unpublished(&state,&owner,&io)==-ETIMEDOUT&&m.command==commands);
  test_faults++;
 }
}
static void cold_roots(void) {
 const enum rtl_l2_table roots[]={RTL_L2_TBL_DFT_FWD,RTL_L2_TBL_VLAN_FIB,RTL_L2_TBL_CF_FIB};
 for(unsigned r=0;r<3;r++) {
  fresh();m.regs[RTL_MCAST_CONTROL/4]&=~RTL_MCAST_COPY_LSPID_TO_POL;
  if(r==0)m.rows[roots[r]][7][0]=1U<<12|23U<<1;
  if(r==1)m.rows[roots[r]][127][1]=23;
  if(r==2) {
   m.rows[RTL_L2_TBL_CF_KEY][511][2]=m.rows[RTL_L2_TBL_CF_KEY][1023][2]=1U<<16;
   m.rows[roots[r]][511][1]=4U<<5|23U<<8;
  }
  m.rows[RTL_L2_TBL_MC_VECTOR][23][1]=1U<<31;
  assert(!rtl_mcast_cold_prepare(&state,&owner,&cold_io));
  assert(rtl_l2_owner_has(owner.ledger.bank[2].foreign,23));
  assert(rtl_l2_owner_has(owner.ledger.bank[1].foreign,63));test_cases++;
 }
 for(unsigned side=0;side<2;side++) {
  fresh();m.rows[RTL_L2_TBL_CF_KEY][511+side*512][2]=1U<<16;
  assert(rtl_mcast_cold_prepare(&state,&owner,&cold_io)==-EOPNOTSUPP);
  assert(!owner.ready_mask&&!state.contract_ready);test_cases++;
 }
 for(unsigned root=0;root<3;root++)for(unsigned high=256;high<1024;high+=257) {
  fresh();if(root==0)m.rows[RTL_L2_TBL_DFT_FWD][255][0]=1U<<12|high<<1;
  if(root==1)m.rows[RTL_L2_TBL_VLAN_FIB][127][1]=high;
  if(root==2) {struct rtl_l2_fdb_entry e={.destination=high,.multicast=1,.valid=1};
   assert(!rtl_l2_fdb_encode(fdb_words,&e));fdb_index=4127;}
  assert(rtl_mcast_cold_prepare(&state,&owner,&cold_io)==-EOPNOTSUPP);
  assert(!owner.ready_mask&&!state.contract_ready);test_cases++;
 }
 fresh();m.rows[RTL_L2_TBL_SPB][255][0]=1U<<5;
 assert(rtl_mcast_cold_prepare(&state,&owner,&cold_io)==-EOPNOTSUPP);test_cases++;
 fresh();m.rows[RTL_L2_TBL_IPPB][4][0]=27;
 assert(rtl_mcast_cold_prepare(&state,&owner,&cold_io)==-EOPNOTSUPP);test_cases++;
 fresh();m.rows[RTL_L2_TBL_REDIR_LDPID][4][0]=1U<<10|27U<<4;
 assert(rtl_mcast_cold_prepare(&state,&owner,&cold_io)==-EOPNOTSUPP);test_cases++;
 fresh();m.regs[RTL_L2_VLAN_MODE_CONTROL/4]|=RTL_MCAST_ELPB_RELOOKUP;
 assert(rtl_mcast_cold_prepare(&state,&owner,&cold_io)==-EOPNOTSUPP);test_cases++;
 fresh();m.rows[RTL_L2_TBL_DFT_FWD][255][0]=1U<<12|255U<<1;
 m.rows[RTL_L2_TBL_MC_VECTOR][255][0]=1;
 assert(rtl_mcast_cold_prepare(&state,&owner,&cold_io)==-EOPNOTSUPP);
 assert(m.regs[RTL_MCAST_CONTROL/4]&RTL_MCAST_COPY_LSPID_TO_POL);test_cases++;
 fresh();for(unsigned i=0;i<64;i++)m.rows[RTL_L2_TBL_MC_FIB][i][0]=(i+1)<<23;
 assert(!rtl_mcast_cold_prepare(&state,&owner,&cold_io));
 unsigned short g;assert(!group(1,0,2,&g));assert(state.vector[g].token==128);test_cases++;
 fresh();for(unsigned i=0;i<8;i++)m.rows[RTL_L2_TBL_MC_FIB][i][0]=(i*64U)<<23;
 assert(!rtl_mcast_cold_prepare(&state,&owner,&cold_io));
 assert(group(1,0,2,&g)==-ENOSPC);test_cases++;
 ready();assert(!group(1,0,2,&g));assert(state.vector[g].token>=64);
 for(unsigned p=0;p<64;p++)assert(rtl_l2_owner_has(state.forbidden_token,p));
 test_cases++;
}
'''

RX_SHIM = r'''
#include <stdarg.h>
#include <sys/types.h>
typedef uint32_t u32;typedef uint16_t u16;typedef uint64_t u64;
#define BIT(n) (1U<<(n))
#define READ_ONCE(x) (x)
#define smp_load_acquire(p) (*(p))
#define smp_store_release(p,v) (*(p)=(v))
#define __maybe_unused __attribute__((unused))
#define SKB_EXT_RTL9617C_MCAST 1
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88a8
struct rtl9617c_mcast_copy {u64 owner,generation;int ingress_ifindex,master_ifindex;u16 vid,token;};
struct sk_buff {unsigned char data[64];struct rtl9617c_mcast_copy copy;bool has_copy;};
struct rtl_fe_mcast {struct rtl_mcast_state state;};
struct rtl_fe {struct rtl_fe_mcast *mcast;};
static int scnprintf(char *buffer,size_t bytes,const char *format,...) {
 va_list args;va_start(args,format);int length=vsnprintf(buffer,bytes,format,args);va_end(args);
 return !bytes?0:(size_t)length<bytes?length:(int)bytes-1;
}
static bool allocation_fail;
static void *skb_ext_add(struct sk_buff *skb,unsigned id) {
 assert(id==SKB_EXT_RTL9617C_MCAST);if(allocation_fail)return NULL;skb->has_copy=true;return &skb->copy;
}
static bool is_link_local_ether_addr(const unsigned char *a) {
 const unsigned char p[]={1,0x80,0xc2,0,0};return !memcmp(a,p,5)&&a[5]<=15;
}
'''

RX_TEST = r'''
static void cached_evidence(void) {
 struct rtl_fe fe={0};char buffer[1024];unsigned commands=m.command,writes=direct_writes;
 assert(fe_mcast_evidence(&fe,buffer,sizeof(buffer))>0);
 assert(strstr(buffer,"not-attempted")&&strstr(buffer,"mce_sample_valid=0x0"));
 struct rtl_fe_mcast mc={0};fe.mcast=&mc;
 mc.state.handoff.missing=31;mc.state.handoff.valid_mask=23;
 mc.state.handoff.value[RTL_MCAST_HANDOFF_CACHE]=~0U;
 mc.state.capacity_fallbacks=3;mc.state.unpublished_aborts=2;
 assert(fe_mcast_evidence(&fe,buffer,sizeof(buffer))>0);
 assert(strstr(buffer,"mce_missing_contracts=0x1f")&&strstr(buffer,"mce_sample_valid=0x17"));
 assert(strstr(buffer,"mce_cache_ini=0xffffffff")&&strstr(buffer,"mce_capacity_fallbacks=3"));
 assert(strstr(buffer,"mce_unpublished_aborts=2")&&strstr(buffer,"mce_cold_handoff_verified=0"));
 char small[33];memset(small,0x5a,sizeof(small));
 assert(fe_mcast_evidence(&fe,small,32)==31&&small[31]==0&&small[32]==0x5a);
 assert(!fe_mcast_evidence(&fe,small,0));
 assert(m.command==commands&&direct_writes==writes);test_cases+=3;
}
static void rx_contract(void) {
 ready();unsigned short group_id;assert(!group(53,2,3,&group_id));
 assert(!rtl_mcast_group_publish(&state,&owner,group_id));
 static struct rtl_fe_mcast mc;mc.state=state;struct rtl_fe fe={.mcast=&mc};
 mc.state.active_owner=5;mc.state.active_generation=53;fe_mcast_arm(&fe,53);
 unsigned id=mc.state.vector[group_id].token;
 for(unsigned type=0;type<4;type++)for(unsigned packet=0;packet<4;packet++)
  for(unsigned cpu=0;cpu<2;cpu++)for(unsigned mirror=0;mirror<2;mirror++) {
   struct sk_buff skb={.data={2}};unsigned source=27;
   unsigned h0=(id<<18)|(packet<<11)|(mirror<<14)|(cpu<<31),h1=(27U<<9)|(type<<30);
   int ret=rtl_fe_mcast_rx(&fe,&skb,h0,h1,&source);
   bool accepted=type!=3 && !mirror;
   assert((ret==1)==accepted);
   if(accepted) {
    assert(source==2 && skb.has_copy && skb.copy.owner==5&&skb.copy.generation==53);
    assert(skb.copy.ingress_ifindex==12&&skb.copy.master_ifindex==31&&skb.copy.token==id);
   } else assert(ret==-EACCES&&!skb.has_copy&&source==27);
   test_cases++;
  }
 struct sk_buff skb={.data={2}};unsigned source=27,h0=id<<18|1U<<11,h1=27U<<9;
 mc.state.active_generation++;assert(rtl_fe_mcast_rx(&fe,&skb,h0,h1,&source)<0);
 mc.state.active_generation--;mc.state.active_owner++;assert(rtl_fe_mcast_rx(&fe,&skb,h0,h1,&source)<0);
 mc.state.active_owner--;allocation_fail=true;
 assert(rtl_fe_mcast_rx(&fe,&skb,h0,h1,&source)<0&&mc.state.rx_no_memory==1);allocation_fail=false;
 fe_mcast_revoke(&fe);assert(rtl_fe_mcast_rx(&fe,&skb,h0,h1,&source)<0);
 assert(rtl_fe_mcast_rx(&fe,&skb,h0,3U<<9,&source)==0);
 fe_mcast_arm(&fe,53);unsigned char reserved[]={1,0x80,0xc2,0,0,0};memcpy(skb.data,reserved,6);
 assert(rtl_fe_mcast_rx(&fe,&skb,h0,h1,&source)<0);
 assert(rtl_fe_mcast_rx(NULL,&skb,h0,h1,&source)<0);test_cases+=7;
 skb=(struct sk_buff){.data={2}};skb.data[12]=0x81;
 assert(rtl_fe_mcast_rx(&fe,&skb,h0,h1,&source)<0);
 skb.data[12]=0x88;skb.data[13]=0xa8;
 assert(rtl_fe_mcast_rx(&fe,&skb,h0,h1,&source)<0);test_cases+=2;
}
int main(void) {
 handoff_contract();matrix();bounds_and_exhaustion();unpublished_abort();capacity_preflight();transaction_faults();cold_roots();cached_evidence();rx_contract();
 printf("{\"cases\":%u,\"fault_points\":%u,\"state_bytes\":%zu,\"hardware_verified\":false}\n",
        test_cases,test_faults,sizeof(state));
}
'''


def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run(headers, sanitize):
    with tempfile.TemporaryDirectory(prefix="mcast-runtime-") as directory:
        work = Path(directory)
        (work / "linux").mkdir()
        (work / "linux/errno.h").write_text("#include <asm-generic/errno.h>\n")
        (work / "linux/string.h").write_text("#include <string.h>\n")
        for name, text in headers.items():
            (work / name).write_text(text)
        source = (DRIVER / "rtl9617c-fe-mcast.h").read_text()
        actual = "\n".join(function(source, name) for name in
                            ("fe_mcast_revoke", "fe_mcast_arm", "fe_mcast_evidence", "rtl_fe_mcast_rx"))
        (work / "test.c").write_text(transport() + SETUP + RX_SHIM + actual + RX_TEST)
        cmd = [os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
               "-Wno-unused-function", "-Wno-unused-variable", "-I", str(work), "-I", str(DRIVER),
               str(work / "test.c"), "-o", str(work / "test")]
        if sanitize:
            cmd[1:1] = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie"]
        subprocess.run(cmd, check=True)
        env = os.environ.copy()
        env["ASAN_OPTIONS"] = env.get("ASAN_OPTIONS", "") + ":detect_leaks=0"
        return subprocess.run([str(work / "test")], capture_output=True, text=True,
                              env=env, preexec_fn=no_core)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-sanitize", action="store_true")
    parser.add_argument("--mutants", action="store_true")
    args = parser.parse_args()
    names = ["rtl9617c-mcast-state.h", "rtl9617c-mcast-cold.h", "rtl9617c-mcast-handoff.h"]
    headers = {name: (DRIVER / name).read_text() for name in names}
    result = run(headers, not args.no_sanitize)
    if result.returncode:
        raise SystemExit(result.stdout + result.stderr)
    print(result.stdout, end="")
    rejected = []
    if args.mutants:
        mutations = {
            "ingress_reflection": (names[0], "(egress & (1U << ingress))", "0"),
            "epoch_aba": (names[0], "copy->generation == generation", "1"),
            "all_lan_bits": (names[0], "if (egress & (1U << port))", "if (1)"),
            "partial_action_capacity": (names[0], ") + new_token;", ");"),
            "skip_vector_preflight": (names[0], "!rtl_l2_shared_available(&owner->ledger, RTL_L2_SHARED_MC_VECTOR)", "0"),
            "zero_epoch_token": (names[0], "|| !generation ||", "||"),
            "timeout_downgraded_to_fallback": (names[0], "return ret == -EOPNOTSUPP || ret == -ENOSPC ? -EIO : ret;", "return -EOPNOTSUPP;"),
            "quarantine_downgraded_to_fallback": (names[0], "return owner->error && owner->error != -EOPNOTSUPP &&\n\t\t\towner->error != -ENOSPC ? owner->error : -EIO;", "return -EOPNOTSUPP;"),
            "group_high_alias": (names[1], "if (group >= RTL_L2_MC_VECTOR_ENTRIES)", "if (0 && group >= RTL_L2_MC_VECTOR_ENTRIES)"),
            "one_sided_valid": (names[1], "if ((x[2] ^ y[2]) & (1U << 16))", "if (0 && ((x[2] ^ y[2]) & (1U << 16)))"),
            "old_cp_token_alias": (names[1], "value | source", "value"),
            "skip_mce_retirement_contract": (names[2], "RTL_MCAST_NEEDS_DDR_RETIRE | RTL_MCAST_NEEDS_MCE_RETIRE)", "RTL_MCAST_NEEDS_DDR_RETIRE)"),
            "invalid_sample_marked_valid": (names[2], "if (value == ~0U)", "if (0)"),
            "xram_disabled_implies_handoff": (names[2], "return ret;", "return (state->value[0] & (1U << 9)) ? 0 : ret;"),
            "read_counter_instead_of_config": (names[2], "0x38a0, 0xaa60,", "0x38a0, 0xaa74,"),
        }
        for label, (name, old, new) in mutations.items():
            if old not in headers[name]:
                raise AssertionError(label)
            candidate = dict(headers)
            candidate[name] = headers[name].replace(old, new)
            result = run(candidate, not args.no_sanitize)
            if not result.returncode:
                raise AssertionError("mutation survived: " + label)
            rejected.append(label)
        print("MCE mutation invariants rejected: " + ", ".join(rejected))
    evidence = {"headers": {name: hashlib.sha256(text.encode()).hexdigest() for name, text in headers.items()},
                "mutations_rejected": rejected, "hardware_verified": False,
                "scope": "actual cold table enumeration, immutable recipe transactions and production CPU decoder"}
    (ROOT / "artifacts").mkdir(exist_ok=True)
    (ROOT / "artifacts/mcast-runtime.json").write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()
