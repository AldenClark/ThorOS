#!/usr/bin/env python3
"""Execute the cold fabric owner against inherited state and MMIO failures.

The model checks control ownership, ordering and readback. It does not model
ASIC timing or establish a full L3/DDR retirement contract.
"""
import hashlib
import argparse
import json
import os
from pathlib import Path
import resource
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"
HEADER = DRIVER / "rtl9617c-fabric.h"
REGISTER_SHA = "ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0"

TEST = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
static unsigned int delays, settles;
static void usleep_range(unsigned int low, unsigned int high)
 { if(low==1000 && high==2000)settles++;else {assert(low==10 && high==20); delays++;} }
#include "rtl9617c-fabric.h"

struct model {
 unsigned int reg[0x10000/4], original[0x10000/4];
 unsigned int writes, scans, vlan_writes, frame_writes, reads, pp_reads;
 unsigned int pending_reg, pending_remaining, permanent_pending;
 unsigned int drop_reg, drop_occurrence, drop_seen;
 unsigned int inherited, scan_result, scan_timeout, busy_on_scan;
 unsigned int corrupt_vlan, rollback_stuck, corrupt_frame, frame_rollback_stuck;
 unsigned int oversize_rollback_stuck, pending_after_vlan, corrupt_learning_stop;
 unsigned int live_rx, live_rx_reads, corrupt_mac_gate;
 unsigned int rx_writes[5], mac_rx_writes[5];
 unsigned int control_writes, last_filter_writes, scan_toggles;
 unsigned int toggle_at_gate, toggle_on_scan, toggle_after_control, toggle_after_filter;
 unsigned int toggle_on_filter_read, last_filter_reads;
 unsigned int fault_after_filter, fault_after_control;
};
static struct model m;
static unsigned int cases;

static bool fdb_busy(void) {
 return (m.reg[RTL_L2_FDB_ACCESS/4] |
         m.reg[RTL_L2_FDB_LIMIT_ACCESS/4]) & RTL_L2_ACCESS_BUSY;
}
static bool mac_rx_enabled(void) {
 for(unsigned i=0;i<5;i++)
  if(m.reg[RTL_FABRIC_RX_MAC(i)/4]&RTL_FABRIC_RX_MAC_ENABLE)return true;
 return false;
}
static void assert_mac_rx_gated(void) {
 for(unsigned i=0;i<5;i++)
  assert(!(m.reg[RTL_FABRIC_RX_MAC(i)/4]&RTL_FABRIC_RX_MAC_ENABLE));
}
static void toggle_scan(void) {
 m.reg[RTL_L2_FDB_CONTROL/4]^=RTL_L2_FDB_SW_AGE_SCAN;m.scan_toggles++;
}
static void control_fault(unsigned int fault) {
 switch(fault) {
 case 0:break;
 case 1:m.reg[RTL_L2_FDB_CONTROL/4]=~0U;break;
 case 2:m.reg[RTL_L2_FDB_CONTROL/4]|=RTL_L2_FDB_INFO_INIT;break;
 case 3:m.reg[RTL_L2_FDB_CONTROL/4]^=RTL_L2_FDB_LEARN_DISABLE;break;
 case 4:m.reg[RTL_L2_FDB_CONTROL/4]^=4U;break;
 case 5:m.reg[RTL_L2_FDB_LIMIT_ACCESS/4]=RTL_L2_ACCESS_BUSY;break;
 case 6:m.reg[RTL_L2_FDB_CONTROL/4]^=RTL_L2_FDB_CMD_MODE;break;
 default:assert(0);
 }
}
static unsigned int read_reg(void *ctx,unsigned int reg) {
 (void)ctx;assert(!(reg&3) && reg<sizeof(m.reg));m.reads++;
 if(reg==RTL_L2_FDB_FILTER_WORD0-(RTL_L2_FDB_FILTER_WORDS-1)*4 &&
    ++m.last_filter_reads==1 && m.toggle_on_filter_read)toggle_scan();
 if(reg==0x11c0) {
  m.pp_reads++;
  /* A bypassed frame still has HeaderA/PP state. CPU16 cannot drain
   * through an as-yet unstarted QM: real RX, not destination selection,
   * is the cold receive fence. This is deliberately independent of the
   * production helper's cold_rx_gated bookkeeping. */
  if(m.live_rx && mac_rx_enabled()){m.live_rx_reads++;return 1U;}
 }
 if(reg==m.pending_reg && (m.pending_remaining || m.permanent_pending)) {
  if(m.pending_remaining)m.pending_remaining--;
  return reg==0x11c0?1U:2U;
 }
 return m.reg[reg/4];
}
static void write_reg(void *ctx,unsigned int reg,unsigned int value) {
 (void)ctx;assert(!(reg&3) && reg<sizeof(m.reg));m.writes++;
 if(reg==RTL_L2_FDB_CONTROL) {
  /* Only the independent SDK scan producer may toggle this edge. */
  assert(!((value^m.reg[reg/4])&RTL_L2_FDB_SW_AGE_SCAN));
  m.control_writes++;
 }
 /* UNI MRU is managed; storage and TPID comparators remain untouched. */
 assert(reg!=RTL_FABRIC_STORAGE_LENGTH && !(reg>=0x1108 && reg<=0x1114));
 if(reg==RTL_L2_FDB_CONTROL ||
    (reg>=0x1c18 && reg<=RTL_L2_FDB_FILTER_WORD0) ||
    reg==RTL_L2_FDB_RETURN ||
    (reg<=RTL_L2_FDB_DATA0 && reg>RTL_L2_FDB_DATA0-RTL_L2_FDB_WORDS*4)) {
  assert(!fdb_busy());assert_mac_rx_gated();
 }
 for(unsigned i=0;i<5;i++) {
  assert(reg!=0xa5d4U+0x90U*i); /* TX must remain able to drain. */
  if(reg==RTL_FABRIC_RX_MAC(i)) {
   m.mac_rx_writes[i]++;
   assert(!(value&RTL_FABRIC_RX_MAC_ENABLE)); /* Only ndo_open may reopen. */
   if(m.corrupt_mac_gate==i+1)value=m.original[reg/4]^4U;
  }
 }
 for(unsigned i=0;i<5;i++)if(reg==RTL_FABRIC_RX(i)) {
  assert_mac_rx_gated();
  m.rx_writes[i]++;
  if(m.rx_writes[i]==2)assert(!(value&RTL_FABRIC_RX_OVERSIZE_ALLOW));
  if(m.rx_writes[i]>=3 && m.oversize_rollback_stuck==(i+1))value&=~RTL_FABRIC_RX_OVERSIZE_ALLOW;
 }
 bool drop=reg==m.drop_reg && ++m.drop_seen==m.drop_occurrence;
 if(reg==RTL_L2_FDB_CONTROL && m.corrupt_learning_stop &&
    (value&RTL_L2_FDB_LEARN_DISABLE)) {
  value=(value&~RTL_L2_FDB_LEARN_DISABLE)^4U;
 }
 if(reg==RTL_L2_VLAN_MODE_CONTROL) {
  assert_mac_rx_gated();
  m.vlan_writes++;
  assert(m.pp_reads>=3 && m.scans);
  assert(m.reg[RTL_L2_FDB_CONTROL/4]&RTL_L2_FDB_LEARN_DISABLE);
  for(unsigned int i=0;i<5;i++)
   assert((m.reg[RTL_FABRIC_RX(i)/4]&RTL_FABRIC_RX_SELECTOR)==RTL_FABRIC_RX_CPU);
  if(m.vlan_writes==1 && m.corrupt_vlan)value^=0x10;
  if(m.vlan_writes==1 && m.pending_after_vlan) {
   m.pending_reg=0x11c0;m.pending_remaining=7;
   m.permanent_pending=m.pending_after_vlan==2;
  }
  if(m.vlan_writes>1)assert(!m.pending_remaining && !m.permanent_pending);
  if(m.vlan_writes>1 && m.rollback_stuck)value|=1;
 }
 if(reg==RTL_FABRIC_FRAME_LENGTH) {
  assert_mac_rx_gated();
  m.frame_writes++;
  assert(m.pp_reads>=3 && (m.reg[RTL_L2_FDB_CONTROL/4]&RTL_L2_FDB_LEARN_DISABLE));
  assert(m.reg[RTL_L2_VLAN_MODE_CONTROL/4]&1U);
  if(m.frame_writes==1)assert((value&0x3fffU)==1526U);
  if(m.frame_writes==1 && m.corrupt_frame)value^=1U<<16;
  if(m.frame_writes>1 && m.frame_rollback_stuck)value=0x4005f6;
 }
 if(!drop)m.reg[reg/4]=value;
 if(reg==RTL_FABRIC_RX(4) && m.rx_writes[4]==1 && m.toggle_at_gate)toggle_scan();
 if(reg==RTL_L2_FDB_FILTER_WORD0-(RTL_L2_FDB_FILTER_WORDS-1)*4) {
  m.last_filter_writes++;
  if(m.last_filter_writes==m.toggle_after_filter)toggle_scan();
  control_fault(m.fault_after_filter);
 }
 if(reg==RTL_L2_FDB_CONTROL) {
  if(m.toggle_after_control&(1U<<m.control_writes))toggle_scan();
  control_fault(m.fault_after_control);
 }
}
static int indirect(void *ctx,unsigned int reg,unsigned int value) {
 (void)ctx;assert(reg==RTL_L2_FDB_ACCESS && !fdb_busy());
 assert_mac_rx_gated();
 assert((value&255U)==RTL_L2_FDB_SCAN);
 assert((value>>8 & 8191U)==0);
 assert(m.reg[RTL_L2_FDB_CONTROL/4]&RTL_L2_FDB_LEARN_DISABLE);
 assert(m.reg[RTL_L2_FDB_CONTROL/4]&RTL_L2_FDB_CMD_MODE);
 /* Independent literal all-valid filter predicates. The inherited narrow
  * filter would hide the row and produce a false empty result. */
 assert((m.reg[0x1c28/4]&63U)==0);
 assert((m.reg[0x1c24/4]&63U)==63U);
 assert((m.reg[0x1c18/4]&0x7fffU)==0x7ffeU);
 assert(m.pp_reads>=3);m.scans++;
 m.reg[reg/4]=value;
 if(m.scan_timeout)return -ETIMEDOUT;
 m.reg[reg/4]=0;
 m.reg[RTL_L2_FDB_RETURN/4]=m.inherited ?
  RTL_L2_FDB_STATUS_HIT|(4127U<<4):m.scan_result;
 if(m.inherited) {
  struct rtl_l2_fdb_entry row={.mac={2,1,2,3,4,5},.valid=1,
   .destination=63,.key_vid=4094,.key_sc=1,.age=3};
  unsigned int words[RTL_L2_FDB_WORDS];
  row.is_static=m.inherited==2;row.multicast=m.inherited==3;
  assert(!rtl_l2_fdb_encode(words,&row));
  for(unsigned i=0;i<RTL_L2_FDB_WORDS;i++)m.reg[(RTL_L2_FDB_DATA0-i*4)/4]=words[i];
 }
 if(m.busy_on_scan)m.reg[RTL_L2_FDB_LIMIT_ACCESS/4]=RTL_L2_ACCESS_BUSY;
 if(m.toggle_on_scan)toggle_scan();
 return 0;
}
static struct rtl_dq_io io={&m,read_reg,write_reg,indirect};
/*SDK_DECL*/

static void setup(unsigned int seed) {
 memset(&m,0,sizeof(m));delays=settles=0;
 for(unsigned i=0;i<sizeof(m.reg)/sizeof(m.reg[0]);i++)
  m.reg[i]=(i*2654435761U)^seed;
 m.reg[RTL_L2_FDB_CONTROL/4]=0x10800ff9U;
 m.reg[RTL_L2_FDB_ACCESS/4]=m.reg[RTL_L2_FDB_LIMIT_ACCESS/4]=0;
 m.reg[RTL_L2_VLAN_MODE_CONTROL/4]=(seed&0xffffffe0U)|2;
 m.reg[0x11c0/4]=0x12341234;m.reg[0x1534/4]=0;
 m.reg[0x175c/4]=m.reg[0x1904/4]=0;
 m.reg[0xa034/4]=0x004023f1;m.reg[0xa038/4]=0x2454;
 m.reg[0x1108/4]=m.reg[0x110c/4]=m.reg[0x1110/4]=0x8100;
 m.reg[0x1114/4]=0x9100;
 for(unsigned i=0;i<5;i++)m.reg[RTL_FABRIC_RX_MAC(i)/4]|=RTL_FABRIC_RX_MAC_ENABLE;
 m.live_rx=1;
 /* Deliberately narrow inherited SCAN predicates. */
 m.reg[0x1c28/4]|=31;m.reg[0x1c24/4]&=~63U;m.reg[0x1c18/4]&=~0x7fffU;
 m.scan_result=RTL_L2_FDB_STATUS_MISS;
 memcpy(m.original,m.reg,sizeof(m.reg));
}
static void command_restored(const struct rtl_fabric *f) {
 assert(m.reg[RTL_L2_FDB_CONTROL/4]==((m.original[RTL_L2_FDB_CONTROL/4]^
  ((m.scan_toggles&1)?RTL_L2_FDB_SW_AGE_SCAN:0))|
  (f->ready?(RTL_L2_FDB_LEARN_DISABLE|RTL_L2_FDB_CMD_MODE):0)));
 for(unsigned i=0;i<RTL_L2_FDB_FILTER_WORDS;i++)
  assert(m.reg[(RTL_L2_FDB_FILTER_WORD0-i*4)/4]==
         m.original[(RTL_L2_FDB_FILTER_WORD0-i*4)/4]);
}
static void baseline_preserved(const struct rtl_fabric *f) {
 if(!f->poisoned)assert(m.reg[0xa034/4]==(f->ready ?
  ((m.original[0xa034/4]&~0x3fffU)|1526U):m.original[0xa034/4]));
 assert(m.reg[0xa038/4]==m.original[0xa038/4]);
 for(unsigned i=0;i<4;i++)assert(m.reg[(0x1108+i*4)/4]==m.original[(0x1108+i*4)/4]);
 for(unsigned i=0;i<5;i++) {
  unsigned reg=RTL_FABRIC_RX(i)/4;
  assert((m.reg[reg]&~(RTL_FABRIC_RX_SELECTOR|RTL_FABRIC_RX_OVERSIZE_ALLOW))==(m.original[reg]&~(RTL_FABRIC_RX_SELECTOR|RTL_FABRIC_RX_OVERSIZE_ALLOW)));
  if(!f->poisoned)assert((m.reg[reg]&RTL_FABRIC_RX_OVERSIZE_ALLOW)==
   (f->ready?0:(m.original[reg]&RTL_FABRIC_RX_OVERSIZE_ALLOW)));
  reg=RTL_FABRIC_RX_MAC(i)/4;
  assert((m.reg[reg]&~RTL_FABRIC_RX_MAC_ENABLE)==
         (m.original[reg]&~RTL_FABRIC_RX_MAC_ENABLE));
  if(f->cold_rx_gated&(1U<<i))assert(!(m.reg[reg]&RTL_FABRIC_RX_MAC_ENABLE));
 }
}
int main(void) {
 {
  /* Continuous ingress cannot be made idle merely by selecting CPU16. */
  setup(0);assert(rtl_fabric_pending(&io));
  for(unsigned i=0;i<5;i++)m.reg[RTL_FABRIC_RX(i)/4]=RTL_FABRIC_RX_CPU;
  assert(rtl_fabric_pending(&io));
  for(unsigned i=0;i<5;i++)m.reg[RTL_FABRIC_RX_MAC(i)/4]&=~RTL_FABRIC_RX_MAC_ENABLE;
  assert(!rtl_fabric_pending(&io));assert(m.live_rx_reads==2);cases++;
 }
 for(unsigned seed=0;seed<128;seed++) {
  struct rtl_fabric f={};setup(seed*0x10001U);
  assert(!rtl_fabric_cold_prepare(&io,&f));
  assert(f.ready && f.changed && !f.refusal && !f.poisoned);
  assert(f.cold_rx_gated==31 && !mac_rx_enabled() && !m.live_rx_reads);
  assert(m.reg[0x1414/4]==(m.original[0x1414/4]|1));
  assert(m.scans==1 && m.pp_reads>=4 && m.frame_writes==1 && settles==1);
  assert(f.packet_length==0x004005f6 && f.original_packet_length==0x004023f1);
  assert(rtl_fabric_native_mtu_compatible(&f));
  command_restored(&f);baseline_preserved(&f);
  unsigned writes=m.writes,scans=m.scans;
  assert(!rtl_fabric_cold_prepare(&io,&f));assert(!rtl_fabric_check(&io,&f));
  assert(m.writes==writes && m.scans==scans);cases++;
 }
 for(unsigned inherited=1;inherited<=3;inherited++) {
  struct rtl_fabric f={};setup(1);m.inherited=inherited;
  assert(rtl_fabric_cold_prepare(&io,&f)==-EOPNOTSUPP);
  assert(!f.ready && f.refusal && !f.poisoned && !m.vlan_writes);
  assert(f.inherited_fdb_present && f.inherited_fdb_index==4127);
  for(unsigned i=0;i<RTL_L2_FDB_WORDS;i++)
   assert(f.inherited_fdb_words[i]==m.reg[(RTL_L2_FDB_DATA0-i*4)/4]);
  assert(m.scans==1);command_restored(&f);baseline_preserved(&f);cases++;
 }
 for(unsigned stage=0;stage<4;stage++) {
  unsigned regs[]={0x11c0,0x1534,0x175c,0x1904};
  for(unsigned permanent=0;permanent<2;permanent++) {
   struct rtl_fabric f={};setup(stage);m.pending_reg=regs[stage];
   m.pending_remaining=7;m.permanent_pending=permanent;
   int ret=rtl_fabric_cold_prepare(&io,&f);
   assert(permanent ? ret==-ETIMEDOUT : ret==0);
   assert(!f.poisoned);assert(permanent ? !m.scans : m.scans==1);
   command_restored(&f);cases++;
  }
 }
 for(unsigned window=0;window<2;window++) {
  struct rtl_fabric f={};setup(0);
  m.reg[(window?RTL_L2_FDB_LIMIT_ACCESS:RTL_L2_FDB_ACCESS)/4]=RTL_L2_ACCESS_BUSY;
  assert(rtl_fabric_cold_prepare(&io,&f)==-EBUSY);
  assert(f.refusal && !f.poisoned && !m.writes && !m.scans);cases++;
 }
 {
  struct rtl_fabric f={};setup(0);m.scan_timeout=1;
  assert(rtl_fabric_cold_prepare(&io,&f)==-ETIMEDOUT);
  assert(f.poisoned && !f.ready && !m.vlan_writes && m.scans==1);
  unsigned writes=m.writes;assert(rtl_fabric_cold_prepare(&io,&f)==-EIO);
  assert(m.writes==writes);cases++;
 }
 {
  struct rtl_fabric f={};setup(0);m.busy_on_scan=1;
  assert(rtl_fabric_cold_prepare(&io,&f)==-EBUSY);
  assert(f.poisoned && !f.ready && !m.vlan_writes);cases++;
 }
 {
  struct rtl_fabric f={};setup(0);m.drop_reg=RTL_L2_FDB_CONTROL;m.drop_occurrence=2;
  /* CMD readback now detects this ignored write before touching SCAN. */
  assert(rtl_fabric_cold_prepare(&io,&f)==-EIO);
  assert(f.refusal && !f.poisoned && !m.scans && !m.frame_writes && !m.vlan_writes);
  command_restored(&f);baseline_preserved(&f);cases++;
 }
 for(unsigned initial=0;initial<2;initial++)for(unsigned path=0;path<5;path++)
  for(unsigned phase=0;phase<6;phase++) {
   if(phase==1 && path>1)continue; /* These paths never reach SCAN. */
   if((phase==2 || phase==3) && path==3)continue; /* No lease acquired. */
   if(phase==4 && path!=2 && path!=3)continue; /* Ignored owned write. */
   struct rtl_fabric f={};setup(0);
   m.reg[RTL_L2_FDB_CONTROL/4]|=initial?RTL_L2_FDB_SW_AGE_SCAN:0;
   m.original[RTL_L2_FDB_CONTROL/4]=m.reg[RTL_L2_FDB_CONTROL/4];
   if(path==1)m.inherited=2;
   if(path==2 || path==3) {
    m.drop_reg=RTL_L2_FDB_CONTROL;m.drop_occurrence=path==2?2:1;
   }
   if(path==4){m.pending_reg=0x11c0;m.permanent_pending=1;}
   if(phase==0)m.toggle_at_gate=1;
   if(phase==1)m.toggle_on_scan=1;
   if(phase==2)m.toggle_after_filter=path<2?2:1;
   if(phase==3)m.toggle_after_control=1U<<(path==4?2:3);
   if(phase==4)m.toggle_after_control=1U<<m.drop_occurrence;
   if(phase==5)m.toggle_on_filter_read=1;
   int ret=rtl_fabric_cold_prepare(&io,&f);
   const int expected[]={0,-EOPNOTSUPP,-EIO,-EIO,-ETIMEDOUT};
   assert(ret==expected[path] && !f.poisoned && m.scan_toggles==1);
   assert(f.ready==(path==0) && f.refusal==(path!=0));
   assert(m.control_writes==(path==3?1U:(path==4?2U:3U)));
   if(path>=2)assert(!m.scans && !m.frame_writes && !m.vlan_writes);
   if(path==3)assert(!m.last_filter_writes);
   command_restored(&f);baseline_preserved(&f);cases++;
  }
 /* The real restore helper must not hide unknown control state by replaying
  * a saved whole word. Inject before filters, after the final filter write,
  * and after the final CTRL write; no DATA/SCAN or baseline mutation occurs. */
 for(unsigned phase=0;phase<3;phase++)for(unsigned fault=1;fault<=6;fault++) {
  if(fault==6 && phase<2)continue; /* CMD is owned and intentionally restored. */
  struct rtl_fabric f={};setup(0);
  for(unsigned port=0;port<5;port++)m.reg[RTL_FABRIC_RX_MAC(port)/4]&=~RTL_FABRIC_RX_MAC_ENABLE;
  for(unsigned word=0;word<RTL_L2_FDB_FILTER_WORDS;word++)
   f.saved_filter[word]=m.original[(RTL_L2_FDB_FILTER_WORD0-word*4)/4];
  m.reg[RTL_L2_FDB_CONTROL/4]|=RTL_L2_FDB_LEARN_DISABLE|RTL_L2_FDB_CMD_MODE;
  if(phase==0)control_fault(fault);
  if(phase==1)m.fault_after_filter=fault;
  if(phase==2)m.fault_after_control=fault;
  int ret=rtl_fabric_restore_command(&io,&f,m.original[RTL_L2_FDB_CONTROL/4]);
  int expected=fault==2?-EOPNOTSUPP:(fault==5 || (fault==3 && phase<2)?-EBUSY:-EIO);
  assert(ret==expected);
  assert(m.control_writes==(phase==2) && !m.scans && !m.frame_writes && !m.vlan_writes);
  assert(m.last_filter_writes==(phase!=0));cases++;
 }
 for(unsigned port=0;port<5;port++) {
  struct rtl_fabric f={};setup(port);
  m.drop_reg=RTL_FABRIC_RX_MAC(port);m.drop_occurrence=1;
  assert(rtl_fabric_cold_prepare(&io,&f)==-EIO);
  assert(!f.poisoned && f.refusal && !f.ready && !m.scans && !m.pp_reads);
  assert(f.cold_rx_gated==((1U<<port)-1));
  assert(f.rejected_register==RTL_FABRIC_RX_MAC(port));
  assert(m.reg[RTL_L2_FDB_CONTROL/4]==m.original[RTL_L2_FDB_CONTROL/4]);
  for(unsigned i=0;i<5;i++)assert(!m.rx_writes[i]);
  baseline_preserved(&f);command_restored(&f);
  cases++;
 }
 for(unsigned port=0;port<5;port++) {
  /* An unknown MAC word is not equivalent to a completely ignored write. */
  struct rtl_fabric f={};setup(port);m.corrupt_mac_gate=port+1;
  assert(rtl_fabric_cold_prepare(&io,&f)==-EIO);
  assert(f.poisoned && !f.refusal && !f.ready && !m.scans && !m.pp_reads);
  assert(f.cold_rx_gated==((1U<<port)-1));
  assert(f.rejected_register==RTL_FABRIC_RX_MAC(port));
  assert(m.reg[RTL_L2_FDB_CONTROL/4]==m.original[RTL_L2_FDB_CONTROL/4]);
  for(unsigned i=0;i<5;i++)assert(!m.rx_writes[i]);
  cases++;
 }
 for(unsigned port=0;port<5;port++) {
  struct rtl_fabric f={};setup(port);
  m.drop_reg=RTL_FABRIC_RX(port);m.drop_occurrence=1;
  assert(rtl_fabric_cold_prepare(&io,&f)==-EIO);
  assert(f.poisoned && !f.ready && !m.scans);cases++;
 }
 for(unsigned kind=0;kind<4;kind++) {
  struct rtl_fabric f={};setup(0);
  if(kind==0){m.drop_reg=RTL_FABRIC_RX(2);m.drop_occurrence=1;}
  if(kind==1){m.drop_reg=RTL_L2_FDB_CONTROL;m.drop_occurrence=1;}
  if(kind==2){m.drop_reg=RTL_L2_VLAN_MODE_CONTROL;m.drop_occurrence=1;}
  if(kind==3){m.corrupt_vlan=1;m.rollback_stuck=1;}
  assert(rtl_fabric_cold_prepare(&io,&f)==-EIO);
  assert(!f.ready);
  if(kind==1 || kind==2){assert(!f.poisoned && f.refusal);command_restored(&f);}
  else assert(f.poisoned);
  baseline_preserved(&f);cases++;
 }
 {
  /* A failed stop-learning write is recoverable ONLY if the old control
   * remains exact. A partial corruption is not an ignored write. */
  struct rtl_fabric f={};setup(0);m.corrupt_learning_stop=1;
  assert(rtl_fabric_cold_prepare(&io,&f)==-EIO);
  assert(f.poisoned && !f.refusal && !f.ready && !m.scans);cases++;
 }
 for(unsigned permanent=0;permanent<2;permanent++) {
  struct rtl_fabric f={};setup(0);m.pending_after_vlan=permanent+1;
  assert(rtl_fabric_cold_prepare(&io,&f)==-EBUSY);
  assert(!f.ready && !m.frame_writes && f.cold_rx_gated==31);
  if(permanent) {
   assert(f.poisoned && !f.refusal && m.vlan_writes==1);
   assert(m.reg[RTL_L2_FDB_CONTROL/4]&RTL_L2_FDB_LEARN_DISABLE);
  } else {
   assert(!f.poisoned && f.refusal && m.vlan_writes==2);
   assert(m.reg[RTL_L2_VLAN_MODE_CONTROL/4]==m.original[RTL_L2_VLAN_MODE_CONTROL/4]);
   command_restored(&f);
  }
  cases++;
 }
 for(unsigned index=0;index<RTL_L2_FDB_FILTER_WORDS;index++) {
  struct rtl_fabric f={};setup(index);m.drop_reg=RTL_L2_FDB_FILTER_WORD0-index*4;
  m.drop_occurrence=1;
  int ret=rtl_fabric_cold_prepare(&io,&f);
  if(index==0 || index==1 || index==4)assert(ret==-EIO && !f.poisoned);
  else assert(!ret); /* SDK intentionally leaves ignored comparisons intact. */
  command_restored(&f);cases++;
 }
 for(unsigned index=0;index<3;index++) {
  unsigned words[]={0,1,4};
  struct rtl_fabric f={};setup(index);
  m.drop_reg=RTL_L2_FDB_FILTER_WORD0-words[index]*4;m.drop_occurrence=2;
  assert(rtl_fabric_cold_prepare(&io,&f)==-EIO);
  assert(f.poisoned && !f.ready && m.vlan_writes==1);cases++;
 }
 {
  struct rtl_fabric f={};setup(0);m.reg[0x1414/4]|=RTL_L2_VLAN_MODE_SVL;
  /* Existing SVL does not use a SCAN lease: the final cold handoff is
   * its first CMD acquisition and must verify that posted mode write. */
  m.drop_reg=RTL_L2_FDB_CONTROL;m.drop_occurrence=2;
  assert(rtl_fabric_cold_prepare(&io,&f)==-EIO);
  assert(f.poisoned && !f.ready && !m.vlan_writes);cases++;
 }
 for(unsigned kind=0;kind<8;kind++) {
  struct rtl_fabric f={};setup(kind);assert(!rtl_fabric_cold_prepare(&io,&f));
  unsigned regs[]={0x1414,0xa034,0xa038,0x1108,0x110c,0x1110,0x1114,0xa034};
  unsigned bits[]={1,1,1,1,1,1,1,1U<<31};
  m.reg[regs[kind]/4]^=bits[kind];unsigned writes=m.writes;
  assert(rtl_fabric_check(&io,&f)==(kind==7?0:-EIO));
  assert(m.writes==writes);cases++;
 }
 {
  struct rtl_fabric f={};setup(0);m.reg[0x1414/4]|=1;
  assert(!rtl_fabric_cold_prepare(&io,&f));
  assert(f.ready && f.changed && !m.scans && !m.vlan_writes && m.pp_reads>=3);
  baseline_preserved(&f);cases++;
 }
 {
  struct rtl_fabric f={};setup(0);m.scan_result=13;
  assert(rtl_fabric_cold_prepare(&io,&f)==-EIO);
  assert(f.refusal && !f.poisoned && !m.vlan_writes);command_restored(&f);cases++;
 }
 {
  struct rtl_fabric f={};setup(0);m.reg[RTL_L2_FDB_CONTROL/4]|=1U<<30;
  assert(rtl_fabric_cold_prepare(&io,&f)==-EBUSY);
  assert(!m.writes && f.refusal && !f.poisoned);cases++;
 }
 for(unsigned kind=0;kind<6;kind++) {
  struct rtl_fabric f={};setup(kind);
  if(kind==0)m.reg[0xa034/4]=(63U<<16)|9201;
  if(kind==1)m.reg[0xa034/4]=(64U<<16)|63;
  if(kind==2)m.reg[0xa038/4]=1525;
  if(kind==3)m.reg[0xa034/4]=(128U<<16)|9201;
  if(kind==4)m.reg[0xa038/4]=1526;
  if(kind==5)m.reg[0xa034/4]=(64U<<16)|1522;
  memcpy(m.original,m.reg,sizeof(m.reg));
  int ret=rtl_fabric_cold_prepare(&io,&f);
  if(kind<4)assert(ret==-EOPNOTSUPP && f.refusal && !m.writes && !f.poisoned);
  else {assert(!ret && f.ready && m.frame_writes==1);baseline_preserved(&f);}
  cases++;
 }
 for(unsigned size=0;size<8;size++)for(unsigned ports=0;ports<32;ports++) {
  const unsigned int maximum[]={63,64,1518,1522,1523,1526,9201,16383};
  struct rtl_fabric f={};setup(size+ports);
  m.reg[0xa034/4]=(64U<<16)|maximum[size];m.reg[0xa038/4]=16383;
  for(unsigned port=0;port<5;port++) {
   unsigned reg=RTL_FABRIC_RX(port)/4;
   m.reg[reg]=(m.reg[reg]&~RTL_FABRIC_RX_OVERSIZE_ALLOW)|((ports&(1U<<port))?RTL_FABRIC_RX_OVERSIZE_ALLOW:0);
  }
  memcpy(m.original,m.reg,sizeof(m.reg));
  int ret=rtl_fabric_cold_prepare(&io,&f);
  if(size==0)assert(ret==-EOPNOTSUPP);
  else assert(!ret && f.ready);
  unsigned reads=m.reads,writes=m.writes;
  assert(rtl_fabric_native_mtu_compatible(&f)==(size!=0));
  assert(m.reads==reads && m.writes==writes);
  assert(m.frame_writes==(size!=0 && maximum[size]!=1526));
  baseline_preserved(&f);cases++;
 }
 for(unsigned kind=0;kind<3;kind++) {
  struct rtl_fabric f={};setup(kind);
  if(kind==0){m.drop_reg=RTL_FABRIC_FRAME_LENGTH;m.drop_occurrence=1;}
  if(kind==1)m.corrupt_frame=1;
  if(kind==2){m.corrupt_frame=1;m.frame_rollback_stuck=1;}
  assert(rtl_fabric_cold_prepare(&io,&f)==-EIO && !f.ready);
  if(kind==2)assert(f.poisoned);
  else {assert(!f.poisoned && f.refusal);baseline_preserved(&f);command_restored(&f);}
  assert(m.reg[0x1414/4]==m.original[0x1414/4]);cases++;
 }
 for(unsigned port=0;port<5;port++)for(unsigned stuck=0;stuck<2;stuck++) {
  struct rtl_fabric f={};setup(port);
  m.reg[RTL_FABRIC_RX(port)/4]|=RTL_FABRIC_RX_OVERSIZE_ALLOW;
  m.original[RTL_FABRIC_RX(port)/4]=m.reg[RTL_FABRIC_RX(port)/4];
  m.drop_reg=RTL_FABRIC_RX(port);m.drop_occurrence=2;
  /* Force an earlier successfully-cleared override to fail restoration. */
  if(stuck) {
   m.reg[RTL_FABRIC_RX(0)/4]|=RTL_FABRIC_RX_OVERSIZE_ALLOW;
   m.original[RTL_FABRIC_RX(0)/4]=m.reg[RTL_FABRIC_RX(0)/4];
   m.oversize_rollback_stuck=1;
  }
  assert(rtl_fabric_cold_prepare(&io,&f)==-EIO && !f.ready);
  if(stuck)assert(f.poisoned);
  else {assert(!f.poisoned && f.refusal);baseline_preserved(&f);command_restored(&f);}
  cases++;
 }
 for(unsigned port=0;port<5;port++) {
  struct rtl_fabric f={};setup(port);assert(!rtl_fabric_cold_prepare(&io,&f));
  m.reg[RTL_FABRIC_RX(port)/4]^=RTL_FABRIC_RX_OVERSIZE_ALLOW;
  unsigned writes=m.writes;assert(rtl_fabric_check(&io,&f)==-EIO);
  assert(!rtl_fabric_native_mtu_compatible(&f));
  assert(m.writes==writes);cases++;
 }
 for(unsigned size=0;size<6;size++) {
  const unsigned int maximum[]={1518,1522,1525,1526,1527,9201};
  struct rtl_fabric f={};setup(size);assert(!rtl_fabric_cold_prepare(&io,&f));
  struct rtl_fabric altered=f;altered.packet_length=(64U<<16)|maximum[size];
  unsigned writes=m.writes,reads=m.reads;
  assert(rtl_fabric_native_mtu_compatible(&altered)==(maximum[size]==1526));
  assert(m.writes==writes && m.reads==reads);cases++;
 }
 {
  struct rtl_fabric f={};setup(0);assert(!rtl_fabric_native_mtu_compatible(&f));
  assert(!rtl_fabric_native_mtu_compatible(NULL));
  assert(!rtl_fabric_cold_prepare(&io,&f));f.poisoned=1;
  assert(!rtl_fabric_native_mtu_compatible(&f));cases++;
 }
 /* Reserved bits and an already-managed baseline are retained exactly. */
 {
  struct rtl_fabric f={};setup(0);m.reg[0x1414/4]|=1;
  m.reg[0xa034/4]=0x804005f6;
  m.reg[0x1c00/4]|=RTL_L2_FDB_LEARN_DISABLE|RTL_L2_FDB_CMD_MODE;
  for(unsigned port=0;port<5;port++) {
   m.reg[RTL_FABRIC_RX(port)/4]=RTL_FABRIC_RX_CPU;
   m.reg[RTL_FABRIC_RX_MAC(port)/4]&=~RTL_FABRIC_RX_MAC_ENABLE;
  }
  memcpy(m.original,m.reg,sizeof(m.reg));
  assert(!rtl_fabric_cold_prepare(&io,&f) && f.ready && !f.changed);
  assert(!m.frame_writes && !m.vlan_writes && !settles);
  baseline_preserved(&f);cases++;
 }
 /* A baseline differing only in CMD mode is still a material ownership
  * handoff. Both originally-live and originally-stopped learners acquire
  * the same permanent CMD lease before route-only operation can begin. */
 for(unsigned int boot_cmd=0;boot_cmd<2;boot_cmd++)
  for(unsigned int boot_learning=0;boot_learning<2;boot_learning++) {
   struct rtl_fabric f={};setup(0);m.reg[0x1414/4]|=1;
   m.reg[0xa034/4]=0x804005f6;
   m.reg[0x1c00/4]&=~(RTL_L2_FDB_LEARN_DISABLE|RTL_L2_FDB_CMD_MODE);
   if(boot_cmd)m.reg[0x1c00/4]|=RTL_L2_FDB_CMD_MODE;
   if(!boot_learning)m.reg[0x1c00/4]|=RTL_L2_FDB_LEARN_DISABLE;
   for(unsigned port=0;port<5;port++) {
    m.reg[RTL_FABRIC_RX(port)/4]=RTL_FABRIC_RX_CPU;
    m.reg[RTL_FABRIC_RX_MAC(port)/4]&=~RTL_FABRIC_RX_MAC_ENABLE;
   }
   memcpy(m.original,m.reg,sizeof(m.reg));
   assert(!rtl_fabric_cold_prepare(&io,&f) && f.ready);
   assert(f.changed==(!boot_cmd || boot_learning));
   command_restored(&f);assert(!rtl_fabric_check(&io,&f));cases++;
  }
 for(unsigned int fault=0;fault<7;fault++) {
  struct rtl_fabric f={};setup(0);assert(!rtl_fabric_cold_prepare(&io,&f));
  int expected=0;
  switch(fault) {
  case 0:m.reg[RTL_L2_FDB_CONTROL/4]&=~RTL_L2_FDB_LEARN_DISABLE;break;
  case 1:m.reg[RTL_L2_FDB_CONTROL/4]^=RTL_L2_FDB_SW_AGE_SCAN;break;
  case 2:m.reg[RTL_L2_FDB_CONTROL/4]&=~RTL_L2_FDB_CMD_MODE;expected=-EOPNOTSUPP;break;
  case 3:m.reg[RTL_L2_FDB_CONTROL/4]=~0U;expected=-EIO;break;
  case 4:m.reg[RTL_L2_FDB_CONTROL/4]|=RTL_L2_FDB_INFO_INIT;expected=-EOPNOTSUPP;break;
  case 5:m.reg[RTL_L2_FDB_ACCESS/4]=RTL_L2_ACCESS_BUSY;expected=-EBUSY;break;
  case 6:m.reg[RTL_L2_FDB_LIMIT_ACCESS/4]=RTL_L2_ACCESS_BUSY;expected=-EBUSY;break;
  }
  unsigned int writes=m.writes;
  assert(rtl_fabric_check(&io,&f)==expected && m.writes==writes);
  assert(!f.poisoned);cases++;
 }
 /*SDK_RUN*/
 printf("{\"cases\":%u,\"hardware_timing_verified\":false,\"managed_uni_max_frame\":1526,\"tpids_or_storage_written\":false}\n",cases);
 return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registers", type=Path, help="Pinned independent RTL8277C register unions")
    args = parser.parse_args()
    production = HEADER.read_text()
    mac_gate = re.search(r"\tfor \(i = 0; i < RTL_FABRIC_LAN_PORTS; i\+\+\) \{\n"
                         r"\t\tunsigned int reg = RTL_FABRIC_RX_MAC\(i\);.*?"
                         r"\t\tfabric->cold_rx_gated \|= 1U << i;\n\t\}", production, re.S)
    assert mac_gate
    mutants = {
        "cold_cmd_not_retained": production.replace(
            "RTL_L2_FDB_LEARN_DISABLE | RTL_L2_FDB_CMD_MODE))",
            "RTL_L2_FDB_LEARN_DISABLE))", 1),
        "bypass_is_not_mac_rx_gate": production.replace(mac_gate.group(), "/* RX gate omitted */", 1),
        "missing_mac_rx_readback": production.replace(
            "ret = rtl_fabric_match(io, fabric, reg, RTL_FABRIC_RX_MAC_ENABLE, 0);", "ret = 0;", 1),
        "ignored_mac_gate_poisoned": production.replace(
            "if (io->read(io->context, reg) == fabric->original_mac_rx[i])", "if (0)", 1),
        "unknown_mac_gate_swallowed": production.replace(
            "if (io->read(io->context, reg) == fabric->original_mac_rx[i])", "if (1)", 1),
        "ignored_learning_stop_poisoned": production.replace(
            "lease = 0;\n\t\t\tgoto refuse;", "goto restore;", 1),
        "rollback_without_drain": production.replace("cleanup = rtl_fabric_drain(io);", "cleanup = 0;", 1),
        "missing_initial_drain": production.replace("ret = rtl_fabric_drain(io);", "ret = 0;"),
        "inherited_fdb_ignored": production.replace(
            "fabric->inherited_fdb_words[i] = row.words[i];\n\t\t\tret = -EOPNOTSUPP;",
            "fabric->inherited_fdb_words[i] = row.words[i];\n\t\t\tret = 0;", 1),
        "old_narrow_scan_filter": production.replace("rtl_l2_fdb_scan_filter(filter);", "/* deliberately omitted */"),
        "missing_mode_readback": production.replace(
            "ret = rtl_fabric_match(io, fabric, RTL_L2_VLAN_MODE_CONTROL, ~0U,\n\t\t\tfabric->original_vlan_mode | RTL_L2_VLAN_MODE_SVL);",
            "ret = 0;"),
        "old_1522_frame_budget": production.replace(
            "#define RTL_FABRIC_NATIVE_MAX_FRAME RTL_NI_FRAME_WIRE_BYTES", "#define RTL_FABRIC_NATIVE_MAX_FRAME 1522U", 1),
        "missing_frame_programming": production.replace(
            "if (fabric->packet_length != fabric->original_packet_length)", "if (0)", 1),
        "oversize_override_left_enabled": production.replace(
            "io->write(io->context, reg, value & ~RTL_FABRIC_RX_OVERSIZE_ALLOW);",
            "io->write(io->context, reg, value);", 1),
        "missing_frame_rollback": production.replace("if (frame_written) {", "if (0) {", 1),
        "missing_oversize_rollback": production.replace(
            "if (!(oversize_written & (1U << i)))", "if (1)", 1),
        "false_native_mtu_compatibility": production.replace(
            "maximum == RTL_FABRIC_NATIVE_MAX_FRAME", "maximum <= RTL_FABRIC_NATIVE_MAX_FRAME", 1),
        "warm_rewrites_baseline": production.replace(
            "return rtl_fabric_check(io, fabric);", "{ fabric->ready = 0; return rtl_fabric_cold_prepare(io, fabric); }", 1),
        "cold_replays_saved_scan_edge": production.replace(
            "control = (live & ~owned) | (control & owned);", "/* stale saved control */", 1),
        "acquire_replays_pre_gate_edge": production.replace(
            "control = live;\n\tfabric->saved_control = control;",
            "/* stale acquisition control */\n\tfabric->saved_control = control;", 1),
        "post_filter_lease_not_refreshed": production.replace(
            "ret = rtl_l2_fdb_mode_control(io, &live);\n\tif (ret)\n\t\treturn ret;\n"
            "\tif ((live ^ control) & ~(owned | RTL_L2_FDB_SW_AGE_SCAN))\n\t\treturn -EIO;\n"
            "\tcontrol = (live & ~owned) | (control & owned);",
            "control = (live & ~owned) | (control & owned);", 1),
        "harmless_readback_toggle_poisoned": production.replace(
            "if ((live ^ control) & ~RTL_L2_FDB_SW_AGE_SCAN) {",
            "if ((live ^ control) & ~0U) {", 1),
        "ignored_write_toggle_poisoned": production.replace(
            "if (!cleanup && !((live ^ control) & ~RTL_L2_FDB_SW_AGE_SCAN))",
            "if (!cleanup && live == control)", 1),
        "unowned_control_drift_swallowed": production.replace(
            "if ((live ^ control) & ~(owned | RTL_L2_FDB_SW_AGE_SCAN))\n\t\treturn -EIO;",
            "/* stable policy drift ignored */"),
        "cold_restore_readback_ignored": production.replace(
            "ret = rtl_l2_fdb_control_read(io, &live);\n\tif (ret)\n\t\treturn ret;\n"
            "\tif ((live ^ control) & ~RTL_L2_FDB_SW_AGE_SCAN) {",
            "return 0;\n\tif ((live ^ control) & ~RTL_L2_FDB_SW_AGE_SCAN) {", 1),
    }
    assert all(text != production for text in mutants.values())
    expected_assertions = {
        "cold_cmd_not_retained": "m.reg[RTL_L2_FDB_CONTROL/4]",
        "bypass_is_not_mac_rx_gate": "!(m.reg[RTL_FABRIC_RX_MAC(i)/4]&RTL_FABRIC_RX_MAC_ENABLE)",
        "missing_mac_rx_readback": "!(m.reg[RTL_FABRIC_RX_MAC(i)/4]&RTL_FABRIC_RX_MAC_ENABLE)",
        "ignored_mac_gate_poisoned": "!f.poisoned && f.refusal && !f.ready && !m.scans && !m.pp_reads",
        "unknown_mac_gate_swallowed": "f.poisoned && !f.refusal && !f.ready && !m.scans && !m.pp_reads",
        "ignored_learning_stop_poisoned": "ret==expected[path] && !f.poisoned && m.scan_toggles==1",
        "rollback_without_drain": "!m.pending_remaining && !m.permanent_pending",
        "missing_initial_drain": "m.pp_reads>=3",
        "inherited_fdb_ignored": "rtl_fabric_cold_prepare(&io,&f)==-EOPNOTSUPP",
        "old_narrow_scan_filter": "(m.reg[0x1c28/4]&63U)==0",
        "missing_mode_readback": "m.reg[RTL_L2_VLAN_MODE_CONTROL/4]&1U",
        "old_1522_frame_budget": "(value&0x3fffU)==1526U",
        "missing_frame_programming": "m.frame_writes==1 && settles==1",
        "oversize_override_left_enabled": "!(value&RTL_FABRIC_RX_OVERSIZE_ALLOW)",
        "missing_frame_rollback": "m.reg[0xa034/4]",
        "missing_oversize_rollback": "f.poisoned",
        "false_native_mtu_compatibility": "rtl_fabric_native_mtu_compatible(&altered)==(maximum[size]==1526)",
        "warm_rewrites_baseline": "m.writes==writes && m.scans==scans",
        "cold_replays_saved_scan_edge": "!((value^m.reg[reg/4])&RTL_L2_FDB_SW_AGE_SCAN)",
        "acquire_replays_pre_gate_edge": "!((value^m.reg[reg/4])&RTL_L2_FDB_SW_AGE_SCAN)",
        "post_filter_lease_not_refreshed": "!((value^m.reg[reg/4])&RTL_L2_FDB_SW_AGE_SCAN)",
        "harmless_readback_toggle_poisoned": "ret==expected[path] && !f.poisoned && m.scan_toggles==1",
        "ignored_write_toggle_poisoned": "ret==expected[path] && !f.poisoned && m.scan_toggles==1",
        "unowned_control_drift_swallowed": "ret==expected",
        "cold_restore_readback_ignored": "ret==expected",
    }
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    evidence = None
    test = TEST
    if args.registers:
        raw = args.registers.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == REGISTER_SHA, "Unpinned register input"
        source = raw.decode()
        names = ("L2FE_PLC_VLAN_MODE_CTRL", "NI_HV_GLB_PKT_LEN_CFG",
                 "NI_HV_GLB_PKT_STOR_LEN_CFG", "NI_HV_PT_RX_CNTRL_CFG", "NI_HV_PT_RXMAC_CFG",
                 "L2FE_L2E_CTRL")
        unions = []
        for name in names:
            match = re.search(r"typedef volatile union \{(?:(?!typedef volatile union).)*?\} " + name + r"_t;", source, re.S)
            assert match, name
            unions.append(match.group())
        declaration = "typedef unsigned int ca_uint32_t;\n" + "\n".join(unions) + r'''
static void sdk_oracle(void) {
 L2FE_PLC_VLAN_MODE_CTRL_t vlan={.wrd=2};vlan.bf.l2e_glb_vlan_mode=1;assert(vlan.wrd==3);
 NI_HV_GLB_PKT_LEN_CFG_t length={.wrd=0x004023f1};
 assert(length.bf.min_pkt_size==64 && length.bf.max_pkt_size==9201);
 length.bf.max_pkt_size=1526;assert(length.wrd==0x004005f6);
 NI_HV_GLB_PKT_STOR_LEN_CFG_t storage={.wrd=0x2454};assert(storage.bf.max_stor_pkt_len==9300);
 NI_HV_PT_RX_CNTRL_CFG_t rx={.wrd=0};rx.bf.ovr_drop_dis=1;assert(rx.wrd==(1U<<5));
 NI_HV_PT_RXMAC_CFG_t mac={.wrd=0};mac.bf.rx_en=1;assert(mac.wrd==RTL_FABRIC_RX_MAC_ENABLE);
 assert(RTL_FABRIC_RX_MAC(0)==0xa5c8 && RTL_FABRIC_RX_MAC(4)==0xa808);
 L2FE_L2E_CTRL_t ctrl={.wrd=0};ctrl.bf.sw_age_entry_scan=1;
 assert(ctrl.wrd==RTL_L2_FDB_SW_AGE_SCAN);
 ctrl.wrd=0;ctrl.bf.cpu_opt_mode=1;assert(ctrl.wrd==RTL_L2_FDB_CMD_MODE);
 ctrl.wrd=0;ctrl.bf.lrn_dis=1;assert(ctrl.wrd==RTL_L2_FDB_LEARN_DISABLE);
 ctrl.wrd=0;ctrl.bf.info_ff_init=1;assert(ctrl.wrd==RTL_L2_FDB_INFO_INIT);
}
'''
        test = test.replace("/*SDK_DECL*/", declaration).replace("/*SDK_RUN*/", "sdk_oracle();")
    with tempfile.TemporaryDirectory(prefix="thoros-fabric-") as temporary:
        build = Path(temporary)
        (build / "linux").mkdir()
        (build / "linux/delay.h").write_text("/* Delay stub is in test source. */\n")
        # Host portability only; target builds use Linux's actual errno header.
        if sys.platform == "darwin":
            (build / "linux/errno.h").write_text("#include <errno.h>\n")
        (build / "test.c").write_text(test)
        for name, source in [("production", production), *mutants.items()]:
            (build / HEADER.name).write_text(source)
            link_flags = [] if sys.platform == "darwin" else ["-no-pie"]
            subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                            *link_flags, "-I", str(build), "-I", str(DRIVER), str(build / "test.c"),
                            "-o", str(build / "test")], check=True)
            result = subprocess.run([str(build / "test")], text=True, capture_output=True,
                                    env={**os.environ, "ASAN_OPTIONS": "detect_leaks=0"})
            if name == "production":
                if result.returncode:
                    raise AssertionError(result.stderr)
                evidence = json.loads(result.stdout)
                print("PASS cold fabric:", result.stdout.strip())
            else:
                assert (result.returncode and "assert" in result.stderr.lower()
                        and expected_assertions[name] in result.stderr), (name, result.stderr)
                print("PASS mutation rejected:", name)
    evidence.update(production_sha256=hashlib.sha256(HEADER.read_bytes()).hexdigest(),
                    mutants_rejected=list(mutants), sanitizers=["address", "undefined"],
                    actual_sdk_registers_verified=bool(args.registers))
    (ROOT / "artifacts").mkdir(exist_ok=True)
    (ROOT / "artifacts/fabric-baseline.json").write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()
