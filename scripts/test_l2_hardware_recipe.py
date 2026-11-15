#!/usr/bin/env python3
"""Execute the real native-L2 hardware transaction with a strict MMIO oracle.

The model validates sequencing, raw preservation, ownership and failures; it
does not simulate undocumented ASIC packet timing or claim measured speed.
Optional --registers uses the pinned genuine RTL8277C register unions to
decode the *production recipe*, independently of the driver field helpers.
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


ROOT = Path(__file__).resolve().parents[1]
DRIVERS = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"
HEADER = DRIVERS / "rtl9617c-fe-switch-hw.h"
REGISTER_HASH = "ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0"

TEST = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "rtl9617c-l2-table.h"
#define BIT(n) (1U << (n))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define READ_ONCE(a) (a)
#define WRITE_ONCE(a,v) ((a)=(v))
#define FE_LAN_PORTS 5
#define FE_LAN_RX_CTRL(n) (0xa5f8 + 0x90 * (n))

struct model {
 unsigned int reg[0x10000 / 4];
 unsigned int limits[64];
 unsigned int rows[RTL_L2_TBL_COUNT][RTL_L2_VLAN_IDS][RTL_L2_TABLE_MAX_WORDS];
 unsigned int commands, writes, fail, pending_address, pending_request;
 unsigned int pending_words[RTL_L2_TABLE_MAX_WORDS];
 unsigned int delays, settles, clear_after, pending_reads, native_writes, tx_writes;
 unsigned int route_gates, route_arms, rx_writes;
 unsigned int lpb_reads;
 unsigned int corrupt_read_address, corrupt_read_value, corrupt_after_command;
 unsigned int corrupt_after_writes, ignore_write_table, ignore_write_address;
 unsigned int ignore_write_value, corrupt_trigger_value;
 bool ignore_write_match, corrupt_wait_write, corrupt_triggered;
 bool ignore_write, ignore_limits, reserved_read_zero;
 bool pending, table_seen_idle[RTL_L2_TBL_COUNT], active, route_closed, arm_failure;
};
static struct model model, original;
struct rtl_fe { struct model *model; bool enabled, prepared, route_gate_verified;
 bool route_gate_ready, dma_exposed; unsigned pending_withdrawals; };
static unsigned int cases, fault_cases, cold_cases;

static int table_at(unsigned int address, bool access)
{
 for (unsigned int t = 0; t < RTL_L2_TBL_COUNT; t++) {
  struct rtl_l2_table_layout l;
  assert(!rtl_l2_table_layout(t, &l));
  if (access ? address == l.access :
      address <= l.data0 && address > l.data0 - l.words * 4)
   return t;
 }
 return -1;
}

static void complete(struct model *m)
{
 struct rtl_l2_table_layout l;
 int t = table_at(m->pending_address, true);
 unsigned int index = m->pending_request & ~(BIT(31) | BIT(30));
 assert(m->pending);
 if(m->pending_address==RTL_L2_FDB_ACCESS) {
  assert((m->pending_request&255U)==RTL_L2_FDB_SCAN);
  assert(((m->pending_request>>8)&8191U)==0);
  assert((m->reg[RTL_L2_FDB_CONTROL/4]&(BIT(31)|BIT(22)))==(BIT(31)|BIT(22)));
  /* The integrated cold path models an empty inherited FDB. Nonempty,
   * ambiguous and rollback cases are exercised by test_fabric_baseline. */
  m->reg[RTL_L2_FDB_RETURN/4]=RTL_L2_FDB_STATUS_MISS;
  m->reg[m->pending_address/4]=0;m->pending=false;return;
 }
 if(m->pending_address==RTL_L2_FDB_LIMIT_ACCESS) {
  assert(!(m->reg[RTL_L2_FDB_CONTROL/4]&BIT(31)));
  assert(m->reg[RTL_L2_FDB_CONTROL/4]&BIT(22));
  assert((index&~63U)==RTL_L2_FDB_LIMIT_SELECT);
  if(m->pending_request&BIT(30)) {
   if(!m->ignore_limits)m->limits[index&63]=m->pending_words[0];
  }
  else m->reg[RTL_L2_FDB_LIMIT_DATA/4]=m->limits[index&63];
  m->reg[m->pending_address/4]=0;m->pending=false;return;
 }
 assert(t >= 0);
 assert(!rtl_l2_table_layout(t, &l) && index < l.entries);
 for (unsigned int w = 0; w < l.words; w++) {
  if (m->pending_request & BIT(30)) {
   assert(m->reg[(l.data0 - 4*w)/4] == m->pending_words[w]);
   if(!m->ignore_write || (unsigned int)t!=m->ignore_write_table)
    m->rows[t][index][w] = m->pending_words[w];
  } else {
   unsigned int value=m->rows[t][index][w];
   if(m->reserved_read_zero && t==RTL_L2_TBL_CF_KEY && w==2)value&=0x1f8ffU;
   if(m->reserved_read_zero && t==RTL_L2_TBL_CF_FIB && w==2)value&=0x3ffU;
   m->reg[(l.data0 - 4*w)/4] = value;
  }
 }
 m->reg[m->pending_address/4] = 0;
 m->pending = false;
}

static unsigned int fe_read(void *context, unsigned int address)
{
 struct model *m = ((struct rtl_fe *)context)->model;
 int t = table_at(address, true);
 assert(!(address & 3) && address < sizeof(m->reg));
 if(address==0x3418 || address==0x3424)m->lpb_reads++;
 if (t >= 0) m->table_seen_idle[t] = !(m->reg[address/4] & BIT(31));
 if (address == 0x1904 && m->clear_after && ++m->pending_reads >= m->clear_after)
  m->reg[address/4] = 0;
 if(m->corrupt_read_address==address && m->commands>=m->corrupt_after_command &&
    m->writes>=m->corrupt_after_writes && (!m->corrupt_wait_write || m->corrupt_triggered))
  return m->corrupt_read_value;
 return m->reg[address/4];
}

static void fe_write(void *context, unsigned int address, unsigned int value)
{
 struct model *m = ((struct rtl_fe *)context)->model;
 int t = table_at(address, false);
 assert(!(address & 3) && address < sizeof(m->reg));
 /* User TPID comparators are shared with foreign ports/PON. The native
  * recipe may observe but must never rewrite them to enable built-ins. */
 assert(address < 0x1108 || address > 0x1114);
 if (t >= 0) {
  struct rtl_l2_table_layout l;
  assert(!rtl_l2_table_layout(t, &l));
  assert(m->table_seen_idle[t] && !(m->reg[l.access/4] & BIT(31)));
 }
 for (unsigned int p = 0; p < FE_LAN_PORTS; p++) {
  if (address == FE_LAN_RX_CTRL(p)) {
   assert(m->route_closed);m->rx_writes++;
   if(!(value & BIT(28))) m->native_writes++;
  }
  if (address == 0xa5d4 + 0x90*p) m->tx_writes++;
 }
 if ((address <= 0x1c28 && address >= 0x1c18) || address == 0x1c00)
  assert(!((m->reg[RTL_L2_FDB_ACCESS/4]|m->reg[RTL_L2_FDB_LIMIT_ACCESS/4]) & BIT(31)));
 if(address==RTL_L2_FDB_LIMIT_DATA) {
  assert(!((m->reg[RTL_L2_FDB_ACCESS/4]|m->reg[RTL_L2_FDB_LIMIT_ACCESS/4])&BIT(31)));
  assert(!(m->reg[RTL_L2_FDB_CONTROL/4]&BIT(31)) && (m->reg[RTL_L2_FDB_CONTROL/4]&BIT(22)));
 }
 if(m->corrupt_wait_write && m->corrupt_read_address==address && value==m->corrupt_trigger_value)
  m->corrupt_triggered=true;
 if(m->ignore_write_address!=address || (m->ignore_write_match && value!=m->ignore_write_value))
  m->reg[address/4] = value;
 m->writes++;
}

static int command(void *context, unsigned int address, unsigned int request)
{
 struct model *m = ((struct rtl_fe *)context)->model;
 struct rtl_l2_table_layout l;
 int t = table_at(address, true);
 assert(!m->pending && !(m->reg[address/4] & BIT(31)));
 if(address==RTL_L2_FDB_ACCESS) {l.words=RTL_L2_FDB_WORDS;l.data0=RTL_L2_FDB_DATA0;}
 else if(address!=RTL_L2_FDB_LIMIT_ACCESS) {
  assert(t >= 0 && m->table_seen_idle[t] && !rtl_l2_table_layout(t, &l));
 } else {l.words=1;l.data0=RTL_L2_FDB_LIMIT_DATA;}
 assert(request & BIT(31));
 m->commands++;
 m->pending = true; m->pending_address = address; m->pending_request = request;
 for (unsigned int w = 0; w < l.words; w++)
  m->pending_words[w] = m->reg[(l.data0-4*w)/4];
 m->reg[address/4] = request;
 if (m->fail == m->commands) return -ETIMEDOUT;
 complete(m); return 0;
}
static struct rtl_dq_io fe_io(struct rtl_fe *fe)
 { return (struct rtl_dq_io){fe,fe_read,fe_write,command}; }
static void usleep_range(unsigned int low, unsigned int high)
 { if(low==1000 && high==2000)model.settles++;else {assert(low==10 && high==20); model.delays++;} }
static void fe_route_gate(struct rtl_fe *fe) {
 fe->model->route_closed=true;fe->model->route_gates++;
 fe->route_gate_verified=!fe->model->arm_failure;
 if(fe->route_gate_verified && (fe->enabled || fe->prepared || fe->route_gate_ready ||
    fe->dma_exposed || fe->pending_withdrawals))
  for(unsigned int i=0;i<2;i++)
   fe->model->reg[(0x3418+i*12)/4]=(fe->model->reg[(0x3418+i*12)/4]&~(15U<<10))|BIT(10);
}
static bool fe_route_arm(struct rtl_fe *fe) {
 assert(fe->model->rx_writes);
 assert(fe->pending_withdrawals || (fe->enabled && fe->prepared));
 fe->model->route_arms++;
 if(fe->model->arm_failure)return false;
 if(fe->pending_withdrawals) {
  fe->model->route_closed=true;fe->route_gate_verified=true;
  for(unsigned int i=0;i<2;i++)
   fe->model->reg[(0x3418+i*12)/4]=(fe->model->reg[(0x3418+i*12)/4]&~(15U<<10))|BIT(10);
  return true;
 }
 fe->model->route_closed=false;fe->route_gate_verified=false;
 for(unsigned int i=0;i<2;i++)fe->model->reg[(0x3418+i*12)/4]&=~(15U<<10);
 return true;
}
#include "rtl9617c-fe-switch-hw.h"
#include "rtl9617c-fabric.h"

static struct rtl_fe fe = { .model = &model };
static struct rtl_fe_switch_hw hw;
static struct rtl_l2_snapshot hw_rows[FE_SW_SNAPSHOTS];
static unsigned short hw_index[7039];

static void reset(void)
{
 memset(&model, 0, sizeof(model)); memset(&hw, 0, sizeof(hw));
 memset(hw_rows,0,sizeof(hw_rows));
 assert(ARRAY_SIZE(hw_index)==rtl_l2_journal_index_count());
 hw.rows=hw_rows;
 assert(!rtl_l2_journal_init(&hw.journal,hw_index,ARRAY_SIZE(hw_index),FE_SW_SNAPSHOTS));
 model.route_closed=true;
 fe.enabled = false; fe.prepared = false; fe.pending_withdrawals = 0;fe.route_gate_verified=true;
 fe.route_gate_ready=fe.dma_exposed=false;
 model.reg[RTL_L2_FDB_CONTROL/4] = BIT(31) | BIT(22) | BIT(25) | BIT(29) | 0xff9;
 model.reg[0x1c04/4] = (3830U << 19) | 300U;
 model.reg[0x1414/4] = 3;
 model.reg[0xa034/4] = (64U << 16) | 1526;
 model.reg[0x1410/4] = 0xa5000046;
 model.reg[0x1408/4] = 0x02000210;
 model.reg[0x140c/4] = 0x08100810;
 model.reg[0x1108/4] = 0x88a8;
 model.reg[0x110c/4] = 0x8100;
 model.reg[0x1110/4] = 0x9100;
 model.reg[0x1114/4] = 0x9200;
 model.reg[0xa1e0/4] = 0xabcdef00;
 model.reg[0x2300/4] = BIT(31) | 0x31f;
 for (unsigned int i = 0; i < 5; i++) model.reg[(0x1c28-4*i)/4] = 0xcafebeefU + i;
 model.rows[RTL_L2_TBL_ELPB][16][0] = 2;
 for (unsigned int p = 0; p < 64; p++) {
  model.rows[RTL_L2_TBL_IPPB][p][0]=p;
  model.limits[p]=0xa5000000U|p; /* zero on port0 must not mean unlimited */
  model.rows[RTL_L2_TBL_ILPB][p][0] = 0xc1000b80;
  model.rows[RTL_L2_TBL_ILPB][p][1] = 0xc1800deb;
  model.rows[RTL_L2_TBL_ILPB][p][2] = 0x1800a363;
  model.rows[RTL_L2_TBL_ILPB][p][3] = 0x00108003;
  model.rows[RTL_L2_TBL_ILPB][p][4] = 0x5a000001;
 }
 for (unsigned int p = 0; p < 5; p++) {
  model.reg[FE_LAN_RX_CTRL(p)/4] = BIT(28) | (16U << 16) | BIT(31) | (p << 24);
  model.reg[(0xa5d4+0x90*p)/4] = 1 | BIT(9);
  model.rows[RTL_L2_TBL_ELPB][p][0] = ~0U;
  model.rows[RTL_L2_TBL_ELPB][p][1] = ~0U;
  model.rows[RTL_L2_TBL_CF_KEY][p][0] = ~(p << 6);
  model.rows[RTL_L2_TBL_CF_KEY][p][1] = ~0U;
  model.rows[RTL_L2_TBL_CF_KEY][p][2] = ~0U;
  model.rows[RTL_L2_TBL_CF_KEY][p+512][0] = ~0xfc0U | (p << 6);
  model.rows[RTL_L2_TBL_CF_KEY][p+512][1] = ~0U;
  model.rows[RTL_L2_TBL_CF_KEY][p+512][2] = ~0U;
  model.rows[RTL_L2_TBL_CF_FIB][p][1] = (3U << 5) | (16U << 8);
  model.rows[RTL_L2_TBL_CF_FIB][p][2] = BIT(6);
 }
 memcpy(&original, &model, sizeof(model));
}

static void cpu_only(void)
{
 for (unsigned int p = 0; p < 5; p++)
  assert((model.reg[FE_LAN_RX_CTRL(p)/4] & (BIT(28) | (63U << 16))) ==
         (BIT(28) | (16U << 16)));
 assert(!model.tx_writes);
}

static void restored(void)
{
 static const unsigned int regs[] = {0x1c00,0x1c04,0x1410,0x1408,0x140c,0xa1e0,
  0x1c28,0x1c24,0x1c20,0x1c1c,0x1c18,0x1414,0x1400};
 assert(!memcmp(model.rows, original.rows, sizeof(model.rows)));
 assert(!memcmp(model.limits, original.limits, sizeof(model.limits)));
 for (unsigned int i = 0; i < ARRAY_SIZE(regs); i++)
  assert(model.reg[regs[i]/4] == original.reg[regs[i]/4]);
 assert(!hw.count && !hw.globals_owned && !hw.prepared);
 assert(hw.rows==hw_rows && hw.journal.row_index==hw_index);
 assert(hw.journal.capacity==FE_SW_SNAPSHOTS && hw.journal.index_count==ARRAY_SIZE(hw_index));
 assert(!hw.journal.quarantined && !hw.journal.restoring && !hw.journal.restored);
 assert(hw.rx_gate_verified);
 for(unsigned int i=0;i<ARRAY_SIZE(hw_index);i++)assert(!hw_index[i]);
 cpu_only();
}

static void recipe(unsigned int ports, bool l3)
{
 unsigned int words[5], expected[5], n = 0;
 reset(); fe.enabled = fe.prepared = l3;
 assert(!fe_switch_hw_prepare(&fe, &hw, ports, 123, true,true));
 assert(hw.prepared && hw.drained && hw.globals_owned && hw.special_profile == 7);
 assert(model.reg[0x1c04/4] == original.reg[0x1c04/4]); /* not before domain claim */
 assert(model.reg[0x1c00/4] & BIT(22)); cpu_only();
 assert((model.reg[0xa1e0/4] & 0x3ff) == 0x3ff);
 assert((model.reg[0xa1e0/4] & ~0x3ffU) == (original.reg[0xa1e0/4] & ~0x3ffU));
 for (unsigned int p = 0; p < 64; p++) {
  assert(fe_switch_hw_field(model.rows[RTL_L2_TBL_ILPB][p], RTL_L2_ILPB_STP) ==
         (p < 5 && (ports & BIT(p)) ? 3U : 2U));
  if (p >= 5 || !(ports & BIT(p))) continue;
  assert(model.limits[p]==(original.limits[p]|RTL_L2_FDB_LIMIT_MAX));
  n++;
  assert(!fe_switch_hw_field(model.rows[RTL_L2_TBL_ILPB][p], RTL_L2_ILPB_TOP_S_TPID_ENABLE));
  assert(fe_switch_hw_field(model.rows[RTL_L2_TBL_ILPB][p], RTL_L2_ILPB_TOP_C_TPID_ENABLE));
  assert(fe_switch_hw_field(model.rows[RTL_L2_TBL_ILPB][p], RTL_L2_ILPB_C_TPID_MATCH)==15);
  assert(!fe_switch_hw_field(model.rows[RTL_L2_TBL_ILPB][p], RTL_L2_ILPB_SC_IND));
  assert(!fe_switch_hw_field(model.rows[RTL_L2_TBL_ILPB][p], RTL_L2_ILPB_CLASSIFIER_ENABLE));
  assert(model.rows[RTL_L2_TBL_PORT_MEMBERSHIP][p][0] ==
         ((ports & ~BIT(p)) | BIT(16) | BIT(l3 ? 25 : 16)));
  for (unsigned int k = 0; k < 4; k++)
   assert(model.rows[RTL_L2_TBL_DFT_FWD][4*p+k][0] == ((16U << 1) | BIT(11) | BIT(12)));
  for (unsigned int k = 0; k < 5; k++) {
   unsigned int id = hw.cf[(n-1)*5+k];
   assert(model.rows[RTL_L2_TBL_CF_FIB][id][0] == 0);
   assert(model.rows[RTL_L2_TBL_CF_FIB][id][1] == ((3U << 5) | (16U << 8)));
   assert(model.rows[RTL_L2_TBL_CF_FIB][id][2] == 0);
  }
 }
 assert(hw.cf_count == n * 5);
 for (unsigned int k = 0; k < 32; k++) {
  unsigned int *s = model.rows[RTL_L2_TBL_SPB][7*32+k];
  assert(fe_switch_hw_field(s, RTL_L2_SPB_NO_EDIT));
  assert(fe_switch_hw_field(s, RTL_L2_SPB_LEARN_DISABLE) == (k != 0));
  assert(fe_switch_hw_field(s, RTL_L2_SPB_SPECIAL_FORWARD) == (k != 0));
  assert(fe_switch_hw_field(s, RTL_L2_SPB_DESTINATION) ==
         (!k ? 0U : k == 12 && l3 ? 25U : 16U));
 }
 memcpy(expected, hw.filter, sizeof(expected)); rtl_l2_fdb_scan_filter(expected);
 for (unsigned int i = 0; i < 5; i++) assert(model.reg[(0x1c28-i*4)/4] == expected[i]);
 assert(fe_switch_hw_arm(&fe, &hw, ports, 0,true));
 assert(model.route_arms==(unsigned)l3);
 assert(model.reg[0x1c04/4] == ((3830U << 19) | 123U));
 assert(!(model.reg[0x1c00/4] & (BIT(22) | BIT(25) | BIT(29))));
 assert(((model.reg[0x1c00/4] >> 23) & 3) == 1);
 for (unsigned int p = 0; p < 5; p++)
  assert(!(model.reg[FE_LAN_RX_CTRL(p)/4] & BIT(28)) == !!(ports & BIT(p)));
 assert(fe_switch_hw_restore(&fe, &hw) == -EBUSY);
 assert(!fe_switch_hw_drain(&fe, &hw));
 assert(!fe_switch_hw_restore(&fe, &hw)); restored(); cases++;
 (void)words;
}

/* Connect the real cold transaction to the real native hardware recipe.
 * Neither ready=1 nor a compatible MRU alone proves that native admission
 * is reachable: exercise prepare/arm/withdraw using exactly its output.
 * The rest of the NI/bridge ownership prerequisites remain modeled here;
 * test_ni_cold_handoff separately executes real probe/open publication. */
static void cold_to_native(unsigned int ports, bool l3)
{
 struct rtl_fabric fabric={0};
 struct rtl_dq_io io=fe_io(&fe);

 reset();
 model.reg[0x1414/4]=2;model.reg[0xa034/4]=0x004023f1;
 model.reg[0xa038/4]=9300;
 model.reg[0x1108/4]=model.reg[0x110c/4]=model.reg[0x1110/4]=0x8100;
 model.reg[0x1114/4]=0x9100;
 for(unsigned p=0;p<5;p++) {
  model.reg[RTL_FABRIC_RX_MAC(p)/4]=0x1101;
  model.reg[FE_LAN_RX_CTRL(p)/4]|=BIT(5);
 }
 assert(!rtl_fabric_cold_prepare(&io,&fabric));
 assert(fabric.ready && fabric.changed && fabric.cold_rx_gated==31);
 assert(rtl_fabric_native_mtu_compatible(&fabric) && model.settles==1);
 assert(model.reg[0x1414/4]==3 && model.reg[0xa034/4]==0x004005f6);
 for(unsigned p=0;p<5;p++) {
  assert(!(model.reg[RTL_FABRIC_RX_MAC(p)/4]&1));
  assert(!(model.reg[FE_LAN_RX_CTRL(p)/4]&BIT(5)));
  /* The NI owner opens RX only after its own DMA/QM start; native recipe
   * does not own or reopen the physical MAC receive-enable bit. */
  if(ports&BIT(p))model.reg[RTL_FABRIC_RX_MAC(p)/4]|=1;
 }
 memcpy(&original,&model,sizeof(model));
 fe.enabled=fe.prepared=l3;
 assert(!fe_switch_hw_prepare(&fe,&hw,ports,300,false,true));
 assert(hw.prepared && hw.drained && hw.globals_owned);
 assert(fe_switch_hw_arm(&fe,&hw,ports,0,true));
 for(unsigned p=0;p<5;p++)
  assert(!(model.reg[FE_LAN_RX_CTRL(p)/4]&BIT(28))==!!(ports&BIT(p)));
 assert(!rtl_fabric_check(&io,&fabric));
 assert(!fe_switch_hw_drain(&fe,&hw));
 assert(!fe_switch_hw_restore(&fe,&hw));restored();
 assert(!rtl_fabric_check(&io,&fabric));
 assert(model.reg[0x1414/4]==3 && model.reg[0xa034/4]==0x004005f6);
 cold_cases++;
}

static void guards(void)
{
	reset(); /* Reserved TCAM bits may read zero even when QM wrote ones. */
	for (unsigned int p=0;p<5;p++) {
	 model.rows[RTL_L2_TBL_CF_KEY][p][2] &= 0x1f8ffU;
	 model.rows[RTL_L2_TBL_CF_KEY][p+512][2] &= 0x1f8ffU;
	 model.rows[RTL_L2_TBL_CF_FIB][p][2] |= 0xfffffc00U;
	}
	memcpy(&original, &model, sizeof(model));
	assert(!fe_switch_hw_prepare(&fe,&hw,31,300,false,true));
	assert(!fe_switch_hw_drain(&fe,&hw)); assert(!fe_switch_hw_restore(&fe,&hw));
	restored(); cases++;
 reset(); assert(fe_switch_hw_prepare(&fe,&hw,32,300,false,true)==-EINVAL); cases++;
 reset(); model.reg[0x1414/4]&=~1U;
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false,true)==-EOPNOTSUPP && !hw.globals_owned);
 assert(!strcmp(fe_switch_hw_reason_name(&hw),"requires-existing-svl"));cases++;
 reset();model.rows[RTL_L2_TBL_IPPB][7][0]=0;
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false,true)==-EOPNOTSUPP&&!hw.globals_owned);
 assert(!strcmp(fe_switch_hw_reason_name(&hw),"foreign-source-alias"));cases++;
 reset();model.rows[RTL_L2_TBL_IPPB][0][0]=4;
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false,true)==-EOPNOTSUPP&&!hw.globals_owned);
 assert(!strcmp(fe_switch_hw_reason_name(&hw),"lan-source-map"));cases++;
 reset(); model.reg[0x1400/4]|=BIT(6);
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false,true)==-EOPNOTSUPP); cases++;
 /* Real TYFZA1 reset comparators do not include 88a8. Built-in ILPB
  * recognition remains available and every CSR must stay unchanged. */
 reset();
 model.reg[0x1108/4]=model.reg[0x110c/4]=model.reg[0x1110/4]=0x8100;
 model.reg[0x1114/4]=0x9100;
 memcpy(&original,&model,sizeof(model));
 assert(!fe_switch_hw_prepare(&fe,&hw,3,300,false,true));
 for(unsigned int i=0;i<4;i++)assert(model.reg[(0x1108+i*4)/4]==original.reg[(0x1108+i*4)/4]);
 assert(!fe_switch_hw_drain(&fe,&hw)); assert(!fe_switch_hw_restore(&fe,&hw));
 restored(); cases++;
 /* Custom comparator values also remain opaque, preserved inputs. */
 reset();
 for(unsigned int i=0;i<4;i++)model.reg[(0x1108+i*4)/4]=0x9300+i;
 memcpy(&original,&model,sizeof(model));
 assert(!fe_switch_hw_prepare(&fe,&hw,3,300,false,true));
 assert(!fe_switch_hw_drain(&fe,&hw)); assert(!fe_switch_hw_restore(&fe,&hw));
 for(unsigned int i=0;i<4;i++)assert(model.reg[(0x1108+i*4)/4]==original.reg[(0x1108+i*4)/4]);
 restored(); cases++;
 for(unsigned int maximum=1522; maximum<=9201; maximum++) {
  if(maximum==1526)continue;
  reset();model.reg[0xa034/4]=(64U<<16)|maximum;
  assert(fe_switch_hw_prepare(&fe,&hw,3,300,false,true)==-EOPNOTSUPP&&!hw.globals_owned);
  assert(!strcmp(fe_switch_hw_reason_name(&hw),"native-mtu-baseline"));cases++;
 }
 reset();model.reg[0xa034/4]=(65U<<16)|1526;
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false,true)==-EOPNOTSUPP&&!hw.globals_owned);
 assert(!strcmp(fe_switch_hw_reason_name(&hw),"native-mtu-baseline"));cases++;
 reset();model.reg[FE_LAN_RX_CTRL(1)/4]|=BIT(5);
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false,true)==-EOPNOTSUPP&&!hw.globals_owned);
 assert(hw.observed.rx_oversize_allow==2);cases++;
 reset(); model.rows[RTL_L2_TBL_ELPB][16][0]|=BIT(18);
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false,true)==-EOPNOTSUPP); cases++;
 reset(); model.reg[0x1c04/4]=300;
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false,true)==-EOPNOTSUPP); cases++;
 reset(); model.reg[RTL_L2_FDB_LIMIT_ACCESS/4]=BIT(31);
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false,true)==-EBUSY&&!hw.globals_owned);
 assert(model.reg[0x1c00/4]==original.reg[0x1c00/4]);cpu_only();cases++;
 reset(); model.reg[0x1c00/4]&=~BIT(22);
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false,true)==-EBUSY);
 assert(!fe_switch_hw_drain(&fe,&hw)); assert(!fe_switch_hw_restore(&fe,&hw));
 assert(!(model.reg[0x1c00/4]&BIT(22))); cases++;
 reset(); model.reg[0x1c00/4]&=~BIT(22);
 for(unsigned int k=0;k<32;k++) model.rows[RTL_L2_TBL_SPB][32+k][0]=BIT(4);
 memcpy(&original,&model,sizeof(model));
 assert(!fe_switch_hw_prepare(&fe,&hw,3,300,false,true));
 assert(fe_switch_hw_field(model.rows[RTL_L2_TBL_ILPB][7],RTL_L2_ILPB_STP)==3);
 assert(!fe_switch_hw_drain(&fe,&hw)); assert(!fe_switch_hw_restore(&fe,&hw));
 restored(); cases++;
 reset(); /* A foreign source wildcard must not be hidden by our traps. */
 model.rows[RTL_L2_TBL_CF_KEY][7][2]=BIT(16);
 model.rows[RTL_L2_TBL_CF_KEY][519][2]=BIT(16);
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false,true)==-EBUSY); cases++;
 reset(); /* A profile cannot be borrowed while any outside LPID uses it. */
 for (unsigned int i=0;i<8;i++)
  rtl_l2_field_set(model.rows[RTL_L2_TBL_ILPB][16+i],RTL_L2_ILPB_SPECIAL_PROFILE,i);
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false,true)==-ENOSPC); cases++;
 reset(); hw.globals_owned=true; model.reg[0x1904/4]=1;
 assert(fe_switch_hw_drain(&fe,&hw)==-ETIMEDOUT && !hw.drained); cpu_only(); cases++;
 model.clear_after=5; model.pending_reads=0;
 assert(!fe_switch_hw_drain(&fe,&hw) && hw.drained); cases++;
 reset(); assert(!fe_switch_hw_arm(&fe,&hw,1,0,true));
 assert(!fe_switch_hw_arm(&fe,&hw,0,1,true)); fe.enabled=fe.prepared=true;
 assert(!fe_switch_hw_arm(&fe,&hw,1,1,true)); assert(fe_switch_hw_arm(&fe,&hw,0,31,true));
 for(unsigned int p=0;p<5;p++)
  assert((model.reg[FE_LAN_RX_CTRL(p)/4]&(BIT(28)|(63U<<16)))==(BIT(28)|(25U<<16)));
 fe_switch_hw_gate(&fe,&hw); cpu_only(); cases++;
 reset();fe.enabled=fe.prepared=true;
 assert(!fe_switch_hw_prepare(&fe,&hw,3,300,true,true));model.arm_failure=true;
 assert(!fe_switch_hw_arm(&fe,&hw,3,0,true)&&model.route_closed);cpu_only();cases++;
 /* The route-off mode may still have a published action whose age/cache
  * withdrawal timed out. Native L2 must demand a verified CPU gate in
  * BOTH modes; neither enabled=false nor the presence of L2 owners proves
  * the route connectors actually closed. Refusal precedes native writes. */
 for(unsigned enabled=0;enabled<2;enabled++)for(unsigned fail=0;fail<2;fail++) {
  reset();fe.enabled=enabled;fe.prepared=true;fe.pending_withdrawals=1;
  assert(!fe_switch_hw_prepare(&fe,&hw,3,300,true,true));model.arm_failure=fail;
  unsigned before=model.native_writes;
  assert(fe_switch_hw_arm(&fe,&hw,3,0,true)==!fail);
  assert(model.route_arms==1 && model.route_closed);
  if(fail) {assert(model.native_writes==before);cpu_only();}
  else for(unsigned p=0;p<2;p++)assert(!(model.reg[FE_LAN_RX_CTRL(p)/4]&BIT(28)));
  cases++;
 }
}

static void faults(void)
{
 reset(); assert(!fe_switch_hw_prepare(&fe,&hw,31,300,true,true));
 unsigned int commands=model.commands;
 /* Inject at EVERY indirect command, including snapshots/read-only
  * validation. An ambiguous write completes late before retrying restore. */
 for (unsigned int at=1;at<=commands;at++) {
  reset(); model.fail=at;
  assert(fe_switch_hw_prepare(&fe,&hw,31,300,true,true)==-ETIMEDOUT);
  assert(model.pending && !hw.prepared); cpu_only();
  complete(&model); model.fail=0;
  assert(!fe_switch_hw_drain(&fe,&hw));
  assert(!fe_switch_hw_restore(&fe,&hw)); restored(); fault_cases++;
 }
 /* Every rollback write can also time out. Original snapshots survive
  * partial restores; a second full rollback is idempotent. */
 reset(); assert(!fe_switch_hw_prepare(&fe,&hw,31,300,true,true));
 unsigned int rows=hw.count, start=model.commands;
 assert(!fe_switch_hw_restore(&fe,&hw));
 unsigned int restores=model.commands-start;
 for (unsigned int at=1;at<=restores;at++) {
  reset(); assert(!fe_switch_hw_prepare(&fe,&hw,31,300,true,true));
  assert(!fe_switch_hw_drain(&fe,&hw));
  model.fail=model.commands+at;
  assert(fe_switch_hw_restore(&fe,&hw)==-ETIMEDOUT);
  assert(hw.globals_owned && hw.count==rows && model.pending);
  complete(&model); model.fail=0;
  assert(!fe_switch_hw_drain(&fe,&hw));
  assert(!fe_switch_hw_restore(&fe,&hw)); restored(); fault_cases++;
 }
}

static void rollback_fixture(void)
{
 reset();fe.enabled=fe.prepared=true;
 assert(!fe_switch_hw_prepare(&fe,&hw,31,123,true,true));
 assert(fe_switch_hw_arm(&fe,&hw,31,0,true));
 assert(!fe_switch_hw_drain(&fe,&hw));
}

static void retained_retry(unsigned int count, unsigned int limits)
{
 assert(hw.count==count && hw.globals_owned && hw.limits_owned==limits);
 assert(hw.journal.quarantined && !hw.port_policy_ready);
 assert(hw.rows==hw_rows && hw.journal.row_index==hw_index);
 for(unsigned int i=0;i<hw.count;i++) {
  unsigned int slot;
  assert(hw.rows[i].valid && !rtl_l2_journal_slot(&hw.journal,hw.rows[i].table,hw.rows[i].index,&slot));
  assert(hw_index[slot]==i+1);
 }
 unsigned int writes=model.writes;
 assert(fe_switch_hw_prepare(&fe,&hw,31,300,true,true)==-EALREADY);
 assert(!fe_switch_hw_arm(&fe,&hw,31,0,true));
 assert(!fe_switch_hw_arm(&fe,&hw,0,31,true));
 assert(model.writes==writes);cpu_only();
 model.ignore_write=false;model.ignore_limits=false;model.ignore_write_address=0;
 model.corrupt_read_address=0;
 assert(!fe_switch_hw_drain(&fe,&hw));
 assert(!fe_switch_hw_restore(&fe,&hw));restored();fault_cases++;
}

static void readback_faults(void)
{
 static const unsigned int tables[]={RTL_L2_TBL_ILPB,RTL_L2_TBL_ELPB,RTL_L2_TBL_SPB,
  RTL_L2_TBL_PORT_MEMBERSHIP,RTL_L2_TBL_DFT_FWD,RTL_L2_TBL_CF_FIB,RTL_L2_TBL_CF_KEY};
 static const unsigned int regs[]={0x1c28,0x1c24,0x1c20,0x1c1c,0x1c18,
  0x1410,0x1408,0x140c,0x1c04,0xa1e0,0x1c00};
 static const unsigned int masks[]={~0U,~0U,~0U,~0U,~0U,0x7fU,BIT(29),
  0x7ffU|(0x7ffU<<16),0x7ffffU,0x3ffU,FE_SW_FDB_OWNED_CONTROL};
 for(unsigned int t=0;t<ARRAY_SIZE(tables);t++) {
  reset();model.ignore_write=true;model.ignore_write_table=tables[t];
  assert(fe_switch_hw_prepare(&fe,&hw,31,123,true,true)==-EIO);
  assert(hw.globals_owned && hw.journal.quarantined && !hw.prepared);
  model.ignore_write=false;assert(!fe_switch_hw_drain(&fe,&hw));
  assert(!fe_switch_hw_restore(&fe,&hw));restored();fault_cases++;
  rollback_fixture();unsigned int count=hw.count,limits=hw.limits_owned;
  model.ignore_write=true;model.ignore_write_table=tables[t];
  assert(fe_switch_hw_restore(&fe,&hw)==-EIO);
  retained_retry(count,limits);
  rollback_fixture();count=hw.count;limits=hw.limits_owned;
  struct rtl_l2_table_layout layout;assert(!rtl_l2_table_layout(tables[t],&layout));
  const struct rtl_l2_snapshot *last=NULL;
  for(unsigned int i=0;i<hw.count;i++)if(hw.rows[i].table==tables[t])last=&hw.rows[i];
  assert(last);model.corrupt_read_address=layout.data0;
  model.corrupt_read_value=last->words[0]^2U;
  assert(fe_switch_hw_restore(&fe,&hw)==-EIO);
  retained_retry(count,limits);
 }
 reset();model.ignore_limits=true;
 assert(fe_switch_hw_prepare(&fe,&hw,31,123,true,true)==-EIO);
 assert(hw.limits_owned==1 && hw.journal.quarantined);
 model.ignore_limits=false;assert(!fe_switch_hw_drain(&fe,&hw));
 assert(!fe_switch_hw_restore(&fe,&hw));restored();fault_cases++;
 rollback_fixture();unsigned int count=hw.count,limits=hw.limits_owned;
 model.ignore_limits=true;assert(fe_switch_hw_restore(&fe,&hw)==-EIO);
 retained_retry(count,limits);
 rollback_fixture();count=hw.count;limits=hw.limits_owned;
 model.corrupt_read_address=RTL_L2_FDB_LIMIT_DATA;model.corrupt_read_value=0x123;
 assert(fe_switch_hw_restore(&fe,&hw)==-EIO);retained_retry(count,limits);
 for(unsigned int r=0;r<ARRAY_SIZE(regs);r++) {
  rollback_fixture();count=hw.count;limits=hw.limits_owned;
  /* Some unchanged scan comparison words still belong to the command
   * lease. A disturbed word must be repaired, not silently relinquished. */
  if(!((model.reg[regs[r]/4]^original.reg[regs[r]/4])&masks[r]))
   model.reg[regs[r]/4]^=masks[r]&-masks[r];
  model.ignore_write_address=regs[r];model.ignore_write_match=true;
  model.ignore_write_value=original.reg[regs[r]/4];
  assert(fe_switch_hw_restore(&fe,&hw)==-EIO);retained_retry(count,limits);
  rollback_fixture();count=hw.count;limits=hw.limits_owned;
  model.corrupt_read_address=regs[r];model.corrupt_read_value=~0U;
  model.corrupt_wait_write=true;model.corrupt_trigger_value=original.reg[regs[r]/4];
  assert(fe_switch_hw_restore(&fe,&hw)==-EIO);retained_retry(count,limits);
 }
 /* Persistent controls restored under owned masks must not overwrite a
  * different owner's unrelated update, even on a rollback retry. */
 rollback_fixture();
 for(unsigned int r=5;r<ARRAY_SIZE(regs);r++) {
  unsigned int foreign=~masks[r]&~FE_SW_FDB_COMMAND_BITS;
  unsigned int bit=foreign&-foreign;
  assert(bit);model.reg[regs[r]/4]^=bit;original.reg[regs[r]/4]^=bit;
 }
 assert(!fe_switch_hw_restore(&fe,&hw));restored();cases++;
 /* A failed first snapshot owns an indirect window despite count zero. */
 reset();hw.journal.quarantined=1;
 model.reg[0x11e4/4]=BIT(31);
 assert(fe_switch_hw_prepare(&fe,&hw,31,300,true,true)==-EALREADY);
 assert(!fe_switch_hw_drain(&fe,&hw));
 assert(fe_switch_hw_restore(&fe,&hw)==-EBUSY && hw.journal.quarantined);
 model.reg[0x11e4/4]=0;
 assert(!fe_switch_hw_drain(&fe,&hw));
 assert(!fe_switch_hw_restore(&fe,&hw));restored();fault_cases++;
 /* FIFO initialization has no supported inherited-state contract. */
 {
  reset();model.reg[0x1c00/4]|=BIT(30);
  assert(fe_switch_hw_prepare(&fe,&hw,31,300,true,true)==-EBUSY && !hw.globals_owned);
  rollback_fixture();model.reg[0x1c00/4]|=BIT(30);
  assert(fe_switch_hw_restore(&fe,&hw)==-EBUSY && hw.globals_owned);
  model.reg[0x1c00/4]&=~BIT(30);
  assert(!fe_switch_hw_drain(&fe,&hw));
  assert(!fe_switch_hw_restore(&fe,&hw));restored();fault_cases++;
 }
 /* SDK software-age request is a toggle, NOT a high-level busy flag.
  * Both stable values work; rollback must preserve a newer live toggle
  * instead of replaying the value captured before native preparation. */
 for(unsigned int level=0;level<2;level++) {
  reset();model.reg[0x1c00/4]|=level<<12;original.reg[0x1c00/4]|=level<<12;
  assert(!fe_switch_hw_prepare(&fe,&hw,31,123,true,true));
  assert(fe_switch_hw_arm(&fe,&hw,31,0,true));
  assert(!fe_switch_hw_drain(&fe,&hw));
  model.reg[0x1c00/4]^=BIT(12);original.reg[0x1c00/4]^=BIT(12);
  assert(!fe_switch_hw_restore(&fe,&hw));restored();cases++;
 }
 /* Journal readback ignores only genuine reserved TCAM bits, while the
  * model leaves all defined key/action bits and the full mask observable. */
 reset();model.reserved_read_zero=true;
 for(unsigned int p=0;p<5;p++) {
  model.rows[RTL_L2_TBL_CF_KEY][p][2]&=0x1f8ffU;
  model.rows[RTL_L2_TBL_CF_KEY][p+512][2]&=0x1f8ffU;
 }
 memcpy(&original,&model,sizeof(model));
 assert(!fe_switch_hw_prepare(&fe,&hw,31,123,true,true));
 assert(!fe_switch_hw_restore(&fe,&hw));restored();cases++;
}

static void admission_faults(void)
{
 for(unsigned int p=0;p<5;p++) {
  unsigned int address=FE_LAN_RX_CTRL(p);
  /* Empty counters cannot justify rewriting tables if a selector refused
   * the close write. This is deliberately NOT asserted as CPU-only. */
  reset();fe.enabled=fe.prepared=true;
  assert(!fe_switch_hw_prepare(&fe,&hw,31,123,true,true));
  assert(fe_switch_hw_arm(&fe,&hw,31,0,true));
  assert(!hw.rx_gate_verified);
  unsigned int count=hw.count,commands=model.commands;
  model.ignore_write_address=address;
  assert(fe_switch_hw_drain(&fe,&hw)==-EIO);
  assert(!hw.rx_gate_verified && !hw.drained && hw.count==count);
  assert(!(model.reg[address/4]&BIT(28)) && model.commands==commands);
  assert(fe_switch_hw_restore(&fe,&hw)==-EBUSY && hw.globals_owned && hw.count==count);
  model.ignore_write_address=0;
  assert(!fe_switch_hw_drain(&fe,&hw));
  assert(!fe_switch_hw_restore(&fe,&hw));restored();fault_cases++;
  /* A previously closed selector can drift before rollback. A recorded
   * proof alone must not allow even the first indirect restore command. */
  rollback_fixture();count=hw.count;commands=model.commands;
  assert(hw.rx_gate_verified);model.reg[address/4]&=~BIT(28);
  assert(fe_switch_hw_restore(&fe,&hw)==-EIO);
  assert(!hw.rx_gate_verified && !hw.drained && hw.journal.quarantined);
  assert(hw.globals_owned && hw.count==count && model.commands==commands);
  assert(!fe_switch_hw_drain(&fe,&hw));
  assert(!fe_switch_hw_restore(&fe,&hw));restored();fault_cases++;
  /* A bad final readback after every row/global was restored still must
   * retain the complete journal and allocation for a healthy retry. */
  rollback_fixture();count=hw.count;
  model.corrupt_read_address=address;model.corrupt_read_value=16U<<16;
  model.corrupt_after_command=model.commands+2*hw.count+10;
  assert(fe_switch_hw_restore(&fe,&hw)==-EIO);
  retained_retry(count,31);
  reset();model.reg[address/4]&=~BIT(28);model.ignore_write_address=address;
  assert(fe_switch_hw_prepare(&fe,&hw,31,123,true,true)==-EIO);
  assert(!hw.globals_owned && !hw.count && !hw.prepared && !hw.rx_gate_verified);
  assert(!model.commands && hw.reason==FE_SW_HW_ADMISSION);
  model.ignore_write_address=0;
  assert(!fe_switch_hw_prepare(&fe,&hw,31,123,true,true));
  assert(!fe_switch_hw_restore(&fe,&hw));restored();fault_cases++;
  for(unsigned int corrupt=0;corrupt<2;corrupt++) {
   reset();fe.enabled=fe.prepared=true;
   assert(!fe_switch_hw_prepare(&fe,&hw,31,123,true,true));
   count=hw.count;unsigned int value=model.reg[address/4];
   if(corrupt) {model.corrupt_read_address=address;model.corrupt_read_value=~0U;}
   else model.ignore_write_address=address;
   assert(!fe_switch_hw_arm(&fe,&hw,31,0,true));
   assert(hw.globals_owned && hw.count==count && !hw.port_policy_ready);
   assert(hw.reason==FE_SW_HW_ADMISSION && model.reg[address/4]==value);
   assert(hw.rx_gate_verified==!corrupt);
   model.ignore_write_address=0;model.corrupt_read_address=0;
   assert(!fe_switch_hw_drain(&fe,&hw));
   assert(!fe_switch_hw_restore(&fe,&hw));restored();fault_cases++;
  }
 }
 for(unsigned int connector=0;connector<2;connector++)for(unsigned int bad=0;bad<2;bad++) {
  rollback_fixture();unsigned int address=0x3418+connector*12;
  unsigned int value=model.reg[address/4],count=hw.count,commands=model.commands;
  assert(fe.route_gate_verified);
  model.reg[address/4]=bad?~0U:value&~(15U<<10);
  assert(fe_switch_hw_restore(&fe,&hw)==-EIO);
  assert(hw.globals_owned && hw.count==count && hw.journal.quarantined);
  assert(!hw.drained && model.commands==commands);
  model.reg[address/4]=value;
  assert(!fe_switch_hw_drain(&fe,&hw));
  assert(!fe_switch_hw_restore(&fe,&hw));restored();fault_cases++;
  rollback_fixture();count=hw.count;
  model.corrupt_read_address=address;model.corrupt_read_value=bad?~0U:0;
  model.corrupt_after_command=model.commands+2*hw.count+10;
  assert(fe_switch_hw_restore(&fe,&hw)==-EIO);
  retained_retry(count,31);
 }
 /* Disabling the administrative flag is not disposal of prepared or DMA
  * exposure. Exercise each independent reason to require the L3 gate. */
 for(unsigned int exposure=0;exposure<5;exposure++) {
  reset();
  if(exposure==0)fe.route_gate_ready=true;
  if(exposure==1)fe.prepared=true;
  if(exposure==2)fe.dma_exposed=true;
  if(exposure==3)fe.enabled=true;
  if(exposure==4)fe.pending_withdrawals=1;
  model.arm_failure=true;
  assert(fe_switch_hw_prepare(&fe,&hw,31,123,true,true)==-EIO);
  assert(!hw.globals_owned && !hw.count && !model.commands);
  rollback_fixture();fe.enabled=fe.prepared=false;
  if(exposure==0)fe.route_gate_ready=true;
  if(exposure==1)fe.prepared=true;
  if(exposure==2)fe.dma_exposed=true;
  if(exposure==3)fe.enabled=true;
  if(exposure==4)fe.pending_withdrawals=1;
  unsigned int commands=model.commands,count=hw.count;
  model.arm_failure=true;
  assert(fe_switch_hw_drain(&fe,&hw)==-EIO && !hw.drained);
  assert(hw.count==count && hw.globals_owned && model.commands==commands);
  model.arm_failure=false;
  assert(!fe_switch_hw_drain(&fe,&hw));
  fe.route_gate_verified=false;commands=model.commands;
  assert(fe_switch_hw_restore(&fe,&hw)==-EIO);
  assert(hw.count==count && hw.globals_owned && model.commands==commands);
  assert(!fe_switch_hw_drain(&fe,&hw));
  assert(!fe_switch_hw_restore(&fe,&hw));restored();fault_cases++;
 }
 /* A never-prepared native-only engine has no L3 gate dependency. */
 reset();model.arm_failure=true;
 assert(!fe_switch_hw_prepare(&fe,&hw,31,123,true,true));
 assert(fe_switch_hw_arm(&fe,&hw,31,0,true));
 assert(!fe_switch_hw_drain(&fe,&hw));
 assert(!fe_switch_hw_restore(&fe,&hw));restored();
 assert(!model.lpb_reads);cases++;
}

/*SDK_ORACLE*/
int main(void)
{
 for(unsigned int ports=1;ports<32;ports++) { recipe(ports,false); recipe(ports,true); }
 for(unsigned int ports=1;ports<32;ports++) { cold_to_native(ports,false); cold_to_native(ports,true); }
 guards(); faults();readback_faults();admission_faults();
 /*SDK_RUN*/
 printf("{\"recipe_cases\":%u,\"fault_cases\":%u,\"cold_to_native_cases\":%u,\"hardware_verified\":false}\n",cases,fault_cases,cold_cases);
 return 0;
}
'''

ORACLE = r'''
static bool sdk_cf_match(unsigned int id, const unsigned int packet[3])
{
 const unsigned int *x=model.rows[RTL_L2_TBL_CF_KEY][id];
 const unsigned int *y=model.rows[RTL_L2_TBL_CF_KEY][id+512];
 L2FE_PONCLE_KEY_DATA2_t xv={.wrd=x[2]},yv={.wrd=y[2]};
 if(!xv.bf.valid || !yv.bf.valid)return false;
 for(unsigned int w=0;w<3;w++) if((packet[w]^(~x[w]&y[w]))&(x[w]^y[w]))return false;
 return true;
}
static void sdk_oracle(void)
{
 reset(); assert(!fe_switch_hw_prepare(&fe,&hw,31,300,true,true));
 for(unsigned int p=0;p<5;p++) {
  const unsigned int *w=model.rows[RTL_L2_TBL_ILPB][p];
  L2FE_PP_ILPB_DATA0_t a={.wrd=w[0]};
  L2FE_PP_ILPB_DATA1_t b={.wrd=w[1]};
  L2FE_PP_ILPB_DATA2_t c={.wrd=w[2]};
  L2FE_PP_ILPB_DATA3_t d={.wrd=w[3]};
  assert(!a.bf.ilpb_dscp_mark_control_bm && !a.bf.ilpb_dscp_mode_sel);
  assert(!a.bf.ilpb_802_1p_mark_control_bm && !a.bf.ilpb_inner_802_1p_mode_sel);
  assert(!b.bf.ilpb_igr_cls_lookup_en && b.bf.ilpb_spcl_pkt_idx==7);
  assert(!b.bf.ilpb_da_sa_swap_en && !b.bf.ilpb_802_1p_mark_control_bm);
  assert(c.bf.ilpb_stp_mode==3 && c.bf.ilpb_top_c_tpid_enable && !c.bf.ilpb_top_s_tpid_enable);
  assert(c.bf.ilpb_c_tpid_match==15 && !c.bf.ilpb_inner_vlan_cmd && !c.bf.ilpb_default_top_vlan_cmd);
  assert(!d.bf.ilpb_sc_ind && !d.bf.ilpb_default_vlanid);
  L2FE_PLC_ELPB_DATA0_t e={.wrd=model.rows[RTL_L2_TBL_ELPB][p][0]};
  L2FE_PLC_ELPB_DATA1_t f={.wrd=model.rows[RTL_L2_TBL_ELPB][p][1]};
  assert(e.bf.elpb_egr_port_stp_status && !e.bf.elpb_egr_ve_srch_en && !e.bf.elpb_egr_cls_lookup_en);
  assert(!e.bf.elpb_dscp_mode_sel && !f.bf.elpb_use_tx_vlan_lkup_acl);
  for(unsigned int k=0;k<4;k++) {
   L2FE_PLE_DFT_FWD_DATA_t q={.wrd=model.rows[RTL_L2_TBL_DFT_FWD][p*4+k][0]};
   assert(!q.bf.dft_fwd_deny && q.bf.dft_fwd_mc_group_id==16);
   assert(q.bf.dft_fwd_redir_en && q.bf.dft_fwd_mc_group_id_valid);
  }
 }
 L2FE_PLC_LRN_FWD_CTRL_1_t exceptions={.wrd=model.reg[0x140c/4]};
 assert(exceptions.bf.sa_limit_excd_fwd_ctrl==1 && exceptions.bf.sa_limit_excd_ldpid==16);
 assert(exceptions.bf.sa_hash_cllsn_fwd_ctrl==1 && exceptions.bf.sa_hash_cllsn_ldpid==16);
 assert(fe_switch_hw_arm(&fe,&hw,31,0,true));
 L2FE_L2E_CTRL_t control={.wrd=model.reg[0x1c00/4]};
 assert(!control.bf.lrn_dis && control.bf.lrn_mode==1 && control.bf.cpu_opt_mode);
 assert(!control.bf.hash_collision_overwrite && !control.bf.ovfl_entries_rcyc_en);
 assert(control.bf.aging_start_val==255 && !control.bf.aging_mode);
 L2FE_L2E_PORT_MAC_CNT_LMT_DATA_t limit={.wrd=model.limits[0]};
 assert(limit.bf.val==8191);
 for(unsigned int p=0;p<5;p++) {
  NI_HV_PT_RX_CNTRL_CFG_t rx={.wrd=model.reg[FE_LAN_RX_CTRL(p)/4]};
  assert(!rx.bf.rxctrl_byp_en && rx.bf.rxctrl_byp_dpid==16);
 }
 /* Build keys with real SDK unions, not production encoders. Known UC
  * continues, tags/BC/known+unknown MC trap, UUC uses direct-CPU DFT.
  * No owned rule may capture PON/CPU/another logical source. */
 for(unsigned int p=0;p<64;p++)for(unsigned int type=0;type<5;type++)
  for(unsigned int tag=0;tag<2;tag++)for(unsigned int vid=0;vid<4096;vid+=4095) {
   L2FE_PONCLE_KEY_DATA0_t a={.wrd=0};
   L2FE_PONCLE_KEY_DATA1_t b={.wrd=0};
   L2FE_PONCLE_KEY_DATA2_t c={.wrd=0};
   a.bf.lspid=p;a.bf.pkt_type=type;a.bf.ctag_pkt=tag;
   b.bf.ctag=vid|0xe000;c.bf.valid=1;
   unsigned int packet[]={a.wrd,b.wrd,c.wrd};bool hit=false;
   for(unsigned int i=0;i<hw.cf_count;i++) if(sdk_cf_match(hw.cf[i],packet)) {
    L2FE_PONCLE_FIB_DATA1_t fib={.wrd=model.rows[RTL_L2_TBL_CF_FIB][hw.cf[i]][1]};
    assert(fib.bf.forward_act==3 && fib.bf.cf_fwd_id==16);hit=true;
   }
   assert(hit==(p<5 && (tag || type==1 || type==2 || type==4)));
  }
 fe_switch_hw_gate(&fe,&hw);
 for(unsigned int p=0;p<5;p++) {
  NI_HV_PT_RX_CNTRL_CFG_t rx={.wrd=model.reg[FE_LAN_RX_CTRL(p)/4]};
  assert(rx.bf.rxctrl_byp_en && rx.bf.rxctrl_byp_dpid==16);
 }
}
'''


def without_table_verification(production, table):
    """Negative control keeps the real snapshot but omits one table readback."""
    needle = "\treturn rtl_l2_journal_replace(&hw->journal, &io, hw->rows, &hw->count,"
    insertion = """\tif (table == TABLE) {
\t\tstruct rtl_l2_snapshot *snapshot;
\t\tint ret = rtl_l2_journal_snapshot(&hw->journal, &io, hw->rows, &hw->count,
\t\t\t\t\t\t table, index, &snapshot);
\t\treturn ret ? ret : rtl_l2_table_write(&io, table, index, words);
\t}
""".replace("TABLE", table)
    assert needle in production
    return production.replace(needle, insertion + needle, 1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--registers", type=Path)
    args = parser.parse_args()
    source = TEST
    sdk_verified = False
    if args.registers:
        raw = args.registers.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == REGISTER_HASH, "Unpinned SDK register input"
        register_text = raw.decode()
        names = sorted(set(re.findall(r"\b((?:L2FE|NI_HV)_[A-Z0-9_]+)_t\b", ORACLE)))
        blocks = []
        for name in names:
            pattern = r"typedef volatile union \{(?:(?!typedef volatile union).)*?\} " + name + r"_t;"
            match = re.search(pattern, register_text, re.S)
            assert match, name
            blocks.append(match.group())
        source = source.replace("/*SDK_ORACLE*/", "typedef unsigned int ca_uint32_t;\n" +
                                "\n".join(blocks) + "\n" + ORACLE)
        source = source.replace("/*SDK_RUN*/", "sdk_oracle();")
        sdk_verified = True
    with tempfile.TemporaryDirectory(prefix="thoros-l2-hw-") as temporary:
        build = Path(temporary)
        (build / "linux").mkdir()
        (build / "linux/delay.h").write_text("/* host delay stub is in the fixture */\n")
        (build / "linux/string.h").write_text("#include <string.h>\n")
        (build / "test.c").write_text(source)
        compiler = os.environ.get("CC", "cc")
        production = HEADER.read_text()
        mutations = {
            "old_1522_envelope": production.replace(
                "!= RTL_NI_FRAME_WIRE_BYTES", "!= 1522", 1),
            "unbounded_jumbo_envelope": production.replace(
                "!= RTL_NI_FRAME_WIRE_BYTES", "> 9201", 1),
            "missing_svl_guard": production.replace(
                "!(hw->observed.vlan_mode & RTL_L2_VLAN_MODE_SVL)", "false", 1),
            "outside_learning_left_enabled": production.replace(
                "rtl_l2_field_set(words, RTL_L2_ILPB_STP, stp & ~1U);", "/* omitted deliberately */", 1),
            "missing_reverse_route_gate": production.replace(
                "fe_route_gate(fe);", "/* omitted deliberately */", 1),
            "discard_builtin_tpid_matches": production.replace(
                "RTL_L2_ILPB_C_TPID_MATCH, FE_SW_TPID_ALL", "RTL_L2_ILPB_C_TPID_MATCH, 1", 1),
            "old_false_tpid_veto": production.replace(
                "/* Cold fabric owns", "if (hw->observed.tpid[0] == 0x8100) return -EOPNOTSUPP;\n\t/* Cold fabric owns", 1),
            "disabled_pending_route_skips_gate": production.replace(
                "if (withdrawing && !fe_route_arm(fe))", "if (withdrawing && fe->enabled && !fe_route_arm(fe))", 1),
            "global_restore_not_verified": production.replace(
                "if ((mask != ~0U && actual == ~0U) || ((actual ^ value) & mask))",
                "if ((actual ^ value) & 0U)", 1),
            "limit_restore_not_verified": production.replace(
                "return (actual ^ expected) & RTL_L2_FDB_LIMIT_MAX ? -EIO : 0;",
                "return 0;", 1),
            "journal_allocations_forgotten": production.replace(
                "hw->rows = rows;", "hw->rows = NULL; (void)rows;", 1),
            "membership_write_not_verified": without_table_verification(production, "RTL_L2_TBL_PORT_MEMBERSHIP"),
            "rx_gate_not_verified": production.replace(
                "if (!fe_switch_hw_rx_check(fe, 0, 0))", "if (false)", 1),
            "rollback_uses_stale_rx_gate": production.replace(
                "|| !fe_switch_hw_rx_check(fe, 0, 0) ||", "||", 1),
            "arm_selector_write_not_verified": production.replace(
                "if (!fe_switch_hw_rx_check(fe, native, route))", "if (false)", 1),
            "disabled_route_exposure_ignored": production.replace(
                "READ_ONCE(fe->route_gate_ready) || READ_ONCE(fe->prepared) ||\n\t      READ_ONCE(fe->dma_exposed) || ",
                "", 1),
            "stale_l3_gate_latch": production.replace(
                "if (value == ~0U || ((value >> 10) & 15U) != 1U)", "if (value & 0U)", 1),
        }
        assert all(value != production for value in mutations.values())
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        for name, contents in [("production", production), *mutations.items()]:
            (build / HEADER.name).write_text(contents)
            subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-g",
                            "-Wno-unused-function", "-fsanitize=address,undefined",
                            "-fno-omit-frame-pointer", "-no-pie", "-I", str(build),
                            "-I", str(DRIVERS), str(build / "test.c"),
                            "-o", str(build / "test")], check=True)
            result = subprocess.run([str(build / "test")], text=True, capture_output=True)
            if name == "production":
                if result.returncode:
                    raise AssertionError(result.stderr)
                print(result.stdout.strip())
                evidence = json.loads(result.stdout)
            else:
                assert result.returncode and "Assertion" in result.stderr, (name, result.stderr)
        print("Recipe self-check: rejected wrong MRU, missing SVL/learning/route gates, disabled pending-withdrawal gate and TPID faults")
    evidence.update({"production_sha256": hashlib.sha256(HEADER.read_bytes()).hexdigest(),
                     "fabric_sha256": hashlib.sha256((DRIVERS / "rtl9617c-fabric.h").read_bytes()).hexdigest(),
                     "actual_sdk_registers_verified": sdk_verified,
                     "mutations_rejected": list(mutations),
                     "sanitizers": ["address", "undefined"],
                     "throughput_measured": False})
    (ROOT / "artifacts").mkdir(exist_ok=True)
    (ROOT / "artifacts/l2-hardware-recipe.json").write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()
