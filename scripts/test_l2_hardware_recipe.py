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
 unsigned int delays, clear_after, pending_reads, native_writes, tx_writes;
 unsigned int route_gates, route_arms, rx_writes;
 bool pending, table_seen_idle[RTL_L2_TBL_COUNT], active, route_closed, arm_failure;
};
static struct model model, original;
struct rtl_fe { struct model *model; bool enabled, prepared; };
static unsigned int cases, fault_cases;

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
 if(m->pending_address==RTL_L2_FDB_LIMIT_ACCESS) {
  assert(!(m->reg[RTL_L2_FDB_CONTROL/4]&BIT(31)));
  assert(m->reg[RTL_L2_FDB_CONTROL/4]&BIT(22));
  assert((index&~63U)==RTL_L2_FDB_LIMIT_SELECT);
  if(m->pending_request&BIT(30)) m->limits[index&63]=m->pending_words[0];
  else m->reg[RTL_L2_FDB_LIMIT_DATA/4]=m->limits[index&63];
  m->reg[m->pending_address/4]=0;m->pending=false;return;
 }
 assert(t >= 0);
 assert(!rtl_l2_table_layout(t, &l) && index < l.entries);
 for (unsigned int w = 0; w < l.words; w++) {
  if (m->pending_request & BIT(30)) {
   assert(m->reg[(l.data0 - 4*w)/4] == m->pending_words[w]);
   m->rows[t][index][w] = m->pending_words[w];
  } else m->reg[(l.data0 - 4*w)/4] = m->rows[t][index][w];
 }
 m->reg[m->pending_address/4] = 0;
 m->pending = false;
}

static unsigned int fe_read(void *context, unsigned int address)
{
 struct model *m = ((struct rtl_fe *)context)->model;
 int t = table_at(address, true);
 assert(!(address & 3) && address < sizeof(m->reg));
 if (t >= 0) m->table_seen_idle[t] = !(m->reg[address/4] & BIT(31));
 if (address == 0x1904 && m->clear_after && ++m->pending_reads >= m->clear_after)
  m->reg[address/4] = 0;
 return m->reg[address/4];
}

static void fe_write(void *context, unsigned int address, unsigned int value)
{
 struct model *m = ((struct rtl_fe *)context)->model;
 int t = table_at(address, false);
 assert(!(address & 3) && address < sizeof(m->reg));
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
 m->reg[address/4] = value;
 m->writes++;
}

static int command(void *context, unsigned int address, unsigned int request)
{
 struct model *m = ((struct rtl_fe *)context)->model;
 struct rtl_l2_table_layout l;
 int t = table_at(address, true);
 assert(!m->pending && !(m->reg[address/4] & BIT(31)));
 if(address!=RTL_L2_FDB_LIMIT_ACCESS) {
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
 { assert(low == 10 && high == 20); model.delays++; }
static void fe_route_gate(struct rtl_fe *fe) {
 fe->model->route_closed=true;fe->model->route_gates++;
}
static bool fe_route_arm(struct rtl_fe *fe) {
 assert(fe->model->rx_writes && !(fe->model->rx_writes%5));
 assert(fe->enabled && fe->prepared);
 fe->model->route_arms++;
 if(fe->model->arm_failure)return false;
 fe->model->route_closed=false;return true;
}
#include "rtl9617c-fe-switch-hw.h"

static struct rtl_fe fe = { .model = &model };
static struct rtl_fe_switch_hw hw;

static void reset(void)
{
 memset(&model, 0, sizeof(model)); memset(&hw, 0, sizeof(hw));
 model.route_closed=true;
 fe.enabled = false; fe.prepared = false;
 model.reg[RTL_L2_FDB_CONTROL/4] = BIT(31) | BIT(22) | BIT(25) | BIT(29) | 0xff9;
 model.reg[0x1c04/4] = (3830U << 19) | 300U;
 model.reg[0x1414/4] = 3;
 model.reg[0xa034/4] = (64U << 16) | 1522;
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
 cpu_only();
}

static void recipe(unsigned int ports, bool l3)
{
 unsigned int words[5], expected[5], n = 0;
 reset(); fe.enabled = fe.prepared = l3;
 assert(!fe_switch_hw_prepare(&fe, &hw, ports, 123, true));
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
 assert(fe_switch_hw_arm(&fe, &hw, ports, 0));
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

static void guards(void)
{
	reset(); /* Reserved TCAM bits may read zero even when QM wrote ones. */
	for (unsigned int p=0;p<5;p++) {
	 model.rows[RTL_L2_TBL_CF_KEY][p][2] &= 0x1f8ffU;
	 model.rows[RTL_L2_TBL_CF_KEY][p+512][2] &= 0x1f8ffU;
	 model.rows[RTL_L2_TBL_CF_FIB][p][2] |= 0xfffffc00U;
	}
	memcpy(&original, &model, sizeof(model));
	assert(!fe_switch_hw_prepare(&fe,&hw,31,300,false));
	assert(!fe_switch_hw_drain(&fe,&hw)); assert(!fe_switch_hw_restore(&fe,&hw));
	restored(); cases++;
 reset(); assert(fe_switch_hw_prepare(&fe,&hw,32,300,false)==-EINVAL); cases++;
 reset(); model.reg[0x1414/4]&=~1U;
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false)==-EOPNOTSUPP && !hw.globals_owned);
 assert(!strcmp(fe_switch_hw_reason_name(&hw),"requires-existing-svl"));cases++;
 reset();model.rows[RTL_L2_TBL_IPPB][7][0]=0;
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false)==-EOPNOTSUPP&&!hw.globals_owned);
 assert(!strcmp(fe_switch_hw_reason_name(&hw),"foreign-source-alias"));cases++;
 reset();model.rows[RTL_L2_TBL_IPPB][0][0]=4;
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false)==-EOPNOTSUPP&&!hw.globals_owned);
 assert(!strcmp(fe_switch_hw_reason_name(&hw),"lan-source-map"));cases++;
 reset(); model.reg[0x1400/4]|=BIT(6);
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false)==-EOPNOTSUPP); cases++;
 reset(); model.reg[0x1108/4]=0x8100;
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false)==-EOPNOTSUPP); cases++;
 reset();model.reg[0xa034/4]=(64U<<16)|1523;
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false)==-EOPNOTSUPP&&!hw.globals_owned);
 assert(!strcmp(fe_switch_hw_reason_name(&hw),"native-mtu-baseline"));cases++;
 reset();model.reg[FE_LAN_RX_CTRL(1)/4]|=BIT(5);
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false)==-EOPNOTSUPP&&!hw.globals_owned);
 assert(hw.observed.rx_oversize_allow==2);cases++;
 reset(); model.rows[RTL_L2_TBL_ELPB][16][0]|=BIT(18);
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false)==-EOPNOTSUPP); cases++;
 reset(); model.reg[0x1c04/4]=300;
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false)==-EOPNOTSUPP); cases++;
 reset(); model.reg[RTL_L2_FDB_LIMIT_ACCESS/4]=BIT(31);
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false)==-EBUSY&&!hw.globals_owned);
 assert(model.reg[0x1c00/4]==original.reg[0x1c00/4]);cpu_only();cases++;
 reset(); model.reg[0x1c00/4]&=~BIT(22);
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false)==-EBUSY);
 assert(!fe_switch_hw_drain(&fe,&hw)); assert(!fe_switch_hw_restore(&fe,&hw));
 assert(!(model.reg[0x1c00/4]&BIT(22))); cases++;
 reset(); model.reg[0x1c00/4]&=~BIT(22);
 for(unsigned int k=0;k<32;k++) model.rows[RTL_L2_TBL_SPB][32+k][0]=BIT(4);
 memcpy(&original,&model,sizeof(model));
 assert(!fe_switch_hw_prepare(&fe,&hw,3,300,false));
 assert(fe_switch_hw_field(model.rows[RTL_L2_TBL_ILPB][7],RTL_L2_ILPB_STP)==3);
 assert(!fe_switch_hw_drain(&fe,&hw)); assert(!fe_switch_hw_restore(&fe,&hw));
 restored(); cases++;
 reset(); /* A foreign source wildcard must not be hidden by our traps. */
 model.rows[RTL_L2_TBL_CF_KEY][7][2]=BIT(16);
 model.rows[RTL_L2_TBL_CF_KEY][519][2]=BIT(16);
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false)==-EBUSY); cases++;
 reset(); /* A profile cannot be borrowed while any outside LPID uses it. */
 for (unsigned int i=0;i<8;i++)
  rtl_l2_field_set(model.rows[RTL_L2_TBL_ILPB][16+i],RTL_L2_ILPB_SPECIAL_PROFILE,i);
 assert(fe_switch_hw_prepare(&fe,&hw,3,300,false)==-ENOSPC); cases++;
 reset(); hw.globals_owned=true; model.reg[0x1904/4]=1;
 assert(fe_switch_hw_drain(&fe,&hw)==-ETIMEDOUT && !hw.drained); cpu_only(); cases++;
 model.clear_after=5; model.pending_reads=0;
 assert(!fe_switch_hw_drain(&fe,&hw) && hw.drained); cases++;
 reset(); assert(!fe_switch_hw_arm(&fe,&hw,1,0));
 assert(!fe_switch_hw_arm(&fe,&hw,0,1)); fe.enabled=fe.prepared=true;
 assert(!fe_switch_hw_arm(&fe,&hw,1,1)); assert(fe_switch_hw_arm(&fe,&hw,0,31));
 for(unsigned int p=0;p<5;p++)
  assert((model.reg[FE_LAN_RX_CTRL(p)/4]&(BIT(28)|(63U<<16)))==(BIT(28)|(25U<<16)));
 fe_switch_hw_gate(&fe,&hw); cpu_only(); cases++;
 reset();fe.enabled=fe.prepared=true;
 assert(!fe_switch_hw_prepare(&fe,&hw,3,300,true));model.arm_failure=true;
 assert(!fe_switch_hw_arm(&fe,&hw,3,0)&&model.route_closed);cpu_only();cases++;
}

static void faults(void)
{
 reset(); assert(!fe_switch_hw_prepare(&fe,&hw,31,300,true));
 unsigned int commands=model.commands;
 /* Inject at EVERY indirect command, including snapshots/read-only
  * validation. An ambiguous write completes late before retrying restore. */
 for (unsigned int at=1;at<=commands;at++) {
  reset(); model.fail=at;
  assert(fe_switch_hw_prepare(&fe,&hw,31,300,true)==-ETIMEDOUT);
  assert(model.pending && !hw.prepared); cpu_only();
  complete(&model); model.fail=0;
  assert(!fe_switch_hw_drain(&fe,&hw));
  assert(!fe_switch_hw_restore(&fe,&hw)); restored(); fault_cases++;
 }
 /* Every rollback write can also time out. Original snapshots survive
  * partial restores; a second full rollback is idempotent. */
 reset(); assert(!fe_switch_hw_prepare(&fe,&hw,31,300,true));
 unsigned int rows=hw.count, restores=rows+5;
 for (unsigned int at=1;at<=restores;at++) {
  reset(); assert(!fe_switch_hw_prepare(&fe,&hw,31,300,true));
  assert(!fe_switch_hw_drain(&fe,&hw));
  model.fail=model.commands+at;
  assert(fe_switch_hw_restore(&fe,&hw)==-ETIMEDOUT);
  assert(hw.globals_owned && hw.count==rows && model.pending);
  complete(&model); model.fail=0;
  assert(!fe_switch_hw_drain(&fe,&hw));
  assert(!fe_switch_hw_restore(&fe,&hw)); restored(); fault_cases++;
 }
}

/*SDK_ORACLE*/
int main(void)
{
 for(unsigned int ports=1;ports<32;ports++) { recipe(ports,false); recipe(ports,true); }
 guards(); faults();
 /*SDK_RUN*/
 printf("{\"recipe_cases\":%u,\"fault_cases\":%u,\"hardware_verified\":false}\n",cases,fault_cases);
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
 reset(); assert(!fe_switch_hw_prepare(&fe,&hw,31,300,true));
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
 assert(fe_switch_hw_arm(&fe,&hw,31,0));
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
        (build / "test.c").write_text(source)
        compiler = os.environ.get("CC", "cc")
        production = HEADER.read_text()
        mutations = {
            "missing_svl_guard": production.replace(
                "!(hw->observed.vlan_mode & RTL_L2_VLAN_MODE_SVL)", "false", 1),
            "outside_learning_left_enabled": production.replace(
                "rtl_l2_field_set(words, RTL_L2_ILPB_STP, stp & ~1U);", "/* omitted deliberately */", 1),
            "missing_reverse_route_gate": production.replace(
                "fe_route_gate(fe);", "/* omitted deliberately */", 1),
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
            result = subprocess.run([str(build / "test")], text=True, capture_output=True,
                                    env={**os.environ, "ASAN_OPTIONS": "detect_leaks=0"})
            if name == "production":
                if result.returncode:
                    raise AssertionError(result.stderr)
                print(result.stdout.strip())
                evidence = json.loads(result.stdout)
            else:
                assert result.returncode and "Assertion" in result.stderr, (name, result.stderr)
        print("Recipe self-check: rejected missing SVL, outside-learning and reverse-route gates")
    evidence.update({"production_sha256": hashlib.sha256(HEADER.read_bytes()).hexdigest(),
                     "actual_sdk_registers_verified": sdk_verified,
                     "mutations_rejected": list(mutations),
                     "sanitizers": ["address", "undefined"],
                     "throughput_measured": False})
    (ROOT / "artifacts").mkdir(exist_ok=True)
    (ROOT / "artifacts/l2-hardware-recipe.json").write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()
