#!/usr/bin/env python3
"""Run real NI TM/TE evidence helpers against the pinned SDK/register oracle.

No router access. Does not establish ASIC timing, reset detection or throughput.
Usage: --registers rtl8277c_registers.h --sdk-root path/to/aal-77c
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
DRIVER = ROOT / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
PINS = {
    'aal_l2_tm.c': 'dc23170e0e3ff71aaa9a81b4d90b07de5d5c1a165a25912c117bd1eb59f433b4',
    'aal_l2_te.c': 'b05f236319071cdcc59ee34ac5f44470b1ac16a6d5822dba6a284613c3ffd852',
    'aal_l2_qm.c': '9ad3f7ee25f9c0d0cdf1714117ba8a58912bb72194732d395185567df51190c1',
    'include/aal_common.h': '6b5b388ed35fd7dd9b91115961da41551b143948e67e50c7f3ae6390817a4b98',
    'include/aal_port.h': '190e4c0c2ac7e99515162fac8775fb33c5ee605423d3809b09bda85708c99f7e',
    'include/aal_l2_tm.h': 'e4e7a780223af189b4ed83aa9e2ea41f4901cbff3a45b485c1a089dfd7f9f6f6',
}
REGISTER_SHA = 'ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0'


def verified(path, digest):
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest, f'unpinned SDK input: {path}'
    return data.decode()


def declaration(text, name):
    begin = re.search(r'^#define ' + name + r'\s+0x', text, re.M).start()
    end = text.index('#endif /* !__ASSEMBLER__ */', begin)
    return text[begin:end] + '#endif /* !__ASSEMBLER__ */\n'


def function(text, name):
    match = re.search(r'^.*\b' + name + r'\s*\([^;]*?\)\s*\{', text, re.M)
    assert match, name
    end = text.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[match.start():end] + '\n'


MODEL = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include "rtl9617c-tm-evidence.h"
#include "rtl9617c-fe-format.h"
typedef uint32_t ca_uint32_t;
typedef uint8_t ca_uint8_t;
typedef unsigned ca_device_id_t;
typedef int ca_status_t;
#define CA_E_OK 0
#define CA_E_PARAM -1
typedef unsigned long long u64;
#define BIT(n) (1U<<(n))
struct model {unsigned int reg[0x10000/4], reads, counter_reads[RTL_TM_COUNTERS];
 unsigned int change_reg, config_reads;unsigned long long now;};
static unsigned int read_reg(void *context,unsigned int reg) {
 struct model *m=context;unsigned value;bool allowed=false;
 assert(!(reg&3) && reg<sizeof(m->reg));m->reads++;
 for(unsigned i=0;i<RTL_TM_CONFIGS;i++)allowed|=reg==rtl_tm_config_registers[i].offset;
 for(unsigned i=0;i<RTL_TM_STATUSES;i++)allowed|=reg==rtl_tm_status_registers[i].offset;
 for(unsigned i=0;i<RTL_TM_COUNTERS;i++)allowed|=reg==rtl_tm_counter_registers[i].offset;
 assert(allowed); /* No indirect ACCESS/data selector or unrelated MMIO. */
 value=m->reg[reg/4];
 if(reg==m->change_reg && ++m->config_reads==2)value^=1;
 for(unsigned i=0;i<RTL_TM_COUNTERS;i++)if(reg==rtl_tm_counter_registers[i].offset) {
  m->counter_reads[i]++;
  if(i<RTL_TM_BM_COUNTERS && (m->reg[0x2010/4]&BIT(31)))m->reg[reg/4]=0;
 }
 return value;
}
static struct model *sdk_model;
#define CA_DEV_NE_REG_READ(device,reg) read_reg(sdk_model,(reg)-0xf4300000U)
static unsigned long long clock_ns(void *context){return ((struct model*)context)->now++;}
static void put_counters(struct model *m,unsigned value) {
 for(unsigned i=0;i<RTL_TM_COUNTERS;i++)m->reg[rtl_tm_counter_registers[i].offset/4]=value+i;
}
static void tick(struct model *m){m->now+=1000000000ULL;}
static void assert_zero(const struct rtl_tm_evidence *s) {
 for(unsigned i=0;i<RTL_TM_BM_COUNTERS;i++)assert(!s->observed[i]);
}

/* These stubs execute the actual sysfs functions, including trylock/lifetime
 * handling and formatting. A read function is deliberately the only I/O API. */
struct mutex {bool held;};
struct rtl_xram {struct mutex tm_evidence_lock;struct rtl_tm_evidence tm_evidence;
 u64 tm_owner_generation;bool removing,provider_ready,base_ready,host_active,engine_poisoned;
 struct model model;};
struct device {struct rtl_xram *priv;};
struct device_attribute {int unused;};
typedef long ssize_t;
static bool rtnl_held;
static struct rtl_xram *clock_owner;
#define READ_ONCE(x) (x)
static bool rtnl_trylock(void){if(rtnl_held)return false;rtnl_held=true;return true;}
static void rtnl_unlock(void){assert(rtnl_held);rtnl_held=false;}
static bool mutex_trylock(struct mutex *m){if(m->held)return false;m->held=true;return true;}
static void mutex_unlock(struct mutex *m){assert(m->held);m->held=false;}
static void *dev_get_drvdata(struct device *d){return d->priv;}
static struct rtl_xram *netdev_priv(void *p){return p;}
static unsigned int rtl_mib_read(void *p,unsigned int reg){return read_reg(&((struct rtl_xram*)p)->model,reg);}
static unsigned long long ktime_get_boottime_ns(void){return clock_ns(&clock_owner->model);}
static int sysfs_emit_at(char *buf,int at,const char *fmt,...) {
 va_list args;int length;
 assert(at>=0 && at<4096);va_start(args,fmt);
 length=vsnprintf(buf+at,4096-at,fmt,args);va_end(args);
 assert(length>=0 && length<4096-at);return length;
}
#define sysfs_emit(buf,...) sysfs_emit_at(buf,0,__VA_ARGS__)
'''

TEST = r'''
int main(void) {
 check_sdk();
 for(unsigned clear=0;clear<2;clear++) {
  struct model m={.now=1000000000ULL};struct rtl_tm_evidence s={0};
  struct rtl_tm_observe_io io={&m,read_reg,clock_ns};
  m.reg[0x2010/4]=clear?BIT(31):0;
  put_counters(&m,100);
  assert(rtl_tm_evidence_capture(&io,&s,1)==1);
  assert(s.seq==1 && s.epoch==1 && s.valid && !s.delta_valid);
  assert(s.epoch_reason==RTL_TM_FIRST_SAMPLE);assert_zero(&s);
  for(unsigned i=0;i<RTL_TM_COUNTERS;i++)assert(m.counter_reads[i]==1);
  unsigned reads=m.reads;
  assert(!rtl_tm_evidence_capture(&io,&s,1));assert(m.reads==reads && s.seq==1);
  tick(&m);put_counters(&m,107);
  assert(rtl_tm_evidence_capture(&io,&s,1)==1);
  assert(s.epoch==1 && s.delta_valid);
  for(unsigned i=0;i<RTL_TM_BM_COUNTERS;i++)assert(s.observed[i]==(clear?107+i:7));
  /* The direct TE sample is raw even though PM memory clear mode changes. */
  assert(s.raw[7]==114);tick(&m);m.reg[0x2f00/4]=BIT(5);
  assert(rtl_tm_evidence_capture(&io,&s,1)==1);
  assert(s.epoch==2 && s.epoch_reason==RTL_TM_CONFIG_CHANGED && !s.delta_valid);assert_zero(&s);
  tick(&m);m.reg[0x2908/4]=0xff000000;
  rtl_tm_evidence_capture(&io,&s,1);assert(s.epoch==3 && !s.delta_valid);
  /* Stop/open, even if final registers are unchanged, starts a new epoch. */
  tick(&m);rtl_tm_evidence_capture(&io,&s,3);
  assert(s.epoch==4 && s.epoch_reason==RTL_TM_OWNER_CHANGED && !s.delta_valid);
  tick(&m);m.change_reg=0x2210;m.config_reads=0;
  unsigned before=m.counter_reads[0];rtl_tm_evidence_capture(&io,&s,3);
  assert(!s.valid && !s.delta_valid && s.epoch_reason==RTL_TM_CONFIG_UNSTABLE);
  assert(m.counter_reads[0]==before+1); /* no retry-consuming a clear counter */
  reads=m.reads;assert(!rtl_tm_evidence_capture(&io,&s,3));
  assert(m.reads==reads); /* invalid samples are rate limited too */
  m.change_reg=0;tick(&m);rtl_tm_evidence_capture(&io,&s,3);
  assert(s.valid && !s.delta_valid);assert_zero(&s);
  tick(&m);put_counters(&m,0xffffffffU);rtl_tm_evidence_capture(&io,&s,3);
  assert(!s.delta_valid && s.epoch_reason==RTL_TM_DECREASE_OR_SATURATION);assert_zero(&s);
  rtl_tm_evidence_invalidate(&s);assert(!s.valid && !s.delta_valid);
 }
 /* A cumulative decrease is NOT silently wrapped by 2^32. */
 {
  struct model m={.now=1};struct rtl_tm_evidence s={0};struct rtl_tm_observe_io io={&m,read_reg,clock_ns};
  put_counters(&m,100);rtl_tm_evidence_capture(&io,&s,1);tick(&m);
  put_counters(&m,10);rtl_tm_evidence_capture(&io,&s,1);
  assert(s.valid && !s.delta_valid && s.epoch==2);assert_zero(&s);
  tick(&m);put_counters(&m,20);rtl_tm_evidence_capture(&io,&s,1);
  assert(s.delta_valid && s.observed[0]==10);
  m.now=1;rtl_tm_evidence_capture(&io,&s,1);assert(!s.delta_valid && s.epoch==3);
  tick(&m);s.observed[0]=~0ULL;put_counters(&m,30);rtl_tm_evidence_capture(&io,&s,1);
  assert(!s.delta_valid && s.epoch_reason==RTL_TM_DECREASE_OR_SATURATION);
 }
 for(unsigned config=0;config<RTL_TM_CONFIGS;config++) {
  struct model m={.now=1};struct rtl_tm_evidence s={0};struct rtl_tm_observe_io io={&m,read_reg,clock_ns};
  rtl_tm_evidence_capture(&io,&s,1);tick(&m);
  m.reg[rtl_tm_config_registers[config].offset/4]^=1;
  rtl_tm_evidence_capture(&io,&s,1);
  assert(s.epoch==2 && !s.delta_valid && s.epoch_reason==RTL_TM_CONFIG_CHANGED);
 }
 /* Exercise the previously untracked pool/selector addresses explicitly,
  * not only the production list: omitting one must break this regression. */
 {
  const unsigned config[]={0x220c,0x2214,0x221c,0x2220,0x2224,0x2228,0x222c};
  for(unsigned i=0;i<sizeof(config)/sizeof(config[0]);i++) {
   struct model m={.now=1};struct rtl_tm_evidence s={0};struct rtl_tm_observe_io io={&m,read_reg,clock_ns};
   rtl_tm_evidence_capture(&io,&s,1);tick(&m);m.reg[config[i]/4]^=1;
   rtl_tm_evidence_capture(&io,&s,1);
   assert(s.epoch==2 && !s.delta_valid && s.epoch_reason==RTL_TM_CONFIG_CHANGED);
   tick(&m);m.change_reg=config[i];m.config_reads=0;
   unsigned before=m.counter_reads[0];rtl_tm_evidence_capture(&io,&s,1);
   assert(!s.valid && !s.delta_valid && s.epoch_reason==RTL_TM_CONFIG_UNSTABLE);
   assert(m.counter_reads[0]==before+1);
  }
 }
 /* These are changing resource gauges, not cumulative counters. Decreasing
  * occupancy/free counts (including reserved bits) does not reset a valid
  * BM epoch, and the complete raw value is kept for interpretation. */
 {
  const unsigned status[]={0x2230,0x2260,0x2238,0x223c,0x2240,0x2244,0x2248,0x224c,0x2250,0x2254};
  struct model m={.now=1};struct rtl_tm_evidence s={0};struct rtl_tm_observe_io io={&m,read_reg,clock_ns};
  for(unsigned i=0;i<sizeof(status)/sizeof(status[0]);i++)m.reg[status[i]/4]=0xa5a50001U+i;
  rtl_tm_evidence_capture(&io,&s,1);tick(&m);
  for(unsigned i=0;i<sizeof(status)/sizeof(status[0]);i++)m.reg[status[i]/4]=0x80000000U+i;
  rtl_tm_evidence_capture(&io,&s,1);assert(s.epoch==1 && s.delta_valid);
  for(unsigned i=0;i<sizeof(status)/sizeof(status[0]);i++) {
   bool found=false;
   for(unsigned j=0;j<RTL_TM_STATUSES;j++)if(rtl_tm_status_registers[j].offset==status[i]) {
    assert(s.status[j]==0x80000000U+i);found=true;
   }
   assert(found);
  }
  assert_zero(&s);
 }
 {
  struct model m={.now=1};struct rtl_tm_evidence s={0};struct rtl_tm_observe_io io={&m,read_reg,clock_ns};
  rtl_tm_evidence_capture(&io,&s,1);tick(&m);m.reg[0x200c/4]^=BIT(30);
  rtl_tm_evidence_capture(&io,&s,1);assert(s.delta_valid && s.epoch==1);
  tick(&m);m.reg[0x200c/4]^=BIT(31);rtl_tm_evidence_capture(&io,&s,1);
  assert(!s.delta_valid && s.epoch==2);
  tick(&m);m.reg[0x2f08/4]^=1;rtl_tm_evidence_capture(&io,&s,1);
  assert(!s.delta_valid && s.epoch==3);
 }
 {
  struct rtl_xram p={.provider_ready=true,.base_ready=true,.host_active=true,.tm_owner_generation=1};
  struct device dev={&p};char output[4096];clock_owner=&p;p.model.now=1000000000ULL;
  assert(fabric_evidence_show(&dev,NULL,output)>0 && !p.model.reads);
  assert(strstr(output,"valid=0") && strstr(output,"wan_arb_readback=0"));
  assert(fabric_sample_show(&dev,NULL,output)>0);
  assert(strstr(output,"sampled=1 seq=1 epoch=1 valid=1"));
  unsigned reads=p.model.reads;
  for(unsigned i=0;i<10;i++) {
   assert(fabric_evidence_show(&dev,NULL,output)>0 && p.model.reads==reads);
   assert(strstr(output,"mode=unknown") && strstr(output,"hardware_reset_verified=0"));
  }
  assert(fabric_sample_show(&dev,NULL,output)>0 && p.model.reads==reads);
  rtnl_held=true;assert(fabric_sample_show(&dev,NULL,output)==-EAGAIN);
  assert(fabric_evidence_show(&dev,NULL,output)==-EAGAIN);rtnl_held=false;
  p.tm_evidence_lock.held=true;assert(fabric_sample_show(&dev,NULL,output)==-EAGAIN && !rtnl_held);
  assert(fabric_evidence_show(&dev,NULL,output)==-EAGAIN && !rtnl_held);p.tm_evidence_lock.held=false;
  for(unsigned i=0;i<5;i++) {
   bool *flag=i==0?&p.removing:i==1?&p.engine_poisoned:i==2?&p.provider_ready:i==3?&p.base_ready:&p.host_active;
   bool saved=*flag;*flag=!saved;
   assert(fabric_sample_show(&dev,NULL,output)==-EAGAIN && p.model.reads==reads);
   assert(!p.tm_evidence.valid && !rtnl_held && !p.tm_evidence_lock.held);*flag=saved;
  }
  tick(&p.model);assert(fabric_sample_show(&dev,NULL,output)>0);
  assert(p.tm_evidence.valid && !p.tm_evidence.delta_valid);
  /* The complete worst-width cache must fit one PAGE_SIZE sysfs read. */
  memset(&p.tm_evidence,0xff,sizeof(p.tm_evidence));
  assert(fabric_evidence_show(&dev,NULL,output)>0 && strlen(output)<4096);
 }
 puts("TM evidence: pinned SDK offsets/modes/NoDrop and actual direct QM getters, all pool/profile configuration mutations, raw resource gauges, real capture/cache endpoints, PAGE_SIZE, read-clear ownership, epochs, decrease/saturation, clock and remove/lock guards PASS (host model only)");
 return 0;
}
'''


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--registers', required=True, type=Path)
    parser.add_argument('--sdk-root', required=True, type=Path)
    args = parser.parse_args()
    regs = verified(args.registers, REGISTER_SHA)
    sdk = {name: verified(args.sdk_root / name, digest) for name, digest in PINS.items()}
    # Compile the original generated field layouts, not duplicate C bitfields.
    names = ('L2TM_L2TM_GLB_CTRL', 'L2TM_L2TE_PM_CTRL', 'L2TM_L2TE_FC_GLB_CTRL',
             'L2TM_L2TM_QM_EQ_FREECNT', 'L2TM_L2TM_QM_EQ_GLB_FREECNT',
             'L2TM_L2TM_QM_EQ_COS0_BUFCNT', 'L2TM_L2TM_QM_PORT_NO_PRVT_STS')
    source = MODEL + '\n'.join(declaration(regs, name) for name in names)
    source += ''.join(function(sdk['aal_l2_qm.c'], name) for name in
                      ('aal_l2_qm_eq_free_cnt_get', 'aal_l2_qm_eq_glb_free_cnt_get',
                       'aal_l2_qm_eq_cos_buf_cnt_get', 'aal_l2_qm_port_prvt_buff_status_get'))
    common = sdk['include/aal_common.h']
    begin = common.index('typedef union {', common.index('/* from G3 Header_v32.xlsm */'))
    source += common[begin:common.index('} HEADER_A_T;', begin) + len('} HEADER_A_T;')] + '\n'
    # All configured and observed addresses must exist in the pinned silicon
    # declaration. Check the NI demux reverse register ordering as well.
    table = {
        'tm_clear_control': 'L2TM_L2TM_GLB_CTRL', 'bm_control': 'L2TM_L2TM_BM_CTRL',
        'buffer_config': 'L2TM_L2TM_QM_GLOB_BUF_CFG', 'eq_config': 'L2TM_L2TM_QM_EQ_CFG',
        'private_config': 'L2TM_L2TM_QM_PORT_PRVT_PROFILE0', 'es_control': 'L2TM_L2TM_ES_CTRL',
        'te_control': 'L2TM_L2TE_GLB_CTRL', 'fc_control': 'L2TM_L2TE_FC_GLB_CTRL',
        'te_pm_control': 'L2TM_L2TE_PM_CTRL', 'ni_internal': 'NI_HV_GLB_INTERNAL_PORT_ID_CFG',
        'lpb_map': 'L3FE_STG0_LDPID_MAP', 'tm_init': 'L2TM_L2TM_GLB_STS',
        'te_pm_init': 'L2TM_L2TE_PM_STS', 'fc_status': 'L2TM_L2TE_FC_GLB_STS',
        'es_ready': 'L2TM_L2TM_ES_STS', 'es_port_ok': 'L2TM_L2TM_ES_PORT_OK_STS',
        'es_arb': 'L2TM_L2TM_ES_ABR_STS', 'buffer_free': 'L2TM_L2TM_QM_EQ_GLB_FREECNT',
        'eq_weight': 'L2TM_L2TM_QM_EQ_CFG1', 'fe_backpressure': 'L2TM_L2TM_QM_GLOB_BUF_CFG1',
        'private_profile1': 'L2TM_L2TM_QM_PORT_PRVT_PROFILE1',
        'private_profile2': 'L2TM_L2TM_QM_PORT_PRVT_PROFILE2',
        'private_profile3': 'L2TM_L2TM_QM_PORT_PRVT_PROFILE3',
        'private_select0': 'L2TM_L2TM_QM_PORT_PRVT_SELECT0',
        'private_select1': 'L2TM_L2TM_QM_PORT_PRVT_SELECT1',
        'private_empty_ports': 'L2TM_L2TM_QM_PORT_NO_PRVT_STS',
        'eq_free': 'L2TM_L2TM_QM_EQ_FREECNT',
    }
    for i in range(4):
        table[f'ni_demux{i}'] = f'NI_HV_GLB_NIRX_L3FE_DEMUX_CFG{i}'
        table[f'ni_deep{i}'] = f'NI_HV_GLB_NIRX_L3FE_DPQ_DEMUX_CFG{i}'
    for key, suffix in (('bm_rx', 'RX_PCNT'), ('bm_tx', 'TX_PCNT'), ('bm_sb_drop', 'SB_DPCNT'),
                        ('bm_hdr_drop', 'HDR_DPCNT'), ('bm_te_drop', 'TE_DPCNT'),
                        ('bm_err_drop', 'ERR_DPCNT'), ('bm_nobuf_drop', 'NOBUF_DPCNT')):
        table[key] = f'L2TM_L2TM_BM_{suffix}'
    for key, suffix in (('te_pol_drop', 'POL_DROP_PCNT'), ('te_tail_drop', 'TAIL_DROP_PCNT'),
                        ('te_wred_y_drop', 'WRED_Y_DROP_PCNT'), ('te_wred_g_drop', 'WRED_G_DROP_PCNT')):
        table[key] = f'L2TM_L2TE_PM_{suffix}'
    oracle = {}
    for key, name in table.items():
        match = re.search(r'^#define ' + name + r'\s+(0x[0-9a-f]+)\s*$', regs, re.M)
        assert match, name
        oracle[key] = int(match[1], 16) - 0xf4300000
    # Generated instance stride; avoid mistaking physical15 for slot15.
    def sdk_value(name):
        match = re.search(r'^#define ' + name + r'\s+(0x[0-9a-f]+|[0-9]+)\s*$', regs, re.M)
        assert match, name
        return int(match[1], 0)

    for i in (0, 1, 2, 3, 4, 10, 12, 13):
        key = f'es_lan{i}' if i < 5 else {10: 'es_l3wan10', 12: 'es_oam12', 13: 'es_l3lan13'}[i]
        oracle[key] = sdk_value('L2TM_L2TM_ES_SCH_CFG0') - 0xf4300000 + sdk_value('L2TM_L2TM_ES_SCH_CFG0_STRIDE') * i
    for i in range(4):
        oracle[f'es_pending{i}'] = sdk_value(f'L2TM_L2TM_ES_VOQ_STS{i}') - 0xf4300000
        oracle[f'es_ok{i}'] = sdk_value(f'L2TM_L2TM_ES_VOQ_OK_STS{i}') - 0xf4300000
    assert sdk_value('L2TM_L2TM_QM_EQ_COS0_BUFCNT_COUNT') == 8
    for i in range(8):
        oracle[f'cos{i}_bufcnt'] = (sdk_value('L2TM_L2TM_QM_EQ_COS0_BUFCNT') - 0xf4300000 +
                                   sdk_value('L2TM_L2TM_QM_EQ_COS0_BUFCNT_STRIDE') * i)
    source += 'static void check_sdk(void) {\n'
    for table_name in ('config', 'status', 'counter'):
        for index, (name, _) in enumerate(re.findall(r'\{"([^\"]+)", (0x[0-9a-f]+)\}',
                (DRIVER / 'rtl9617c-tm-evidence.h').read_text().split(f'rtl_tm_{table_name}_registers[] = {{')[1].split('};', 1)[0])):
            source += f'assert(rtl_tm_{table_name}_registers[{index}].offset=={oracle[name]}U);\n'
    source += r'''
 L2TM_L2TM_GLB_CTRL_t tm={.wrd=0};tm.bf.cntrcfg_clear_on_read=1;assert(tm.wrd==BIT(31));
 L2TM_L2TE_PM_CTRL_t te={.wrd=0};te.bf.mem_auto_clr_on_read=1;assert(te.wrd==BIT(5));
 L2TM_L2TE_FC_GLB_CTRL_t fc={.wrd=0};fc.bf.l3felan_rxpfc_en=255;assert(fc.wrd==0xff000000U);
 HEADER_A_T header={.bits64=0};header.bits.bits_32_63.pkt_info.no_drop=1;
 assert(header.bits32.bits32_h==BIT(13));
 struct rtl_fe_ipv4_action action={0};unsigned words[RTL_FE_ACTION_WORDS];
 rtl_fe_ipv4_action(words,&action);assert(!(words[0]&(BIT(2)|BIT(3))));
 /* Execute the unmodified SDK getters, not a second hand-written decoder.
  * Each getter makes exactly one allowed direct read. The resource gauges
  * are not subjected to TM counter clear mode. */
 struct model m={0};ca_uint32_t value;unsigned reads;sdk_model=&m;
 m.reg[0x2010/4]=BIT(31);
 m.reg[0x2260/4]=0xabcd9876U;
 for(unsigned eq=0;eq<2;eq++) {
  reads=m.reads;assert(aal_l2_qm_eq_free_cnt_get(0,eq,&value)==CA_E_OK);
  assert(value==((0xabcd9876U>>(eq*16))&0x7fffU) && m.reads==reads+1);
 }
 m.reg[0x2234/4]=0xffff1234U;reads=m.reads;
 assert(aal_l2_qm_eq_glb_free_cnt_get(0,&value)==CA_E_OK);
 assert(value==0x1234U && m.reads==reads+1);
 for(unsigned cos=0;cos<8;cos++) {
  m.reg[(0x2238+cos*4)/4]=0xffff8040U+cos;reads=m.reads;
  assert(aal_l2_qm_eq_cos_buf_cnt_get(0,cos,&value)==CA_E_OK);
  assert(value==0x40U+cos && m.reads==reads+1);
 }
 m.reg[0x2230/4]=0x80704021U;reads=m.reads;
 assert(aal_l2_qm_port_prvt_buff_status_get(0,&value)==CA_E_OK);
 assert(value==0x80704021U && m.reads==reads+1);
 for(unsigned i=0;i<RTL_TM_COUNTERS;i++)assert(!m.counter_reads[i]);
}
'''
    xram = (DRIVER / 'rtl9617c-xram.c').read_text()
    # Actual CPU LAN construction and fallback DMA use the externally checked
    # bit13; keep this explicit legacy behaviour from silently changing.
    assert '.header_high = BIT(13)' in function(xram, 'rtl_xmit')
    assert 'frame ? frame->header_high : BIT(13)' in (DRIVER / 'rtl9617c-dma.c').read_text()
    source += ''.join(function(xram, name) for name in
                      ('rtl_tm_clock', 'fabric_sample_show', 'fabric_evidence_show'))
    source += TEST
    with tempfile.TemporaryDirectory(prefix='tm-evidence-') as temporary:
        path = Path(temporary)
        (path / 'test.c').write_text(source)
        compile_command = [os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                           '-Wno-unused-parameter', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                           '-I', str(DRIVER), str(path / 'test.c'), '-o', str(path / 'test')]
        subprocess.run(compile_command, check=True)
        environment = dict(os.environ)
        environment.setdefault('ASAN_OPTIONS', 'detect_leaks=0')
        environment.setdefault('UBSAN_OPTIONS', 'halt_on_error=1')
        subprocess.run([str(path / 'test')], check=True, env=environment)
        # Deliberately lose one added configuration's epoch protection while
        # retaining its raw export: reproduces the old continuity blind spot,
        # not just a missing-name/offset failure in the SDK address oracle.
        header = (DRIVER / 'rtl9617c-tm-evidence.h').read_text()
        controls = ('RTL_TM_EQ_WEIGHT', 'RTL_TM_FE_BACKPRESSURE', 'RTL_TM_PRIVATE_PROFILE1',
                    'RTL_TM_PRIVATE_PROFILE2', 'RTL_TM_PRIVATE_PROFILE3',
                    'RTL_TM_PRIVATE_SELECT0', 'RTL_TM_PRIVATE_SELECT1')
        for config in controls:
            mutant = header.replace('if (state->config[i] != next.config[i])',
                                    f'if (i != {config} && state->config[i] != next.config[i])')
            assert mutant != header
            (path / 'rtl9617c-tm-evidence.h').write_text(mutant)
            subprocess.run(compile_command, check=True)
            result = subprocess.run([str(path / 'test')], env=environment, capture_output=True, text=True)
            assert result.returncode != 0 and 's.epoch==2 && !s.delta_valid' in result.stderr, (
                f'negative control did not reproduce lost epoch protection: {config}', result.stderr)
        print(f'TM evidence: {len(controls)} lost-configuration-epoch negative controls rejected')


if __name__ == '__main__':
    main()
