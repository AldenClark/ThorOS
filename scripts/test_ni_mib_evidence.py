#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute the production NI raw-counter sampler, cache getter and busy guard.

Optional --registers compiles pinned generated MMIO unions as an independent
field oracle. With --sdk-ni as well, execute the actual pinned vendor RX/TX
getters and their access macro, comparing all raw slots and the ordered
48 ACCESS writes plus 50 DATA reads, including DATA1-before-DATA0 for octets.
No hardware is accessed; this does not establish reset continuity or L2 hits.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"
REGISTER_SHA = "ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0"
SDK_NI_SHA = "b9a44c40b07e484ef017653afdb60e19d20163a3c12e64d435c0880319cf14e7"


def function(source, name):
    match = re.search(r"^(?:static )?(?:unsigned int|int|void|ssize_t|ca_status_t) " + name + r"\(", source, re.M)
    if not match:
        raise ValueError(f"missing production function {name}")
    start = match.start()
    end = source.index("{", start) + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end] + "\n"


SHIM = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include "rtl9617c-mib.h"
typedef unsigned long long u64;
typedef uint32_t u32;
typedef uint32_t ca_uint32_t;
#define BIT(n) (1U<<(n))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define READ_ONCE(v) (v)
#define GLB_STATIC 0xa01c
#define PAGE_SIZE 4096
EVIDENCE_STRUCT
struct mutex { bool held, deny; };
struct net_device {int ifindex;};
struct device {void *data;};
struct device_attribute {};
struct rtl_xram {
 void *ni, *fe;
 struct mutex mib_lock;
 struct net_device *ports[5];
 unsigned int registered_ports;
 unsigned long long mib_total[5][RTL_NI_MIB_COUNTERS];
 struct rtl_lan_mib_evidence mib_evidence[5];
 bool removing;
};
struct transaction {int polls;bool active;unsigned int port,index,opcode;};
struct command {unsigned int reg,value;};
struct mib_event {unsigned int kind,reg,value;};
static u32 regs[0x10000/4];
static unsigned long long hardware[5][52];
static struct transaction transactions[2];
static struct command commands[512];
static struct mib_event events[128];
static struct rtl_xram *owner;
static unsigned int reads,writes,stall_at,expected_opcode,config_reads,event_count;
static bool no_mmio,deny_rtnl,rtnl_held,change_config;
static u64 now;
static void *dev_get_drvdata(struct device *dev){return dev->data;}
static void *netdev_priv(void *dev){return dev;}
static void mutex_lock(struct mutex *m){assert(!m->held && !m->deny);m->held=true;}
static int mutex_trylock(struct mutex *m){if(m->held || m->deny)return 0;m->held=true;return 1;}
static void mutex_unlock(struct mutex *m){assert(m->held);m->held=false;}
static int rtnl_trylock(void){assert(!rtnl_held);if(deny_rtnl)return 0;rtnl_held=true;return 1;}
static void rtnl_unlock(void){assert(rtnl_held);rtnl_held=false;}
static u64 ktime_get_boottime_ns(void){return now+=1000000ULL;}
static void register_oracle(unsigned int reg,unsigned int command);
static void complete(unsigned int direction){
 struct transaction *t=&transactions[direction];
 unsigned int access=direction?0xa1b0:0xa1a4;
 u64 value=hardware[t->port][direction*26+t->index];
 regs[(access+8)/4]=(u32)value;regs[(access+4)/4]=(u32)(value>>32);
 regs[access/4]&=~BIT(31);t->active=false;
}
static u32 readl(void *address){
 assert(!no_mmio && owner->mib_lock.held);
 unsigned int offset=(unsigned int)((char *)address-(char *)regs);
 assert(!(offset&3) && offset<sizeof(regs));reads++;
 if(offset==GLB_STATIC){
  config_reads++;
  if(change_config && config_reads==2)regs[offset/4]^=BIT(24);
 }else if(offset==0xa1a4 || offset==0xa1b0){
  struct transaction *t=&transactions[offset==0xa1b0];
  if(t->active && t->polls>=0 && !t->polls--)complete(offset==0xa1b0);
 }else{
  assert(offset==0xa1a8 || offset==0xa1ac || offset==0xa1b4 || offset==0xa1b8);
  assert(event_count<ARRAY_SIZE(events));
  events[event_count++]=(struct mib_event){1,offset,regs[offset/4]};
 }
 return regs[offset/4];
}
static void writel(u32 value,void *address){
 assert(!no_mmio && owner->mib_lock.held);
 unsigned int offset=(unsigned int)((char *)address-(char *)regs);
 assert(offset==0xa1a4 || offset==0xa1b0);
 assert(!(regs[offset/4]&BIT(31))); /* A timeout cannot cancel the preceding command. */
 assert((value>>28)==(8U|expected_opcode)); /* ACCESS + explicit read opcode; never RBW. */
 assert(((value>>5)&7)<5 && (value&31)<26);
 assert(writes<ARRAY_SIZE(commands));commands[writes++]=(struct command){offset,value};
 assert(event_count<ARRAY_SIZE(events));
 events[event_count++]=(struct mib_event){0,offset,value};
 register_oracle(offset,value);
 transactions[offset==0xa1b0]=(struct transaction){
  .active=true,.polls=writes==stall_at?-1:2,.port=(value>>5)&7,.index=value&31,
  .opcode=(value>>28)&3,
 };
 regs[offset/4]=value;
}
/* Model only the bounded poll boundary; production read-before-write logic is
 * extracted unchanged. No wall-clock sleep is required for a transaction test. */
#define readl_poll_timeout(address,value,condition,delay,timeout) ({ \
 int poll_ret=-ETIMEDOUT; \
 for(unsigned int poll=0;poll<8;poll++){(value)=readl(address); \
  if(condition){poll_ret=0;break;}}poll_ret;})
static int sysfs_emit(char *buf,const char *format,...){
 assert(!owner->mib_lock.held && !rtnl_held);
 va_list ap;va_start(ap,format);int n=vsnprintf(buf,PAGE_SIZE,format,ap);va_end(ap);
 assert(n>=0 && n<PAGE_SIZE);return n;
}
static int sysfs_emit_at(char *buf,int at,const char *format,...){
 assert(!owner->mib_lock.held && !rtnl_held && at>=0 && at<PAGE_SIZE);
 va_list ap;va_start(ap,format);int n=vsnprintf(buf+at,PAGE_SIZE-at,format,ap);va_end(ap);
 assert(n>=0 && n<PAGE_SIZE-at);return n;
}
static void reset_bus(void){
 assert(!owner->mib_lock.held && !rtnl_held);
 reads=writes=stall_at=config_reads=expected_opcode=event_count=0;
 no_mmio=deny_rtnl=change_config=false;
 memset(regs,0,sizeof(regs));memset(transactions,0,sizeof(transactions));
 regs[GLB_STATIC/4]=0x0204000fU;
}
static void seed_hardware(unsigned int seed){
 for(unsigned int port=0;port<5;port++)for(unsigned int i=0;i<52;i++){
  hardware[port][i]=seed*101U+port*1000U+i*7U;
  if(i%26==25)hardware[port][i]|=0xdeadbeef00000000ULL;
 }
}
static ssize_t rtl_fe_state(void *fe,char *buf){assert(fe==(void *)123);return sysfs_emit(buf,"fixture_state=1\n");}
'''

CASES = r'''
static struct rtl_xram priv;
static struct device device={.data=&priv};
static struct net_device ports[5];
static char output[PAGE_SIZE];
static unsigned long long counters[37];
static unsigned int cases;
static void setup(void){
 memset(&priv,0,sizeof(priv));owner=&priv;priv.ni=regs;priv.fe=(void *)123;
 priv.registered_ports=31;
 for(unsigned int p=0;p<5;p++){ports[p].ifindex=17+p;priv.ports[p]=&ports[p];}
 reset_bus();seed_hardware(3);cases++;
}
static const char *line(unsigned int port){
 char key[32];snprintf(key,sizeof(key),"\nport=%u ",port);
 const char *found=strstr(output,key);assert(found);return found+1;
}
static void show(void){
 unsigned int old_reads=reads,old_writes=writes;
 no_mmio=true;
 ssize_t n=lan_mib_evidence_show(&device,NULL,output);
 no_mmio=false;
 assert(n>0 && n<PAGE_SIZE && n==(ssize_t)strlen(output));
 assert(reads==old_reads && writes==old_writes);
 assert(strstr(output,"cached=1 clock=boottime raw=1 reset_tracking=0"));
 assert(strstr(output,"counter_mode_verified=0"));
 assert(strstr(output,"l2_attribution=0 atomic_hardware_snapshot=0 read_opcode=0"));
 assert(!priv.mib_lock.held && !rtnl_held);
 for(unsigned int p=0;p<5;p++)assert(line(p));
}
static void assert_cached(unsigned int port){
 const struct rtl_lan_mib_evidence *s=&priv.mib_evidence[port];
 const unsigned long long *raw=hardware[port];
 assert(s->valid && !s->error && s->begin_ns<s->end_ns);
 assert(s->rx_bytes==raw[25] && s->tx_bytes==raw[51]);
 assert(s->rx_uc==(u32)raw[0] && s->rx_mc==(u32)raw[1] && s->rx_bc==(u32)raw[2]);
 assert(s->tx_uc==(u32)raw[26] && s->tx_mc==(u32)raw[27] && s->tx_bc==(u32)raw[28]);
 assert(s->config_begin==0x0204000fU);
}
static void getter_cases(void){
 setup();show();assert(!reads && !writes);
 for(unsigned int p=0;p<5;p++){
  char expected[160];snprintf(expected,sizeof(expected),
   "port=%u ifindex=%d registered=1 valid=0 error=%d seq=0 attempts=0",p,ports[p].ifindex,-ENODATA);
  assert(strstr(line(p),expected)==line(p));
 }
 for(unsigned int lock=0;lock<2;lock++){
  deny_rtnl=!lock;priv.mib_lock.deny=lock;no_mmio=true;
  assert(lan_mib_evidence_show(&device,NULL,output)==-EAGAIN);
  assert(!priv.mib_lock.held && !rtnl_held);no_mmio=false;
 }
 deny_rtnl=priv.mib_lock.deny=false;
 priv.registered_ports&=~BIT(2);
 /* A not-yet-registered probe pointer must never be dereferenced. */
 priv.ports[2]=(void *)1;priv.ports[3]=NULL;
 show();assert(strstr(line(2),"ifindex=0 registered=0")==line(2)+7);
 assert(strstr(line(3),"ifindex=0 registered=1")==line(3)+7);
 assert(!reads && !writes);
 assert(l2_state_show(&device,NULL,output)>0 && strstr(output,"fixture_state=1"));
 setup();
 assert(rtl9617c_ni_pm_read(&device,5,counters)==-EINVAL);
 assert(rtl9617c_ni_pm_read(&device,0,NULL)==-EINVAL);
 assert(!reads && !writes && !priv.mib_evidence[0].attempts);
 priv.removing=true;
 assert(rtl9617c_ni_pm_read(&device,0,counters)==-ENODEV && !reads && !writes);
 show();assert(!priv.mib_evidence[0].valid && priv.mib_evidence[0].error==-ENODEV);
}
static void sampler_cases(void){
 setup();
 for(unsigned int p=0;p<5;p++){
  reset_bus();assert(!rtl9617c_ni_pm_read(&device,p,counters));assert_cached(p);
  assert(writes==48 && config_reads==2);
  assert(priv.mib_evidence[p].seq==1 && priv.mib_evidence[p].attempts==1);
  assert(counters[2]==hardware[p][51] && counters[3]==hardware[p][25]);
 }
 show();
 /* Reset/wrap must remain raw, never converted into OAM's synthetic total. */
 reset_bus();hardware[4][0]=UINT32_MAX-2U;
 assert(!rtl9617c_ni_pm_read(&device,4,counters));
 reset_bus();hardware[4][0]=3;hardware[4][25]=7;hardware[4][51]=9;
 assert(!rtl9617c_ni_pm_read(&device,4,counters));assert_cached(4);
 assert(priv.mib_total[4][0]>UINT32_MAX && priv.mib_evidence[4].rx_uc==3);
 assert(priv.mib_evidence[4].seq==3 && priv.mib_evidence[3].seq==1);
 show();assert(strstr(line(4),"rx_bytes=7 tx_bytes=9 rx_uc=3 "));
 reset_bus();change_config=true;
 assert(!rtl9617c_ni_pm_read(&device,0,counters));
 assert(priv.mib_evidence[0].config_begin!=priv.mib_evidence[0].config_end);
 show(); /* Valid is a completed sample, never a proof of continuous mode. */
 for(unsigned int p=0;p<5;p++){
  struct rtl_lan_mib_evidence *s=&priv.mib_evidence[p];
  s->seq=s->attempts=s->begin_ns=s->end_ns=s->attempt_begin_ns=s->attempt_end_ns=~0ULL;
  s->rx_bytes=s->tx_bytes=~0ULL;
  s->rx_uc=s->rx_mc=s->rx_bc=s->tx_uc=s->tx_mc=s->tx_bc=~0U;
  s->config_begin=s->config_end=~0U;
 }
 show(); /* Every maximum-width field still fits one sysfs PAGE_SIZE. */
}
static void raw_reader_cases(void){
 for(unsigned int port=0;port<5;port++)for(unsigned int seed=0;seed<8;seed++){
  setup();seed_hardware(seed);
  const struct rtl_dq_io io={&priv,rtl_mib_read,rtl_mib_write,rtl_mib_indirect};
  unsigned long long actual[52];unsigned int count=0,event=0;
  mutex_lock(&priv.mib_lock);assert(!rtl_ni_mib_read(&io,port,actual));
  mutex_unlock(&priv.mib_lock);
  for(unsigned int direction=0;direction<2;direction++)for(unsigned int index=0;index<26;index++){
   unsigned int slot=direction*26+index,access=direction?0xa1b0U:0xa1a4U;
   bool skipped=index==24 || (direction && (index==12 || index==23));
   assert(actual[slot]==(skipped?0:hardware[port][slot]));
   if(skipped)continue;
   assert(commands[count].reg==access);
   assert(commands[count++].value==(BIT(31)|(port<<5)|index));
   assert(events[event].kind==0 && events[event].reg==access);
   assert(events[event++].value==(BIT(31)|(port<<5)|index));
   if(index==25){
    assert(events[event].kind==1 && events[event].reg==access+4);
    assert(events[event++].value==(u32)(hardware[port][slot]>>32));
   }
   assert(events[event].kind==1 && events[event].reg==access+8);
   assert(events[event++].value==(u32)hardware[port][slot]);
  }
  assert(count==48 && writes==count && !config_reads && event==98 && event_count==event);
 }
}
static void failures(void){
 for(unsigned int port=0;port<5;port++)for(unsigned int fail=1;fail<=48;fail++){
  setup();assert(!rtl9617c_ni_pm_read(&device,port,counters));
  struct rtl_lan_mib_evidence last=priv.mib_evidence[port];
  unsigned long long totals[52];memcpy(totals,priv.mib_total[port],sizeof(totals));
  reset_bus();seed_hardware(9);stall_at=fail;
  for(unsigned int i=0;i<37;i++)counters[i]=0xaabbccddULL;
  assert(rtl9617c_ni_pm_read(&device,port,counters)==-ETIMEDOUT);
  struct rtl_lan_mib_evidence *s=&priv.mib_evidence[port];
  assert(s->valid && s->error==-ETIMEDOUT && s->seq==last.seq && s->attempts==last.attempts+1);
  assert(s->begin_ns==last.begin_ns && s->end_ns==last.end_ns);
  assert(s->attempt_begin_ns>last.attempt_end_ns && s->attempt_end_ns>s->attempt_begin_ns);
  assert(s->rx_bytes==last.rx_bytes && s->tx_bytes==last.tx_bytes);
  assert(s->rx_uc==last.rx_uc && s->rx_mc==last.rx_mc && s->rx_bc==last.rx_bc);
  assert(s->tx_uc==last.tx_uc && s->tx_mc==last.tx_mc && s->tx_bc==last.tx_bc);
  assert(s->config_begin==last.config_begin && s->config_end==last.config_end);
  assert(!memcmp(totals,priv.mib_total[port],sizeof(totals)) && writes==fail);
  for(unsigned int i=0;i<37;i++)assert(counters[i]==0xaabbccddULL);
  show();assert(strstr(line(port),"valid=1 error=-110 seq=1 attempts=2"));
 }
 setup();stall_at=1;
 assert(rtl9617c_ni_pm_read(&device,1,counters)==-ETIMEDOUT);
 show();assert(!priv.mib_evidence[1].valid && priv.mib_evidence[1].seq==0);
}
static void busy_cases(void){
 setup();mutex_lock(&priv.mib_lock);
 regs[0xa1a4/4]=BIT(31)|7;transactions[0]=(struct transaction){.active=true,.polls=-1};
 assert(rtl_mib_indirect(&priv,0xa1a4,BIT(31)|8)==-ETIMEDOUT);
 assert(!writes && regs[0xa1a4/4]==(BIT(31)|7));
 transactions[0].polls=2;
 assert(!rtl_mib_indirect(&priv,0xa1a4,BIT(31)|8));assert(writes==1);
 mutex_unlock(&priv.mib_lock);
 reset_bus();stall_at=1;mutex_lock(&priv.mib_lock);
 assert(rtl_mib_indirect(&priv,0xa1b0,BIT(31)|9)==-ETIMEDOUT);
 assert(writes==1 && regs[0xa1b0/4]==(BIT(31)|9));
 assert(rtl_mib_indirect(&priv,0xa1b0,BIT(31)|10)==-ETIMEDOUT);
 assert(writes==1 && regs[0xa1b0/4]==(BIT(31)|9));
 transactions[1].polls=1;stall_at=0;
 assert(!rtl_mib_indirect(&priv,0xa1b0,BIT(31)|10));assert(writes==2);
 mutex_unlock(&priv.mib_lock);
}
int main(void){
 sdk_compare();getter_cases();sampler_cases();raw_reader_cases();failures();busy_cases();
 printf("PASS: NI MIB production cache/reads: %u setups incl. 240 partial-transaction failures; 48 ACCESS/50 DATA ordered events, raw 32/64-bit, reset, stale, trylocks, ifindex, all five ports, prior-busy/late completion, no-MMIO getter\n",cases);
}
'''


def register_oracle(path):
    if path is None:
        return "static void register_oracle(unsigned int reg,unsigned int command){(void)reg;(void)command;}\n"
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != REGISTER_SHA:
        raise SystemExit("RTL8277C register header SHA256 pin mismatch")
    source = data.decode()
    blocks = []
    for name in ["NI_HV_GLB_STATIC_CFG", *(
        f"NI_HV_GLB_{direction}MIB_{field}" for direction in ("RX", "TX")
        for field in ("ACCESS", "DATA1", "DATA0"))]:
        start = re.search(r"^#define " + name + r"\s+0x", source, re.M).start()
        end = source.index("#endif /* !__ASSEMBLER__ */", start)
        blocks.append(source[start:end] + "#endif\n")
    blocks.append(r'''
static void register_oracle(unsigned int reg,unsigned int command){
 NI_HV_GLB_RXMIB_ACCESS_t rx={.wrd=command};
 NI_HV_GLB_TXMIB_ACCESS_t tx={.wrd=command};
 assert(GLB_STATIC==NI_HV_GLB_STATIC_CFG-0xf4300000U);
 assert(reg==(reg==0xa1a4?NI_HV_GLB_RXMIB_ACCESS:NI_HV_GLB_TXMIB_ACCESS)-0xf4300000U);
 assert(NI_HV_GLB_RXMIB_DATA0-NI_HV_GLB_RXMIB_ACCESS==8);
 assert(NI_HV_GLB_RXMIB_DATA1-NI_HV_GLB_RXMIB_ACCESS==4);
 assert(NI_HV_GLB_TXMIB_DATA0-NI_HV_GLB_TXMIB_ACCESS==8);
 assert(NI_HV_GLB_TXMIB_DATA1-NI_HV_GLB_TXMIB_ACCESS==4);
 assert(rx.bf.access && !rx.bf.rbw && rx.bf.op_code==expected_opcode);
 assert(tx.bf.access && !tx.bf.rbw && tx.bf.op_code==expected_opcode);
 assert(rx.bf.counter_id==(command&31) && rx.bf.port_id==((command>>5)&7));
 assert(tx.bf.counter_id==(command&31) && tx.bf.port_id==((command>>5)&7));
}
''')
    return "\n".join(blocks)


def sdk_oracle(path):
    if path is None:
        return "static void sdk_compare(void){}\n"
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != SDK_NI_SHA:
        raise SystemExit("aal_ni_l2.c SHA256 pin mismatch")
    source = data.decode()
    enums = source[source.index("/* Ethernet MIB operation code enumeration */"):
                   source.index("} __ni_tx_mib_id_t;") + len("} __ni_tx_mib_id_t;")]
    macros = source[source.index("#define  __NI_TABLE_ACCESS_TIMEOUT"):
                    source.index("#define  __NI_MC_TABLE_ACCESS")]
    public = function(source, "aal_ni_eth_port_mib_get")
    # The independently executed SDK public getter supplies its own mapping;
    # boundary structure layout is irrelevant to the observed field values.
    members = sorted(set(re.findall(r"stats->(\w+)", public)))
    boundary = "typedef struct {" + "".join(f"ca_uint64_t {m};" for m in members) + "} aal_ni_mib_stats_t;\n"
    result = r'''
typedef unsigned long long ca_uint64_t;
typedef unsigned int ca_device_id_t;
typedef int ca_status_t;
typedef bool ca_boolean_t;
#define CA_IN
#define CA_OUT
#define CA_E_OK 0
#define CA_E_TIMEOUT (-ETIMEDOUT)
#define __NI_ASSERT(p) assert(p)
#define CA_DEV_NI_REG_READ(dev,reg) readl((char *)regs+(reg)-0xf4300000U)
#define CA_DEV_NI_REG_WRITE2(dev,reg,value) writel((value),(char *)regs+(reg)-0xf4300000U)
'''
    result += enums + "\n" + macros + "\n" + boundary
    result += function(source, "__ni_eth_port_rx_mib_get")
    result += function(source, "__ni_eth_port_tx_mib_get") + public
    result += r'''
static void sdk_compare(void){
 struct rtl_xram priv={.ni=regs};owner=&priv;
 const struct rtl_dq_io io={&priv,rtl_mib_read,rtl_mib_write,rtl_mib_indirect};
 for(unsigned int port=0;port<5;port++)for(unsigned int seed=0;seed<8;seed++){
  unsigned long long actual[52],vendor[52];struct command expected[48];
  struct mib_event expected_trace[98];
  reset_bus();seed_hardware(seed);mutex_lock(&priv.mib_lock);
  assert(!rtl_ni_mib_read(&io,port,actual));assert(writes==48);
  memcpy(expected,commands,sizeof(expected));assert(event_count==98);
  memcpy(expected_trace,events,sizeof(expected_trace));mutex_unlock(&priv.mib_lock);
  reset_bus();mutex_lock(&priv.mib_lock);
  assert(!__ni_eth_port_rx_mib_get(0,port,false,vendor));
  assert(!__ni_eth_port_tx_mib_get(0,port,false,vendor+26));
  assert(!memcmp(actual,vendor,sizeof(actual)) && writes==48);
  assert(!memcmp(expected,commands,sizeof(expected)));
  assert(event_count==98 && !memcmp(expected_trace,events,sizeof(expected_trace)));
  mutex_unlock(&priv.mib_lock);
  aal_ni_mib_stats_t stats;
  reset_bus();mutex_lock(&priv.mib_lock);
  assert(!aal_ni_eth_port_mib_get(0,port,false,&stats));
  assert(stats.rx_byte_cnt==actual[25] && stats.tx_byte_cnt==actual[51]);
  assert(stats.rx_uc_pkt_cnt==actual[0] && stats.rx_mc_frame_cnt==actual[1] && stats.rx_bc_frame_cnt==actual[2]);
  assert(stats.tx_uc_pkt_cnt==actual[26] && stats.tx_mc_frame_cnt==actual[27] && stats.tx_bc_frame_cnt==actual[28]);
  assert(!memcmp(expected,commands,sizeof(expected)));
  assert(event_count==98 && !memcmp(expected_trace,events,sizeof(expected_trace)));
  mutex_unlock(&priv.mib_lock);
 }
 reset_bus();expected_opcode=2;mutex_lock(&priv.mib_lock);
 aal_ni_mib_stats_t stats;assert(!aal_ni_eth_port_mib_get(0,4,true,&stats));
 assert(writes==48);mutex_unlock(&priv.mib_lock);
 puts("PASS: pinned SDK actual RX/TX/public MIB getters: 40 x 52 raw slots and ordered 48 ACCESS writes/50 DATA reads (DATA1 before DATA0), explicit READ_ONLY vs READ_CLEAR_ALL; generated register fields");
}
'''
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registers", type=Path)
    parser.add_argument("--sdk-ni", type=Path)
    args = parser.parse_args()
    if args.sdk_ni and not args.registers:
        parser.error("--sdk-ni needs --registers to compile the actual SDK MMIO bitfield types")
    source = (DRIVER / "rtl9617c-xram.c").read_text()
    record = re.search(r"struct rtl_lan_mib_evidence \{.*?^\};", source, re.S | re.M).group(0)
    production = "\n".join(function(source, n) for n in (
        "rtl_mib_read", "rtl_mib_write", "rtl_mib_indirect", "rtl9617c_ni_pm_read",
        "l2_state_show", "lan_mib_evidence_show"))
    variants = {
        "production": production,
        "overwrite_busy_command": production.replace("if (ret)\n\t\treturn ret;", "if (ret)\n\t\tret = 0;", 1),
        "getter_triggers_mmio": production.replace("struct rtl_lan_mib_evidence samples[5];",
            "struct rtl_lan_mib_evidence samples[5];\n(void)readl(priv->ni + GLB_STATIC);", 1),
        "failed_sample_erases_last_good": production.replace("sample->error = ret;",
            "sample->error = ret;\nif (ret) sample->valid = false;", 1),
        "cache_truncates_64bit_octets": production.replace("sample->rx_bytes = raw[25];",
            "sample->rx_bytes = (u32)raw[25];", 1),
    }
    for name, candidate in variants.items():
        if name != "production" and candidate == production:
            raise SystemExit(f"missing mutation anchor: {name}")
    mib_header = (DRIVER / "rtl9617c-mib.h").read_text()
    old_order = mib_header.replace(
        "\t\t\tif (index == 25)\n\t\t\t\tvalue = (unsigned long long)io->read(io->context, access + 4) << 32;\n"
        "\t\t\tvalue |= io->read(io->context, access + 8);",
        "\t\t\tvalue = io->read(io->context, access + 8);\n"
        "\t\t\tif (index == 25)\n\t\t\t\tvalue |= (unsigned long long)io->read(io->context, access + 4) << 32;", 1)
    if old_order == mib_header:
        raise SystemExit("missing mutation anchor: low_word_before_high_word")
    variants = {name: (candidate, mib_header) for name, candidate in variants.items()}
    variants["low_word_before_high_word"] = (production, old_order)
    shim = SHIM.replace("EVIDENCE_STRUCT", record) + register_oracle(args.registers)
    oracle = sdk_oracle(args.sdk_ni)
    env = dict(os.environ)
    env.setdefault("ASAN_OPTIONS", "detect_leaks=0")
    env.setdefault("UBSAN_OPTIONS", "halt_on_error=1")
    with tempfile.TemporaryDirectory(prefix="ni-mib-evidence-") as tmp:
        directory = Path(tmp)
        for name, (candidate, header) in variants.items():
            path, binary = directory / f"{name}.c", directory / name
            # Quote-include resolves the exact current production header here;
            # only the deliberate old-order negative control changes its body.
            (directory / "rtl9617c-mib.h").write_text(header)
            path.write_text(shim + candidate + oracle + CASES)
            subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                            "-Wno-unused-function", "-Wno-unused-parameter", "-fsanitize=address,undefined",
                            "-fno-sanitize-recover=all", "-I", str(DRIVER), str(path), "-o", str(binary)], check=True)
            result = subprocess.run([str(binary)], env=env, capture_output=True, text=True)
            if name == "production":
                if result.returncode:
                    raise SystemExit(result.stdout + result.stderr)
                print(result.stdout.strip())
            else:
                if result.returncode != -6 or "Assertion" not in result.stderr:
                    raise SystemExit(f"{name}: expected a contract assertion, got {result.returncode}: {result.stderr}")
                if name == "low_word_before_high_word":
                    expected_assertion = ("!memcmp(expected_trace,events,sizeof(expected_trace))"
                                          if args.sdk_ni else "events[event].reg==access+4")
                    if expected_assertion not in result.stderr:
                        raise SystemExit(f"{name}: did not fail the intended ordered trace assertion: {result.stderr}")
                print(f"PASS: runtime regression mutant rejected: {name}")
    (ROOT / "artifacts").mkdir(exist_ok=True)
    (ROOT / "artifacts/ni-mib-evidence.json").write_text(json.dumps({
        "production_functions_sha256": hashlib.sha256(production.encode()).hexdigest(),
        "mib_header_sha256": hashlib.sha256(mib_header.encode()).hexdigest(),
        "runtime_mutants_rejected": list(variants)[1:],
        "ordered_access_writes": 48, "ordered_data_reads": 50,
        "sdk_ni_sha256": SDK_NI_SHA if args.sdk_ni else None,
        "registers_sha256": REGISTER_SHA if args.registers else None,
        "hardware_verified": False, "reset_continuity_proven": False, "l2_attribution_proven": False,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
