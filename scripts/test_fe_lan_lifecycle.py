#!/usr/bin/env python3
"""Run production FE admission/restore with five different LAN register states."""
import hashlib
import json
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
drivers = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--revision', help='Run the same hardware contract against an older commit')
args = parser.parse_args()
relative = str((drivers / 'rtl9617c-fe.c').relative_to(root))
source = subprocess.check_output(['git', 'show', args.revision + ':' + relative], text=True) if args.revision else (drivers / 'rtl9617c-fe.c').read_text()

def function(name):
    start = re.search(r'^(?:static )?(?:int|void|bool|unsigned int) ' + name + r'\(', source, re.M).start()
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

registers = re.search(r'static const unsigned int fe_registers\[\] = \{.*?\};', source, re.S).group()
common = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <linux/ppp_defs.h>
#include <linux/if_ether.h>
#include "rtl9617c-fe-pipeline.h"
#define BIT(n) (1U<<(n))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define FE_LAN_PORTS 5
#define FE_LAN_RX_CTRL(p) (0xa5f8+0x90*(p))
#define lower_32_bits(v) ((unsigned int)(v))
#define upper_32_bits(v) ((unsigned int)((uint64_t)(v)>>32))
#define WRITE_ONCE(dst,value) ((dst)=(value))
struct spinlock {bool held;};
#define spin_lock_irqsave(lock,flags) do{(flags)=0;assert(!(lock)->held);(lock)->held=true;}while(0)
#define spin_unlock_irqrestore(lock,flags) do{(void)(flags);assert((lock)->held);(lock)->held=false;}while(0)
struct mutex {bool held;};
enum rtl_fe_mode {RTL_FE_MODE_OFF,RTL_FE_MODE_CPU,RTL_FE_MODE_HARDWARE};
struct rtl_fe_flow {struct rtl_fe_flow *next;};
struct list_head {struct rtl_fe_flow *first;};
#define list_for_each_entry_safe(p,n,h,m) for(p=(h)->first,n=p?p->next:NULL;p;p=n,n=p?p->next:NULL)
static void mutex_lock(struct mutex *m){assert(!m->held);m->held=true;}
static void mutex_unlock(struct mutex *m){assert(m->held);m->held=false;}
struct rtl_fe {
 struct mutex lock;struct list_head flows;
 uint64_t dma;bool prepared,enabled,cpu_path,lan_redirected;int error;
 bool engine_ready,shutting_down;enum rtl_fe_mode desired_mode;
 struct spinlock route_lock;bool route_gate_ready,route_admitted,dma_exposed;
 unsigned int saved[64],lan_saved[5],mask_saved[8],classifier_saved[2][4][2][7],map_saved[2][4];
 unsigned int bridge_mask_saved[3][8],bridge_mask[3][8];
 unsigned int reg[0x10000/4],mask[8],cls[1056][7],map[256],cls_keys[256];
 struct rtl_fe_cam_protocol protocol_cam[3];unsigned char ppp_protocol_ids[2];
 unsigned int cam[9][64][5];
 unsigned int admission_writes,cache_ready,fail_mask,fail_mask_writes,deletes,fail_delete;
 unsigned int switch_quiesces,switch_reconciles,register_writes;
 unsigned int key_reads,fail_key_read,fail_route_open,fail_cpu_selector;
 unsigned int pp_rejected_register,pp_rejected_value;
 int switch_error;
 unsigned int expected_lan[5];
};
static unsigned int fe_read(void *ctx,unsigned int reg){struct rtl_fe *f=ctx;assert(reg<0x10000);return f->reg[reg/4];}
static void fe_write(void *ctx,unsigned int reg,unsigned int value){
 struct rtl_fe *f=ctx;assert(reg<0x10000);
 f->register_writes++;
 if(reg==0x383c)assert(f->dma_exposed);
 if(reg==0x38c4)f->cache_ready=value==0xa0000000;
 if(reg==0x351c && (value&BIT(10)) && ((value>>4)&63)==32) {
  assert(f->cache_ready && f->reg[0x3860/4]==0x020d0000);
  assert(((f->reg[0x3418/4]>>10)&15)==1 && ((f->reg[0x3424/4]>>10)&15)==1);
  assert(((f->cls[1024][4]>>26)&7)==7 && ((f->cls[1028][4]>>26)&7)==7);
 }
 if((reg==0x3418 || reg==0x3424) && f->route_gate_ready && ((value>>10)&15)==0){
  assert(f->route_lock.held && f->prepared && f->enabled);
  if(f->fail_route_open){f->fail_route_open--;return;}
 }
 if(reg==f->fail_cpu_selector && ((value>>10)&15)==1)return;
 if(reg==0x38c4 && value==0)assert(!(f->reg[0x351c/4]&BIT(10)));
 if(reg>=0xa5f8 && reg<=0xa838 && !((reg-0xa5f8)%0x90) && ((value>>16)&63)==25){
  f->admission_writes++;
  assert(!"FE mode setup cannot reopen route25 outside the generation gate");
 }
 f->reg[reg/4]=value;
}
static int fe_access(void *ctx,unsigned int reg,unsigned int value){
 struct rtl_fe *f=ctx;unsigned int index=value&255,i;
 if(reg==0x3200){
  unsigned int bank=(value>>16)&15;index=value&63;assert(bank==2||bank==8);
  for(i=0;i<5;i++)if(value&BIT(30))f->cam[bank][index][i]=f->reg[(0x3214-i*4)/4];
  else f->reg[(0x3214-i*4)/4]=f->cam[bank][index][i];
 } else if(reg==0x3910){
  if(f->fail_mask){f->fail_mask=0;return -ETIMEDOUT;}
  if((value&BIT(30)) && f->fail_mask_writes){f->fail_mask_writes--;return -ETIMEDOUT;}
  unsigned int bank=(value>>6)&1;
  unsigned int slot=value&63;
  assert(slot==63 || slot==61 || slot==59 || slot==57);
  unsigned int *selected=slot==63?f->mask:f->bridge_mask[(61-slot)/2];
  for(i=0;i<4;i++)if(value&BIT(30))selected[bank*4+i]=f->reg[(0x3920-i*4)/4];
  else f->reg[(0x3920-i*4)/4]=selected[bank*4+i];
 } else if(reg==0x3380){
  assert(!(value&BIT(30)) && (value&~(BIT(31)|255U))==0);f->key_reads++;
  if(f->fail_key_read==index+1)return -ETIMEDOUT;
  f->reg[0x3384/4]=f->cls_keys[index];
 } else if(reg==0x33b0){
  unsigned int side=value&0x3fff;assert(side<1056);
  if(value&BIT(30))assert(!(f->reg[0x351c/4]&BIT(10)));
  for(i=0;i<7;i++)if(value&BIT(30))f->cls[side][i]=f->reg[(0x33cc-i*4)/4];
  else f->reg[(0x33cc-i*4)/4]=f->cls[side][i];
 } else if(reg==0x1654){
  if(value&BIT(30))f->map[index]=f->reg[0x1658/4];else f->reg[0x1658/4]=f->map[index];
 } else {
  assert(reg==0x393c && value==1);
  /* The independent NI owner supplies the current reset/native values. */
  for(i=0;i<5;i++)assert(fe_read(f,0xa5f8+i*0x90)==f->expected_lan[i]);
 }
 return 0;
}
static struct rtl_dq_io fe_io(struct rtl_fe *f){return (struct rtl_dq_io){f,fe_read,fe_write,fe_access};}
static __attribute__((unused)) int fe_switch_quiesce_locked(struct rtl_fe *f){
 assert(f->lock.held);f->switch_quiesces++;return f->switch_error;
}
static __attribute__((unused)) void fe_switch_reconcile_locked(struct rtl_fe *f){
 assert(f->lock.held);f->switch_reconciles++;
}
static void fe_collect_ports(struct rtl_fe *f){(void)f;}
static int fe_delete(struct rtl_fe *f,struct rtl_fe_flow *p){
 assert(!f->enabled && f->flows.first==p);
 if(f->fail_delete){f->fail_delete--;return -ETIMEDOUT;}
 f->flows.first=p->next;f->deletes++;return 0;
}
static void usleep_range(unsigned int a,unsigned int b){assert(a==1000 && b==2000);}
'''
lan_defines = re.search(r'^#define FE_LAN_PORTS[^\n]*\n#define FE_LAN_RX_CTRL[^\n]*', source, re.M)
if lan_defines:
    common = common.replace('#define FE_LAN_PORTS 5\n#define FE_LAN_RX_CTRL(p) (0xa5f8+0x90*(p))', lan_defines.group())
test = r'''
int main(void){
 struct rtl_fe f={.dma=0x03800000,.engine_ready=true};unsigned int lan[5],old_regs[64],old_mask[8],old_cls[1056][7],old_map[256],old_demux;
 unsigned int old_bridge_mask[3][8];
 for(unsigned int i=0;i<0x10000/4;i++)f.reg[i]=0x80000000U+i;
 /* Configuration snapshots may contain high bits; ACCESS registers must
  * start idle. Real stuck/busy commands have their own window fault test. */
 const unsigned int access[]={0x1654,0x1ca0,0x1cb4,0x3000,0x3200,0x3380,0x33b0,
  0x35c8,0x38b0,0x38e0,0x38e4,0x3910,0x3928,0x393c};
 for(unsigned int i=0;i<ARRAY_SIZE(access);i++)f.reg[access[i]/4]=0;
 const unsigned int pp_exception[]={0x3248,0x324c,0x3314,0x3318};
 for(unsigned int i=0;i<ARRAY_SIZE(pp_exception);i++)f.reg[pp_exception[i]/4]=0xfffffa10U;
 f.reg[0x30a4/4]=0x0001b000U;
 for(unsigned int i=0;i<5;i++)f.reg[(0xa5f8+i*0x90)/4]=f.expected_lan[i]=lan[i]=0x18100400U|(i<<24);
 for(unsigned int i=0;i<8;i++)f.mask[i]=old_mask[i]=0x55000000+i;
 for(unsigned int s=0;s<3;s++)for(unsigned int i=0;i<8;i++)
  f.bridge_mask[s][i]=old_bridge_mask[s][i]=0x5a000000+s*8+i;
 for(unsigned int s=0;s<1056;s++)for(unsigned int i=0;i<7;i++)f.cls[s][i]=old_cls[s][i]=0x11000000+s*7+i;
 /* Deliberately non-zero stale second-row format bits must be owned, cleared
  * for the installed standard FIB, and restored exactly on release. */
 const unsigned int base[2][4]={{1024,1026,1040,1042},{1028,1030,1044,1046}};
 for(unsigned int p=0;p<2;p++)for(unsigned int type=0;type<4;type++)
  f.cls[base[p][type]+1][6]=old_cls[base[p][type]+1][6]=0xffffffff;
 for(unsigned int i=0;i<256;i++)f.map[i]=old_map[i]=0x100+i;
 for(unsigned int i=0;i<ARRAY_SIZE(fe_registers);i++)old_regs[i]=fe_read(&f,fe_registers[i]);
 old_demux=fe_read(&f,0xa1e0);
 /* An uncertain L2 withdrawal must block ALL shared FE mode transitions,
  * before preparing tables, restoring snapshots or admitting LAN packets. */
 f.switch_error=-ETIMEDOUT;
 unsigned int before_switch_writes=f.register_writes;
 assert(rtl_fe_enable(&f)==-ETIMEDOUT && !f.enabled && !f.prepared);
 assert(rtl_fe_cpu_path(&f)==-ETIMEDOUT && !f.cpu_path && !f.prepared);
 assert(rtl_fe_disable(&f)==-ETIMEDOUT && f.desired_mode==RTL_FE_MODE_OFF);
 assert(f.register_writes==before_switch_writes && f.switch_quiesces==3);
 f.switch_error=0;
 /* A parser override must fail before even TCAM probes, table snapshots
  * or DMA publication. Exercise both CPU and drop allow-lists, all stage
  * selectors, packet preservation, and reserved destination values. */
 const unsigned int unsafe_pp[]={0,0xfffffa11U,0xfffff810U,0xfffffe10U,
  0xfffff210U,0xffffea10U,0xfffefa10U,0xffeffa10U,0xfefffa10U,0xeffffa10U};
 for(unsigned int side=0;side<ARRAY_SIZE(pp_exception);side++){
  for(unsigned int bad=0;bad<ARRAY_SIZE(unsafe_pp);bad++){
   unsigned int before_keys=f.key_reads;
   f.reg[pp_exception[side]/4]=unsafe_pp[bad];
   before_switch_writes=f.register_writes;
   assert(rtl_fe_enable(&f)==-EOPNOTSUPP && !f.enabled && !f.prepared && !f.dma_exposed);
   assert(f.register_writes==before_switch_writes && f.key_reads==before_keys);
   assert(f.pp_rejected_register==pp_exception[side] && f.pp_rejected_value==unsafe_pp[bad]);
  }
  f.reg[pp_exception[side]/4]=0xfffffa10U;
 }
 /* A foreign key of any of the four valid forms, at any TCAM index, makes
  * default-only classifier ownership unsafe. Real prepare must not write. */
 for(unsigned int index=0;index<256;index++)for(unsigned int bit=27;bit<=30;bit++){
  f.cls_keys[index]=BIT(bit);before_switch_writes=f.register_writes;
  assert(rtl_fe_enable(&f)==-EBUSY && !f.enabled && !f.prepared && !f.route_gate_ready);
  assert(f.register_writes==before_switch_writes);f.cls_keys[index]=0;
 }
 for(unsigned int index=0;index<256;index++){
  f.fail_key_read=index+1;before_switch_writes=f.register_writes;
  assert(rtl_fe_enable(&f)==-ETIMEDOUT && !f.prepared && !f.enabled);
  assert(f.register_writes==before_switch_writes);
 }
 f.fail_key_read=0;f.reg[0x3380/4]=BIT(31);before_switch_writes=f.register_writes;
 unsigned int key_reads=f.key_reads;
 assert(rtl_fe_enable(&f)==-EBUSY && f.key_reads==key_reads && f.register_writes==before_switch_writes);
 f.reg[0x3380/4]=0;
 /* Either connector failing its CPU profile readback must prevent prepare
  * from publishing GEM admission or claiming successful enable. */
 for(unsigned int side=0;side<2;side++){
  f.fail_cpu_selector=0x3418+side*12;
  assert(rtl_fe_enable(&f)==-EIO && !f.enabled && !f.prepared && !f.route_gate_ready);
  assert(!f.route_admitted && !f.admission_writes);
  for(unsigned int i=0;i<ARRAY_SIZE(fe_registers);i++)assert(fe_read(&f,fe_registers[i])==old_regs[i]);
 }
 f.fail_cpu_selector=0;
 for(unsigned int cycle=0;cycle<3;cycle++){
  assert(!rtl_fe_enable(&f) && f.enabled && f.prepared);
  assert(!f.pp_rejected_register && !f.pp_rejected_value);
  /* Table/errata preparation remains checked even though admission itself
   * now belongs to a different, generation-gated hardware owner. */
  assert(f.cache_ready && f.reg[0x383c/4]==0x03800000);
  assert((f.reg[0x3944/4]&0x80000001U)==0x80000001U);
  assert(f.reg[0x3948/4]&1U);
  assert((f.reg[0x3c80/4]&255)==255);
  assert((f.reg[0x3940/4]&0xffff)==0xd0d0);
  assert(!(f.mask[6]&BIT(25)));
  for(unsigned int i=0;i<3;i++)assert(!(f.bridge_mask[i][6]&BIT(25)));
  assert(f.reg[0x351c/4]&BIT(12));
  assert((f.reg[0x3508/4]&0x1f00)==0x1f00);
  assert((f.reg[0x30cc/4]&0xfff)==0xf21);
  assert(f.reg[0x30a4/4]==0x8001b000U);
  assert((f.reg[0xa1e0/4]&1023)==1023 && (f.reg[0x3400/4]&BIT(19)));
  for(unsigned int profile=0;profile<2;profile++)for(unsigned int type=0;type<4;type++){
   unsigned int row=base[profile][type];
   assert(fe_classifier_default_index(profile,type,0)==row);
   assert(fe_classifier_default_index(profile,type,1)==row+1);
   assert(((f.cls[row][4]>>26)&7)==7);
   assert(((f.cls[row][4]>>30)|(f.cls[row][5]<<2))%1024==16);
   assert(!(f.cls[row][6]&BIT(16))); /* Every profile preserves physical LSPID. */
   assert(((f.cls[row][6]>>11)&31)==(profile?31:1)); /* valid + T2 selector */
   assert(((f.cls[row][5]>>22)&3)==(profile?3:0)); /* keep original frame */
   for(unsigned int word=0;word<7;word++)assert(!f.cls[row+1][word]);
  }
  assert(fe_read(&f,0x3700)==4 && fe_read(&f,0x3704)==63 && fe_read(&f,0x3708)==(61|1U<<8));
  assert(fe_read(&f,0x370c)==(59|2U<<8) && fe_read(&f,0x3710)==(57|3U<<8));
  assert(f.ppp_protocol_ids[0]==1 && f.ppp_protocol_ids[1]==2);
  assert(f.cam[2][0][0]==0x18864 && f.cam[8][0][0]==0x10021 && f.cam[8][1][0]==0x10057);
  for(unsigned int i=0;i<5;i++)assert(fe_read(&f,0xa5f8+i*0x90)==lan[i]);
  assert(f.switch_reconciles && !f.admission_writes); /* Worker admission is deferred. */
  assert(f.route_gate_ready && !f.route_admitted);
  assert(((fe_read(&f,0x3418)>>10)&15)==1 && ((fe_read(&f,0x3424)>>10)&15)==1);
  assert((fe_read(&f,0x351c)&BIT(10)) && ((fe_read(&f,0x351c)>>4)&63)==32);
  /* The SDK owns two rows per result group, not one consecutive block. */
  for(unsigned int row=0;row<1056;row++){
   bool owned=false;
   for(unsigned int profile=0;profile<2;profile++)for(unsigned int type=0;type<4;type++)
    owned|=row==base[profile][type] || row==base[profile][type]+1;
   if(!owned)assert(!memcmp(f.cls[row],old_cls[row],sizeof(old_cls[row])));
  }
  /* Only explicit fabric arm opens BOTH LAN and PON hash profiles; an
   * unsuccessful readback must reclose both without indirect operations. */
  unsigned int before_keys=f.key_reads;
  assert(fe_route_arm(&f) && f.route_admitted);
  assert(!((fe_read(&f,0x3418)>>10)&15) && !((fe_read(&f,0x3424)>>10)&15));
  fe_route_gate(&f);assert(!f.route_admitted);
  f.fail_route_open=1;assert(!fe_route_arm(&f) && !f.route_admitted);
  assert(((fe_read(&f,0x3418)>>10)&15)==1 && ((fe_read(&f,0x3424)>>10)&15)==1);
  assert(f.key_reads==before_keys);
  assert(fe_read(&f,0xa1e0)==(old_demux|0x3ff));
  unsigned int writes=f.admission_writes;assert(!rtl_fe_enable(&f) && f.admission_writes==writes);
  assert(!rtl_fe_disable(&f) && !f.enabled && !f.prepared && !f.route_gate_ready && !f.route_admitted);
  assert(fe_read(&f,0x30a4)==0x0001b000U);
  for(unsigned int i=0;i<5;i++)assert(fe_read(&f,0xa5f8+i*0x90)==lan[i]);
  for(unsigned int i=0;i<ARRAY_SIZE(fe_registers);i++)assert(fe_read(&f,fe_registers[i])==old_regs[i]);
  assert(!memcmp(f.mask,old_mask,sizeof(old_mask)) && !memcmp(f.cls,old_cls,sizeof(old_cls)));
  assert(!memcmp(f.bridge_mask,old_bridge_mask,sizeof(old_bridge_mask)));
  assert(!memcmp(f.map,old_map,sizeof(old_map)));
  assert(!rtl_fe_disable(&f));
  assert(!f.cam[2][0][0] && !f.cam[8][0][0] && !f.cam[8][1][0]);
 }
 assert(f.admission_writes==0);
 f.fail_mask=1;assert(rtl_fe_enable(&f)==-ETIMEDOUT && !f.enabled && !f.prepared);
 for(unsigned int i=0;i<5;i++)assert(fe_read(&f,0xa5f8+i*0x90)==lan[i]);
 /* Warm parser state can place the PPP protocols at arbitrary CAM rows. */
 f.cam[2][11][0]=0x18864;f.cam[8][5][0]=0x10021;f.cam[8][9][0]=0x10057;
 assert(!rtl_fe_enable(&f));
 assert(f.ppp_protocol_ids[0]==6 && f.ppp_protocol_ids[1]==10);
 for(unsigned int i=0;i<3;i++)assert(!f.protocol_cam[i].created);
 assert(!rtl_fe_disable(&f));
 assert(f.cam[2][11][0]==0x18864 && f.cam[8][5][0]==0x10021 && f.cam[8][9][0]==0x10057);
 /* Fail a table write during prepare and again during its rollback. */
 f.fail_mask_writes=2;
 assert(rtl_fe_enable(&f)==-ETIMEDOUT && !f.enabled && f.prepared);
 f.fail_mask_writes=1;
 assert(rtl_fe_enable(&f)==-ETIMEDOUT && !f.enabled && f.prepared);
 assert(!memcmp(f.saved,old_regs,ARRAY_SIZE(fe_registers)*sizeof(old_regs[0])));
 assert(!rtl_fe_enable(&f) && f.enabled);
 assert(!rtl_fe_disable(&f) && !f.prepared);
 for(unsigned int i=0;i<ARRAY_SIZE(fe_registers);i++)assert(fe_read(&f,fe_registers[i])==old_regs[i]);
 /* A failed normal disable has the same unfinished ownership. */
 assert(!rtl_fe_enable(&f));
 f.fail_mask_writes=1;
 assert(rtl_fe_disable(&f)==-ETIMEDOUT && !f.enabled && f.prepared);
 assert(f.desired_mode==RTL_FE_MODE_HARDWARE);
 assert(!rtl_fe_enable(&f));
 assert(!rtl_fe_disable(&f));
 for(unsigned int i=0;i<ARRAY_SIZE(fe_registers);i++)assert(fe_read(&f,fe_registers[i])==old_regs[i]);
 /* CPU trap mode is a legitimate prepared state, not failed rollback. */
 assert(!rtl_fe_cpu_path(&f) && f.prepared && !f.enabled && f.cpu_path);
 unsigned int snapshot[64];memcpy(snapshot,f.saved,sizeof(snapshot));
 unsigned int cpu_regs[64];
 for(unsigned int i=0;i<ARRAY_SIZE(fe_registers);i++)cpu_regs[i]=fe_read(&f,fe_registers[i]);
 unsigned int before=f.admission_writes;
 assert(!rtl_fe_cpu_path(&f) && f.cpu_path && f.prepared);
 assert(f.admission_writes==before && !memcmp(snapshot,f.saved,sizeof(snapshot)));
 for(unsigned int i=0;i<5;i++)assert(fe_read(&f,FE_LAN_RX_CTRL(i))==lan[i]);
 for(unsigned int cycle=0;cycle<3;cycle++){
  assert(!rtl_fe_enable(&f) && f.enabled && f.prepared && !f.cpu_path);
  assert(!memcmp(snapshot,f.saved,sizeof(snapshot)));
  struct rtl_fe_flow second={},first={.next=&second};f.flows.first=&first;
  unsigned int deleted=f.deletes;
  assert(!rtl_fe_cpu_path(&f) && !f.enabled && f.prepared && f.cpu_path);
  assert(!f.flows.first && f.deletes==deleted+2);
  assert(!memcmp(snapshot,f.saved,sizeof(snapshot)));
  for(unsigned int i=0;i<ARRAY_SIZE(fe_registers);i++)assert(fe_read(&f,fe_registers[i])==cpu_regs[i]);
  for(unsigned int i=0;i<5;i++)assert(fe_read(&f,FE_LAN_RX_CTRL(i))==lan[i]);
 }
 /* Failed cleanup cannot silently turn a partial state into valid CPU mode. */
 assert(!rtl_fe_enable(&f));
 struct rtl_fe_flow stuck={};f.flows.first=&stuck;f.fail_delete=1;
 assert(rtl_fe_cpu_path(&f)==-ETIMEDOUT && !f.enabled && f.prepared && !f.cpu_path);
 assert(f.flows.first==&stuck && !memcmp(snapshot,f.saved,sizeof(snapshot)));
 assert(!rtl_fe_cpu_path(&f) && f.cpu_path && !f.flows.first);
 assert(!rtl_fe_disable(&f) && !f.enabled && !f.prepared && !f.cpu_path);
 for(unsigned int i=0;i<ARRAY_SIZE(fe_registers);i++)assert(fe_read(&f,fe_registers[i])==old_regs[i]);
 /* A cold CPU-only request must prepare without ever admitting LAN. */
 before=f.admission_writes;f.fail_mask=1;
 assert(rtl_fe_cpu_path(&f)==-ETIMEDOUT && !f.enabled && !f.prepared && !f.cpu_path);
 assert(!rtl_fe_cpu_path(&f) && f.cpu_path && f.prepared && f.admission_writes==before);
 assert(!rtl_fe_disable(&f) && !f.prepared && !f.cpu_path);
 /* A cold CPU request must wait for NI startup, matching the production
  * init ordering (NI/OMCI up before PDC admits business GEMs). No premature
  * snapshot may restore boot/reset values over the NI's active scheduler. */
 for(unsigned int admit=0;admit<2;admit++){
  unsigned int reset[5],native[5];
  assert(!rtl_fe_engine_suspend(&f) && !f.engine_ready);
  for(unsigned int i=0;i<5;i++){
   reset[i]=0x08000400U|(i<<24);
   f.expected_lan[i]=reset[i];
   fe_write(&f,FE_LAN_RX_CTRL(i),reset[i]);
  }
  assert(rtl_fe_cpu_path(&f)==-EAGAIN && !f.prepared && !f.cpu_path);
  for(unsigned int i=0;i<5;i++)assert(fe_read(&f,FE_LAN_RX_CTRL(i))==reset[i]);
  for(unsigned int i=0;i<5;i++){
   native[i]=(reset[i]&~(BIT(28)|(63U<<16)|BIT(31)))|BIT(28)|(16U<<16);
   f.expected_lan[i]=native[i];
   fe_write(&f,FE_LAN_RX_CTRL(i),native[i]);
  }
  assert(!rtl_fe_engine_resume(&f) && f.engine_ready);
  assert(!rtl_fe_cpu_path(&f));
  for(unsigned int i=0;i<5;i++)assert(fe_read(&f,FE_LAN_RX_CTRL(i))==native[i]);
  if(admit){
   assert(!rtl_fe_enable(&f) && f.enabled);
   for(unsigned int i=0;i<5;i++)assert(fe_read(&f,FE_LAN_RX_CTRL(i))==native[i]);
   assert(!rtl_fe_cpu_path(&f) && !f.enabled && f.cpu_path);
   for(unsigned int i=0;i<5;i++)assert(fe_read(&f,FE_LAN_RX_CTRL(i))==native[i]);
  }
  assert(!rtl_fe_disable(&f) && !f.prepared);
  for(unsigned int i=0;i<5;i++)assert(fe_read(&f,FE_LAN_RX_CTRL(i))==native[i]);
 }
 /* Full NI restart: requested mode survives but every register snapshot is
  * re-created after the new native baseline. Do not leave enabled=1 while
  * all LAN selectors have silently reverted to CPU16. */
 for(unsigned int mode=RTL_FE_MODE_CPU;mode<=RTL_FE_MODE_HARDWARE;mode++){
  assert(!(mode==RTL_FE_MODE_CPU?rtl_fe_cpu_path(&f):rtl_fe_enable(&f)));
  assert((unsigned int)f.desired_mode==mode);
  assert(!rtl_fe_engine_suspend(&f));
  assert(!f.engine_ready && !f.enabled && !f.prepared && !f.cpu_path);
  assert((unsigned int)f.desired_mode==mode);
  assert(rtl_fe_enable(&f)==-EAGAIN && !f.prepared);
  assert(!rtl_fe_engine_suspend(&f)); /* start preflight is idempotent */
  unsigned int scheduler=0x81000000U|mode;
  fe_write(&f,0x2300,scheduler);
  for(unsigned int i=0;i<5;i++){
   f.expected_lan[i]=(0x18100400U|(i<<24))+mode;
   fe_write(&f,FE_LAN_RX_CTRL(i),f.expected_lan[i]);
  }
  assert(!rtl_fe_engine_resume(&f) && f.engine_ready && f.prepared);
  assert(f.enabled==(mode==RTL_FE_MODE_HARDWARE));
  assert(f.cpu_path==(mode==RTL_FE_MODE_CPU));
  for(unsigned int i=0;i<5;i++)assert(((fe_read(&f,FE_LAN_RX_CTRL(i))>>16)&63)==16);
  assert(!rtl_fe_disable(&f) && f.desired_mode==RTL_FE_MODE_OFF);
  assert(fe_read(&f,0x2300)==scheduler);
  for(unsigned int i=0;i<5;i++)assert(fe_read(&f,FE_LAN_RX_CTRL(i))==f.expected_lan[i]);
 }
 /* Failed suspend retains its owners. Resume refuses an uncleared snapshot;
  * successful retry must precede NI reset and a later prepare. */
 assert(!rtl_fe_enable(&f));
 f.flows.first=&stuck;stuck.next=NULL;f.fail_delete=1;
 assert(rtl_fe_engine_suspend(&f)==-ETIMEDOUT && !f.engine_ready && f.prepared);
 assert(f.desired_mode==RTL_FE_MODE_HARDWARE && f.flows.first==&stuck);
 assert(rtl_fe_engine_resume(&f)==-EBUSY && !f.engine_ready);
 assert(!rtl_fe_engine_suspend(&f) && !f.prepared && !f.flows.first);
 f.fail_mask=1;
 assert(rtl_fe_engine_resume(&f)==-ETIMEDOUT && !f.engine_ready && !f.enabled);
 assert(f.desired_mode==RTL_FE_MODE_HARDWARE);
 assert(!rtl_fe_engine_suspend(&f));
 assert(!rtl_fe_engine_resume(&f) && f.engine_ready && f.enabled);
 assert(!rtl_fe_disable(&f));
 /* The same gate applies when a live L3 engine owns the previous snapshot. */
 assert(!rtl_fe_enable(&f));
 before_switch_writes=f.register_writes;f.switch_error=-EBUSY;
 assert(rtl_fe_disable(&f)==-EBUSY && f.enabled && f.prepared);
 assert(rtl_fe_cpu_path(&f)==-EBUSY && f.enabled && !f.cpu_path);
 assert(f.register_writes==before_switch_writes && f.desired_mode==RTL_FE_MODE_HARDWARE);
 f.switch_error=0;assert(!rtl_fe_disable(&f));
 /* A stale saved selector is data, not permission to bypass a newer gate. */
 f.lan_redirected=true;
 for(unsigned int i=0;i<5;i++)f.lan_saved[i]=(f.expected_lan[i]&~(BIT(28)|(63U<<16)))|((i&1?i:25U)<<16);
 mutex_lock(&f.lock);fe_lan_restore_locked(&f);mutex_unlock(&f.lock);
 for(unsigned int i=0;i<5;i++)assert(fe_read(&f,FE_LAN_RX_CTRL(i))==
  ((f.lan_saved[i]&~(63U<<16))|BIT(28)|(16U<<16)));
 assert(!f.lan_redirected && !f.admission_writes);
 f.shutting_down=true;
 assert(rtl_fe_enable(&f)==-ENODEV && rtl_fe_cpu_path(&f)==-ENODEV);
 assert(rtl_fe_engine_resume(&f)==-ENODEV && !f.engine_ready);
 puts("NI/FE lifecycle: CPU/HW desired mode, fresh restart snapshots, failed suspend/restore and offline admission guards passed");
 puts("CPU-only FE: first prepare, idempotence, on/off snapshots, cleanup failure and final full restore passed");
 puts("Five-LAN FE:deferred guarded admission,physical source preservation,direct L2TM output,three restore cycles and failed preparation passed");
 puts("FE rollback: failed prepare/disable preserves original snapshots across re-enable and repeated rollback failure");
}
'''
functions = ['fe_route_select_locked', 'fe_route_gate', 'fe_route_arm',
             'fe_classifier_default_index', 'fe_prepare', 'fe_restore']
if re.search(r'^static void fe_lan_restore_locked\(', source, re.M):
    functions.append('fe_lan_restore_locked')
if re.search(r'^static int fe_disable_locked\(', source, re.M):
    functions.append('fe_disable_locked')
functions += ['rtl_fe_enable', 'rtl_fe_cpu_path', 'rtl_fe_disable']
for helper in ('fe_enable_locked', 'fe_cpu_path_locked'):
    if re.search(r'^static int ' + helper + r'\(', source, re.M):
        functions.insert(functions.index('rtl_fe_enable'), helper)
functions += ['rtl_fe_engine_suspend', 'rtl_fe_engine_resume']
with tempfile.TemporaryDirectory(dir=root / 'artifacts', prefix='fe-lan-lifecycle-') as work:
    path = Path(work) / 'test.c'
    binary = Path(work) / 'test'
    path.write_text(common + registers + '\n' + '\n'.join(function(n) for n in functions) + test)
    subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-g', '-fsanitize=address,undefined',
        '-I', str(drivers), str(path), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
(root / 'logs/fe-five-lan-lifecycle.json').write_text(json.dumps({
    'production_source_sha256': hashlib.sha256(source.encode()).hexdigest(),
    'LAN_ports': [0, 1, 2, 3, 4], 'exact_enable_disable_cycles': 3,
    'failed_prepare_admits_no_LAN': True,
    'mode_setup_never_bypasses_single_fabric_admission_owner': True,
    'stale_saved_RX_selector_cannot_reopen_native_or_route_admission': True,
    'CPU_only_prepares_without_LAN_admission_and_preserves_snapshot': True,
    'CPU_only_cleanup_failure_requires_retry': True,
    'cold_CPU_request_waits_for_NI_ready': True,
    'NI_restart_restores_requested_mode_after_fresh_register_snapshot': True,
    'failed_suspend_blocks_resume_and_retains_owners': True,
    'GEM_gate_opens_after_CLS_defaults_LPB_cache_and_closes_before_restore': True,
    'PON_stream_identity_enabled_before_admission_and_restored': True,
    'two_profiles_four_result_groups_two_rows_saved_programmed_and_restored': True,
    'all_foreign_TCAM_valid_flags_rejected_without_data_writes': True,
    'both_CPU_profile_readbacks_required_before_enable': True,
    'CPU_original_profile_stops_both_LAN_and_PON_hash_admission': True,
    'physical_LSPID_preserved': True,
    'failed_rollback_preserves_original_snapshot_on_reenable': True,
    'post_PE_LAN_output': 'NI demux3 to L2TM; upper selectors preserved',
    'sanitizers': ['ASan', 'UBSan'], 'hardware_verified_by_this_test': False,
}, indent=2) + '\n')
