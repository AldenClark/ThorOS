#!/usr/bin/env python3
"""Run production FE device-lifetime base ownership and warm NI admission."""
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
registers += '\n' + re.search(r'static const unsigned int fe_cls_mode0_mask\[2\]\[7\] = \{.*?\};', source, re.S).group()
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
static bool list_empty(struct list_head *head){return !head->first;}
static void mutex_lock(struct mutex *m){assert(!m->held);m->held=true;}
static void mutex_unlock(struct mutex *m){assert(m->held);m->held=false;}
struct rtl_fe {
 struct mutex lock;struct list_head flows;
 uint64_t dma;bool prepared,enabled,cpu_path,lan_redirected;int error;
 bool engine_ready,shutting_down;enum rtl_fe_mode desired_mode;
 struct spinlock route_lock;bool route_gate_ready,route_admitted,dma_exposed;
 bool base_ready,base_failed;
 unsigned int saved[64],lan_saved[5],mask_saved[8],classifier_saved[2][4][2][7],map_saved[2][4];
 unsigned int bridge_mask_saved[3][8],bridge_mask[3][8];
 unsigned int reg[0x10000/4],mask[8],cls[1056][7],map[256],cls_keys[256];
 struct rtl_fe_cam_protocol protocol_cam[3];unsigned char ppp_protocol_ids[2];
 unsigned int cam[9][64][5];
 unsigned int admission_writes,cache_ready,fail_mask,fail_mask_writes,deletes,fail_delete;
 unsigned int switch_quiesces,switch_reconciles,register_writes;
 unsigned int key_reads,fail_key_read,fail_route_open,fail_cpu_selector;
 unsigned int pp_rejected_register,pp_rejected_value;
 unsigned int base_rejected_register,base_rejected_value;
 unsigned int commands,fail_command,base_writes;
 int switch_error;
 unsigned int expected_lan[5];
};
static unsigned int fe_read(void *ctx,unsigned int reg){struct rtl_fe *f=ctx;assert(reg<0x10000);return f->reg[reg/4];}
static void fe_write(void *ctx,unsigned int reg,unsigned int value){
 struct rtl_fe *f=ctx;assert(reg<0x10000);
 f->register_writes++;
 if(reg!=0x3418 && reg!=0x3424 &&
    !(reg>=0xa5f8 && reg<=0xa838 && !((reg-0xa5f8)%0x90)))f->base_writes++;
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
 f->commands++;
 if(f->fail_command==f->commands)return -ETIMEDOUT;
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
'''
lan_defines = re.search(r'^#define FE_LAN_PORTS[^\n]*\n#define FE_LAN_RX_CTRL[^\n]*', source, re.M)
if lan_defines:
    common = common.replace('#define FE_LAN_PORTS 5\n#define FE_LAN_RX_CTRL(p) (0xa5f8+0x90*(p))', lan_defines.group())
test = r'''
static void initialize(struct rtl_fe *f) {
 memset(f,0,sizeof(*f));f->dma=0x03800000;f->engine_ready=true;
 for(unsigned int i=0;i<0x10000/4;i++)f->reg[i]=0x80000000U+i;
 const unsigned int access[]={0x1654,0x1ca0,0x1cb4,0x3000,0x3200,0x3380,0x33b0,
  0x35c8,0x38b0,0x38e0,0x38e4,0x3910,0x3928,0x393c};
 for(unsigned int i=0;i<ARRAY_SIZE(access);i++)f->reg[access[i]/4]=0;
 const unsigned int pp[]={0x3248,0x324c,0x3314,0x3318};
 for(unsigned int i=0;i<ARRAY_SIZE(pp);i++)f->reg[pp[i]/4]=0xfffffa10U;
 f->reg[0x30a4/4]=0x0001b000U;
 for(unsigned int i=0;i<5;i++)
  f->reg[FE_LAN_RX_CTRL(i)/4]=f->expected_lan[i]=0x18100400U|(i<<24);
 for(unsigned int i=0;i<8;i++)f->mask[i]=0x55000000+i;
 for(unsigned int s=0;s<3;s++)for(unsigned int i=0;i<8;i++)
  f->bridge_mask[s][i]=0x5a000000+s*8+i;
 for(unsigned int s=0;s<1056;s++)for(unsigned int i=0;i<7;i++)
  f->cls[s][i]=0x11000000+s*7+i;
 const unsigned int base[2][4]={{1024,1026,1040,1042},{1028,1030,1044,1046}};
 for(unsigned int p=0;p<2;p++)for(unsigned int type=0;type<4;type++)
  f->cls[base[p][type]+1][6]=0xffffffffU;
 for(unsigned int i=0;i<256;i++)f->map[i]=0x100+i;
}
static void check_cpu_gate(struct rtl_fe *f) {
 assert(f->prepared && f->base_ready && !f->base_failed && !f->shutting_down);
 assert(f->route_gate_ready && !f->route_admitted);
 assert(((fe_read(f,0x3418)>>10)&15)==1 && ((fe_read(f,0x3424)>>10)&15)==1);
 for(unsigned int i=0;i<5;i++)
  assert((fe_read(f,FE_LAN_RX_CTRL(i))&(BIT(28)|(63U<<16)))==(BIT(28)|(16U<<16)));
}
static void check_base_retained(struct rtl_fe *f,const struct rtl_fe *base) {
 check_cpu_gate(f);
 assert(!memcmp(f->saved,base->saved,sizeof(f->saved)));
 assert(!memcmp(f->mask,base->mask,sizeof(f->mask)));
 assert(!memcmp(f->bridge_mask,base->bridge_mask,sizeof(f->bridge_mask)));
 assert(!memcmp(f->cls,base->cls,sizeof(f->cls)));
 assert(!memcmp(f->map,base->map,sizeof(f->map)));
 assert(!memcmp(f->cam,base->cam,sizeof(f->cam)));
 for(unsigned int i=0;i<ARRAY_SIZE(fe_registers);i++)
  assert(fe_read(f,fe_registers[i])==base->reg[fe_registers[i]/4]);
 assert(f->base_writes==base->base_writes);
}
static void check_poisoned(struct rtl_fe *f) {
 assert(f->prepared && f->dma_exposed && f->base_failed && f->shutting_down);
 assert(!f->engine_ready && !f->enabled && !f->cpu_path && !f->route_admitted);
 unsigned int writes=f->base_writes,commands=f->commands;
 assert(rtl_fe_enable(f)==-ENODEV && rtl_fe_cpu_path(f)==-ENODEV);
 assert(rtl_fe_disable(f)==-ENODEV && rtl_fe_engine_resume(f)==-ENODEV);
 assert(rtl_fe_engine_suspend(f)==-ENODEV);
 assert(fe_restore(f)==-EBUSY); /* Even a direct accidental rollback is refused. */
 assert(f->base_writes==writes && f->commands==commands);
}
int main(void) {
 struct rtl_fe f,cold,base;
 unsigned int failures=0,drifts=0;
 initialize(&cold);f=cold;
 /* L2 errors gate even an existing live mode, but are retryable and do not
  * manufacture a complete base or acquire memory ownership. */
 f.switch_error=-ETIMEDOUT;
 assert(rtl_fe_enable(&f)==-ETIMEDOUT && !f.prepared && !f.base_failed);
 assert(rtl_fe_cpu_path(&f)==-ETIMEDOUT && !f.prepared && !f.base_failed);
 assert(rtl_fe_disable(&f)==-ETIMEDOUT && !f.dma_exposed);
 assert(!f.base_writes && f.switch_quiesces==3);
 const unsigned int pp[]={0x3248,0x324c,0x3314,0x3318};
 const unsigned int unsafe[]={0,0xfffffa11U,0xfffff810U,0xfffffe10U,
  0xfffff210U,0xffffea10U,0xfffefa10U,0xffeffa10U,0xfefffa10U,0xeffffa10U};
 for(unsigned int side=0;side<ARRAY_SIZE(pp);side++)for(unsigned int n=0;n<ARRAY_SIZE(unsafe);n++){
  f=cold;f.reg[pp[side]/4]=unsafe[n];
  assert(rtl_fe_enable(&f)==-EOPNOTSUPP);
  assert(!f.prepared && !f.dma_exposed && !f.base_failed && !f.shutting_down);
  assert(!f.base_writes && !f.key_reads && f.pp_rejected_register==pp[side]);
  f.reg[pp[side]/4]=0xfffffa10U;
  assert(!rtl_fe_enable(&f));check_cpu_gate(&f);failures++;
 }
 /* The four valid forms at every actual TCAM key still exclude foreign ACLs. */
 for(unsigned int index=0;index<256;index++)for(unsigned int bit=27;bit<=30;bit++){
  f=cold;f.cls_keys[index]=BIT(bit);
  assert(rtl_fe_enable(&f)==-EBUSY && !f.prepared && !f.dma_exposed);
  assert(!f.base_failed && !f.shutting_down && !f.base_writes);failures++;
 }
 for(unsigned int index=0;index<256;index++){
  f=cold;f.fail_key_read=index+1;
  assert(rtl_fe_enable(&f)==-ETIMEDOUT && !f.prepared && !f.dma_exposed);
  assert(!f.base_failed && !f.shutting_down && !f.base_writes);failures++;
 }
 f=cold;f.fail_mask=1;
 assert(rtl_fe_enable(&f)==-ETIMEDOUT && !f.prepared && !f.dma_exposed && !f.base_failed);
 assert(!rtl_fe_enable(&f));check_cpu_gate(&f);
 f=cold;assert(!rtl_fe_enable(&f));check_cpu_gate(&f);
 unsigned int prepare_commands=f.commands;
 base=f;
 assert(f.enabled && f.base_ready && f.dma_exposed);
 assert(f.cache_ready && fe_read(&f,0x383c)==0x03800000);
 assert((fe_read(&f,0x3944)&0x80000001U)==0x80000001U);
 assert((fe_read(&f,0x3948)&1U) && (fe_read(&f,0x3c80)&255U)==255U);
 assert((fe_read(&f,0x3940)&0xffff)==0xd0d0);
 assert(!(f.mask[6]&BIT(25)));
 for(unsigned int i=0;i<3;i++)assert(!(f.bridge_mask[i][6]&BIT(25)));
 assert(fe_read(&f,0x30a4)==0x8001b000U);
 assert(f.ppp_protocol_ids[0]==1 && f.ppp_protocol_ids[1]==2);
 assert(f.cam[2][0][0]==0x18864 && f.cam[8][0][0]==0x10021 && f.cam[8][1][0]==0x10057);
 const unsigned int rows[2][4]={{1024,1026,1040,1042},{1028,1030,1044,1046}};
 for(unsigned int p=0;p<2;p++)for(unsigned int type=0;type<4;type++){
  unsigned int r=rows[p][type];
  assert(fe_classifier_default_index(p,type,0)==r && fe_classifier_default_index(p,type,1)==r+1);
  assert(((f.cls[r][4]>>26)&7)==7 && !(f.cls[r][6]&BIT(16)));
  assert(((f.cls[r][6]>>11)&31)==(p?31:1));
  assert(((f.cls[r][5]>>22)&3)==(p?3:0));
  for(unsigned int word=0;word<7;word++)assert(!f.cls[r+1][word]);
 }
 /* Successful OFF is policy OFF, not a handoff to arbitrary boot profiles.
  * Ten complete CPU/HW/OFF transitions keep every exposed base table. */
 for(unsigned int cycle=0;cycle<10;cycle++){
  assert(!rtl_fe_enable(&f) && f.enabled);
  assert(fe_route_arm(&f) && f.route_admitted);
  assert(!rtl_fe_disable(&f) && !f.enabled && !f.cpu_path);
  assert(f.desired_mode==RTL_FE_MODE_OFF);check_base_retained(&f,&base);
  assert(!rtl_fe_cpu_path(&f) && f.cpu_path);check_base_retained(&f,&base);
  assert(!rtl_fe_cpu_path(&f));check_base_retained(&f,&base);
  assert(!rtl_fe_enable(&f) && f.enabled && !f.cpu_path);
  struct rtl_fe_flow second={},first={.next=&second};f.flows.first=&first;
  unsigned int deleted=f.deletes;
  assert(!rtl_fe_cpu_path(&f) && f.cpu_path && f.deletes==deleted+2 && !f.flows.first);
  check_base_retained(&f,&base);
 }
 assert(!f.admission_writes);
 /* A failed route withdrawal stays gated and retryable. It does NOT justify
  * restoring the base or claiming the requested CPU mode was completed. */
 assert(!rtl_fe_enable(&f));
 struct rtl_fe_flow stuck={};f.flows.first=&stuck;f.fail_delete=1;
 assert(rtl_fe_cpu_path(&f)==-ETIMEDOUT && !f.enabled && !f.cpu_path && !f.base_failed);
 check_base_retained(&f,&base);
 f.fail_delete=1;
 assert(rtl_fe_engine_suspend(&f)==-ETIMEDOUT && !f.engine_ready);
 assert(rtl_fe_engine_resume(&f)==-EBUSY && f.flows.first==&stuck);
 assert(!rtl_fe_engine_suspend(&f) && !f.flows.first);
 assert(!rtl_fe_engine_resume(&f) && f.engine_ready && f.enabled);
 check_base_retained(&f,&base);
 /* Ordinary warm NI opens reuse the same DMA/CLS owner in all requested
  * modes; no MEM_INI, cache-stop, parser rewrite or original snapshot reset. */
 for(unsigned int mode=0;mode<=RTL_FE_MODE_HARDWARE;mode++){
  assert(!(mode==RTL_FE_MODE_OFF?rtl_fe_disable(&f):
   mode==RTL_FE_MODE_CPU?rtl_fe_cpu_path(&f):rtl_fe_enable(&f)));
  assert(!rtl_fe_engine_suspend(&f) && !f.engine_ready && !f.enabled && !f.cpu_path);
  check_base_retained(&f,&base);
  assert((unsigned int)f.desired_mode==mode && rtl_fe_enable(&f)==-EAGAIN);
  assert(!rtl_fe_engine_suspend(&f));
  unsigned int writes=f.base_writes;
  assert(!rtl_fe_engine_resume(&f) && f.engine_ready);
  assert(f.enabled==(mode==RTL_FE_MODE_HARDWARE) && f.cpu_path==(mode==RTL_FE_MODE_CPU));
  assert(f.base_writes==writes);check_base_retained(&f,&base);
 }
 /* Defined bits only: unrelated ports, high reserved address bits, PDPID
  * padding and LPB HI[31:30] read noise cannot falsely poison a warm owner. */
 assert(!rtl_fe_engine_suspend(&f));
 f.reg[0x2300/4]^=BIT(8)|BIT(20);f.reg[0xa1e0/4]^=BIT(16);
 f.reg[0x2394/4]^=BIT(8)|BIT(15)|BIT(28);f.reg[0x23a0/4]^=BIT(8)|BIT(15)|BIT(28);
 const unsigned int high[]={0x3838,0x3840,0x384c,0x3858};
 const unsigned int low[]={0x383c,0x3844,0x3850,0x385c};
 for(unsigned int i=0;i<4;i++){f.reg[high[i]/4]^=0xa5000000U;f.reg[low[i]/4]^=127;}
 f.reg[0x341c/4]^=0xc0000000U;f.reg[0x3428/4]^=0xc0000000U;
 for(unsigned int i=0;i<4;i++){f.map[24|(i<<6)]|=0xfffffff0U;f.map[25|(i<<6)]|=0xfffffff0U;}
 /* Independent SDK mode0 layout: reserved fields are not action bits;
  * the second row only carries the three-bit format selector. */
 const unsigned int cls_valid[2][7]={
  {0xffffcfffU,0xcfffffffU,~0U,0xfffffffbU,~0U,0xecffffffU,0x03ffffffU},
  {0,0,0,0,0,0,0x03800000U}};
 for(unsigned int p=0;p<2;p++)for(unsigned int type=0;type<4;type++)
  for(unsigned int row=0;row<2;row++)for(unsigned int word=0;word<7;word++)
   f.cls[rows[p][type]+row][word]|=~cls_valid[row][word];
 assert(!rtl_fe_engine_resume(&f) && !f.base_failed && f.base_ready);
 /* Every preparation command may time out. Read-only failures remain
  * retryable; once publication begins, ALL partial states are poisoned,
  * including late failures in post-program readback rather than only writes. */
 for(unsigned int fail=1;fail<=prepare_commands;fail++){
  f=cold;f.fail_command=fail;
  assert(rtl_fe_enable(&f)==-ETIMEDOUT && !f.enabled);
  if(f.prepared || f.dma_exposed)check_poisoned(&f);
  else {assert(!f.base_failed && !f.shutting_down);f.fail_command=0;assert(!rtl_fe_enable(&f));}
  failures++;
 }
 for(unsigned int side=0;side<2;side++){
  f=cold;f.fail_cpu_selector=0x3418+side*12;
  assert(rtl_fe_enable(&f)==-EIO);check_poisoned(&f);failures++;
 }
 /* A successful past prepare is not permission to reopen after reset,
  * foreign drift, a corrupted CPU result or a changed connector mapping. */
 const unsigned int reg[][2]={
  {0x3414,BIT(0)},{0x3418,BIT(0)},{0x341c,BIT(0)},
  {0x3420,BIT(0)},{0x3424,BIT(0)},{0x3428,BIT(0)},
  {0x3838,BIT(0)},{0x3840,BIT(0)},{0x384c,BIT(0)},{0x3858,BIT(0)},
  {0x383c,BIT(7)},{0x3844,BIT(7)},{0x3850,BIT(7)},{0x385c,BIT(7)},
  {0x3848,BIT(0)},{0x3854,BIT(0)},{0x38c4,BIT(29)},
  {0x2300,BIT(12)},{0x2300,BIT(13)},{0x2394,BIT(0)},{0x23a0,BIT(16)},
  {0xa1e0,BIT(0)},{0x30a4,BIT(31)},{0x351c,BIT(10)},
  {0x3400,BIT(0)},{0x3400,BIT(10)},{0x3404,BIT(8)}};
 for(unsigned int n=0;n<ARRAY_SIZE(reg);n++){
  f=base;assert(!rtl_fe_engine_suspend(&f));f.reg[reg[n][0]/4]^=reg[n][1];
  unsigned int writes=f.base_writes;
  assert(rtl_fe_engine_resume(&f)==-EIO);check_poisoned(&f);
  assert(f.base_writes==writes && f.base_rejected_register==reg[n][0]);drifts++;
 }
 for(unsigned int p=0;p<2;p++)for(unsigned int type=0;type<4;type++)
  for(unsigned int row=0;row<2;row++)for(unsigned int word=0;word<7;word++){
   for(unsigned int bit=0;bit<32;bit++)if(cls_valid[row][word]&BIT(bit)){
    f=base;assert(!rtl_fe_engine_suspend(&f));f.cls[rows[p][type]+row][word]^=BIT(bit);
    assert(rtl_fe_engine_resume(&f)==-EIO);check_poisoned(&f);drifts++;
   }
  }
 for(unsigned int i=0;i<2;i++)for(unsigned int side=0;side<4;side++){
  f=base;assert(!rtl_fe_engine_suspend(&f));f.map[(24+i)|(side<<6)]^=1;
  assert(rtl_fe_engine_resume(&f)==-EIO);check_poisoned(&f);drifts++;
 }
 f=base;assert(!rtl_fe_engine_suspend(&f));f.cls_keys[7]=BIT(30);
 assert(rtl_fe_engine_resume(&f)==-EBUSY);check_poisoned(&f);drifts++;
 for(unsigned int i=0;i<4;i++){
  f=base;assert(!rtl_fe_engine_suspend(&f));f.reg[pp[i]/4]=0;
  assert(rtl_fe_engine_resume(&f)==-EOPNOTSUPP);check_poisoned(&f);drifts++;
 }
 /* A transient L2 command failure closes admission without poisoning the
  * intact base. Retrying can complete; no async owner may silently reopen. */
 f=base;assert(fe_route_arm(&f));f.switch_error=-EBUSY;
 assert(rtl_fe_disable(&f)==-EBUSY && !f.enabled && !f.cpu_path && !f.base_failed);
 assert(!f.route_admitted && f.desired_mode==RTL_FE_MODE_HARDWARE);
 f.switch_error=0;assert(!rtl_fe_disable(&f));check_base_retained(&f,&base);
 f.lan_redirected=true;
 for(unsigned int i=0;i<5;i++)f.lan_saved[i]=i&1?0:(25U<<16);
 mutex_lock(&f.lock);fe_lan_restore_locked(&f);mutex_unlock(&f.lock);
 for(unsigned int i=0;i<5;i++)assert((fe_read(&f,FE_LAN_RX_CTRL(i))&(BIT(28)|(63U<<16)))==(BIT(28)|(16U<<16)));
 /* A cold CPU mode also takes a complete base owner without LAN admission. */
 f=cold;f.engine_ready=false;
 assert(rtl_fe_cpu_path(&f)==-EAGAIN && !f.prepared && !f.dma_exposed);
 assert(!rtl_fe_engine_resume(&f) && !f.prepared);
 assert(!rtl_fe_cpu_path(&f) && f.cpu_path);check_cpu_gate(&f);
 printf("FE lifetime base: ten CPU/HW/OFF cycles, warm OFF/CPU/HW reopen, %u faults and %u retained-state drifts passed\n",failures,drifts);
 puts("Base profile/DMA publication is permanent; no full L3 drain or per-flow retirement proof is claimed.");
}
'''

functions = ['fe_route_select_locked', 'fe_route_gate', 'fe_route_arm',
             'fe_classifier_default_index', 'fe_prepare', 'fe_restore']
if re.search(r'^static void fe_lan_restore_locked\(', source, re.M):
    functions.append('fe_lan_restore_locked')
functions += ['fe_base_match', 'fe_base_check_locked',
              'fe_base_quarantine_locked', 'fe_base_require_locked']
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
    'LAN_ports': [0, 1, 2, 3, 4], 'exact_enable_disable_cycles': 10,
    'failed_prepare_admits_no_LAN': True,
    'mode_setup_never_bypasses_single_fabric_admission_owner': True,
    'stale_saved_RX_selector_cannot_reopen_native_or_route_admission': True,
    'CPU_only_prepares_without_LAN_admission_and_preserves_snapshot': True,
    'CPU_only_cleanup_failure_requires_retry': True,
    'cold_CPU_request_waits_for_NI_ready': True,
    'NI_warm_restart_reuses_and_validates_permanent_base': True,
    'failed_suspend_blocks_resume_and_retains_owners': True,
    'GEM_gate_opens_after_CLS_defaults_LPB_cache': True,
    'PON_stream_identity_and_CPU_profile_retained_while_OFF': True,
    'two_profiles_four_result_groups_two_rows_retained_not_boot_restored': True,
    'all_foreign_TCAM_valid_flags_rejected_without_data_writes': True,
    'both_CPU_profile_readbacks_required_before_enable': True,
    'CPU_original_profile_stops_both_LAN_and_PON_hash_admission': True,
    'physical_LSPID_preserved': True,
    'partial_exposed_prepare_is_permanently_quarantined': True,
    'readonly_preflight_failure_is_not_poisoned': True,
    'warm_reopen_does_not_reset_cache_tables_or_DMA_bases': True,
    'shared_and_reserved_readback_bits_ignored': True,
    'full_L3_AXI_drain_verified': False,
    'per_flow_slot_retirement_verified': False,
    'post_PE_LAN_output': 'NI demux3 to L2TM; upper selectors preserved',
    'sanitizers': ['ASan', 'UBSan'], 'hardware_verified_by_this_test': False,
}, indent=2) + '\n')
