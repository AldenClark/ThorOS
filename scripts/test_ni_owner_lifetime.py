#!/usr/bin/env python3
"""Execute production NI lifetime, physical claims, teardown and TX admission.

QM/DMA initialization and kernel scheduling boundaries are instrumented, not
emulated hardware. The real NI functions must preserve every queue-owner token
over warm cycles; removal must retain exposed RAM and reject physical reprobe.
The actual DMA quiesce function is executed against an MMIO recorder. This does
not claim an ASIC drain, queue performance, or a real board removal test.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
driver = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
source = (driver / 'rtl9617c-xram.c').read_text()
dma_source = (driver / 'rtl9617c-dma.c').read_text()
qm_source = (driver / 'rtl9617c-qm.c').read_text()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--mutants', action='store_true')
args = parser.parse_args()


def function(text, name):
    match = re.search(r'(?m)^(?:static\s+)?(?:inline\s+)?[\w *]+\b' + name +
                      r'\([^;{}]*\)\s*\{', text)
    assert match, name
    end = text.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[match.start():end]


names = ('rtl_ni_owner_claim', 'rtl_ni_owner_expose', 'rtl_ni_owner_release',
         'rtl_pon_host_gate',
         'rtl_engine_poison', 'rtl_engine_prepare', 'rtl_engine_start',
         'rtl_engine_stop', 'rtl_engine_get', 'rtl_engine_put',
         'rtl_ni_release_dma', 'rtl_remove', 'rtl9617c_ni_transmit', 'rtl9617c_ni_pon_gate')
functions = '\n'.join(function(source, name) for name in names)
dma_functions = '\n'.join(function(dma_source, name) for name in
                          ('rtl_dma_vp', 'rtl_dma_tx_quiesce'))
qm_start = function(qm_source, 'rtl_qm_rx_start')
qm_tail = ('static int rtl_qm_start_admission_tail(struct rtl_qm_rx *rx,void *ni) {\n' +
           qm_start[qm_start.index('\t/* Stock aal_l3_te_init'):])
# These publication/removal boundaries are not replaced by a test-only API.
probe = function(source, 'rtl_probe')
assert probe.index('rtl_ni_owner_claim(') < probe.index('devm_platform_ioremap_resource(')
assert 'rtl_ni_release_dma(priv, dev)' in probe
assert '.suppress_bind_attrs = true' in source
for attribute in ('qm_es', 'qm_buffer', 'qm_wait'):
    assert attribute + '_store(' not in source
    assert 'DEVICE_ATTR_RO(' + attribute + ');' in source
for field in ('base_ready', 'dma_exposed', 'engine_poisoned', 'host_active', 'reboot_required'):
    assert field + '=%u' in function(source, 'xram_state_show')
config = (root / 'port/overlay/target/linux/rtl9617c/patches-6.18/221-native-l2-switchdev-config.patch').read_text()
assert '+\tbool "RTL9617C management XRAM Ethernet"' in config

common = r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
typedef uint32_t u32;
typedef uint64_t resource_size_t;
typedef int netdev_tx_t;
#define __iomem
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,y) ((x)=(y))
#define unlikely(x) (x)
#define GFP_KERNEL 0
#define ERR_PTR(x) ((void *)(intptr_t)(x))
#define PTR_ERR(x) ((int)(intptr_t)(x))
#define IS_ERR(x) ((uintptr_t)(x) >= (uintptr_t)-4095)
#define PORT_STRIDE 0x90
#define GLB_STATIC 0xa01c
#define PORT_TO_CPU 0xf
#define RX_ADDR 0xaa20
#define TX_ADDR 0xaa24
#define XRAM_CFG 0xaa28
#define RX_PROMISC (3U<<14)
#define CPU_DISABLE 0x201
#define RTL_XRAM_RX_END 512
#define RTL_XRAM_TX_END 1024
#define RTL_XRAM_TX_START 512
#define HRTIMER_MODE_REL 0
#define CTRL 0
#define CTRL_ENABLE BIT(0)
#define CTRL_RESET BIT(8)
#define VP_BASE 0x100
#define VP_STRIDE 0xa0
#define VP_ENABLE 0
#define CB_CTRL 0x950c
#define ES_CTRL 0x6108
#define RMU_CTRL 0x6104
#define NETDEV_TX_OK 0
struct list_head {struct list_head *next,*prev;};
#define container_of(ptr,type,member) ((type *)((char *)(ptr)-offsetof(type,member)))
#define LIST_HEAD(name) struct list_head name={&name,&name}
#define list_for_each_entry(p,head,member) \
 for(p=container_of((head)->next,__typeof__(*p),member);&p->member!=(head); \
 p=container_of(p->member.next,__typeof__(*p),member))
static void list_add_tail(struct list_head *entry,struct list_head *head) {
 entry->prev=head->prev;entry->next=head;head->prev->next=entry;head->prev=entry;
}
static void list_del(struct list_head *entry) {entry->prev->next=entry->next;entry->next->prev=entry->prev;}
#define DEFINE_MUTEX(name) pthread_mutex_t name=PTHREAD_MUTEX_INITIALIZER
static void mutex_lock(pthread_mutex_t *p){assert(!pthread_mutex_lock(p));}
static void mutex_unlock(pthread_mutex_t *p){assert(!pthread_mutex_unlock(p));}
static void *kzalloc(size_t n,int flags){(void)flags;return calloc(1,n);}
#define kfree free
struct device {unsigned refs;int kobj;void *data;};
struct resource {resource_size_t start,end;};
static struct device *get_device(struct device *dev){dev->refs++;return dev;}
static void put_device(struct device *dev){assert(dev->refs);dev->refs--;}
struct rtl_ni_owner {struct list_head list;resource_size_t start,end;struct device *device;bool exposed;};
static LIST_HEAD(rtl_ni_owners);
static DEFINE_MUTEX(rtl_ni_owners_lock);
struct net_device {void *priv;struct {unsigned tx_dropped;} stats;};
struct platform_device {struct device dev;};
struct rtl_fe {bool ready,active;};
struct rtl_dma_tx {
 unsigned char *registers;unsigned vp;
 void *memory;struct net_device *owners[64];
 unsigned read,write,prefetched;bool active;
};
struct rtl_qm_rx {
 void *memory,*pon;struct rtl_fe *fe;
 unsigned read,refill,bids,deepq;bool active,deepq_configured;
};
struct napi_struct {bool active;};
struct rtl_xram {
 struct net_device *netdev,*ports[5];struct rtl_fe *fe;
 struct rtl_ni_owner *owner;unsigned char *ni;
 struct rtl_dma_tx dma;struct rtl_qm_rx qm;struct napi_struct napi;
 unsigned int port,engine_users;
 bool dma_tx,qm_rx,base_ready,dma_exposed,engine_poisoned,host_active,removing;
 bool pon_gate_valid;u32 pon_gate_requested;
 bool tx_pending,rx_active,native_groups_created,irq_requested;
 int tx_lock,rx_lock,timer,rx_irq,lan4_ready,lan4_phy,lan4_work,mib_work;
};
struct sk_buff {unsigned freed;};
struct rtl9617c_ni_frame {int unused;};
static struct rtl_xram *active_priv;
static int fail_suspend,fail_resume,fail_dma,fail_qm;
static bool request_zero_in_qm;
static bool fe_release_success=true,irq_off,rtnl,removed;
static unsigned suspends,resumes,writes,dma_starts,qm_starts,dma_quiesces,qm_stops;
static unsigned qm_frees,dma_frees,netdev_frees,irq_frees,fe_frees,napi_deletes;
static unsigned schedules,waits,warnings,tx_frames,graces;
static void lock(int *p){assert(!*p);*p=1;}
static void unlock(int *p){assert(*p);*p=0;}
#define spin_lock_irqsave(p,f) do{(f)=irq_off;irq_off=true;lock(p);}while(0)
#define spin_unlock_irqrestore(p,f) do{unlock(p);irq_off=(f);}while(0)
#define WARN_ON_ONCE(x) ((x)?(warnings++,1):0)
static u32 readl(void *reg){return *(u32 *)reg;}
static void writel(u32 val,void *reg){
 if(active_priv && (reg==active_priv->ni+ES_CTRL || reg==active_priv->ni+RMU_CTRL) && (val&BIT(31)))
  assert(!(readl(active_priv->ni+0x610c)&0xffff));
 *(u32 *)reg=val;writes++;
}
static void rtl_update(struct rtl_xram *p,unsigned reg,u32 mask,u32 value){
 if(reg==0x6110){
  assert(p->rx_lock && irq_off);
  if(value)assert(p->napi.active && p->fe->ready);
 }
 writel((readl(p->ni+reg)&~mask)|value,p->ni+reg);
}
static void rtl_mac_address(struct rtl_xram *p){assert(p==active_priv);}
static void rtl_rx_mode(struct net_device *d){assert(d==active_priv->netdev);}
static void udelay(unsigned u){assert(u==100);}
static int rtl_fe_engine_suspend(struct rtl_fe *fe){
 assert(!irq_off);suspends++;fe->ready=false;
 if(fail_suspend)return -ETIMEDOUT;fe->active=false;return 0;
}
static int rtl_fe_engine_resume(struct rtl_fe *fe){
 assert(!irq_off && !fe->ready && !active_priv->napi.active);
 assert(active_priv->base_ready);resumes++;
 if(fail_resume)return -EIO;fe->ready=fe->active=true;return 0;
}
static int rtl_dma_tx_start(struct rtl_dma_tx *dma){
 assert(!active_priv->fe->ready && active_priv->dma_exposed && active_priv->owner->exposed);
 dma_starts++;dma->active=true;
 dma->read=3;dma->write=7;dma->prefetched=2;
 if(fail_dma)return -ENOSPC;return 0;
}
static int rtl_qm_start_admission_tail(struct rtl_qm_rx *qm,void *ni);
u32 rtl9617c_ni_pon_gate(struct device *dev,u32 enabled);
static int rtl_qm_rx_start(struct rtl_qm_rx *qm,unsigned port){
 (void)port;assert(!active_priv->fe->ready && active_priv->dma_exposed);
 qm_starts++;qm->active=true;qm->read=24;qm->refill=5;qm->bids=511;qm->deepq=14;
 if(fail_qm)return -ENOBUFS;
 if(request_zero_in_qm){
  struct device parent={.data=active_priv->netdev};
  rtl9617c_ni_pon_gate(&parent,0);
 }
 /* The external SDK declares ES_CTRL1 reset=ffff; do not assume TQM
  * reset preserved the NI-side close even if this model does not reset it. */
 writel(readl(active_priv->ni+0x610c)|0xffffU,active_priv->ni+0x610c);
 int ret=rtl_qm_start_admission_tail(qm,active_priv->ni);
 assert(!(readl(active_priv->ni+0x610c)&0xffff));return ret;
}
static void rtl_qm_rx_stop(struct rtl_qm_rx *qm){
 assert(!active_priv->napi.active);qm_stops++;qm->active=false;
}
static void napi_enable(struct napi_struct *n){assert(!n->active && active_priv->fe->ready);n->active=true;}
static void napi_disable(struct napi_struct *n){assert(n->active && !active_priv->host_active);n->active=false;}
static void napi_schedule(struct napi_struct *n){assert(n->active);schedules++;}
static void synchronize_irq(int n){(void)n;assert(!irq_off && !active_priv->rx_active);}
static void synchronize_net(void){assert(!irq_off && !active_priv->napi.active);graces++;}
static int ms_to_ktime(int n){return n;}
static void hrtimer_start(int *timer,int time,int mode){
 assert(time==1 && mode==HRTIMER_MODE_REL && active_priv->napi.active && active_priv->host_active);*timer=1;
}
static void hrtimer_cancel(int *timer){assert(!active_priv->host_active);*timer=0;}
static void wait_for_completion(int *p){(void)p;waits++;}
#define netdev_err(dev,fmt,...) do{(void)(dev);warnings++;}while(0)
#define dev_err(dev,fmt,...) do{(void)(dev);warnings++;}while(0)
static bool rtl_fe_free(struct rtl_fe *fe){
 (void)fe;assert(!active_priv->napi.active && !active_priv->host_active);fe_frees++;
 return fe_release_success;
}
static void rtl_qm_rx_free(struct device *dev,struct rtl_qm_rx *qm){
 (void)dev;(void)qm;assert(!active_priv->dma_exposed && fe_release_success);qm_frees++;
}
static void rtl_dma_tx_free(struct device *dev,struct rtl_dma_tx *dma){
 (void)dev;(void)dma;assert(!active_priv->dma_exposed && fe_release_success);dma_frees++;
}
static void *dev_get_drvdata(struct device *dev){return dev->data;}
static struct net_device *platform_get_drvdata(struct platform_device *p){return p->dev.data;}
static void platform_set_drvdata(struct platform_device *p,void *data){p->dev.data=data;}
static void *netdev_priv(struct net_device *dev){return dev->priv;}
static void flush_work(int *work){(void)work;}
static void cancel_delayed_work_sync(int *work){(void)work;}
static const int rtl_native_groups[1];
static void sysfs_remove_groups(int *kobj,const int *groups){(void)kobj;(void)groups;}
static void rtl_unregister_lan(struct rtl_xram *p,unsigned port){
 assert(p->removing);p->ports[port]=NULL;
}
static void rtnl_lock(void){assert(!rtnl);rtnl=true;}
static void rtnl_unlock(void){assert(rtnl);rtnl=false;}
#define rcu_assign_pointer(p,v) ((p)=(v))
static void free_irq(int irq,struct rtl_xram *p){
 (void)irq;assert(!p->napi.active && !p->timer && !p->host_active);irq_frees++;
}
static void netif_napi_del(struct napi_struct *n){assert(!n->active);napi_deletes++;}
static void free_netdev(struct net_device *d){assert(!active_priv->dma_exposed && fe_release_success);(void)d;netdev_frees++;}
static void dev_kfree_skb_any(struct sk_buff *skb){skb->freed++;}
static netdev_tx_t rtl_dma_tx_frame(struct rtl_dma_tx *dma,struct sk_buff *skb,
 struct net_device *netdev,const struct rtl9617c_ni_frame *frame){
 (void)dma;(void)skb;(void)netdev;(void)frame;
 assert(active_priv->host_active && !active_priv->engine_poisoned && !active_priv->removing);
 tx_frames++;return NETDEV_TX_OK;
}
'''

main = r'''
static unsigned cases;
static struct device device={.refs=1};
static resource_size_t next_address=0x100000;
static struct rtl_ni_owner *claim(void){
 struct resource resource={next_address,next_address+0xffff};next_address+=0x20000;
 struct rtl_ni_owner *owner=rtl_ni_owner_claim(&device,&resource);assert(!IS_ERR(owner));return owner;
}
static void reset_counts(void){
 suspends=resumes=writes=dma_starts=qm_starts=dma_quiesces=qm_stops=0;
 qm_frees=dma_frees=netdev_frees=irq_frees=fe_frees=napi_deletes=0;
 schedules=waits=warnings=tx_frames=graces=0;
 fail_suspend=fail_resume=fail_dma=fail_qm=0;fe_release_success=true;request_zero_in_qm=false;
 irq_off=rtnl=removed=false;
}
static void assert_tokens(struct rtl_xram *p){
 if(p->dma_tx)assert(p->dma.read==13 && p->dma.write==19 && p->dma.prefetched==2);
 if(p->qm_rx)assert(p->qm.read==88 && p->qm.refill==9 && p->qm.bids==499 && p->qm.deepq==23);
}
int main(void){
 u32 registers[0x10000/4],dma_registers[0x2000/4];
 struct net_device dev={0};struct rtl_fe fe;
 for(unsigned mode=0;mode<4;mode++){
  struct rtl_xram p={.netdev=&dev,.fe=&fe,.owner=claim(),.ni=(void *)registers,
   .dma_tx=!!(mode&1),.qm_rx=!!(mode&2),.ports={&dev,NULL,&dev,NULL,&dev},
   .dma={.registers=(void *)dma_registers,.vp=8,.memory=&dev},.qm={.memory=&dev}};
  dev.priv=&p;active_priv=&p;memset(registers,0x5a,sizeof(registers));
  memset(dma_registers,0,sizeof(dma_registers));memset(&fe,0,sizeof(fe));reset_counts();
  assert(!rtl_engine_get(&p));assert(p.base_ready && p.host_active && p.engine_users==1);
  assert(dma_starts==p.dma_tx && qm_starts==p.qm_rx && schedules==1);
  assert(p.dma_exposed==(p.dma_tx||p.qm_rx));
  p.dma.read=13;p.dma.write=19;p.dma.prefetched=2;
  p.qm.read=88;p.qm.refill=9;p.qm.bids=499;p.qm.deepq=23;
  for(unsigned cycle=0;cycle<25;cycle++){
   assert(!rtl_engine_get(&p) && p.engine_users==2);rtl_engine_put(&p);
   assert(p.engine_users==1 && p.host_active);
   rtl_engine_put(&p);assert(!p.host_active && !p.napi.active && !p.timer && !p.engine_users);
   assert(p.base_ready && !qm_stops && !(readl(dma_registers)&CTRL_RESET));
   assert_tokens(&p);
   unsigned old_writes=writes;
   assert(!rtl_engine_get(&p));
   assert(writes-old_writes==(p.qm_rx?2:0)); /* PON mask and host IRQ, never setup. */
   assert(dma_starts==p.dma_tx && qm_starts==p.qm_rx);assert_tokens(&p);cases++;
  }
  rtl_engine_put(&p);rtl_ni_owner_release(p.owner);
 }
 /* Every failed cold stage keeps partial DMA exposure and prohibits retry.
  * A pre-exposure FE veto remains retryable without touching shared state. */
 for(unsigned mode=0;mode<4;mode++)for(unsigned failure=1;failure<5;failure++){
  struct rtl_xram p={.netdev=&dev,.fe=&fe,.owner=claim(),.ni=(void *)registers,
   .dma_tx=!!(mode&1),.qm_rx=!!(mode&2),
   .dma={.registers=(void *)dma_registers,.vp=8},.qm={0}};
  dev.priv=&p;active_priv=&p;memset(&fe,0,sizeof(fe));reset_counts();
  fail_suspend=failure==1;fail_dma=failure==2;fail_qm=failure==3;fail_resume=failure==4;
  int expected=fail_suspend?-ETIMEDOUT:(fail_dma&&p.dma_tx)?-ENOSPC:
   (fail_qm&&p.qm_rx)?-ENOBUFS:fail_resume?-EIO:0;
  assert(rtl_engine_get(&p)==expected);
  if(expected){
   assert(!p.host_active && !p.napi.active && !p.timer && !p.engine_users);
   if(fail_suspend){assert(!p.dma_exposed && !p.engine_poisoned && !writes);}
   else if(fail_resume){
    assert(p.base_ready && !p.engine_poisoned && !qm_stops);
    if(p.qm_rx)assert(!(readl(p.ni+0x610c)&0xffff));
    unsigned old_dma=dma_starts,old_qm=qm_starts;
    fail_resume=0;assert(!rtl_engine_get(&p));
    assert(dma_starts==old_dma && qm_starts==old_qm);rtl_engine_put(&p);
   }
   else{
    assert(p.engine_poisoned);unsigned old_writes=writes;
    assert(rtl_engine_get(&p)==-EIO && writes==old_writes);
    if(p.qm_rx)assert(qm_stops==1);
    if(p.dma_tx){assert(!(readl(dma_registers)&(CTRL_RESET|CTRL_ENABLE)));}
   }
  }else rtl_engine_put(&p);
  rtl_ni_owner_release(p.owner);cases++;
 }
 /* An explicit zero request before, or during, sleeping cold initialization
  * must survive QM's actual final MMIO writes and final host publication. */
 for(unsigned when=0;when<2;when++){
  struct rtl_xram p={.netdev=&dev,.fe=&fe,.owner=claim(),.ni=(void *)registers,
   .dma_tx=true,.qm_rx=true,.dma={.registers=(void *)dma_registers,.vp=8}};
  dev.priv=&p;active_priv=&p;reset_counts();memset(&fe,0,sizeof(fe));
  if(when)request_zero_in_qm=true;
  else {p.pon_gate_valid=true;p.pon_gate_requested=0;}
  writel(0xa5a5ffff,p.ni+0x610c);
  assert(!rtl_engine_get(&p));
  assert(p.host_active && p.pon_gate_valid && !p.pon_gate_requested);
  assert(readl(p.ni+0x610c)==0xa5a50000);rtl_engine_put(&p);cases++;
 }
 /* A temporary FE cleanup failure does not poison/reset the NI queue.
  * Retry is gated on FE's next suspend; partial FE bases reject there. */
 {
  struct rtl_xram p={.netdev=&dev,.fe=&fe,.owner=claim(),.ni=(void *)registers,
   .dma_tx=true,.qm_rx=true,.dma={.registers=(void *)dma_registers,.vp=8}};
  active_priv=&p;reset_counts();memset(&fe,0,sizeof(fe));assert(!rtl_engine_get(&p));
  fail_suspend=1;rtl_engine_put(&p);assert(!p.engine_poisoned && !p.host_active && !p.napi.active);
  assert(p.base_ready && p.dma_exposed && !qm_stops);
  unsigned old_writes=writes;
  assert(rtl_engine_get(&p)==-ETIMEDOUT && writes==old_writes && !qm_frees && !dma_frees);
  fail_suspend=0;assert(!rtl_engine_get(&p));assert(dma_starts==1 && qm_starts==1);
  rtl_engine_put(&p);cases++;
 }
 /* Execute actual remove. Unexposed/no callbacks frees; DMA or FE reference
  * quarantine keeps primary owner, storage and physical reprobe tombstone. */
 for(unsigned exposed=0;exposed<2;exposed++)for(unsigned retained_fe=0;retained_fe<2;retained_fe++){
  struct platform_device platform={.dev={.refs=1,.data=&dev}};
  struct rtl_xram p={.netdev=&dev,.fe=&fe,.owner=claim(),.ni=(void *)registers,
   .dma_tx=true,.qm_rx=true,.irq_requested=true,.native_groups_created=true,.lan4_phy=1,
   .dma={.registers=(void *)dma_registers,.vp=8,.memory=&dev},.qm={.memory=&dev,.pon=&dev}};
  dev.priv=&p;active_priv=&p;reset_counts();memset(&fe,0,sizeof(fe));
  p.dma_exposed=exposed;fe_release_success=!retained_fe;
  struct resource resource={p.owner->start,p.owner->end};
  if(exposed)rtl_ni_owner_expose(p.owner);
  p.dma.owners[3]=&dev;p.dma.owners[53]=&dev;
  rtl_remove(&platform);
  assert(!platform.dev.data && !p.qm.pon && p.removing && p.engine_poisoned);
  for(unsigned i=0;i<64;i++)assert(!p.dma.owners[i]);
  assert(irq_frees==1 && napi_deletes==1 && fe_frees==1);
  if(exposed||retained_fe){
   assert(!netdev_frees && !qm_frees && !dma_frees && p.owner->exposed);
   assert(PTR_ERR(rtl_ni_owner_claim(&device,&resource))==-EBUSY);
  }else{
   assert(netdev_frees==1 && qm_frees==1 && dma_frees==1);
   struct rtl_ni_owner *again=rtl_ni_owner_claim(&device,&resource);
   assert(!IS_ERR(again));rtl_ni_owner_release(again);
  }
  cases++;
 }
 /* Same/overlapping physical apertures are rejected, adjacent ones work. */
 {
  struct rtl_ni_owner *a=claim();struct resource r={a->start+8,a->end+8};
  assert(PTR_ERR(rtl_ni_owner_claim(&device,&r))==-EBUSY);
  r.start=a->end+1;r.end+=0xffff;
  struct rtl_ni_owner *b=rtl_ni_owner_claim(&device,&r);assert(!IS_ERR(b));
  rtl_ni_owner_release(b);rtl_ni_owner_release(a);cases++;
 }
 {
  struct rtl_ni_owner *a=claim();struct resource r={a->start,a->end};
  rtl_ni_owner_expose(a);rtl_ni_owner_release(a);
  assert(PTR_ERR(rtl_ni_owner_claim(&device,&r))==-EBUSY);cases++;
 }
 /* Actual exported TX path rejects stopped/removed/poisoned owners. */
 for(unsigned mask=0;mask<8;mask++){
  struct device parent={.data=&dev};
  struct rtl_xram p={.host_active=!!(mask&1),.removing=!!(mask&2),.engine_poisoned=!!(mask&4)};
  struct sk_buff skb={0};dev.priv=&p;active_priv=&p;reset_counts();
  assert(rtl9617c_ni_transmit(&parent,&dev,&skb,NULL)==NETDEV_TX_OK);
  assert(tx_frames==(mask==1) && skb.freed==(mask!=1));cases++;
 }
 /* PON's saved-gate recovery may run independently of RTNL; a poisoned or
  * removing NI must serialize and reject reopening its shared low16 gate. */
 for(unsigned mask=0;mask<8;mask++){
  struct device parent={.data=&dev};
  struct rtl_xram p={.ni=(void *)registers,.removing=!!(mask&1),.engine_poisoned=!!(mask&2),.host_active=!!(mask&4),.qm_rx=true};
  dev.priv=&p;active_priv=&p;reset_counts();writel(0xa5a51234,p.ni+0x610c);
  assert(rtl9617c_ni_pon_gate(&parent,0xffff)==0x1234);
  assert(readl(p.ni+0x610c)==(mask==4?0xa5a5ffffU:0xa5a50000U));
  assert(p.pon_gate_valid && p.pon_gate_requested==0xffff);
  assert(rtl9617c_ni_pon_gate(&parent,0x4321)==0xffff);
  assert(readl(p.ni+0x610c)==(mask==4?0xa5a54321U:0xa5a50000U));
  unsigned long flags;spin_lock_irqsave(&p.tx_lock,flags);
  rtl_pon_host_gate(&p,true);spin_unlock_irqrestore(&p.tx_lock,flags);
  assert(readl(p.ni+0x610c)==(mask==4?0xa5a54321U:0xa5a50000U));cases++;
 }
 /* Free only fixture allocations at simulated reboot; production release
  * deliberately cannot remove an exposed tombstone. */
 while(rtl_ni_owners.next!=&rtl_ni_owners){
  struct rtl_ni_owner *owner=container_of(rtl_ni_owners.next,struct rtl_ni_owner,list);
  list_del(&owner->list);put_device(owner->device);free(owner);
 }
 assert(device.refs==1);
 printf("NI device lifetime: %u cases passed; warm queues retained, partial init quarantined, removal/reprobe/TX closed\n",cases);
}
'''

# The production DMA quiesce implementation must not include reset or memset.
assert 'CTRL_RESET' not in function(dma_source, 'rtl_dma_tx_quiesce')
assert 'memset' not in function(dma_source, 'rtl_dma_tx_quiesce')
text = common + '\n' + dma_functions + '\n' + qm_tail + '\n' + functions + '\n' + main
variants = [('production', text, True)]
if args.mutants:
    variants.extend([
        ('warm_reinitialize', text.replace('if (!priv->base_ready) {', 'if (true) {', 1), False),
        ('free_exposed', text.replace('if (priv->dma_exposed || !fe_released) {', 'if (false) {', 1), False),
        ('retry_partial', text.replace('WRITE_ONCE(priv->engine_poisoned, true);', '(void)priv;', 1), False),
        ('clear_tombstone', text.replace('if (!owner || READ_ONCE(owner->exposed))', 'if (!owner)', 1), False),
        ('cold_gate_override', text.replace('rx->deepq_configured = true;',
            'writel(readl(ni+0x610c)|0xffffU,ni+0x610c); rx->deepq_configured = true;', 1), False),
        ('ignore_reset_gate', text.replace('writel(readl(ni + 0x610c) & ~0xffffU, ni + 0x610c);',
            '(void)ni;', 1), False),
    ])
with tempfile.TemporaryDirectory(prefix='ni-owner-lifetime-') as directory:
    directory = Path(directory)
    for name, unit, expected in variants:
        cfile, binary = directory / (name + '.c'), directory / name
        cfile.write_text(unit)
        subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                        '-Wno-misleading-indentation', '-O1', '-g', '-pthread',
                        '-fsanitize=address,undefined', str(cfile), '-o', str(binary)], check=True)
        run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
        if expected:
            print(run.stdout + run.stderr, end='')
            if run.returncode:
                raise SystemExit(1)
        else:
            assert run.returncode != 0 and 'Assertion' in run.stderr, (
                name + ' was not rejected by a contract assertion: ' + run.stderr)
            print(name + ': detected by runtime oracle')
(root / 'logs').mkdir(exist_ok=True)
(root / 'logs/ni-owner-lifetime-test.json').write_text(json.dumps({
    'production_functions': list(names),
    'source_sha256': hashlib.sha256((functions + dma_functions + qm_tail).encode()).hexdigest(),
    'warm_cycles_per_mode': 25, 'modes': 4, 'runtime_mutants': len(variants) - 1,
    'physical_overlap_claims': True, 'retain_exposed_dma_on_remove': True,
    'fe_callback_only_quarantine': True, 'retained_queue_tokens': ['EPP', 'refill', 'BID', 'deepQ', 'TX', 'prefetch'],
    'hardware_access': False, 'hardware_drain_proven': False,
}, indent=2) + '\n')
