#!/usr/bin/env python3
"""Execute NI-local cold bootstrap through first LAN open without a PON driver.

Actual PON fence, fabric transaction, FE adapter, temporary MMIO lease, probe
tail and NI start/open code execute together. Resource allocation, QM/DMA
initialization and kernel services remain instrumented boundaries. This is
not ASIC timing emulation and does not prove a board boot.
"""
import argparse
import os
from pathlib import Path
import re
import resource
import runpy
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVERS = ROOT / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
source = (DRIVERS / 'rtl9617c-xram.c').read_text()
fe_source = (DRIVERS / 'rtl9617c-fe.c').read_text()
pon_source = (DRIVERS / 'rtl9617c-pon.c').read_text()
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


def production_sources(name, seen=None):
    seen = set() if seen is None else seen
    if name in seen:
        return ''
    seen.add(name)
    text = (ROOT / 'port/overlay/target/linux/rtl9617c/dts' / name).read_text()
    return text + '\n' + ''.join(production_sources(child, seen)
        for child in re.findall(r'^#include "([^"]+)"', text, re.M))


for name in ('rtl9617c-tyfza1-ubi.dts', 'rtl9617c-tyfza1-ubi-2p5g.dts'):
    tree = production_sources(name)
    assert re.search(r'^\s*realtek,cold-fabric-bootstrap\s*;', tree, re.M), name
    for resource_name in ('pon-cold-mac', 'pon-cold-control', 'pon-cold-epon', 'pon-cold-gpon'):
        assert '"' + resource_name + '"' in tree, (name, resource_name)

probe = function(source, 'rtl_probe')
assert '"realtek,cold-fabric-bootstrap"' in probe
assert '"realtek,pon-cold-handoff"' in probe  # Legacy DT compatibility is local.
assert probe.index('mutex_init(&priv->fabric_lock)') < probe.index('rtl_ni_cold_bootstrap(priv, pdev)')
assert probe.index('rtl_ni_cold_bootstrap(priv, pdev)') < probe.index('platform_set_drvdata(pdev, netdev)')
assert probe.index('platform_set_drvdata(pdev, netdev)') < probe.index('rtl_ni_publish(priv, dev)')
probe_tail = probe[probe.index('\tret = rtl_ni_cold_bootstrap(priv, pdev);'):probe.index('\nfree_dma:')]
assert 'rtl9617c_ni_cold_handoff' not in source
assert 'rtl_pon_cold_handoff' not in pon_source
assert 'rtl_pon_cold_quiesce' not in pon_source
assert 'cold_handoff_required' not in function(source, 'rtl_engine_get')
registration = function(source, 'rtl_register_lans')
registration_tail = registration[registration.index('\tif (!priv->lan4_phy)'):registration.rindex('\n}')]
assert registration_tail.index('WRITE_ONCE(priv->provider_ready, true)') < registration_tail.index('rtnl_unlock()')
assert 'WRITE_ONCE(priv->provider_ready, true)' not in function(source, 'rtl_ni_publish')
cached_show = function(source, 'cold_bootstrap_show')
assert set(re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', cached_show)) <= {
    'cold_bootstrap_show', 'netdev_priv', 'dev_get_drvdata', 'sysfs_emit', 'READ_ONCE'}
assert 'DEVICE_ATTR_RO(cold_bootstrap)' in source

# Reuse independent MMIO/fault behavior, not its algorithm or main loop.
model = runpy.run_path(str(ROOT / 'scripts/test_fabric_baseline.py'))['TEST'].split('int main(void) {', 1)[0]
model = model.replace('{ if(low==1000 && high==2000)settles++;',
                      '{ if(low==100 && high==200)return; if(low==1000 && high==2000)settles++;', 1)
assert 'if(low==100 && high==200)return;' in model

common = r'''
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <sys/types.h>
#include "rtl9617c-pon-cold.h"
typedef uint32_t u32;
typedef uint64_t resource_size_t;
#define __iomem
#define EPROBE_DEFER 517
#define HZ 100
#define IORESOURCE_MEM 0
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,y) ((x)=(y))
#define WARN_ON_ONCE(x) (!!(x))
#define PORT_STRIDE 0x90
#define PORT_STATIC 0xa5c0
#define PORT_RX 0xa5c8
#define PORT_TX 0xa5d4
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
struct mutex {pthread_mutex_t native;};
struct device {void *data;int kobj;};
struct device_attribute {int unused;};
struct platform_device {struct device dev;};
struct resource {resource_size_t start,end;};
struct rtl_xram;
struct rtl_lan {struct rtl_xram *shared;unsigned int port;};
struct net_device {void *priv;unsigned char dev_addr[6];void *phydev;};
struct rtl_fe {
 struct mutex lock;struct rtl_fabric fabric;
 bool engine_ready,prepared,dma_exposed,shutting_down;
};
struct rtl_ni_owner {bool exposed;};
struct rtl_dma_tx {void *owners[64];bool active;};
struct rtl_qm_rx {void *pon;bool active;};
struct napi_struct {bool active;};
struct rtl_xram {
 struct rtl_lan lan;
 unsigned long long tm_owner_generation;
 struct mutex fabric_lock;
 bool cold_handoff_required,cold_attempted,provider_ready,fabric_managed;
 bool removing,engine_poisoned,native_groups_created,irq_requested;
 bool dma_tx,qm_rx,base_ready,dma_exposed,host_active,rx_active,tx_pending,pon_gate_valid;
 u32 pon_gate_requested;
 int fabric_error,mib_work,lan4_ready,lan4_phy,lan4_work,tx_lock,rx_lock,rx_irq,timer;
 unsigned int engine_users,port;
 unsigned char *ni;
 struct net_device *netdev,*ports[5];struct rtl_fe *fe;struct rtl_ni_owner *owner;
 struct rtl_pon_cold_state pon_cold;
 struct rtl_qm_rx qm;struct rtl_dma_tx dma;struct napi_struct napi;
};
static struct rtl_xram *current;
static struct platform_device platform;
static struct rtl_fe fe;
static struct net_device netdev;
static struct rtl_ni_owner owner;
static struct resource resources[4];
static unsigned int pon_mac[0xc000/4],pon_global[3];
static bool claimed[4],mapped[4];
static int map_fault,map_fault_index,sysfs_result;
static bool stuck_pon_gate,stuck_fifo,post_fabric_drift;
static unsigned int map_calls,unmap_calls,pon_reads,pon_writes;
static unsigned int registrations,sysfs_calls,mib_calls,exposes,opens,dma_starts,qm_starts;
static pthread_mutex_t gate=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed=PTHREAD_COND_INITIALIZER;
static _Thread_local unsigned int held,role;
static bool block_baseline,baseline_entered,allow_baseline,second_attempted;
static bool rtnl;
static void mutex_lock(struct mutex *lock){
 assert(!pthread_mutex_lock(&gate));
 if(role==2)second_attempted=true;
 assert(!pthread_cond_broadcast(&changed));assert(!pthread_mutex_unlock(&gate));
 assert(!pthread_mutex_lock(&lock->native));held++;
}
static void mutex_unlock(struct mutex *lock){assert(held);held--;assert(!pthread_mutex_unlock(&lock->native));}
static struct rtl_dq_io fe_io(struct rtl_fe *unused){
 (void)unused;assert(held && current && !current->provider_ready);
 assert(!registrations && !sysfs_calls && !mib_calls && !platform.dev.data);
 assert(!pthread_mutex_lock(&gate));baseline_entered=true;assert(!pthread_cond_broadcast(&changed));
 while(block_baseline && !allow_baseline)assert(!pthread_cond_wait(&changed,&gate));
 assert(!pthread_mutex_unlock(&gate));return io;
}
static void rtl_ni_owner_expose(struct rtl_ni_owner *item){item->exposed=true;exposes++;}
#define dev_warn(d,...) ((void)(d))
#define dev_info(d,...) ((void)(d))
#define dev_err(d,...) ((void)(d))
#define netdev_err(d,...) ((void)(d))
static void *netdev_priv(struct net_device *dev){return dev->priv;}
static void *dev_get_drvdata(struct device *dev){return dev->data;}
static int sysfs_emit(char *buffer,const char *format,...){
 va_list args;va_start(args,format);int result=vsnprintf(buffer,4096,format,args);va_end(args);return result;
}
static unsigned int resource_index(resource_size_t start){
 for(unsigned int i=0;i<4;i++)if(resources[i].start==start)return i;
 assert(false);return 0;
}
static resource_size_t resource_size(const struct resource *res){return res->end-res->start+1;}
static const struct resource *platform_get_resource_byname(struct platform_device *pdev,int type,const char *name){
 static const char * const names[]={"pon-cold-mac","pon-cold-control","pon-cold-epon","pon-cold-gpon"};
 assert(pdev==&platform && type==IORESOURCE_MEM && !pdev->dev.data && !current->provider_ready);
 for(unsigned int i=0;i<4;i++)if(!strcmp(name,names[i])){
  if(map_fault==1 && (int)i==map_fault_index)return NULL;
  return &resources[i];
 }
 assert(false);return NULL;
}
static void *request_mem_region(resource_size_t start,resource_size_t size,const char *name){
 unsigned int i=resource_index(start);assert(!claimed[i] && size==resource_size(&resources[i]));
 assert(!strcmp(name,"rtl9617c-cold-fabric"));map_calls++;
 if(map_fault==3 && (int)i==map_fault_index)return NULL;
 claimed[i]=true;return &resources[i];
}
static void *ioremap(resource_size_t start,resource_size_t size){
 unsigned int i=resource_index(start);assert(claimed[i] && !mapped[i] && size==resource_size(&resources[i]));
 if(map_fault==4 && (int)i==map_fault_index)return NULL;
 mapped[i]=true;return i?(void *)&pon_global[i-1]:(void *)pon_mac;
}
static void iounmap(void *base){
 for(unsigned int i=0;i<4;i++)if(base==(i?(void *)&pon_global[i-1]:(void *)pon_mac)){
  assert(mapped[i] && claimed[i]);mapped[i]=false;unmap_calls++;return;
 }
 assert(false);
}
static void release_mem_region(resource_size_t start,resource_size_t size){
 unsigned int i=resource_index(start);assert(claimed[i] && !mapped[i] && size==resource_size(&resources[i]));
 claimed[i]=false;
}
static bool leases_empty(void){
 for(unsigned int i=0;i<4;i++)if(claimed[i] || mapped[i])return false;
 return true;
}
static u32 readl(void *address){
 uintptr_t at=(uintptr_t)address,ni=(uintptr_t)m.reg,mac=(uintptr_t)pon_mac,global=(uintptr_t)pon_global;
 if(at>=ni && at<ni+sizeof(m.reg))return *(u32 *)address;
 assert(!current->provider_ready && !platform.dev.data);pon_reads++;
 if(at>=global && at<global+sizeof(pon_global)){
  unsigned int i=(at-global)/4;assert(mapped[i+1]);
  if(post_fabric_drift && fe.fabric.ready && i==0)return pon_global[i]^RTL_PON_COLD_EPON_MODE;
  return pon_global[i];
 }
 assert(at>=mac && at<mac+sizeof(pon_mac) && mapped[0]);
 unsigned int offset=at-mac;
 if(offset==RTL_PON_COLD_PDC_FIFO_STATUS && stuck_fifo)return 1;
 return *(u32 *)address;
}
static void writel(u32 value,void *address){
 uintptr_t at=(uintptr_t)address,ni=(uintptr_t)m.reg,mac=(uintptr_t)pon_mac;
 if(at>=ni && at<ni+sizeof(m.reg)){
  unsigned int offset=at-ni;
  /* NI startup may configure queues/open MACs, never redo SVL/MRU. */
  assert(offset!=RTL_L2_VLAN_MODE_CONTROL && offset!=RTL_FABRIC_FRAME_LENGTH && offset!=RTL_FABRIC_STORAGE_LENGTH);
  for(unsigned int i=0;i<5;i++)if(offset==RTL_FABRIC_RX_MAC(i) && (value&RTL_FABRIC_RX_MAC_ENABLE))
   assert(current->host_active && current->base_ready && current->provider_ready);
  *(u32 *)address=value;return;
 }
 assert(!current->provider_ready && !platform.dev.data && mapped[0]);
 assert(at>=mac && at<mac+sizeof(pon_mac));pon_writes++;
 if(stuck_pon_gate)return;
 *(u32 *)address=value;
}
static void rtl_update(struct rtl_xram *priv,unsigned int reg,u32 mask,u32 value){
 writel((readl(priv->ni+reg)&~mask)|value,priv->ni+reg);
}
static void lock(int *p){assert(!*p);*p=1;}
static void unlock(int *p){assert(*p);*p=0;}
#define spin_lock_irqsave(p,f) do{(f)=0;lock(p);}while(0)
#define spin_unlock_irqrestore(p,f) do{(void)(f);unlock(p);}while(0)
static void rtl_mac_address(struct rtl_xram *priv){assert(priv==current);}
static void rtl_rx_mode(struct net_device *dev){assert(dev==current->netdev);}
static void udelay(unsigned int us){assert(us==100);}
static int rtl_fe_engine_suspend(struct rtl_fe *item){
 if(item)item->engine_ready=false;return 0;
}
static int rtl_fe_engine_resume(struct rtl_fe *item){
 assert(current->base_ready && !current->napi.active);
 if(item){
  assert(!item->fabric.poisoned);
  if(item->fabric.ready)assert(!rtl_fabric_check(&io,&item->fabric));
  item->engine_ready=true;
 }
 return 0;
}
static int rtl_dma_tx_start(struct rtl_dma_tx *dma){
 assert(current->provider_ready && current->dma_exposed && owner.exposed && leases_empty());
 if(current->fabric_managed)assert_mac_rx_gated();
 dma->active=true;dma_starts++;return 0;
}
static int rtl_qm_rx_start(struct rtl_qm_rx *qm,unsigned int port){
 assert(port==0 && current->provider_ready && leases_empty());
 if(current->fabric_managed)assert_mac_rx_gated();
 qm->active=true;qm_starts++;return 0;
}
static void rtl_dma_tx_quiesce(struct rtl_dma_tx *dma){dma->active=false;}
static void rtl_qm_rx_stop(struct rtl_qm_rx *qm){qm->active=false;}
static void napi_enable(struct napi_struct *n){assert(!n->active);n->active=true;}
static void napi_disable(struct napi_struct *n){assert(n->active);n->active=false;}
static void napi_schedule(struct napi_struct *n){assert(n->active);}
static void synchronize_irq(int irq){(void)irq;}
static void synchronize_net(void){}
static int ms_to_ktime(int n){return n;}
static void hrtimer_start(int *timer,int time,int mode){assert(time==1 && mode==0);*timer=1;}
static void hrtimer_cancel(int *timer){*timer=0;}
static void wait_for_completion(int *completion){assert(*completion && rtnl);}
static void complete_all(int *completion){*completion=1;}
static void rtnl_lock(void){assert(!rtnl);rtnl=true;}
static void rtnl_unlock(void){
 assert(rtnl && current->provider_ready && current->lan4_ready);rtnl=false;
}
static void phy_start(void *phy){(void)phy;assert(current->host_active);}
static void netif_start_queue(struct net_device *dev){assert(dev==current->netdev);opens++;}
static int rtl_open(struct net_device *dev);
static int rtl_engine_get(struct rtl_xram *priv);
static void platform_set_drvdata(struct platform_device *pdev,void *data){
 assert(current->cold_attempted && leases_empty() && !current->engine_poisoned);
 pdev->dev.data=data;
}
static void rtl_register_lans(struct rtl_xram *priv,struct device *dev){
 assert(dev==&platform.dev && dev->data==priv->netdev && !priv->provider_ready && priv->cold_attempted);
 assert(leases_empty() && !priv->engine_poisoned);registrations++;
 if(priv->fabric_managed){
  assert(rtl_fabric_native_mtu_compatible(&fe.fabric));assert_mac_rx_gated();
  command_restored(&fe.fabric);baseline_preserved(&fe.fabric);
 }
 /* The independent pthread LAN test executes the complete registration
  * path. Here execute its ACTUAL publication tail, including ready/RTNL,
  * and verify an external early NI user defers while work is not queued. */
 rtnl_lock();assert(rtl_engine_get(priv)==-EPROBE_DEFER);
 priv->ports[0]=priv->netdev;priv->lan4_phy=0;
 /* NI_REGISTRATION_TAIL */
 rtnl=true;assert(!rtl_open(priv->netdev));rtnl=false;
 assert(priv->engine_users==1);
}
static const int rtl_native_groups[1];
static int sysfs_create_groups(int *kobj,const int *groups){
 (void)kobj;(void)groups;assert(current->provider_ready && registrations==1);sysfs_calls++;return sysfs_result;
}
static void schedule_delayed_work(int *work,int delay){
 (void)work;assert(delay==HZ && current->provider_ready && registrations==1);mib_calls++;
}
'''
common = common.replace('/* NI_REGISTRATION_TAIL */', registration_tail)

map_struct = re.search(r'struct rtl_ni_cold_maps \{.*?\n\};', source, re.S).group()
functions = '\n'.join(function(fe_source, name) for name in (
    'rtl_fe_fabric_cold_prepare', 'rtl_fe_fabric_cold_abort'))
functions += '\n' + map_struct + '\n' + '\n'.join(function(source, name) for name in (
    'rtl_ni_cold_unmap', 'rtl_ni_cold_map', 'rtl_ni_cold_read', 'rtl_ni_cold_write',
    'rtl_pon_host_gate', 'rtl_engine_poison', 'rtl_engine_prepare', 'rtl_engine_start',
    'rtl_engine_stop', 'rtl_engine_get', 'rtl_engine_put', 'rtl_open',
    'rtl_ni_cold_bootstrap', 'rtl_ni_publish', 'cold_bootstrap_show'))
publication = '''
static int probe_publication_tail(struct platform_device *pdev) {
 struct device *dev=&pdev->dev;
 struct net_device *netdev=current->netdev;
 struct rtl_xram *priv=current;
 int ret;
''' + probe_tail + '\nfree_dma:\n return ret;\n}\n'

main = r'''
static void init(struct rtl_xram *priv,bool required){
 setup(0);memset(priv,0,sizeof(*priv));memset(&fe,0,sizeof(fe));
 assert(!pthread_mutex_init(&priv->fabric_lock.native,NULL));
 assert(!pthread_mutex_init(&fe.lock.native,NULL));
 memset(&platform,0,sizeof(platform));memset(&owner,0,sizeof(owner));
 memset(&netdev,0,sizeof(netdev));memset(pon_mac,0,sizeof(pon_mac));
 memset(claimed,0,sizeof(claimed));memset(mapped,0,sizeof(mapped));
 current=priv;netdev.priv=priv;priv->lan.shared=priv;priv->netdev=&netdev;priv->fe=&fe;priv->owner=&owner;
 priv->ni=(void *)m.reg;priv->cold_handoff_required=required;priv->dma_tx=priv->qm_rx=true;
 resources[0]=(struct resource){0x4f5500000ULL,0x4f550bfffULL};
 resources[1]=(struct resource){0x4f4320094ULL,0x4f4320097ULL};
 resources[2]=(struct resource){0x4f4320074ULL,0x4f4320077ULL};
 resources[3]=(struct resource){0x4f432007cULL,0x4f432007fULL};
 pon_global[0]=RTL_PON_COLD_PDC_RELEASED|RTL_PON_COLD_EPON_MODE;
 pon_global[1]=RTL_PON_COLD_EPON_RELEASED|RTL_PON_COLD_EPON_1G_RELEASED|RTL_PON_COLD_EPON_10G_RELEASED;
 pon_global[2]=0;pon_mac[0x088c/4]=1;pon_mac[0x10b4/4]=1U<<7;
 map_fault=map_fault_index=sysfs_result=0;stuck_pon_gate=stuck_fifo=post_fabric_drift=false;
 map_calls=unmap_calls=pon_reads=pon_writes=registrations=sysfs_calls=mib_calls=exposes=opens=dma_starts=qm_starts=0;
 block_baseline=baseline_entered=allow_baseline=second_attempted=false;rtnl=false;
}
static void done(struct rtl_xram *priv){
 assert(leases_empty() && !held);
 assert(!pthread_mutex_destroy(&priv->fabric_lock.native));assert(!pthread_mutex_destroy(&fe.lock.native));
}
static void normal_lan(struct rtl_xram *priv){
 assert(priv->cold_attempted && priv->provider_ready && !priv->engine_poisoned);
 assert(platform.dev.data==priv->netdev && registrations==1 && opens==1);
 assert(sysfs_calls==1 && mib_calls==1 && priv->base_ready && priv->host_active);
 assert(m.reg[RTL_FABRIC_RX_MAC(0)/4]&RTL_FABRIC_RX_MAC_ENABLE);
 assert(leases_empty());
 unsigned int old_reads=pon_reads,old_writes=pon_writes,old_maps=map_calls,old_fabric=m.writes;
 char cached[4096];assert(cold_bootstrap_show(&platform.dev,NULL,cached)>0);
 assert(strstr(cached,"cached=1 historical=1") && strstr(cached,"attempted=1"));
 assert(pon_reads==old_reads && pon_writes==old_writes && map_calls==old_maps && m.writes==old_fabric);
}
static void no_publication(struct rtl_xram *priv){
 assert(!priv->provider_ready && !platform.dev.data && !registrations && !opens && !sysfs_calls && !mib_calls);
 assert(!dma_starts && !qm_starts && leases_empty());
}
static void *bootstrap_thread(void *context){
 role=(unsigned int)(uintptr_t)context;
 return (void *)(intptr_t)rtl_ni_cold_bootstrap(current,&platform);
}
static void wait_flag(bool *flag){assert(!pthread_mutex_lock(&gate));while(!*flag)assert(!pthread_cond_wait(&changed,&gate));assert(!pthread_mutex_unlock(&gate));}
static void release_flag(bool *flag){assert(!pthread_mutex_lock(&gate));*flag=true;assert(!pthread_cond_broadcast(&changed));assert(!pthread_mutex_unlock(&gate));}
int main(void){
 struct rtl_xram priv;
 /* NO PON device, BOSA, GPIO, IRQ or callback exists in this fixture.
  * Success must come from the real NI probe tail alone. */
 for(unsigned int flavor=0;flavor<3;flavor++){
  init(&priv,true);sysfs_result=flavor==1?-ENOMEM:0;
  if(flavor==2)pon_global[0]=0; /* PDC reset: no speculative MAC/FIFO access. */
  assert(!probe_publication_tail(&platform));normal_lan(&priv);
  assert(priv.fabric_managed && fe.fabric.ready && !fe.fabric.poisoned);
  assert(rtl_fabric_native_mtu_compatible(&fe.fabric));
  assert(m.vlan_writes==1 && m.frame_writes==1 && m.scans==1);
  assert(priv.native_groups_created==(sysfs_result==0));
  assert(pon_writes==(flavor==2?0U:2U));
  unsigned int old_writes=m.writes,old_pon=pon_writes,old_maps=map_calls;
  assert(!rtl_ni_cold_bootstrap(&priv,&platform));
  rtnl=true;rtl_engine_put(&priv);assert(!rtl_open(priv.netdev));rtnl=false;
  assert(m.writes==old_writes && pon_writes==old_pon && map_calls==old_maps);
  assert(dma_starts==1 && qm_starts==1 && priv.fabric_managed);
  done(&priv);cases++;
 }
 /* Legacy/unflagged bring-up still boots; this is not the shipping default. */
 init(&priv,false);assert(!probe_publication_tail(&platform));normal_lan(&priv);
 assert(!priv.fabric_managed && !map_calls && !pon_reads && !m.writes);done(&priv);cases++;
 /* A bring-up image without FE/QM still has its original XRAM LAN path. */
 init(&priv,true);priv.fe=NULL;priv.dma_tx=priv.qm_rx=false;
 assert(!probe_publication_tail(&platform));normal_lan(&priv);
 assert(priv.fabric_error==-EOPNOTSUPP && !priv.fabric_managed && !map_calls && !m.writes);
 assert(!owner.exposed && !dma_starts && !qm_starts);done(&priv);cases++;
 /* Every partial resource lease unwinds BEFORE drvdata publication. */
 for(int stage=1;stage<=5;stage++)for(int index=0;index<4;index++){
  init(&priv,true);map_fault=stage;map_fault_index=index;
  if(stage==2)resources[index].end--;
  if(stage==5){resources[index].start+=4;resources[index].end+=4;}
  assert(!probe_publication_tail(&platform));normal_lan(&priv);
  assert(!priv.fabric_managed && priv.fabric_error<0 && !m.writes && !pon_reads && !pon_writes);
  assert(!priv.engine_poisoned);done(&priv);cases++;
 }
 for(unsigned int kind=0;kind<4;kind++){
  init(&priv,true);
  if(kind==0)stuck_pon_gate=true;
  if(kind==1)stuck_fifo=true;
  if(kind==2)pon_global[0]=~0U;
  if(kind==3)pon_global[1]|=RTL_PON_COLD_ACTIVE_ETH_RELEASED;
  assert(!probe_publication_tail(&platform));normal_lan(&priv);
  assert(!priv.fabric_managed && priv.fabric_error<0 && !m.writes && !m.scans);
  unsigned int before=pon_writes;assert(!rtl_ni_cold_bootstrap(&priv,&platform));
  assert(before==pon_writes);done(&priv);cases++;
 }
 /* Actual FE adapter distinguishes verified refusal from ambiguous failure. */
 for(unsigned int kind=0;kind<7;kind++){
  init(&priv,true);
  if(kind<3)m.inherited=kind+1;
  if(kind==3){m.drop_reg=RTL_L2_FDB_CONTROL;m.drop_occurrence=1;}
  if(kind==4){m.drop_reg=RTL_L2_VLAN_MODE_CONTROL;m.drop_occurrence=1;}
  if(kind==5)m.reg[RTL_L2_FDB_ACCESS/4]=RTL_L2_ACCESS_BUSY;
  if(kind==6){m.drop_reg=RTL_FABRIC_RX_MAC(2);m.drop_occurrence=1;}
  assert(!probe_publication_tail(&platform));normal_lan(&priv);
  assert(!priv.fabric_managed && fe.fabric.refusal && !fe.fabric.poisoned && fe.fabric.error<0);
  assert(!rtl_fabric_native_mtu_compatible(&fe.fabric));
  assert(m.reg[RTL_L2_VLAN_MODE_CONTROL/4]==m.original[RTL_L2_VLAN_MODE_CONTROL/4]);
  assert(m.reg[RTL_FABRIC_FRAME_LENGTH/4]==m.original[RTL_FABRIC_FRAME_LENGTH/4]);
  done(&priv);cases++;
 }
 /* Ambiguous shared writes must not become a successful LAN boot claim. */
 for(unsigned int kind=0;kind<4;kind++){
  init(&priv,true);
  if(kind==0)m.scan_timeout=1;
  if(kind==1){m.corrupt_vlan=1;m.rollback_stuck=1;}
  if(kind==2)post_fabric_drift=true;
  if(kind==3)m.corrupt_mac_gate=1;
  assert(probe_publication_tail(&platform)<0);no_publication(&priv);
  assert(priv.engine_poisoned && owner.exposed && fe.fabric.poisoned && !priv.fabric_managed);
  assert(!rtl_fabric_native_mtu_compatible(&fe.fabric));
  unsigned int before=m.writes;assert(rtl_ni_cold_bootstrap(&priv,&platform)==-EIO);
  assert(m.writes==before);done(&priv);cases++;
 }
 /* No first cold attempt is permitted after provider/start publication. */
 for(unsigned int kind=0;kind<3;kind++){
  init(&priv,true);
  if(kind==0)priv.provider_ready=true;
  if(kind==1)priv.base_ready=true;
  if(kind==2)priv.engine_users=1;
  assert(rtl_ni_cold_bootstrap(&priv,&platform)==-EBUSY);
  assert(!priv.cold_attempted && !map_calls && !m.writes);done(&priv);cases++;
 }
 init(&priv,true);assert(rtl_engine_get(&priv)==-EPROBE_DEFER && !opens);done(&priv);cases++;
 init(&priv,false);assert(rtl_engine_get(&priv)==-EPROBE_DEFER && !opens);done(&priv);cases++;
 for(unsigned int kind=0;kind<2;kind++){
  init(&priv,true);priv.removing=kind==0;priv.engine_poisoned=kind==1;
  assert(rtl_ni_cold_bootstrap(&priv,&platform)==-EIO);
  assert(!priv.cold_attempted && !map_calls && !m.writes);no_publication(&priv);done(&priv);cases++;
 }
 /* Once-only transaction under real concurrent callers. */
 {
  pthread_t a,b;void *ra,*rb;init(&priv,true);block_baseline=true;
  assert(!pthread_create(&a,NULL,bootstrap_thread,(void *)1));wait_flag(&baseline_entered);
  assert(!platform.dev.data && !priv.provider_ready && !registrations);
  assert(!pthread_create(&b,NULL,bootstrap_thread,(void *)2));wait_flag(&second_attempted);
  release_flag(&allow_baseline);
  assert(!pthread_join(a,&ra) && !pthread_join(b,&rb) && !ra && !rb);
  assert(m.scans==1 && m.vlan_writes==1 && m.frame_writes==1 && map_calls==4 && leases_empty());
  assert(!probe_publication_tail(&platform));normal_lan(&priv);
  assert(m.scans==1 && map_calls==4);done(&priv);cases++;
 }
 printf("NI local cold startup: %u integrated cases; actual PON/fabric/FE/NI paths, leases, warm opens and concurrent acquisition passed\n",cases);
}
'''

unit = model + common + functions + publication + main
variants = [('production', unit, None)]
if args.mutants:
    variants += [
        ('skip_automatic_cold', unit.replace('if (!priv->cold_handoff_required)', 'if (true)', 1),
         'priv.fabric_managed && fe.fabric.ready'),
        ('provider_before_registration_lock', unit.replace('\trtl_register_lans(priv, dev);',
                 '\tWRITE_ONCE(priv->provider_ready, true);\n\trtl_register_lans(priv, dev);', 1),
         '!priv->provider_ready'),
        ('provider_after_registration_unlock', unit.replace('WRITE_ONCE(priv->provider_ready, true);\n\trtnl_unlock();',
                 'rtnl_unlock();\n\tWRITE_ONCE(priv->provider_ready, true);', 1),
         'current->provider_ready'),
        ('ignore_ambiguous_shared_failure', unit.replace('if (ret < 0)\n\t\tgoto quarantine;',
                                                        'if (ret < 0) { rtl_ni_cold_unmap(&maps); goto fallback; }', 1),
         'item->fabric.poisoned'),
        ('omit_post_fabric_verify', unit.replace('ret = rtl_pon_cold_verify(&io, &priv->pon_cold);', 'ret = 0;', 1),
         'probe_publication_tail(&platform)<0'),
        ('omit_provider_open_gate', unit.replace('if (!READ_ONCE(priv->provider_ready))\n\t\treturn -EPROBE_DEFER;',
                                               'if (false)\n\t\treturn -EPROBE_DEFER;', 1),
         '*completion && rtnl'),
        ('warm_attempt_reallowed', unit.replace('if (READ_ONCE(priv->provider_ready) || priv->base_ready || priv->engine_users)',
                                               'if (false)', 1),
         'current->provider_ready'),
        ('repeat_cold_acquisition', unit.replace('if (priv->cold_attempted)\n\t\tgoto out;',
                                                'if (false)\n\t\tgoto out;', 1),
         '!rtl_ni_cold_bootstrap(&priv,&platform)'),
        ('leak_cold_resource', unit.replace('if (maps->claimed[i])', 'if (false)', 1),
         'leases_empty()'),
    ]
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
with tempfile.TemporaryDirectory(prefix='ni-cold-startup-') as directory:
    directory = Path(directory)
    (directory / 'linux').mkdir()
    (directory / 'linux/delay.h').write_text('/* Delay oracle provided by the model. */\n')
    if sys.platform == 'darwin':
        (directory / 'linux/errno.h').write_text('#include <errno.h>\n')
    for name, text, expected in variants:
        assert name == 'production' or text != unit, name
        cfile, binary = directory / (name + '.c'), directory / name
        cfile.write_text(text)
        subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                        '-Wno-misleading-indentation', '-Wno-unused-parameter', '-O1', '-g', '-pthread', '-fsanitize=address,undefined',
                        *([] if sys.platform == 'darwin' else ['-no-pie']),
                        '-I', str(directory), '-I', str(DRIVERS), str(cfile), '-o', str(binary)], check=True)
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30,
                                env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'})
        if expected is None:
            assert result.returncode == 0, result.stdout + result.stderr
            print(result.stdout, end='')
        else:
            assert result.returncode != 0 and 'assert' in result.stderr.lower() and expected in result.stderr, (name, result.stderr)
            print(name + ': detected by its runtime oracle')
print('Both production boards request NI-local cold bootstrap; no PON service/provider callback is used to publish LAN')
