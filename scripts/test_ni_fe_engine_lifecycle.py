#!/usr/bin/env python3
"""Run production NI start/stop against an instrumented FE/DMA/QM contract.

The FE state machine is tested separately by test_fe_lan_lifecycle.py. This
fixture checks the actual NI integration: old FE state must retire before
shared register writes, and successful restoration must precede admission.
It models call ordering, not ASIC drain or throughput.
"""
import json
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c-xram.c').read_text()


def function(name):
    start = source.index(name + '(')
    start = source.rfind('\n', 0, start) + 1
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


test = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
#define BIT(n) (1U << (n))
#define GENMASK(h,l) ((~0U >> (31-(h))) & (~0U << (l)))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define PORT_STRIDE 0x100
#define GLB_STATIC 0xa000
#define PORT_TO_CPU 0xf
#define RX_ADDR 0xaa20
#define TX_ADDR 0xaa24
#define XRAM_CFG 0xaa28
#define RX_PROMISC BIT(4)
#define CPU_DISABLE 0x201
#define RTL_XRAM_RX_END 512
#define RTL_XRAM_TX_END 1024
#define RTL_XRAM_TX_START 512
#define HRTIMER_MODE_REL 0
struct net_device {int unused;};
struct rtl_fe {bool desired,active,ready;};
struct engine {bool active;};
struct napi_struct {bool active;};
struct rtl_xram {
 struct net_device *netdev;
 struct rtl_fe *fe;
 bool dma_tx,qm_rx,tx_pending,rx_active;
 unsigned int port,ports[5],engine_users;
 unsigned char *ni;
 struct engine dma,qm;
 struct napi_struct napi;
 int rx_lock,rx_irq,timer,lan4_ready;
};
static struct rtl_xram *current;
static int fail_suspend,fail_resume,fail_dma,fail_qm;
static unsigned int suspends,resumes,writes,admissions,stops,waits,warnings;
static bool held,irq_off,rx_mode_done,completion_waited;
static bool shutdown;
static void lock(void) {assert(!held);held=true;}
static void unlock(void) {assert(held);held=false;}
#define spin_lock_irqsave(p,f) do{(void)(p);(f)=irq_off;irq_off=true;lock();}while(0)
#define spin_unlock_irqrestore(p,f) do{(void)(p);unlock();irq_off=(f);}while(0)
static u32 readl(void *reg) {return *(u32 *)reg;}
static void writel(u32 value,void *reg) {
 assert(suspends && !current->fe->ready);
 assert(!fail_suspend);
 *(u32 *)reg=value;writes++;
}
static void rtl_update(struct rtl_xram *p,unsigned int reg,u32 mask,u32 value) {
 assert(p==current);
 if(reg==0x6110) {
  assert(held && irq_off);
  if(value)assert(p->fe->ready && p->napi.active && p->qm.active);
  *(u32 *)(p->ni+reg)=(readl(p->ni+reg)&~mask)|value;
  return;
 }
 if(shutdown && reg==XRAM_CFG) {
  assert(!p->napi.active && !p->dma.active && !p->qm.active);
  *(u32 *)(p->ni+reg)=(readl(p->ni+reg)&~mask)|value;
  return;
 }
 writel((readl(p->ni+reg)&~mask)|value,p->ni+reg);
}
static int rtl_fe_engine_suspend(struct rtl_fe *fe) {
 assert(!held && !irq_off);suspends++;fe->ready=false;
 if(fail_suspend)return -ETIMEDOUT;
 fe->active=false;return 0;
}
static int rtl_fe_engine_resume(struct rtl_fe *fe) {
 assert(!held && !irq_off && !fe->ready && !fe->active);
 assert(writes && rx_mode_done && !current->tx_pending && !current->napi.active);
 assert(current->dma.active==current->dma_tx);
 assert(current->qm.active==current->qm_rx);
 if(current->qm_rx)for(unsigned int p=0;p<ARRAY_SIZE(current->ports);p++)
  if(current->ports[p])assert(((readl(current->ni+0xa5f8+PORT_STRIDE*p)>>16)&63)==16);
 resumes++;
 if(fail_resume)return -EIO;
 fe->active=fe->desired;fe->ready=true;return 0;
}
static int rtl_dma_tx_start(struct engine *engine) {
 assert(suspends && !current->fe->ready && !current->fe->active);
 if(fail_dma)return -ENOSPC;
 engine->active=true;return 0;
}
static int rtl_qm_rx_start(struct engine *engine,unsigned int port) {
 (void)port;assert(suspends && !current->fe->ready && !current->fe->active);
 if(fail_qm)return -ENOBUFS;
 engine->active=true;return 0;
}
static void rtl_dma_tx_stop(struct engine *engine) {engine->active=false;stops++;}
static void rtl_qm_rx_stop(struct engine *engine) {
 assert(!current->napi.active);engine->active=false;stops++;
}
static void rtl_mac_address(struct rtl_xram *p) {assert(p==current && writes);}
static void rtl_rx_mode(struct net_device *dev) {assert(dev==current->netdev);rx_mode_done=true;}
static void udelay(unsigned int usecs) {assert(usecs==100);}
static void napi_enable(struct napi_struct *napi) {
 assert(current->fe->ready && resumes && !fail_resume);napi->active=true;admissions++;
}
static void napi_disable(struct napi_struct *napi) {assert(shutdown);napi->active=false;}
static void synchronize_irq(int irq) {(void)irq;assert(!held && !irq_off);}
static void synchronize_net(void) {assert(!current->napi.active && shutdown);}
static int ms_to_ktime(int ms) {return ms;}
static void hrtimer_start(int *timer,int ms,int mode) {
 assert(ms==1 && mode==HRTIMER_MODE_REL && current->napi.active);*timer=1;
}
static void hrtimer_cancel(int *timer) {assert(shutdown && suspends);*timer=0;}
static void wait_for_completion(int *completion) {(void)completion;waits++;completion_waited=true;}
#define netdev_err(dev,fmt,...) do{(void)(dev);warnings++;}while(0)
'''
for name in ('rtl_engine_start', 'rtl_engine_stop', 'rtl_engine_get', 'rtl_engine_put'):
    test += '\n' + function(name) + '\n'
test += r'''
int main(void) {
 u32 registers[0x10000/4];
 struct net_device netdev={0};
 unsigned int cases=0;
 for(unsigned int mode=0;mode<4;mode++)for(unsigned int failure=0;failure<5;failure++) {
  struct rtl_fe fe={.desired=true,.active=true,.ready=true};
  struct rtl_xram p={.netdev=&netdev,.fe=&fe,.dma_tx=!!(mode&1),.qm_rx=!!(mode&2),
   .tx_pending=true,.port=0,.ports={1,0,1,0,1},.ni=(unsigned char *)registers};
  memset(registers,0x5a,sizeof(registers));current=&p;
  suspends=resumes=writes=admissions=stops=waits=warnings=0;
  held=irq_off=rx_mode_done=shutdown=completion_waited=false;
  fail_suspend=failure==1;fail_dma=failure==2;fail_qm=failure==3;fail_resume=failure==4;
  int expected=fail_suspend?-ETIMEDOUT:
   (fail_dma&&p.dma_tx)?-ENOSPC:(fail_qm&&p.qm_rx)?-ENOBUFS:fail_resume?-EIO:0;
  assert(rtl_engine_get(&p)==expected && completion_waited && waits==1);
  assert(!held && !irq_off && suspends==1);
  if(expected) {
   assert(!p.engine_users && !admissions && !p.timer && !fe.ready);
   assert(!p.dma.active && !p.qm.active && !p.napi.active);
   if(fail_suspend)assert(!writes && !resumes && !stops);
   if(expected==-EIO)assert(resumes==1);
  } else {
   assert(p.engine_users==1 && fe.ready && fe.active && admissions==1 && p.timer);
   unsigned int original_writes=writes;
   assert(!rtl_engine_get(&p));
   assert(p.engine_users==2 && suspends==1 && writes==original_writes && waits==1);
   rtl_engine_put(&p);
   assert(p.engine_users==1 && suspends==1 && p.napi.active);
   shutdown=true;
   rtl_engine_put(&p);
   assert(!p.engine_users && suspends==2 && !fe.ready && !fe.active);
   assert(!p.dma.active && !p.qm.active && !p.napi.active && !p.timer && !p.rx_active);
  }
  cases++;
 }
 /* A void last-user stop still drains NI on FE failure and reports it. */
 struct rtl_fe fe={.desired=true,.active=true,.ready=true};
 struct rtl_xram p={.netdev=&netdev,.fe=&fe,.dma_tx=true,.qm_rx=true,.engine_users=1,
  .dma={true},.qm={true},.napi={true},.ni=(unsigned char *)registers,.rx_active=true,.timer=1};
 current=&p;shutdown=true;fail_suspend=1;warnings=0;
 rtl_engine_put(&p);
 assert(!p.engine_users && !p.dma.active && !p.qm.active && !p.napi.active && !p.timer);
 assert(!fe.ready && fe.active && warnings==1);
 /* Restart must retry FE retirement before touching the retained snapshot. */
 shutdown=false;writes=resumes=0;
 assert(rtl_engine_get(&p)==-ETIMEDOUT);
 assert(!p.engine_users && !writes && !resumes);
 printf("NI/FE integration: %u mode/failure cases; preflight before shared writes, restore before NAPI, last-user failure retained\n",cases);
}
'''
with tempfile.TemporaryDirectory(prefix='ni-fe-lifecycle-') as directory:
    directory = Path(directory)
    cfile, binary = directory / 'ni-fe.c', directory / 'ni-fe'
    cfile.write_text(test)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
                    '-fsanitize=address,undefined', str(cfile), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
(root / 'logs').mkdir(exist_ok=True)
(root / 'logs/ni-fe-engine-lifecycle-test.json').write_text(json.dumps({
    'production_start_stop_get_put': True,
    'mode_failure_combinations': 20,
    'suspend_before_shared_registers': True,
    'resume_before_napi_and_admission': True,
    'failed_resume_unwinds_dma_qm': True,
    'failed_stop_blocks_next_start_before_register_writes': True,
    'hardware_access': False,
}, indent=2) + '\n')
