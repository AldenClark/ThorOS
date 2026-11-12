#!/usr/bin/env python3
"""Exercise the real NI hrtimer callback for idle/active TX and PON wakeups.

Timer, device ownership and MMIO are mocked; hardware latency still needs testing.
"""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c-xram.c').read_text()
match = re.search(r'^static enum hrtimer_restart rtl_timer\(.*?\)\s*\{', source, re.M)
assert match
end = source.index('{', match.start()) + 1
depth = 1
while depth:
    depth += (source[end] == '{') - (source[end] == '}')
    end += 1

model = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
typedef uint32_t u32;
typedef uint64_t u64;
#define READ_ONCE(x) (x)
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#define container_of(p,t,m) ((t*)((char*)(p)-offsetof(t,m)))
#define HRTIMER_RESTART 1
#define TX_READ 0xaa48
#define TX_WRITE 0xaa44
#define ms_to_ktime(x) (x)
enum hrtimer_restart {unused_timer,HRTIMER_RESTART_ENUM};
struct hrtimer {unsigned interval;};
struct napi_struct {unsigned unused;};
struct net_device {bool running,stopped;struct {u64 tx_packets,tx_bytes;}stats;};
struct rtl_dma_tx {unsigned read,write,hardware_read;bool wake_pending;};
struct rtl_qm_rx {unsigned refill_pending;struct {unsigned pending;}refill;struct rtl9617c_ni_endpoint *pon;};
struct rtl9617c_ni_endpoint {void (*wake)(struct rtl9617c_ni_endpoint *);};
struct rtl_xram {struct hrtimer timer;struct rtl_qm_rx qm;struct rtl_dma_tx dma;
 bool qm_rx,dma_tx,tx_pending;struct napi_struct napi;struct net_device *netdev,*ports[5];
 int tx_lock;u32 idle_poll_ms;u64 timer_fast_ticks,timer_idle_ticks;unsigned tx_length;};
static unsigned calls,wakes,napi_calls,hardware_cursor;
static unsigned xram_read,xram_write;
static int spin_lock(int *v){assert(!*v);*v=1;return 0;}
static int spin_unlock(int *v){assert(*v);*v=0;return 0;}
static void napi_schedule(struct napi_struct *n){(void)n;napi_calls++;}
static void hrtimer_forward_now(struct hrtimer *t,unsigned interval){t->interval=interval;}
static bool rtl_dma_tx_available(struct rtl_dma_tx *tx){return ((tx->read-tx->write-1)&63)>2;}
static void rtl_dma_tx_complete(struct rtl_dma_tx *tx,struct net_device *dev){
 (void)dev;tx->hardware_read=hardware_cursor;calls++;
 while(((hardware_cursor-tx->read)&63)>2)tx->read=(tx->read+1)&63;
}
static bool netif_running(struct net_device*d){return d->running;}
static bool netif_queue_stopped(struct net_device*d){return d->stopped;}
static void netif_wake_queue(struct net_device*d){d->stopped=false;wakes++;}
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define rcu_dereference(x) (x)
static unsigned rtl_pointer(struct rtl_xram *p,unsigned addr){(void)p;return addr==TX_READ?xram_read:xram_write;}
static void pon_wake(struct rtl9617c_ni_endpoint *e){(void)e;wakes++;}
'''
test = r'''
int main(void) {
 struct net_device main={.running=true},port={.running=true,.stopped=true};
 struct rtl9617c_ni_endpoint pon={.wake=pon_wake};
 struct rtl_xram x={.netdev=&main,.ports={&port},.qm_rx=true,.dma_tx=true,.idle_poll_ms=4};
 x.qm.pon=&pon;
 for(unsigned i=0;i<100;i++){
  assert(rtl_timer(&x.timer)==HRTIMER_RESTART);
  assert(x.timer.interval==4);
 }
 assert(x.timer_idle_ticks==100 && x.timer_fast_ticks==0 && wakes==0);
 /* A stopped queue must be awakened only after the reserved descriptor
  * margin reappears, and PON's 64 interfaces are not scanned when idle. */
 x.dma.write=61;x.dma.wake_pending=true;
 assert(rtl_timer(&x.timer)==HRTIMER_RESTART && x.timer.interval==1 && wakes==0);
 assert(x.dma.wake_pending && port.stopped);
 hardware_cursor=61;
 assert(rtl_timer(&x.timer)==HRTIMER_RESTART && x.timer.interval==4);
 assert(!x.dma.wake_pending && !port.stopped && wakes==2 && x.dma.read==59);
 assert(rtl_timer(&x.timer)==HRTIMER_RESTART && wakes==2);
 x.qm.refill.pending=1;
 assert(rtl_timer(&x.timer)==HRTIMER_RESTART && x.timer.interval==1 && napi_calls==1);
 x.qm.refill.pending=0;x.idle_poll_ms=1;
 assert(rtl_timer(&x.timer)==HRTIMER_RESTART && x.timer.interval==1);
 /* Legacy XRAM RX remains on its required one-millisecond poll. */
 x.dma_tx=x.qm_rx=false;x.tx_pending=true;x.tx_length=90;main.stopped=true;
 xram_read=xram_write=8;
 assert(rtl_timer(&x.timer)==HRTIMER_RESTART && x.timer.interval==1);
 assert(!x.tx_pending && !main.stopped && main.stats.tx_packets==1);
 assert(napi_calls==2);
 printf("Native NI timer: 100 idle ticks, pending DMA, PON wake-once, refill and XRAM fallback passed (%u MMIO model polls)\n",calls);
}
'''
with tempfile.TemporaryDirectory(prefix='ni-timer-', dir=root / 'artifacts') as path:
    file = Path(path) / 'test.c'
    executable = Path(path) / 'test'
    file.write_text(model + source[match.start():end] + test)
    subprocess.run(['cc', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    '-fsanitize=address,undefined', str(file), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
