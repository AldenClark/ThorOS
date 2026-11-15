#!/usr/bin/env python3
"""Execute actual NI timer, both TX wrappers and stop across deadline races.

The clock, hrtimer queue/running contract and DMA cursor are host models, not
hardware. Two controlled threads reproduce callback-before-lock and
callback-after-forward windows, including synchronous cancellation on stop.
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
DRIVERS = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"
source = (DRIVERS / "rtl9617c-xram.c").read_text()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--mutants", action="store_true")
args = parser.parse_args()


def function(name):
    match = re.search(r"(?m)^(?:static\s+)?[\w *]+\b" + name +
                      r"\([^;{}]*\)\s*\{", source)
    assert match, name
    end = source.index("{", match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


functions = "\n".join(function(name) for name in (
    "rtl_tx_timer_kick_locked", "rtl_timer", "rtl_xmit",
    "rtl9617c_ni_transmit", "rtl_engine_start", "rtl_engine_stop"))
COMMON = r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "rtl9617c-xram-format.h"
typedef uint32_t u32;typedef uint64_t u64;typedef int64_t ktime_t;
typedef int netdev_tx_t;
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,y) ((x)=(y))
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define NETDEV_TX_OK 0
#define NETDEV_TX_BUSY 1
#define HRTIMER_MODE_REL 0
#define ETH_HLEN 14
#define BIT(n) (1U<<(n))
#define TX_READ 0xaa48
#define TX_WRITE 0xaa44
#define XRAM_CFG 0xaa28
#define CPU_DISABLE 0x201
#define ALIGN(n,a) (((n)+(a)-1)&~((a)-1))
#define unlikely(x) (x)
#define ms_to_ktime(n) ((ktime_t)(n)*1000)
enum hrtimer_restart {HRTIMER_NORESTART,HRTIMER_RESTART};
struct hrtimer {pthread_mutex_t lock;pthread_cond_t event;bool queued,running;
 ktime_t expires;unsigned starts,cancels;};
struct spinlock {pthread_mutex_t lock;bool tx;};
struct napi_struct {bool enabled;unsigned schedules;};
struct sk_buff {unsigned len;bool consumed;};
struct net_device {void *priv;bool running,stopped;
 struct {u64 tx_dropped,tx_packets,tx_bytes;}stats;};
struct device {void *data;};
struct rtl9617c_ni_frame {unsigned header_high,header_low;};
struct rtl9617c_ni_endpoint {void (*wake)(struct rtl9617c_ni_endpoint *);};
struct rtl_dma_tx {unsigned read,write,hardware_read;bool wake_pending;};
struct rtl_qm_rx {struct {unsigned pending;}refill;struct rtl9617c_ni_endpoint *pon;};
struct rtl_xram;
struct rtl_lan {struct rtl_xram *shared;unsigned port;};
struct rtl_xram {struct rtl_lan lan;struct hrtimer timer;struct rtl_qm_rx qm;struct rtl_dma_tx dma;
 bool qm_rx,dma_tx,tx_pending,host_active,removing,engine_poisoned,rx_active,base_ready;
 struct napi_struct napi;struct net_device *netdev,*ports[5];
 struct spinlock tx_lock,rx_lock;u32 idle_poll_ms;u64 timer_fast_ticks,timer_idle_ticks,tm_owner_generation;
 unsigned tx_length,mask;unsigned char tx_buffer[2048];void *ni,*xram;int rx_irq,fe;};
static struct rtl_xram x;
static struct net_device main_dev,lan_dev,pon_dev;
static struct rtl_lan lan;
static struct device parent;
static struct rtl9617c_ni_endpoint endpoint;
static atomic_llong clock_now;
static unsigned hardware_cursor,polls,wakes,cases;
static _Thread_local bool held_tx,held_rx;
static _Thread_local unsigned role;
enum {CALLBACK=1,CLOSER,STARTER};
enum {NO_PAUSE,BEFORE_TX_LOCK,AFTER_TX_UNLOCK,DURING_FORWARD};
static pthread_mutex_t gate=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t event=PTHREAD_COND_INITIALIZER;
static unsigned pause_at;
static bool window,released,cancel_wait,closed;
static bool start_window,start_released;
static void signal_event(void){assert(!pthread_cond_broadcast(&event));}
static void wait_event(void){assert(!pthread_cond_wait(&event,&gate));}
static void callback_window(unsigned phase){
 if(role!=CALLBACK || pause_at!=phase)return;
 assert(!pthread_mutex_lock(&gate));window=true;signal_event();
 while(!released)wait_event();
 assert(!pthread_mutex_unlock(&gate));
}
static void spin_lock(struct spinlock *lock){
 if(lock->tx)callback_window(BEFORE_TX_LOCK);
 assert(!pthread_mutex_lock(&lock->lock));
 if(lock->tx){assert(!held_tx);held_tx=true;}else{assert(!held_rx);held_rx=true;}
}
static void spin_unlock(struct spinlock *lock){
 if(lock->tx){assert(held_tx);held_tx=false;}else{assert(held_rx);held_rx=false;}
 assert(!pthread_mutex_unlock(&lock->lock));
 if(lock->tx)callback_window(AFTER_TX_UNLOCK);
 if(lock->tx && role==STARTER && x.host_active){
  assert(!pthread_mutex_lock(&gate));start_window=true;signal_event();
  while(!start_released)wait_event();
  assert(!pthread_mutex_unlock(&gate));
 }
}
#define spin_lock_irqsave(p,f) do{(f)=0;spin_lock(p);}while(0)
#define spin_unlock_irqrestore(p,f) do{(void)(f);spin_unlock(p);}while(0)
static int ktime_compare(ktime_t a,ktime_t b){return (a>b)-(a<b);}
static bool hrtimer_active(struct hrtimer *t){
 assert(!pthread_mutex_lock(&t->lock));bool value=t->queued||t->running;
 assert(!pthread_mutex_unlock(&t->lock));return value;
}
static ktime_t hrtimer_get_remaining(struct hrtimer *t){
 assert(!pthread_mutex_lock(&t->lock));ktime_t value=t->expires-atomic_load(&clock_now);
 assert(!pthread_mutex_unlock(&t->lock));return value;
}
static void hrtimer_start(struct hrtimer *t,ktime_t delay,int mode){
 assert(mode==HRTIMER_MODE_REL && delay==1000 && x.host_active && !x.removing && !x.engine_poisoned);
 if(role==STARTER)assert(held_tx && "initial start must serialize with a recovery-started callback");
 assert(!pthread_mutex_lock(&t->lock));t->expires=atomic_load(&clock_now)+delay;
 t->queued=true;t->starts++;assert(!pthread_mutex_unlock(&t->lock));
}
static void hrtimer_forward_now(struct hrtimer *t,ktime_t interval){
 assert(held_tx && "deadline publication must serialize with BUSY kicks");
 assert(!pthread_mutex_lock(&t->lock));assert(t->running);
 ktime_t now=atomic_load(&clock_now);
 /* Match hrtimer_forward's actual order: a future expiry returns before
  * testing ENQUEUED. Its later check-to-update sequence has no base lock;
  * the driver must exclude concurrent starts for that entire window. */
 if(now<t->expires){assert(!pthread_mutex_unlock(&t->lock));return;}
 assert(!t->queued);ktime_t advance=((now-t->expires)/interval+1)*interval;
 assert(!pthread_mutex_unlock(&t->lock));
 callback_window(DURING_FORWARD);
 assert(!pthread_mutex_lock(&t->lock));
 assert(!t->queued && "no start may re-enqueue between hrtimer_forward check and expiry update");
 t->expires+=advance;
 assert(!pthread_mutex_unlock(&t->lock));
}
static void hrtimer_cancel(struct hrtimer *t){
 assert(!held_tx && !held_rx && !x.host_active);
 assert(!pthread_mutex_lock(&t->lock));
 while(t->running){
  assert(!pthread_mutex_lock(&gate));cancel_wait=true;signal_event();assert(!pthread_mutex_unlock(&gate));
  assert(!pthread_cond_wait(&t->event,&t->lock));
 }
 t->queued=false;t->cancels++;assert(!pthread_mutex_unlock(&t->lock));
}
static void napi_schedule(struct napi_struct *n){assert(n->enabled);n->schedules++;}
static void napi_enable(struct napi_struct *n){assert(!n->enabled && !x.host_active);n->enabled=true;}
static void napi_disable(struct napi_struct *n){assert(!held_tx && !held_rx && !x.host_active);n->enabled=false;}
static void synchronize_irq(int irq){(void)irq;assert(!held_tx && !held_rx && !x.rx_active);}
static void synchronize_net(void){assert(!held_tx && !held_rx && !x.napi.enabled);}
static int rtl_fe_engine_suspend(int fe){(void)fe;assert(!held_tx && !x.host_active);return 0;}
static int rtl_fe_engine_resume(int fe){(void)fe;assert(!held_tx && !x.host_active);return 0;}
static int rtl_engine_prepare(struct rtl_xram *p){(void)p;assert(false);return -EIO;}
static void rtl_engine_poison(struct rtl_xram *p){(void)p;assert(false);}
static void rtl_pon_host_gate(struct rtl_xram *p,bool active){assert(p==&x && held_tx && active==p->host_active);}
static void rtl_update(struct rtl_xram *p,unsigned reg,unsigned mask,unsigned value){
 assert(p==&x && held_rx && reg==0x6110 && mask==255 && value==(p->rx_active?255U:0U));p->mask=value;
}
#define netdev_err(dev,fmt,...) do{(void)(dev);fprintf(stderr,fmt,##__VA_ARGS__);}while(0)
static bool rtl_dma_tx_available(struct rtl_dma_tx *tx){return ((tx->read-tx->write-1)&63)>2;}
static void rtl_dma_tx_complete(struct rtl_dma_tx *tx,struct net_device *dev){
 (void)dev;assert(held_tx);tx->hardware_read=hardware_cursor;polls++;
 while(((hardware_cursor-tx->read)&63)>2)tx->read=(tx->read+1)&63;
}
static void netif_stop_queue(struct net_device *d){d->stopped=true;}
static bool netif_running(struct net_device *d){return d->running;}
static bool netif_queue_stopped(struct net_device *d){return d->stopped;}
static void netif_wake_queue(struct net_device *d){assert(x.host_active);d->stopped=false;wakes++;}
static void pon_wake(struct rtl9617c_ni_endpoint *e){assert(e==&endpoint);netif_wake_queue(&pon_dev);}
static netdev_tx_t rtl_dma_tx_frame(struct rtl_dma_tx *tx,struct sk_buff *skb,
 struct net_device *d,const struct rtl9617c_ni_frame *frame){
 (void)frame;assert(held_tx && x.host_active && !skb->consumed);
 if(!rtl_dma_tx_available(tx))rtl_dma_tx_complete(tx,d);
 if(!rtl_dma_tx_available(tx)){tx->wake_pending=true;netif_stop_queue(d);return NETDEV_TX_BUSY;}
 tx->write=(tx->write+1)&63;skb->consumed=true;return NETDEV_TX_OK;
}
static void *dev_get_drvdata(struct device *dev){return dev->data;}
static void *netdev_priv(struct net_device *dev){return dev->priv;}
static void dev_kfree_skb_any(struct sk_buff *skb){assert(!skb->consumed);skb->consumed=true;}
static void dev_consume_skb_any(struct sk_buff *skb){dev_kfree_skb_any(skb);}
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define rcu_dereference(x) (x)
static unsigned rtl_pointer(struct rtl_xram *p,unsigned reg){(void)p;(void)reg;assert(false);return 0;}
static void skb_copy_bits(struct sk_buff *skb,unsigned offset,void *to,unsigned bytes){(void)skb;(void)offset;(void)to;(void)bytes;assert(false);}
static u32 crc32_le(u32 crc,void *buffer,unsigned bytes){(void)crc;(void)buffer;(void)bytes;assert(false);return 0;}
static void put_unaligned_le32(u32 value,void *pointer){(void)value;(void)pointer;assert(false);}
static u32 get_unaligned_le32(void *pointer){(void)pointer;assert(false);return 0;}
static void writel(u32 value,void *pointer){(void)value;(void)pointer;assert(false);}
#define wmb() ((void)0)
'''
TEST = r'''
static void setup_unstarted(unsigned idle){
 memset(&x,0,sizeof(x));memset(&main_dev,0,sizeof(main_dev));memset(&lan_dev,0,sizeof(lan_dev));memset(&pon_dev,0,sizeof(pon_dev));
 main_dev.priv=&x;main_dev.running=true;x.netdev=&main_dev;
 lan=(struct rtl_lan){.shared=&x,.port=1};lan_dev.priv=&lan;lan_dev.running=true;x.ports[1]=&lan_dev;
 parent.data=&main_dev;endpoint.wake=pon_wake;x.qm.pon=&endpoint;pon_dev.running=true;
 x.qm_rx=x.dma_tx=x.base_ready=true;x.idle_poll_ms=idle;
 x.tx_lock.tx=true;assert(!pthread_mutex_init(&x.tx_lock.lock,NULL));assert(!pthread_mutex_init(&x.rx_lock.lock,NULL));
 assert(!pthread_mutex_init(&x.timer.lock,NULL));assert(!pthread_cond_init(&x.timer.event,NULL));
 atomic_store(&clock_now,0);hardware_cursor=polls=wakes=0;role=NO_PAUSE;pause_at=NO_PAUSE;
 window=released=cancel_wait=closed=start_window=start_released=false;
}
static void setup(unsigned idle){setup_unstarted(idle);assert(!rtl_engine_start(&x));}
static void finish(void){
 if(x.host_active)rtl_engine_stop(&x);
 assert(!x.timer.queued && !x.timer.running && !x.host_active && !x.napi.enabled);
 assert(!pthread_mutex_destroy(&x.tx_lock.lock));assert(!pthread_mutex_destroy(&x.rx_lock.lock));
 assert(!pthread_mutex_destroy(&x.timer.lock));assert(!pthread_cond_destroy(&x.timer.event));cases++;
}
static void *fire(void *unused){
 (void)unused;role=CALLBACK;
 assert(!pthread_mutex_lock(&x.timer.lock));
 assert(x.timer.queued && !x.timer.running && x.timer.expires<=atomic_load(&clock_now));
 x.timer.queued=false;x.timer.running=true;assert(!pthread_mutex_unlock(&x.timer.lock));
 enum hrtimer_restart restart=rtl_timer(&x.timer);
 assert(!pthread_mutex_lock(&x.timer.lock));
 /* kernel/time/hrtimer.c preserves an external start done during callback. */
 if(restart==HRTIMER_RESTART && !x.timer.queued)x.timer.queued=true;
 x.timer.running=false;assert(!pthread_cond_broadcast(&x.timer.event));assert(!pthread_mutex_unlock(&x.timer.lock));
 role=NO_PAUSE;return NULL;
}
static void tick(void){atomic_store(&clock_now,x.timer.expires);fire(NULL);}
static void burst(void){
 for(unsigned i=0;i<61;i++){
  struct sk_buff skb={.len=100};
  assert(rtl9617c_ni_transmit(&parent,&pon_dev,&skb,NULL)==NETDEV_TX_OK && skb.consumed);
 }
 assert(x.dma.write==61 && !x.dma.wake_pending);
}
static void busy(bool from_lan){
 struct sk_buff skb={.len=100};
 int ret=from_lan?rtl_xmit(&skb,&lan_dev):rtl9617c_ni_transmit(&parent,&pon_dev,&skb,NULL);
 assert(ret==NETDEV_TX_BUSY && !skb.consumed && x.dma.wake_pending);
}
static void wait_window(void){
 assert(!pthread_mutex_lock(&gate));while(!window)wait_event();assert(!pthread_mutex_unlock(&gate));
}
static void release_window(void){
 assert(!pthread_mutex_lock(&gate));released=true;signal_event();assert(!pthread_mutex_unlock(&gate));
}
static void *close_engine(void *unused){
 (void)unused;role=CLOSER;rtl_engine_stop(&x);
 assert(!pthread_mutex_lock(&gate));closed=true;signal_event();assert(!pthread_mutex_unlock(&gate));
 role=NO_PAUSE;return NULL;
}
static void *open_engine(void *unused){
 (void)unused;role=STARTER;assert(!rtl_engine_start(&x));role=NO_PAUSE;return NULL;
}
static void deadlines(void){
 for(unsigned idle=1;idle<=10;idle++)for(unsigned producer=0;producer<2;producer++){
  setup(idle);tick();assert(x.timer.expires==1000+(ktime_t)idle*1000);
  atomic_store(&clock_now,1200);burst();assert(x.timer.starts==1);
  busy(producer);ktime_t deadline=x.timer.expires;
  assert(deadline==(idle==1?2000:2200) && x.timer.starts==(idle==1?1:2));
  /* Continuous retries must not postpone the existing sooner deadline. */
  for(unsigned i=0;i<100;i++){atomic_store(&clock_now,1200+i*5);busy(!producer);assert(x.timer.expires==deadline);}
  hardware_cursor=x.dma.write;tick();assert(!x.dma.wake_pending && wakes==2 && !lan_dev.stopped && !pon_dev.stopped);
  assert(x.timer.expires==deadline+(ktime_t)idle*1000);
  unsigned starts=x.timer.starts;
  for(unsigned i=0;i<100;i++){ktime_t before=x.timer.expires;tick();assert(x.timer.expires-before==(ktime_t)idle*1000);}
  assert(x.timer.starts==starts && wakes==2);finish();
 }
 /* An expired-but-not-dispatched callback is already sooner than 1 ms. */
 setup(10);tick();burst();atomic_store(&clock_now,x.timer.expires+50);busy(true);
 assert(x.timer.starts==1);fire(NULL);assert(x.timer.expires-atomic_load(&clock_now)<=1000);finish();
 /* Repair an inactive timer only while the shared host is online. */
 setup(4);burst();x.timer.queued=false;busy(false);assert(x.timer.queued && x.timer.starts==2);finish();
}
static void callback_races(void){
 for(unsigned repeat=0;repeat<25;repeat++)for(unsigned phase=BEFORE_TX_LOCK;phase<=AFTER_TX_UNLOCK;phase++){
  setup(10);tick();pause_at=phase;atomic_store(&clock_now,x.timer.expires);
  pthread_t callback;assert(!pthread_create(&callback,NULL,fire,NULL));wait_window();
  burst();busy(repeat%2);busy(!(repeat%2));
  if(phase==BEFORE_TX_LOCK)assert(x.timer.starts==1 && !x.timer.queued);
  else assert(x.timer.starts==2 && x.timer.queued && x.timer.expires==atomic_load(&clock_now)+1000);
  release_window();assert(!pthread_join(callback,NULL));pause_at=NO_PAUSE;
  assert(x.timer.queued && !x.timer.running && x.timer.expires==atomic_load(&clock_now)+1000);
  hardware_cursor=x.dma.write;tick();assert(!x.dma.wake_pending && wakes==2);finish();
 }
}
static void stop_races(void){
 for(unsigned repeat=0;repeat<25;repeat++)for(unsigned phase=BEFORE_TX_LOCK;phase<=AFTER_TX_UNLOCK;phase++){
  setup(4);tick();pause_at=phase;atomic_store(&clock_now,x.timer.expires);
  pthread_t callback,closer;assert(!pthread_create(&callback,NULL,fire,NULL));wait_window();
  assert(!pthread_create(&closer,NULL,close_engine,NULL));
  assert(!pthread_mutex_lock(&gate));while(!cancel_wait)wait_event();assert(!closed);assert(!pthread_mutex_unlock(&gate));
  assert(!x.host_active);unsigned starts=x.timer.starts,previous_polls=polls;
  struct sk_buff skb={.len=100};
  assert(rtl9617c_ni_transmit(&parent,&pon_dev,&skb,NULL)==NETDEV_TX_OK && skb.consumed);
  spin_lock(&x.tx_lock);rtl_tx_timer_kick_locked(&x);spin_unlock(&x.tx_lock);
  assert(x.timer.starts==starts);
  release_window();assert(!pthread_join(callback,NULL));assert(!pthread_join(closer,NULL));pause_at=NO_PAUSE;
  assert(closed && !x.timer.queued && !x.timer.running && !x.mask && !x.rx_active && polls==previous_polls);
  /* Execute the actual warm start, not a synthetic host=true shortcut. */
  assert(!rtl_engine_start(&x));tick();assert(x.timer.queued);finish();
 }
 /* A successful BUSY kick immediately before stop is cancelled too. */
 setup(10);tick();burst();busy(true);assert(x.timer.starts==2);finish();
 for(unsigned poison=0;poison<2;poison++){
  setup(4);x.removing=!poison;x.engine_poisoned=poison;
  spin_lock(&x.tx_lock);rtl_tx_timer_kick_locked(&x);spin_unlock(&x.tx_lock);
  tick();assert(!x.timer.queued && x.timer.starts==1 && !polls);finish();
 }
}
static void startup_races(void){
 for(unsigned repeat=0;repeat<25;repeat++){
  setup_unstarted(10);pthread_t starter,callback;
  assert(!pthread_create(&starter,NULL,open_engine,NULL));
  assert(!pthread_mutex_lock(&gate));while(!start_window)wait_event();assert(!pthread_mutex_unlock(&gate));
  /* PON recovery is not serialized by RTNL. It may fill/stop the shared
   * TX ring immediately after host publication, while open is paused. */
  burst();busy(false);busy(true);pause_at=DURING_FORWARD;atomic_store(&clock_now,x.timer.expires);
  assert(!pthread_create(&callback,NULL,fire,NULL));wait_window();
  assert(!pthread_mutex_lock(&gate));start_released=true;signal_event();assert(!pthread_mutex_unlock(&gate));
  assert(!pthread_join(starter,NULL));
  /* A second initial start here would change a timer already examined by
   * hrtimer_forward; the sole queued/restart decision belongs to callback. */
  assert(x.timer.starts==1 && x.timer.running && !x.timer.queued);
  release_window();assert(!pthread_join(callback,NULL));pause_at=NO_PAUSE;
  assert(x.timer.expires==atomic_load(&clock_now)+1000 && x.timer.queued);
  hardware_cursor=x.dma.write;tick();assert(!x.dma.wake_pending && wakes==2);finish();
 }
}
int main(void){deadlines();callback_races();stop_races();startup_races();
 printf("NI timer deadlines: %u scenarios passed; LAN/PON idle-to-BUSY, no postponement, 125 controlled callback/stop/actual-start races, no lock-held cancellation or rearm after stop\n",cases);
}
'''


def run(code, name, expect_failure=False):
    with tempfile.TemporaryDirectory(prefix="ni-timer-deadlines-") as directory:
        path = Path(directory)
        (path / "test.c").write_text(COMMON + code + TEST)
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-function", "-pthread", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                        "-I", str(DRIVERS), str(path / "test.c"), "-o", str(path / "test")], check=True)
        environment = dict(os.environ)
        environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
        result = subprocess.run([str(path / "test")], capture_output=True, text=True, timeout=25, env=environment)
        if expect_failure:
            assert result.returncode != 0, f"mutant survived: {name}"
            print(f"REJECTED {name}")
        else:
            print(result.stdout + result.stderr, end="")
            assert result.returncode == 0, name


run(functions, "production")
mutants = {
    "missing LAN BUSY kick": functions.replace("\t\tif (result == NETDEV_TX_BUSY)\n\t\t\trtl_tx_timer_kick_locked(priv);", "", 1),
    "missing PON BUSY kick": functions.replace("\tif (result == NETDEV_TX_BUSY)\n\t\trtl_tx_timer_kick_locked(priv);", "", 1),
    "retries postpone deadline": functions.replace("if (!hrtimer_active(&priv->timer) ||\n\t    ktime_compare(hrtimer_get_remaining(&priv->timer), fast) > 0)", "if (true)"),
    "callback publishes after unlock": functions.replace("\thrtimer_forward_now(timer, ms_to_ktime(interval));\n\tspin_unlock(&priv->tx_lock);", "\tspin_unlock(&priv->tx_lock);\n\thrtimer_forward_now(timer, ms_to_ktime(interval));"),
    "callback ignores stopped host": functions.replace("\t\treturn HRTIMER_NORESTART;", "\t\tspin_lock(&priv->tx_lock);", 1),
    "initial start outside publication lock": functions.replace(
        "\thrtimer_start(&priv->timer, ms_to_ktime(1), HRTIMER_MODE_REL);", "", 1).replace(
        "\tnapi_schedule(&priv->napi);\n\treturn 0;", "\tnapi_schedule(&priv->napi);\n\thrtimer_start(&priv->timer, ms_to_ktime(1), HRTIMER_MODE_REL);\n\treturn 0;", 1),
}
if args.mutants:
    for name, mutant in mutants.items():
        assert mutant != functions, name
        run(mutant, name, expect_failure=True)
(ROOT / "artifacts").mkdir(exist_ok=True)
(ROOT / "artifacts/ni-timer-deadlines.json").write_text(json.dumps({
    "production_functions_sha256": hashlib.sha256(functions.encode()).hexdigest(),
    "scope": "actual NI timer, both TX wrappers, warm start and stop; host-modeled hrtimer/DMA boundaries",
    "idle_intervals_ms": list(range(1, 11)), "controlled_thread_races": 125,
    "mutants_rejected": list(mutants) if args.mutants else [], "hardware_verified": False,
}, indent=2) + "\n")
