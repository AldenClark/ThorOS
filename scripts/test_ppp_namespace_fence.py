#!/usr/bin/env python3
"""Exercise real PPP generation and namespace-move fences with a host backend.

Production inline helpers, PPP policy/writer functions, late cls validation,
and the actual core move publication blocks are extracted unchanged from the
prepared kernel. The backend supplies locks, namespace references and policy
scopes. It checks controlled pthread schedules and CAS retry/wrap, not an
actual Linux netns transition, an LKMM proof, or hardware packet forwarding.
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
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--kernel", type=Path, required=True)
parser.add_argument("--mutants", action="store_true")
args = parser.parse_args()
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def source(path):
    return (args.kernel / path).read_text()


def function(text, name):
    match = re.search(r"\b" + re.escape(name) + r"\([^;]*?\)\s*\{", text)
    assert match, "Missing production function: " + name
    start = text.rfind("\n", 0, match.start()) + 1
    if not text[start:match.start()].strip():
        start = text.rfind("\n", 0, start - 1) + 1
    end = text.index("{", match.start()) + 1
    depth = 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end] + "\n"


netdev = source("include/linux/netdevice.h")
ppp = source("drivers/net/ppp/ppp_generic.c")
core = source("net/core/dev.c")
offload = source("include/net/flow_offload.h")
ioctl = source("include/uapi/linux/ppp-ioctl.h")
defs = source("include/uapi/linux/ppp_defs.h")
move = function(core, "__dev_change_net_namespace")
begin_at = move.index("\tWRITE_ONCE(dev->moving_ns, true);")
begin_end = move.index("\n\tnetdev_unlock(dev);", begin_at) + len("\n\tnetdev_unlock(dev);")
move_start = move[begin_at:begin_end]
publish_at = move.index("\tnetdev_lock(dev);\n\trtl9617c_switch_move_begin(dev, net);")
publish_end = move.index("\n\tnetdev_unlock(dev);", publish_at) + len("\n\tnetdev_unlock(dev);")
move_publish = move[publish_at:publish_end]
finish_at = move.rfind("\tnetdev_lock(dev);", 0, move.index("smp_store_release(&dev->moving_ns, false)"))
finish_end = move.index("\n\t\tnetdev_unlock(dev);", finish_at) + len("\n\t\tnetdev_unlock(dev);")
move_finish = move[finish_at:finish_end]
assert begin_at < move.index("netdev_ppp_path_advance(dev, 2)") < move.index("synchronize_net();", begin_at) < publish_at
assert publish_at < move.index("dev_net_set(dev, net)", publish_at) < finish_at
assert "bool moving_ns;" in netdev
assert "atomic_try_cmpxchg" in function(netdev, "netdev_ppp_path_advance")
assert "smp_load_acquire" in function(netdev, "netdev_ppp_path_cookie")
assert "smp_load_acquire" in function(netdev, "netdev_ppp_path_valid")

constants = "\n".join(re.findall(r"^#define\s+SC_[A-Z0-9_]+\s+0x[0-9a-fA-F]+.*$", ioctl, re.M))
constants += "\n" + "\n".join(re.findall(r"^#define\s+(?:NP_[A-Z0-9_]+|NUM_NP)\s+[0-9]+.*$", ppp, re.M))
constants += "\n" + re.search(r"enum NPmode \{.*?\n\};", defs, re.S)[0] + "\n"

COMMON = r'''
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
typedef uint32_t u32;typedef uint16_t __be16;typedef _Atomic int atomic_t;
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define atomic_read(p) atomic_load_explicit((p),memory_order_seq_cst)
#define atomic_set(p,v) atomic_store_explicit((p),(int)(v),memory_order_seq_cst)
#define smp_rmb() atomic_thread_fence(memory_order_acquire)
#define smp_load_acquire(p) atomic_load_explicit((p),memory_order_acquire)
#define smp_store_release(p,v) atomic_store_explicit((p),(v),memory_order_release)
struct lock {pthread_mutex_t mutex;};
static void lock_init(struct lock *l){assert(!pthread_mutex_init(&l->mutex,NULL));}
static void lock_destroy(struct lock *l){assert(!pthread_mutex_destroy(&l->mutex));}
static void lock(struct lock *l){assert(!pthread_mutex_lock(&l->mutex));}
static void unlock(struct lock *l){assert(!pthread_mutex_unlock(&l->mutex));}
struct net {atomic_uint active,begins,ends;};
struct net_device {atomic_t ppp_channel_generation;_Atomic bool moving_ns;_Atomic(struct net *) net;struct lock mutex;};
struct ppp {struct net_device *dev;struct net *ppp_net;struct lock wlock,rlock;unsigned int flags;void *xc_state,*rc_state,*pass_filter,*active_filter;enum NPmode npmode[NUM_NP];};
struct flow_cls_offload {struct {struct net_device *dev;u32 cookie;} ppp_paths[2];};
static _Thread_local bool ppp_locked,pause_next_cas;
#define lockdep_assert_held(l) do{(void)(l);assert(ppp_locked);}while(0)
static void ppp_lock(struct ppp *p){lock(&p->wlock);lock(&p->rlock);assert(!ppp_locked);ppp_locked=true;}
static void ppp_unlock(struct ppp *p){assert(ppp_locked);ppp_locked=false;unlock(&p->rlock);unlock(&p->wlock);}
static struct net *dev_net(const struct net_device *d){return atomic_load_explicit(&d->net,memory_order_acquire);}
static inline bool net_eq(const struct net *a,const struct net *b){return a==b;}
static void dev_net_set(struct net_device *d,struct net *n){atomic_store_explicit(&d->net,n,memory_order_release);}
static void netdev_lock(struct net_device *d){lock(&d->mutex);}
static void netdev_unlock(struct net_device *d){unlock(&d->mutex);}
static bool netdev_need_ops_lock(const struct net_device *d){(void)d;return false;}
static void policy_begin(struct net *n){atomic_fetch_add(&n->active,1);atomic_fetch_add(&n->begins,1);}
static struct net *rtl9617c_switch_policy_begin(struct net_device *d){struct net *n=dev_net(d);policy_begin(n);return n;}
static void rtl9617c_switch_policy_end(struct net *n){assert(atomic_fetch_sub(&n->active,1)>0);atomic_fetch_add(&n->ends,1);}
static void rtl9617c_switch_move_begin(struct net_device *d,struct net *n){policy_begin(dev_net(d));policy_begin(n);}
static pthread_mutex_t cas_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cas_cond=PTHREAD_COND_INITIALIZER;
static bool cas_waiting,cas_resume;
static bool atomic_try_cmpxchg(atomic_t *value,int *old,int next){
 if(pause_next_cas){pause_next_cas=false;pthread_mutex_lock(&cas_mutex);cas_waiting=true;pthread_cond_broadcast(&cas_cond);while(!cas_resume)pthread_cond_wait(&cas_cond,&cas_mutex);pthread_mutex_unlock(&cas_mutex);}
 return atomic_compare_exchange_strong_explicit(value,old,next,memory_order_seq_cst,memory_order_seq_cst);
}
static void wait_for_cas(void){pthread_mutex_lock(&cas_mutex);while(!cas_waiting)pthread_cond_wait(&cas_cond,&cas_mutex);pthread_mutex_unlock(&cas_mutex);}
static void resume_cas(void){pthread_mutex_lock(&cas_mutex);cas_resume=true;pthread_cond_broadcast(&cas_cond);pthread_mutex_unlock(&cas_mutex);}
static struct net origin,other;
static struct net_device device;
static struct ppp unit;
static unsigned int cases;
'''

production = "\n".join(function(netdev, name) for name in [
    "netdev_ppp_path_advance", "netdev_ppp_path_cookie", "netdev_ppp_path_valid",
])
production += "\n".join(function(ppp, name) for name in [
    "ppp_flow_change_begin", "ppp_flow_change_end", "ppp_flow_policy_allows",
])
production += function(offload, "flow_cls_offload_ppp_valid")
production += "\nstatic void real_move_start(struct net_device *dev){\n\tnetdev_lock(dev);\n" + move_start + "\n}\n"
production += "\nstatic void real_move_publish(struct net_device *dev,struct net *net){\n\tstruct net *net_old=dev_net(dev);\n" + move_publish + "\n}\n"
production += "\nstatic void real_move_finish(struct net_device *dev){\n" + move_finish + "\n}\n"

TEST = r'''
static void setup(u32 generation){
 memset(&origin,0,sizeof(origin));memset(&other,0,sizeof(other));
 memset(&device,0,sizeof(device));memset(&unit,0,sizeof(unit));
 lock_init(&device.mutex);lock_init(&unit.wlock);lock_init(&unit.rlock);
 atomic_set(&device.ppp_channel_generation,generation);dev_net_set(&device,&origin);
 unit.dev=&device;unit.ppp_net=&origin;
 for(unsigned int i=0;i<NUM_NP;i++)unit.npmode[i]=NPMODE_PASS;
 cas_waiting=cas_resume=false;assert(!ppp_locked);
}
static void teardown(void){
 assert(!atomic_load(&origin.active)&&!atomic_load(&other.active));
 assert(atomic_load(&origin.begins)==atomic_load(&origin.ends));
 assert(atomic_load(&other.begins)==atomic_load(&other.ends));
 assert(!atomic_load(&device.moving_ns));
 lock_destroy(&device.mutex);lock_destroy(&unit.wlock);lock_destroy(&unit.rlock);
}
static void change_channel(void){
 ppp_lock(&unit);struct net *n=ppp_flow_change_begin(&unit);
 u32 generation=(u32)atomic_read(&device.ppp_channel_generation);assert(!generation||(generation&1));
 u32 cookie=netdev_ppp_path_cookie(&device);assert(!netdev_ppp_path_valid(&device,cookie));
 sched_yield();ppp_flow_change_end(&unit,n);
 assert(!((u32)atomic_read(&device.ppp_channel_generation)&1));ppp_unlock(&unit);
}
static void move_to(struct net *n){real_move_start(&device);real_move_publish(&device,n);real_move_finish(&device);}
static void ordinary_move(void){
 setup(2);u32 old=netdev_ppp_path_cookie(&device);
 struct flow_cls_offload cls={.ppp_paths={{&device,old},{&device,old}}};
 assert(flow_cls_offload_ppp_valid(&cls));
 assert(ppp_flow_policy_allows(&unit,htons(ETH_P_IP))&&ppp_flow_policy_allows(&unit,htons(ETH_P_IPV6)));
 real_move_start(&device);assert(atomic_read(&device.ppp_channel_generation)==4);
 assert(!netdev_ppp_path_cookie(&device)&&!netdev_ppp_path_valid(&device,old));
 assert(!netdev_ppp_path_valid(&device,4)&&!flow_cls_offload_ppp_valid(&cls));
 assert(!ppp_flow_policy_allows(&unit,htons(ETH_P_IP)));
 real_move_publish(&device,&other);assert(dev_net(&device)==&other);
 assert(!netdev_ppp_path_cookie(&device)&&!flow_cls_offload_ppp_valid(&cls));
 real_move_finish(&device);
 assert(!ppp_flow_policy_allows(&unit,htons(ETH_P_IP))&&!ppp_flow_policy_allows(&unit,htons(ETH_P_IPV6)));
 assert(!flow_cls_offload_ppp_valid(&cls));
 change_channel();assert(atomic_read(&device.ppp_channel_generation)==6);
 move_to(&origin);assert(atomic_read(&device.ppp_channel_generation)==8);
 assert(!flow_cls_offload_ppp_valid(&cls));
 assert(ppp_flow_policy_allows(&unit,htons(ETH_P_IP))&&ppp_flow_policy_allows(&unit,htons(ETH_P_IPV6)));
 cls.ppp_paths[0].cookie=cls.ppp_paths[1].cookie=netdev_ppp_path_cookie(&device);
 assert(flow_cls_offload_ppp_valid(&cls));cases+=12;teardown();
}
static void writer_open_across_move(void){
 setup(2);ppp_lock(&unit);struct net *n=ppp_flow_change_begin(&unit);
 assert(atomic_read(&device.ppp_channel_generation)==3);
 move_to(&other);assert(atomic_read(&device.ppp_channel_generation)==5);
 move_to(&origin);assert(atomic_read(&device.ppp_channel_generation)==7);
 assert(!netdev_ppp_path_valid(&device,netdev_ppp_path_cookie(&device)));
 ppp_flow_change_end(&unit,n);ppp_unlock(&unit);
 assert(atomic_read(&device.ppp_channel_generation)==8&&netdev_ppp_path_valid(&device,8));
 cases+=4;teardown();
}
static void *paused_channel(void *unused){(void)unused;pause_next_cas=true;change_channel();return NULL;}
static void *paused_move(void *unused){(void)unused;pause_next_cas=true;move_to(&other);return NULL;}
static void deterministic_cas_races(void){
 for(unsigned int direction=0;direction<2;direction++)for(unsigned int wrap=0;wrap<2;wrap++){
  setup(wrap?UINT32_MAX-1:2);pthread_t t;
  assert(!pthread_create(&t,NULL,direction?paused_move:paused_channel,NULL));wait_for_cas();
  if(direction){
   /* The mover is paused after moving_ns publication, before its CAS. */
   assert(atomic_load(&device.moving_ns));assert(!netdev_ppp_path_cookie(&device));
   assert(!netdev_ppp_path_valid(&device,(u32)atomic_read(&device.ppp_channel_generation)));
   assert(!ppp_flow_policy_allows(&unit,htons(ETH_P_IP)));change_channel();
  }else{
   /* A PPP writer retained its old CAS expectation across the move. */
   move_to(&other);
  }
  resume_cas();assert(!pthread_join(t,NULL));
  assert((u32)atomic_read(&device.ppp_channel_generation)==(wrap?0:6));
  assert(!netdev_ppp_path_valid(&device,2));
  if(wrap){change_channel();move_to(&origin);assert(!atomic_read(&device.ppp_channel_generation));}
  cases+=4;teardown();
 }
}
static void saturation(void){
 const u32 starts[]={0,UINT32_MAX,UINT32_MAX-1};
 for(unsigned int i=0;i<ARRAY_SIZE(starts);i++){
  setup(starts[i]);move_to(&other);assert(!atomic_read(&device.ppp_channel_generation));
  change_channel();move_to(&origin);assert(!atomic_read(&device.ppp_channel_generation));
  assert(!netdev_ppp_path_cookie(&device)&&!netdev_ppp_path_valid(&device,2));cases+=3;teardown();
 }
 setup(UINT32_MAX-2);move_to(&other);assert((u32)atomic_read(&device.ppp_channel_generation)==UINT32_MAX);
 assert(!netdev_ppp_path_valid(&device,UINT32_MAX));move_to(&origin);
 assert(!atomic_read(&device.ppp_channel_generation));cases+=2;teardown();
}
enum {ROUNDS=3000};
static void *stress_channels(void *unused){(void)unused;for(unsigned int i=0;i<ROUNDS;i++)change_channel();return NULL;}
static void *stress_moves(void *unused){
 (void)unused;for(unsigned int i=0;i<ROUNDS;i++){
  u32 old=netdev_ppp_path_cookie(&device);real_move_start(&device);
  assert(!netdev_ppp_path_cookie(&device)&&!netdev_ppp_path_valid(&device,old));
  assert(!ppp_flow_policy_allows(&unit,htons(ETH_P_IP)));
  real_move_publish(&device,(i&1)?&origin:&other);sched_yield();real_move_finish(&device);
  assert(!netdev_ppp_path_valid(&device,old));
 }return NULL;
}
static void concurrent_stress(void){
 setup(2);pthread_t writers[2],mover;
 for(unsigned int i=0;i<ARRAY_SIZE(writers);i++)assert(!pthread_create(&writers[i],NULL,stress_channels,NULL));
 assert(!pthread_create(&mover,NULL,stress_moves,NULL));
 for(unsigned int i=0;i<ARRAY_SIZE(writers);i++)assert(!pthread_join(writers[i],NULL));
 assert(!pthread_join(mover,NULL));
 assert(atomic_read(&device.ppp_channel_generation)==2+6*ROUNDS);
 assert(dev_net(&device)==&origin&&netdev_ppp_path_valid(&device,netdev_ppp_path_cookie(&device)));
 assert(ppp_flow_policy_allows(&unit,htons(ETH_P_IP)));cases+=3*ROUNDS;teardown();
}
int main(void){ordinary_move();writer_open_across_move();deterministic_cas_races();saturation();concurrent_stress();
 printf("PPP namespace fence: %u cases; real core move blocks, stale cls, move-back, writer parity, controlled CAS retries and sticky wrap PASS (host backend)\n",cases);return 0;}
'''

mutations = {
    "publish_generation_before_moving_flag": (
        move_start,
        move_start.replace("\tWRITE_ONCE(dev->moving_ns, true);\n", "", 1).replace(
            "netdev_ppp_path_advance(dev, 2);",
            "netdev_ppp_path_advance(dev, 2);\n\tWRITE_ONCE(dev->moving_ns, true);", 1)),
    "skip_move_generation": ("netdev_ppp_path_advance(dev, 2);", "(void)dev;"),
    "toggle_writer_parity_on_move": ("netdev_ppp_path_advance(dev, 2);", "netdev_ppp_path_advance(dev, 1);"),
    "discard_failed_cas_retry": ("while (old) {", "if (old) {"),
    "resurrect_zero": ("while (old) {", "while (old || step) {"),
    "wrap_nonzero_on_odd_move": ("if (next < (u32)old)", "if (next == 0)"),
    "capture_cookie_while_moving": ("return smp_load_acquire(&dev->moving_ns) ? 0 : cookie;", "return cookie;"),
    "accept_late_cls_during_move": ("!smp_load_acquire(&dev->moving_ns) &&", "true &&"),
    "decode_path_during_move": ("if (smp_load_acquire(&ppp->dev->moving_ns) ||", "if (false ||"),
    "bypass_cross_namespace_scrub": ("!net_eq(ppp->ppp_net, dev_net(ppp->dev))", "false"),
}
environment = os.environ.copy()
environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
rejected = []
with tempfile.TemporaryDirectory(prefix="ppp-namespace-fence-") as directory:
    c = Path(directory) / "test.c"
    executable = Path(directory) / "test"
    candidates = [("production", production)]
    if args.mutants:
        for name, (old, new) in mutations.items():
            assert old in production, "Missing production mutant anchor: " + name
            candidates.append((name, production.replace(old, new, 1)))
    for name, code in candidates:
        c.write_text(constants + COMMON + code + TEST)
        options = ["-fsanitize=address,undefined", "-fno-sanitize-recover=all"] if name == "production" else []
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-pthread",
                        "-DCONFIG_PPP_FILTER=1", "-Wall", "-Wextra", "-Werror", *options,
                        str(c), "-o", str(executable)], check=True)
        result = subprocess.run([str(executable)], capture_output=True, text=True,
                                env=environment, timeout=45)
        if name == "production":
            assert result.returncode == 0, result.stdout + result.stderr
            print(result.stdout, end="")
        else:
            assert result.returncode == -6 and "Assertion" in result.stderr, (name, result)
            rejected.append(name)
            print("Runtime regression mutant rejected: " + name)

(ROOT / "artifacts").mkdir(exist_ok=True)
(ROOT / "artifacts/ppp-namespace-fence.json").write_text(json.dumps({
    "production_functions_sha256": hashlib.sha256(production.encode()).hexdigest(),
    "mutations_rejected": rejected,
    "sanitizers": ["address", "undefined"],
    "scope": "real inline helpers, PPP writer/policy, late cls validation and core namespace publication blocks with host locks and namespace backend; deterministic pthread/CAS races, not actual kernel netns or LKMM execution",
    "hardware_verified": False,
}, indent=2) + "\n")
