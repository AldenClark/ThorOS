#!/usr/bin/env python3
"""Run real PPP handoff, path capture and late-HW-ADD functions on a host model.

Requires a kernel prepared through patch 224. Production functions are extracted
unchanged; locks, devices, routes and MMIO admission are explicit test backends.
This does not establish silicon performance or full PPP protocol-policy support.
"""
import argparse
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--kernel", type=Path, required=True)
args = parser.parse_args()
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def source(path):
    return (args.kernel / path).read_text()


def function(text, name):
    match = re.search(r"\b" + re.escape(name) + r"\([^;]*?\)\s*\{", text)
    if not match:
        raise AssertionError(f"Production function missing: {name}")
    start = text.rfind("\n", 0, match.start()) + 1
    if text[start:match.start()].strip() == "":
        start = text.rfind("\n", 0, start - 1) + 1
    end = text.index("{", match.start()) + 1
    depth = 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end] + "\n"


ppp = source("drivers/net/ppp/ppp_generic.c")
netdev = source("include/linux/netdevice.h")
flow_header = source("include/net/netfilter/nf_flow_table.h")
flow_offload = source("include/net/flow_offload.h")
path = source("net/netfilter/nf_flow_table_path.c")
xt = source("net/netfilter/xt_FLOWOFFLOAD.c")
core = source("net/netfilter/nf_flow_table_core.c")
offload = source("net/netfilter/nf_flow_table_offload.c")
fe = (ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c-fe.c").read_text()

assert "atomic_set(&dev->ppp_channel_generation, 2)" in function(ppp, "ppp_setup")
unregister = function(ppp, "ppp_unregister_channel")
assert "WRITE_ONCE(pch->chan, NULL)" not in unregister
assert unregister.index("down_write") < unregister.index("ppp_channel_unpublish") < unregister.index("up_write")
assert unregister.index("ppp_channel_unpublish") < unregister.index("ppp_disconnect_channel")
assert "flow_tuple->out.ppp_cookie = route->tuple[dir].out.ppp_cookie" in function(core, "flow_offload_fill_route")
tuple_dispatch = function(offload, "nf_flow_offload_tuple")
assert tuple_dispatch.index("nf_flow_offload_ppp_prepare") < tuple_dispatch.index("block_cb->cb")
assert tuple_dispatch.index("block_cb->cb") < tuple_dispatch.index("nf_flow_offload_ppp_release")
assert re.search(r"if \(!nf_flow_offload_ppp_prepare\([^;]*?return 0;", tuple_dispatch, re.S), "Tuple dispatch returns a callback count, never a negative errno"

COMMON = r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
typedef uint8_t u8; typedef uint16_t u16,__u16,__be16; typedef uint32_t u32;
#define ETH_ALEN 6
#define ARPHRD_ETHER 1
#define ARPHRD_PPP 512
#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10
#define NF_FLOW_OFFLOAD_ROUTE 1
#define NF_FLOW_TABLE_ENCAP_MAX 2
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define READ_ONCE(x) (x)
#define WARN_ON_ONCE(x) assert(!(x))
#define smp_rmb() atomic_thread_fence(memory_order_seq_cst)
typedef _Atomic unsigned int atomic_t;
#define atomic_read(p) atomic_load_explicit((p),memory_order_seq_cst)
#define atomic_set(p,v) atomic_store_explicit((p),(unsigned int)(v),memory_order_seq_cst)
static inline unsigned int atomic_inc_return(atomic_t *p){return atomic_fetch_add_explicit(p,1,memory_order_seq_cst)+1U;}
struct lock {pthread_mutex_t m;pthread_t owner;bool held;};
static _Thread_local unsigned int held_locks;
static void init_lock(struct lock *l){pthread_mutex_init(&l->m,NULL);l->held=false;}
static void lock(struct lock *l){assert(!pthread_mutex_lock(&l->m));l->owner=pthread_self();l->held=true;held_locks++;}
static void unlock(struct lock *l){assert(l->held&&pthread_equal(l->owner,pthread_self()));l->held=false;held_locks--;assert(!pthread_mutex_unlock(&l->m));}
static bool lock_owned(struct lock *l){return l->held&&pthread_equal(l->owner,pthread_self());}
#define spin_lock(l) lock(l)
#define spin_unlock(l) unlock(l)
#define spin_lock_bh(l) lock(l)
#define spin_unlock_bh(l) unlock(l)
#define mutex_lock(l) lock(l)
#define mutex_unlock(l) unlock(l)
#define lockdep_is_held(l) lock_owned(l)
#define lockdep_assert_held(l) assert(lock_owned(l))
struct net {unsigned int unused;};
struct net_device {unsigned int type,addr_len,ifindex,refs;unsigned long priv_flags;int hard_header_len;atomic_t ppp_channel_generation;struct net *net;};
static struct net net;
struct gate {pthread_mutex_t lock;unsigned int active,begins,ends;bool open;};
static struct gate gate={.lock=PTHREAD_MUTEX_INITIALIZER};
static struct net *rtl9617c_switch_policy_begin(struct net_device *d){assert(d&&d->net==&net);pthread_mutex_lock(&gate.lock);gate.active++;gate.begins++;gate.open=false;pthread_mutex_unlock(&gate.lock);return &net;}
static void rtl9617c_switch_policy_end(struct net *n){assert(n==&net);pthread_mutex_lock(&gate.lock);assert(gate.active);gate.active--;gate.ends++;pthread_mutex_unlock(&gate.lock);}
static bool gate_open(void){pthread_mutex_lock(&gate.lock);bool v=gate.open;pthread_mutex_unlock(&gate.lock);return v;}
static void rearm(void){pthread_mutex_lock(&gate.lock);assert(!gate.active);gate.open=true;pthread_mutex_unlock(&gate.lock);}
static _Thread_local struct net_device *mutating_dev;
static void publication(void){if(!mutating_dev)return;pthread_mutex_lock(&gate.lock);assert(gate.active&&!gate.open);pthread_mutex_unlock(&gate.lock);u32 c=atomic_read(&mutating_dev->ppp_channel_generation);assert(!c||(c&1));}
#define WRITE_ONCE(x,v) ((x)==(v)?((x)=(v)):(publication(),(x)=(v)))
#define rcu_dereference_protected(p,c) (assert(c),(p))
#define rcu_assign_pointer(p,v) do{publication();(p)=(v);}while(0)
#define RCU_INIT_POINTER(p,v) do{publication();(p)=(v);}while(0)
static _Thread_local unsigned int rcu_depth;
#define rcu_read_lock() (++rcu_depth)
#define rcu_read_unlock() do{assert(rcu_depth);--rcu_depth;}while(0)
static void synchronize_net(void){assert(!held_locks);}
static void dev_hold(struct net_device *d){assert(rcu_depth);d->refs++;}
static void dev_put(struct net_device *d){assert(d->refs);d->refs--;}
struct file_model {unsigned int hdrlen;atomic_t refcnt;int rwait;};
#define refcount_inc(p) ((void)atomic_fetch_add((p),1))
#define refcount_dec_and_test(p) (atomic_fetch_sub((p),1)==1)
struct node {bool attached;};
struct ppp {struct lock wlock,rlock;struct net_device *dev;struct file_model file;struct node channels;unsigned int n_channels;};
struct ppp_channel {bool direct_xmit;};
struct channel {struct lock upl,downl;struct ppp *ppp;void *bridge;struct ppp_channel *chan;struct net *chan_net;struct file_model file;struct node clist;};
struct ppp_net {struct lock all_ppp_mutex;};
static struct ppp unit;
static struct ppp_net pn;
static struct net_device device;
#define ppp_lock(p) do{spin_lock_bh(&(p)->wlock);spin_lock_bh(&(p)->rlock);mutating_dev=(p)->dev;}while(0)
#define ppp_unlock(p) do{mutating_dev=NULL;spin_unlock_bh(&(p)->rlock);spin_unlock_bh(&(p)->wlock);}while(0)
static struct ppp_net *ppp_pernet(struct net *n){assert(n==&net);return &pn;}
static struct ppp *ppp_find_unit(struct ppp_net *p,int i){assert(p==&pn&&lock_owned(&p->all_ppp_mutex));return i==1?&unit:NULL;}
#define IFF_NO_QUEUE 1UL
static void list_add_tail_rcu(struct node *n,struct node *head){(void)head;publication();assert(!n->attached);n->attached=true;}
static void list_del_rcu(struct node *n){publication();assert(n->attached);n->attached=false;}
static void wake_up_interruptible(int *w){(void)w;}
static void ppp_destroy_interface(struct ppp *p){(void)p;assert(!"unit reference must remain");}
static void setup(void){device=(struct net_device){.type=ARPHRD_PPP,.addr_len=0,.ifindex=10,.refs=1,.net=&net};atomic_set(&device.ppp_channel_generation,2);unit.dev=&device;unit.n_channels=0;unit.file.hdrlen=0;atomic_set(&unit.file.refcnt,1);init_lock(&unit.wlock);init_lock(&unit.rlock);init_lock(&pn.all_ppp_mutex);gate.active=gate.begins=gate.ends=0;gate.open=true;}
static void channel_init(struct channel *c,struct ppp_channel *driver){memset(c,0,sizeof(*c));init_lock(&c->upl);init_lock(&c->downl);c->chan=driver;c->chan_net=&net;c->file.hdrlen=8;}
'''

NET_HELPERS = function(netdev, "netdev_ppp_path_cookie") + function(netdev, "netdev_ppp_path_valid")
PPP_FUNCTIONS = "\n".join(function(ppp, n) for n in [
    "ppp_flow_change_begin", "ppp_flow_change_end", "ppp_channel_unpublish",
    "ppp_connect_channel", "ppp_disconnect_channel",
])

ROUTE_MODEL = r'''
enum flow_offload_tuple_dir {FLOW_OFFLOAD_DIR_ORIGINAL,FLOW_OFFLOAD_DIR_REPLY,FLOW_OFFLOAD_DIR_MAX};
enum flow_offload_xmit_type {FLOW_OFFLOAD_XMIT_UNSPEC,FLOW_OFFLOAD_XMIT_NEIGH,FLOW_OFFLOAD_XMIT_XFRM,FLOW_OFFLOAD_XMIT_DIRECT};
enum ip_conntrack_dir {IP_CT_DIR_ORIGINAL,IP_CT_DIR_REPLY};
struct neighbour {u8 ha[6],nud_state;int lock;};
#define NUD_VALID 0xde
struct dst_entry {struct net_device *dev;bool valid;struct neighbour *neigh;};
static struct dst_entry *dst_check(struct dst_entry *d,u32 c){(void)c;return d&&d->valid?d:NULL;}
static unsigned int ip_dst_mtu_maybe_forward(const struct dst_entry *d,bool forwarding){assert(d&&forwarding);return 1500;}
static unsigned int ip6_dst_mtu_maybe_forward(const struct dst_entry *d,bool forwarding){return ip_dst_mtu_maybe_forward(d,forwarding);}
static struct neighbour *dst_neigh_lookup(struct dst_entry *d,const void *a){(void)a;return d->neigh;}
#define read_lock_bh(l) ((void)(l))
#define read_unlock_bh(l) ((void)(l))
#define ether_addr_equal(a,b) (!memcmp((a),(b),ETH_ALEN))
#define neigh_release(n) ((void)(n))
struct nf_conn {int unused;};
'''
STRUCTURES = "\n".join(re.search(p, flow_header, re.S)[0] for p in [
    r"struct flow_offload_tuple \{.*?\n\};", r"struct nf_flow_route \{.*?\n\};",
]) + r'''
struct flow_offload_tuple_rhash {struct flow_offload_tuple tuple;};
struct flow_offload {struct flow_offload_tuple_rhash tuplehash[2];unsigned int type;};
struct flow_cls_common_offload {unsigned int chain_index;};
struct flow_rule {unsigned int unused;};
struct flow_stats {unsigned int unused;};
enum flow_cls_command {FLOW_CLS_REPLACE,FLOW_CLS_DESTROY,FLOW_CLS_STATS};
''' + re.search(r"struct flow_cls_offload \{.*?\n\};", flow_offload, re.S)[0] + "\n"

PATH_BACKEND = r'''
struct net_device_path_stack {unsigned int unused;};
struct nft_flowtable {int data;};
static unsigned int mutate_path,decodes;
static struct net_device physical={.type=ARPHRD_ETHER,.addr_len=6,.ifindex=7,.refs=1};
static void change_cookie(void){ppp_lock(&unit);struct net *n=ppp_flow_change_begin(&unit);ppp_flow_change_end(&unit,n);ppp_unlock(&unit);}
static int nft_dev_fill_forward_path(const struct nf_flow_route *r,const struct dst_entry *d,const struct nf_conn *c,enum ip_conntrack_dir dir,u8 *ha,struct net_device_path_stack *s){(void)r;(void)d;(void)c;(void)dir;(void)s;memset(ha,1,6);decodes++;if(mutate_path)change_cookie();return 0;}
#define nf_dev_fill_forward_path nft_dev_fill_forward_path
'''
INFO = re.search(r"struct nft_forward_info \{.*?\n\};", path, re.S)[0] + "\n"
INFO += re.search(r"struct nf_forward_info \{.*?\n\};", xt, re.S)[0].replace("struct id {", "struct xt_id {") + "\n"
PATH_STUBS = r'''
static int nft_dev_path_info(const struct net_device_path_stack *s,struct nft_forward_info *i,const u8 *ha,int *data){(void)s;(void)ha;(void)data;i->indev=i->outdev=i->hw_outdev=&physical;i->xmit_type=FLOW_OFFLOAD_XMIT_DIRECT;return 0;}
static int nf_dev_path_info(const struct net_device_path_stack *s,struct nf_forward_info *i,const u8 *ha){(void)s;(void)ha;i->indev=i->outdev=i->hw_outdev=&physical;i->xmit_type=FLOW_OFFLOAD_XMIT_DIRECT;return 0;}
static bool nft_flowtable_find_dev(const struct net_device *d,struct nft_flowtable *f){(void)f;return d==&physical;}
'''

FE_MODEL = r'''
enum tc_setup_type {TC_SETUP_CLSFLOWER};
struct rtl_fe {struct lock lock;bool shutting_down;unsigned int misses;};
struct rtl_fe_port {struct rtl_fe *fe;bool retired;};
struct rtl_fe_flow {struct rtl_fe_port *input;bool deleting;};
static struct rtl_fe hardware;
static struct rtl_fe_port hardware_port={.fe=&hardware};
static bool hw_rule,pause_install;
static pthread_mutex_t install_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t install_cond=PTHREAD_COND_INITIALIZER;
static bool installing,resume_install;
static int fe_replace(struct rtl_fe_port *p,struct flow_cls_offload *cls){(void)cls;assert(lock_owned(&p->fe->lock));if(pause_install){pthread_mutex_lock(&install_mutex);installing=true;pthread_cond_broadcast(&install_cond);while(!resume_install)pthread_cond_wait(&install_cond,&install_mutex);pthread_mutex_unlock(&install_mutex);}hw_rule=true;return 0;}
static struct rtl_fe_flow *fe_flow(struct rtl_fe *f,unsigned long c){(void)f;(void)c;return NULL;}
static int fe_delete(struct rtl_fe *f,struct rtl_fe_flow *x){(void)f;(void)x;return 0;}
static int fe_stats(struct rtl_fe *f,struct rtl_fe_flow *x,struct flow_cls_offload *c){(void)f;(void)x;(void)c;return 0;}
static void fe_collect_ports(struct rtl_fe *f){(void)f;}
static void worker_rearm(void){mutex_lock(&hardware.lock);hw_rule=false;rearm();mutex_unlock(&hardware.lock);}
'''

PRODUCTION = "\n".join([
    function(flow_offload, "flow_cls_offload_ppp_valid"),
    function(path, "nft_dev_forward_path"), function(xt, "nf_dev_forward_path"),
    function(core, "nf_flow_direct_mtu_valid"),
    function(core, "nf_flow_direct_route_changed"), function(core, "nf_flow_direct_neigh_valid"),
    function(offload, "nf_flow_offload_ppp_release"), function(offload, "nf_flow_offload_ppp_prepare"),
    function(fe, "fe_block_callback"),
])

MAIN = r'''
static unsigned int cases;
struct stress {struct channel channel;struct ppp_channel backend;};
static void *writer(void *data){struct stress *s=data;for(unsigned int i=0;i<500;i++){assert(!ppp_connect_channel(&s->channel,1));assert(!ppp_disconnect_channel(&s->channel));}return NULL;}
static void *add(void *data){int ret=fe_block_callback(TC_SETUP_CLSFLOWER,data,&hardware_port);assert(!ret);return NULL;}
static void flow_init(struct flow_offload *f,struct dst_entry *d){memset(f,0,sizeof(*f));f->type=NF_FLOW_OFFLOAD_ROUTE;for(int i=0;i<2;i++){f->tuplehash[i].tuple.xmit_type=FLOW_OFFLOAD_XMIT_DIRECT;f->tuplehash[i].tuple.l3proto=NFPROTO_IPV4;f->tuplehash[i].tuple.mtu=1500;f->tuplehash[i].tuple.out.route_dst=d;f->tuplehash[i].tuple.out.ppp_cookie=netdev_ppp_path_cookie(&device);}}
int main(void){
 setup();init_lock(&hardware.lock);
 struct channel c;struct ppp_channel driver={0};channel_init(&c,&driver);
 assert(ppp_connect_channel(&c,99)==-ENXIO);assert(!gate.begins&&atomic_read(&device.ppp_channel_generation)==2);cases++;
 c.bridge=&c;assert(ppp_connect_channel(&c,1)==-EINVAL);c.bridge=NULL;assert(!gate.begins);cases++;
 c.chan=NULL;assert(ppp_connect_channel(&c,1)==-ENOTCONN);c.chan=&driver;assert(!gate.begins);cases++;
 assert(!ppp_connect_channel(&c,1));assert(c.ppp==&unit&&unit.n_channels==1&&atomic_read(&device.ppp_channel_generation)==4&&!gate_open());cases++;
 unsigned int before=gate.begins;assert(ppp_connect_channel(&c,1)==-EINVAL);assert(gate.begins==before);cases++;
 assert(!ppp_disconnect_channel(&c));assert(!c.ppp&&!unit.n_channels&&atomic_read(&device.ppp_channel_generation)==6);before=gate.begins;assert(ppp_disconnect_channel(&c)==-EINVAL&&gate.begins==before);cases++;
 assert(!ppp_connect_channel(&c,1));u32 cookie=netdev_ppp_path_cookie(&device);rearm();ppp_channel_unpublish(&c);assert(!c.chan&&!gate_open()&&!netdev_ppp_path_valid(&device,cookie));before=gate.begins;ppp_channel_unpublish(&c);assert(before==gate.begins);assert(!ppp_disconnect_channel(&c));cases++;
 struct stress stress[4]={0};pthread_t writers[4];for(unsigned int i=0;i<4;i++){channel_init(&stress[i].channel,&stress[i].backend);pthread_create(&writers[i],NULL,writer,&stress[i]);}for(unsigned int i=0;i<4;i++)pthread_join(writers[i],NULL);assert(!unit.n_channels&&!gate.active&&gate.begins==gate.ends&&!(atomic_read(&device.ppp_channel_generation)&1)&&atomic_read(&unit.file.refcnt)==1);cases+=4000;
 struct dst_entry dst={.dev=&device,.valid=true};struct nf_flow_route route={0};route.tuple[0].dst=&dst;struct nf_conn ct={0};struct nft_flowtable ft={0};struct net_device *devs[2]={0};
 cookie=netdev_ppp_path_cookie(&device);assert(!nft_dev_forward_path(&route,&ct,0,&ft));assert(route.tuple[0].out.ppp_cookie==cookie);assert(!nf_dev_forward_path(&route,&ct,0,devs)&&route.tuple[0].out.ppp_cookie==cookie);cases+=2;
 mutate_path=1;assert(nft_dev_forward_path(&route,&ct,0,&ft)==-ENOENT);assert(nf_dev_forward_path(&route,&ct,0,devs)==-ENOENT);mutate_path=0;cases+=2;
 ppp_lock(&unit);struct net *scope=ppp_flow_change_begin(&unit);unsigned int old_decodes=decodes;assert(nft_dev_forward_path(&route,&ct,0,&ft)==-ENOENT&&decodes==old_decodes);assert(nf_dev_forward_path(&route,&ct,0,devs)==-ENOENT);ppp_flow_change_end(&unit,scope);ppp_unlock(&unit);cases+=2;
 struct flow_offload f;flow_init(&f,&dst);assert(!nf_flow_direct_route_changed(&f)&&nf_flow_direct_neigh_valid(&f,0));change_cookie();assert(nf_flow_direct_route_changed(&f)&&!nf_flow_direct_neigh_valid(&f,0));cases+=2;
 flow_init(&f,&dst);struct flow_cls_offload cls={.command=FLOW_CLS_REPLACE};assert(nf_flow_offload_ppp_prepare(&cls,&f)&&device.refs==3&&flow_cls_offload_ppp_valid(&cls));change_cookie();worker_rearm();assert(fe_block_callback(TC_SETUP_CLSFLOWER,&cls,&hardware_port)==-EAGAIN&&!hw_rule);nf_flow_offload_ppp_release(&cls);assert(device.refs==1);cases++;
 flow_init(&f,&dst);f.tuplehash[1].tuple.out.ppp_cookie-=2;assert(!nf_flow_offload_ppp_prepare(&cls,&f)&&device.refs==1&&!cls.ppp_paths[0].dev&&!cls.ppp_paths[1].dev);cases++;
 flow_init(&f,&dst);assert(nf_flow_offload_ppp_prepare(&cls,&f));dst.dev=&physical;assert(device.refs==3);assert(!nf_flow_offload_ppp_prepare(&(struct flow_cls_offload){0},&f));nf_flow_offload_ppp_release(&cls);assert(device.refs==1);dst.dev=&device;cases++;
 flow_init(&f,&dst);assert(nf_flow_offload_ppp_prepare(&cls,&f));pause_install=true;pthread_t install;pthread_create(&install,NULL,add,&cls);pthread_mutex_lock(&install_mutex);while(!installing)pthread_cond_wait(&install_cond,&install_mutex);pthread_mutex_unlock(&install_mutex);change_cookie();assert(!gate_open());assert(pthread_mutex_trylock(&hardware.lock.m)==EBUSY);pthread_mutex_lock(&install_mutex);resume_install=true;pthread_cond_broadcast(&install_cond);pthread_mutex_unlock(&install_mutex);pthread_join(install,NULL);assert(hw_rule&&!gate_open());worker_rearm();assert(!hw_rule&&gate_open());nf_flow_offload_ppp_release(&cls);pause_install=false;cases++;
 atomic_set(&device.ppp_channel_generation,UINT32_MAX-1);change_cookie();assert(!atomic_read(&device.ppp_channel_generation));change_cookie();assert(!atomic_read(&device.ppp_channel_generation));assert(nft_dev_forward_path(&route,&ct,0,&ft)==-ENOENT);assert(nf_dev_forward_path(&route,&ct,0,devs)==-ENOENT);assert(!netdev_ppp_path_valid(&device,0));flow_init(&f,&dst);assert(nf_flow_direct_route_changed(&f)&&!nf_flow_direct_neigh_valid(&f,0));assert(!nf_flow_offload_ppp_prepare(&cls,&f)&&device.refs==1);cases+=5;
 dst.dev=&physical;assert(!nft_dev_forward_path(&route,&ct,0,&ft)&&!route.tuple[0].out.ppp_cookie);assert(!nf_dev_forward_path(&route,&ct,0,devs)&&!route.tuple[0].out.ppp_cookie);assert(!held_locks&&!rcu_depth&&!gate.active&&gate.begins==gate.ends);cases+=2;
 printf("PPP generation: %u cases; real channel mutations, concurrent writers, path capture, CPU/GC, callback device refs and late HW ADD fences PASS (host model)\n",cases);
 return 0;
}
'''

text = COMMON + NET_HELPERS + PPP_FUNCTIONS + ROUTE_MODEL + STRUCTURES + PATH_BACKEND + INFO + PATH_STUBS + FE_MODEL + PRODUCTION + MAIN
mutations = {
    "missing_prepublication_gate": (
        "policy = rtl9617c_switch_policy_begin(ppp->dev);", "policy = &net;"),
    "stamp_old_path_with_new_cookie": (
        "if (ppp_cookie && !netdev_ppp_path_valid(dst->dev, ppp_cookie))",
        "if (false && ppp_cookie && !netdev_ppp_path_valid(dst->dev, ppp_cookie))"),
    "missing_driver_mutex_cookie_check": (
        "if(!flow_cls_offload_ppp_valid(cls)){ret=-EAGAIN;break;}",
        "if(false){ret=-EAGAIN;break;}"),
    "missing_callback_device_reference": ("dev_hold(dev);", "(void)dev;"),
    "resurrect_wrapped_cookie": (
        "if (atomic_read(&ppp->dev->ppp_channel_generation))", "if (true)"),
    "skip_ppp_cpu_gc_validation": (
        "if ((tuple->out.ppp_cookie ||", "if (false && (tuple->out.ppp_cookie ||"),
}
with tempfile.TemporaryDirectory(prefix="rtl9617c-ppp-generation-") as directory:
    c = Path(directory) / "test.c"
    executable = Path(directory) / "test"
    c.write_text(text)
    subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-pthread", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", str(c), "-o", str(executable)], check=True)
    env = os.environ.copy()
    env.setdefault("ASAN_OPTIONS", "detect_leaks=0")
    subprocess.run([str(executable)], check=True, env=env, timeout=45)
    for name, (original, changed) in mutations.items():
        assert original in text, f"Missing production mutation anchor: {name}"
        c.write_text(text.replace(original, changed))
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-pthread", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", str(c), "-o", str(executable)], check=True)
        result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=45)
        assert result.returncode == -6 and "Assertion" in result.stderr, (
            f"Mutant {name} must be rejected by an assertion, not a compiler error or unrelated crash: {result}"
        )
    print(f"PPP generation: {len(mutations)} negative production mutations rejected")
