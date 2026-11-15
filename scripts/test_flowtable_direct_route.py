#!/usr/bin/env python3
"""Execute DIRECT route ownership, lookup and GC using prepared kernel code.

Tuple/route layouts and production functions are extracted unchanged. The
dst/ARP/ND backend models Linux's IPv4 generation and IPv6 cookie contracts;
it is not a live FIB, packet, device, ASIC or throughput test. In particular
hardware withdrawal remains asynchronous after the GC validation interval.
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
args = parser.parse_args()
core = (args.kernel / "net/netfilter/nf_flow_table_core.c").read_text()
header = (args.kernel / "include/net/netfilter/nf_flow_table.h").read_text()
netdevice = (args.kernel / "include/linux/netdevice.h").read_text()


def function(name, source=core):
    match = re.search(r"^.*\b" + name + r"\([^;]*?\)\s*\{", source, re.M)
    if not match:
        raise AssertionError(f"Production function missing: {name}")
    start, end = match.start(), source.index("{", match.start()) + 1
    if source[start:].startswith(name + "("):
        start = source.rfind("\n", 0, start - 1) + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end] + "\n"


COMMON = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
typedef uint8_t u8;typedef uint16_t u16,__be16;typedef uint32_t u32;
#define ETH_ALEN 6
#define ARPHRD_ETHER 1
#define ARPHRD_PPP 512
#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10
#define NF_FLOW_OFFLOAD_ROUTE 1
#define NF_FLOW_TABLE_ENCAP_MAX 2
#define BIT(n) (1UL<<(n))
#define READ_ONCE(x) (x)
#define WARN_ON_ONCE(x) assert(!(x))
#define unlikely(x) (x)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define test_bit(n,p) (!!(*(p)&BIT(n)))
#define test_bit_acquire(n,p) test_bit(n,p)
static bool test_and_set_bit(unsigned int n,unsigned long *p){bool old=test_bit(n,p);*p|=BIT(n);return old;}
enum flow_offload_tuple_dir {FLOW_OFFLOAD_DIR_ORIGINAL,FLOW_OFFLOAD_DIR_REPLY,FLOW_OFFLOAD_DIR_MAX};
enum flow_offload_xmit_type {FLOW_OFFLOAD_XMIT_UNSPEC,FLOW_OFFLOAD_XMIT_NEIGH,FLOW_OFFLOAD_XMIT_XFRM,FLOW_OFFLOAD_XMIT_DIRECT,FLOW_OFFLOAD_XMIT_TC};
enum {NF_FLOW_TEARDOWN,NF_FLOW_HW,NF_FLOW_HW_DYING,NF_FLOW_HW_DEAD,NF_FLOW_CLOSING,NF_FLOW_PENDING,NF_FLOW_SNAT,NF_FLOW_DNAT};
#define GFP_ATOMIC 0
#define IPS_SRC_NAT BIT(0)
#define IPS_DST_NAT BIT(1)
#define __set_bit(n,p) (*(p)|=BIT(n))
enum {NUD_INCOMPLETE=1,NUD_REACHABLE=2,NUD_STALE=4,NUD_DELAY=8,NUD_PROBE=16,NUD_FAILED=32,NUD_NOARP=64,NUD_PERMANENT=128};
#define NUD_VALID (NUD_REACHABLE|NUD_STALE|NUD_DELAY|NUD_PROBE|NUD_NOARP|NUD_PERMANENT)
struct net {unsigned int id;};
typedef unsigned int atomic_t;
#define atomic_read(p) (*(p))
#define smp_rmb() ((void)0)
struct net_device {unsigned int ifindex,type,addr_len;atomic_t ppp_channel_generation;};
struct neighbour {u8 ha[ETH_ALEN],nud_state;unsigned int refs,lock;};
struct dst_entry {
 struct net_device *dev;struct neighbour *neigh;
 unsigned int refs,held_generation,current_generation,cookie,family;
 bool alive;const void *expected_daddr;
};
struct rcu_head {int unused;};
struct nf_conn {bool dying,offloaded;union {unsigned int refs;struct {unsigned int use;}ct_general;};unsigned long status;};
'''

STRUCTURES = "\n".join(re.search(pattern, header, re.S)[0] for pattern in [
    r"struct flow_offload_tuple \{.*?\n\};", r"struct nf_flow_route \{.*?\n\};",
]) + r'''
struct flow_offload_tuple_rhash {struct flow_offload_tuple tuple;};
struct flow_offload {
 struct flow_offload_tuple_rhash tuplehash[2];struct nf_conn *ct;
 unsigned int type;unsigned long flags;struct rcu_head rcu_head;bool expired;
};
struct nf_flowtable {struct flow_offload_tuple_rhash *rhashtable;struct net *net;};
struct nf_br_utils {bool (*fdb_valid_dst)(struct net_device *,const u8 *,u16);};
'''

BACKEND = r'''
static unsigned int lookups,checks,stats,extensions,deletes,freed,ct_puts,rcu_depth,cases;
static struct nf_br_utils *nf_br_utils_hook;
static struct net_device *bridge_egress;
static bool bridge_valid=true;
static int nf_flow_offload_rhash_params;
static struct net_device logical[2],physical[2];
static struct neighbour neighbors[2];
static struct dst_entry routes[2];
static struct nf_conn ct;
static struct net ns;
static struct nf_flowtable table;
static struct flow_offload *heap_flow;
static bool allocation_failure;
static void flow_offload_free(struct flow_offload *);
static void *kzalloc(size_t size,unsigned int flags){(void)flags;if(allocation_failure)return NULL;heap_flow=calloc(1,size);return heap_flow;}
static void refcount_inc(unsigned int *ref){assert(*ref);(*ref)++;}
static void flow_offload_fill_dir(struct flow_offload *flow,enum flow_offload_tuple_dir dir){flow->tuplehash[dir].tuple.dir=dir;}
static void rcu_read_lock(void){rcu_depth++;}
static void rcu_read_unlock(void){assert(rcu_depth);rcu_depth--;}
#define rcu_dereference(x) (x)
static struct net *read_pnet(struct net **net){return *net;}
static struct net_device *dev_get_by_index_rcu(struct net *net,unsigned int idx){assert(net==&ns && rcu_depth);return bridge_egress && bridge_egress->ifindex==idx?bridge_egress:NULL;}
static struct net_device *__vlan_find_dev_deep_rcu(struct net_device *dev,u16 proto,u16 vid){(void)proto;(void)vid;return dev;}
static bool fdb_valid(struct net_device *dev,const u8 *mac,u16 vid){(void)mac;(void)vid;assert(dev==bridge_egress);return bridge_valid;}
static struct dst_entry *dst_rt6_info(struct dst_entry *dst){assert(dst->family==NFPROTO_IPV6);return dst;}
static u32 rt6_get_cookie(struct dst_entry *dst){assert(dst->family==NFPROTO_IPV6 && dst->refs);return dst->cookie;}
static struct dst_entry *dst_check(struct dst_entry *dst,u32 cookie){
 assert(dst && dst->refs);checks++;
 if(!dst->alive || dst->held_generation!=dst->current_generation)return NULL;
 if(dst->family==NFPROTO_IPV6 && cookie!=dst->cookie)return NULL;
 if(dst->family==NFPROTO_IPV4)assert(cookie==0);return dst;
}
static unsigned int ip_dst_mtu_maybe_forward(const struct dst_entry *dst,bool f){assert(dst && f && dst->refs);return 1500;}
static unsigned int ip6_dst_mtu_maybe_forward(const struct dst_entry *dst,bool f){return ip_dst_mtu_maybe_forward(dst,f);}
static void dst_release(struct dst_entry *dst){if(dst){assert(dst->refs);dst->refs--;}}
static struct neighbour *dst_neigh_lookup(struct dst_entry *dst,const void *daddr){
 assert(dst->refs && dst->alive && dst->dev->type==ARPHRD_ETHER);
 assert(daddr==dst->expected_daddr); /* opposite tuple's post-NAT destination */
 assert(dst->dev==&logical[0] || dst->dev==&logical[1]); /* never resolved physical device */
 lookups++;if(dst->neigh)dst->neigh->refs++;return dst->neigh;
}
static void read_lock_bh(unsigned int *lock){assert(!*lock);*lock=1;}
static void read_unlock_bh(unsigned int *lock){assert(*lock);*lock=0;}
static bool ether_addr_equal(const u8 *a,const u8 *b){return !memcmp(a,b,ETH_ALEN);}
static void neigh_release(struct neighbour *neigh){assert(neigh->refs && !neigh->lock);neigh->refs--;}
static void nf_ct_put(struct nf_conn *conn){assert(conn->refs);conn->refs--;ct_puts++;}
static void kfree(void *ptr){assert(ptr);freed++;if(ptr==heap_flow){free(ptr);heap_flow=NULL;}} /* remaining cases use stack-backed lifetime fixtures */
static void call_rcu(struct rcu_head *rcu,void (*fn)(struct rcu_head *)){fn(rcu);}
static void *rhashtable_lookup(void *h,void *key,int params){(void)key;(void)params;return *(void **)h;}
static bool nf_ct_is_dying(struct nf_conn *conn){return conn->dying;}
static bool nf_flow_has_expired(struct flow_offload *flow){return flow->expired;}
static bool nf_flow_bridge_changed(const struct flow_offload *flow){(void)flow;return !bridge_valid;}
static bool nf_flow_custom_gc(struct nf_flowtable *t,struct flow_offload *flow){(void)t;(void)flow;return false;}
static void flow_offload_teardown(struct flow_offload *flow){flow->flags|=BIT(NF_FLOW_TEARDOWN);flow->ct->offloaded=false;}
static void nf_flow_table_extend_ct_timeout(struct nf_conn *conn){assert(conn->offloaded);extensions++;}
static void nf_flow_offload_stats(struct nf_flowtable *t,struct flow_offload *flow){(void)t;assert(!test_bit(NF_FLOW_TEARDOWN,&flow->flags));stats++;}
static void nf_flow_offload_del(struct nf_flowtable *t,struct flow_offload *flow){(void)t;flow->flags|=BIT(NF_FLOW_HW_DYING);deletes+=2;}
static void flow_offload_del(struct nf_flowtable *t,struct flow_offload *flow){(void)t;flow_offload_free(flow);}
'''

TEST = r'''
static void setup(struct flow_offload *flow,unsigned int family,bool hw){
 *flow=(struct flow_offload){.ct=&ct,.flags=hw?BIT(NF_FLOW_HW):0};
 ct=(struct nf_conn){.offloaded=true,.refs=1};table=(struct nf_flowtable){.net=&ns};
 lookups=checks=stats=extensions=deletes=freed=ct_puts=rcu_depth=0;bridge_valid=true;nf_br_utils_hook=NULL;bridge_egress=NULL;
 struct nf_flow_route route={0};
 for(unsigned int dir=0;dir<2;dir++){
  logical[dir]=(struct net_device){.ifindex=10+dir,.type=ARPHRD_ETHER,.addr_len=6};
  physical[dir]=(struct net_device){.ifindex=2+dir,.type=ARPHRD_ETHER,.addr_len=6};
  neighbors[dir]=(struct neighbour){.ha={2,0,0,0,0,dir+1},.nud_state=NUD_REACHABLE};
  routes[dir]=(struct dst_entry){.dev=&logical[dir],.neigh=&neighbors[dir],.refs=1,.family=family,
   .held_generation=5,.current_generation=5,.cookie=123+dir,.alive=true,
   .expected_daddr=&flow->tuplehash[!dir].tuple.src_v4};
  route.tuple[dir].dst=&routes[dir];route.tuple[dir].xmit_type=FLOW_OFFLOAD_XMIT_DIRECT;
  route.tuple[dir].out.ifindex=route.tuple[dir].out.hw_ifindex=physical[dir].ifindex;
  memcpy(route.tuple[dir].out.h_dest,neighbors[dir].ha,6);
  flow->tuplehash[dir].tuple.l3proto=family;flow->tuplehash[dir].tuple.dir=dir;
 }
 flow_offload_route_init(flow,&route);
 assert(flow->type==NF_FLOW_OFFLOAD_ROUTE);
 for(unsigned int dir=0;dir<2;dir++){
  assert(!route.tuple[dir].dst && routes[dir].refs==1);
  assert(flow->tuplehash[dir].tuple.out.route_dst==&routes[dir]);
  assert(flow->tuplehash[dir].tuple.out.route_cookie==(family==NFPROTO_IPV6?routes[dir].cookie:0));
 }
 table.rhashtable=&flow->tuplehash[0];
}
static void release(struct flow_offload *flow){
 flow_offload_free(flow);assert(routes[0].refs==0 && routes[1].refs==0 && ct.refs==0 && ct_puts==1 && freed==1);
 for(unsigned int dir=0;dir<2;dir++)assert(!neighbors[dir].refs && !neighbors[dir].lock);
 cases++;
}
static void route_and_neighbor_cases(void){
 for(unsigned int family=NFPROTO_IPV4;family<=NFPROTO_IPV6;family+=8)for(unsigned int dir=0;dir<2;dir++){
  struct flow_offload flow;setup(&flow,family,true);
  assert(flow_offload_lookup(&table,&flow.tuplehash[0].tuple));assert(!lookups); /* cheap CPU path */
  nf_flow_offload_gc_step(&table,&flow,NULL);assert(stats==1 && extensions==1 && lookups==2);
  unsigned int old_stats=stats,old_extensions=extensions;
  routes[dir].current_generation++; /* unchanged ifindex and MAC */
  assert(!flow_offload_lookup(&table,&flow.tuplehash[0].tuple));
  assert(test_bit(NF_FLOW_TEARDOWN,&flow.flags) && !ct.offloaded);
  nf_flow_offload_gc_step(&table,&flow,NULL);assert(deletes==2 && stats==old_stats && extensions==old_extensions);
  assert(!freed && routes[0].refs && routes[1].refs); /* asynchronous withdrawal */
  flow.flags|=BIT(NF_FLOW_HW_DEAD);nf_flow_offload_gc_step(&table,&flow,NULL);
  assert(freed==1 && !routes[0].refs && !routes[1].refs && ct_puts==1);cases++;
  setup(&flow,family,true);routes[dir].cookie++;
  assert(nf_flow_direct_route_changed(&flow)==(family==NFPROTO_IPV6));release(&flow);
  const unsigned int states[]={NUD_REACHABLE,NUD_STALE,NUD_DELAY,NUD_PROBE,NUD_NOARP,NUD_PERMANENT,NUD_INCOMPLETE,NUD_FAILED,0};
  for(unsigned int i=0;i<sizeof(states)/sizeof(states[0]);i++){
   setup(&flow,family,true);neighbors[dir].nud_state=states[i];
   bool valid=states[i]&NUD_VALID;
   assert(nf_flow_direct_neigh_valid(&flow,dir)==valid);
   nf_flow_offload_gc_step(&table,&flow,NULL);
   assert((stats==1)==valid && (deletes==2)==!valid);release(&flow);
  }
  setup(&flow,family,true);neighbors[dir].ha[5]^=0x40;
  assert(flow_offload_lookup(&table,&flow.tuplehash[0].tuple)); /* no ARP on CPU fast path */
  nf_flow_offload_gc_step(&table,&flow,NULL);assert(!stats && deletes==2 && !ct.offloaded);release(&flow);
  setup(&flow,family,true);routes[dir].neigh=NULL;
  nf_flow_offload_gc_step(&table,&flow,NULL);assert(!stats && deletes==2);release(&flow);
  setup(&flow,family,true);logical[dir].type=ARPHRD_PPP;logical[dir].addr_len=0;routes[dir].neigh=NULL;
  logical[dir].ppp_channel_generation=2;flow.tuplehash[dir].tuple.out.ppp_cookie=2;
  assert(nf_flow_direct_neigh_valid(&flow,dir) && !lookups);
  logical[dir].ppp_channel_generation=3;
  assert(nf_flow_direct_route_changed(&flow) && !nf_flow_direct_neigh_valid(&flow,dir));
  logical[dir].ppp_channel_generation=4;
  assert(nf_flow_direct_route_changed(&flow) && !nf_flow_direct_neigh_valid(&flow,dir));
  logical[dir].ppp_channel_generation=2;
  assert(nf_flow_tuple_uses_dev(&flow.tuplehash[dir].tuple,&logical[dir]));
  routes[dir].alive=false;assert(!nf_flow_direct_neigh_valid(&flow,dir));release(&flow);
  setup(&flow,family,false);neighbors[dir].ha[5]^=1;
  nf_flow_offload_gc_step(&table,&flow,NULL);assert(!stats && !deletes && freed==1 && !ct.offloaded);
  assert(!routes[0].refs && !routes[1].refs);cases++;
 }
}
static void bridge_and_pending_cases(void){
 struct flow_offload flow;setup(&flow,NFPROTO_IPV4,true);
 struct nf_br_utils utils={.fdb_valid_dst=fdb_valid};nf_br_utils_hook=&utils;
 flow.tuplehash[0].tuple.bridge_path=1;bridge_egress=&physical[0];
 assert(nf_flow_dst_valid(&table,&flow,0));
 neighbors[0].ha[5]++;assert(!nf_flow_dst_valid(&table,&flow,0));release(&flow);
 setup(&flow,NFPROTO_IPV6,true);flow.flags|=BIT(NF_FLOW_PENDING);routes[0].current_generation++;
 nf_flow_offload_gc_step(&table,&flow,NULL);assert(!deletes && !checks);
 /* An in-flight stats request may finish first; the first subsequent GC
  * must still retire this pair even though its timeout was extended. */
 flow.flags&=~BIT(NF_FLOW_PENDING);flow.expired=false;
 nf_flow_offload_gc_step(&table,&flow,NULL);assert(deletes==2 && !stats && !extensions);release(&flow);
 setup(&flow,NFPROTO_IPV4,true);
 struct dst_entry *saved=flow.tuplehash[0].tuple.out.route_dst;flow.tuplehash[0].tuple.out.route_dst=NULL;
 assert(nf_flow_direct_route_changed(&flow) && !nf_flow_direct_neigh_valid(&flow,0));
 flow.tuplehash[0].tuple.out.route_dst=saved;release(&flow);
 /* Allocation failure must not take a conntrack or caller-owned dst ref;
  * free-before-route-init likewise must not release the caller's dst. */
 ct=(struct nf_conn){.refs=1};routes[0].refs=routes[1].refs=1;
 allocation_failure=true;assert(!flow_offload_alloc(&ct));assert(ct.refs==1 && routes[0].refs==1 && routes[1].refs==1);
 allocation_failure=false;freed=ct_puts=0;
 struct flow_offload *allocated=flow_offload_alloc(&ct);assert(allocated && ct.refs==2);
 flow_offload_free(allocated);assert(!heap_flow && ct.refs==1 && routes[0].refs==1 && routes[1].refs==1 && freed==1);cases++;
 struct flow_offload uninitialized={.ct=&ct};ct=(struct nf_conn){.refs=1};
 routes[0].refs=routes[1].refs=1;freed=ct_puts=0;
 flow_offload_free(&uninitialized);assert(routes[0].refs==1 && routes[1].refs==1 && freed==1);
 dst_release(&routes[0]);dst_release(&routes[1]);cases++;
 /* Existing NEIGH/XFRM release semantics are unchanged. */
 setup(&flow,NFPROTO_IPV6,false);
 for(unsigned int dir=0;dir<2;dir++){
  struct dst_entry *dst=flow.tuplehash[dir].tuple.out.route_dst;
  memset(&flow.tuplehash[dir].tuple.out,0,sizeof(flow.tuplehash[dir].tuple.out));
  flow.tuplehash[dir].tuple.xmit_type=dir?FLOW_OFFLOAD_XMIT_XFRM:FLOW_OFFLOAD_XMIT_NEIGH;
  flow.tuplehash[dir].tuple.dst_cache=dst;
 }
 assert(!nf_flow_direct_route_changed(&flow));release(&flow);
}
int main(void){route_and_neighbor_cases();bridge_and_pending_cases();
 printf("DIRECT route production checks: %u reference/IPv4/IPv6/neighbor/GC/paired-withdrawal cases PASS (host backend, not hardware)\n",cases);return 0;}
'''

functions = function("netdev_ppp_path_valid", netdevice) + "\n".join(function(name) for name in [
    "flow_offload_alloc", "flow_offload_dst_cookie", "nft_route_dst_fetch", "flow_offload_fill_route",
    "nft_flow_dst_release", "flow_offload_route_init", "flow_offload_route_release",
    "flow_offload_free_rcu", "flow_offload_free", "nf_flow_direct_mtu_valid", "nf_flow_direct_route_changed",
    "flow_offload_lookup", "nf_flow_direct_neigh_valid", "nf_flow_dst_valid",
    "nf_flow_offload_gc_step", "nf_flow_tuple_uses_dev",
])
mutations = {
    "drop_direct_reference_early": ("flow_tuple->out.route_dst = dst;", "flow_tuple->out.route_dst = dst; dst_release(dst);"),
    "omit_direct_reference_release": ("dst_release(flow->tuplehash[dir].tuple.out.route_dst);", "((void)flow->tuplehash[dir].tuple.out.route_dst);"),
    "ignore_route_generation_in_gc": ("if (!dst || !dst_check(dst, tuple->out.route_cookie))", "if (!dst)"),
    "ignore_neighbor_mac_change": ("ether_addr_equal(n->ha, tuple->out.h_dest)", "(ether_addr_equal(n->ha, tuple->out.h_dest), true)"),
    "reject_stale_but_valid_neighbor": ("n->nud_state & NUD_VALID", "n->nud_state & NUD_REACHABLE"),
    "skip_lookup_route_validation": ("nf_flow_direct_route_changed(flow) || nf_flow_bridge_changed(flow)", "nf_flow_bridge_changed(flow)"),
}
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
environment = dict(os.environ)
environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
with tempfile.TemporaryDirectory(prefix="flowtable-direct-route-") as directory:
    directory = Path(directory)
    for name in ["production", *mutations]:
        code = functions
        if name != "production":
            old, new = mutations[name]
            assert old in code, name
            code = code.replace(old, new, 1)
        (directory / "test.c").write_text(COMMON + STRUCTURES + BACKEND + code + TEST)
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra",
                        "-Werror", "-Wno-unused-parameter", "-Wno-misleading-indentation",
                        "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                        str(directory / "test.c"), "-o", str(directory / "test")], check=True)
        result = subprocess.run([str(directory / "test")], capture_output=True, text=True, timeout=30, env=environment)
        if name == "production":
            assert result.returncode == 0, result.stdout + result.stderr
            print(result.stdout, end="")
        else:
            assert result.returncode != 0 and "Assertion" in result.stderr, (name, result.stderr)
            print(f"Runtime regression mutant rejected: {name}")
(ROOT / "artifacts").mkdir(exist_ok=True)
(ROOT / "artifacts/flowtable-direct-route.json").write_text(json.dumps({
    "production_functions_sha256": hashlib.sha256(functions.encode()).hexdigest(),
    "mutations_rejected": list(mutations), "sanitizers": ["address", "undefined"],
    "scope": "production DIRECT route transfer/release, lookup, GC and logical-next-hop selection with modeled dst/neighbor backend; not full FIB or silicon",
    "hardware_verified": False,
}, indent=2) + "\n")
