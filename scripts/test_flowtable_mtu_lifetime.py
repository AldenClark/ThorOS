#!/usr/bin/env python3
"""Execute DIRECT MTU retirement with the prepared kernel's real IP helpers.

The IPv4/IPv6 forwarding MTU selectors and in-place route update helpers are
extracted unchanged, together with DIRECT CPU lookup and GC. Device/route/RCU
backends are host models: this is neither a complete FIB nor silicon timing.
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
ip = (args.kernel / "include/net/ip.h").read_text()
ip6 = (args.kernel / "include/net/ip6_route.h").read_text()
route4 = (args.kernel / "net/ipv4/route.c").read_text()
route6 = (args.kernel / "net/ipv6/route.c").read_text()


def function(source, name):
    match = re.search(r"^.*\b" + re.escape(name) + r"\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    start = match.start()
    if source[start:].startswith(name + "("):
        start = source.rfind("\n", 0, start - 1) + 1
    end = source.index("{", match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end] + "\n"


COMMON = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10
#define ARPHRD_ETHER 1
#define ARPHRD_PPP 512
#define ETH_ALEN 6
#define AF_INET 2
#define RTCF_REDIRECTED 1
#define RTF_MODIFIED 1
#define RTAX_MTU 2
#define IP_MAX_MTU 65535
#define IP6_MAX_MTU 65535
#define IPV6_MIN_MTU 1280
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define unlikely(x) (x)
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define BIT(n) (1UL<<(n))
#define test_bit(n,p) (!!(*(p)&BIT(n)))
#define test_bit_acquire(n,p) test_bit(n,p)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define rcu_dereference(p) (p)
#define NUD_VALID 0xde
enum {FLOW_OFFLOAD_XMIT_UNSPEC,FLOW_OFFLOAD_XMIT_NEIGH,FLOW_OFFLOAD_XMIT_DIRECT};
enum {NF_FLOW_TEARDOWN,NF_FLOW_HW,NF_FLOW_HW_DYING,NF_FLOW_HW_DEAD,NF_FLOW_CLOSING,NF_FLOW_PENDING,NF_FLOW_INITIALIZING};
enum {FLOW_OFFLOAD_DIR_ORIGINAL,FLOW_OFFLOAD_DIR_REPLY,FLOW_OFFLOAD_DIR_MAX};
#define NF_FLOW_OFFLOAD_ROUTE 1
struct net {struct {int sysctl_ip_fwd_use_pmtu;}ipv4;struct {struct {int ip6_rt_mtu_expires;}sysctl;}ipv6;};
struct inet6_dev {struct {unsigned int mtu6;}cnf;};
struct net_device {struct net *net;struct inet6_dev *idev;unsigned int mtu,type,addr_len,ifindex;u32 ppp_cookie;};
struct neighbour {u8 ha[6],nud_state;unsigned int lock,refs;};
struct dst_entry {struct net_device *dev;struct neighbour *neigh;unsigned int metric;bool locked,valid;unsigned long expires;void *lwtstate;};
struct rtable {struct dst_entry dst;unsigned int rt_pmtu,rt_mtu_locked,rt_uses_gateway,rt_flags,rt_gw_family,rt_gw4;};
struct rt6_info {struct dst_entry dst;unsigned int rt6i_flags;};
struct fib_nh_exception {unsigned int fnhe_pmtu,fnhe_mtu_locked,fnhe_gw;unsigned long fnhe_expires;};
struct flow_offload_tuple {unsigned int xmit_type,l3proto,mtu,dir;u8 bridge_path,port_vlans,bridge_vlan;u32 src_v4;struct {u16 proto,id;}encap[2];struct {struct dst_entry *route_dst;u32 route_cookie,ppp_cookie;unsigned int hw_ifidx;u8 h_dest[6];}out;};
struct flow_offload_tuple_rhash {struct flow_offload_tuple tuple;};
struct nf_conn {bool dying,offloaded;};
struct flow_offload {unsigned int type;unsigned long flags;bool expired;struct nf_conn *ct;struct flow_offload_tuple_rhash tuplehash[2];};
struct nf_flowtable {struct net *net;struct flow_offload_tuple_rhash *rhashtable;};
struct nf_br_utils {bool (*fdb_valid_dst)(struct net_device *,const u8 *,u16);};
static struct nf_br_utils *nf_br_utils_hook;
static unsigned int cases,rcu_depth,lookups,checks,stats,extensions,deletes,freed;
static unsigned long jiffies;
static struct net ns;
static struct inet6_dev idev[2];
static struct net_device devices[2];
static struct neighbour neighbors[2];
static union {struct rtable v4;struct rt6_info v6;}routes[2];
static struct nf_conn ct;
static struct nf_flowtable table;
static int nf_flow_offload_rhash_params;
static void rcu_read_lock(void){rcu_depth++;}
static void rcu_read_unlock(void){assert(rcu_depth);rcu_depth--;}
static const struct net_device *dst_dev_rcu(const struct dst_entry *d){assert(rcu_depth);return d->dev;}
static struct net *dev_net_rcu(const struct net_device *d){assert(rcu_depth);return d->net;}
static struct net *dev_net(const struct net_device *d){return d->net;}
static struct inet6_dev *__in6_dev_get(const struct net_device *d){assert(rcu_depth);return d->idev;}
#define dst_rtable(d) container_of(d,struct rtable,dst)
static unsigned int dst_metric_raw(const struct dst_entry *d,int m){assert(m==RTAX_MTU);return d->metric;}
static bool dst_metric_locked(const struct dst_entry *d,int m){assert(m==RTAX_MTU);return d->locked;}
static bool ip_mtu_locked(const struct dst_entry *d){return d->locked||dst_rtable(d)->rt_mtu_locked;}
static unsigned int lwtunnel_headroom(void *s,unsigned int mtu){assert((uintptr_t)s<mtu);return (uintptr_t)s;}
#define time_before(a,b) ((long)((a)-(b))<0)
static void dst_metric_set(struct dst_entry *d,int m,unsigned int value){assert(m==RTAX_MTU);d->metric=value;}
static void rt6_update_expires(struct rt6_info *r,int timeout){r->dst.expires=jiffies+timeout;}
static struct dst_entry *dst_check(struct dst_entry *d,u32 cookie){assert(cookie==17);checks++;return d&&d->valid?d:NULL;}
static bool netdev_ppp_path_valid(const struct net_device *d,u32 c){return c&&c==d->ppp_cookie;}
static struct neighbour *dst_neigh_lookup(struct dst_entry *d,const void *a){(void)a;assert(d->valid);lookups++;if(d->neigh)d->neigh->refs++;return d->neigh;}
static void read_lock_bh(unsigned int *l){assert(!*l);*l=1;}
static void read_unlock_bh(unsigned int *l){assert(*l);*l=0;}
static bool ether_addr_equal(const u8 *a,const u8 *b){return !memcmp(a,b,6);}
static void neigh_release(struct neighbour *n){assert(n->refs&&!n->lock);n->refs--;}
static struct net *read_pnet(struct net **n){return *n;}
static struct net_device *dev_get_by_index_rcu(struct net *n,unsigned int i){(void)n;(void)i;assert(false);return NULL;}
static struct net_device *__vlan_find_dev_deep_rcu(struct net_device *d,u16 p,u16 i){(void)d;(void)p;(void)i;assert(false);return NULL;}
static void *rhashtable_lookup(void *h,void *k,int p){(void)k;(void)p;return *(void **)h;}
static bool nf_ct_is_dying(const struct nf_conn *c){return c->dying;}
static bool nf_flow_has_expired(const struct flow_offload *f){return f->expired;}
static bool nf_flow_bridge_changed(const struct flow_offload *f){(void)f;return false;}
static bool nf_flow_custom_gc(struct nf_flowtable *t,struct flow_offload *f){(void)t;(void)f;return false;}
static void flow_offload_teardown(struct flow_offload *f){f->flags|=BIT(NF_FLOW_TEARDOWN);f->ct->offloaded=false;}
static void nf_flow_table_extend_ct_timeout(struct nf_conn *c){assert(c->offloaded);extensions++;}
static void nf_flow_offload_stats(struct nf_flowtable *t,struct flow_offload *f){(void)t;assert(!test_bit(NF_FLOW_TEARDOWN,&f->flags));stats++;}
static void nf_flow_offload_del(struct nf_flowtable *t,struct flow_offload *f){(void)t;f->flags|=BIT(NF_FLOW_HW_DYING);deletes+=2;}
static void flow_offload_del(struct nf_flowtable *t,struct flow_offload *f){(void)t;(void)f;freed++;}
static bool test_and_set_bit(unsigned int n,unsigned long *p){bool old=test_bit(n,p);*p|=BIT(n);return old;}
'''

FUNCTIONS = "\n".join([
    function(ip, "ip_dst_mtu_maybe_forward"),
    function(ip6, "ip6_dst_mtu_maybe_forward"),
    function(route4, "fill_route_from_fnhe"),
    function(route6, "rt6_do_update_pmtu"),
    *[function(core, n) for n in ("nf_flow_direct_mtu_valid", "nf_flow_direct_route_changed",
       "flow_offload_lookup", "nf_flow_direct_neigh_valid", "nf_flow_dst_valid", "nf_flow_offload_gc_step")],
])

TEST = r'''
static void recache(struct flow_offload *f){for(unsigned int d=0;d<2;d++){struct flow_offload_tuple *t=&f->tuplehash[d].tuple;t->mtu=t->l3proto==NFPROTO_IPV4?ip_dst_mtu_maybe_forward(t->out.route_dst,true):ip6_dst_mtu_maybe_forward(t->out.route_dst,true);}}
static void setup(struct flow_offload *f,unsigned int family){
 memset(routes,0,sizeof(routes));ns=(struct net){.ipv6.sysctl.ip6_rt_mtu_expires=100};jiffies=100;
 ct=(struct nf_conn){.offloaded=true};*f=(struct flow_offload){.ct=&ct,.type=NF_FLOW_OFFLOAD_ROUTE,.flags=BIT(NF_FLOW_HW)};
 table=(struct nf_flowtable){.net=&ns,.rhashtable=&f->tuplehash[0]};rcu_depth=lookups=checks=stats=extensions=deletes=freed=0;
 for(unsigned int d=0;d<2;d++){
  idev[d]=(struct inet6_dev){.cnf.mtu6=1500};devices[d]=(struct net_device){.net=&ns,.idev=&idev[d],.mtu=1500,.type=ARPHRD_ETHER,.addr_len=6,.ifindex=2+d};
  neighbors[d]=(struct neighbour){.ha={2,0,0,0,0,d+1},.nud_state=2};
  struct dst_entry *dst=family==NFPROTO_IPV4?&routes[d].v4.dst:&routes[d].v6.dst;
  *dst=(struct dst_entry){.dev=&devices[d],.neigh=&neighbors[d],.valid=true};
  f->tuplehash[d].tuple=(struct flow_offload_tuple){.xmit_type=FLOW_OFFLOAD_XMIT_DIRECT,.l3proto=family,.dir=d,.out={.route_dst=dst,.route_cookie=17}};
  memcpy(f->tuplehash[d].tuple.out.h_dest,neighbors[d].ha,6);
 }
 recache(f);
}
static void unchanged(struct flow_offload *f){
 unsigned int before=lookups;
 assert(!nf_flow_direct_route_changed(f));assert(flow_offload_lookup(&table,&f->tuplehash[0].tuple));assert(lookups==before);
 nf_flow_offload_gc_step(&table,f,NULL);assert(!deletes&&stats&&ct.offloaded);assert(!rcu_depth);cases++;
}
static void changed(struct flow_offload *f){
 unsigned int before=lookups;
 assert(nf_flow_direct_route_changed(f));
 /* CPU must retire the pair even when the packet used the opposite path. */
 assert(!flow_offload_lookup(&table,&f->tuplehash[0].tuple));assert(lookups==before&&!ct.offloaded);
 assert(test_bit(NF_FLOW_TEARDOWN,&f->flags));
 /* Independently exercise a pure-HW flow reaching GC without a CPU miss. */
 f->flags=BIT(NF_FLOW_HW);ct.offloaded=true;stats=extensions=0;
 nf_flow_offload_gc_step(&table,f,NULL);assert(deletes==2&&!stats&&!extensions&&!ct.offloaded&&!freed);
 assert(!rcu_depth);for(unsigned int d=0;d<2;d++)assert(!neighbors[d].refs&&!neighbors[d].lock);
 cases++;
}
static void ipv4_cases(void){
 for(unsigned int d=0;d<2;d++){
  struct flow_offload f;setup(&f,NFPROTO_IPV4);unchanged(&f);
  /* Default forwarding ignores untrusted ICMP PMTU, including updates. */
  struct fib_nh_exception ex={.fnhe_pmtu=1300,.fnhe_expires=500};fill_route_from_fnhe(&routes[d].v4,&ex);unchanged(&f);
  ns.ipv4.sysctl_ip_fwd_use_pmtu=1;changed(&f);
  for(unsigned int m=1300;m<=1450;m+=150){
   setup(&f,NFPROTO_IPV4);ns.ipv4.sysctl_ip_fwd_use_pmtu=1;
   ex=(struct fib_nh_exception){.fnhe_pmtu=1400,.fnhe_expires=500};fill_route_from_fnhe(&routes[d].v4,&ex);recache(&f);unchanged(&f);
   ex.fnhe_pmtu=m;fill_route_from_fnhe(&routes[d].v4,&ex);assert(dst_check(&routes[d].v4.dst,17));changed(&f);
  }
  /* A locked exception is honoured even with ip_fwd_use_pmtu disabled. */
  setup(&f,NFPROTO_IPV4);ex=(struct fib_nh_exception){.fnhe_pmtu=1400,.fnhe_mtu_locked=1,.fnhe_expires=500};fill_route_from_fnhe(&routes[d].v4,&ex);recache(&f);unchanged(&f);
  ex.fnhe_pmtu=1300;fill_route_from_fnhe(&routes[d].v4,&ex);changed(&f);
  /* Expiry can increase effective MTU while route generation stays valid. */
  setup(&f,NFPROTO_IPV4);ns.ipv4.sysctl_ip_fwd_use_pmtu=1;ex=(struct fib_nh_exception){.fnhe_pmtu=1400,.fnhe_expires=110};fill_route_from_fnhe(&routes[d].v4,&ex);recache(&f);jiffies=111;changed(&f);
  setup(&f,NFPROTO_IPV4);routes[d].v4.dst.metric=1400;recache(&f);routes[d].v4.dst.metric=1280;changed(&f);
  setup(&f,NFPROTO_IPV4);devices[d].mtu=1492;changed(&f);
  setup(&f,NFPROTO_IPV4);routes[d].v4.dst.lwtstate=(void *)20;recache(&f);assert(f.tuplehash[d].tuple.mtu==1480);unchanged(&f);
 }
}
static void ipv6_cases(void){
 for(unsigned int d=0;d<2;d++){
  struct flow_offload f;setup(&f,NFPROTO_IPV6);unchanged(&f);
  /* IPv6 forwarding ignores an unlocked ICMP-learned metric. */
  rt6_do_update_pmtu(&routes[d].v6,1300);assert(dst_check(&routes[d].v6.dst,17));unchanged(&f);
  for(unsigned int m=1280;m<=1450;m+=170){
   setup(&f,NFPROTO_IPV6);routes[d].v6.dst.locked=true;routes[d].v6.dst.metric=1400;recache(&f);unchanged(&f);
   rt6_do_update_pmtu(&routes[d].v6,m);changed(&f);
  }
  setup(&f,NFPROTO_IPV6);idev[d].cnf.mtu6=1400;assert(devices[d].mtu==1500);changed(&f);
  setup(&f,NFPROTO_IPV6);idev[d].cnf.mtu6=1400;recache(&f);idev[d].cnf.mtu6=1500;changed(&f);
  setup(&f,NFPROTO_IPV6);devices[d].idev=NULL;changed(&f);
  setup(&f,NFPROTO_IPV6);routes[d].v6.dst.lwtstate=(void *)20;recache(&f);assert(f.tuplehash[d].tuple.mtu==1480);unchanged(&f);
 }
}
static void lifecycle_cases(void){
 struct flow_offload f;setup(&f,NFPROTO_IPV4);devices[0].mtu=1400;f.flags|=BIT(NF_FLOW_PENDING);
 nf_flow_offload_gc_step(&table,&f,NULL);assert(!stats&&!deletes&&ct.offloaded);f.flags&=~BIT(NF_FLOW_PENDING);changed(&f);
 setup(&f,NFPROTO_IPV4);f.tuplehash[0].tuple.out.route_dst=NULL;assert(!nf_flow_direct_mtu_valid(&f.tuplehash[0].tuple));changed(&f);
 setup(&f,NFPROTO_IPV4);f.tuplehash[0].tuple.l3proto=0;assert(!nf_flow_direct_mtu_valid(&f.tuplehash[0].tuple));changed(&f);
 setup(&f,NFPROTO_IPV4);devices[0].mtu=1400;f.tuplehash[0].tuple.xmit_type=FLOW_OFFLOAD_XMIT_NEIGH;unchanged(&f);
 setup(&f,NFPROTO_IPV4);devices[0].mtu=1400;f.type=0;unchanged(&f);
}
int main(void){ipv4_cases();ipv6_cases();lifecycle_cases();printf("DIRECT effective MTU: %u cases; actual IPv4/IPv6 selectors and in-place updates, CPU/GC paired retirement, policy/expiry/headroom/no-churn PASS (host backend)\n",cases);}
'''

MUTATIONS = {
    "skip_cpu_mtu_validation": ("\t\tif (!nf_flow_direct_mtu_valid(tuple))\n\t\t\treturn true;", ""),
    "skip_gc_mtu_validation": ("\tif (!nf_flow_direct_mtu_valid(tuple))\n\t\treturn false;", ""),
    "retain_old_smaller_mtu": ("return mtu == tuple->mtu;", "return mtu >= tuple->mtu;"),
    "ipv4_nonforwarding_semantics": ("mtu = ip_dst_mtu_maybe_forward(dst, true);", "mtu = ip_dst_mtu_maybe_forward(dst, false);"),
    "ipv6_nonforwarding_semantics": ("mtu = ip6_dst_mtu_maybe_forward(dst, true);", "mtu = ip6_dst_mtu_maybe_forward(dst, false);"),
    "only_original_direction": ("dir < FLOW_OFFLOAD_DIR_MAX", "dir < 1"),
}
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
environment = dict(os.environ)
environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
with tempfile.TemporaryDirectory(prefix="flowtable-mtu-") as directory:
    directory = Path(directory)
    for name in ["production", *MUTATIONS]:
        code = FUNCTIONS
        if name != "production":
            old, new = MUTATIONS[name]
            assert old in code, name
            code = code.replace(old, new, 1)
        (directory / "mtu.c").write_text(COMMON + code + TEST)
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra",
                        "-Werror", "-Wno-unused-parameter", "-Wno-unused-function", "-Wno-misleading-indentation",
                        "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                        str(directory / "mtu.c"), "-o", str(directory / "mtu")], check=True)
        result = subprocess.run([str(directory / "mtu")], text=True, capture_output=True, timeout=30, env=environment)
        if name == "production":
            assert result.returncode == 0, result.stdout + result.stderr
            print(result.stdout, end="")
        else:
            assert result.returncode != 0 and "Assertion" in result.stderr, (name, result.stderr)
            print(f"Runtime MTU mutant rejected: {name}")
(ROOT / "artifacts").mkdir(exist_ok=True)
(ROOT / "artifacts/flowtable-mtu-lifetime.json").write_text(json.dumps({
    "production_sha256": hashlib.sha256(FUNCTIONS.encode()).hexdigest(),
    "mutations_rejected": list(MUTATIONS), "sanitizers": ["address", "undefined"],
    "scope": "actual forwarding MTU selectors and route update functions with modeled device/dst/GC; not a full FIB or hardware test",
    "hardware_verified": False,
}, indent=2) + "\n")
