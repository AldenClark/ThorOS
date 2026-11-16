#!/usr/bin/env python3
"""Run real PPP policy setters and forward-path selection with host backends.

Extracts prepared Linux functions, including the actual ioctl dispatch arms
for native/compat filters and nft/xt protocol propagation. The backend models
PPP locking, admission, user copies and allocation; it does not run a PPP
session, a BPF program, real networking concurrency or hardware forwarding.
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
ppp = (args.kernel / "drivers/net/ppp/ppp_generic.c").read_text()
netdev = (args.kernel / "include/linux/netdevice.h").read_text()
nft = (args.kernel / "net/netfilter/nf_flow_table_path.c").read_text()
xt = (args.kernel / "net/netfilter/xt_FLOWOFFLOAD.c").read_text()
ioctl = (args.kernel / "include/uapi/linux/ppp-ioctl.h").read_text()
defs = (args.kernel / "include/uapi/linux/ppp_defs.h").read_text()


def function(source, name):
    match = re.search(r"^[A-Za-z_][^;{}\n]*\b" + re.escape(name) +
                      r"\([^;]*?\)\s*\{|^" + re.escape(name) + r"\([^;]*?\)\s*\{", source, re.M)
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


def dispatch(source, name, first, stop):
    code = function(source, name)
    start = code.index(first)
    end = code.index(stop, start)
    return code[start:end]


constants = "\n".join(re.findall(r"^#define\s+SC_[A-Z0-9_]+\s+0x[0-9a-fA-F]+.*$", ioctl, re.M))
constants += "\n" + "\n".join(re.findall(r"^#define\s+(?:NP_[A-Z0-9_]+|NUM_NP)\s+[0-9]+.*$", ppp, re.M))
constants += "\n" + "\n".join(re.findall(r"^#define\s+PPP_[A-Z0-9_]+\s+0x[0-9a-fA-F]+.*$", defs, re.M))
constants += "\n" + re.search(r"#define SC_FLAG_BITS.*?(?=\n\n)", ppp, re.S)[0]
constants += "\n" + re.search(r"enum NPmode \{.*?\n\};", defs, re.S)[0] + "\n"

COMMON = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
typedef uint8_t u8;typedef uint16_t __be16,u16;typedef uint32_t u32;
typedef u32 atomic_t;
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define atomic_read(p) (*(p))
#define smp_rmb() ((void)0)
#define smp_load_acquire(p) (*(p))
#define lockdep_assert_held(p) assert(*(p))
#define ppp_lock(p) do {assert(!(p)->wlock && !(p)->rlock);(p)->wlock=(p)->rlock=true;}while(0)
#define ppp_unlock(p) do {assert((p)->wlock && (p)->rlock);(p)->wlock=(p)->rlock=false;}while(0)
#define __user
#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10
#define NUD_VALID 0xde
#define CCP_MAX_OPTION_LENGTH 32
#define IS_ERR(p) ((intptr_t)(p)<0)
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define try_then_request_module(x,...) (x)
enum {PPPIOCSFLAGS=1,PPPIOCGNPMODE,PPPIOCSNPMODE,PPPIOCSPASS,PPPIOCSACTIVE,PPPIOCSPASS32,PPPIOCSACTIVE32};
enum ip_conntrack_dir {IP_CT_DIR_ORIGINAL,IP_CT_DIR_REPLY};
struct net {unsigned int dummy;};
struct ppp;
struct net_device {atomic_t ppp_channel_generation;struct ppp *priv;struct net *net;bool moving_ns;};
#define dev_net(d) ((d)->net)
#define net_eq(a,b) ((a)==(b))
struct bpf_prog {unsigned int id;};
struct npioctl {int protocol;enum NPmode mode;};
struct ppp_option_data {u8 *ptr;unsigned int length;int transmit;};
struct compressor {
 void *(*comp_alloc)(u8 *,unsigned int);void *(*decomp_alloc)(u8 *,unsigned int);
 void (*comp_free)(void *);void (*decomp_free)(void *);void *owner;
};
struct net_device_path_ctx {
 const struct net_device *dev;u8 daddr[ETH_ALEN];__be16 l3_proto;bool ieee80211;
};
struct net_device_path {unsigned int dummy;};
struct net_device_path_stack {unsigned int dummy;};
struct ppp_channel;
struct ppp_channel_ops {int (*fill_forward_path)(struct net_device_path_ctx *,struct net_device_path *,struct ppp_channel *);};
struct ppp_channel {const struct ppp_channel_ops *ops;};
struct channel {struct ppp_channel *chan;};
struct ppp {
 struct net_device *dev;struct net *ppp_net;int flags;bool wlock,rlock;unsigned int nextseq,xstate,rstate;
 enum NPmode npmode[NUM_NP];struct channel *channels;
 void *xc_state,*rc_state;struct compressor *xcomp,*rcomp;
 struct bpf_prog *pass_filter,*active_filter;
};
#define netdev_priv(d) ((d)->priv)
#define list_first_or_null_rcu(p,t,m) (*(p))
struct nf_flow_route {unsigned int dummy;};
struct dst_entry {struct net_device *dev;};
struct nf_conn {struct {struct {struct {unsigned int l3num;u32 u3;}src;}tuple;}tuplehash[2];};
struct neighbour {unsigned int lock;u8 nud_state,ha[6];};
static void ppp_ccp_closed(struct ppp *);
static int ppp_fill_forward_path(struct net_device_path_ctx *,struct net_device_path *);
'''

BACKEND = r'''
static struct ppp unit;
static struct net_device device;
static struct net net;
static struct bpf_prog filters[3];
static unsigned int begins,ends,forwarded,freed_filters,freed_states,module_puts,wakes,cases;
static bool gated,copy_failure,alloc_failure,missing_compressor,filter_failure;
static int state_tokens[4];
static void *allocated_state;
static struct bpf_prog *supplied_filter;
static u16 decoded_proto;
static struct net *rtl9617c_switch_policy_begin(struct net_device *dev){
 assert(dev==&device && unit.wlock && unit.rlock && begins==ends);
 assert(!(device.ppp_channel_generation&1));begins++;gated=true;return &net;
}
static void rtl9617c_switch_policy_end(struct net *policy){
 assert(policy==&net && unit.wlock && unit.rlock && begins==ends+1 && gated);
 assert(!(device.ppp_channel_generation&1));ends++;
}
static bool atomic_try_cmpxchg(atomic_t *v,int *old,int next){assert(v==&device.ppp_channel_generation && unit.wlock && unit.rlock && gated);if(*v!=(u32)*old){*old=(int)*v;return false;}*v=(u32)next;return true;}
static int copy_from_user(void *to,const void *from,size_t n){if(copy_failure)return 1;memcpy(to,from,n);return 0;}
static int copy_to_user(void *to,const void *from,size_t n){return copy_from_user(to,from,n);}
#define get_user(value,p) (copy_failure?1:((value)=*(p),0))
static void netif_wake_queue(struct net_device *dev){assert(dev==&device && !unit.wlock && !unit.rlock);wakes++;}
#ifdef CONFIG_PPP_FILTER
static struct bpf_prog *ppp_get_filter(void *argp){(void)argp;return filter_failure?ERR_PTR(-EINVAL):supplied_filter;}
static struct bpf_prog *compat_ppp_get_filter(void *argp){return ppp_get_filter(argp);}
static void bpf_prog_destroy(struct bpf_prog *filter){assert(filter && !unit.wlock && !unit.rlock && filter!=unit.pass_filter && filter!=unit.active_filter);freed_filters++;}
#endif
static void *allocate_state(u8 *option,unsigned int length){assert(!unit.wlock && !unit.rlock && length>=2 && option[1]>=2);return alloc_failure?NULL:allocated_state;}
static void free_state(void *state){assert(state && !unit.wlock && !unit.rlock && state!=unit.xc_state && state!=unit.rc_state);freed_states++;}
static struct compressor comp={allocate_state,allocate_state,free_state,free_state,&comp};
static struct compressor *find_compressor(int type){(void)type;return missing_compressor?NULL:&comp;}
static void module_put(void *owner){assert(owner==&comp);module_puts++;}
static int channel_forward(struct net_device_path_ctx *ctx,struct net_device_path *path,struct ppp_channel *chan){
 (void)path;assert(chan && ctx->dev==&device);decoded_proto=ntohs(ctx->l3_proto);forwarded++;return 0;
}
static const struct ppp_channel_ops channel_ops={channel_forward};
static struct ppp_channel channel={&channel_ops};
static struct channel channel_owner={&channel};
static bool nft_is_valid_ether_device(struct net_device *dev){assert(dev==&device);return false;}
static bool nf_is_valid_ether_device(struct net_device *dev){return nft_is_valid_ether_device(dev);}
static void eth_zero_addr(u8 *p){memset(p,0,6);}
static void ether_addr_copy(u8 *to,const u8 *from){memcpy(to,from,6);}
static struct neighbour *dst_neigh_lookup(const struct dst_entry *d,const void *addr){(void)d;(void)addr;assert(false);return NULL;}
static void read_lock_bh(unsigned int *p){(void)p;assert(false);}
static void read_unlock_bh(unsigned int *p){(void)p;assert(false);}
static void neigh_release(struct neighbour *n){(void)n;assert(false);}
static int dev_fill_forward_path(struct net_device_path_ctx *ctx,struct net_device_path_stack *stack){
 (void)stack;struct net_device_path path={0};return ppp_fill_forward_path(ctx,&path);
}
'''

functions = "\n".join(function(netdev, name) for name in ["netdev_ppp_path_advance", "netdev_ppp_path_cookie", "netdev_ppp_path_valid"])
functions += "\n".join(function(ppp, name) for name in [
    "ppp_flow_change_begin", "ppp_flow_change_end", "ppp_flow_policy_allows",
    "ppp_flow_set_flags", "ppp_flow_set_npmode", "ppp_flow_replace_compressor",
    "ppp_set_compress", "ppp_ccp_closed", "ppp_fill_forward_path", "proto_to_npindex",
])
functions += "\n#ifdef CONFIG_PPP_FILTER\n" + function(ppp, "ppp_flow_set_filter") + "#endif\n"
functions += function(nft, "nft_dev_fill_forward_path") + function(xt, "nf_dev_fill_forward_path")
flags_case = dispatch(ppp, "ppp_ioctl", "\tcase PPPIOCSFLAGS:", "\n\tcase PPPIOCGFLAGS:")
np_case = dispatch(ppp, "ppp_ioctl", "\tcase PPPIOCGNPMODE:", "\n#ifdef CONFIG_PPP_FILTER")
filter_case = dispatch(ppp, "ppp_ioctl", "\tcase PPPIOCSPASS:", "\n#endif /* CONFIG_PPP_FILTER */")
compat_filter_case = dispatch(ppp, "ppp_compat_ioctl", "\t\tcase PPPIOCSPASS32:", "\n#endif /* CONFIG_PPP_FILTER */")
functions += r'''
static int real_ioctl_cases(struct ppp *ppp,unsigned int cmd,void *argp){
 int err=-EFAULT,val,i,*p=argp;struct npioctl npi;
 switch(cmd){
''' + flags_case + np_case + "\n#ifdef CONFIG_PPP_FILTER\n" + filter_case + compat_filter_case + r'''
#endif
 default:err=-ENOTTY;break;
 }return err;
}
'''

TEST = r'''
static void setup(void){
 unit=(struct ppp){.dev=&device,.ppp_net=&net,.channels=&channel_owner};
 device=(struct net_device){.priv=&unit,.ppp_channel_generation=2,.net=&net};
 for(unsigned int i=0;i<NUM_NP;i++)unit.npmode[i]=NPMODE_PASS;
 begins=ends=forwarded=freed_filters=freed_states=module_puts=wakes=0;
 copy_failure=alloc_failure=missing_compressor=filter_failure=gated=false;
 supplied_filter=NULL;allocated_state=&state_tokens[0];channel_owner.chan=&channel;decoded_proto=0;
}
static bool allows(u16 proto){
 struct net_device_path_ctx ctx={.dev=&device,.l3_proto=htons(proto)};struct net_device_path path={0};
 unsigned int before=forwarded;int ret=ppp_fill_forward_path(&ctx,&path);
 assert((ret==0)==(forwarded==before+1));cases++;return !ret;
}
static void flags_cases(void){
 setup();assert(allows(ETH_P_IP) && allows(ETH_P_IPV6));
 int flags=0;assert(!real_ioctl_cases(&unit,PPPIOCSFLAGS,&flags));assert(!begins && device.ppp_channel_generation==2);
 const unsigned int plain[]={SC_CCP_OPEN,SC_NO_TCP_CCID,SC_REJ_COMP_TCP,SC_MP_SHORTSEQ,SC_MP_XSHORTSEQ};
 for(unsigned int i=0;i<sizeof(plain)/sizeof(plain[0]);i++){
  setup();flags=plain[i];u32 old=netdev_ppp_path_cookie(&device);
  assert(!real_ioctl_cases(&unit,PPPIOCSFLAGS,&flags));assert(begins==1 && ends==1 && !netdev_ppp_path_valid(&device,old));
  assert(allows(ETH_P_IP) && allows(ETH_P_IPV6));
  gated=false;assert(!real_ioctl_cases(&unit,PPPIOCSFLAGS,&flags));assert(begins==1 && !gated);
 }
 const unsigned int blocking[]={SC_LOOP_TRAFFIC,SC_COMP_TCP,SC_CCP_UP,SC_MUST_COMP,SC_MULTILINK};
 for(unsigned int i=0;i<sizeof(blocking)/sizeof(blocking[0]);i++){
  setup();flags=blocking[i];unit.nextseq=99;
  assert(!real_ioctl_cases(&unit,PPPIOCSFLAGS,&flags));assert(begins==1 && ends==1 && gated);
  assert(!allows(ETH_P_IP) && !allows(ETH_P_IPV6));
#ifdef CONFIG_PPP_MULTILINK
  if(flags==SC_MULTILINK)assert(!unit.nextseq);
#endif
  flags=0;assert(!real_ioctl_cases(&unit,PPPIOCSFLAGS,&flags));assert(begins==2 && ends==2);
  assert(allows(ETH_P_IP) && allows(ETH_P_IPV6));
 }
 setup();copy_failure=true;flags=SC_LOOP_TRAFFIC;assert(real_ioctl_cases(&unit,PPPIOCSFLAGS,&flags)==-EFAULT);
 assert(!begins && !unit.flags);copy_failure=false;assert(allows(ETH_P_IP));
 setup();flags=SC_DEBUG;assert(!real_ioctl_cases(&unit,PPPIOCSFLAGS,&flags));assert(!begins && !unit.flags);
 /* Cookie wrap must never authorize an old recipe, even after restoration. */
 device.ppp_channel_generation=0xfffffffeU;flags=SC_LOOP_TRAFFIC;assert(!real_ioctl_cases(&unit,PPPIOCSFLAGS,&flags));
 assert(!device.ppp_channel_generation && !netdev_ppp_path_valid(&device,2));
 flags=0;assert(!real_ioctl_cases(&unit,PPPIOCSFLAGS,&flags));assert(!device.ppp_channel_generation);
}
static void namespace_cases(void){
 setup();struct net other_net={0};u32 cookie=netdev_ppp_path_cookie(&device);
 assert(allows(ETH_P_IP) && allows(ETH_P_IPV6) && netdev_ppp_path_valid(&device,cookie));
 device.moving_ns=true;
 assert(!netdev_ppp_path_cookie(&device) && !netdev_ppp_path_valid(&device,cookie));
 device.net=&other_net;device.moving_ns=false;
 assert(!allows(ETH_P_IP) && !allows(ETH_P_IPV6));
 device.net=&net;assert(allows(ETH_P_IP) && allows(ETH_P_IPV6));
}
static void np_cases(void){
 for(unsigned int proto=0;proto<2;proto++)for(int mode=NPMODE_PASS;mode<=NPMODE_QUEUE;mode++){
  setup();struct npioctl npi={.protocol=proto?PPP_IPV6:PPP_IP,.mode=mode};
  assert(!real_ioctl_cases(&unit,PPPIOCSNPMODE,&npi));
  assert(begins==(mode!=NPMODE_PASS) && begins==ends && wakes==1);
  assert(allows(proto?ETH_P_IPV6:ETH_P_IP)==(mode==NPMODE_PASS));
  assert(allows(proto?ETH_P_IP:ETH_P_IPV6)); /* v4-only / v6-only remain eligible */
  unsigned int before=begins;assert(!real_ioctl_cases(&unit,PPPIOCSNPMODE,&npi));assert(begins==before);
  npi.mode=NPMODE_PASS;assert(!real_ioctl_cases(&unit,PPPIOCGNPMODE,&npi));assert(npi.mode==(enum NPmode)mode && begins==before);
 }
 setup();struct npioctl npi={.protocol=PPP_MPLS_UC,.mode=NPMODE_DROP};
 assert(!real_ioctl_cases(&unit,PPPIOCSNPMODE,&npi));assert(!begins && unit.npmode[NP_MPLS_UC]==NPMODE_DROP);
 assert(allows(ETH_P_IP) && allows(ETH_P_IPV6));
 npi.protocol=0;assert(real_ioctl_cases(&unit,PPPIOCSNPMODE,&npi)==-EINVAL && !begins);
 npi.protocol=PPP_IP;copy_failure=true;assert(real_ioctl_cases(&unit,PPPIOCSNPMODE,&npi)==-EFAULT && !begins);
 copy_failure=false;assert(!allows(0) && !allows(ETH_P_ARP) && !allows(ETH_P_MPLS_UC));
}
#ifdef CONFIG_PPP_FILTER
static void filter_cases(void){
 const unsigned int commands[]={PPPIOCSPASS,PPPIOCSACTIVE,PPPIOCSPASS32,PPPIOCSACTIVE32};
 for(unsigned int i=0;i<4;i++){
  setup();unsigned int cmd=commands[i];bool pass=cmd==PPPIOCSPASS || cmd==PPPIOCSPASS32;
  struct bpf_prog **which=pass?&unit.pass_filter:&unit.active_filter;
  assert(!real_ioctl_cases(&unit,cmd,NULL));assert(!begins && !freed_filters); /* absent -> absent */
  supplied_filter=&filters[0];u32 old=netdev_ppp_path_cookie(&device);
  assert(!real_ioctl_cases(&unit,cmd,NULL));assert(*which==supplied_filter && begins==1 && ends==1 && !netdev_ppp_path_valid(&device,old));
  assert(!allows(ETH_P_IP) && !allows(ETH_P_IPV6));
  assert(!real_ioctl_cases(&unit,cmd,NULL));assert(begins==1 && !freed_filters); /* same identity test backend */
  supplied_filter=&filters[1];assert(!real_ioctl_cases(&unit,cmd,NULL));assert(begins==2 && freed_filters==1);
  filter_failure=true;assert(real_ioctl_cases(&unit,cmd,NULL)==-EINVAL);assert(begins==2 && *which==&filters[1]);
  filter_failure=false;supplied_filter=NULL;assert(!real_ioctl_cases(&unit,cmd,NULL));assert(begins==3 && ends==3 && freed_filters==2 && !*which);
  assert(allows(ETH_P_IP) && allows(ETH_P_IPV6));
 }
}
#endif
static void compression_cases(void){
 for(unsigned int tx=0;tx<2;tx++){
  setup();unit.flags=SC_CCP_OPEN;assert(allows(ETH_P_IP));
  u8 option[2]={1,2};struct ppp_option_data data={.ptr=option,.length=2,.transmit=tx};
  u32 old=netdev_ppp_path_cookie(&device);assert(!ppp_set_compress(&unit,&data));
  assert(begins==1 && ends==1 && !netdev_ppp_path_valid(&device,old));
  assert((tx?unit.xc_state:unit.rc_state)==allocated_state && !freed_states);
  assert(!allows(ETH_P_IP) && !allows(ETH_P_IPV6)); /* installed before CCP_UP */
  allocated_state=&state_tokens[1];assert(!ppp_set_compress(&unit,&data));assert(begins==2 && freed_states==1 && module_puts==1);
  ppp_ccp_closed(&unit);assert(begins==3 && ends==3 && freed_states==2 && module_puts==2);
  assert(!unit.flags && !unit.xc_state && !unit.rc_state && allows(ETH_P_IP) && allows(ETH_P_IPV6));
  ppp_ccp_closed(&unit);assert(begins==3); /* no-op close */
 }
 setup();unit.flags=SC_CCP_OPEN;ppp_ccp_closed(&unit);assert(!begins && !unit.flags && allows(ETH_P_IP));
 for(unsigned int fail=0;fail<4;fail++){
  setup();u8 option[2]={1,2};struct ppp_option_data data={.ptr=option,.length=2,.transmit=1};
  if(fail==0)copy_failure=true;if(fail==1)alloc_failure=true;if(fail==2)missing_compressor=true;if(fail==3)data.length=1;
  assert(ppp_set_compress(&unit,&data)<0 && !begins && !unit.xc_state && !unit.rc_state);assert(allows(ETH_P_IP));
 }
 /* Closing OPEN while UP is supplied must not create an unfenced close. */
 setup();unit.flags=SC_CCP_OPEN|SC_CCP_UP;int flags=SC_CCP_UP;
 assert(!real_ioctl_cases(&unit,PPPIOCSFLAGS,&flags));assert(begins==2 && ends==2 && !unit.flags && allows(ETH_P_IP));
}
static void family_propagation(void){
 for(unsigned int xtables=0;xtables<2;xtables++)for(unsigned int dir=0;dir<2;dir++)for(unsigned int ipv6=0;ipv6<2;ipv6++){
  setup();struct nf_conn ct={0};ct.tuplehash[dir].tuple.src.l3num=ipv6?NFPROTO_IPV6:NFPROTO_IPV4;
  ct.tuplehash[!dir].tuple.src.l3num=ct.tuplehash[dir].tuple.src.l3num;
  struct dst_entry dst={.dev=&device};struct nf_flow_route route={0};struct net_device_path_stack stack={0};u8 ha[6]={0};
  unit.npmode[ipv6?NP_IP:NP_IPV6]=NPMODE_DROP;
  int ret=xtables?nf_dev_fill_forward_path(&route,&dst,&ct,dir,ha,&stack):nft_dev_fill_forward_path(&route,&dst,&ct,dir,ha,&stack);
  assert(ret==0 && decoded_proto==(ipv6?ETH_P_IPV6:ETH_P_IP));
  unit.npmode[ipv6?NP_IPV6:NP_IP]=NPMODE_DROP;
  ret=xtables?nf_dev_fill_forward_path(&route,&dst,&ct,dir,ha,&stack):nft_dev_fill_forward_path(&route,&dst,&ct,dir,ha,&stack);
  assert(ret==-EOPNOTSUPP && forwarded==1);cases+=2;
 }
 setup();unit.channels=NULL;assert(!allows(ETH_P_IP));unit.channels=&channel_owner;
 channel_owner.chan=NULL;assert(!allows(ETH_P_IP));
}
int main(void){flags_cases();namespace_cases();np_cases();compression_cases();family_propagation();
#ifdef CONFIG_PPP_FILTER
 filter_cases();
#endif
 printf("PPP production policy/selector: %u cases; actual native+compat dispatch, independent IP family, cookie fences, compressor ownership and rollback PASS (host backend)\n",cases);return 0;}
'''

mutants = {
    "bypass_cross_namespace_scrub": functions.replace("!net_eq(ppp->ppp_net, dev_net(ppp->dev))", "false", 1),
    "ignore_loop_policy": functions.replace("SC_MULTILINK | SC_LOOP_TRAFFIC |", "SC_MULTILINK |", 1),
    "require_both_ip_families_pass": functions.replace(
        "return READ_ONCE(ppp->npmode[index]) == NPMODE_PASS;",
        "return READ_ONCE(ppp->npmode[index]) == NPMODE_PASS && ppp->npmode[NP_IP] == NPMODE_PASS && ppp->npmode[NP_IPV6] == NPMODE_PASS;", 1),
    "block_plain_ccp_negotiation": functions.replace("SC_COMP_TCP | SC_CCP_UP | SC_MUST_COMP", "SC_COMP_TCP | SC_CCP_UP | SC_CCP_OPEN | SC_MUST_COMP", 1),
    "bypass_installed_compressor": functions.replace("if (READ_ONCE(ppp->xc_state) || READ_ONCE(ppp->rc_state))", "if (false)", 1),
    "bypass_active_filter": functions.replace("READ_ONCE(ppp->pass_filter) || READ_ONCE(ppp->active_filter)", "READ_ONCE(ppp->pass_filter)", 1),
    "skip_npmode_fence": functions.replace("bool ip = index == NP_IP || index == NP_IPV6;", "bool ip = false;", 1),
    "skip_filter_generation": functions.replace("WRITE_ONCE(*which, filter);", "WRITE_ONCE(*which, filter); ppp->dev->ppp_channel_generation -= 2;", 1),
    "wrong_nft_network_protocol": functions.replace(".l3_proto = ct->tuplehash[dir].tuple.src.l3num == NFPROTO_IPV4 ?", ".l3_proto = ct->tuplehash[dir].tuple.src.l3num == NFPROTO_IPV6 ?", 1),
}
for name, candidate in mutants.items():
    assert candidate != functions, name
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
environment = dict(os.environ)
environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
with tempfile.TemporaryDirectory(prefix="ppp-flow-policy-") as directory:
    directory = Path(directory)
    jobs = [(f"production-filter-{f}-multilink-{m}", functions, f, m) for f in [0, 1] for m in [0, 1]]
    jobs += [(name, candidate, 1, 1) for name, candidate in mutants.items()]
    for name, candidate, filter_enabled, multilink in jobs:
        (directory / "test.c").write_text(constants + COMMON + BACKEND + candidate + TEST)
        options = (["-DCONFIG_PPP_FILTER=1"] if filter_enabled else []) + (["-DCONFIG_PPP_MULTILINK=1"] if multilink else [])
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-parameter", "-Wno-unused-variable", "-Wno-misleading-indentation",
                        "-fsanitize=address,undefined", "-fno-sanitize-recover=all", *options,
                        str(directory / "test.c"), "-o", str(directory / "test")], check=True)
        result = subprocess.run([str(directory / "test")], capture_output=True, text=True, env=environment, timeout=30)
        if name.startswith("production"):
            assert result.returncode == 0, name + result.stdout + result.stderr
            print(name + ": " + result.stdout, end="")
        else:
            assert result.returncode != 0 and "Assertion" in result.stderr, (name, result.stdout, result.stderr)
            print("Runtime regression mutant rejected: " + name)
(ROOT / "artifacts").mkdir(exist_ok=True)
(ROOT / "artifacts/ppp-flow-policy.json").write_text(json.dumps({
    "production_functions_sha256": hashlib.sha256(functions.encode()).hexdigest(),
    "mutations_rejected": list(mutants), "sanitizers": ["address", "undefined"],
    "configurations": "CONFIG_PPP_FILTER and CONFIG_PPP_MULTILINK each on/off",
    "scope": "actual policy setters/native+compat dispatch/forward-path predicates with modeled locking, allocation and admission; not actual PPP or hardware",
    "hardware_verified": False,
}, indent=2) + "\n")
