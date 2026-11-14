#!/usr/bin/env python3
"""Execute actual bridge/flowtable code against stable-FDB policy changes.

Netdevices, RCU, FDB and VLAN storage are modeled. This does not measure ASIC
invalidation latency or physical forwarding throughput.
"""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--kernel', type=Path, required=True)
parser.add_argument('--before', action='store_true', help='Reproduce the stable-FDB policy bypass')
args = parser.parse_args()


def function(source, name):
    match = re.search(r'^.*\b' + name + r'\([^;]*?\)\s*\{', source, re.M)
    assert match, name
    start = match.start()
    if source[start:].startswith(name + '('):
        start = source.rfind('\n', 0, start - 1) + 1
    end = source.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


common = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
typedef uint8_t u8;typedef uint16_t u16,__be16;typedef uint32_t u32;
#define CONFIG_BRIDGE_VLAN_FILTERING 1
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88a8
#define ETH_P_PPP_SES 0x8864
#define FLOW_OFFLOAD_DIR_MAX 2
#define FLOW_OFFLOAD_XMIT_DIRECT 3
#define NF_FLOW_OFFLOAD_ROUTE 1
#define BR_STATE_FORWARDING 3
#define BROPT_VLAN_ENABLED 1
#define BRIDGE_VLAN_INFO_MASTER 1
#define BRIDGE_VLAN_INFO_UNTAGGED 4
#define BRIDGE_VLAN_INFO_BRENTRY 32
#define BR_VLFLAG_ADDED_BY_SWITCHDEV 1
#define READ_ONCE(v) (v)
#define BIT(n) (1U<<(n))
#define RCU_LOCKDEP_WARN(v,s) assert(!(v))
static bool rcu_read_lock_held(void){return true;}
struct net {unsigned id;};
struct net_device {unsigned ifindex;bool bridge,running,carrier;void *priv;};
enum {DEV_PATH_BR_VLAN_KEEP,DEV_PATH_BR_VLAN_TAG,DEV_PATH_BR_VLAN_UNTAG,DEV_PATH_BR_VLAN_UNTAG_HW};
struct net_device_path {struct {unsigned vlan_mode;u16 vlan_id;__be16 vlan_proto;}bridge;};
struct net_device_path_ctx {int num_vlans;struct {u16 id;__be16 proto;}vlan[2];};
struct nft_forward_info {u32 bridge_cookie;u8 num_encaps;struct {u16 id;__be16 proto;}encap[2];};
struct net_bridge_vlan {unsigned vid;bool present;u8 state;u16 flags,priv_flags;};
struct net_bridge_vlan_group {u16 pvid;struct net_bridge_vlan vlan;};
struct net_bridge {bool filtering;u16 vlan_proto;struct net_bridge_vlan_group group;};
struct net_bridge_port {struct net_bridge *br;struct net_device *dev;u8 state;struct net_bridge_vlan_group group;};
struct net_bridge_fdb_entry {struct net_bridge_port *dst;};
static struct net net,other_net;
static struct net_bridge bridge,other_bridge;
static struct net_device brdev={.ifindex=10,.bridge=true,.running=true,.carrier=true,.priv=&bridge};
static struct net_device lan={.ifindex=2,.running=true,.carrier=true};
static struct net_device moved={.ifindex=3,.running=true,.carrier=true};
static struct net_bridge_port port={.br=&bridge,.dev=&lan,.state=BR_STATE_FORWARDING};
static struct net_bridge_port moved_port={.br=&bridge,.dev=&moved,.state=BR_STATE_FORWARDING};
static struct net_bridge_fdb_entry entry={.dst=&port};
static bool present=true;
static u16 expected_vid=7;
static bool netif_is_bridge_master(const struct net_device *d){return d->bridge;}
static bool netif_running(const struct net_device *d){return d->running;}
static bool netif_carrier_ok(const struct net_device *d){return d->carrier;}
static struct net_bridge *netdev_priv(const struct net_device *d){return d->priv;}
static struct net_bridge_port *br_port_get_check_rcu(const struct net_device *d){
 return d==&lan?&port:d==&moved?&moved_port:NULL;
}
static struct net_bridge_fdb_entry *br_fdb_find_rcu(struct net_bridge *b,const u8 *addr,u16 vid){
 return b==&bridge&&present&&addr[5]==1&&vid==expected_vid?&entry:NULL;
}
static struct net_device *br_fdb_find_port_rcu(struct net_device *b,const u8 *addr,u16 vid){
 struct net_bridge_fdb_entry *f=br_fdb_find_rcu(b->priv,addr,vid);
 return f?f->dst->dev:NULL;
}
static bool br_opt_get(struct net_bridge *b,int option){assert(option==BROPT_VLAN_ENABLED);return b->filtering;}
static struct net_bridge_vlan_group *nbp_vlan_group_rcu(const struct net_bridge_port *p){return (void *)&p->group;}
static struct net_bridge_vlan_group *br_vlan_group_rcu(struct net_bridge *b){return &b->group;}
static struct net_bridge_vlan *br_vlan_find(struct net_bridge_vlan_group *g,u16 vid){
 return g&&g->vlan.present&&g->vlan.vid==vid?&g->vlan:NULL;
}
static u8 br_vlan_get_state(const struct net_bridge_vlan *v){return v->state;}
static u16 br_get_pvid(const struct net_bridge_vlan_group *g){return g?g->pvid:0;}
struct nf_conn {struct net *net;};
struct flow_offload_tuple {unsigned xmit_type;struct {
 unsigned bridge_ifidx,bridge_port;u16 bridge_vid;u32 bridge_cookie;u8 h_dest[6];
}out;};
struct flow_offload {unsigned type;struct nf_conn *ct;struct {struct flow_offload_tuple tuple;}tuplehash[2];};
static struct net *nf_ct_net(struct nf_conn *c){return c->net;}
static struct net_device *dev_get_by_index_rcu(struct net *n,unsigned index){
 if(n!=&net)return NULL;
 return index==10?&brdev:index==2?&lan:index==3?&moved:NULL;
}
'''

cases = r'''
int main(void){
 static const u8 addr[6]={0,0,0,0,0,1};
 struct nf_conn ct={.net=&net};
 struct flow_offload flow={.type=NF_FLOW_OFFLOAD_ROUTE,.ct=&ct};
 flow.tuplehash[0].tuple=(struct flow_offload_tuple){.xmit_type=FLOW_OFFLOAD_XMIT_DIRECT,
  .out={.bridge_ifidx=10,.bridge_port=2,.bridge_vid=7,.h_dest={0,0,0,0,0,1}}};
 bridge.filtering=true;bridge.vlan_proto=htons(0x8100);
 bridge.group=(struct net_bridge_vlan_group){.pvid=7,.vlan={.vid=7,.present=true,.state=BR_STATE_FORWARDING,
  .flags=BRIDGE_VLAN_INFO_MASTER|BRIDGE_VLAN_INFO_BRENTRY}};
 port.group=bridge.group;port.group.vlan.flags=0;
#ifdef EXPECT_BEFORE
 (void)addr;
 (void)other_net;(void)other_bridge;
 assert(!nf_flow_bridge_changed(&flow));
 port.state=4;assert(!nf_flow_bridge_changed(&flow));
 port.state=BR_STATE_FORWARDING;port.group.vlan.present=false;
 assert(!nf_flow_bridge_changed(&flow));
 port.group.vlan.present=true;port.group.vlan.flags=BRIDGE_VLAN_INFO_UNTAGGED;
 assert(!nf_flow_bridge_changed(&flow));
 puts("Pre-fix: unchanged FDB hides blocked STP, removed VLAN and changed tag treatment");
#else
 u32 cookie,changed;
 /* Ordinary bridge VLAN configurations remain eligible, including tagged
  * trunks, untagged access, 802.1ad and VLANs that are not the PVID. Use the
  * kernel's actual br_vlan_should_use()/master predicates, not a boolean mock. */
 const u16 pvids[]={0,7,9};
 for(unsigned tpid=0;tpid<2;tpid++)for(unsigned untagged=0;untagged<2;untagged++)
 for(unsigned pp=0;pp<3;pp++)for(unsigned bp=0;bp<3;bp++)for(unsigned sw=0;sw<2;sw++){
  bridge.vlan_proto=htons(tpid?0x88a8:0x8100);
  bridge.group.pvid=pvids[bp];port.group.pvid=pvids[pp];
  port.group.vlan.flags=untagged?BRIDGE_VLAN_INFO_UNTAGGED:0;
  port.group.vlan.priv_flags=sw?BR_VLFLAG_ADDED_BY_SWITCHDEV:0;
  assert(br_flowtable_path_cookie_rcu(&brdev,&lan,addr,7,&cookie));
  flow.tuplehash[0].tuple.out.bridge_cookie=cookie;
  assert(!nf_flow_bridge_changed(&flow));
  struct net_device_path_ctx ctx={.num_vlans=1,.vlan={{7,bridge.vlan_proto}}};
  struct nft_forward_info info={.bridge_cookie=cookie,.num_encaps=1,.encap={{7,bridge.vlan_proto}}};
  struct net_device_path path={};
  br_vlan_fill_forward_path_pvid(&bridge,&ctx,&path);
  assert(!br_vlan_fill_forward_path_mode(&bridge,&port,&path));
  assert(nft_bridge_path_matches_cookie(&path,&info));
 }
 bridge.filtering=false;expected_vid=0;flow.tuplehash[0].tuple.out.bridge_vid=0;
 assert(br_flowtable_path_cookie_rcu(&brdev,&lan,addr,0,&cookie)&&cookie==0);
 flow.tuplehash[0].tuple.out.bridge_cookie=cookie;assert(!nf_flow_bridge_changed(&flow));
 bridge.filtering=true;expected_vid=7;flow.tuplehash[0].tuple.out.bridge_vid=7;
 bridge.vlan_proto=htons(0x8100);bridge.group.pvid=port.group.pvid=7;
 port.group.vlan.flags=port.group.vlan.priv_flags=0;
 /* A path was built, then an in-place policy update happened before cookie
  * capture. RCU cannot prevent this. The old action must never get the new
  * cookie, or subsequent lookup would incorrectly consider it current. */
 struct net_device_path_ctx ctx={.num_vlans=1,.vlan={{7,htons(ETH_P_8021Q)}}};
 struct nft_forward_info info={.num_encaps=1,.encap={{7,htons(ETH_P_8021Q)}}};
 struct net_device_path path={};
 br_vlan_fill_forward_path_pvid(&bridge,&ctx,&path);
 assert(!br_vlan_fill_forward_path_mode(&bridge,&port,&path));
 port.group.vlan.flags=BRIDGE_VLAN_INFO_UNTAGGED;
 assert(br_flowtable_path_cookie_rcu(&brdev,&lan,addr,7,&info.bridge_cookie));
 assert(!nft_bridge_path_matches_cookie(&path,&info)); /* KEEP -> UNTAG */
 assert(!br_vlan_fill_forward_path_mode(&bridge,&port,&path));
 assert(nft_bridge_path_matches_cookie(&path,&info));
 port.group.vlan.priv_flags=BR_VLFLAG_ADDED_BY_SWITCHDEV;
 assert(br_flowtable_path_cookie_rcu(&brdev,&lan,addr,7,&info.bridge_cookie));
 assert(!nft_bridge_path_matches_cookie(&path,&info)); /* UNTAG -> UNTAG_HW */
 br_vlan_fill_forward_path_pvid(&bridge,&ctx,&path);
 assert(!br_vlan_fill_forward_path_mode(&bridge,&port,&path));
 assert(nft_bridge_path_matches_cookie(&path,&info));
 port.group.vlan.flags=port.group.vlan.priv_flags=0;
 br_vlan_fill_forward_path_pvid(&bridge,&ctx,&path);
 assert(!br_vlan_fill_forward_path_mode(&bridge,&port,&path));
 bridge.vlan_proto=htons(ETH_P_8021AD);
 assert(br_flowtable_path_cookie_rcu(&brdev,&lan,addr,7,&info.bridge_cookie));
 assert(!nft_bridge_path_matches_cookie(&path,&info)); /* TPID changed */
 br_vlan_fill_forward_path_pvid(&bridge,&ctx,&path);
 assert(!br_vlan_fill_forward_path_mode(&bridge,&port,&path));
 assert(nft_bridge_path_matches_cookie(&path,&info)); /* other TPID -> PVID */
 ctx.num_vlans=0;info.num_encaps=0;
 br_vlan_fill_forward_path_pvid(&bridge,&ctx,&path);
 assert(!br_vlan_fill_forward_path_mode(&bridge,&port,&path));
 bridge.group.pvid=9;
 assert(br_flowtable_path_cookie_rcu(&brdev,&lan,addr,7,&info.bridge_cookie));
 assert(!nft_bridge_path_matches_cookie(&path,&info)); /* old PVID */
 bridge.group.pvid=7;bridge.filtering=false;
 assert(br_flowtable_path_cookie_rcu(&brdev,&lan,addr,7,&info.bridge_cookie));
 assert(!nft_bridge_path_matches_cookie(&path,&info)); /* filtering removed */
 path=(struct net_device_path){.bridge={.vlan_mode=DEV_PATH_BR_VLAN_KEEP}};
 assert(nft_bridge_path_matches_cookie(&path,&info));
 bridge.filtering=true;bridge.vlan_proto=htons(ETH_P_8021Q);
 ctx.num_vlans=1;ctx.vlan[0].proto=bridge.vlan_proto;
 info.num_encaps=2;info.encap[0].proto=bridge.vlan_proto;
 info.encap[1].id=0xbeef;info.encap[1].proto=htons(ETH_P_PPP_SES);
 assert(br_flowtable_path_cookie_rcu(&brdev,&lan,addr,7,&info.bridge_cookie));
 br_vlan_fill_forward_path_pvid(&bridge,&ctx,&path);
 assert(!br_vlan_fill_forward_path_mode(&bridge,&port,&path));
 assert(nft_bridge_path_matches_cookie(&path,&info)); /* PPPoE SID is not VID */
 assert(br_flowtable_path_cookie_rcu(&brdev,&lan,addr,7,&cookie));
 flow.tuplehash[0].tuple.out.bridge_cookie=cookie;
 assert(!nf_flow_bridge_changed(&flow));
 for(unsigned state=0;state<=4;state++){
  port.state=state;assert(nf_flow_bridge_changed(&flow)==(state!=BR_STATE_FORWARDING));
 }
 port.state=BR_STATE_FORWARDING;
 for(unsigned state=0;state<=4;state++){
  port.group.vlan.state=state;assert(nf_flow_bridge_changed(&flow)==(state!=BR_STATE_FORWARDING));
 }
 port.group.vlan.state=BR_STATE_FORWARDING;
 port.group.vlan.present=false;assert(nf_flow_bridge_changed(&flow));port.group.vlan.present=true;
 bridge.group.vlan.present=false;assert(nf_flow_bridge_changed(&flow));bridge.group.vlan.present=true;
 port.group.vlan.flags=BRIDGE_VLAN_INFO_MASTER;assert(nf_flow_bridge_changed(&flow));port.group.vlan.flags=0;
 bridge.group.vlan.flags=BRIDGE_VLAN_INFO_MASTER;assert(nf_flow_bridge_changed(&flow));
 bridge.group.vlan.flags|=BRIDGE_VLAN_INFO_BRENTRY;
 port.group.vlan.flags=BRIDGE_VLAN_INFO_UNTAGGED;assert(nf_flow_bridge_changed(&flow));
 assert(br_flowtable_path_cookie_rcu(&brdev,&lan,addr,7,&changed)&&changed!=cookie);
 port.group.vlan.flags=0;
 port.group.pvid=9;assert(nf_flow_bridge_changed(&flow));port.group.pvid=7;
 bridge.group.pvid=9;assert(nf_flow_bridge_changed(&flow));bridge.group.pvid=7;
 bridge.vlan_proto=htons(0x88a8);assert(nf_flow_bridge_changed(&flow));bridge.vlan_proto=htons(0x8100);
 port.group.vlan.priv_flags=BR_VLFLAG_ADDED_BY_SWITCHDEV;assert(nf_flow_bridge_changed(&flow));port.group.vlan.priv_flags=0;
 bridge.filtering=false;assert(nf_flow_bridge_changed(&flow));bridge.filtering=true;
 port.br=&other_bridge;assert(nf_flow_bridge_changed(&flow));port.br=&bridge;
 entry.dst=&moved_port;assert(nf_flow_bridge_changed(&flow));entry.dst=&port;
 present=false;assert(nf_flow_bridge_changed(&flow));present=true;
 lan.carrier=false;assert(nf_flow_bridge_changed(&flow));lan.carrier=true;
 lan.running=false;assert(nf_flow_bridge_changed(&flow));lan.running=true;
 brdev.running=false;assert(nf_flow_bridge_changed(&flow));brdev.running=true;
 assert(!nf_flow_bridge_changed(&flow));
 ct.net=&other_net;assert(nf_flow_bridge_changed(&flow));ct.net=&net;
 flow.type=0;assert(!nf_flow_bridge_changed(&flow));flow.type=NF_FLOW_OFFLOAD_ROUTE;
 flow.tuplehash[0].tuple.out.bridge_ifidx=0;assert(!nf_flow_bridge_changed(&flow));
 puts("Bridge policy: 72 positive VLAN paths + unfiltered bridge; old-action/new-cookie races; STP/VLAN/FDB/carrier/namespace invalidation passed");
#endif
}
'''

with tempfile.TemporaryDirectory(prefix='flowtable-bridge-policy-') as directory:
    work = Path(directory)
    kernel = args.kernel
    if args.before:
        patch = root / 'port/overlay/target/linux/rtl9617c/patches-6.18/219-flowtable-bridge-policy.patch'
        for name in re.findall(r'^\+\+\+ b/(.+)$', patch.read_text(), re.M):
            target = work / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(kernel / name, target)
        subprocess.run(['patch', '-R', '-p1', '--fuzz=0', '-i', str(patch)],
                       cwd=work, check=True, stdout=subprocess.DEVNULL)
        kernel = work
    code = common
    private = (args.kernel / 'net/bridge/br_private.h').read_text()
    for name in ('br_vlan_is_master', 'br_vlan_is_brentry', 'br_vlan_should_use'):
        code += function(private, name)
    if not args.before:
        code += function((kernel / 'net/bridge/br_fdb.c').read_text(), 'br_flowtable_path_cookie_rcu')
        vlan = (kernel / 'net/bridge/br_vlan.c').read_text()
        for name in ('br_vlan_fill_forward_path_pvid', 'br_vlan_fill_forward_path_mode'):
            code += function(vlan, name)
        code += function((kernel / 'net/netfilter/nf_flow_table_path.c').read_text(),
                         'nft_bridge_path_matches_cookie')
    code += function((kernel / 'net/netfilter/nf_flow_table_core.c').read_text(), 'nf_flow_bridge_changed')
    code += cases
    source, binary = work / 'policy.c', work / 'policy'
    source.write_text(code)
    command = ['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
               '-Wno-unused-parameter', '-Wno-unused-function', '-fsanitize=address,undefined']
    if args.before:
        command.append('-DEXPECT_BEFORE')
    subprocess.run(command + [str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
