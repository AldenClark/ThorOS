#!/usr/bin/env python3
"""Check the native parser against Linux6.18's actual NAT action builders."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--kernel', type=Path,
                    help='Prepared kernel tree (default: OpenWrt build directory)')
parser.add_argument('--revision', help='Historical native parser for a negative control')
parser.add_argument('--mutants', action='store_true', help='Reject scoped same-port admission semantic mutations')
args = parser.parse_args()
drivers = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
native = (drivers / 'rtl9617c-fe.c').read_text()
if args.revision:
    native = subprocess.check_output(['git', 'show', args.revision + ':' +
        str((drivers / 'rtl9617c-fe.c').relative_to(root))], cwd=root, text=True)
kernel = args.kernel or Path(subprocess.check_output([
    'python3', str(root / 'port/tools/project_paths.py'),
    '--kernel-directory', str(root / 'sources/openwrt')], text=True).strip())
upstream_path = kernel / 'net/netfilter/nf_flow_table_offload.c'
upstream = upstream_path.read_text()
kernel_header = (kernel / 'include/net/netfilter/nf_flow_table.h').read_text()

def function(source, name):
    start = re.search(r'^.*\b' + re.escape(name) + r'\([^;]*?\)\s*\{', source, re.M).start()
    if source[start:].startswith(name):
        start = source.rfind('\n', 0, start - 1) + 1
    end = source.index('{', start) + 1
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
#include <string.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/ppp_defs.h>
#include "rtl9617c-fe-format.h"
#include "rtl9617c-fe-observe.h"
#include "rtl9617c-pon-path.h"
typedef uint8_t u8;typedef uint16_t u16,__be16;typedef uint32_t u32;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(v) __builtin_bswap16((uint16_t)(v))
#endif
#define ETH_ALEN 6
#define ETH_HLEN 14
#define ETH_P_IP 0x800
#define ETH_P_IPV6 0x86dd
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88a8
#define ETH_P_PPP_SES 0x8864
#define VLAN_VID_MASK 4095
#define VLAN_HLEN 4
#define FE_LAN_PORTS 5
#define BIT(n) (1U<<(n))
#define BIT_ULL(n) (1ULL<<(n))
#define NF_FLOW_RULE_ACTION_MAX 24
#define NF_FLOW_TABLE_ENCAP_MAX 3
#define NF_FLOW_TABLE_VLAN_MAX 2
#define unlikely(x) (x)
enum {FLOW_DISSECTOR_KEY_META,FLOW_DISSECTOR_KEY_BASIC,FLOW_DISSECTOR_KEY_IPV4_ADDRS,
 FLOW_DISSECTOR_KEY_PORTS,FLOW_DISSECTOR_KEY_VLAN,FLOW_DISSECTOR_KEY_CVLAN,FLOW_DISSECTOR_KEY_ENC_CONTROL,FLOW_DISSECTOR_KEY_IPV6_ADDRS,FLOW_DISSECTOR_KEY_PPPOE,FLOW_DISSECTOR_KEY_CONTROL,FLOW_DISSECTOR_KEY_TCP,FLOW_DISSECTOR_KEY_ETH_ADDRS,FLOW_DISSECTOR_KEY_IP,FLOW_DISSECTOR_KEY_MAX};
enum {FLOW_ACTION_REDIRECT,FLOW_ACTION_CSUM,FLOW_ACTION_MANGLE,FLOW_ACTION_VLAN_POP,FLOW_ACTION_VLAN_PUSH,FLOW_ACTION_PPPOE_PUSH};
enum {TCA_CSUM_UPDATE_FLAG_IPV4HDR=1,TCA_CSUM_UPDATE_FLAG_ICMP=2,
 TCA_CSUM_UPDATE_FLAG_TCP=8,TCA_CSUM_UPDATE_FLAG_UDP=16,TCA_CSUM_UPDATE_FLAG_SCTP=64};
enum flow_action_mangle_base {FLOW_ACT_MANGLE_HDR_TYPE_ETH,FLOW_ACT_MANGLE_HDR_TYPE_IP4,
 FLOW_ACT_MANGLE_HDR_TYPE_TCP,FLOW_ACT_MANGLE_HDR_TYPE_UDP,FLOW_ACT_MANGLE_HDR_TYPE_IP6};
struct net_device {int ifindex;};
struct flow_dissector_key_meta {int ingress_ifindex;u16 ingress_iftype;u8 l2_miss;};
struct flow_dissector_key_basic {__be16 n_proto;u8 ip_proto;};
struct flow_dissector_key_ipv4_addrs {__be32 src,dst;};
struct flow_dissector_key_ipv6_addrs {struct in6_addr src,dst;};
struct flow_dissector_key_ports {__be16 src,dst;};
struct flow_dissector_key_vlan {unsigned int vlan_id,vlan_priority,vlan_dei;__be16 vlan_tpid,vlan_eth_type;};
struct flow_dissector_key_pppoe {__be16 session_id,ppp_proto,type;};
struct flow_dissector_key_control {unsigned short thoff,addr_type;unsigned int flags;};
struct flow_dissector_key_eth_addrs {u8 dst[6],src[6];};
struct flow_dissector_key_tcp {__be16 flags;};
struct flow_action_entry {int id;union {struct net_device *dev;u32 csum_flags;
 struct {enum flow_action_mangle_base htype;u32 offset,mask,val;} mangle;
 struct {unsigned short vid;__be16 proto;u8 prio;} vlan;struct {unsigned short sid,mtu;} pppoe;};};
struct flow_action {unsigned int num_entries;struct flow_action_entry entries[NF_FLOW_RULE_ACTION_MAX];};
struct flow_rule {
 unsigned int used;
 struct flow_dissector_key_meta meta,meta_mask;
 struct flow_dissector_key_basic basic,basic_mask;
 struct flow_dissector_key_ipv4_addrs ipv4,ipv4_mask;
 struct flow_dissector_key_ipv6_addrs ipv6,ipv6_mask;
 struct flow_dissector_key_ports ports,ports_mask;
 struct flow_dissector_key_vlan vlan,vlan_mask,cvlan,cvlan_mask;
 struct flow_dissector_key_pppoe pppoe,pppoe_mask;
 struct flow_dissector_key_control control,control_mask;
 struct flow_dissector_key_tcp tcp,tcp_mask;
 struct flow_dissector_key_eth_addrs eth,eth_mask;
 struct flow_action action;
};
struct flow_cls_offload {struct flow_rule *rule;u16 route_mtu;};
#define FLOW_MATCH(name,type) \
 struct flow_match_##name {struct flow_dissector_key_##type *key,*mask;};
FLOW_MATCH(meta,meta)
FLOW_MATCH(basic,basic)
FLOW_MATCH(ipv4_addrs,ipv4_addrs)
FLOW_MATCH(ipv6_addrs,ipv6_addrs)
FLOW_MATCH(ports,ports)
FLOW_MATCH(vlan,vlan)
FLOW_MATCH(pppoe,pppoe)
FLOW_MATCH(control,control)
FLOW_MATCH(tcp,tcp)
FLOW_MATCH(eth_addrs,eth_addrs)
static void flow_rule_match_meta(struct flow_rule *r,struct flow_match_meta *m){m->key=&r->meta;m->mask=&r->meta_mask;}
static void flow_rule_match_basic(struct flow_rule *r,struct flow_match_basic *m){m->key=&r->basic;m->mask=&r->basic_mask;}
static void flow_rule_match_ipv4_addrs(struct flow_rule *r,struct flow_match_ipv4_addrs *m){m->key=&r->ipv4;m->mask=&r->ipv4_mask;}
static void flow_rule_match_ipv6_addrs(struct flow_rule *r,struct flow_match_ipv6_addrs *m){m->key=&r->ipv6;m->mask=&r->ipv6_mask;}
static void flow_rule_match_ports(struct flow_rule *r,struct flow_match_ports *m){m->key=&r->ports;m->mask=&r->ports_mask;}
static void flow_rule_match_vlan(struct flow_rule *r,struct flow_match_vlan *m){m->key=&r->vlan;m->mask=&r->vlan_mask;}
static void flow_rule_match_cvlan(struct flow_rule *r,struct flow_match_vlan *m){m->key=&r->cvlan;m->mask=&r->cvlan_mask;}
static void flow_rule_match_pppoe(struct flow_rule *r,struct flow_match_pppoe *m){m->key=&r->pppoe;m->mask=&r->pppoe_mask;}
static void flow_rule_match_control(struct flow_rule *r,struct flow_match_control *m){m->key=&r->control;m->mask=&r->control_mask;}
static void flow_rule_match_tcp(struct flow_rule *r,struct flow_match_tcp *m){m->key=&r->tcp;m->mask=&r->tcp_mask;}
static void flow_rule_match_eth_addrs(struct flow_rule *r,struct flow_match_eth_addrs *m){m->key=&r->eth;m->mask=&r->eth_mask;}
static bool flow_rule_match_key(struct flow_rule *r,unsigned int key){return r->used&(1U<<key);}
static struct flow_rule *flow_cls_offload_flow_rule(struct flow_cls_offload *f){return f->rule;}
#define flow_action_for_each(i,act,a) for(i=0;i<(int)(a)->num_entries && ((act)=&(a)->entries[i]);i++)
static void ether_addr_copy(u8 *d,const u8 *s){memcpy(d,s,6);}
static bool is_valid_ether_addr(const u8 *m){return !(m[0]&1) && memcmp(m,"\0\0\0\0\0\0",6);}
static u32 get_unaligned(const u32 *p){u32 v;memcpy(&v,p,4);return v;}
static void put_unaligned(u32 v,u32 *p){memcpy(p,&v,4);}
struct rtl_fe;
struct rtl_fe_port {struct rtl_fe *fe;struct net_device *netdev;unsigned int source,destination,llid;};
struct rtl_fe {struct rtl_fe_port *ports[2];struct net_device *itu_netdev;struct rtl_itu_paths *itu_paths;bool naptv6;};
static struct rtl_fe_port *fe_port(struct rtl_fe *fe,struct net_device *dev){for(unsigned int i=0;i<2;i++)if(fe->ports[i]->netdev==dev)return fe->ports[i];return NULL;}
struct net {};
enum flow_offload_tuple_dir {FLOW_OFFLOAD_DIR_ORIGINAL,FLOW_OFFLOAD_DIR_REPLY};
struct flow_offload_tuple {u8 l4proto;struct in_addr src_v4,dst_v4;__be16 src_port,dst_port;
 struct in6_addr src_v6,dst_v6;
 unsigned int encap_num,in_vlan_ingress,mtu,l3proto,iifidx,xmit_type;
 struct {unsigned int iifidx;} tc;
 struct {unsigned short id;__be16 proto;} encap[NF_FLOW_TABLE_ENCAP_MAX];};
struct flow_offload {struct {struct flow_offload_tuple tuple;} tuplehash[2];};
struct nf_flow_rule {struct flow_rule *rule;};
struct nf_flow_key {
 struct flow_dissector_key_meta meta;
 struct flow_dissector_key_control control;
 struct flow_dissector_key_basic basic;
 struct flow_dissector_key_vlan vlan,cvlan;
 struct flow_dissector_key_pppoe pppoe;
 struct flow_dissector_key_ipv4_addrs ipv4;
 struct flow_dissector_key_ipv6_addrs ipv6;
 struct flow_dissector_key_tcp tcp;
 struct flow_dissector_key_ports tp;
};
struct nf_flow_match {struct {unsigned int offset[16];uint64_t used_keys;} dissector;struct nf_flow_key key,mask;};
#define NF_FLOW_DISSECTOR(m,t,f) (m)->dissector.offset[t]=offsetof(struct nf_flow_key,f)
#define FLOW_OFFLOAD_XMIT_TC 3
#define TCP_FLAG_RST 0x00040000
#define TCP_FLAG_FIN 0x00010000
#define be32_to_cpu(v) ntohl(v)
#define cpu_to_be16(v) htons(v)
struct dst_entry {void *lwtstate;};
struct ip_tunnel_info {};
static struct ip_tunnel_info *lwt_tun_info(void *state){(void)state;return NULL;}
static void nf_flow_rule_lwt_match(struct nf_flow_match *match,struct ip_tunnel_info *info){(void)match;(void)info;}
'''

test = r'''
/* Literal network addresses/ports from the verified ASIC DNS transaction.
 * MAC mangle offsets/masks are Linux's Ethernet constructor format. */
static void ethernet_actions(struct nf_flow_rule *nf,const u8 *source,const u8 *destination,struct net_device *output)
{
 u32 value,mask;uint16_t short_value;
 struct flow_action_entry *entry;
 entry=flow_action_entry_next(nf);memcpy(&short_value,source,2);value=(u32)short_value<<16;mask=0xffff;
 flow_offload_mangle(entry,FLOW_ACT_MANGLE_HDR_TYPE_ETH,4,&value,&mask);
 entry=flow_action_entry_next(nf);memcpy(&value,source+2,4);mask=0;
 flow_offload_mangle(entry,FLOW_ACT_MANGLE_HDR_TYPE_ETH,8,&value,&mask);
 entry=flow_action_entry_next(nf);memcpy(&value,destination,4);mask=0;
 flow_offload_mangle(entry,FLOW_ACT_MANGLE_HDR_TYPE_ETH,0,&value,&mask);
 entry=flow_action_entry_next(nf);memcpy(&short_value,destination+4,2);value=short_value;mask=0xffff0000;
 flow_offload_mangle(entry,FLOW_ACT_MANGLE_HDR_TYPE_ETH,4,&value,&mask);
 entry=flow_action_entry_next(nf);entry->id=FLOW_ACTION_REDIRECT;entry->dev=output;
}
/* Both routed directions resolve to the SAME physical UNI. Compile the
 * actual kernel match and VLAN/PPPoE action builders, then the production
 * parser/action encoder; a hand-written tag stack would miss wire order. */
static unsigned int same_uni_routes(struct rtl_fe_port *port,const u8 *source,const u8 *destination)
{
 unsigned int cases=0;
 for(unsigned int physical=0;physical<5;physical++)
  for(unsigned int ipv6=0;ipv6<2;ipv6++)
   for(unsigned int protocol=6;protocol<=17;protocol+=11)
    for(unsigned int in_tags=0;in_tags<3;in_tags++)
     for(unsigned int out_tags=0;out_tags<3;out_tags++)
      for(unsigned int vector=0;vector<4;vector++)
       for(unsigned int nat=0;nat<(ipv6?1U:2U);nat++)
        for(unsigned int direction=0;direction<2;direction++) {
  struct flow_offload flow={};
  port->source=port->destination=physical;
  for(unsigned int dir=0;dir<2;dir++) {
   struct flow_offload_tuple *t=&flow.tuplehash[dir].tuple;
   t->iifidx=port->netdev->ifindex;t->l3proto=ipv6?AF_INET6:AF_INET;
   t->l4proto=protocol;t->mtu=1400;
   t->src_v4.s_addr=htonl(dir?0xc6336402:0x0a000001);
   t->dst_v4.s_addr=htonl(dir?(nat?0xcb007103:0x0a000001):0xc6336402);
   t->src_port=htons(dir?443:53000);t->dst_port=htons(dir?(nat?54000:53000):443);
   for(unsigned int word=0;word<4;word++) {
    t->src_v6.s6_addr32[word]=htonl(word?word+dir*7:0x20010db8);
    t->dst_v6.s6_addr32[word]=htonl(word?word+!dir*7:0x20010db8);
   }
   t->encap_num=dir?out_tags:in_tags;
   for(unsigned int tag=0;tag<t->encap_num;tag++) {
    t->encap[tag].proto=htons((vector^dir)&BIT(tag)?ETH_P_8021AD:ETH_P_8021Q);
    /* Include VID0 priority tags and fully distinct logical VLANs. */
    t->encap[tag].id=vector?(100+100*dir+tag):tag;
   }
  }
  struct nf_flow_match match={};
  assert(!nf_flow_rule_match(&match,&flow.tuplehash[direction].tuple,NULL));
  struct flow_rule rule={.used=match.dissector.used_keys,
   .meta=match.key.meta,.meta_mask=match.mask.meta,
   .control=match.key.control,.control_mask=match.mask.control,
   .tcp=match.key.tcp,.tcp_mask=match.mask.tcp,
   .basic=match.key.basic,.basic_mask=match.mask.basic,
   .ipv4=match.key.ipv4,.ipv4_mask=match.mask.ipv4,
   .ipv6=match.key.ipv6,.ipv6_mask=match.mask.ipv6,
   .ports=match.key.tp,.ports_mask=match.mask.tp,
   .vlan=match.key.vlan,.vlan_mask=match.mask.vlan,
   .cvlan=match.key.cvlan,.cvlan_mask=match.mask.cvlan};
  struct nf_flow_rule nf={.rule=&rule};
  struct flow_cls_offload cls={.rule=&rule,.route_mtu=1400};
  struct rtl_fe_rule parsed={};
  if(nat) {
   assert(!flow_offload_ipv4_snat(NULL,&flow,direction,&nf));
   assert(!flow_offload_port_snat(NULL,&flow,direction,&nf));
  }
  assert(!linux_vlan_actions(&flow,direction,&nf));
  ethernet_actions(&nf,source,destination,port->netdev);
  assert(!fe_parse(port,&cls,&parsed));
  assert(parsed.input==port && parsed.output==port && !parsed.bridge);
  assert(parsed.key.ingress==physical && parsed.action.destination==physical);
  assert(parsed.ipv6==ipv6 && parsed.action.translate==nat && !parsed.action.deep_queue);
  if(nat) {
   assert(parsed.action.translate_destination==direction);
   assert(parsed.action.address==(direction?0x0a000001:0xcb007103));
   assert(parsed.action.port==(direction?53000:54000));
  }
  unsigned int input=flow.tuplehash[direction].tuple.encap_num;
  unsigned int output=flow.tuplehash[!direction].tuple.encap_num;
  assert(parsed.mtu==1400 && parsed.vlan_count==input && parsed.action.vlan_count==output);
  assert(parsed.action.vlan_set==(input||output));
  assert(parsed.ethernet_bytes==14+4*output);
  assert(!memcmp(parsed.source,source,6) && !memcmp(parsed.destination,destination,6));
  for(unsigned int tag=0;tag<input;tag++) {
   const typeof(flow.tuplehash[direction].tuple.encap[0]) *e=&flow.tuplehash[direction].tuple.encap[tag];
   assert(parsed.vlan[tag].vid==e->id && parsed.vlan[tag].tpid==(e->proto==htons(ETH_P_8021AD)?2:1));
  }
  for(unsigned int tag=0;tag<output;tag++) {
   const typeof(flow.tuplehash[!direction].tuple.encap[0]) *e=&flow.tuplehash[!direction].tuple.encap[tag];
   assert(parsed.action.vlan[tag].vid==e->id && parsed.action.vlan[tag].tpid==(e->proto==htons(ETH_P_8021AD)?2:1));
  }
  unsigned int words[8];rtl_fe_ipv4_action(words,&parsed.action);
  assert(((words[0]>>8)&1023)==physical); /* Exact selected egress; no L2 lookup. */
  assert((words[0]&(1U<<28)) && !(words[0]&(1U<<29))); /* L3 rewrite, not MAC keep. */
  assert((words[1]&(1U<<11)) && (words[1]&(1U<<12))); /* TTL/Hop-Limit. */
  assert(words[2]&(1U<<16)); /* Indexed next-hop destination rewrite. */
  cases++;
 }
 port->source=port->destination=0;
 return cases;
}
static unsigned int packed_bits(const unsigned int *words,unsigned int offset,unsigned int width)
{
 unsigned int result=0;
 for(unsigned int bit=0;bit<width;bit++)
  result|=((words[(offset+bit)/32]>>((offset+bit)%32))&1U)<<bit;
 return result;
}
/* Exact Linux IPv6 SNAT/DNAT and port constructors. A port-only request
 * must carry the original entire address; zero high96 is never harmless. */
static unsigned int naptv6_routes(struct rtl_fe_port *lan,struct rtl_fe_port *pon,
 const u8 *source,const u8 *destination)
{
 unsigned int cases=0;
 const unsigned short ports[]={0,1,1024,53000,65535,53,443,32768};
 for(unsigned int protocol=6;protocol<=17;protocol+=11)
  for(unsigned int dnat=0;dnat<2;dnat++)
   for(unsigned int direction=0;direction<2;direction++)
    for(unsigned int kind=0;kind<3;kind++) /* port, address, or both */
     for(unsigned int encap=0;encap<5;encap++)
      for(unsigned int vector=0;vector<8;vector++) {
  struct flow_offload flow={};
  for(unsigned int dir=0;dir<2;dir++) {
   struct flow_offload_tuple *t=&flow.tuplehash[dir].tuple;
   t->iifidx=dir?pon->netdev->ifindex:lan->netdev->ifindex;
   t->l3proto=AF_INET6;t->l4proto=protocol;t->mtu=1400;
   t->src_port=htons(dir?443:ports[vector]);
   t->dst_port=htons(dir?ports[vector]:443);
   for(unsigned int word=0;word<4;word++) {
    t->src_v6.s6_addr32[word]=htonl(word?0x12345678U+vector*7919+word*901+dir*733:0x20010db8U+dir);
    t->dst_v6.s6_addr32[word]=htonl(word?0x12345678U+vector*7919+word*901+!dir*733:0x20010db8U+!dir);
   }
  }
  struct flow_offload_tuple *reply=&flow.tuplehash[1].tuple;
  struct in6_addr *translated=dnat?&reply->src_v6:&reply->dst_v6;
  if(kind)for(unsigned int word=0;word<4;word++)
   translated->s6_addr32[word]=htonl(word?0xa1223344U+word*103+vector*317:0x20020db8U+vector);
  if(kind!=1) {
   if(dnat)reply->src_port=htons(443^0x1234);
   else reply->dst_port=htons(ports[vector]^0x1234);
  }
  unsigned int tags=encap==1?1:(encap==2||encap==4?2:0);
  bool ppp=encap>=3;
  for(unsigned int tag=0;tag<tags;tag++) {
   reply->encap[tag].proto=htons(tag?ETH_P_8021Q:ETH_P_8021AD);
   reply->encap[tag].id=100+vector*3+tag;
  }
  reply->encap_num=tags+ppp;
  if(ppp) {
   reply->encap[tags].proto=htons(ETH_P_PPP_SES);
   reply->encap[tags].id=0x1234+vector;
  }
  struct nf_flow_match match={};
  assert(!nf_flow_rule_match(&match,&flow.tuplehash[direction].tuple,NULL));
  struct flow_rule rule={.used=match.dissector.used_keys,
   .meta=match.key.meta,.meta_mask=match.mask.meta,
   .control=match.key.control,.control_mask=match.mask.control,
   .tcp=match.key.tcp,.tcp_mask=match.mask.tcp,
   .basic=match.key.basic,.basic_mask=match.mask.basic,
   .ipv4=match.key.ipv4,.ipv4_mask=match.mask.ipv4,
   .ipv6=match.key.ipv6,.ipv6_mask=match.mask.ipv6,
   .ports=match.key.tp,.ports_mask=match.mask.tp,
   .vlan=match.key.vlan,.vlan_mask=match.mask.vlan,
   .cvlan=match.key.cvlan,.cvlan_mask=match.mask.cvlan,
   .pppoe=match.key.pppoe,.pppoe_mask=match.mask.pppoe};
  struct nf_flow_rule nf={.rule=&rule};
  if(dnat) {
   assert(!flow_offload_ipv6_dnat(NULL,&flow,direction,&nf));
   assert(!flow_offload_port_dnat(NULL,&flow,direction,&nf));
  } else {
   assert(!flow_offload_ipv6_snat(NULL,&flow,direction,&nf));
   assert(!flow_offload_port_snat(NULL,&flow,direction,&nf));
  }
  assert(!linux_vlan_actions(&flow,direction,&nf));
  ethernet_actions(&nf,source,destination,direction?lan->netdev:pon->netdev);
  struct flow_cls_offload cls={.rule=&rule,.route_mtu=1400};
  struct rtl_fe_rule parsed={};struct rtl_fe_port *input=direction?pon:lan;
  lan->fe->naptv6=false;
  assert(fe_parse(input,&cls,&parsed)==-EOPNOTSUPP && parsed.reject_reason==FE_REJECT_NAT);
  lan->fe->naptv6=true;memset(&parsed,0,sizeof(parsed));
  assert(!fe_parse(input,&cls,&parsed));
  const struct flow_offload_tuple *other=&flow.tuplehash[!direction].tuple;
  bool destination_changed=dnat^direction;
  const struct in6_addr *address=destination_changed?&other->src_v6:&other->dst_v6;
  __be16 translated_port=destination_changed?other->src_port:other->dst_port;
  assert(parsed.ipv6 && parsed.action.translate && parsed.action.translate_ipv6);
  assert(parsed.action.translate_destination==destination_changed);
  for(unsigned int word=0;word<3;word++)
   assert(parsed.action.address6_high[word]==ntohl(address->s6_addr32[word]));
  assert(parsed.action.address==ntohl(address->s6_addr32[3]));
  assert(parsed.action.port==ntohs(translated_port));
  assert(parsed.action.destination==(direction?lan->destination:pon->destination));
  assert(parsed.action.vlan_count==(direction?0:tags));
  assert(parsed.pppoe_input==(ppp&&direction));
  assert(parsed.egress_pppoe==((ppp&&!direction)?3U|((0x1234+vector)<<2):0));
  assert(parsed.action.pppoe_pop==(ppp&&direction));
  unsigned int packed[RTL_FE_NAPTV6_ACTION_WORDS];
  memset(packed,255,sizeof(packed));rtl_fe_naptv6_action(packed,&parsed.action);
  assert(packed_bits(packed,45,1)==1 && packed_bits(packed,46,1)==destination_changed);
  assert(packed_bits(packed,47,32)==ntohl(address->s6_addr32[3]));
  assert(packed_bits(packed,79,1)==1 && packed_bits(packed,224,1)==1);
  for(unsigned int word=0;word<3;word++)
   assert(packed_bits(packed,225+32*word,32)==ntohl(address->s6_addr32[2-word]));
  assert(packed_bits(packed,191,16)==ntohs(translated_port));
  assert(!(packed[10]&~1U) && !packed[11]);
  /* A supported L4 checksum does not imply an IPv4 header checksum. */
  unsigned int n=rule.action.num_entries++;
  rule.action.entries[n]=rule.action.entries[n-1];
  rule.action.entries[n-1]=(struct flow_action_entry){.id=FLOW_ACTION_CSUM,
   .csum_flags=protocol==IPPROTO_TCP?TCA_CSUM_UPDATE_FLAG_TCP:TCA_CSUM_UPDATE_FLAG_UDP};
  memset(&parsed,0,sizeof(parsed));assert(!fe_parse(input,&cls,&parsed));
  rule.action.entries[n-1].csum_flags|=TCA_CSUM_UPDATE_FLAG_IPV4HDR;
  memset(&parsed,0,sizeof(parsed));assert(fe_parse(input,&cls,&parsed)==-EOPNOTSUPP);
  cases++;
 }
 lan->fe->naptv6=false;
 return cases;
}
static unsigned int naptv6_boundaries(struct rtl_fe_port *lan,struct rtl_fe_port *pon,
 const u8 *source,const u8 *destination)
{
 unsigned int cases=0;
 struct flow_rule base={.used=BIT(FLOW_DISSECTOR_KEY_META)|BIT(FLOW_DISSECTOR_KEY_BASIC)|
  BIT(FLOW_DISSECTOR_KEY_IPV6_ADDRS)|BIT(FLOW_DISSECTOR_KEY_PORTS),
  .meta={.ingress_ifindex=lan->netdev->ifindex},.meta_mask={.ingress_ifindex=-1},
  .basic={.n_proto=htons(ETH_P_IPV6),.ip_proto=IPPROTO_TCP},
  .basic_mask={.n_proto=65535,.ip_proto=255},
  .ports={htons(53000),htons(443)},.ports_mask={65535,65535}};
 for(unsigned int word=0;word<4;word++) {
  base.ipv6.src.s6_addr32[word]=htonl(word?0x12345678+word*31:0x20010db8);
  base.ipv6.dst.s6_addr32[word]=htonl(word?0xaabbccdd+word*37:0x20010db9);
  base.ipv6_mask.src.s6_addr32[word]=base.ipv6_mask.dst.s6_addr32[word]=~0U;
 }
 lan->fe->naptv6=true;
 for(unsigned int side=0;side<2;side++)for(unsigned int word=0;word<4;word++) {
  struct flow_rule rule=base;struct nf_flow_rule nf={.rule=&rule};
  unsigned int offset=(side?offsetof(struct ipv6hdr,daddr):offsetof(struct ipv6hdr,saddr))+4*word;
  __be32 value=htonl(word?0x9abcdef1:0x20020db8);unsigned int mask=0;
  flow_offload_mangle(flow_action_entry_next(&nf),FLOW_ACT_MANGLE_HDR_TYPE_IP6,offset,&value,&mask);
  ethernet_actions(&nf,source,destination,pon->netdev);
  struct flow_cls_offload cls={.rule=&rule,.route_mtu=1400};struct rtl_fe_rule parsed={};
  assert(!fe_parse(lan,&cls,&parsed));
  const struct in6_addr *original=side?&base.ipv6.dst:&base.ipv6.src;
  for(unsigned int i=0;i<3;i++)
   assert(parsed.action.address6_high[i]==ntohl(i==word?value:original->s6_addr32[i]));
  assert(parsed.action.address==ntohl(word==3?value:original->s6_addr32[3]));
  assert(parsed.action.port==ntohs(side?base.ports.dst:base.ports.src));
  assert(parsed.action.translate_ipv6 && parsed.action.translate_destination==side);
  cases++;
  rule.action.entries[0].mangle.mask=1;
  memset(&parsed,0,sizeof(parsed));assert(fe_parse(lan,&cls,&parsed)==-EOPNOTSUPP);cases++;
  rule.action.entries[0].mangle.mask=0;
  if(!word) {
   rule.action.entries[0].mangle.val=htonl(0xff020003);
   memset(&parsed,0,sizeof(parsed));
   assert(fe_parse(lan,&cls,&parsed)==-EOPNOTSUPP && parsed.reject_reason==FE_REJECT_NAT);cases++;
  }
  const unsigned int invalid_offsets[]={0,4,7,9,23,25,39,40,44,~0U};
  rule.action.entries[0].mangle.val=value;
  for(unsigned int i=0;i<sizeof(invalid_offsets)/sizeof(invalid_offsets[0]);i++) {
   rule.action.entries[0].mangle.offset=invalid_offsets[i];
   memset(&parsed,0,sizeof(parsed));assert(fe_parse(lan,&cls,&parsed)==-EOPNOTSUPP);cases++;
  }
 }
 /* One 321-bit action carries exactly one translated address/port side.
  * Opposite-side address or port edits cannot be silently discarded. */
 for(unsigned int protocol=6;protocol<=17;protocol+=11)
  for(unsigned int src_port=0;src_port<2;src_port++)for(unsigned int dst_port=0;dst_port<2;dst_port++) {
   struct flow_rule rule=base;rule.basic.ip_proto=protocol;
   struct nf_flow_rule nf={.rule=&rule};u32 mask=0,value;
   if(!src_port) {
    value=htonl(0x20020db8);
    flow_offload_mangle(flow_action_entry_next(&nf),FLOW_ACT_MANGLE_HDR_TYPE_IP6,
     offsetof(struct ipv6hdr,saddr),&value,&mask);
   }
   if(!dst_port) {
    value=htonl(0x20030db8);
    flow_offload_mangle(flow_action_entry_next(&nf),FLOW_ACT_MANGLE_HDR_TYPE_IP6,
     offsetof(struct ipv6hdr,daddr),&value,&mask);
   }
   if(src_port||dst_port) {
    __be16 pair[]={src_port?htons(12345):rule.ports.src,dst_port?htons(8443):rule.ports.dst};
    memcpy(&value,pair,4);
    flow_offload_mangle(flow_action_entry_next(&nf),protocol==IPPROTO_TCP?
     FLOW_ACT_MANGLE_HDR_TYPE_TCP:FLOW_ACT_MANGLE_HDR_TYPE_UDP,0,&value,&mask);
   }
   ethernet_actions(&nf,source,destination,pon->netdev);
   struct flow_cls_offload cls={.rule=&rule,.route_mtu=1400};struct rtl_fe_rule parsed={};
   assert(fe_parse(lan,&cls,&parsed)==-EOPNOTSUPP && parsed.reject_reason==FE_REJECT_NAT);cases++;
  }
 lan->fe->naptv6=false;
 return cases;
}
int main(void)
{
 struct net_device lan={.ifindex=2},pon={.ifindex=4};
 struct rtl_fe_port lp={.netdev=&lan,.source=0,.destination=0},pp={.netdev=&pon,.source=7,.destination=32};
 struct rtl_fe fe={.ports={&lp,&pp}};lp.fe=pp.fe=&fe;
 const u8 source[6]={2,0x66,0x55,0x44,0x33,0x22},destination[6]={2,0x77,0x66,0x55,0x44,0x33};
 unsigned int cases=0;
 for(unsigned int protocol=6;protocol<=17;protocol+=11)
  for(unsigned int vector=0;vector<256;vector++)
   for(unsigned int dir=0;dir<2;dir++) {
    unsigned int port=1+vector*65534/255;
    struct flow_offload flow={};
    flow.tuplehash[0].tuple=(struct flow_offload_tuple){.l4proto=protocol,.src_v4={.s_addr=htonl(0x0a172a01)},
     .dst_v4={.s_addr=htonl(0x74e46f76)},.src_port=htons(port),.dst_port=htons(53)};
    flow.tuplehash[1].tuple=(struct flow_offload_tuple){.l4proto=protocol,.src_v4={.s_addr=htonl(0x74e46f76)},
     .dst_v4={.s_addr=htonl(0xc0a8471c)},.src_port=htons(53),.dst_port=htons(65536-port)};
    struct flow_offload_tuple *t=&flow.tuplehash[dir].tuple;
    struct flow_rule rule={.used=15,.meta={.ingress_ifindex=dir?4:2},.meta_mask={.ingress_ifindex=-1},
     .basic={.n_proto=htons(ETH_P_IP),.ip_proto=protocol},.basic_mask={.n_proto=htons(65535),.ip_proto=255},
     .ipv4={t->src_v4.s_addr,t->dst_v4.s_addr},.ipv4_mask={~0U,~0U},.ports={t->src_port,t->dst_port},.ports_mask={65535,65535}};
    struct nf_flow_rule nf={.rule=&rule};struct flow_cls_offload cls={.rule=&rule,.route_mtu=1500};
    struct rtl_fe_rule parsed={};
    assert(!flow_offload_ipv4_snat(NULL,&flow,dir,&nf));
    assert(!flow_offload_port_snat(NULL,&flow,dir,&nf));
    ethernet_actions(&nf,source,destination,dir?&lan:&pon);
    assert(!fe_parse(dir?&pp:&lp,&cls,&parsed));
    assert(parsed.mtu==1500);
    assert(parsed.key.source==ntohl(t->src_v4.s_addr) && parsed.key.destination==ntohl(t->dst_v4.s_addr));
    assert(parsed.key.source_port==ntohs(t->src_port) && parsed.key.destination_port==ntohs(t->dst_port));
    assert(parsed.action.translate && parsed.action.translate_destination==dir);
    assert(parsed.action.address==(dir?0x0a172a01:0xc0a8471c));
    assert(parsed.action.port==(dir?port:65536-port));
    assert(parsed.action.destination==(dir?0:32) && parsed.action.deep_queue==!dir);
    assert(parsed.action.check_mask==63);
    assert(!memcmp(parsed.source,source,6) && !memcmp(parsed.destination,destination,6));
    rule.used|=1U<<FLOW_DISSECTOR_KEY_VLAN;
    assert(fe_parse(dir?&pp:&lp,&cls,&parsed)==-EOPNOTSUPP);
    rule.used&=~(1U<<FLOW_DISSECTOR_KEY_VLAN);
    rule.ports_mask.src=htons(0xff00);
    assert(fe_parse(dir?&pp:&lp,&cls,&parsed)==-EOPNOTSUPP);
    cases++;
   }
 for(unsigned int direction=0;direction<2;direction++)
  for(unsigned int protocol=6;protocol<=17;protocol+=11) {
   struct flow_rule rule={.used=(1U<<FLOW_DISSECTOR_KEY_META)|(1U<<FLOW_DISSECTOR_KEY_BASIC)|
    (1U<<FLOW_DISSECTOR_KEY_PORTS)|(1U<<FLOW_DISSECTOR_KEY_IPV6_ADDRS),
    .meta={.ingress_ifindex=direction?4:2},.meta_mask={.ingress_ifindex=-1},.basic={.n_proto=htons(ETH_P_IPV6),.ip_proto=protocol},
    .basic_mask={.n_proto=65535,.ip_proto=255},.ports={htons(53123),htons(443)},.ports_mask={65535,65535}};
   struct nf_flow_rule nf={.rule=&rule};struct flow_cls_offload cls={.rule=&rule,.route_mtu=1400};
   struct rtl_fe_rule parsed={};
   for(unsigned int word=0;word<4;word++) {
    rule.ipv6.src.s6_addr32[word]=htonl(0x20010db8+word*37);
    rule.ipv6.dst.s6_addr32[word]=htonl(0x20010db8+word*103+1);
    rule.ipv6_mask.src.s6_addr32[word]=~0U;rule.ipv6_mask.dst.s6_addr32[word]=~0U;
   }
   ethernet_actions(&nf,source,destination,direction?&lan:&pon);
   assert(!fe_parse(direction?&pp:&lp,&cls,&parsed) && parsed.ipv6 && !parsed.action.translate);
   assert(parsed.mtu==1400);
   for(unsigned int word=0;word<4;word++) {
    assert(parsed.key6.source[word]==0x20010db8+word*37);
    assert(parsed.key6.destination[word]==0x20010db8+word*103+1);
   }
   assert(parsed.action.destination==(direction?0:32));
   assert(parsed.action.check_mask==63);
   assert(parsed.key6.source_port==53123 && parsed.key6.destination_port==443);
   cases++;
  }
 unsigned int vlan_cases=0;
 for(unsigned int input=0;input<=2;input++)
  for(unsigned int output=0;output<=2;output++)
   for(unsigned int vector=0;vector<16;vector++)
    for(unsigned int protocol=6;protocol<=17;protocol+=11) {
     struct flow_rule rule={.used=15,.meta={.ingress_ifindex=2},.meta_mask={.ingress_ifindex=-1},
      .basic={.n_proto=htons(ETH_P_IP),.ip_proto=protocol},.basic_mask={.n_proto=htons(65535),.ip_proto=255},
      .ipv4={htonl(0x0a172a01),htonl(0x74e46f76)},.ipv4_mask={~0U,~0U},
      .ports={htons(53000),htons(53)},.ports_mask={65535,65535}};
     struct nf_flow_rule nf={.rule=&rule};struct flow_cls_offload cls={.rule=&rule,.route_mtu=1400};
     struct flow_offload flow={};struct rtl_fe_rule parsed={};
     unsigned int id=vector*4095/15;
     flow.tuplehash[0].tuple.encap_num=input;flow.tuplehash[1].tuple.encap_num=output;
     for(unsigned int tag=0;tag<input;tag++) {
      flow.tuplehash[0].tuple.encap[tag].id=(id+tag)&4095;
      flow.tuplehash[0].tuple.encap[tag].proto=htons(vector&BIT(tag)?ETH_P_8021AD:ETH_P_8021Q);
      rule.used|=1U<<(tag?FLOW_DISSECTOR_KEY_CVLAN:FLOW_DISSECTOR_KEY_VLAN);
      nf_flow_rule_vlan_match(tag?&rule.cvlan:&rule.vlan,tag?&rule.cvlan_mask:&rule.vlan_mask,
                             (id+tag)&4095,flow.tuplehash[0].tuple.encap[tag].proto);
     }
     for(unsigned int tag=0;tag<output;tag++) {
      flow.tuplehash[1].tuple.encap[tag].id=(4095-id+tag)&4095;
      flow.tuplehash[1].tuple.encap[tag].proto=htons(vector&BIT(tag+2)?ETH_P_8021AD:ETH_P_8021Q);
     }
     assert(!linux_vlan_actions(&flow,0,&nf));
     ethernet_actions(&nf,source,destination,&pon);
     assert(!fe_parse(&lp,&cls,&parsed));
     assert(parsed.mtu==1400); /* Logical VLAN/route limit, not physical1500. */
     assert(parsed.vlan_count==input && parsed.action.vlan_count==output);
     assert(parsed.action.vlan_set==(input!=0||output!=0));
     assert(parsed.ethernet_bytes==14+4*output);
     for(unsigned int tag=0;tag<input;tag++)
      assert(parsed.vlan[tag].vid==((id+tag)&4095) && parsed.vlan[tag].tpid==(vector&BIT(tag)?2:1));
     /* Core stores outermost first; reverse PUSH must preserve wire order. */
     for(unsigned int tag=0;tag<output;tag++)
      assert(parsed.action.vlan[tag].vid==((4095-id+tag)&4095) && parsed.action.vlan[tag].tpid==(vector&BIT(tag+2)?2:1));
     unsigned int packed[8],key[23];rtl_fe_ipv4_action(packed,&parsed.action);
     rtl_fe_ipv4_key(key,&parsed.key);rtl_fe_vlan_key(key,parsed.vlan,parsed.vlan_count);
     assert((packed[5]&12)==(output<<2)); /* Literal group20 final VLAN count at162. */
     assert(((key[14]>>16)&3)==input);   /* Parser VLAN count at464. */
     if(input) {
      rule.vlan.vlan_tpid=htons(ETH_P_8021AD);
      assert(!fe_parse(&lp,&cls,&parsed) && parsed.vlan[0].tpid==2);
      rule.vlan_mask.vlan_id=255;
      assert(fe_parse(&lp,&cls,&parsed)==-EOPNOTSUPP);
     }
     vlan_cases++;
    }
 unsigned int pppoe_cases=0;
 for(unsigned int direction=0;direction<2;direction++)
  for(unsigned int ipv6=0;ipv6<2;ipv6++)
   for(unsigned int protocol=6;protocol<=17;protocol+=11)
    for(unsigned int tags=1;tags<=2;tags++)
     for(unsigned int tpids=0;tpids<4;tpids++)
   for(unsigned int sid=1;sid<=0xabcd;sid+=0xabcc) {
    struct flow_offload flow={};
    flow.tuplehash[0].tuple.mtu=1492;
    flow.tuplehash[1].tuple.mtu=1500;
    for(unsigned int dir=0;dir<2;dir++) {
     struct flow_offload_tuple *t=&flow.tuplehash[dir].tuple;
     t->iifidx=dir?4:2;t->l3proto=ipv6?AF_INET6:AF_INET;t->l4proto=protocol;
     t->src_v4.s_addr=htonl(dir?0x74e46f76:0x0a172a01);
     t->dst_v4.s_addr=htonl(dir?0xc0a8471c:0x74e46f76);
     t->src_port=htons(dir?443:53123);t->dst_port=htons(dir?12341:443);
     for(unsigned int word=0;word<4;word++) {
      t->src_v6.s6_addr32[word]=htonl(0x20010db8+word+(dir?10:0));
      t->dst_v6.s6_addr32[word]=htonl(0x20010db8+word+(dir?0:10));
     }
    }
    struct flow_offload_tuple *input=&flow.tuplehash[1].tuple;
    flow.tuplehash[1].tuple.encap_num=tags+1;
    for(unsigned int tag=0;tag<tags;tag++) {
     flow.tuplehash[1].tuple.encap[tag].proto=htons(tpids&BIT(tag)?ETH_P_8021AD:ETH_P_8021Q);
     flow.tuplehash[1].tuple.encap[tag].id=100+tag;
    }
    flow.tuplehash[1].tuple.encap[tags].proto=htons(ETH_P_PPP_SES);
    flow.tuplehash[1].tuple.encap[tags].id=sid;
    struct nf_flow_match match={};
    assert(!nf_flow_rule_match(&match,input,NULL));
    assert(match.dissector.used_keys&BIT_ULL(FLOW_DISSECTOR_KEY_PPPOE));
    assert(match.key.basic.n_proto==htons(ETH_P_PPP_SES));
    assert(match.key.pppoe.session_id==htons(sid));
    assert(match.key.pppoe.ppp_proto==htons(ipv6?PPP_IPV6:PPP_IP));
    assert(match.mask.pppoe.session_id==65535 && match.mask.pppoe.ppp_proto==65535);
    assert(match.key.meta.ingress_ifindex==4 && match.key.vlan.vlan_id==100);
    memset(&match,0,sizeof(match));
    assert(!nf_flow_rule_match(&match,&flow.tuplehash[direction].tuple,NULL));
    struct flow_rule rule={.used=match.dissector.used_keys,.meta=match.key.meta,.meta_mask=match.mask.meta,
     .control=match.key.control,.control_mask=match.mask.control,.tcp=match.key.tcp,.tcp_mask=match.mask.tcp,
     .basic=match.key.basic,.basic_mask=match.mask.basic,
     .ipv4=match.key.ipv4,.ipv4_mask=match.mask.ipv4,
     .ipv6=match.key.ipv6,.ipv6_mask=match.mask.ipv6,
     .ports=match.key.tp,.ports_mask=match.mask.tp,
     .vlan=match.key.vlan,.vlan_mask=match.mask.vlan,
     .cvlan=match.key.cvlan,.cvlan_mask=match.mask.cvlan,
     .pppoe=match.key.pppoe,.pppoe_mask=match.mask.pppoe};
    struct nf_flow_rule nf={.rule=&rule};struct flow_cls_offload cls={.rule=&rule,.route_mtu=direction?1500:1492};
    struct rtl_fe_rule parsed={};unsigned int words[8];
    if(!ipv6) {
     assert(!flow_offload_ipv4_snat(NULL,&flow,direction,&nf));
     assert(!flow_offload_port_snat(NULL,&flow,direction,&nf));
    }
    assert(!linux_vlan_actions(&flow,direction,&nf));
    ethernet_actions(&nf,source,destination,direction?&lan:&pon);
    assert(!fe_parse(direction?&pp:&lp,&cls,&parsed));
    assert(parsed.ipv6==ipv6 && parsed.pppoe_input==direction);
    assert(parsed.action.translate==!ipv6);
    if(!ipv6)assert(parsed.action.address==(direction?0x0a172a01:0xc0a8471c));
    assert(parsed.pppoe_session==(direction?sid:0));
    assert(parsed.egress_pppoe==(direction?0:3U|sid<<2));
    assert(parsed.mtu==(direction?1500:1492));
    assert(parsed.ethernet_bytes==(direction?14:22+4*tags));
    assert(parsed.vlan_count==(direction?tags:0));
    assert(parsed.action.vlan_count==(direction?0:tags));
    for(unsigned int tag=0;tag<tags;tag++) {
     const struct rtl_fe_vlan *v=direction?&parsed.vlan[tag]:&parsed.action.vlan[tag];
     assert(v->vid==100+tag && v->tpid==(tpids&BIT(tag)?2:1));
    }
    pppoe_cases++;
    for(unsigned int llid=0;llid<32;llid++) {
     pp.llid=llid;pp.destination=32+llid;
     memset(&parsed,0,sizeof(parsed));
     assert(!fe_parse(direction?&pp:&lp,&cls,&parsed));
     assert(parsed.key.llid==(direction?llid:0));
     assert(parsed.key6.llid==(ipv6&&direction?llid:0));
     assert(parsed.action.destination==(direction?0:32+llid));
    }
    pp.llid=0;pp.destination=32;
    struct rtl_itu_paths paths={.count=1,.path={{.alloc_id=1063,.gem_id=0x8327,
     .vlan=100,.tcont=3,.pbits=255,.downstream_pbits=255,.queue=2,.encrypted=1,.index=8}}};
    fe.itu_netdev=&pon;fe.itu_paths=&paths;
    memset(&parsed,0,sizeof(parsed));
    assert(!fe_parse(direction?&pp:&lp,&cls,&parsed));
    assert(parsed.key.llid==(direction?8:0));
    if(ipv6)assert(parsed.key6.llid==(direction?8:0));
    assert(parsed.action.destination==(direction?0:35));
    assert(parsed.action.gem_set==!direction && parsed.action.deep_queue==!direction);
    if(!direction)assert(parsed.action.gem_index==8 && parsed.action.cos==2);
    paths.path[0].pbits=1;
    memset(&parsed,0,sizeof(parsed));
    assert(fe_parse(direction?&pp:&lp,&cls,&parsed)==(direction?0:-EOPNOTSUPP));
    paths.path[0].downstream_pbits=1;
    memset(&parsed,0,sizeof(parsed));
    assert(fe_parse(direction?&pp:&lp,&cls,&parsed)==-EOPNOTSUPP);
    paths.count=0;
    memset(&parsed,0,sizeof(parsed));
    assert(fe_parse(direction?&pp:&lp,&cls,&parsed)==-EOPNOTSUPP);
    fe.itu_netdev=NULL;fe.itu_paths=NULL;
    memset(&parsed,0,sizeof(parsed));
    assert(!fe_parse(direction?&pp:&lp,&cls,&parsed));
    rtl_fe_ipv4_action(words,&parsed.action);
    assert(((words[190/32]>>(190%32))&1)==direction);
    assert(!((words[189/32]>>(189%32))&1));
    if(!direction) {
     /* A second, inconsistent MTU must not silently replace the route's. */
     cls.route_mtu=1400;memset(&parsed,0,sizeof(parsed));
     assert(fe_parse(&lp,&cls,&parsed)==-EOPNOTSUPP);
    }
   }

 unsigned int bridge_cases=0;
 unsigned int ethernet_types[]={0x800,0x86dd,0x8864,0x806};
 for(unsigned int kind=0;kind<4;kind++)
  for(unsigned int direction=0;direction<2;direction++)
   for(unsigned int tags=0;tags<3;tags++) {
    struct flow_rule rule={.used=BIT(FLOW_DISSECTOR_KEY_BASIC)|BIT(FLOW_DISSECTOR_KEY_ETH_ADDRS),
     .basic={.n_proto=htons(ethernet_types[kind])},.basic_mask={.n_proto=65535}};
    struct flow_cls_offload cls={.rule=&rule};struct rtl_fe_rule parsed={};
    unsigned int words[8];
    memcpy(rule.eth.src,source,6);memcpy(rule.eth.dst,destination,6);
    memset(&rule.eth_mask,255,sizeof(rule.eth_mask));
    rule.action.entries[0]=(struct flow_action_entry){.id=FLOW_ACTION_REDIRECT,.dev=direction?&lan:&pon};
    rule.action.num_entries=1;
    if(tags) {
     rule.used|=BIT(FLOW_DISSECTOR_KEY_VLAN);
     rule.vlan=(struct flow_dissector_key_vlan){.vlan_id=100,.vlan_tpid=htons(ETH_P_8021Q)};
     rule.vlan_mask=(struct flow_dissector_key_vlan){.vlan_id=4095,.vlan_tpid=65535};
    }
    if(tags==2) {
     rule.used|=BIT(FLOW_DISSECTOR_KEY_CVLAN);
     rule.cvlan=rule.vlan;rule.cvlan.vlan_id=200;rule.cvlan_mask=rule.vlan_mask;
    }
    if(kind==2) {
     rule.used|=BIT(FLOW_DISSECTOR_KEY_PPPOE);
     rule.pppoe.session_id=htons(0x1234);rule.pppoe_mask.session_id=65535;
    }
    assert(!fe_parse(direction?&pp:&lp,&cls,&parsed));
    assert(parsed.bridge && parsed.action.bridge && parsed.action.check_mask==61);
    assert(!memcmp(parsed.source,source,6) && !memcmp(parsed.destination,destination,6));
    assert(parsed.ethernet_protocol==ethernet_types[kind] && parsed.vlan_count==tags);
    assert(parsed.action.destination==(direction?0:32));
    assert(parsed.pppoe_session==(kind==2?0x1234:0));
    assert(!parsed.egress_pppoe && !parsed.action.pppoe_pop && !parsed.action.translate);
    rtl_fe_ipv4_action(words,&parsed.action);
    assert((words[29/32]>>(29%32))&1);
    for(unsigned int i=0;i<4;i++) {
     unsigned int bit=(unsigned int[]){28,43,44,80}[i];
     assert(!((words[bit/32]>>(bit%32))&1));
    }
    if(tags==1) {
     rule.action.entries[0]=(struct flow_action_entry){.id=FLOW_ACTION_VLAN_POP};
     rule.action.entries[1]=(struct flow_action_entry){.id=FLOW_ACTION_VLAN_PUSH,.vlan={.vid=300,.proto=htons(ETH_P_8021Q),.prio=5}};
     rule.action.entries[2]=(struct flow_action_entry){.id=FLOW_ACTION_REDIRECT,.dev=direction?&lan:&pon};
     rule.action.num_entries=3;
     memset(&parsed,0,sizeof(parsed));
     assert(!fe_parse(direction?&pp:&lp,&cls,&parsed));
     assert(parsed.action.vlan_set && parsed.action.vlan_count==1 && parsed.action.vlan[0].vid==300);
    }
    bridge_cases++;
   }
 /* Exact nft rule admission must not silently discard a new predicate or
  * synthesize a partly unspecified MAC rewrite. Each mutation starts fresh. */
 struct flow_rule base={.used=15,.meta={.ingress_ifindex=2},.meta_mask={.ingress_ifindex=-1},
  .basic={.n_proto=htons(ETH_P_IP),.ip_proto=IPPROTO_TCP},.basic_mask={.n_proto=65535,.ip_proto=255},
  .ipv4={htonl(0x0a000002),htonl(0xc6336401)},.ipv4_mask={~0U,~0U},
  .ports={htons(53000),htons(443)},.ports_mask={65535,65535}};
 struct nf_flow_rule nf={.rule=&base};ethernet_actions(&nf,source,destination,&pon);
 unsigned int same_uni_cases=same_uni_routes(&lp,source,destination);
 unsigned int naptv6_cases=naptv6_routes(&lp,&pp,source,destination);
 unsigned int naptv6_boundary_cases=naptv6_boundaries(&lp,&pp,source,destination);
 /* Same-port eligibility is not a general hairpin/PON escape hatch. */
 for(unsigned int source_port=0;source_port<8;source_port++)
  for(unsigned int destination_port=0;destination_port<8;destination_port++) {
   struct flow_rule rule=base;
   struct flow_cls_offload cls={.rule=&rule,.route_mtu=1500};struct rtl_fe_rule parsed={};
   rule.action.entries[rule.action.num_entries-1].dev=&lan;
   lp.source=source_port;lp.destination=destination_port;
   int ret=fe_parse(&lp,&cls,&parsed);
   if(source_port<5 && source_port==destination_port)assert(!ret);
   else assert(ret==-EOPNOTSUPP && parsed.reject_reason==FE_REJECT_PORT);
  }
 lp.source=lp.destination=0;
 {
  struct flow_rule rule=base;
  struct flow_cls_offload cls={.rule=&rule,.route_mtu=1500};struct rtl_fe_rule parsed={};
  rule.meta.ingress_ifindex=pon.ifindex; /* same PON physical netdev */
  assert(fe_parse(&pp,&cls,&parsed)==-EOPNOTSUPP && parsed.reject_reason==FE_REJECT_PORT);
  rule=base;rule.action.entries[rule.action.num_entries-1].dev=&lan;
  rule.used=BIT(FLOW_DISSECTOR_KEY_BASIC)|BIT(FLOW_DISSECTOR_KEY_ETH_ADDRS);
  rule.basic.ip_proto=rule.basic_mask.ip_proto=0;
  memcpy(rule.eth.src,source,6);memcpy(rule.eth.dst,destination,6);
  memset(&rule.eth_mask,255,sizeof(rule.eth_mask));
  rule.action.entries[0]=(struct flow_action_entry){.id=FLOW_ACTION_REDIRECT,.dev=&lan};
  rule.action.num_entries=1;memset(&parsed,0,sizeof(parsed));
  assert(fe_parse(&lp,&cls,&parsed)==-EOPNOTSUPP && parsed.reject_reason==FE_REJECT_PORT);
 }
 /* The ordinary hash domain is unicast-only. A multicast IP MDB miss
  * must never find an installed ordinary route with the same IP tuple;
  * NAT cannot introduce a multicast/reserved endpoint either. Exercise
  * actual fe_parse and the same action list used by Linux above. */
 unsigned int multicast_cases=0;
 const unsigned int multicast4[]={0xe0000001U,0xef010203U,0xf0000001U,0xffffffffU};
 for(unsigned int protocol=6;protocol<=17;protocol+=11)
  for(unsigned int side=0;side<2;side++)for(unsigned int ip=0;ip<4;ip++) {
   struct flow_rule rule=base;
   rule.basic.ip_proto=protocol;
   if(side)rule.ipv4.dst=htonl(multicast4[ip]);else rule.ipv4.src=htonl(multicast4[ip]);
   struct flow_cls_offload cls={.rule=&rule,.route_mtu=1500};struct rtl_fe_rule parsed={};
   assert(fe_parse(&lp,&cls,&parsed)==-EOPNOTSUPP && parsed.reject_reason==FE_REJECT_PROTOCOL);
   multicast_cases++;
   rule=base;rule.basic.ip_proto=protocol;
   unsigned int n=rule.action.num_entries++;
   rule.action.entries[n]=rule.action.entries[n-1];
   rule.action.entries[n-1]=(struct flow_action_entry){.id=FLOW_ACTION_MANGLE,
    .mangle={.htype=FLOW_ACT_MANGLE_HDR_TYPE_IP4,
     .offset=side?offsetof(struct iphdr,daddr):offsetof(struct iphdr,saddr),
     .val=htonl(multicast4[ip]),.mask=0}};
   memset(&parsed,0,sizeof(parsed));
   assert(fe_parse(&lp,&cls,&parsed)==-EOPNOTSUPP && parsed.reject_reason==FE_REJECT_NAT);
   multicast_cases++;
  }
 for(unsigned int protocol=6;protocol<=17;protocol+=11)
  for(unsigned int side=0;side<2;side++)for(unsigned int scope=0;scope<16;scope++) {
   struct flow_rule rule=base;
   rule.used&=~BIT(FLOW_DISSECTOR_KEY_IPV4_ADDRS);rule.used|=BIT(FLOW_DISSECTOR_KEY_IPV6_ADDRS);
   rule.basic.n_proto=htons(ETH_P_IPV6);rule.basic.ip_proto=protocol;
   for(unsigned int i=0;i<4;i++) {
    rule.ipv6.src.s6_addr32[i]=htonl(i?i:0x20010db8U);
    rule.ipv6.dst.s6_addr32[i]=htonl(i?i+1:0x20010db8U);
    rule.ipv6_mask.src.s6_addr32[i]=rule.ipv6_mask.dst.s6_addr32[i]=~0U;
   }
   if(side)rule.ipv6.dst.s6_addr32[0]=htonl(0xff000000U|(scope<<16));
   else rule.ipv6.src.s6_addr32[0]=htonl(0xff000000U|(scope<<16));
   struct flow_cls_offload cls={.rule=&rule,.route_mtu=1500};struct rtl_fe_rule parsed={};
   assert(fe_parse(&lp,&cls,&parsed)==-EOPNOTSUPP && parsed.reject_reason==FE_REJECT_PROTOCOL);
   multicast_cases++;
  }
 for(unsigned int mutation=0;mutation<20;mutation++) {
  struct flow_rule rule=base;
  struct flow_cls_offload cls={.rule=&rule,.route_mtu=1500};struct rtl_fe_rule parsed={};
  switch(mutation) {
  case 0:rule.used|=BIT(FLOW_DISSECTOR_KEY_IP);break;
  case 1:rule.meta_mask.ingress_ifindex=0;break;
  case 2:rule.meta_mask.ingress_iftype=0xffff;break;
  case 3:rule.meta_mask.l2_miss=1;break;
  case 4:rule.used|=BIT(FLOW_DISSECTOR_KEY_CONTROL);rule.control_mask.flags=1;break;
  case 5:rule.used|=BIT(FLOW_DISSECTOR_KEY_CONTROL);rule.control_mask.thoff=0xffff;break;
  case 6:rule.used|=BIT(FLOW_DISSECTOR_KEY_CONTROL);rule.control_mask.addr_type=0xffff;
         rule.control.addr_type=FLOW_DISSECTOR_KEY_IPV6_ADDRS;break;
  case 7:rule.used|=BIT(FLOW_DISSECTOR_KEY_TCP);rule.tcp_mask.flags=htons(0x10);break;
  case 8:rule.used|=BIT(FLOW_DISSECTOR_KEY_TCP);rule.tcp.flags=htons(2);rule.tcp_mask.flags=htons(2);break;
  case 9:rule.used|=BIT(FLOW_DISSECTOR_KEY_PPPOE);break;
  case 10:rule.used|=BIT(FLOW_DISSECTOR_KEY_IPV6_ADDRS);break;
  case 11:rule.action.entries[0].mangle.mask=~0U;break;
  case 12:rule.action.entries[1].mangle.offset=10;break;
  case 13:rule.action.entries[rule.action.num_entries++]=(struct flow_action_entry){.id=FLOW_ACTION_REDIRECT,.dev=&pon};break;
  case 14:rule.used|=BIT(FLOW_DISSECTOR_KEY_ENC_CONTROL);break;
  case 15:rule.used|=BIT(FLOW_DISSECTOR_KEY_VLAN);
          rule.vlan_mask=(struct flow_dissector_key_vlan){.vlan_id=4095,.vlan_tpid=65535,.vlan_eth_type=65535};
          rule.vlan=(struct flow_dissector_key_vlan){.vlan_id=100,.vlan_tpid=htons(ETH_P_8021Q),.vlan_eth_type=htons(0x806)};break;
  case 16:rule.action.entries[0]=(struct flow_action_entry){.id=FLOW_ACTION_MANGLE,
          .mangle={.htype=FLOW_ACT_MANGLE_HDR_TYPE_UDP}};break;
  case 17:rule.action.entries[0]=(struct flow_action_entry){.id=FLOW_ACTION_CSUM,
          .csum_flags=TCA_CSUM_UPDATE_FLAG_SCTP};break;
  case 18:rule.action.entries[0]=(struct flow_action_entry){.id=FLOW_ACTION_CSUM,
          .csum_flags=TCA_CSUM_UPDATE_FLAG_UDP};break;
  case 19:rule.action.entries[0]=(struct flow_action_entry){.id=FLOW_ACTION_CSUM,
          .csum_flags=TCA_CSUM_UPDATE_FLAG_ICMP};break;
  }
  assert(fe_parse(&lp,&cls,&parsed)==-EOPNOTSUPP);
  assert(parsed.reject_reason>FE_REJECT_UNSPECIFIED && parsed.reject_reason<FE_REJECT_COUNT);
 }
 for(unsigned int mask=0;mask<8;mask++) {
  struct flow_rule rule=base;struct flow_cls_offload cls={.rule=&rule,.route_mtu=1500};struct rtl_fe_rule parsed={};
  rule.used|=BIT(FLOW_DISSECTOR_KEY_TCP);rule.tcp_mask.flags=htons(mask);
  assert(!fe_parse(&lp,&cls,&parsed));
 }
 /* Insert a supported checksum action before REDIRECT without losing the
  * complete MAC rewrite; both nft TCP and UDP checksum builders are legal. */
 for(unsigned int udp=0;udp<2;udp++) {
  struct flow_rule rule=base;struct flow_cls_offload cls={.rule=&rule,.route_mtu=1500};struct rtl_fe_rule parsed={};
  rule.basic.ip_proto=udp?IPPROTO_UDP:IPPROTO_TCP;
  unsigned int n=rule.action.num_entries++;
  rule.action.entries[n]=rule.action.entries[n-1];
  rule.action.entries[n-1]=(struct flow_action_entry){.id=FLOW_ACTION_CSUM,
   .csum_flags=TCA_CSUM_UPDATE_FLAG_IPV4HDR|(udp?TCA_CSUM_UPDATE_FLAG_UDP:TCA_CSUM_UPDATE_FLAG_TCP)};
  assert(!fe_parse(&lp,&cls,&parsed));
 }
 unsigned int limits[]={0,1,68,576,1280,1400,1492,1500,0x3fff,0x4000,0xffff};
 for(unsigned int i=0;i<sizeof(limits)/sizeof(limits[0]);i++) {
  struct flow_rule rule=base;
  struct flow_cls_offload cls={.rule=&rule,.route_mtu=limits[i]};
  struct rtl_fe_rule parsed={};int ret=fe_parse(&lp,&cls,&parsed);
  if(!limits[i] || limits[i]>0x3fff)assert(ret==-EOPNOTSUPP);
  else assert(!ret && parsed.mtu==limits[i]);
 }
 printf("Native flow parser: %u NAT/IPv6, %u VLAN/QinQ, %u bidirectional PPPoE/QinQ and %u authorized bridge vectors; %u same-UNI routed vectors, %u NAPT6 original/reply vectors, %u NAPT6 boundary cases, %u multicast/NAT endpoint rejections, 20 widened-rule rejections, 8 TCP masks, valid checksum actions and per-route MTU limits passed\n",cases,vlan_cases,pppoe_cases,bridge_cases,same_uni_cases,naptv6_cases,naptv6_boundary_cases,multicast_cases);
}
'''

for name, source in [('NF_FLOW_RULE_ACTION_MAX', upstream),
                     ('NF_FLOW_TABLE_ENCAP_MAX', kernel_header),
                     ('NF_FLOW_TABLE_VLAN_MAX', kernel_header)]:
    value = re.search(r'^#define\s+' + name + r'\s+(\d+)', source, re.M)[1]
    common = re.sub(r'(#define ' + name + r' )\d+', r'\g<1>' + value, common)
parts = [common, re.search(r'struct rtl_fe_rule \{.*?\n\};', native, re.S)[0]]
parts += [function(native,n) for n in ('fe_vlan_tpid','fe_vlan_match')]
parts += [(drivers / 'rtl9617c-fe-vlan.h').read_text()]
parts += [function(native,n) for n in ('fe_parse_bridge','fe_parse')]
for name in ('flow_action_entry_next','flow_offload_mangle','flow_offload_ipv4_snat',
             'flow_offload_ipv6_mangle','flow_offload_ipv6_snat','flow_offload_ipv6_dnat',
             'flow_offload_l4proto','flow_offload_port_snat','flow_offload_port_dnat'):
    parts.append(function(upstream, name))
parts.append(function(upstream,'nf_flow_rule_vlan_match'))
parts.append(function(kernel_header,'nf_flow_tuple_encap_valid'))
parts.append(function(upstream,'nf_flow_rule_match'))
parts.append(function(upstream,'nf_flow_rule_route_encap'))
parts.append('#define linux_vlan_actions nf_flow_rule_route_encap\n')
parts.append(test)
with tempfile.TemporaryDirectory(dir=root / 'artifacts',prefix='fe-parser-') as work:
    source = Path(work) / 'parser.c'
    binary = Path(work) / 'parser'
    production = '\n'.join(parts)
    def run(candidate, mutant=None):
        source.write_text(candidate)
        subprocess.run(['cc','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',
            '-I'+str(drivers),str(source),'-o',str(binary)],check=True)
        result = subprocess.run([str(binary)],capture_output=bool(mutant),text=True)
        if mutant:
            if not result.returncode or 'Assertion' not in result.stderr:
                raise AssertionError(f'{mutant}: no runtime semantic assertion: {result.stderr}')
            print(f'PASS: actual parser rejected {mutant}')
        else:
            result.check_returncode()
    run(production)
    if args.mutants:
        routed = function(native,'fe_parse')
        bridge = function(native,'fe_parse_bridge')
        mutations = {
            'same-UNI-routes-still-rejected': (routed,
                'if(!data->output)return -EOPNOTSUPP;',
                'if(!data->output || data->input==data->output)return -EOPNOTSUPP;'),
            'unknown-source-accepted-as-UNI': (routed,
                'port->source>=FE_LAN_PORTS || ', ''),
            'non-UNI-destination-accepted': (routed,
                'port->destination!=port->source', 'false'),
            'bridge-hairpin-accidentally-opened': (bridge,
                '!data->output || data->input==data->output', '!data->output'),
            'NAPT6-accepted-in-normal-cache-mode': (routed,
                '!port->fe->naptv6', 'false'),
            'IPv6-untouched-source-words-zeroed': (routed,
                'new_source6[i]=addresses6.key->src.s6_addr32[i];', 'new_source6[i]=0;'),
            'IPv6-high96-wrong-word-order': (routed,
                'data->action.address6_high[i]=ntohl(address[i]);',
                'data->action.address6_high[i]=ntohl(address[2-i]);'),
            'opposite-NAT-side-silently-dropped': (routed,
                'if(source_changed && destination_changed)return -EOPNOTSUPP;', ''),
            'IPv6-partial-mask-silently-widened': (routed,
                '!data->ipv6 || act->mangle.mask || (offset&3)', '!data->ipv6 || (offset&3)'),
        }
        for name,(body,old,new) in mutations.items():
            if body.count(old)!=1:
                raise AssertionError(f'{name}: mutation anchor is not unique')
            run(production.replace(body,body.replace(old,new,1),1),name)
(root / 'logs/fe-flow-parser.json').write_text(json.dumps({
    'production_source_sha256':hashlib.sha256(native.encode()).hexdigest(),
    'Linux_NAT_builder_sha256':hashlib.sha256(upstream.encode()).hexdigest(),
    'Linux_version':json.loads((root / 'port/sources.lock.json').read_text())['openwrt']['kernel'],
    'TCP_UDP_both_directions':True,
    'multicast_route_and_NAT_endpoints_fall_back':True,
    'same_UNI_routed_VLAN_QinQ_vectors':2160,
    'same_UNI_narrow_identity_and_bridge_guards':True,
    'IPv6_NAT_addr_port_original_reply_vectors':960,
    'IPv6_NAT_boundary_vectors':106,
    'semantic_mutants':9 if args.mutants else 0,
    'vectors':1028,'IPv6_128bit_route_vectors':4,'Linux_VLAN_QinQ_vectors':288,'PPPoE_IPv4_IPv6_both_directions':128,'sanitizers':['ASan','UBSan'],
    'hardware_flowtable_acceptance':False,
},indent=2)+'\n')
