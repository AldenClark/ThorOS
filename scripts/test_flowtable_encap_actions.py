#!/usr/bin/env python3
"""Exercise the prepared kernel's actual flowtable encapsulation match/actions.

Only transport/type shims live here. Stack validation, matching, allocation and
action construction are extracted verbatim from the selected prepared kernel.
The host action storage includes guarded spare entries to turn capacity mutants
into assertion failures rather than relying on an out-of-bounds crash.
"""

import argparse
import re
import resource
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def function(source, name):
    match = re.search(r'^.*\b' + re.escape(name) + r'\([^;]*?\)\s*\{', source, re.M)
    if match is None:
        raise RuntimeError(f'missing production function: {name}')
    start = match.start()
    if source[start:].startswith(name):
        start = source.rfind('\n', 0, start - 1) + 1
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


COMMON = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/ppp_defs.h>
typedef uint8_t u8;
typedef uint16_t u16, __be16;
typedef uint32_t u32, __be32;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#undef htons
#define htons(v) __builtin_bswap16((uint16_t)(v))
#endif
#define ETH_ALEN 6
#define ETH_P_IP 0x800
#define ETH_P_IPV6 0x86dd
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88a8
#define ETH_P_PPP_SES 0x8864
#define VLAN_VID_MASK 4095
#define BIT(n) (1U << (n))
#define BIT_ULL(n) (1ULL << (n))
#define unlikely(v) (v)
#define cpu_to_be16(v) htons(v)
#define be32_to_cpu(v) ntohl(v)
#define TCP_FLAG_RST 0x00040000
#define TCP_FLAG_FIN 0x00010000
#define FLOW_OFFLOAD_XMIT_TC 3
enum {
 FLOW_DISSECTOR_KEY_META, FLOW_DISSECTOR_KEY_CONTROL,
 FLOW_DISSECTOR_KEY_BASIC, FLOW_DISSECTOR_KEY_IPV4_ADDRS,
 FLOW_DISSECTOR_KEY_IPV6_ADDRS, FLOW_DISSECTOR_KEY_TCP,
 FLOW_DISSECTOR_KEY_PORTS, FLOW_DISSECTOR_KEY_VLAN,
 FLOW_DISSECTOR_KEY_CVLAN, FLOW_DISSECTOR_KEY_PPPOE
};
enum { FLOW_ACTION_VLAN_POP=10, FLOW_ACTION_VLAN_PUSH, FLOW_ACTION_PPPOE_PUSH };
enum flow_offload_tuple_dir { FLOW_OFFLOAD_DIR_ORIGINAL, FLOW_OFFLOAD_DIR_REPLY };
struct flow_dissector_key_vlan {
 unsigned int vlan_id, vlan_priority, vlan_dei;
 __be16 vlan_tpid, vlan_eth_type;
};
struct flow_dissector_key_meta { unsigned int ingress_ifindex; };
struct flow_dissector_key_control { unsigned int addr_type; };
struct flow_dissector_key_basic { __be16 n_proto; u8 ip_proto; };
struct flow_dissector_key_ipv4_addrs { __be32 src, dst; };
struct flow_dissector_key_ipv6_addrs { struct in6_addr src, dst; };
struct flow_dissector_key_tcp { __be16 flags; };
struct flow_dissector_key_ports { __be16 src, dst; };
struct flow_dissector_key_pppoe { __be16 session_id, ppp_proto, type; };
struct nf_flow_key {
 struct flow_dissector_key_meta meta;
 struct flow_dissector_key_control control;
 struct flow_dissector_key_basic basic;
 struct flow_dissector_key_ipv4_addrs ipv4;
 struct flow_dissector_key_ipv6_addrs ipv6;
 struct flow_dissector_key_tcp tcp;
 struct flow_dissector_key_ports tp;
 struct flow_dissector_key_vlan vlan, cvlan;
 struct flow_dissector_key_pppoe pppoe;
};
struct nf_flow_match {
 struct { uint64_t used_keys; unsigned int offset[16]; } dissector;
 struct nf_flow_key key, mask;
};
#define NF_FLOW_DISSECTOR(m,t,f) (m)->dissector.offset[t] = offsetof(struct nf_flow_key,f)
struct flow_action_entry {
 int id;
 union {
  struct { unsigned short vid; __be16 proto; u8 prio; } vlan;
  struct { unsigned short sid, mtu; } pppoe;
  unsigned char guard[24];
 };
};
struct flow_action {
 unsigned int num_entries;
 struct flow_action_entry entries[NF_FLOW_RULE_ACTION_MAX + 8];
};
struct flow_rule { struct flow_action action; };
struct nf_flow_rule { struct flow_rule *rule; };
/* Wider count/bitmap fields allow injecting corrupt metadata unreachable by
 * a well-formed bitfield. The actual kernel bitfields are checked below too. */
struct flow_offload_tuple {
 struct in_addr src_v4, dst_v4;
 struct in6_addr src_v6, dst_v6;
 __be16 src_port, dst_port;
 unsigned int iifidx, l3proto, l4proto, xmit_type, mtu;
 unsigned int encap_num, in_vlan_ingress;
 struct { unsigned int iifidx; } tc;
 struct { u16 id; __be16 proto; } encap[NF_FLOW_TABLE_ENCAP_MAX];
};
struct flow_offload { struct { struct flow_offload_tuple tuple; } tuplehash[2]; };
struct dst_entry { void *lwtstate; };
struct ip_tunnel_info {};
static struct ip_tunnel_info *lwt_tun_info(void *state)
{ (void)state; return NULL; }
static void nf_flow_rule_lwt_match(struct nf_flow_match *match, struct ip_tunnel_info *info)
{ (void)match; (void)info; }
'''


TEST = r'''
static unsigned int matches, actions, rejected;

static struct flow_offload_tuple stack(unsigned int tags, unsigned int tpids,
                                      unsigned int hidden, bool ppp)
{
 struct flow_offload_tuple t = {
  .l3proto=AF_INET, .l4proto=IPPROTO_TCP, .iifidx=7, .mtu=1492,
  .src_v4={.s_addr=htonl(0xc0000201)}, .dst_v4={.s_addr=htonl(0xc6336401)},
  .src_port=htons(53123), .dst_port=htons(443),
  .encap_num=tags+ppp, .in_vlan_ingress=hidden
 };
 for (unsigned int i=0; i<tags; i++) {
  t.encap[i].id=i ? 4094 : 0; /* VID zero must remain a real priority tag. */
  t.encap[i].proto=htons(tpids & BIT(i) ? ETH_P_8021AD : ETH_P_8021Q);
 }
 if (ppp) {
  t.encap[tags].id=0xabcd;
  t.encap[tags].proto=htons(ETH_P_PPP_SES);
 }
 for (unsigned int i=0; i<4; i++) {
  t.src_v6.s6_addr32[i]=htonl(0x20010db8 + i);
  t.dst_v6.s6_addr32[i]=htonl(0x20010db8 + i + 17);
 }
 return t;
}

static void expect_match(const struct flow_offload_tuple *t)
{
 struct nf_flow_match m={};
 unsigned int count=0, ppp=0;
 assert(nf_flow_tuple_encap_valid(t));
 assert(!nf_flow_rule_match(&m,t,NULL));
 assert(m.key.meta.ingress_ifindex==t->iifidx);
 assert(m.mask.meta.ingress_ifindex==0xffffffffU);
 assert(m.key.basic.ip_proto==t->l4proto && m.mask.basic.ip_proto==255);
 assert(m.key.tp.src==t->src_port && m.key.tp.dst==t->dst_port);
 assert(m.mask.tp.src==65535 && m.mask.tp.dst==65535);
 for (unsigned int i=0; i<t->encap_num; i++) {
  if (t->encap[i].proto==htons(ETH_P_PPP_SES)) {
   ppp++;
   assert(m.key.pppoe.session_id==htons(t->encap[i].id));
   assert(m.key.pppoe.type==htons(ETH_P_PPP_SES));
   assert(m.key.pppoe.ppp_proto==htons(t->l3proto==AF_INET ? PPP_IP : PPP_IPV6));
   assert(m.mask.pppoe.session_id==65535 && m.mask.pppoe.type==65535 && m.mask.pppoe.ppp_proto==65535);
  } else if (!(t->in_vlan_ingress & BIT(i))) {
   const struct flow_dissector_key_vlan *key=count ? &m.key.cvlan : &m.key.vlan;
   const struct flow_dissector_key_vlan *mask=count ? &m.mask.cvlan : &m.mask.vlan;
   assert(key->vlan_id==t->encap[i].id && key->vlan_tpid==t->encap[i].proto);
   assert(mask->vlan_id==VLAN_VID_MASK && mask->vlan_tpid==65535);
   assert(!mask->vlan_priority && !mask->vlan_dei && !mask->vlan_eth_type);
   count++;
  }
 }
 assert(!!(m.dissector.used_keys & BIT_ULL(FLOW_DISSECTOR_KEY_VLAN))==(count>0));
 assert(!!(m.dissector.used_keys & BIT_ULL(FLOW_DISSECTOR_KEY_CVLAN))==(count>1));
 assert(!!(m.dissector.used_keys & BIT_ULL(FLOW_DISSECTOR_KEY_PPPOE))==!!ppp);
 assert(m.key.basic.n_proto==htons(ppp ? ETH_P_PPP_SES : t->l3proto==AF_INET ? ETH_P_IP : ETH_P_IPV6));
 assert(m.mask.basic.n_proto==65535);
 if (t->l3proto==AF_INET) {
  assert(m.key.control.addr_type==FLOW_DISSECTOR_KEY_IPV4_ADDRS);
  assert(m.key.ipv4.src==t->src_v4.s_addr && m.key.ipv4.dst==t->dst_v4.s_addr);
  assert(m.mask.ipv4.src==0xffffffffU && m.mask.ipv4.dst==0xffffffffU);
 } else {
  const struct in6_addr full={.s6_addr32={~0U,~0U,~0U,~0U}};
  assert(m.key.control.addr_type==FLOW_DISSECTOR_KEY_IPV6_ADDRS);
  assert(!memcmp(&m.key.ipv6.src,&t->src_v6,sizeof(full)));
  assert(!memcmp(&m.key.ipv6.dst,&t->dst_v6,sizeof(full)));
  assert(!memcmp(&m.mask.ipv6.src,&full,sizeof(full)) && !memcmp(&m.mask.ipv6.dst,&full,sizeof(full)));
 }
 assert(!!(m.dissector.used_keys & BIT_ULL(FLOW_DISSECTOR_KEY_TCP))==(t->l4proto==IPPROTO_TCP));
 matches++;
}

static unsigned int required(const struct flow_offload_tuple *in,
                             const struct flow_offload_tuple *out)
{
 unsigned int n=0;
 for (unsigned int i=0; i<in->encap_num; i++)
  n+=!(in->in_vlan_ingress & BIT(i)) && in->encap[i].proto!=htons(ETH_P_PPP_SES);
 for (unsigned int i=0; i<out->encap_num; i++)
  n+=!(out->in_vlan_ingress & BIT(i));
 return n;
}

static void expect_actions(const struct flow_offload *flow, unsigned int dir,
                           unsigned int start)
{
 const struct flow_offload_tuple *in=&flow->tuplehash[dir].tuple;
 const struct flow_offload_tuple *out=&flow->tuplehash[!dir].tuple;
 struct flow_rule r, before;
 struct nf_flow_rule nf={.rule=&r};
 unsigned int needed=required(in,out), n=start;
 memset(&r,0xa5,sizeof(r));
 r.action.num_entries=start;
 before=r;
 int ret=nf_flow_rule_route_encap(flow,dir,&nf);
 if (start>NF_FLOW_RULE_ACTION_MAX || needed>NF_FLOW_RULE_ACTION_MAX-start) {
  assert(ret==-E2BIG);
  assert(!memcmp(&r,&before,sizeof(r))); /* All entries, not just live prefix. */
  rejected++;
  return;
 }
 assert(!ret);
 assert(r.action.num_entries==start+needed);
 assert(!memcmp(r.action.entries,before.action.entries,start*sizeof(r.action.entries[0])));
 for (unsigned int i=0; i<in->encap_num; i++) {
  if ((in->in_vlan_ingress & BIT(i)) || in->encap[i].proto==htons(ETH_P_PPP_SES))
   continue;
  assert(r.action.entries[n++].id==FLOW_ACTION_VLAN_POP);
 }
 /* Independent wire stack oracle: PPP is inner, then VLAN inner to outer. */
 if (out->encap_num && out->encap[out->encap_num-1].proto==htons(ETH_P_PPP_SES)) {
  const struct flow_action_entry *entry=&r.action.entries[n++];
  assert(entry->id==FLOW_ACTION_PPPOE_PUSH);
  assert(entry->pppoe.sid==out->encap[out->encap_num-1].id && entry->pppoe.mtu==in->mtu);
 }
 for (unsigned int tag=NF_FLOW_TABLE_VLAN_MAX; tag>0; tag--) {
  unsigned int i=tag-1;
  if (i>=out->encap_num || (out->in_vlan_ingress & BIT(i)) ||
      out->encap[i].proto==htons(ETH_P_PPP_SES))
   continue;
  const struct flow_action_entry *entry=&r.action.entries[n++];
  assert(entry->id==FLOW_ACTION_VLAN_PUSH);
  assert(entry->vlan.vid==out->encap[i].id && entry->vlan.proto==out->encap[i].proto);
  assert(entry->vlan.prio==0);
 }
 assert(n==r.action.num_entries);
 assert(!memcmp(&r.action.entries[n],&before.action.entries[n],
                (NF_FLOW_RULE_ACTION_MAX+8-n)*sizeof(r.action.entries[0])));
 actions++;
}

static void expect_invalid(const struct flow_offload_tuple *bad)
{
 struct nf_flow_match match, before_match;
 memset(&match,0x5a,sizeof(match));
 before_match=match;
 assert(!nf_flow_tuple_encap_valid(bad));
 assert(nf_flow_rule_match(&match,bad,NULL)==-EOPNOTSUPP);
 assert(!memcmp(&match,&before_match,sizeof(match)));
 for (unsigned int side=0; side<2; side++)
  for (unsigned int dir=0; dir<2; dir++)
   for (unsigned int start=0; start<=NF_FLOW_RULE_ACTION_MAX+1; start++) {
    struct flow_offload f={};
    struct flow_rule r, before;
    struct nf_flow_rule nf={.rule=&r};
    f.tuplehash[side].tuple=*bad;
    f.tuplehash[!side].tuple=stack(2,3,0,true);
    memset(&r,0xa5,sizeof(r));r.action.num_entries=start;before=r;
    assert(nf_flow_rule_route_encap(&f,dir,&nf)==-EOPNOTSUPP);
    assert(!memcmp(&r,&before,sizeof(r)));
    rejected++;
   }
}

int main(void)
{
 struct kernel_flow_offload_tuple real={.encap_num=3,.in_vlan_ingress=BIT(2)};
 assert(real.encap_num==3 && real.in_vlan_ingress==BIT(2));
 assert(sizeof(real.encap)/sizeof(real.encap[0])==3);
 struct flow_offload_tuple variants[42];unsigned int count=0;
 for (unsigned int tags=0; tags<=2; tags++)
  for (unsigned int tpids=0; tpids<BIT(tags); tpids++)
   for (unsigned int hidden=0; hidden<BIT(tags); hidden++)
    for (unsigned int ppp=0; ppp<2; ppp++) {
     struct flow_offload_tuple t=stack(tags,tpids,hidden,ppp);
     variants[count++]=t;
     for (unsigned int family=0; family<2; family++)
      for (unsigned int udp=0; udp<2; udp++)
       for (unsigned int vidcase=0; vidcase<4; vidcase++) {
        const unsigned int vids[]={0,1,4094,4095};
        t.l3proto=family ? AF_INET6 : AF_INET;
        t.l4proto=udp ? IPPROTO_UDP : IPPROTO_TCP;
        for (unsigned int i=0; i<tags; i++)t.encap[i].id=vids[(vidcase+i)%4];
        expect_match(&t);
       }
    }
 assert(count==42);
 for (unsigned int i=0; i<count; i++)
  for (unsigned int j=0; j<count; j++)
   for (unsigned int dir=0; dir<2; dir++)
    for (unsigned int start=0; start<=NF_FLOW_RULE_ACTION_MAX+1; start++) {
     struct flow_offload f={};f.tuplehash[0].tuple=variants[i];f.tuplehash[1].tuple=variants[j];
     f.tuplehash[0].tuple.mtu=1492;f.tuplehash[1].tuple.mtu=1500;
     expect_actions(&f,dir,start);
    }
 for (unsigned int start=0; start<=NF_FLOW_RULE_ACTION_MAX+2; start++) {
  struct flow_rule r, before;struct nf_flow_rule nf={.rule=&r};
  memset(&r,0xa5,sizeof(r));r.action.num_entries=start;before=r;
  struct flow_action_entry *entry=flow_action_entry_next(&nf);
  if (start>=NF_FLOW_RULE_ACTION_MAX)assert(!entry && !memcmp(&r,&before,sizeof(r)));
  else assert(entry==&r.action.entries[start] && r.action.num_entries==start+1 &&
              !memcmp(r.action.entries,before.action.entries,sizeof(r.action.entries)));
 }
 for (unsigned int index=0; index<3; index++) {
  struct flow_offload_tuple bad=stack(2,3,0,true);bad.encap[index].proto=htons(0x88b5);expect_invalid(&bad);
 }
 struct flow_offload_tuple bad=stack(2,3,0,true);
 bad.encap[0].proto=htons(ETH_P_PPP_SES);bad.encap[0].id=1;expect_invalid(&bad); /* PPP before VLAN / duplicate. */
 bad=stack(2,3,0,true);bad.encap[2].id=0;expect_invalid(&bad);
 bad=stack(2,3,BIT(2),true);expect_invalid(&bad); /* PPP must not be an ingress VLAN. */
 bad=stack(2,3,0,true);bad.encap[2].proto=htons(ETH_P_8021Q);bad.encap[2].id=200;expect_invalid(&bad);
 bad=stack(2,3,0,false);bad.encap[0].id=4096;expect_invalid(&bad);
 bad=stack(2,3,0,false);bad.encap_num=NF_FLOW_TABLE_ENCAP_MAX+1;expect_invalid(&bad);
 for (unsigned int n=0; n<=3; n++) {
  bad=stack(n>2 ? 2 : n,3,0,n==3);bad.in_vlan_ingress=BIT(n);expect_invalid(&bad);
 }
 printf("Flowtable encapsulation actions: %u exact IPv4/IPv6 TCP/UDP matches, %u successful action/capacity vectors, %u atomic rejections; 42 wire stacks and real bitfields PASS\n",matches,actions,rejected);
 return 0;
}
'''


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise RuntimeError('mutation anchor changed: ' + old)
    return source.replace(old, new, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True,
                        help='Prepared kernel tree including the platform patches')
    parser.add_argument('--mutants', action='store_true',
                        help='Require semantic assertion failures from six historical/safety mutations')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    header = (args.kernel / 'include/net/netfilter/nf_flow_table.h').read_text()
    offload = (args.kernel / 'net/netfilter/nf_flow_table_offload.c').read_text()
    defines = []
    for name, source in [('NF_FLOW_RULE_ACTION_MAX', offload),
                         ('NF_FLOW_TABLE_ENCAP_MAX', header),
                         ('NF_FLOW_TABLE_VLAN_MAX', header)]:
        value = re.search(r'^#define\s+' + name + r'\s+(\d+)', source, re.M)
        if value is None:
            raise RuntimeError('missing kernel constant: ' + name)
        defines.append(f'#define {name} {value[1]}')
    real_tuple = re.search(r'^struct flow_offload_tuple \{.*?^\};', header, re.M | re.S)
    if real_tuple is None:
        raise RuntimeError('missing actual kernel tuple structure')
    real_tuple = real_tuple[0].replace('struct flow_offload_tuple {', 'struct kernel_flow_offload_tuple {', 1)
    validation = function(header, 'nf_flow_tuple_encap_valid')
    matching = function(offload, 'nf_flow_rule_match')
    construction = function(offload, 'nf_flow_rule_route_encap')
    fixed = '\n'.join(defines) + COMMON + real_tuple + '\n'
    fixed += function(offload, 'nf_flow_rule_vlan_match')
    fixed += function(offload, 'flow_action_entry_next')
    base = fixed + validation + matching + construction + TEST
    variants = [('production', base)]
    if args.mutants:
        changes = {
            'ascending-push': (construction,
                replace_once(construction,
                    'for (i = other_tuple->encap_num - 1; i >= 0; i--)',
                    'for (i = 0; i < other_tuple->encap_num; i++)')),
            'unknown-protocol-accepted': (validation,
                replace_once(validation, 'default:\n\t\t\treturn false;', 'default:\n\t\t\tbreak;')),
            'capacity-off-by-one': (construction,
                replace_once(construction, 'needed > NF_FLOW_RULE_ACTION_MAX - next',
                             'needed > NF_FLOW_RULE_ACTION_MAX - next + 1')),
            'partial-write-on-failure': (construction,
                replace_once(construction, 'return -E2BIG;',
                             '{ action->num_entries = next + 1; return -E2BIG; }')),
            '8021ad-match-lost': (matching,
                replace_once(matching, 'tuple->encap[i].proto != htons(ETH_P_8021AD)',
                             'tuple->encap[i].proto != htons(0x88a9)')),
            'nonterminal-pppoe': (validation,
                replace_once(validation, 'i + 1 != count || ', '')),
        }
        for name, (old, new) in changes.items():
            variants.append((name, replace_once(base, old, new)))
    with tempfile.TemporaryDirectory(prefix='flowtable-encap-actions-') as directory:
        work = Path(directory)
        for name, source in variants:
            path, binary = work / (name + '.c'), work / name
            path.write_text(source)
            subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                            '-Wno-sign-compare', '-g', '-fsanitize=address,undefined',
                            '-fno-omit-frame-pointer', str(path), '-o', str(binary)], check=True)
            result = subprocess.run([str(binary)], text=True, capture_output=True)
            if name == 'production':
                if result.returncode:
                    raise RuntimeError(result.stdout + result.stderr)
                print(result.stdout, end='')
            elif result.returncode == 0 or 'Assertion' not in result.stderr:
                raise RuntimeError(f'mutant {name} did not fail a semantic assertion:\n'
                                   + result.stdout + result.stderr)
            else:
                print(f'PASS: semantic assertion rejected {name}')


if __name__ == '__main__':
    main()
