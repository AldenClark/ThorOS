#!/usr/bin/env python3
"""Exercise the patched kernel's real flowtable skb decoder, lookup and pop."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def function(source, name):
    match = re.search(r'^.*\b' + re.escape(name) + r'\([^;]*?\)\s*\{', source, re.M)
    if match is None:
        raise ValueError('required production function is absent: ' + name)
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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_pppox.h>
#include <linux/ppp_defs.h>
typedef uint8_t u8;typedef uint16_t u16,__be16;typedef uint32_t u32;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(v) __builtin_bswap16((uint16_t)(v))
#endif
#define VLAN_HLEN 4
#define VLAN_VID_MASK 4095
#define PPPOE_SES_HLEN 8
#define BIT(n) (1U<<(n))
#define unlikely(x) (x)
#define GRE_VERSION 0x0007
#define GRE_VERSION_0 0
#define NF_ACCEPT 1
#define NF_STOLEN 2
struct gre_base_hdr {__be16 flags,protocol;};
struct vlan_hdr {__be16 h_vlan_TCI,h_vlan_encapsulated_proto;};
struct flow_ports {__be16 source,dest;};
struct rhash_head {void *next;};
struct net_device {int ifindex;};
struct nf_flowtable {int unused;};
struct nf_hook_state {const struct net_device *in;};
struct sk_buff {
 u8 *storage,*data,wire[512];
 unsigned int len,linear,data_abs,network_abs,wire_len;
 unsigned int reallocs,fail_at;
 bool failed,tag;
 __be16 protocol,vlan_proto;
 u16 tci;
};
static int skb_network_offset(const struct sk_buff *s){return (int)s->network_abs-(int)s->data_abs;}
static u8 *skb_network_header(const struct sk_buff *s){return s->storage+s->network_abs;}
static u8 *skb_mac_header(const struct sk_buff *s){return s->storage+64-ETH_HLEN;}
static bool skb_vlan_tag_present(const struct sk_buff *s){return s->tag;}
static u16 skb_vlan_tag_get_id(const struct sk_buff *s){return s->tci&VLAN_VID_MASK;}
static void __vlan_hwaccel_clear_tag(struct sk_buff *s){s->tag=false;s->tci=0;}
static bool pskb_may_pull(struct sk_buff *s,unsigned int need)
{
 if(need>s->len)return false;
 if(need<=s->linear)return true;
 s->reallocs++;
 if(s->fail_at==s->reallocs){s->failed=true;return false;}
 /* Allocate only the requested linear bytes, free the old allocation, and
  * preserve the original MAC header. ASan catches stale skb header pointers
  * or a header read that was not preceded by a sufficient pull. */
 u8 *next=malloc(s->data_abs+need);assert(next);
 memcpy(next,s->storage,64);
 memcpy(next+64,s->wire,s->data_abs-64+need);
 free(s->storage);s->storage=next;s->data=next+s->data_abs;s->linear=need;
 return true;
}
static u8 *__skb_pull(struct sk_buff *s,unsigned int n)
{
 assert(n<=s->len && n<=s->linear);
 s->len-=n;s->linear-=n;s->data_abs+=n;s->data=s->storage+s->data_abs;
 return s->data;
}
static u8 *skb_pull(struct sk_buff *s,unsigned int n){return __skb_pull(s,n);}
static void skb_reset_network_header(struct sk_buff *s){s->network_abs=s->data_abs;}
static void vlan_set_encap_proto(struct sk_buff *s,const struct vlan_hdr *h){s->protocol=h->h_vlan_encapsulated_proto;}
static bool ip_is_fragment(const struct iphdr *h){return ntohs(h->frag_off)&0x3fff;}
'''

LOOKUP_STUB = r'''
static struct flow_offload_tuple_rhash captured;
static unsigned int lookup_calls,ipv4_calls,ipv6_calls;
static struct nf_flowtable table;
static struct nf_flowtable_ctx last_ctx;
static struct flow_offload_tuple_rhash *flow_offload_lookup(struct nf_flowtable *t,const struct flow_offload_tuple *tuple)
{(void)t;captured.tuple=*tuple;lookup_calls++;return &captured;}
'''

DISPATCH_STUB = r'''
static unsigned int nf_flow_offload_ip_hook(void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
{(void)priv;last_ctx=(struct nf_flowtable_ctx){.in=state->in};ipv4_calls++;return nf_flow_offload_lookup(&last_ctx,&table,skb)?NF_STOLEN:NF_ACCEPT;}
static unsigned int nf_flow_offload_ipv6_hook(void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
{(void)priv;last_ctx=(struct nf_flowtable_ctx){.in=state->in};ipv6_calls++;return nf_flow_offload_ipv6_lookup(&last_ctx,&table,skb)?NF_STOLEN:NF_ACCEPT;}
'''

TESTS = r'''
static void put16(u8 *p,unsigned int n){__be16 b=htons(n);memcpy(p,&b,2);}
struct packet {
 u8 bytes[512];unsigned int length,ipoff,pppoff,inner;
 unsigned int tags,metadata,tpids,ppp,ipv6,udp,tci;
 __be16 protocol,vlan_proto;
};
static unsigned int tag_proto(const struct packet *p,unsigned int tag){return p->tpids&BIT(tag)?ETH_P_8021AD:ETH_P_8021Q;}
static unsigned int tag_id(const struct packet *p,unsigned int tag){return (p->tci+tag)&VLAN_VID_MASK;}
static struct packet make_packet(unsigned int tags,unsigned int metadata,unsigned int tpids,
 unsigned int ppp,unsigned int ipv6,unsigned int udp,unsigned int tci)
{
 struct packet p={.tags=tags,.metadata=metadata,.tpids=tpids,.ppp=ppp,.ipv6=ipv6,.udp=udp,.tci=tci};
 unsigned int ipproto=ipv6?ETH_P_IPV6:ETH_P_IP;
 unsigned int proto=tags>metadata?tag_proto(&p,metadata):(ppp?ETH_P_PPP_SES:ipproto);
 p.protocol=htons(proto);p.vlan_proto=htons(tag_proto(&p,0));
 for(unsigned int i=metadata;i<tags;i++) {
  put16(p.bytes+p.length,(tci&0xf000)|tag_id(&p,i));
  put16(p.bytes+p.length+2,i+1<tags?tag_proto(&p,i+1):(ppp?ETH_P_PPP_SES:ipproto));
  p.length+=VLAN_HLEN;
 }
 if(ppp){p.pppoff=p.length;p.length+=PPPOE_SES_HLEN;}
 p.ipoff=p.length;
 p.inner=(ipv6?40:20)+(udp?8:20)+12;
 if(ppp) {
  u8 *h=p.bytes+p.pppoff;h[0]=0x11;h[1]=0;put16(h+2,0xabcd);
  put16(h+4,p.inner+2);put16(h+6,ipv6?PPP_IPV6:PPP_IP);
 }
 u8 *h=p.bytes+p.ipoff;
 if(ipv6) {
  h[0]=0x60;put16(h+4,p.inner-40);h[6]=udp?17:6;h[7]=64;
  for(unsigned int i=0;i<32;i++)h[8+i]=i+1;
  h+=40;
 } else {
  h[0]=0x45;put16(h+2,p.inner);h[8]=64;h[9]=udp?17:6;
  h[12]=10;h[15]=2;h[16]=198;h[17]=51;h[18]=100;h[19]=1;h+=20;
 }
 put16(h,53001);put16(h+2,443);
 if(udp)put16(h+4,p.inner-(ipv6?40:20));else h[12]=0x50;
 p.length+=p.inner;return p;
}
static struct sk_buff make_skb(const struct packet *p,unsigned int length,unsigned int linear,unsigned int fail_at)
{
 struct sk_buff s={.len=length,.linear=linear,.data_abs=64,.network_abs=64,.wire_len=length,
  .fail_at=fail_at,.tag=!!p->metadata,.protocol=p->protocol,.vlan_proto=p->vlan_proto,.tci=p->tci};
 assert(length<=p->length && linear<=length);
 s.storage=calloc(1,64+linear);assert(s.storage);s.data=s.storage+64;
 memcpy(s.wire,p->bytes,length);memcpy(s.data,p->bytes,linear);
 memcpy(s.storage+64-2,&s.protocol,2);return s;
}
static const struct net_device indev={.ifindex=23};
static const struct nf_hook_state state={.in=&indev};
static struct flow_offload_tuple_rhash *lookup(struct sk_buff *s,bool ipv6)
{
 last_ctx=(struct nf_flowtable_ctx){.in=&indev};lookup_calls=0;
 return ipv6?nf_flow_offload_ipv6_lookup(&last_ctx,&table,s):nf_flow_offload_lookup(&last_ctx,&table,s);
}
static void expect_reject(const struct packet *p,unsigned int length,unsigned int linear)
{
 struct sk_buff s=make_skb(p,length,linear,0);
 unsigned int before_len=s.len;__be16 before_protocol=s.protocol;bool before_tag=s.tag;
 assert(!lookup(&s,p->ipv6));assert(!lookup_calls);
 assert(s.len==before_len && s.protocol==before_protocol && s.tag==before_tag);
 free(s.storage);
 s=make_skb(p,length,linear,0);ipv4_calls=ipv6_calls=lookup_calls=0;
 assert(nf_flow_offload_inet_hook(NULL,&s,&state)==NF_ACCEPT);
 assert(!lookup_calls);free(s.storage);
 s=make_skb(p,length,linear,0);ipv4_calls=ipv6_calls=lookup_calls=0;
 assert(xt_flowoffload_net_hook(NULL,&s,&state)==NF_ACCEPT);
 assert(!lookup_calls);free(s.storage);
}
int main(void)
{
 unsigned int good=0,shorts=0,faults=0,bad=0;
 for(unsigned int tags=0;tags<=2;tags++)
  for(unsigned int metadata=0;metadata<=(tags?1:0);metadata++)
   for(unsigned int tpids=0;tpids<(1U<<tags);tpids++)
    for(unsigned int ppp=0;ppp<2;ppp++)
     for(unsigned int ipv6=0;ipv6<2;ipv6++)
      for(unsigned int udp=0;udp<2;udp++)
       for(unsigned int v=0;v<3;v++) {
        unsigned int tci=(unsigned int[]){0,0xf064,0xfffe}[v];
        struct packet p=make_packet(tags,metadata,tpids,ppp,ipv6,udp,tci);
        for(unsigned int linear=0;linear<=p.length;linear++) {
         struct sk_buff s=make_skb(&p,p.length,linear,0);
         struct nf_flow_encap encap={};
         assert(nf_flow_encap_parse(&s,&encap));
         assert(encap.offset==p.ipoff && encap.length==p.inner && encap.num==tags+ppp);
         assert(encap.proto==htons(ipv6?ETH_P_IPV6:ETH_P_IP));
         for(unsigned int tag=0;tag<tags;tag++) {
          assert(encap.encap[tag].id==tag_id(&p,tag));
          assert(encap.encap[tag].proto==htons(tag_proto(&p,tag)));
         }
         if(ppp)assert(encap.encap[tags].id==0xabcd && encap.encap[tags].proto==htons(ETH_P_PPP_SES));
         for(unsigned int i=tags+ppp;i<NF_FLOW_TABLE_ENCAP_MAX;i++)
          assert(!encap.encap[i].id && !encap.encap[i].proto);
         assert(lookup(&s,ipv6)==&captured && lookup_calls==1);
         assert(captured.tuple.iifidx==23 && captured.tuple.l3proto==(ipv6?AF_INET6:AF_INET));
         assert(captured.tuple.l4proto==(udp?17:6));
         assert(captured.tuple.src_port==htons(53001) && captured.tuple.dst_port==htons(443));
         assert(captured.tuple.encap_num==tags+ppp && nf_flow_tuple_encap_valid(&captured.tuple));
         assert(!memcmp(captured.tuple.encap,encap.encap,sizeof(encap.encap)));
         assert(last_ctx.offset==p.ipoff && last_ctx.inner_len==p.inner);
         nf_flow_encap_pop(&s,&captured);
         assert(!s.tag && s.protocol==htons(ipv6?ETH_P_IPV6:ETH_P_IP));
         assert(s.len==p.inner && skb_network_offset(&s)==0 && s.data_abs==64+p.ipoff);
         assert(!memcmp(s.data,p.bytes+p.ipoff,(ipv6?40:20)+(udp?8:20)));
         free(s.storage);good++;
        }
        for(unsigned int length=0;length<p.length;length++) {
         expect_reject(&p,length,length/2);shorts++;
        }
        for(unsigned int fail=1;fail<=6;fail++) {
         struct sk_buff s=make_skb(&p,p.length,0,fail);
         struct flow_offload_tuple_rhash *result=lookup(&s,ipv6);
         if(s.failed){assert(!result && !lookup_calls);faults++;}
         else assert(result==&captured);
         free(s.storage);
        }
        struct sk_buff s=make_skb(&p,p.length,0,0);
        ipv4_calls=ipv6_calls=lookup_calls=0;
        assert(nf_flow_offload_inet_hook(NULL,&s,&state)==NF_STOLEN);
        assert(ipv4_calls==!ipv6 && ipv6_calls==ipv6 && lookup_calls==1);
        free(s.storage);
        s=make_skb(&p,p.length,0,0);ipv4_calls=ipv6_calls=lookup_calls=0;
        assert(xt_flowoffload_net_hook(NULL,&s,&state)==NF_STOLEN);
        assert(ipv4_calls==!ipv6 && ipv6_calls==ipv6 && lookup_calls==1);
        free(s.storage);
       }
 /* Invalid outer stacks must fail without publishing even a partial encap
  * result. This includes a metadata tag plus two inline tags. */
 for(unsigned int metadata=0;metadata<2;metadata++)
  for(unsigned int tpids=0;tpids<8;tpids++) {
   struct packet p=make_packet(3,metadata,tpids,0,0,1,0);
   struct sk_buff s=make_skb(&p,p.length,0,0);
   struct nf_flow_encap output,saved;memset(&output,0xa5,sizeof(output));saved=output;
   assert(!nf_flow_encap_parse(&s,&output));assert(!memcmp(&output,&saved,sizeof(output)));
   free(s.storage);expect_reject(&p,p.length,0);bad++;
  }
 for(unsigned int ipv6=0;ipv6<2;ipv6++)
  for(unsigned int mutation=0;mutation<18;mutation++) {
   struct packet p=make_packet(2,1,1,1,ipv6,0,0xf000);
   u8 *ip=p.bytes+p.ipoff,*ppp=p.bytes+p.pppoff;
   switch(mutation) {
   case 0:p.vlan_proto=htons(0x9100);break;
   case 1:p.protocol=htons(0x9100);break;
   case 2:put16(p.bytes+2,0x9100);break;
   case 3:ppp[0]=0x21;break;
   case 4:ppp[0]=0x12;break;
   case 5:ppp[1]=9;break;
   case 6:put16(ppp+2,0);break;
   case 7:put16(ppp+4,1);break;
   case 8:put16(ppp+4,0xffff);break;
   case 9:put16(ppp+6,0xc021);break;
   case 10:put16(ppp+6,ETH_P_8021Q);break;
   case 11:put16(ppp+4,2+(ipv6?40:20)+19);break;
   case 12:ip[0]=ipv6?0x40:0x65;break;
   case 13:ip[ipv6?7:8]=1;break;
   case 14:ip[ipv6?6:9]=59;break;
   case 15:put16(ip+(ipv6?4:2),ipv6?19:39);break;
   case 16:put16(ip+(ipv6?4:2),0xffff);break;
   case 17:put16(ppp+4,2+(ipv6?39:19));break;
   }
   expect_reject(&p,p.length,0);bad++;
  }
 for(unsigned int fragment=1;fragment<=0x2000;fragment<<=1) {
  struct packet p=make_packet(1,0,1,1,0,1,1);
  put16(p.bytes+p.ipoff+6,fragment);expect_reject(&p,p.length,0);bad++;
 }
 for(unsigned int malformed=0;malformed<2;malformed++) {
  struct packet p=make_packet(1,1,1,0,0,1,1);
  struct sk_buff s=make_skb(&p,p.length,p.length,0);
  s.network_abs=malformed?65:63;assert(!lookup(&s,0));free(s.storage);bad++;
 }
 /* Failure after the first tag must leave the caller's entire decoded key
  * unchanged, even when an earlier pull relocated the skb head. */
 for(unsigned int fail=1;fail<=3;fail++) {
  struct packet p=make_packet(2,0,1,1,0,1,1);
  struct sk_buff s=make_skb(&p,p.length,0,fail);
  struct nf_flow_encap output,saved;memset(&output,0x5a,sizeof(output));saved=output;
  assert(!nf_flow_encap_parse(&s,&output));assert(!memcmp(&output,&saved,sizeof(output)));
  assert(s.failed && s.len==p.length && s.protocol==p.protocol);free(s.storage);bad++;
 }
 printf("flowtable skb: %u linear/nonlinear decode/lookup/pop, %u short frames, %u pull failures, %u malformed/rollback cases PASS\n",good,shorts,faults,bad);
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', required=True, type=Path)
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    header = (args.kernel / 'include/net/netfilter/nf_flow_table.h').read_text()
    ip = (args.kernel / 'net/netfilter/nf_flow_table_ip.c').read_text()
    inet = (args.kernel / 'net/netfilter/nf_flow_table_inet.c').read_text()
    xt = (args.kernel / 'net/netfilter/xt_FLOWOFFLOAD.c').read_text()
    parts = [COMMON]
    for name in ('NF_FLOW_TABLE_ENCAP_MAX', 'NF_FLOW_TABLE_VLAN_MAX'):
        parts.append(re.search(r'^#define\s+' + name + r'\s+\d+', header, re.M)[0])
    for name in ('flow_offload_tuple', 'flow_offload_tuple_rhash', 'nf_flow_encap'):
        parts.append(re.search(r'^struct ' + name + r' \{.*?^\};', header, re.M | re.S)[0])
    parts.append(re.search(r'^struct nf_flowtable_ctx \{.*?^\};', ip, re.M | re.S)[0])
    parts.append(LOOKUP_STUB)
    for name in ('nf_flow_tuple_encap_valid', '__nf_flow_pppoe_proto', 'nf_flow_encap_parse'):
        parts.append(function(header, name))
    for name in ('ip_has_options', 'nf_flow_tuple_encap', 'nf_flow_tuple_ip',
                 'nf_flow_tuple_ipv6', 'nf_flow_offload_lookup',
                 'nf_flow_offload_ipv6_lookup', 'nf_flow_encap_pop'):
        parts.append(function(ip, name))
    parts.extend([DISPATCH_STUB, function(inet, 'nf_flow_offload_inet_hook'),
                  function(xt, 'xt_flowoffload_net_hook'), TESTS])
    source = '\n'.join(parts)
    mutations = {
        'missing-8021ad-inline': ('while (proto == htons(ETH_P_8021Q) || proto == htons(ETH_P_8021AD))',
                                 'while (proto == htons(ETH_P_8021Q))'),
        'stale-pppoe-mac-offset': ('skb_network_header(skb) +\n\t\t\t     sizeof(struct pppoe_hdr)',
                                  'skb_mac_header(skb) + ETH_HLEN +\n\t\t\t     sizeof(struct pppoe_hdr)'),
        'metadata-outside-depth-budget': ('\t\tvlans++;', '\t\t/* broken: metadata was not counted */'),
        'unbounded-pppoe-length': ('length > next.length - sizeof(*phdr)', 'false'),
        'ignores-ip-length': ('ntohs(iph->tot_len) > ctx->inner_len', 'false'),
    }
    with tempfile.TemporaryDirectory(prefix='flowtable-skb-', dir=ROOT / 'artifacts') as work:
        work = Path(work)
        def run(label, contents, negative=False):
            src, binary = work / (label + '.c'), work / label
            src.write_text(contents)
            subprocess.run(['cc', '-g', '-Wall', '-Wextra', '-Wno-unused-function',
                            '-Wno-unused-parameter', '-fsanitize=address,undefined',
                            '-fno-omit-frame-pointer', str(src), '-o', str(binary)], check=True)
            result = subprocess.run([str(binary)], text=True, capture_output=True)
            if negative:
                if result.returncode == 0 or 'Assertion' not in result.stderr:
                    raise AssertionError('mutant did not fail a semantic assertion: ' + label + '\n' + result.stderr)
                print('PASS: assertion rejected ' + label)
            elif result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
            else:
                print(result.stdout, end='')
        run('production', source)
        if args.mutants:
            for label, (before, after) in mutations.items():
                if source.count(before) != 1:
                    raise AssertionError('mutation anchor drifted: ' + label)
                run(label, source.replace(before, after), True)
    (ROOT / 'logs/flowtable-encap-skb.json').write_text(json.dumps({
        'production_header_sha256': hashlib.sha256(header.encode()).hexdigest(),
        'production_ip_sha256': hashlib.sha256(ip.encode()).hexdigest(),
        'production_inet_sha256': hashlib.sha256(inet.encode()).hexdigest(),
        'production_xt_sha256': hashlib.sha256(xt.encode()).hexdigest(),
        'sanitizers': ['ASan', 'UBSan'], 'mutants': list(mutations) if args.mutants else [],
        'hardware_acceptance': False,
    }, indent=2) + '\n')


if __name__ == '__main__':
    main()
