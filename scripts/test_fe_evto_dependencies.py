#!/usr/bin/env python3
"""Exercise the production EVTO compiler against its actual packet policy.

The counterexamples use legal profiles, a nonzero PPPoE session with one VLAN,
and pure IPv4 QinQ (two encapsulations, never PPPoE plus QinQ). This is a host
helper test, not full-kernel or hardware throughput verification. --revision
selects historical code; --benchmark-only compares compiler CPU/evaluation cost.
"""

import argparse
import hashlib
from pathlib import Path
import platform
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
relative = "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/"
drivers = root / relative
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--revision")
mode = parser.add_mutually_exclusive_group()
mode.add_argument("--benchmark-only", action="store_true")
mode.add_argument("--upstream-cost-only", action="store_true",
                  help="Isolate the unused-DSCP expansion regression from downstream admission")
args = parser.parse_args()


def production(name):
    if args.revision:
        return subprocess.check_output(
            ["git", "show", args.revision + ":" + relative + name], cwd=root, text=True
        )
    return (drivers / name).read_text()


for dependency in ("rtl9617c-fe-format.h", "rtl9617c-pon-path.h", "rtl9617c-pon-vlan.h"):
    if production(dependency) != (drivers / dependency).read_text():
        raise RuntimeError("refusing mixed-revision dependency: " + dependency)
native = production("rtl9617c-fe.c")
vlan = production("rtl9617c-fe-vlan.h")
rule = re.search(r"struct rtl_fe_rule \{.*?\n\};", native, re.S).group()
common = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <time.h>
typedef uint8_t u8;typedef uint16_t u16,__be16;
#define ETH_P_IP 0x800
#define ETH_P_IPV6 0x86dd
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88a8
#define ETH_P_PPP_SES 0x8864
#define ETH_HLEN 14
#define ETH_ALEN 6
#define VLAN_HLEN 4
#include "rtl9617c-fe-format.h"
#include "rtl9617c-pon-path.h"
struct net_device {unsigned ifindex;};
struct rtl_fe;
struct rtl_fe_port {struct rtl_fe *fe;struct net_device *netdev;};
struct rtl_fe {struct net_device *itu_netdev;struct rtl_itu_paths *itu_paths;};
static int fe_vlan_tpid(__be16 p){return p==htons(0x8100)?1:p==htons(0x88a8)?2:-EOPNOTSUPP;}
static unsigned long policy_tx_calls,policy_rx_calls,oracle_cases;
static unsigned maximum_image_dscp;
static bool saw_wire100,saw_wire101;
static const struct rtl_itu_path *counted_transmit(const struct rtl_itu_paths *p,
 const struct rtl_evto_packet *in,struct rtl_evto_packet *out){
 policy_tx_calls++;return rtl_itu_path_transmit_vlan(p,in,out);
}
static const struct rtl_itu_path *counted_receive(const struct rtl_itu_paths *p,unsigned gem,
 const struct rtl_evto_packet *in,struct rtl_evto_packet *out){
 const struct rtl_itu_path *path=rtl_itu_path_receive_vlan(p,gem,in,out);
 policy_rx_calls++;if(in->dscp>maximum_image_dscp)maximum_image_dscp=in->dscp;
 if(path && in->count){saw_wire100|=(in->tag[0].tci&4095)==100;saw_wire101|=(in->tag[0].tci&4095)==101;}
 return path;
}
#define rtl_itu_path_transmit_vlan counted_transmit
#define rtl_itu_path_receive_vlan counted_receive
'''
fixtures = r'''
#undef rtl_itu_path_transmit_vlan
#undef rtl_itu_path_receive_vlan
static void row(struct rtl_evto_profile *p,unsigned n,unsigned a,unsigned b,unsigned c,unsigned d){
 unsigned words[4]={a,b,c,d};
 for(unsigned i=0;i<4;i++)for(unsigned byte=0;byte<4;byte++)p->row[n][i*4+byte]=words[i]>>(24-byte*8);
 if(p->count<=n)p->count=n+1;
}
static void priority_map(u8 map[24],int constant){
 memset(map,0,24);
 for(unsigned d=0;d<64;d++)for(unsigned b=0;b<3;b++){
  unsigned bit=d*3+b,value=constant<0?(d&7):(unsigned)constant;
  map[bit/8]|=((value>>(2-b))&1)<<(7-bit%8);
 }
}
static void dscp_map(u8 map[24],bool variable){priority_map(map,variable?-1:0);}
static void path_init(struct rtl_itu_path *path,unsigned vid,unsigned gem){
 *path=(struct rtl_itu_path){.vlan=vid,.pbits=255,.downstream_pbits=255,.index=gem,.tcont=1,.queue=3};
 for(unsigned s=0;s<RTL_EVTO_STAGES;s++)path->vlan_profile[s]=RTL_EVTO_NONE;
}
static struct rtl_itu_paths *config(void){
 struct rtl_itu_paths *p=calloc(1,sizeof(*p)+4*sizeof(p->profile[0]));assert(p);
 p->count=p->profile_count=1;path_init(&p->path[0],41,8);
 p->path[0].vlan_profile[0]=0;
 p->profile[0]=(struct rtl_evto_profile){.input_tpid=0x8100,.output_tpid=0x8100,.downstream=8};
 row(&p->profile[0],0,0xe8000000,0xe8000000,0xc00f0000,0x000f0000);
 row(&p->profile[0],1,0xf8000000,0xe8000000,0xc00f0000,0x000f0000);
 row(&p->profile[0],2,0xf8000000,0xf8000000,0x000f0000,0x000f0000);
 assert(rtl_evto_valid(&p->profile[0]));return p;
}
static struct rtl_evto_profile *variable_priority(struct rtl_itu_paths *p,unsigned id,unsigned vid){
 struct rtl_evto_profile *profile=&p->profile[id];
 *profile=(struct rtl_evto_profile){.input_tpid=0x8100,.output_tpid=0x8100,.downstream=0};
 row(profile,0,0xf8000000,0x80000000|(vid<<15),0x400f0000,(10U<<16)|(4096U<<3));
 dscp_map(profile->dscp,true);assert(rtl_evto_valid(profile));
 if(p->profile_count<=id)p->profile_count=id+1;
 return profile;
}
static struct rtl_fe_rule downstream(struct rtl_fe_port *pp,struct rtl_fe_port *lp){
 return (struct rtl_fe_rule){.input=pp,.output=lp,.key={.protocol=6},.pppoe_input=true,
  .pppoe_session=1,.vlan_count=1,.vlan={{.vid=41,.tpid=1}}};
}
static struct rtl_fe_rule upstream(struct rtl_fe_port *lp,struct rtl_fe_port *pp,unsigned tags){
 return (struct rtl_fe_rule){.input=lp,.output=pp,.key={.protocol=6},
  .action={.vlan_count=tags,.vlan={{.vid=41,.tpid=1},{.vid=42,.tpid=1}}}};
}
static bool traced_dependency(const struct rtl_itu_paths *p,const struct rtl_evto_packet *in){
#if HAVE_DEPENDENCY_TRACE
 return fe_evto_may_read_dscp(p,in) && fe_evto_upstream_dscp(p,in);
#else
 (void)in;return !!(fe_evto_dependencies(p)&1);
#endif
}
static bool same_packet(const struct rtl_evto_packet *a,const struct rtl_evto_packet *b){
 return a->priority==b->priority && fe_evto_equal(a,b);
}
/* An independent exhaustive oracle: if the optimized trace says DSCP cannot
 * matter, all64 real selector executions must agree, including rejection. */
static void trace_oracle(const struct rtl_itu_paths *p){
 static const unsigned protocols[]={ETH_P_IP,ETH_P_IPV6,ETH_P_PPP_SES,0x806};
 for(unsigned protocol=0;protocol<4;protocol++)for(unsigned tags=0;tags<=2;tags++)
  for(unsigned service=0;service<2;service++)for(unsigned criteria=0;criteria<3;criteria++)
   for(unsigned vid=41;vid<=99;vid+=58)for(unsigned v=0;v<16;v++){
    struct rtl_evto_packet input={.count=tags,.protocol=protocols[protocol],.priority=v&7,
     .criteria=criteria,.service_entry=service,.tag={{0x8100,vid|((v&7)<<13)|((v>>3)<<12)},
      {0x8100,42|(((v+3)&7)<<13)|((v>>3)<<12)}}},first;
    if(traced_dependency(p,&input))continue;
    const struct rtl_itu_path *expected=rtl_itu_path_transmit_vlan(p,&input,&first);
    for(unsigned d=1;d<64;d++){
     struct rtl_evto_packet output;input.dscp=d;
     const struct rtl_itu_path *actual=rtl_itu_path_transmit_vlan(p,&input,&output);
     assert(!!actual==!!expected);
     if(actual)assert(actual->index==expected->index && actual->queue==expected->queue &&
                      actual->tcont==expected->tcont && same_packet(&output,&first));
     oracle_cases++;
    }
   }
}
static void benchmark(void){
 struct net_device lan={1},pon={7};struct rtl_fe fe={.itu_netdev=&pon,.itu_paths=config()};
 struct rtl_fe_port lp={.fe=&fe,.netdev=&lan},pp={.fe=&fe,.netdev=&pon};
 struct rtl_fe_rule up=upstream(&lp,&pp,2);
 /* Pure IPv4 QinQ, no impossible third PPPoE encapsulation. */
 dscp_map(fe.itu_paths->path[0].mapper_dscp,true);
 for(unsigned mode=0;mode<2;mode++){
  fe.itu_paths->path[0].unmarked_mode=mode;policy_tx_calls=0;
  clock_t start=clock();unsigned loops=200;
  for(unsigned n=0;n<loops;n++){struct rtl_fe_rule data=up;assert(!fe_itu_rule(&data));}
  printf("IPv4 QinQ helper: mapper=%u, %u rules, %.3f ms CPU, selector evaluations/rule=%lu\n",
   mode,loops,1000.0*(clock()-start)/CLOCKS_PER_SEC,policy_tx_calls/loops);
 }
 free(fe.itu_paths);
}
'''
tests = r'''
static void upstream_cost_only(void){
 struct net_device lan={1},pon={7};struct rtl_fe fe={.itu_netdev=&pon,.itu_paths=config()};
 struct rtl_fe_port lp={.fe=&fe,.netdev=&lan},pp={.fe=&fe,.netdev=&pon};
 fe.itu_paths->path[0].unmarked_mode=1;dscp_map(fe.itu_paths->path[0].mapper_dscp,true);
 struct rtl_fe_rule data=upstream(&lp,&pp,1);data.egress_pppoe=3U|(1U<<2);
 policy_tx_calls=0;assert(!fe_itu_rule(&data));
 printf("Tagged PPPoE/session1 unused mapper: %lu selector evaluations (expected16)\n",policy_tx_calls);fflush(stdout);
 assert(policy_tx_calls==16);
 data=upstream(&lp,&pp,2);policy_tx_calls=0;assert(!fe_itu_rule(&data));
 printf("Pure IPv4 QinQ unused mapper: %lu selector evaluations (expected256)\n",policy_tx_calls);fflush(stdout);
 assert(policy_tx_calls==256);
 free(fe.itu_paths);
}
static void tagged_and_unrelated(void){
 struct net_device lan={1},pon={7};struct rtl_fe fe={.itu_netdev=&pon,.itu_paths=config()};
 struct rtl_fe_port lp={.fe=&fe,.netdev=&lan},pp={.fe=&fe,.netdev=&pon};
 struct rtl_itu_paths *p=fe.itu_paths;
 struct rtl_fe_rule data=downstream(&pp,&lp);assert(!fe_itu_rule(&data));
 p->path[0].unmarked_mode=1;dscp_map(p->path[0].mapper_dscp,true);
 unsigned vectors=0;
 for(unsigned d=0;d<64;d++)for(unsigned v=0;v<16;v++){
  struct rtl_evto_packet input={.count=1,.protocol=ETH_P_PPP_SES,.dscp=d,.priority=v&7,
   .service_entry=1,.tag={{0x8100,41|((v&7)<<13)|((v>>3)<<12)}}},rx,tx;
  assert(rtl_itu_path_receive_vlan(p,8,&input,&rx)==&p->path[0]);
  assert(rtl_itu_path_transmit_vlan(p,&input,&tx)==&p->path[0]);
  assert(same_packet(&input,&rx) && same_packet(&input,&tx));vectors++;
 }
 data=downstream(&pp,&lp);assert(!fe_itu_rule(&data) && data.key.llid==8);
 assert(data.vlan_count==1 && data.vlan[0].vid==41 && !data.action.vlan_set);
 data=upstream(&lp,&pp,1);data.egress_pppoe=3U|(1U<<2);policy_tx_calls=0;
 assert(!fe_itu_rule(&data) && data.action.gem_index==8 && policy_tx_calls==16);
 data=upstream(&lp,&pp,2);policy_tx_calls=0;
 assert(!fe_itu_rule(&data) && policy_tx_calls==256);
 /* A variable profile not referenced by this service must not poison it. */
 variable_priority(p,1,99);
 data=downstream(&pp,&lp);assert(!fe_itu_rule(&data));
 data=upstream(&lp,&pp,2);policy_tx_calls=0;assert(!fe_itu_rule(&data) && policy_tx_calls==256);
 /* Nor a real, different VID service whose variable stage is unreachable. */
 p->count=2;path_init(&p->path[1],99,9);p->path[1].vlan_profile[3]=1;
 data=downstream(&pp,&lp);assert(!fe_itu_rule(&data) && data.key.llid==8);
 data=upstream(&lp,&pp,2);policy_tx_calls=0;assert(!fe_itu_rule(&data) && policy_tx_calls==256);
 trace_oracle(p);
 /* Recompilation uses the new snapshot; no stale positive/negative cache. */
 p->path[1]=p->path[0];p->path[1].index=9;
 data=downstream(&pp,&lp);assert(fe_itu_rule(&data)==-EOPNOTSUPP);
 data=upstream(&lp,&pp,1);assert(fe_itu_rule(&data)==-EOPNOTSUPP);
 p->count=1;data=downstream(&pp,&lp);assert(!fe_itu_rule(&data));
 printf("Tagged PPPoE/session1: %u DSCP/PCP/DEI vectors, irrelevant profile/service isolation and multi-GEM veto passed\n",vectors);
 free(p);
}
static void real_dependencies(void){
 struct net_device lan={1},pon={7};struct rtl_fe fe={.itu_netdev=&pon,.itu_paths=config()};
 struct rtl_fe_port lp={.fe=&fe,.netdev=&lan},pp={.fe=&fe,.netdev=&pon};
 struct rtl_itu_paths *p=fe.itu_paths;
 p->count=2;
 for(unsigned n=0;n<2;n++){
  path_init(&p->path[n],RTL_ITU_VLAN_ANY,8+n);p->path[n].unmarked_mode=1;
  p->path[n].pbits=n?0xf0:0x0f;dscp_map(p->path[n].mapper_dscp,true);
 }
 struct rtl_fe_rule data=upstream(&lp,&pp,0);
 assert(fe_itu_rule(&data)==-EOPNOTSUPP); /* Untagged DSCP really changes GEM. */
 trace_oracle(p);
 for(unsigned n=0;n<2;n++)dscp_map(p->path[n].mapper_dscp,false);
 data=upstream(&lp,&pp,0);policy_tx_calls=0;
 assert(!fe_itu_rule(&data) && data.action.gem_index==8 && policy_tx_calls==8);
 /* An initially tagged packet becomes untagged BEFORE the mapper. */
 p->profile_count=2;
 p->profile[1]=(struct rtl_evto_profile){.input_tpid=0x8100,.output_tpid=0x8100,.downstream=1};
 row(&p->profile[1],0,0xf8000000,0x88000000,0x400f0000,0x000f0000);
 assert(rtl_evto_valid(&p->profile[1]));
 for(unsigned n=0;n<2;n++){
  p->path[n].vlan=41;p->path[n].vlan_profile[2]=1;dscp_map(p->path[n].mapper_dscp,true);
 }
 struct rtl_evto_packet packet={.count=1,.protocol=ETH_P_IP,.service_entry=1,.tag={{0x8100,41}}};
 assert(traced_dependency(p,&packet));
 data=upstream(&lp,&pp,1);assert(fe_itu_rule(&data)==-EOPNOTSUPP);
 trace_oracle(p);
 /* A reached EVTO DSCP edit, rather than the mapper, can select another GEM. */
 variable_priority(p,1,41);
 for(unsigned n=0;n<2;n++)p->path[n].unmarked_mode=0;
 data=upstream(&lp,&pp,1);assert(fe_itu_rule(&data)==-EOPNOTSUPP);
 trace_oracle(p);
 /* A DHCP-only variable row does not affect ordinary TCP, but must be
  * considered for DHCP. Default-row ordering remains the production order. */
 p->count=1;p->path[0].pbits=255;
 p->profile[1].row[0][7]|=0x10;
 row(&p->profile[1],1,0xf8000000,0xe8000000,0x000f0000,0x000f0000);
 assert(rtl_evto_valid(&p->profile[1]));
 packet.criteria=0;assert(!traced_dependency(p,&packet));
 packet.criteria=1;assert(traced_dependency(p,&packet));
 data=upstream(&lp,&pp,1);assert(!fe_itu_rule(&data));
 data=upstream(&lp,&pp,1);data.key.protocol=IPPROTO_UDP;data.key.source_port=67;data.key.destination_port=68;
 assert(fe_itu_rule(&data)==-EOPNOTSUPP);
 trace_oracle(p);
 p->profile[1].row[0][7]=0x20; /* DHCPv6-only criteria, including IPv6 over PPPoE. */
 assert(rtl_evto_valid(&p->profile[1]));
 data=upstream(&lp,&pp,1);data.ipv6=true;assert(!fe_itu_rule(&data));
 data=upstream(&lp,&pp,1);data.ipv6=true;data.key.protocol=IPPROTO_UDP;
 data.key.source_port=546;data.key.destination_port=547;assert(fe_itu_rule(&data)==-EOPNOTSUPP);
 data=upstream(&lp,&pp,1);data.ipv6=true;data.egress_pppoe=3U|(1U<<2);data.key.protocol=IPPROTO_UDP;
 data.key.source_port=546;data.key.destination_port=547;assert(fe_itu_rule(&data)==-EOPNOTSUPP);
 trace_oracle(p);
 free(p);puts("Actual mapper/EVTO/after-pop/DSCP-to-GEM and DHCP dependencies remain fail-closed; constant maps avoid64-way expansion");
}
static void stage_order_and_rank(void){
 struct net_device lan={1},pon={7};struct rtl_fe fe={.itu_netdev=&pon,.itu_paths=config()};
 struct rtl_fe_port lp={.fe=&fe,.netdev=&lan},pp={.fe=&fe,.netdev=&pon};
 struct rtl_itu_paths *p=fe.itu_paths;
 path_init(&p->path[0],41,8);p->path[0].vlan_profile[2]=1;p->path[0].vlan_profile[3]=2;
 variable_priority(p,1,41);p->profile_count=3;
 p->profile[2]=(struct rtl_evto_profile){.input_tpid=0x8100,.output_tpid=0x8100,.downstream=0};
 row(&p->profile[2],0,0xf8000000,0x88000000,0x400f0000,(5U<<16)|(4096U<<3)|4U);
 assert(rtl_evto_valid(&p->profile[2]));
 struct rtl_evto_packet packet={.count=1,.protocol=ETH_P_IP,.service_entry=1,.tag={{0x8100,41}}};
 assert(traced_dependency(p,&packet)); /* Earlier read is not erased by later overwrite. */
 struct rtl_fe_rule data=upstream(&lp,&pp,1);
 assert(!fe_itu_rule(&data) && data.action.vlan_set && data.action.vlan[0].priority==5);
 for(unsigned d=0;d<64;d++){
  struct rtl_evto_packet output;packet.dscp=d;
  assert(rtl_itu_path_transmit_vlan(p,&packet,&output)==&p->path[0]);
  assert(output.count==1 && output.tag[0].tci==(41|(5U<<13)));
 }
 /* Constant maps with different nonzero values are independent of DSCP. */
 priority_map(p->profile[1].dscp,2);
 row(&p->profile[2],0,0xf8000000,0x88000000,0x400f0000,(10U<<16)|(4096U<<3)|4U);
 priority_map(p->profile[2].dscp,5);assert(rtl_evto_valid(&p->profile[2]));
 assert(!traced_dependency(p,&packet));
 data=upstream(&lp,&pp,1);policy_tx_calls=0;
 assert(!fe_itu_rule(&data) && data.action.vlan[0].priority==5 && policy_tx_calls==16);
 trace_oracle(p);
 /* A higher-ranked path is viable at some DSCPs, not all. Its lower-ranked
  * fallback must not be pruned based on the DSCP0 result or iteration order. */
 p->count=2;path_init(&p->path[0],RTL_ITU_VLAN_ANY,8);path_init(&p->path[1],41,9);
 p->path[1].vlan_profile[2]=1;p->path[1].pbits=0x0f;dscp_map(p->profile[1].dscp,true);
 for(unsigned order=0;order<2;order++){
  packet.dscp=0;struct rtl_evto_packet output;
  assert(rtl_itu_path_transmit_vlan(p,&packet,&output)->index==9);
  packet.dscp=4;assert(rtl_itu_path_transmit_vlan(p,&packet,&output)->index==8);
  data=upstream(&lp,&pp,1);assert(fe_itu_rule(&data)==-EOPNOTSUPP);
  trace_oracle(p);
  struct rtl_itu_path swap=p->path[0];p->path[0]=p->path[1];p->path[1]=swap;
 }
 /* vlan_exclude is tested before the unmarked mapper, not after it. */
 p->count=1;path_init(&p->path[0],RTL_ITU_VLAN_ANY,8);
 p->path[0].unmarked_mode=1;p->path[0].vlan_exclude=2;dscp_map(p->path[0].mapper_dscp,true);
 packet=(struct rtl_evto_packet){.protocol=ETH_P_IPV6,.priority=1};
 assert(!traced_dependency(p,&packet));
 for(unsigned d=0;d<64;d++){
  struct rtl_evto_packet output;packet.dscp=d;assert(!rtl_itu_path_transmit_vlan(p,&packet,&output));
 }
 data=upstream(&lp,&pp,0);assert(fe_itu_rule(&data)==-EOPNOTSUPP);
 trace_oracle(p);
 free(p);puts("Multi-stage overwrite, nonzero constant maps, rank/order-dependent fallback and pre-mapper exclusion passed");
}
static void downstream_images(void){
 struct net_device lan={1},pon={7};struct rtl_fe fe={.itu_netdev=&pon,.itu_paths=config()};
 struct rtl_fe_port lp={.fe=&fe,.netdev=&lan},pp={.fe=&fe,.netdev=&pon};
 struct rtl_itu_paths *p=fe.itu_paths;
 path_init(&p->path[0],RTL_ITU_VLAN_ANY,8);p->profile_count=3;
 p->path[0].vlan_profile[2]=1;p->path[0].vlan_profile[3]=2;
 p->profile[1]=(struct rtl_evto_profile){.input_tpid=0x8100,.output_tpid=0x8100,.downstream=6};
 row(&p->profile[1],0,0xf8000000,0xf8000000,0x000f0000,(10U<<16)|(41U<<3)|4U);
 dscp_map(p->profile[1].dscp,true);
 p->profile[2]=(struct rtl_evto_profile){.input_tpid=0x8100,.output_tpid=0x8100,.downstream=0};
 for(unsigned pri=0;pri<8;pri++)row(&p->profile[2],pri,0xf8000000,(pri<<28)|(41U<<15)|(4U<<12),
  0x400f0000,(8U<<16)|((100U+(pri&1))<<3));
 assert(rtl_evto_valid(&p->profile[1]) && rtl_evto_valid(&p->profile[2]));
 struct rtl_fe_rule data=downstream(&pp,&lp);data.pppoe_input=false;data.pppoe_session=0;data.vlan_count=0;
 maximum_image_dscp=0;saw_wire100=saw_wire101=false;
 assert(fe_itu_rule(&data)==-EOPNOTSUPP);
 assert(maximum_image_dscp>0 && saw_wire100 && saw_wire101);
 /* An early variable edit must remain marked when a later stage drops d0. */
 p->profile[2].count=1;
 row(&p->profile[2],0,0xf8000000,(1U<<28)|(41U<<15)|(4U<<12),0x400f0000,(8U<<16)|(101U<<3));
 assert(rtl_evto_valid(&p->profile[2]));
#if HAVE_DEPENDENCY_TRACE
 struct rtl_evto_packet packet={.protocol=ETH_P_IP};bool dependent=false;
 assert(!fe_evto_path_upstream(p,&p->path[0],&packet,0,RTL_EVTO_STAGES,&dependent) && dependent);
#endif
 data=downstream(&pp,&lp);data.pppoe_input=false;data.pppoe_session=0;data.vlan_count=0;
 maximum_image_dscp=0;saw_wire101=false;
 assert(fe_itu_rule(&data)==-EOPNOTSUPP && maximum_image_dscp>0 && saw_wire101);
 trace_oracle(p);
 free(p);puts("Downstream: all reachable DSCP images considered, multiple wire-key ambiguity still rejected; late-drop dependency retained");
}
int main(void){
#if EVTO_COST_ONLY
 upstream_cost_only();
#else
 tagged_and_unrelated();upstream_cost_only();real_dependencies();stage_order_and_rank();downstream_images();
 printf("Exhaustive production-selector oracle: %lu DSCP comparisons passed\n",oracle_cases);
 assert(oracle_cases>100000);
 puts("EVTO dependency regression passed (host helpers, no hardware throughput claim).");
#endif
}
'''
code = ("#define HAVE_DEPENDENCY_TRACE " + str(int("fe_evto_upstream_dscp(" in vlan)) + "\n" +
        "#define EVTO_COST_ONLY " + str(int(args.upstream_cost_only)) + "\n" +
        common + rule + "\n" + vlan + fixtures +
        ("int main(void){benchmark();return 0;}\n" if args.benchmark_only else tests))
print("EVTO source SHA256:", hashlib.sha256(vlan.encode()).hexdigest(), flush=True)
print("Host:", platform.machine(), "; cc -O2; production helper only", flush=True)
with tempfile.TemporaryDirectory(prefix="fe-evto-dependencies-") as directory:
    binary = str(Path(directory) / "test")
    command = ["cc", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function"]
    if not args.benchmark_only:
        command += ["-fsanitize=address,undefined"]
    command += ["-I" + str(drivers), "-x", "c", "-", "-o", binary]
    subprocess.run(command, input=code, text=True, check=True)
    subprocess.run([binary], check=True)
