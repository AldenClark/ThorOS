#!/usr/bin/env python3
"""Run the production topology snapshot and static replay, not a copied plan.

Only netdevice/bridge query boundaries are represented by a host fixture.
This verifies Linux admission and replay decisions, not ASIC packet delivery.
"""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVERS = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"
source = (DRIVERS / "rtl9617c-fe-switch.h").read_text()


def function(name):
    start = source.index(name + "(")
    start = source.rfind("\n", 0, start) + 1
    if not source[start:].startswith("static "):
        start = source.rfind("\n", 0, start - 1) + 1
    end = source.index("{", start) + 1
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
#include <string.h>
#include "rtl9617c-l2-format.h"
typedef uint32_t u32;typedef uint8_t u8;
#define FE_LAN_PORTS 5
#define ETH_ALEN 6
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define READ_ONCE(value) (value)
#define WRITE_ONCE(target,value) ((target)=(value))
#define NETREG_REGISTERED 1
#define IFF_PROMISC 0x100
#define BR_BPDU_GUARD BIT(1)
#define BR_ROOT_BLOCK BIT(2)
#define BR_MULTICAST_FAST_LEAVE BIT(3)
#define BR_ADMIN_COST BIT(4)
#define BR_LEARNING BIT(5)
#define BR_FLOOD BIT(6)
#define BR_PROMISC BIT(7)
#define BR_LEARNING_SYNC BIT(9)
#define BR_MCAST_FLOOD BIT(11)
#define BR_BCAST_FLOOD BIT(14)
#define BR_BPDU_FILTER BIT(24)
#define BR_STATE_DISABLED 0
#define BR_STATE_FORWARDING 3
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
struct list_head {struct list_head *next,*prev;};
static void init_list(struct list_head *h){h->next=h->prev=h;}
static void append(struct list_head *item,struct list_head *h){
 item->next=h;item->prev=h->prev;h->prev->next=item;h->prev=item;
}
static void remove_item(struct list_head *item){
 item->prev->next=item->next;item->next->prev=item->prev;init_list(item);
}
#define list_for_each_entry(p,h,m) \
 for(struct list_head *_node=(h)->next;_node!=(h) && ((p)=container_of(_node,__typeof__(*(p)),m),true);_node=_node->next)
struct net_device {
 unsigned int reg_state,flags,state,bridge_flags,index;
 bool running,carrier,bridge,policy,vlan,port_eligible,master_eligible;
 struct net_device *master;struct list_head lowers;
 unsigned int policy_reads,master_reads,port_reads;
};
struct lower_link {struct list_head list;struct net_device *dev;};
#define netdev_for_each_lower_dev(master,lower,iter) \
 for((iter)=(master)->lowers.next;(iter)!=&(master)->lowers && \
 ((lower)=container_of(iter,struct lower_link,list)->dev,true);(iter)=(iter)->next)
struct rtl_fe_port {
 struct list_head list;struct net_device *netdev;unsigned int source,destination;bool retired;
};
struct rtl_fe {struct list_head ports;bool enabled;};
struct rtl_fe_bridge {
 struct rtl_fe *fe;struct net_device *ports[5],*master;u32 route_mask,native_mask;
 unsigned int local_target,rule_count,rules[RTL_L2_FDB_ENTRIES][RTL_L2_FDB_WORDS];
};
struct switchdev_notifier_info {struct net_device *dev;};
struct switchdev_notifier_fdb_info {
 struct switchdev_notifier_info info;unsigned int vid;bool locked,is_local,added_by_user;
 const u8 *addr;
};
static bool netif_running(const struct net_device *dev){return dev->running;}
static bool netif_carrier_ok(const struct net_device *dev){return dev->carrier;}
static struct net_device *netdev_master_upper_dev_get(struct net_device *dev){return dev->master;}
static bool netif_is_bridge_master(const struct net_device *dev){return dev->bridge;}
static bool rtl9617c_switch_device_has_policy(struct net_device *dev){dev->policy_reads++;return dev->policy;}
static bool br_vlan_enabled(struct net_device *dev){return dev->vlan;}
static bool br_rtl9617c_l2_eligible(struct net_device *dev){dev->master_reads++;return dev->master_eligible;}
static bool br_rtl9617c_l2_port_eligible(struct net_device *dev){dev->port_reads++;return dev->port_eligible;}
static unsigned int br_port_get_stp_state(const struct net_device *dev){return dev->state;}
static bool br_port_flag_is_set(const struct net_device *dev,unsigned long bit){return dev->bridge_flags & bit;}
static unsigned int hweight32(u32 value){return __builtin_popcount(value);}
static bool switchdev_fdb_is_dynamically_learned(const struct switchdev_notifier_fdb_info *info){return !info->added_by_user && !info->is_local;}
static bool is_valid_ether_addr(const u8 *mac){unsigned int any=0;for(unsigned int i=0;i<6;i++)any|=mac[i];return any && !(mac[0]&1);}
static void ether_addr_copy(u8 *dst,const u8 *src){memcpy(dst,src,6);}
static bool ether_addr_equal(const u8 *a,const u8 *b){return !memcmp(a,b,6);}
'''

TEST = r'''
static struct rtl_fe fe;
static struct rtl_fe_bridge sw;
static struct net_device lan[5],master[2],foreign;
static struct rtl_fe_port owners[5];
static struct lower_link links[6];
static struct fe_switch_plan plan;
static unsigned int cases;
static void netdev_init(struct net_device *dev){
 *dev=(struct net_device){.reg_state=NETREG_REGISTERED,.state=BR_STATE_FORWARDING,
  .bridge_flags=BR_LEARNING|BR_FLOOD|BR_MCAST_FLOOD|BR_BCAST_FLOOD,
  .running=true,.carrier=true,.port_eligible=true,.master_eligible=true};
 init_list(&dev->lowers);
}
static void setup(u32 running,u32 carrier){
 memset(&fe,0,sizeof(fe));memset(&sw,0,sizeof(sw));init_list(&fe.ports);fe.enabled=true;
 sw.fe=&fe;sw.local_target=25;netdev_init(&foreign);
 for(unsigned int i=0;i<2;i++){netdev_init(&master[i]);master[i].bridge=true;}
 for(unsigned int i=0;i<5;i++){
  netdev_init(&lan[i]);lan[i].index=i;lan[i].master=&master[0];
  lan[i].running=running&BIT(i);lan[i].carrier=carrier&BIT(i);
  if(!lan[i].running || !lan[i].carrier)lan[i].state=BR_STATE_DISABLED;
  owners[i]=(struct rtl_fe_port){.netdev=&lan[i],.source=i,.destination=i};
  append(&owners[i].list,&fe.ports);links[i].dev=&lan[i];append(&links[i].list,&master[0].lowers);
 }
}
static void expect(enum fe_switch_reason reason,u32 active,u32 route){
 assert(fe_switch_snapshot(&sw,&plan)==reason);assert(plan.ports==active);assert(sw.route_mask==route);cases++;
}
static void online_matrix(void){
 for(u32 running=0;running<32;running++)for(u32 carrier=0;carrier<32;carrier++){
  u32 active=running&carrier;setup(running,carrier);
  enum fe_switch_reason expected=hweight32(active)>=2?FE_SWITCH_OK:FE_SWITCH_NO_BRIDGE;
  expect(expected,active,active);assert(sw.master==&master[0]);
  for(unsigned int i=0;i<5;i++){
   assert(sw.ports[i]==&lan[i]);assert(!!lan[i].port_reads==!!(active&BIT(i)));
  }
  assert(master[0].master_reads && master[0].policy_reads);
  fe.enabled=false;expect(expected,active,0);
 }
}
static void topology_and_policy(void){
 /* A single active bridge member still has a valid routed HW ingress. */
 setup(31,1);expect(FE_SWITCH_NO_BRIDGE,1,1);assert(plan.state[0]==BR_STATE_FORWARDING);
 /* A live STP restriction is never treated as an unplugged port. */
 for(unsigned int state=0;state<=4;state++)if(state!=BR_STATE_FORWARDING){
  setup(31,31);lan[2].state=state;expect(FE_SWITCH_PORT_POLICY,31,31);
 }
 setup(31,1);lan[4].bridge_flags=BIT(16);lan[4].port_eligible=false;
 expect(FE_SWITCH_NO_BRIDGE,1,1);assert(!lan[4].port_reads);
 setup(31,3);lan[1].bridge_flags|=BIT(16);expect(FE_SWITCH_PORT_POLICY,3,3);
 setup(31,3);lan[1].port_eligible=false;expect(FE_SWITCH_PRIVATE_POLICY,3,3);
 setup(31,1);lan[4].policy=true;expect(FE_SWITCH_GUARDED,1,1);
 /* An offline member still identifies a different bridge. Its policies,
  * and policies of the earlier master, must both be inspected. */
 setup(31,1);remove_item(&links[4].list);append(&links[4].list,&master[1].lowers);lan[4].master=&master[1];
 expect(FE_SWITCH_MULTI_BRIDGE,1,1);assert(plan.multi_bridge);
 master[0].vlan=true;master[0].master_eligible=false;master[0].flags=IFF_PROMISC;master[0].policy=true;
 expect(FE_SWITCH_GUARDED,1,1);
 assert(plan.vlan_filtering && plan.private_policy && plan.promisc && master[0].policy_reads && master[1].policy_reads);
 master[0].policy=false;master[1].policy=true;expect(FE_SWITCH_GUARDED,1,1);
 setup(31,0);master[0].vlan=true;expect(FE_SWITCH_VLAN_UNSUPPORTED,0,0);
 setup(31,1);master[0].master_eligible=false;expect(FE_SWITCH_PRIVATE_POLICY,1,1);
 setup(31,1);master[0].flags=IFF_PROMISC;expect(FE_SWITCH_PROMISC,1,1);
 setup(31,1);master[0].policy=true;expect(FE_SWITCH_GUARDED,1,1);
 setup(31,1);links[5].dev=&foreign;append(&links[5].list,&master[0].lowers);
 expect(FE_SWITCH_MIXED_PORTS,1,1);
 /* Missing, retired and non-LAN FE registrations are not live native
  * devices. If still bridged they count as unknown topology, not an
  * excuse to forward around a partially removed bridge member. */
 setup(31,31);lan[4].reg_state=2;expect(FE_SWITCH_MIXED_PORTS,15,15);assert(!sw.ports[4]);
 remove_item(&links[4].list);expect(FE_SWITCH_OK,15,15);
 setup(31,31);owners[4].retired=true;expect(FE_SWITCH_MIXED_PORTS,15,15);assert(!sw.ports[4]);
 remove_item(&links[4].list);expect(FE_SWITCH_OK,15,15);
 setup(31,31);owners[4].destination=24;remove_item(&links[4].list);expect(FE_SWITCH_OK,15,15);assert(!sw.ports[4]);
 setup(31,31);owners[4].source=7;owners[4].netdev=NULL;remove_item(&links[4].list);expect(FE_SWITCH_OK,15,15);
 setup(31,31);owners[4].retired=true;owners[4].netdev=NULL;remove_item(&links[4].list);expect(FE_SWITCH_OK,15,15);
 /* Routed ports need no bridge. A non-bridge upper is not a bridge. */
 setup(31,1);for(unsigned int i=0;i<5;i++)lan[i].master=NULL;
 expect(FE_SWITCH_NO_BRIDGE,0,1);assert(!sw.master);
 lan[0].master=&foreign;expect(FE_SWITCH_NO_BRIDGE,0,1);assert(!sw.master);
 foreign.policy=true;lan[0].policy=true;expect(FE_SWITCH_GUARDED,0,1);
}
static void replay_mask(void){
 struct rtl_l2_fdb_entry decoded;
 for(unsigned int port=0;port<5;port++){
  setup(31,5);expect(FE_SWITCH_OK,5,5);sw.native_mask=plan.ports;
  u8 mac[6]={2,0,0,0,0,(u8)(port+1)};
  struct switchdev_notifier_fdb_info info={.info={.dev=&lan[port]},.added_by_user=true,.addr=mac};
  assert(!fe_switch_replay_fdb(&sw,&info));assert(sw.rule_count==!!(5&BIT(port)));
  if(sw.rule_count){rtl_l2_fdb_decode(sw.rules[0],&decoded);assert(decoded.destination==port);}
  /* A local address remains CPU-owned even when its physical member is
   * offline; omitting it could instead make it a hardware UC destination. */
  sw.rule_count=0;info.is_local=true;assert(!fe_switch_replay_fdb(&sw,&info));
  assert(sw.rule_count==1);rtl_l2_fdb_decode(sw.rules[0],&decoded);assert(decoded.destination==25);cases++;
 }
 setup(31,1);expect(FE_SWITCH_NO_BRIDGE,1,1);sw.native_mask=0;
 u8 mac[6]={2,0,0,0,0,1};
 struct switchdev_notifier_fdb_info info={.info={.dev=&lan[0]},.added_by_user=true,.addr=mac};
 assert(!fe_switch_replay_fdb(&sw,&info) && !sw.rule_count);
 info.info.dev=&foreign;assert(fe_switch_replay_fdb(&sw,&info)==-EOPNOTSUPP);
 info.info.dev=&lan[0];info.is_local=true;assert(!fe_switch_replay_fdb(&sw,&info) && sw.rule_count==1);cases++;
}
int main(void){online_matrix();topology_and_policy();replay_mask();
 printf("Production L2 topology: %u snapshots/replay cases; online membership, all bridge policies, live STP rejection and offline FDB exclusion passed\n",cases);return 0;}
'''

declarations = re.search(r"enum fe_switch_reason \{.*?\n\};", source, re.S).group()
declarations += "\n" + re.search(r"struct fe_switch_plan \{.*?\n\};", source, re.S).group()
production = "\n".join(function(name) for name in (
    "fe_switch_port_index", "fe_switch_plan_validate", "fe_switch_snapshot", "fe_switch_replay_fdb"))
environment = os.environ.copy()
environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
with tempfile.TemporaryDirectory(prefix="l2-topology-") as directory:
    directory = Path(directory)
    cfile, binary = directory / "test.c", directory / "test"
    cfile.write_text(COMMON + declarations + production + TEST)
    subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                    "-I", str(DRIVERS), str(cfile), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], env=environment, check=True)
print("Extracted production functions sha256:", hashlib.sha256(production.encode()).hexdigest())
