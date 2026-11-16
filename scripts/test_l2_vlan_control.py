#!/usr/bin/env python3
"""Execute the driver's VID-aware snapshot/replay, not a copied planner.

Only Linux query boundaries are represented here. This test does not enable
the hardware IVL backend or claim that its parser/consumer contract is proven.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVERS = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"
SWITCH = (DRIVERS / "rtl9617c-fe-switch.h").read_text()
VLAN = (DRIVERS / "rtl9617c-fe-switch-vlan.h").read_text()


def function(name, source=SWITCH):
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
#include <stdio.h>
#include <string.h>
#include "rtl9617c-l2-domain.h"
typedef unsigned int u32;typedef unsigned char u8;
#define FE_LAN_PORTS 5
#define ETH_ALEN 6
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
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
#define BR_ISOLATED BIT(16)
#define BR_BPDU_FILTER BIT(24)
#define BR_STATE_FORWARDING 3
#define BR_STATE_BLOCKING 4
#define BRIDGE_VLAN_INFO_PVID 2
#define BRIDGE_VLAN_INFO_UNTAGGED 4
struct bridge_vlan_info {unsigned short flags,vid;};
struct net_device {
 bool bridge,filtering,eligible;struct net_device *master;
 struct bridge_vlan_info vlan[129];unsigned int count;unsigned long age;int error;
};
struct rtl_fe {bool ivl;};
struct rtl_fe_bridge {
 struct rtl_fe *fe;struct net_device *ports[5],*master,*masters[5];
 struct rtl_l2_vlan_plan vlans;unsigned int master_count;bool vlan_domain;
 unsigned int replay_ports,local_target,rule_count,reason;
 unsigned int rules[RTL_L2_FDB_ENTRIES][RTL_L2_FDB_WORDS];
 unsigned int replay_traps[(RTL_L2_FDB_ENTRIES+31)/32];
};
struct switchdev_notifier_info {struct net_device *dev;};
struct switchdev_notifier_fdb_info {
 struct switchdev_notifier_info info;unsigned short vid;
 bool locked,is_local,added_by_user;const unsigned char *addr;
};
static unsigned int queries,cases;
static bool fe_native_l2_ivl(struct rtl_fe *fe){return fe->ivl;}
static struct net_device *netdev_master_upper_dev_get(struct net_device *dev){return dev->master;}
static bool netif_is_bridge_master(struct net_device *dev){return dev->bridge;}
static bool br_vlan_enabled(struct net_device *dev){return dev->filtering;}
static bool br_rtl9617c_l2_vlan_port_eligible(struct net_device *dev){return dev->eligible;}
static int br_vlan_get_info(struct net_device *dev,unsigned short vid,struct bridge_vlan_info *info){
 queries++;if(dev->error)return dev->error;
 for(unsigned int i=0;i<dev->count;i++)if(dev->vlan[i].vid==vid){*info=dev->vlan[i];return 0;}
 return -ENOENT;
}
static int br_rtl9617c_fdb_hold_time(struct net_device *dev,unsigned long *age){
 if(!dev)return -ENODEV;if(dev->error)return dev->error;*age=dev->age;return 0;
}
static unsigned int hweight32(unsigned int value){return __builtin_popcount(value);}
static bool switchdev_fdb_is_dynamically_learned(const struct switchdev_notifier_fdb_info *info){return !info->added_by_user && !info->is_local;}
static bool is_valid_ether_addr(const u8 *mac){unsigned int any=0;for(unsigned int i=0;i<6;i++)any|=mac[i];return any && !(mac[0]&1);}
static void ether_addr_copy(u8 *to,const u8 *from){memcpy(to,from,6);}
static bool ether_addr_equal(const u8 *a,const u8 *b){return !memcmp(a,b,6);}
static void rcu_read_lock(void){}
static void rcu_read_unlock(void){}
static struct net_device *br_switchdev_fdb_find_port(struct net_device *br,const u8 *address,unsigned short vid){
 (void)br;(void)address;(void)vid;return NULL;
}
'''

TEST = r'''
static struct rtl_fe fe;
static struct rtl_fe_bridge sw;
static struct net_device master[2],lan[5];
static struct fe_switch_plan plan;
static void member(unsigned int port,unsigned int vid,unsigned int flags){
 assert(lan[port].count<129);lan[port].vlan[lan[port].count++]=(struct bridge_vlan_info){.vid=vid,.flags=flags};
}
static void setup(void){
 memset(&sw,0,sizeof(sw));memset(lan,0,sizeof(lan));memset(master,0,sizeof(master));memset(&plan,0,sizeof(plan));
 sw.fe=&fe;fe.ivl=true;plan.ports=15;plan.vlan_filtering=plan.multi_bridge=true;queries=0;
 for(unsigned int i=0;i<2;i++){master[i].bridge=master[i].filtering=true;master[i].age=30000;}
 for(unsigned int i=0;i<5;i++){
  sw.ports[i]=&lan[i];lan[i].eligible=true;
  lan[i].master=i<2?&master[0]:i<4?&master[1]:NULL;
  plan.flags[i]=BR_LEARNING;plan.state[i]=BR_STATE_FORWARDING;
 }
 sw.master=&master[1];sw.local_target=25;sw.replay_ports=15;
 member(0,10,0);member(1,10,0);member(0,20,0);member(1,20,0);
 member(2,30,0);member(3,30,0);
}
static enum fe_switch_reason snapshot(void){
 cases++;return fe_switch_vlan_snapshot(&sw,&plan,FE_SWITCH_MULTI_BRIDGE);
}
static void snapshot_contract(void){
 setup();fe.ivl=false;assert(snapshot()==FE_SWITCH_MULTI_BRIDGE && !queries && !sw.vlan_domain);
 setup();plan.vlan_filtering=false;assert(snapshot()==FE_SWITCH_VLAN_UNSUPPORTED && !queries);
 setup();assert(snapshot()==FE_SWITCH_OK && sw.vlan_domain && sw.master_count==2 && sw.vlans.count==3);
 assert(fe_switch_bridge_for_vid(&sw,10)==&master[0] && fe_switch_bridge_for_vid(&sw,30)==&master[1]);
 assert(!fe_switch_bridge_for_vid(&sw,0) && !fe_switch_bridge_for_vid(&sw,99));
 assert(sw.vlans.vlans[0].members==3 && sw.vlans.vlans[0].forwarding==3 && sw.vlans.vlans[0].learning==3);
 assert(sw.vlans.vlans[2].members==12);
 for(unsigned int veto=0;veto<5;veto++){
  setup();if(veto==0)plan.software_policy=true;if(veto==1)plan.private_policy=true;
  if(veto==2)plan.mixed=true;if(veto==3)plan.promisc=true;if(veto==4)plan.flags[0]|=BIT(31);
  const enum fe_switch_reason why[]={FE_SWITCH_GUARDED,FE_SWITCH_PRIVATE_POLICY,FE_SWITCH_MIXED_PORTS,FE_SWITCH_PROMISC,FE_SWITCH_PORT_POLICY};
  assert(snapshot()==why[veto] && !sw.vlan_domain && !queries);
 }
 setup();member(2,10,0);assert(snapshot()==FE_SWITCH_MULTI_BRIDGE && !sw.vlan_domain);
 setup();lan[4].master=&master[1];member(4,10,0);assert(snapshot()==FE_SWITCH_MULTI_BRIDGE && !sw.vlan_domain);
 for(unsigned int flag=2;flag<=4;flag+=2){setup();lan[1].vlan[0].flags=flag;assert(snapshot()==FE_SWITCH_VLAN_UNSUPPORTED && !sw.vlan_domain);}
 setup();lan[1].eligible=false;assert(snapshot()==FE_SWITCH_VLAN_UNSUPPORTED);
 setup();master[1].filtering=false;assert(snapshot()==FE_SWITCH_VLAN_UNSUPPORTED);
 setup();lan[1].error=-EIO;assert(snapshot()==FE_SWITCH_VLAN_UNSUPPORTED);
 setup();plan.ports=5;assert(snapshot()==FE_SWITCH_NO_BRIDGE && !sw.vlan_domain);
 setup();lan[4].master=&master[0];member(4,10,0);
 assert(snapshot()==FE_SWITCH_OK && sw.vlans.vlans[0].members==19 && sw.vlans.vlans[0].forwarding==3);
 setup();plan.flags[0]&=~BR_LEARNING;plan.flags[1]|=BR_ISOLATED;
 assert(snapshot()==FE_SWITCH_OK && sw.vlans.vlans[0].learning==2 && sw.vlans.vlans[0].isolated==2);
 setup();lan[0].count=lan[1].count=lan[2].count=lan[3].count=0;
 for(unsigned int vid=1;vid<=129;vid++){member(0,vid,0);member(1,vid,0);}
 assert(snapshot()==FE_SWITCH_VLAN_UNSUPPORTED && !sw.vlan_domain);
}
static void ageing_contract(void){
 unsigned long ticks=0;setup();assert(snapshot()==FE_SWITCH_OK);
 assert(!fe_switch_age_ticks(&sw,&ticks) && ticks==30000);
 master[1].age=1500;assert(fe_switch_age_ticks(&sw,&ticks)==-EOPNOTSUPP);
 master[0].age=1500;assert(!fe_switch_age_ticks(&sw,&ticks) && ticks==1500);
 master[0].age=master[1].age=0;assert(!fe_switch_age_ticks(&sw,&ticks) && !ticks);
 master[1].error=-EAGAIN;assert(fe_switch_age_ticks(&sw,&ticks)==-EAGAIN);
 sw.master_count=0;assert(fe_switch_age_ticks(&sw,&ticks)==-ENODEV);cases++;
}
static void replay_contract(void){
 const u8 mac[]={2,0,0,0,0,1};struct rtl_l2_fdb_entry entry;
 setup();lan[4].master=&master[0];member(4,10,0);assert(snapshot()==FE_SWITCH_OK);
 struct switchdev_notifier_fdb_info info={.info={.dev=&lan[0]},.vid=10,.addr=mac,.added_by_user=true};
 assert(!fe_switch_replay_fdb(&sw,&info) && sw.rule_count==1);
 info.vid=20;assert(!fe_switch_replay_fdb(&sw,&info) && sw.rule_count==2);
 rtl_l2_fdb_decode(sw.rules[0],&entry);assert(entry.key_vid==10 && entry.destination==0);
 rtl_l2_fdb_decode(sw.rules[1],&entry);assert(entry.key_vid==20 && entry.destination==0);
 info.info.dev=&lan[1];assert(!fe_switch_replay_fdb(&sw,&info) && sw.rule_count==2);
 rtl_l2_fdb_decode(sw.rules[1],&entry);assert(entry.key_vid==20 && entry.destination==1);
 info.info.dev=&lan[2];assert(!fe_switch_replay_fdb(&sw,&info) && sw.rule_count==2);
 info.info.dev=&lan[4];assert(!fe_switch_replay_fdb(&sw,&info) && sw.rule_count==2);
 rtl_l2_fdb_decode(sw.rules[1],&entry);assert(entry.key_vid==20 && entry.destination==1);
 info.info.dev=&lan[4];info.vid=10;assert(!fe_switch_replay_fdb(&sw,&info) && sw.rule_count==2);
 rtl_l2_fdb_decode(sw.rules[0],&entry);assert(entry.key_vid==10 && entry.destination==16 && (sw.replay_traps[0]&1));
 info.info.dev=&master[0];info.is_local=true;assert(!fe_switch_replay_fdb(&sw,&info));
 rtl_l2_fdb_decode(sw.rules[0],&entry);assert(entry.destination==25 && !(sw.replay_traps[0]&1));
 info.info.dev=&master[1];assert(!fe_switch_replay_fdb(&sw,&info) && sw.rule_count==2);
 info.vid=0;assert(!fe_switch_replay_fdb(&sw,&info) && sw.rule_count==2);
 info.info.dev=&lan[0];info.vid=10;info.is_local=false;info.locked=true;
 assert(fe_switch_replay_fdb(&sw,&info)==-EOPNOTSUPP);cases++;
}
int main(void){snapshot_contract();ageing_contract();replay_contract();
 printf("VID-aware production control: %u snapshots, disjoint multi-bridge VID namespaces, offline sticky traps, exact VLAN replay and shared ageing contract PASS; hardware IVL not asserted\n",cases);return 0;}
'''

definitions = "\n".join(re.search(pattern, SWITCH, re.S)[0] for pattern in [
    r"enum fe_switch_reason \{.*?\n\};", r"struct fe_switch_plan \{.*?\n\};",
])
functions = "\n".join(function(name) for name in [
    "fe_switch_plan_validate", "fe_switch_port_index", "fe_switch_vlan_find", "fe_switch_bridge_for_vid",
]) + "\n" + "\n".join(function(name, VLAN) for name in [
    "fe_switch_vlan_snapshot", "fe_switch_age_ticks", "fe_switch_vlan_replay_member",
]) + "\n" + function("fe_switch_replay_fdb")
mutations = {
    "global_vid_conflict_ignored": functions.replace("return ret == -EADDRINUSE ? FE_SWITCH_MULTI_BRIDGE :", "return ret == -EADDRINUSE ? FE_SWITCH_OK :", 1),
    "vlan_replay_uses_mac_only": functions.replace("if (previous.key_vid == entry.key_vid &&", "if (", 1),
    "offline_sticky_key_leaks_to_port": functions.replace("trap ? 16 : (unsigned int)port", "trap ? (unsigned int)port : (unsigned int)port", 1),
    "different_bridge_ageing_accepted": functions.replace("if (i && next != *ticks)", "if (false && i && next != *ticks)", 1),
    "port_vlan_membership_ignored": functions.replace("return (vlan->members & BIT(port)) &&", "return", 1),
}
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
with tempfile.TemporaryDirectory(prefix="thoros-vlan-control-") as directory:
    temporary = Path(directory)
    environment = dict(os.environ)
    environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
    for name, body in {"production": functions, **mutations}.items():
        assert name == "production" or body != functions, name
        (temporary / "test.c").write_text(COMMON + definitions + body + TEST)
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                        "-Wno-misleading-indentation", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                        "-I", str(DRIVERS), str(temporary / "test.c"), "-o", str(temporary / "test")], check=True)
        result = subprocess.run([str(temporary / "test")], text=True, capture_output=True, env=environment)
        if name == "production":
            assert not result.returncode, result.stderr
            print(result.stdout.strip())
        else:
            assert result.returncode == -6 and "Assertion" in result.stderr, (name, result.returncode, result.stderr)
            print("Runtime regression mutant rejected:", name)
(ROOT / "artifacts").mkdir(exist_ok=True)
(ROOT / "artifacts/l2-vlan-control.json").write_text(json.dumps({
    "production_functions_sha256": hashlib.sha256(functions.encode()).hexdigest(),
    "runtime_mutants_rejected": list(mutations), "hardware_ivl_verified": False,
    "scope": "production VLAN topology/control-plane/FDB replay only; no hardware-contract bypass",
}, indent=2) + "\n")
