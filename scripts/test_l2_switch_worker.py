#!/usr/bin/env python3
"""Run the complete production L2 reconciliation worker with fault boundaries.

Topology discovery, the guard lock and hardware transactions are covered in
separate tests. Here their boundary outcomes are injected into the unchanged
production worker, notifier, replay and admission callbacks, including changes
while its FE mutex is released for RCU or switchdev replay. The switchdev
boundary replays actual FDB records, never fabricates rule_count. No hardware
claim is made.
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
DRIVERS = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"
source = (DRIVERS / "rtl9617c-fe-switch.h").read_text()
source += "\n" + (DRIVERS / "rtl9617c-fe-switch-vlan.h").read_text()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--authority-only", action="store_true", help="Only CPU-owned native fallback and independent routed admission")
args = parser.parse_args()


def function(name):
    body = (DRIVERS / "rtl9617c-fe-switch-vlan.h").read_text() if name == "fe_switch_age_ticks" else source
    start = body.index(name + "(")
    start = body.rfind("\n", 0, start) + 1
    if not body[start:].startswith("static "):
        start = body.rfind("\n", 0, start - 1) + 1
    end = body.index("{", start) + 1
    depth = 1
    while depth:
        depth += (body[end] == "{") - (body[end] == "}")
        end += 1
    return body[start:end] + "\n"


COMMON = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include "rtl9617c-l2-format.h"
#include "rtl9617c-l2-domain.h"
typedef uint32_t u32;typedef unsigned long long u64;typedef uint16_t u16;typedef unsigned char u8;
#define FE_LAN_PORTS 5
#define ETH_ALEN 6
#define HZ 250
#define USER_HZ 100
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define READ_ONCE(value) (value)
#define ARRAY_SIZE(value) (sizeof(value)/sizeof((value)[0]))
#define WRITE_ONCE(target,value) ((target)=(value))
#define min(a,b) ((a)<(b)?(a):(b))
#define system_long_wq 7
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define NOTIFY_DONE 0
#define notifier_from_errno(error) (error)
#define SWITCHDEV_FDB_ADD_TO_DEVICE 1
#define SWITCHDEV_FDB_DEL_TO_DEVICE 2
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
struct net_device {unsigned int index;};
struct notifier_block {int (*notifier_call)(struct notifier_block *,unsigned long,void *);};
struct switchdev_notifier_info {struct net_device *dev;void *ctx;};
struct switchdev_notifier_fdb_info {
 struct switchdev_notifier_info info;const u8 *addr;
 unsigned int vid;bool added_by_user,is_local,locked;
};
struct work_struct {unsigned int unused;};
struct delayed_work {struct work_struct work;};
struct rtl_fe_bridge;
struct rtl9617c_switch_guard {struct rtl_fe_bridge *owner;u64 generation;bool blocked,armed,registered;};
/* PRODUCTION_OBSERVED_DEFINITION */
struct rtl_fe_switch_hw {bool owned,open,port_policy_ready;u32 ports,learning_mask,isolated_mask;unsigned int reason;const struct rtl_l2_vlan_plan *vlan_plan;struct {bool quarantined,restoring;} journal;struct fe_switch_hw_observed observed;};
struct rtl_mcast_groups {unsigned short group[5][4];unsigned char enabled[5];};
struct rtl_fe {bool lock,enabled,prepared,engine_ready,shutting_down,route_admitted;int error;unsigned pending_withdrawals;struct rtl_fe_bridge *bridge;};
static int scnprintf(char *out,size_t size,const char *format,...){
 va_list args;va_start(args,format);int count=vsnprintf(out,size,format,args);va_end(args);
 return count<0?0:((size_t)count<size?count:(int)(size?size-1:0));
}
'''

BACKEND = r'''
static struct rtl_fe fe;
static struct rtl_fe_bridge sw;
static struct net_device ports[5],master,pon,foreign,internal;
static unsigned int rules[RTL_L2_FDB_ENTRIES][4];
static struct fe_switch_published published[RTL_L2_FDB_ENTRIES];
struct bridge_row {u8 address[6];unsigned int port;bool local;u64 cookie;};
static struct bridge_row bridge_rows[RTL_L2_FDB_ENTRIES+4];
static unsigned int bridge_count,publish_calls,publish_successes,unpublish_calls,rules_reuses;
static unsigned int fail_publish_at,change_before_publish_at,change_after_publish_at,publish_change;
static u64 next_cookie;
static unsigned long configured_flags[5];
static u8 configured_states[5];
static unsigned int closures,restores,unoffloads,snapshots,syncs,route_flushes,offloads,prepares,claims,appends,arms,scheduled,last_delay,queued,cases;
static unsigned int restore_fail_at,offload_fail_at,append_fail_at,replay_error_at,change_in_sync,change_in_replay;
static unsigned int online_ports,static_port,offline_port,invalidates,extra_replay_rows,port_policies;
static struct rtl_l2_fdb_entry installed[RTL_L2_FDB_ENTRIES*4];
static int hw_error,domain_error,flush_error,port_policy_error;
static int mcast_error,mcast_hw_error;
static unsigned int mcast_prepares,mcast_applies,mcast_arms,mcast_revokes;
static bool mcast_ready,mcast_live;
static int mdb_error,mdb_hw_error;
static unsigned int mdb_prepares,mdb_steers;
static bool rtnl_held,arm_failure,epoch_during_append,additional_policy;
static bool cpu_dynamic;
static bool cpu_after_preflight;
static int cpu_preflight_error,hardware_preflight_error;
static unsigned int cpu_preflights,hardware_preflights;
static bool watch_completed;
static struct fe_switch_completed previous_completed;
static unsigned int rcu_depth;
static void rcu_read_lock(void){rcu_depth++;}
static void rcu_read_unlock(void){assert(rcu_depth);rcu_depth--;}
static struct net_device *br_switchdev_fdb_find_port(struct net_device *br,const u8 *address,unsigned short vid){
 assert(rcu_depth && rtnl_held && br==&master && !vid);
 return cpu_dynamic && address[5]==13?&ports[0]:NULL;
}
static int br_rtl9617c_fdb_cpu_count(const struct net_device *br,u16 vid,unsigned int *count){
 assert(fe.lock && rtnl_held && br==&master && !vid && count);
 cpu_preflights++;*count=cpu_dynamic;
 if(cpu_after_preflight)cpu_dynamic=true;
 return cpu_preflight_error;
}
static enum fe_switch_reason policy_reason;
static clock_t ageing;
static void mutex_lock(bool *lock){assert(!*lock);*lock=true;}
static void mutex_unlock(bool *lock){
 assert(*lock);if(watch_completed && sw.worker_busy)assert(!memcmp(&sw.completed,&previous_completed,sizeof(previous_completed)));
 *lock=false;
}
static void rtnl_lock(void){assert(!rtnl_held);rtnl_held=true;}
static void rtnl_unlock(void){assert(rtnl_held);rtnl_held=false;}
static void fe_switch_hw_gate(struct rtl_fe *owner,struct rtl_fe_switch_hw *hw){
 assert(owner==&fe && hw==&sw.hw && !mcast_live);hw->open=false;owner->route_admitted=false;closures++;
}
static bool fe_switch_hw_arm(struct rtl_fe *owner,struct rtl_fe_switch_hw *hw,u32 native,u32 route,bool route_allowed,bool native_route_allowed){
 assert(owner==&fe && hw==&sw.hw && fe.lock && rtnl_held && !hw->open);
 assert(!(native&route) && !((native|route)&~31U));
 assert(!native || (hw->owned && hw->port_policy_ready && sw.domain_owned && sw.offloaded==native));
 assert(route_allowed==sw.route_policy_allowed && (route_allowed || !route));
 assert(native_route_allowed==sw.native_route_policy_allowed);
 assert(!native || sw.local_target==(native_route_allowed && owner->enabled && owner->prepared?25U:16U));
 assert(!native || !mcast_ready || mcast_live);
 hw->open=!arm_failure;owner->route_admitted=!arm_failure && owner->enabled && route_allowed && !owner->pending_withdrawals;return !arm_failure;
}
static void fe_switch_gate(void *private);
static bool fe_switch_arm(void *private);
static int fe_switch_atomic_event(struct notifier_block *,unsigned long,void *);
static bool switchdev_fdb_is_dynamically_learned(const struct switchdev_notifier_fdb_info *info){return !info->added_by_user && !info->is_local;}
static bool is_valid_ether_addr(const u8 *mac){unsigned int any=0;for(unsigned int i=0;i<6;i++)any|=mac[i];return any && !(mac[0]&1);}
static void ether_addr_copy(u8 *dst,const u8 *src){memcpy(dst,src,6);}
static bool ether_addr_equal(const u8 *a,const u8 *b){return !memcmp(a,b,6);}
static bool fe_switch_vlan_replay_member(struct rtl_fe_bridge *owner,
 const struct switchdev_notifier_fdb_info *info,int port){
 (void)info;(void)port;assert(!owner->vlan_domain);return false;
}
static void fe_mcast_revoke(struct rtl_fe *owner){assert(owner==&fe);mcast_revokes++;mcast_live=false;}
static void fe_mcast_arm(struct rtl_fe *owner,u64 generation){
 assert(owner==&fe && generation==sw.guard.generation && !sw.active && !sw.hw.open);
 if(mcast_ready){mcast_arms++;mcast_live=true;}
}
static int fe_mcast_prepare_bum(struct rtl_fe *owner,struct rtl9617c_switch_guard *guard,
 u64 generation,struct net_device *bridge,struct net_device **devs,
 const unsigned long *flags,unsigned int native,struct rtl_mcast_groups *groups){
 assert(owner==&fe && guard==&sw.guard && generation==guard->generation && bridge==&master);
 assert(devs==sw.ports && flags && native && groups && fe.lock && rtnl_held);
 assert(sw.domain_owned && !sw.hw.open && !sw.active);mcast_prepares++;
 memset(groups,0,sizeof(*groups));
 if(mcast_error)return mcast_error;
 groups->enabled[0]=groups->enabled[1]=3;mcast_ready=true;return 0;
}
static int fe_switch_hw_mcast_groups(struct rtl_fe *owner,struct rtl_fe_switch_hw *hw,
 const struct rtl_mcast_groups *groups){
 assert(owner==&fe && hw==&sw.hw && groups->enabled[0]==3);
 assert(mcast_ready && fe.lock && !hw->open && sw.domain_owned);mcast_applies++;
 return mcast_hw_error;
}
static int fe_mdb_prepare(struct rtl_fe *owner,struct rtl9617c_switch_guard *guard,
 u64 generation,struct net_device *bridge,struct net_device **devs,const unsigned long *flags,
 unsigned int forwarding,unsigned int *steer){
 assert(owner==&fe && guard==&sw.guard && generation==guard->generation && bridge==&master);
 assert(devs==sw.ports && flags && forwarding && steer && fe.lock && rtnl_held);
 assert(sw.domain_owned && !sw.hw.open && !sw.active && sw.native_route_policy_allowed && fe.enabled && fe.prepared);
 mdb_prepares++;*steer=mdb_error?0:forwarding;return mdb_error;
}
static int fe_switch_hw_mdb_steer(struct rtl_fe *owner,struct rtl_fe_switch_hw *hw,unsigned int ports){
 assert(owner==&fe && hw==&sw.hw && !sw.replay_ports && ports==hw->ports);
 assert(sw.native_route_policy_allowed && fe.enabled && fe.prepared && !hw->open);mdb_steers++;return mdb_hw_error;
}
static void rtl9617c_switch_guard_invalidate(struct rtl9617c_switch_guard *guard){
 assert(guard==&sw.guard);invalidates++;guard->generation++;guard->armed=false;fe_switch_gate(&sw);
}
static void rtl9617c_switch_guard_quiesce(struct rtl9617c_switch_guard *guard){assert(guard==&sw.guard);guard->armed=false;fe_switch_gate(&sw);}
static u64 rtl9617c_switch_guard_generation(struct rtl9617c_switch_guard *guard){assert(guard==&sw.guard);return guard->generation;}
static bool rtl9617c_switch_guard_blocked(struct rtl9617c_switch_guard *guard){return guard->blocked;}
static bool rtl9617c_switch_guard_try_arm(struct rtl9617c_switch_guard *guard,u64 generation){
 arms++;assert(guard==&sw.guard && fe.lock && rtnl_held);
 if(guard->blocked || generation!=guard->generation)return false;
 bool ret=fe_switch_arm(&sw);guard->armed=ret;if(!ret)fe_switch_gate(&sw);return ret;
}
static int fe_switch_restore_locked(struct rtl_fe_bridge *owner){
 assert(owner==&sw && fe.lock && rtnl_held && !sw.hw.open && !sw.active && !sw.flow_allowed);
 restores++;if(restores==restore_fail_at){sw.error=-ETIMEDOUT;sw.reason=FE_SWITCH_IO_ERROR;return -ETIMEDOUT;}
 /* The real domain_flush reuses rules[] to collect arbitrary silicon
  * keys. Its independent tests cover the hardware transport; poison this
  * scratch buffer so no later publication/withdrawal can rely on it. */
 if(sw.domain_owned){memset(rules,0xa5,sizeof(rules));sw.rule_count=0;rules_reuses++;}
 sw.hw.port_policy_ready=false;sw.hw.learning_mask=sw.hw.isolated_mask=sw.hw.ports=0;
 sw.hw.owned=sw.domain_owned=false;return 0;
}
static bool netif_is_bridge_port(struct net_device *dev){
 for(unsigned int i=0;i<5;i++)if(dev==&ports[i])return true;
 return false;
}
static void switchdev_bridge_port_unoffload(struct net_device *dev,struct rtl_fe_bridge *owner,
 struct notifier_block *atomic,struct notifier_block *blocking){
 assert(owner==&sw && !fe.lock && rtnl_held && netif_is_bridge_port(dev));
 assert(atomic==&sw.atomic_nb && blocking==&sw.blocking_nb);unoffloads++;
}
static int fe_switch_feedback(struct rtl_fe_bridge *owner,const struct fe_switch_learned *entry,bool adding,u64 generation){
 assert(owner==&sw && entry && !adding && !generation && !fe.lock && rtnl_held);
 /* Full dynamic feedback is independently executed in the FDB scan test. */
 return 0;
}
static unsigned int expected_native_ports(void){
 unsigned int mask=0;
 for(unsigned int i=0;i<5;i++)if((online_ports&BIT(i)) && configured_states[i]==BR_STATE_FORWARDING)mask|=BIT(i);
 return mask;
}
static enum fe_switch_reason fe_switch_plan_validate(const struct fe_switch_plan *plan);
static enum fe_switch_reason fe_switch_snapshot(struct rtl_fe_bridge *owner,struct fe_switch_plan *plan){
 assert(owner==&sw && fe.lock && rtnl_held && !sw.hw.open);snapshots++;
 memset(plan,0,sizeof(*plan));plan->ports=online_ports;sw.master=&master;sw.route_mask=fe.enabled?31:0;
 for(unsigned int i=0;i<5;i++){
  sw.ports[i]=&ports[i];plan->flags[i]=configured_flags[i];plan->state[i]=configured_states[i];
 }
 plan->multi_bridge=policy_reason==FE_SWITCH_MULTI_BRIDGE;
 plan->mixed=policy_reason==FE_SWITCH_MIXED_PORTS;
 plan->vlan_filtering=policy_reason==FE_SWITCH_VLAN_UNSUPPORTED;
 plan->private_policy=policy_reason==FE_SWITCH_PRIVATE_POLICY;
 plan->promisc=policy_reason==FE_SWITCH_PROMISC;
 plan->software_policy=additional_policy || policy_reason==FE_SWITCH_GUARDED;
 if(policy_reason==FE_SWITCH_PORT_POLICY)plan->flags[0]|=BIT(31);
 if(policy_reason==FE_SWITCH_NO_BRIDGE)plan->ports=0;
 return fe_switch_plan_validate(plan);
}
static enum fe_switch_reason fe_switch_vlan_snapshot(struct rtl_fe_bridge *owner,
 struct fe_switch_plan *plan,enum fe_switch_reason reason){
 assert(owner==&sw && plan);sw.vlan_domain=false;return reason;
}
static void change_state(unsigned int kind){
 if(kind==1)sw.guard.generation++;
 if(kind==2)fe.engine_ready=false;
 if(kind==3)sw.stopping=true;
 if(kind==4)fe.shutting_down=true;
}
static struct bridge_row *bridge_row_find(const u8 *address,bool create){
 for(unsigned int i=0;i<bridge_count;i++)if(!memcmp(bridge_rows[i].address,address,6))return &bridge_rows[i];
 if(!create)return NULL;
 assert(bridge_count<ARRAY_SIZE(bridge_rows));
 struct bridge_row *row=&bridge_rows[bridge_count++];memcpy(row->address,address,6);return row;
}
static unsigned int bridge_owned_count(void){
 unsigned int count=0;for(unsigned int i=0;i<bridge_count;i++)count+=!!bridge_rows[i].cookie;return count;
}
static void publication_change(unsigned int kind){
 assert(!fe.lock && rtnl_held);mutex_lock(&fe.lock);
 if(kind==1)rtl9617c_switch_guard_invalidate(&sw.guard);
 if(kind==2){sw.guard.blocked=true;fe_switch_gate(&sw);}
 if(kind==3){
  /* A sysfs FE disable may acquire the FE mutex without taking RTNL.
   * Gate, drain and restore it while the bridge publication is unlocked. */
  fe.enabled=fe.prepared=false;fe_switch_gate(&sw);
  assert(!fe_switch_restore_locked(&sw));
 }
 mutex_unlock(&fe.lock);
}
static int br_rtl9617c_fdb_offload(const struct net_device *brdev,const struct net_device *dev,
 const u8 *address,unsigned short vid,bool local,struct rtl9617c_switch_guard *guard,u64 generation,u64 *cookie){
 assert(rtnl_held && !fe.lock && brdev==&master && !vid && guard==&sw.guard && cookie && !*cookie);
 publish_calls++;
 if(publish_calls==change_before_publish_at)publication_change(publish_change);
 if(guard->blocked || generation!=guard->generation)return -EAGAIN;
 if(publish_calls==fail_publish_at)return -ENOMEM;
 struct bridge_row *row=bridge_row_find(address,false);
 assert(row && row->local==local && (local?!dev:dev==&ports[row->port]));
 assert(!row->cookie);row->cookie=*cookie=++next_cookie;publish_successes++;
 if(publish_calls==change_after_publish_at)publication_change(publish_change);
 return 0;
}
static bool br_rtl9617c_fdb_unoffload(const struct net_device *brdev,const u8 *address,
 unsigned short vid,struct rtl9617c_switch_guard *guard,u64 cookie){
 assert(rtnl_held && !fe.lock && brdev==&master && !vid && guard==&sw.guard && cookie);
 struct bridge_row *row=bridge_row_find(address,false);
 assert(row && row->cookie==cookie);row->cookie=0;unpublish_calls++;return true;
}
static void synchronize_net(void){assert(rtnl_held && !fe.lock && !sw.hw.open);syncs++;change_state(change_in_sync);}
static int fe_switch_flush_routes_locked(struct rtl_fe *owner){
 assert(owner==&fe && fe.lock && rtnl_held && !sw.hw.open);route_flushes++;return flush_error;
}
static int br_rtl9617c_fdb_hold_time(struct net_device *dev,unsigned long *ticks){
 assert(dev==&master && ticks);if(ageing<0)return -EINVAL;*ticks=ageing;return 0;
}
static bool br_multicast_enabled(struct net_device *dev){assert(dev==&master);return true;}
static int switchdev_bridge_port_offload(struct net_device *dev,struct net_device *brport,void *context,
 struct notifier_block *atomic,struct notifier_block *blocking,bool tx_fwd_offload,void *extack){
 assert(!fe.lock && rtnl_held && !sw.hw.open && sw.replaying && context==&sw && dev==brport);
 assert(atomic==&sw.atomic_nb && blocking==&sw.blocking_nb && !tx_fwd_offload && !extack);
 offloads++;if(offloads==offload_fail_at)return -ENOMEM;
 if(offloads==replay_error_at)sw.replay_error=-ENOSPC;
 /* Linux br_switchdev_fdb_replay() replays the WHOLE bridge for each
  * offloaded port. Invoke the actual atomic/replay functions with those
  * records while native_mask is still deliberately unpublished. */
 const u8 addresses[][6]={{2,0,0,0,0,10},{2,0,0,0,0,11},
                         {2,0,0,0,0,12},{2,0,0,0,0,13}};
 for(unsigned int i=0;i<4;i++){
  struct switchdev_notifier_fdb_info item={.info={.dev=i==0?&master:
    i==1?&ports[static_port]:i==2?&ports[offline_port]:&ports[0],.ctx=context},
   .addr=addresses[i],.is_local=i==0,.added_by_user=i==1 || i==2};
  if(i<3){struct bridge_row *row=bridge_row_find(addresses[i],true);row->local=i==0;row->port=i==1?static_port:offline_port;}
  int ret=atomic->notifier_call(atomic,SWITCHDEV_FDB_ADD_TO_DEVICE,&item);
  if(ret)return ret;
 }
 for(unsigned int i=0;i<extra_replay_rows;i++){
  u8 address[6]={2,1,0,0,(1000+i)>>8,1000+i};
  struct bridge_row *row=bridge_row_find(address,true);row->port=static_port;
  struct switchdev_notifier_fdb_info item={.info={.dev=&ports[static_port],.ctx=context},.addr=address,.added_by_user=true};
  int ret=atomic->notifier_call(atomic,SWITCHDEV_FDB_ADD_TO_DEVICE,&item);
  if(ret)return ret;
 }
 assert(!sw.native_mask && !sw.active && sw.replay_ports==expected_native_ports());
 change_state(change_in_replay);return 0;
}
static int fe_switch_hw_prepare(struct rtl_fe *owner,struct rtl_fe_switch_hw *hw,u32 native,unsigned long seconds,bool snooping,bool route_allowed){
 assert(owner==&fe && hw==&sw.hw && fe.lock && rtnl_held && !hw->open && !sw.active);
 assert(fe.engine_ready && native==expected_native_ports() && seconds==(unsigned long)(ageing/HZ) && snooping);prepares++;
 assert(route_allowed==sw.native_route_policy_allowed);
 hw->owned=true;hw->ports=native;return hw_error;
}
static int fe_switch_hw_preflight(struct rtl_fe *owner,struct rtl_fe_switch_hw *hw,unsigned int native){
 assert(owner==&fe && hw==&sw.hw && native==expected_native_ports() && fe.lock && rtnl_held);
 hardware_preflights++;hw->observed.vlan_mode=hardware_preflight_error?2:3;
 hw->reason=hardware_preflight_error?1:0;return hardware_preflight_error;
}
static const char *fe_switch_hw_reason_name(const struct rtl_fe_switch_hw *hw){return hw->reason?"requires-existing-svl":"ok";}
static int fe_switch_hw_port_policy(struct rtl_fe *owner,struct rtl_fe_switch_hw *hw,u32 learning,u32 isolated){
 assert(owner==&fe && hw==&sw.hw && fe.lock && rtnl_held && hw->owned && !hw->open && !sw.active);
 unsigned int expected_learning=0,expected_isolated=0;
 for(unsigned int i=0;i<5;i++)if(hw->ports&BIT(i)){
  if(ageing && (configured_flags[i]&BR_LEARNING))expected_learning|=BIT(i);
  if(configured_flags[i]&BR_ISOLATED)expected_isolated|=BIT(i);
 }
 assert(learning==expected_learning && isolated==expected_isolated);port_policies++;
 if(port_policy_error)return port_policy_error;
 hw->learning_mask=learning;hw->isolated_mask=isolated;hw->port_policy_ready=true;return 0;
}
static int fe_switch_domain_claim(struct rtl_fe_bridge *owner){
 assert(owner==&sw && fe.lock && rtnl_held && sw.hw.owned && !sw.hw.open);claims++;
 if(domain_error)return domain_error;
 sw.domain_owned=true;return 0;
}
static int fe_switch_fdb_write(struct rtl_fe_bridge *owner,enum rtl_l2_fdb_command command,const unsigned int *words){
 assert(owner==&sw && command==RTL_L2_FDB_APPEND && words && fe.lock && rtnl_held && sw.domain_owned && !sw.hw.open);
 assert(!sw.native_mask && !sw.replay_ports && !sw.replaying);
 assert(appends<ARRAY_SIZE(installed));rtl_l2_fdb_decode(words,&installed[appends]);
 appends++;if(epoch_during_append)sw.guard.generation++;
 return appends==append_fail_at?-ENOSPC:0;
}
static void mod_delayed_work(unsigned int queue,struct delayed_work *work,unsigned int delay){
 assert(queue==system_long_wq && work==&sw.scan_work && fe.lock && rtnl_held);
 scheduled++;last_delay=delay;
}
static void queue_work(unsigned int queue,struct work_struct *work){
 assert(queue==system_long_wq && work==&sw.work && fe.lock);queued++;
}
static void setup(void){
 fe=(struct rtl_fe){.enabled=true,.prepared=true,.engine_ready=true};memset(&sw,0,sizeof(sw));
 sw.fe=&fe;fe.bridge=&sw;sw.guard.owner=&sw;sw.guard.generation=1;sw.guard.registered=true;sw.rules=rules;sw.published=published;sw.requested=true;
 sw.atomic_nb.notifier_call=fe_switch_atomic_event;
 online_ports=3;static_port=1;offline_port=2;invalidates=0;memset(installed,0,sizeof(installed));
 memset(rules,0,sizeof(rules));memset(published,0,sizeof(published));memset(bridge_rows,0,sizeof(bridge_rows));
 for(unsigned int i=0;i<5;i++){ports[i].index=i;configured_flags[i]=BR_LEARNING;configured_states[i]=BR_STATE_FORWARDING;sw.owned_devices[i]=&ports[i];}
 sw.owned_devices[32]=&pon;sw.owned_devices[16]=&internal;
 bridge_count=publish_calls=publish_successes=unpublish_calls=rules_reuses=port_policies=0;
 fail_publish_at=change_before_publish_at=change_after_publish_at=publish_change=extra_replay_rows=0;next_cookie=0;
 policy_reason=FE_SWITCH_OK;ageing=300*HZ;
 closures=restores=unoffloads=snapshots=syncs=route_flushes=offloads=prepares=claims=appends=arms=scheduled=last_delay=queued=0;
 restore_fail_at=offload_fail_at=append_fail_at=replay_error_at=change_in_sync=change_in_replay=0;
 hw_error=domain_error=flush_error=port_policy_error=0;rtnl_held=arm_failure=epoch_during_append=additional_policy=false;
 cpu_dynamic=cpu_after_preflight=false;rcu_depth=0;
 cpu_preflight_error=hardware_preflight_error=0;cpu_preflights=hardware_preflights=0;
 watch_completed=false;memset(&previous_completed,0,sizeof(previous_completed));
 mcast_error=-EOPNOTSUPP;mcast_hw_error=0;mcast_prepares=mcast_applies=mcast_arms=mcast_revokes=0;
 mcast_ready=mcast_live=false;
 mdb_error=-EOPNOTSUPP;mdb_hw_error=0;mdb_prepares=mdb_steers=0;
}
static void run(void){
 fe_switch_work(&sw.work);assert(!fe.lock && !rtnl_held && !sw.replaying && !sw.replay_ports);
 if(!sw.active)assert(!sw.published_count && !bridge_owned_count());
 cases++;
}
'''

TEST = r'''
static void success_and_policy(void){
 setup();run();assert(sw.active && sw.hw.open && sw.flow_allowed && fe.route_admitted);
 assert(sw.native_mask==3 && sw.route_mask==28 && sw.armed_route_mask==28 && sw.offloaded==3);
 assert(prepares==1 && claims==1 && appends==3 && route_flushes==1 && sw.rebuilds==1 && last_delay==HZ && sw.local_target==25);
 assert(port_policies==1 && sw.published_count==2 && publish_successes==2 && bridge_owned_count()==2);
 assert(sw.route_generation_valid && sw.route_generation==1);
 run();assert(sw.active && sw.rebuilds==1 && sw.worker_skips==1 && route_flushes==1);
 /* A queued scan can belong to the same policy epoch yet predate the
  * worker's complete hardware teardown/rebuild. It must start over. */
 sw.scan_running=sw.scan_complete=sw.scan_removed=true;
 sw.scan_start=17;sw.scan_count=9;sw.scan_cursor=5;sw.scan_old=3;sw.scan_generation=sw.guard.generation;
 sw.force_reconcile=true; /* Explicit retry, not a duplicate deferred event. */
 run();assert(sw.active && !sw.scan_running && !sw.scan_complete && !sw.scan_removed &&
  !sw.scan_start && !sw.scan_count && !sw.scan_cursor && !sw.scan_old && route_flushes==1);
 sw.guard.generation++;run();assert(route_flushes==2 && sw.route_generation==2);
 setup();fe.enabled=fe.prepared=false;run();
 assert(sw.active && sw.hw.open && !sw.flow_allowed && !fe.route_admitted && !sw.armed_route_mask && sw.local_target==16);
 setup();sw.requested=false;run();
 assert(!sw.active && sw.hw.open && sw.flow_allowed && sw.reason==FE_SWITCH_REQUEST_OFF);
 assert(!prepares && !claims && !appends && !offloads && !scheduled && !sw.offloaded && sw.armed_route_mask==31);
 setup();policy_reason=FE_SWITCH_NO_BRIDGE;run();assert(sw.hw.open && !sw.active && !prepares && sw.armed_route_mask==31);
 const enum fe_switch_reason vetoes[]={FE_SWITCH_PRIVATE_POLICY,FE_SWITCH_PROMISC,FE_SWITCH_GUARDED};
 for(unsigned int i=0;i<sizeof(vetoes)/sizeof(vetoes[0]);i++){
  setup();policy_reason=vetoes[i];run();
  assert(!sw.hw.open && !sw.active && !sw.flow_allowed && !prepares && !route_flushes && !arms && sw.route_mask==0);
 }
 setup();policy_reason=FE_SWITCH_PORT_POLICY;run();
 assert(sw.hw.open && !sw.active && sw.flow_allowed && !prepares && sw.armed_route_mask==30);
 const enum fe_switch_reason capabilities[]={FE_SWITCH_MULTI_BRIDGE,FE_SWITCH_MIXED_PORTS,FE_SWITCH_VLAN_UNSUPPORTED};
 for(unsigned int i=0;i<sizeof(capabilities)/sizeof(capabilities[0]);i++)for(unsigned int requested=0;requested<2;requested++){
  setup();policy_reason=capabilities[i];sw.requested=requested;run();
  assert(sw.hw.open && sw.flow_allowed && !sw.active && !prepares && !offloads && sw.armed_route_mask==31);
  setup();policy_reason=capabilities[i];sw.requested=requested;additional_policy=true;run();
  assert(!sw.hw.open && !sw.flow_allowed && !arms && !route_flushes && !sw.route_mask);
  for(unsigned int restriction=0;restriction<3;restriction++){
   setup();policy_reason=capabilities[i];sw.requested=requested;
   if(restriction==0)configured_flags[0]|=BR_ISOLATED;
   if(restriction==1)configured_flags[0]&=~BR_LEARNING;
   if(restriction==2)configured_states[0]=BR_STATE_BLOCKING;
   run();assert(sw.hw.open && !sw.active && sw.flow_allowed && arms==1 && sw.route_mask==30);
   assert(sw.armed_route_eligible_mask==30 && !fe_switch_flow_ports_allowed(&fe,&ports[0],&pon));
  }
 }
 setup();sw.guard.blocked=true;run();assert(!sw.hw.open && !syncs && !route_flushes && !prepares && !arms && sw.reason==FE_SWITCH_GUARDED);
 for(unsigned int mode=0;mode<3;mode++){
  setup();if(mode==0)sw.stopping=true;if(mode==1)fe.shutting_down=true;if(mode==2)fe.engine_ready=false;
  run();assert(!sw.hw.open && !prepares && !arms && !route_flushes);
 }
}
static void replay_to_publication(void){
 /* First activation must install both the local row and the allowed
  * sticky/static destination; clearing native_mask must not discard it. */
 setup();run();assert(appends==3 && sw.native_mask==3 && !invalidates);
 assert(installed[0].mac[5]==10 && installed[0].destination==25);
 assert(installed[1].mac[5]==11 && installed[1].destination==1);
 assert(installed[2].mac[5]==12 && installed[2].destination==16);
 assert(!bridge_rows[2].cookie && sw.rule_count==3 && sw.published_count==2);
 for(unsigned int i=0;i<3;i++)assert(installed[i].valid && installed[i].is_static);
 /* New snapshot moves the static output and excludes the old/down port;
  * switchdev still replays the down port's entry for every online port. */
 online_ports=5;static_port=2;offline_port=1;sw.guard.generation++;run();
 assert(appends==6 && sw.native_mask==5 && sw.offloaded==5 && !invalidates);
 assert(installed[3].mac[5]==10 && installed[3].destination==25);
 assert(installed[4].mac[5]==11 && installed[4].destination==2);
 assert(installed[5].mac[5]==12 && installed[5].destination==16 && !bridge_rows[2].cookie);
 for(unsigned int i=0;i<appends;i++)assert(installed[i].mac[5]!=13);
 /* A later failed rebuild cannot publish the pending mask or retain an
  * earlier active generation merely because its first local row worked. */
 append_fail_at=appends+2;sw.guard.generation++;run();
 assert(!sw.active && !sw.native_mask && !sw.hw.open && !sw.offloaded &&
        sw.reason==FE_SWITCH_FDB_CAPACITY && !sw.replay_ports);
}
static void cpu_dynamic_native_fallback(void){
 setup();cpu_dynamic=true;run();
 assert(!sw.active && sw.reason==FE_SWITCH_SOFTWARE_FDB && sw.hw.open && sw.flow_allowed);
 assert(!prepares && !claims && !appends && !offloads && !sw.offloaded && !invalidates && !sw.pending_count);
 assert(sw.completed.valid && sw.completed.cpu_fdb_count==1 && sw.completed.preflight_done &&
  sw.completed.reason==FE_SWITCH_SOFTWARE_FDB && sw.completed.error==-EOPNOTSUPP);
 assert(sw.armed_route_mask==31 && fe_switch_flow_ports_allowed(&fe,&ports[0],&pon));
 assert(!fe_switch_needs_recovery(&fe));
 unsigned int flushes=route_flushes,closed=closures,replayed=offloads,serial=sw.completed.serial;run();
 assert(route_flushes==flushes && !sw.active && !invalidates && !prepares);
 assert(closures==closed && offloads==replayed && sw.completed.serial==serial && sw.worker_skips==1);
 /* CPU arrival after preflight must still fail in real replay, never
  * turn the advisory count into a cached ownership permission. */
 setup();cpu_after_preflight=true;run();
 assert(!sw.active && sw.reason==FE_SWITCH_SOFTWARE_FDB && sw.flow_allowed && offloads==1 && !prepares);
 /* Linux expiry/deletion removes the authoritative row under the normal
  * core epoch fence; the surviving hardware-owned subset can re-enable. */
 cpu_dynamic=cpu_after_preflight=false;sw.guard.generation++;run();
 assert(sw.active && sw.native_mask==3 && prepares==1 && claims==1 && !sw.error);
}
static void preflight_completed_and_noop(void){
 setup();cpu_dynamic=true;hardware_preflight_error=-EOPNOTSUPP;run();
 assert(!offloads && !prepares && !claims && hardware_preflights==1 && cpu_preflights==1);
 assert(sw.reason==FE_SWITCH_SOFTWARE_FDB && sw.flow_allowed && sw.completed.hw_reason==1 &&
  sw.completed.cpu_fdb_count==1 && sw.completed.preflight_error==-EOPNOTSUPP && sw.completed.observed.vlan_mode==2);
 char evidence[4096];unsigned int hw_reads=hardware_preflights;
 sw.worker_busy=true;sw.reason=FE_SWITCH_OK;sw.error=0;sw.hw.observed.vlan_mode=3;
 assert(fe_bridge_evidence(&sw,evidence,sizeof(evidence))>0);
 assert(strstr(evidence,"l2_completed_reason=16 ") && strstr(evidence,"l2_pending_reason=0 ") &&
  strstr(evidence,"l2_worker_busy=1 ") && strstr(evidence,"l2_cpu_fdb_count=1 ") &&
  strstr(evidence,"l2_hw_vlan_mode=0x2 "));
 assert(hardware_preflights==hw_reads && sw.completed.serial==1 && sw.completed.observed.vlan_mode==2);
 sw.reason=sw.completed.reason;sw.error=sw.completed.error;sw.worker_busy=false;
 previous_completed=sw.completed;watch_completed=true;sw.force_reconcile=true;
 hardware_preflight_error=0;run();watch_completed=false;
 assert(sw.completed.serial==2 && sw.completed.hw_reason==0 && sw.completed.cpu_fdb_count==1 &&
  sw.completed.observed.vlan_mode==3);
 assert(!sw.worker_busy && sw.completed.armed && sw.completed.route_eligible_ports==31);
 policy_reason=FE_SWITCH_NO_BRIDGE;sw.guard.generation++;run();
 assert(sw.completed.valid && !sw.completed.preflight_done && !sw.completed.observed.vlan_mode);
 /* Same-epoch duplicate work preserves live admission and a partial scan.
  * Only real state changes or explicit requests can make the shortcut miss. */
 setup();run();sw.scan_running=true;sw.scan_cursor=17;
 unsigned int closed=closures,flushed=route_flushes;run();
 assert(closures==closed && route_flushes==flushed && sw.scan_running && sw.scan_cursor==17 && sw.worker_skips==1);
 for(unsigned int reason=0;reason<11;reason++){
  setup();cpu_dynamic=true;run();unsigned int serial=sw.completed.serial;
  switch(reason){
   case 0:sw.force_reconcile=true;break;
   case 1:sw.guard.generation++;break;
   case 2:sw.guard.armed=false;break;
   case 3:sw.guard.blocked=true;break;
   case 4:fe.enabled=false;break;
   case 5:fe.prepared=false;break;
   case 6:fe.error=-EIO;break;
   case 7:fe.pending_withdrawals=1;break;
   case 8:sw.hw.journal.quarantined=true;break;
   case 9:sw.hw.journal.restoring=true;break;
   case 10:sw.requested=false;break;
  }
  run();assert(sw.completed.serial==serial+1 && !sw.worker_skips);
 }
 setup();hardware_preflight_error=-EOPNOTSUPP;run();
 assert(sw.reason==FE_SWITCH_HW_UNSUPPORTED && sw.flow_allowed && !offloads && !prepares);
 setup();cpu_dynamic=true;hardware_preflight_error=-EIO;run();
 assert(sw.reason==FE_SWITCH_IO_ERROR && sw.error==-EIO && !sw.flow_allowed && !offloads);
 setup();cpu_preflight_error=-ENODEV;run();
 assert(sw.error==-ENODEV && !sw.flow_allowed && !offloads && !hardware_preflights);
 /* Hash/cache withdrawal gates routes independently of the bridge epoch.
  * A snapshot completed while cleanup is pending may still be armed for
  * native switching; final cleanup's explicit reconcile must not noop. */
 for(unsigned int intermediate=0;intermediate<2;intermediate++){
  setup();cpu_dynamic=true;run();u64 epoch=sw.guard.generation;
  fe.pending_withdrawals=1;fe.route_admitted=false;
  if(intermediate){run();assert(sw.guard.armed && !sw.flow_allowed);}
  unsigned int serial=sw.completed.serial,closed=closures;
  mutex_lock(&fe.lock);fe.pending_withdrawals=0;fe_switch_reconcile_locked(&fe);mutex_unlock(&fe.lock);
  assert(queued==1 && sw.force_reconcile && !fe.route_admitted);run();
  assert(sw.guard.generation==epoch && sw.completed.serial==serial+1 && closures>closed &&
   fe.route_admitted && sw.flow_allowed && !sw.force_reconcile && !sw.worker_skips);
 }
}
static void released_lock_changes(void){
 for(unsigned int place=0;place<2;place++)for(unsigned int change=1;change<=4;change++){
  setup();if(place)change_in_replay=change;else change_in_sync=change;
  run();assert(!sw.hw.open && !sw.active && !sw.flow_allowed && !prepares && !claims && !appends && !sw.offloaded);
 }
}
static void transaction_failures(void){
 setup();sw.hw.owned=sw.domain_owned=true;restore_fail_at=1;run();
 assert(sw.hw.owned && sw.domain_owned && !sw.hw.open && !snapshots && !arms && sw.error==-ETIMEDOUT);
 setup();flush_error=-ETIMEDOUT;run();assert(!sw.hw.open && !prepares && !arms && sw.error==-ETIMEDOUT);
 const clock_t invalid_age[]={-1,1,HZ-1,((clock_t)1<<19)*HZ};
 for(unsigned int i=0;i<ARRAY_SIZE(invalid_age);i++){
  setup();ageing=invalid_age[i];run();
  assert(sw.hw.open && sw.flow_allowed && !sw.active && !prepares && !claims && !offloads &&
   arms==1 && sw.armed_route_mask==31 && sw.reason==FE_SWITCH_AGING_UNSUPPORTED && !sw.error);
  /* Timer capability fallback must never mask real bridge/netfilter policy. */
  setup();ageing=invalid_age[i];additional_policy=true;run();
  assert(!sw.hw.open && !sw.flow_allowed && !arms && !sw.route_mask && !offloads);
  setup();ageing=invalid_age[i];sw.guard.blocked=true;run();
  assert(!sw.hw.open && !sw.flow_allowed && !arms && !sw.route_mask && !offloads);
  setup();ageing=invalid_age[i];arm_failure=true;run();
  assert(!sw.hw.open && !sw.flow_allowed && !sw.active && !offloads && sw.error==-EAGAIN &&
   sw.reason==FE_SWITCH_GUARDED && fe_switch_needs_recovery(&fe));
 }
 const clock_t valid_age[]={0,HZ,((clock_t)((1U<<19)-1))*HZ};
 for(unsigned int i=0;i<ARRAY_SIZE(valid_age);i++){
  setup();ageing=valid_age[i];run();assert(sw.hw.open && sw.active && prepares==1 && sw.reason==FE_SWITCH_OK);
 }
 for(unsigned int port=1;port<=2;port++){
  setup();offload_fail_at=port;run();assert(!sw.hw.open && !prepares && !sw.offloaded && sw.error==-ENOMEM);
  setup();replay_error_at=port;run();assert(!sw.hw.open && !prepares && !sw.offloaded && sw.error==-ENOSPC);
 }
 setup();hw_error=-ETIMEDOUT;run();assert(!sw.hw.open && !sw.hw.owned && !sw.domain_owned && !sw.offloaded && sw.error==-ETIMEDOUT);
 setup();hw_error=-ETIMEDOUT;restore_fail_at=2;run();
 assert(!sw.hw.open && sw.hw.owned && !sw.offloaded && sw.error==-ETIMEDOUT && sw.reason==FE_SWITCH_IO_ERROR);
 hw_error=0;restore_fail_at=0;run();assert(sw.active && sw.hw.open); /* Retained owner can be safely retried. */
 setup();domain_error=-EIO;run();assert(!sw.hw.open && !sw.hw.owned && !sw.domain_owned && !sw.offloaded && sw.error==-EIO);
 const int policy_errors[]={-EIO,-EINVAL,-ETIMEDOUT};
 for(unsigned int i=0;i<ARRAY_SIZE(policy_errors);i++){
  setup();port_policy_error=policy_errors[i];run();
  assert(port_policies==1 && !arms && !claims && !appends && !publish_calls &&
   !sw.hw.open && !sw.hw.owned && !sw.domain_owned && !sw.offloaded && sw.error==policy_errors[i]);
 }
 setup();configured_flags[1]|=BR_ISOLATED;port_policy_error=-EOPNOTSUPP;run();
 assert(!sw.active && sw.flow_allowed && fe.route_admitted && sw.armed_route_mask==29 &&
  !sw.native_mask && sw.route_mask==29 && !claims && !appends && !publish_calls);
 for(unsigned int i=1;i<=2;i++){setup();append_fail_at=i;run();assert(!sw.hw.open && !sw.hw.owned && !sw.domain_owned && !sw.offloaded && sw.reason==FE_SWITCH_FDB_CAPACITY);}
 setup();epoch_during_append=true;run();assert(!sw.hw.open && !sw.hw.owned && !sw.domain_owned && !sw.offloaded && sw.reason==FE_SWITCH_GUARDED);
 setup();arm_failure=true;run();assert(!sw.hw.open && !sw.active && !sw.flow_allowed && !sw.hw.owned && !sw.domain_owned);
 setup();hw_error=-EOPNOTSUPP;run();assert(sw.hw.open && !sw.active && !sw.hw.owned && !sw.offloaded && sw.armed_route_mask==31 && sw.reason==FE_SWITCH_HW_UNSUPPORTED);
 setup();domain_error=-EEXIST;
 const unsigned int delays[]={5,10,20,40,60,60,60,60};
 for(unsigned int retry=0;retry<10;retry++){
  unsigned int before=scheduled;run();
  assert(sw.hw.open && !sw.active && !sw.hw.owned && !sw.domain_owned && !sw.offloaded && sw.armed_route_mask==31);
  assert(sw.reason==FE_SWITCH_FOREIGN_FDB && !appends && sw.retry_count==(retry<8?retry+1:8));
  if(retry<8)assert(scheduled==before+1 && last_delay==delays[retry]*HZ);else assert(scheduled==before);
 }
}
static void independent_port_policies(void){
 /* Static forwarding is useful with learning disabled. Isolation changes
  * only eligible LAN-to-LAN policy, never authorizes a bypass through L3
  * or a hardware-forwarded mark on CPU/bridge-generated packets. */
 for(unsigned int learning=0;learning<32;learning++)for(unsigned int isolated=0;isolated<32;isolated++){
  setup();online_ports=31;
  for(unsigned int i=0;i<5;i++)configured_flags[i]=((learning&BIT(i))?BR_LEARNING:0)|((isolated&BIT(i))?BR_ISOLATED:0);
  run();bool route_allowed=learning==31 && !isolated;unsigned int eligible=learning&~isolated;
  assert(sw.active && sw.native_mask==31 && sw.offloaded==31 && sw.hw.port_policy_ready);
  assert(sw.hw.learning_mask==learning && sw.hw.isolated_mask==isolated);
  assert(sw.route_policy_allowed && sw.flow_allowed && fe.route_admitted);
  assert(sw.native_route_policy_allowed==route_allowed && sw.armed_route_eligible_mask==eligible);
  assert(!sw.route_mask && !sw.armed_route_mask && sw.local_target==(route_allowed?25U:16U));
  assert(appends==3 && publish_successes==3 && sw.published_count==3 && bridge_owned_count()==3);
  assert(installed[0].destination==(route_allowed?25U:16U) && installed[1].destination==1 && installed[2].destination==2);
  for(unsigned int i=0;i<5;i++)for(unsigned int j=0;j<5;j++){
   bool allowed=(eligible&BIT(i)) && (eligible&BIT(j));
   assert(fe_switch_flow_ports_allowed(&fe,&ports[i],&ports[j])==allowed);
  }
  for(unsigned int i=0;i<5;i++){
   assert(fe_switch_flow_ports_allowed(&fe,&ports[i],&pon)==!!(eligible&BIT(i)));
   assert(fe_switch_flow_ports_allowed(&fe,&pon,&ports[i])==!!(eligible&BIT(i)));
  }
 }
 /* Keep every online member in the route-policy snapshot, but replay and
  * prepare only the forwarding subset. Local MACs remain CPU reachable;
  * a blocked port's static key must instead pin a CPU-only trap. */
 for(unsigned int blocked=0;blocked<5;blocked++)for(unsigned int state=0;state<=BR_STATE_BLOCKING;state++){
  if(state==BR_STATE_FORWARDING)continue;
  setup();online_ports=31;configured_states[blocked]=state;run();
  unsigned int expected=31&~BIT(blocked),count=3-(blocked==static_port)-(blocked==offline_port);
  assert(sw.active && sw.native_mask==expected && sw.offloaded==expected && sw.hw.ports==expected);
  assert(sw.hw.learning_mask==expected && !sw.hw.isolated_mask && sw.route_policy_allowed);
  assert(sw.flow_allowed && fe.route_admitted && !sw.route_mask && !sw.armed_route_mask && sw.local_target==25);
  assert(sw.native_route_policy_allowed && sw.armed_route_eligible_mask==expected);
  assert(!fe_switch_flow_ports_allowed(&fe,&ports[blocked],&pon));
  assert(!fe_switch_flow_ports_allowed(&fe,&pon,&ports[blocked]));
  assert(!fe_switch_flow_ports_allowed(&fe,&ports[blocked],&ports[blocked]));
  assert(appends==3 && publish_successes==count && sw.published_count==count && offloads==4);
  assert(installed[0].destination==25);
  for(unsigned int i=1;i<appends;i++)assert(installed[i].destination!=blocked);
  assert(installed[1].destination==(blocked==static_port?16U:static_port));
  assert(installed[2].destination==(blocked==offline_port?16U:offline_port));
 }
 for(unsigned int restriction=0;restriction<3;restriction++){
  setup();sw.requested=false;
  if(restriction==0)configured_flags[0]=0;
  if(restriction==1)configured_flags[0]|=BR_ISOLATED;
  if(restriction==2)configured_states[0]=BR_STATE_BLOCKING;
  run();assert(!sw.active && sw.flow_allowed && fe.route_admitted && arms==1 && sw.route_mask==30);
  assert(sw.armed_route_eligible_mask==30);
 }
 setup();configured_states[1]=BR_STATE_BLOCKING;run();
 assert(sw.reason==FE_SWITCH_NO_BRIDGE && arms==1 && !offloads && !sw.active && sw.flow_allowed && sw.armed_route_eligible_mask==29);
 setup();configured_states[1]=BR_STATE_BLOCKING+1;run();
 assert(sw.reason==FE_SWITCH_PORT_POLICY && arms==1 && !offloads && !sw.active && sw.flow_allowed && sw.armed_route_eligible_mask==29);
 /* ageing_time=0 is a supported static-only hardware bridge, not
  * infinite-lifetime dynamic learning. Every transition is rebuilt. */
 setup();run();assert(sw.hw.learning_mask==3);
 ageing=0;sw.guard.generation++;run();
 assert(sw.active && sw.native_mask==3 && !sw.hw.learning_mask && sw.flow_allowed);
 assert(sw.rule_count==3 && sw.published_count==2 && bridge_owned_count()==2);
 ageing=15*HZ;sw.guard.generation++;run();
 assert(sw.active && sw.hw.learning_mask==3 && sw.published_count==2);
}
static void physical_route_permissions(void){
 setup();run();assert(sw.armed_route_eligible_mask==31);
 assert(fe_switch_flow_ports_allowed(&fe,&ports[0],&ports[0]));
 assert(fe_switch_flow_ports_allowed(&fe,&pon,&ports[4]));
 assert(!fe_switch_flow_ports_allowed(&fe,NULL,&pon));
 assert(!fe_switch_flow_ports_allowed(&fe,&pon,NULL));
 assert(!fe_switch_flow_ports_allowed(&fe,&foreign,&pon));
 assert(!fe_switch_flow_ports_allowed(&fe,&pon,&foreign));
 assert(!fe_switch_flow_ports_allowed(&fe,&internal,&pon));
 assert(!fe_switch_flow_ports_allowed(&fe,&pon,&internal));
 /* Same ifindex is not the same physical owner; an unregister cannot
  * lend its permission to a different object before the next snapshot. */
 foreign.index=ports[0].index;
 assert(!fe_switch_flow_ports_allowed(&fe,&foreign,&pon));
 sw.owned_devices[0]=NULL;
 assert(!fe_switch_flow_ports_allowed(&fe,&ports[0],&pon));
 sw.owned_devices[0]=&ports[0];
 sw.owned_devices[32]=NULL;
 assert(!fe_switch_flow_ports_allowed(&fe,&ports[1],&pon));
 sw.owned_devices[32]=&pon;
 /* Invalidation is synchronous, including between a snapshot and arm.
  * A failed replacement must not resurrect the old per-port bitmap. */
 rtl9617c_switch_guard_invalidate(&sw.guard);
 assert(!sw.armed_route_eligible_mask && !fe_switch_flow_ports_allowed(&fe,&ports[0],&pon));
 configured_flags[0]|=BR_ISOLATED;run();
 assert(sw.armed_route_eligible_mask==30 && !sw.native_route_policy_allowed && sw.local_target==16);
 assert(!fe_switch_flow_ports_allowed(&fe,&ports[0],&pon));
 assert(!fe_switch_flow_ports_allowed(&fe,&pon,&ports[0]));
 assert(fe_switch_flow_ports_allowed(&fe,&ports[1],&pon));
 unsigned int flushed=route_flushes;
 rtl9617c_switch_guard_invalidate(&sw.guard);arm_failure=true;run();
 assert(route_flushes==flushed+1 && !sw.armed_route_eligible_mask && !sw.flow_allowed);
 arm_failure=false;run();assert(sw.armed_route_eligible_mask==30);
 additional_policy=true;rtl9617c_switch_guard_invalidate(&sw.guard);run();
 assert(!sw.route_policy_allowed && !sw.armed_route_eligible_mask && !sw.flow_allowed);
 assert(!fe_switch_flow_ports_allowed(&fe,&ports[1],&pon));
 cases++;
}
static void static_feedback_ownership(void){
 for(unsigned int failure=1;failure<=2;failure++){
  setup();fail_publish_at=failure;run();
  assert(!sw.active && !sw.hw.open && !sw.offloaded && !sw.published_count && !bridge_owned_count());
  assert(publish_calls==failure && publish_successes==failure-1 && unpublish_calls==failure-1);
  assert(rules_reuses==1 && !sw.rule_count && !scheduled && !sw.rebuilds && sw.error==-ENOMEM);
 }
 /* Even an unsuccessful hardware restore cannot retain a Linux-visible
  * cookie prefix. Silicon ownership stays pinned and gated for retry. */
 setup();fail_publish_at=2;restore_fail_at=2;run();
 assert(sw.hw.owned && sw.domain_owned && !sw.active && !sw.hw.open && !sw.published_count);
 assert(publish_successes==1 && unpublish_calls==1 && !bridge_owned_count() && sw.error==-ETIMEDOUT);
 fail_publish_at=restore_fail_at=0;run();
 assert(sw.active && bridge_owned_count()==2 && sw.published_count==2 && publish_successes==3);
 /* Invalidation before/after either callback, including after the final
  * successful publication, may not commit or leak a successfully owned
  * prefix. FE disable additionally reuses rules[] WITHOUT changing epoch;
  * the independent journal must survive until all cookies are withdrawn. */
 for(unsigned int kind=1;kind<=3;kind++)for(unsigned int after=0;after<2;after++)for(unsigned int position=1;position<=2;position++){
  setup();publish_change=kind;
  if(after)change_after_publish_at=position;else change_before_publish_at=position;
  run();unsigned int successful=kind==3?2:position-(after?0:1);
  assert(!sw.active && !sw.hw.open && !sw.flow_allowed && !fe.route_admitted && !sw.offloaded && !sw.published_count);
  assert(!bridge_owned_count() && publish_successes==successful && unpublish_calls==successful);
  assert(rules_reuses==1 && !sw.rule_count && !scheduled && !sw.rebuilds && sw.error==-EAGAIN);
  if(kind==3)assert(!fe.enabled && !fe.prepared && sw.guard.generation==1);
 }
 /* An explicitly requested same-epoch rebuild withdraws the OLD cookies before
  * staging resets each slot and obtains fresh, distinct ownership. */
 setup();run();u64 first_cookie=published[0].cookie,second_cookie=published[1].cookie;
 sw.force_reconcile=true;run();assert(sw.active && unpublish_calls==2 && publish_successes==4 && sw.published_count==2);
 assert(published[0].cookie>second_cookie && published[1].cookie>published[0].cookie && second_cookie>first_cookie);
 assert(rules_reuses==1 && bridge_owned_count()==2);
 /* Missing RTNL-resolved endpoints fail explicitly before any API call. */
 setup();sw.master=&master;sw.published_count=1;published[0].destination=16;
 rtnl_lock();sw.master=NULL;assert(fe_switch_static_publish(&sw,1)==-ENODEV);
 sw.master=&master;published[0].destination=1;sw.ports[1]=NULL;
 assert(fe_switch_static_publish(&sw,1)==-ENODEV && !publish_calls);rtnl_unlock();cases++;
}
static void static_capacity_boundaries(void){
 const unsigned int sizes[]={4095,4096,4097,RTL_L2_FDB_ENTRIES};
 for(unsigned int i=0;i<ARRAY_SIZE(sizes);i++){
  setup();online_ports=31;extra_replay_rows=sizes[i]-3;run();
  assert(sw.active && sw.rule_count==sizes[i] && sw.published_count==sizes[i] && appends==sizes[i]);
  assert(publish_successes==sizes[i] && bridge_owned_count()==sizes[i] && offloads==5);
  for(unsigned int slot=0;slot<sw.published_count;slot++)assert(published[slot].cookie);
  /* Existing large tables are restored before a policy-only CPU fallback,
   * and withdrawal never decodes the overwritten rules scratch buffer. */
  sw.requested=false;run();assert(!sw.active && !sw.published_count && unpublish_calls==sizes[i] && !bridge_owned_count());
 }
 setup();online_ports=31;extra_replay_rows=RTL_L2_FDB_ENTRIES-2;run();
 assert(!sw.active && !sw.hw.open && !prepares && !claims && !appends && !publish_calls && !sw.offloaded);
 assert(sw.error==-ENOSPC && sw.reason==FE_SWITCH_FDB_CAPACITY);
 /* The rollback prefix itself crosses the 4096 boundary, not only the
  * successful append/publication path. Every acquired cookie is released. */
 const unsigned int failures[]={4096,RTL_L2_FDB_ENTRIES};
 for(unsigned int i=0;i<ARRAY_SIZE(failures);i++){
  setup();online_ports=31;extra_replay_rows=RTL_L2_FDB_ENTRIES-3;fail_publish_at=failures[i];run();
  assert(!sw.active && !sw.hw.open && !sw.offloaded && !sw.published_count && !bridge_owned_count());
  assert(appends==RTL_L2_FDB_ENTRIES && publish_successes==failures[i]-1 && unpublish_calls==failures[i]-1);
  assert(rules_reuses==1 && !scheduled && !sw.rebuilds && sw.error==-ENOMEM);
 }
}
static void retry_classification(void){
 setup();assert(!fe_switch_needs_recovery(&fe));
 for(unsigned int reason=0;reason<=FE_SWITCH_AGING_UNSUPPORTED;reason++){
  sw.reason=reason;sw.error=0;assert(!fe_switch_needs_recovery(&fe));
  sw.error=-EIO;
  assert(fe_switch_needs_recovery(&fe)==(reason!=FE_SWITCH_HW_UNSUPPORTED && reason!=FE_SWITCH_FOREIGN_FDB));cases++;
 }
 setup();restore_fail_at=1;run();assert(fe_switch_needs_recovery(&fe));
 restore_fail_at=0;run();assert(sw.active && !fe_switch_needs_recovery(&fe));
 setup();arm_failure=true;run();assert(fe_switch_needs_recovery(&fe));
 arm_failure=false;run();assert(sw.active && !fe_switch_needs_recovery(&fe));
 setup();domain_error=-EEXIST;run();assert(!fe_switch_needs_recovery(&fe));
 setup();hw_error=-EOPNOTSUPP;run();assert(!fe_switch_needs_recovery(&fe));
 /* A capability fallback whose final hardware gate failed is still an
  * operational failure, not a healthy unsupported-native state. */
 setup();hw_error=-EOPNOTSUPP;arm_failure=true;run();
 assert(!sw.hw.open && !sw.flow_allowed && sw.reason==FE_SWITCH_GUARDED &&
        sw.error==-EAGAIN && fe_switch_needs_recovery(&fe));
 arm_failure=false;run();assert(sw.hw.open && sw.flow_allowed &&
        sw.reason==FE_SWITCH_HW_UNSUPPORTED && !fe_switch_needs_recovery(&fe));
 /* The same applies before and after the eight bounded foreign-owner
  * retries. Exhaustion must not make a later route-gate failure sticky. */
 for(unsigned int exhausted=0;exhausted<2;exhausted++){
  setup();domain_error=-EEXIST;
  if(exhausted){for(unsigned int retry=0;retry<8;retry++)run();assert(sw.retry_count==8);}
  arm_failure=true;unsigned int before=scheduled;run();
  assert(!sw.hw.open && !sw.flow_allowed && sw.reason==FE_SWITCH_GUARDED &&
         sw.error==-EAGAIN && fe_switch_needs_recovery(&fe) && scheduled==before);
  arm_failure=false;run();assert(sw.hw.open && sw.flow_allowed &&
         sw.reason==FE_SWITCH_FOREIGN_FDB && !fe_switch_needs_recovery(&fe));
 }
}
static void stable_owner_identity(void){
 setup();memset(sw.owned_devices,0,sizeof(sw.owned_devices));
 assert(!fe_switch_owns_device(&sw,&ports[0]));
 const unsigned int destinations[]={0,4,32,63};
 for(unsigned int i=0;i<ARRAY_SIZE(destinations);i++){
  unsigned int destination=destinations[i];
  fe_switch_track_port_locked(&fe,&ports[0],destination,true);
  assert(fe_switch_owns_device(&sw,&ports[0]) && sw.owned_devices[destination]==&ports[0]);
  fe_switch_track_port_locked(&fe,&ports[1],destination,true);
  assert(sw.owned_devices[destination]==&ports[1]);
  fe_switch_track_port_locked(&fe,&ports[0],destination,false);
  assert(sw.owned_devices[destination]==&ports[1]);
  fe_switch_track_port_locked(&fe,&ports[1],destination,false);
  assert(!sw.owned_devices[destination]);cases++;
 }
 unsigned int before=invalidates;
 fe_switch_track_port_locked(&fe,&ports[0],64,true);assert(invalidates==before);
 fe.bridge=NULL;fe_switch_track_port_locked(&fe,&ports[0],0,true);assert(invalidates==before);cases++;
}
static void multicast_publication_boundaries(void){
 setup();mcast_error=0;run();
 assert(sw.active && mcast_live && mcast_prepares==1 && mcast_applies==1 && mcast_arms==1);
 assert(mcast_revokes && appends==3 && publish_successes==2);
 sw.requested=false;run();assert(!sw.active && !mcast_live && mcast_arms==1);
 const int unavailable[]={-EOPNOTSUPP,-ENOSPC};
 for(unsigned int i=0;i<ARRAY_SIZE(unavailable);i++){
  setup();mcast_error=unavailable[i];run();
  assert(sw.active && !mcast_live && mcast_prepares==1 && !mcast_applies && !mcast_arms);
  assert(appends==3 && !sw.error);
 }
 const int failures[]={-EAGAIN,-EIO,-EBUSY,-ETIMEDOUT};
 for(unsigned int i=0;i<ARRAY_SIZE(failures);i++)for(unsigned int stage=0;stage<2;stage++){
  setup();mcast_error=stage?0:failures[i];mcast_hw_error=stage?failures[i]:0;run();
  assert(!sw.active && !sw.hw.open && !mcast_live && !mcast_arms && !appends && !publish_calls);
  assert(sw.error==failures[i] && mcast_prepares==1 && mcast_applies==stage);
 }
 setup();mcast_error=0;epoch_during_append=true;run();
 assert(mcast_applies==1 && !mcast_live && !mcast_arms && !sw.active);
 setup();mcast_error=0;fail_publish_at=2;run();
 assert(mcast_arms==1 && !mcast_live && !sw.active && unpublish_calls==1);
 setup();mcast_error=0;arm_failure=true;run();
 assert(mcast_arms==1 && !mcast_live && !sw.active && !sw.hw.open);
 setup();mdb_error=0;run();assert(sw.active && mdb_prepares==1 && mdb_steers==1);
 const int mdb_fallback[]={-EOPNOTSUPP,-ENOSPC};
 for(unsigned int i=0;i<ARRAY_SIZE(mdb_fallback);i++){
  setup();mdb_error=mdb_fallback[i];run();assert(sw.active && !sw.error && mdb_prepares==1 && !mdb_steers);
 }
 for(unsigned int i=0;i<ARRAY_SIZE(failures);i++)for(unsigned int stage=0;stage<2;stage++){
  setup();mdb_error=stage?0:failures[i];mdb_hw_error=stage?failures[i]:0;run();
  assert(!sw.active && !sw.hw.open && !mcast_live && !appends && !publish_calls);
  assert(sw.error==failures[i] && mdb_prepares==1 && mdb_steers==stage);
 }
 for(unsigned int policy=0;policy<4;policy++){
  setup();mdb_error=0;
  if(policy==0)configured_flags[0]&=~BR_LEARNING;
  if(policy==1)configured_flags[0]|=BR_ISOLATED;
  if(policy==2)fe.enabled=false;
  if(policy==3)fe.prepared=false;
  run();assert(sw.active && !mdb_prepares && !mdb_steers);
 }
}
int main(void){
 if(getenv("THOROS_FDB_AUTHORITY_ONLY")){
  cpu_dynamic_native_fallback();preflight_completed_and_noop();printf("Native worker CPU authority: %u preflight/replay/fallback/completed-epoch cases PASS\n",cases);return 0;
 }
 success_and_policy();replay_to_publication();released_lock_changes();transaction_failures();independent_port_policies();static_feedback_ownership();static_capacity_boundaries();retry_classification();stable_owner_identity();
 multicast_publication_boundaries();physical_route_permissions();cpu_dynamic_native_fallback();preflight_completed_and_noop();
 printf("Native switch production worker: %u policy/RCU/FDB-replay/rollback cases; forwarding-only native subsets, per-endpoint route permissions, independent static-cookie journal and 4096/4128-row success/failure boundaries PASS\n",cases);return 0;}
'''

COMMON = COMMON.replace("/* PRODUCTION_OBSERVED_DEFINITION */", re.search(
    r"struct fe_switch_hw_observed \{.*?\n\};",
    (DRIVERS / "rtl9617c-fe-switch-hw.h").read_text(), re.S)[0])
definitions = "\n".join(re.search(pattern, source, re.S)[0] for pattern in [
    r"enum fe_switch_reason \{.*?\n\};", r"struct fe_switch_plan \{.*?\n\};",
    r"struct fe_switch_learned \{.*?\n\};", r"struct fe_switch_published \{.*?\n\};",
    r"struct fe_switch_completed \{.*?\n\};",
    r"struct rtl_fe_bridge \{.*?\n\};",
])
functions = "\n".join(function(name) for name in [
    "fe_switch_queue", "fe_switch_reconcile_locked",
    "fe_switch_scan_reset", "fe_switch_route_plan_validate", "fe_switch_route_global_allowed", "fe_switch_route_eligible_ports", "fe_switch_plan_validate", "fe_switch_forwarding_ports", "fe_switch_flag_ports", "fe_switch_needs_recovery", "fe_switch_track_port_locked", "fe_switch_owns_device", "fe_switch_port_index", "fe_switch_vlan_find", "fe_switch_bridge_for_vid", "fe_switch_is_master", "fe_switch_age_ticks", "fe_switch_replay_fdb", "fe_switch_static_stage", "fe_switch_static_publish", "fe_switch_unoffload", "fe_switch_atomic_event", "fe_switch_flow_allowed", "fe_switch_flow_port_allowed", "fe_switch_flow_ports_allowed",
    "fe_switch_gate", "fe_switch_arm", "fe_switch_cpu_fdb_preflight", "fe_switch_rebuild_current", "fe_switch_complete", "fe_switch_work", "fe_bridge_evidence",
])
def replace_once(candidate, before, after):
    if candidate.count(before) != 1:
        raise SystemExit(f"Mutation anchor missing/ambiguous: {before!r}")
    return candidate.replace(before, after, 1)


route_assignment = ("\tsw->route_policy_allowed =\n"
                    "\t\tfe_switch_route_global_allowed(&plan);")
early_native = replace_once(functions, "\tsw->native_mask = native_ports;\n", "")
early_native = replace_once(
    early_native, "\tfor (i = 0; i < sw->rule_count; i++) {\n\t\tret = fe_switch_fdb_write",
    "\tsw->native_mask = native_ports;\n\tfor (i = 0; i < sw->rule_count; i++) {\n\t\tret = fe_switch_fdb_write")
# With the real unoffload callback extracted, BOTH reset sites protect a
# rebuild. Removing only the worker's redundant reset is not a regression.
assert functions.count("\tfe_switch_scan_reset(sw);") == 2
mutants = {
    "cpu_preflight_skipped": replace_once(functions,
        "\tret = fe_switch_cpu_fdb_preflight(sw);", "\tret = fe_switch_cpu_fdb_preflight(sw);\n\tsw->cpu_fdb_count = 0;"),
    "duplicate_work_rebuilds": replace_once(functions,
        "if (fe_switch_rebuild_current(sw, generation)) {", "if (fe_switch_rebuild_current(sw, generation) && false) {"),
    "no_op_ignores_force_retry": replace_once(functions,
        "sw->worker_busy || sw->force_reconcile ||", "sw->worker_busy ||"),
    "no_op_ignores_policy_epoch": replace_once(functions,
        "done->generation != generation ||", "(generation && false) ||"),
    "no_op_ignores_pending_withdrawal": replace_once(functions,
        "fe->error || fe->pending_withdrawals ||", "fe->error ||"),
    "same_epoch_reconcile_not_forced": replace_once(functions,
        "\t\tfe->bridge->force_reconcile = true;", "\t\t(void)fe->bridge;"),
    "completed_evidence_uses_pending_sample": replace_once(functions,
        "observed = &done->observed;", "observed = &sw->hw.observed;"),
    "cpu_owned_dynamic_ignored": replace_once(functions, "\t\tif (cpu_port) {", "\t\tif (false && cpu_port) {"),
    "cpu_fallback_disables_independent_routing": replace_once(
        functions, "sw->reason == FE_SWITCH_SOFTWARE_FDB)", "(false && sw->reason == FE_SWITCH_SOFTWARE_FDB))"),
    "cpu_fallback_churns_recovery": replace_once(
        functions, "sw->reason != FE_SWITCH_SOFTWARE_FDB;", "true;"),
    "native_producer_opens_before_rx_provenance": replace_once(
        functions, "\tif (sw->native_mask)\n\t\tfe_mcast_arm(sw->fe, sw->route_generation);",
        "\tif (false && sw->native_mask)\n\t\tfe_mcast_arm(sw->fe, sw->route_generation);"),
    "gate_leaves_old_cpu_copy_epoch_active": functions.replace(
        function("fe_switch_gate"), replace_once(function("fe_switch_gate"),
        "\tfe_mcast_revoke(sw->fe);", "\tif (false) fe_mcast_revoke(sw->fe);")),
    "rebuild_retains_same_generation_scan": functions.replace(
        "\tfe_switch_scan_reset(sw);", "\tif (0) fe_switch_scan_reset(sw);"),
    "native_aging_disables_independent_routing": functions.replace(
        "\t\tsw->reason = FE_SWITCH_AGING_UNSUPPORTED;\n\t\tret = 0;\n\t\tgoto arm;",
        "\t\tsw->reason = FE_SWITCH_AGING_UNSUPPORTED;\n\t\tret = 0;\n\t\tgoto unlock;", 1),
    "native_capability_disables_routing": replace_once(
        functions, route_assignment,
        "\tsw->route_policy_allowed = fe_switch_route_global_allowed(&plan) && sw->reason == FE_SWITCH_OK;"),
    "capability_masks_real_policy": replace_once(
        functions, route_assignment,
        "\tsw->route_policy_allowed = fe_switch_route_global_allowed(&plan) ||\n"
        "\t\tplan.multi_bridge || plan.mixed || plan.vlan_filtering;"),
    "one_port_policy_disables_unrelated_routes": replace_once(
        functions, route_assignment,
        "\tsw->route_policy_allowed = fe_switch_route_plan_validate(&plan) == FE_SWITCH_OK;"),
    "route_publisher_ignores_output_permission": replace_once(
        functions, "fe_switch_flow_port_allowed(fe->bridge, output);",
        "(output != NULL);"),
    "route_publisher_ignores_input_permission": replace_once(
        functions, "fe_switch_flow_port_allowed(fe->bridge, input) &&",
        "(input != NULL) &&"),
    "gate_retains_old_physical_permissions": replace_once(
        functions, "\tWRITE_ONCE(sw->armed_route_eligible_mask, 0);", ""),
    "local_native_trap_uses_global_route_permission": replace_once(
        functions, "\tsw->local_target = sw->native_route_policy_allowed &&",
        "\tsw->local_target = sw->route_policy_allowed &&"),
    "replay_uses_unpublished_native_mask": functions.replace(
        "!(sw->replay_ports & BIT(port))", "!(sw->native_mask & BIT(port))", 1),
    "native_mask_published_before_static_fdb": early_native,
    "failed_route_fallback_claimed_healthy": functions.replace(
        "\t\tret = sw->error = -EAGAIN;\n\t\tsw->reason = FE_SWITCH_GUARDED;",
        "\t\tret = 0;", 1),
    "blocked_ports_enter_native_subset": replace_once(
        functions, "\tnative_ports = fe_switch_forwarding_ports(&plan);",
        "\tnative_ports = (fe_switch_forwarding_ports(&plan), plan.ports);"),
    "isolation_authorizes_route_bypass": replace_once(
        functions, "\t\tBR_BPDU_FILTER;", "\t\tBR_BPDU_FILTER | BR_ISOLATED;"),
    "learning_off_authorizes_route_bypass": replace_once(
        functions, "\t\t    !(plan->flags[port] & BR_LEARNING) ||\n", ""),
    "zero_age_still_learns": replace_once(
        functions, "\t\tseconds ? fe_switch_flag_ports(&plan, native_ports, BR_LEARNING) : 0,",
        "\t\tfe_switch_flag_ports(&plan, native_ports, BR_LEARNING),"),
    "failed_port_policy_ignored": replace_once(
        functions, "\t\tfe_switch_flag_ports(&plan, native_ports, BR_ISOLATED));\n\tif (ret) {",
        "\t\tfe_switch_flag_ports(&plan, native_ports, BR_ISOLATED));\n\tret = 0;\n\tif (ret) {"),
    "static_stage_not_called": replace_once(
        functions, "\tfe_switch_static_stage(sw);", "\tif (0) fe_switch_static_stage(sw);"),
    "static_stage_reuses_old_cookie": replace_once(
        functions, "\t\tsw->published[count].cookie = 0;\n", ""),
    "blocked_static_key_omitted": replace_once(
        functions, "\ttrap = !info->is_local && !(sw->replay_ports & BIT(port));",
        "\ttrap = !info->is_local && !(sw->replay_ports & BIT(port));\n\tif (trap) return 0;"),
    "blocked_static_key_sent_to_l3": replace_once(
        functions, "\t\ttrap ? 16 : (unsigned int)port;", "\t\ttrap ? sw->local_target : (unsigned int)port;"),
    "trap_only_static_falsely_published": replace_once(
        functions, "\t\tif (sw->replay_traps[i / 32] & BIT(i % 32))",
        "\t\tif (false && (sw->replay_traps[i / 32] & BIT(i % 32)))"),
    "static_publication_decodes_reused_rules": functions.replace(
        function("fe_switch_static_publish"), replace_once(function("fe_switch_static_publish"),
        "\t\tstruct fe_switch_published *row = &sw->published[i];",
        "\t\tstruct fe_switch_published *row = &sw->published[i];\n"
        "\t\tstruct rtl_l2_fdb_entry reused;\n"
        "\t\trtl_l2_fdb_decode(sw->rules[i], &reused);\n"
        "\t\tether_addr_copy(row->address, reused.mac);")),
    "static_withdrawal_uses_flushed_rule_count": functions.replace(
        function("fe_switch_unoffload"), replace_once(function("fe_switch_unoffload"),
        "\tfor (i = 0; i < sw->published_count; i++) {",
        "\tfor (i = 0; i < sw->rule_count; i++) {")),
    "static_publication_failure_ignored": replace_once(
        functions, "\t\tret = fe_switch_static_publish(sw, generation);",
        "\t\tret = fe_switch_static_publish(sw, generation);\n\t\tret = 0;"),
    "final_publication_epoch_not_rechecked": replace_once(
        functions, "\t\tif (!ret && (!sw->active || generation !=\n",
        "\t\tif (false && !ret && (!sw->active || generation !=\n"),
}
for name, mutated in mutants.items():
    if mutated == functions:
        raise SystemExit(f"Mutation anchor missing: {name}")
if args.authority_only:
    mutants = {name: body for name, body in mutants.items() if name in {
        "cpu_owned_dynamic_ignored", "cpu_fallback_disables_independent_routing", "cpu_fallback_churns_recovery",
        "cpu_preflight_skipped", "duplicate_work_rebuilds", "no_op_ignores_force_retry",
        "no_op_ignores_policy_epoch", "no_op_ignores_pending_withdrawal", "same_epoch_reconcile_not_forced",
        "completed_evidence_uses_pending_sample"}}
environment = dict(os.environ)
environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
if args.authority_only:
    environment["THOROS_FDB_AUTHORITY_ONLY"] = "1"
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
with tempfile.TemporaryDirectory(prefix="l2-switch-worker-") as directory:
    temporary = Path(directory)
    for name, candidate in {"production": functions, **mutants}.items():
        (temporary / "test.c").write_text(COMMON + definitions + "\nstatic void fe_switch_work(struct work_struct *work);\n" + BACKEND + candidate + TEST)
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-I", str(DRIVERS),
                        str(temporary / "test.c"), "-o", str(temporary / "test")], check=True)
        if name == "production":
            subprocess.run([str(temporary / "test")], check=True, env=environment)
        else:
            result = subprocess.run([str(temporary / "test")], env=environment,
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != -6 or "Assertion" not in result.stderr:
                raise SystemExit(f"{name}: expected a contract assertion, got {result.returncode}: {result.stderr}")
            print(f"Runtime regression mutant rejected: {name}", flush=True)
if args.authority_only:
    raise SystemExit(0)
(ROOT / "artifacts").mkdir(exist_ok=True)
(ROOT / "artifacts/l2-switch-worker.json").write_text(json.dumps({
    "production_functions_sha256": hashlib.sha256(functions.encode()).hexdigest(),
    "scope": "production reconciliation worker, policy validators, atomic notifier, static FDB replay/stage/publish/unoffload and admission callbacks; learning/isolation/STP matrix, stable-epoch FE-disable rules reuse, publication prefix rollback and 4096/4128-row boundaries; bridge API/guard/HW boundaries injected",
    "runtime_mutants_rejected": list(mutants),
    "hardware_verified": False,
}, indent=2) + "\n")
