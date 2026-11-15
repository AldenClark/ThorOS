#!/usr/bin/env python3
"""Run the complete production L2 reconciliation worker with fault boundaries.

Topology discovery, the guard lock and hardware transactions are covered in
separate tests. Here their boundary outcomes are injected into the unchanged
production worker, notifier, replay and admission callbacks, including changes
while its FE mutex is released for RCU or switchdev replay. The switchdev
boundary replays actual FDB records, never fabricates rule_count. No hardware
claim is made.
"""
import hashlib
import json
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
#include <time.h>
#include "rtl9617c-l2-format.h"
typedef uint32_t u32;typedef uint64_t u64;typedef unsigned char u8;
#define FE_LAN_PORTS 5
#define ETH_ALEN 6
#define HZ 100
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
#define BR_BPDU_FILTER BIT(24)
#define BR_STATE_FORWARDING 3
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
struct rtl9617c_switch_guard {struct rtl_fe_bridge *owner;u64 generation;bool blocked;};
struct rtl_fe_switch_hw {bool owned,open;};
struct rtl_fe {bool lock,enabled,prepared,engine_ready,shutting_down,route_admitted;struct rtl_fe_bridge *bridge;};
'''

BACKEND = r'''
static struct rtl_fe fe;
static struct rtl_fe_bridge sw;
static struct net_device ports[5],master;
static unsigned int rules[RTL_L2_FDB_ENTRIES][4];
static unsigned int closures,restores,unoffloads,snapshots,syncs,route_flushes,offloads,prepares,claims,appends,arms,scheduled,last_delay,cases;
static unsigned int restore_fail_at,offload_fail_at,append_fail_at,replay_error_at,change_in_sync,change_in_replay;
static unsigned int online_ports,static_port,offline_port,invalidates;
static struct rtl_l2_fdb_entry installed[32];
static int hw_error,domain_error,flush_error;
static bool rtnl_held,arm_failure,epoch_during_append,additional_policy;
static enum fe_switch_reason policy_reason;
static clock_t ageing;
static void mutex_lock(bool *lock){assert(!*lock);*lock=true;}
static void mutex_unlock(bool *lock){assert(*lock);*lock=false;}
static void rtnl_lock(void){assert(!rtnl_held);rtnl_held=true;}
static void rtnl_unlock(void){assert(rtnl_held);rtnl_held=false;}
static void fe_switch_hw_gate(struct rtl_fe *owner,struct rtl_fe_switch_hw *hw){
 assert(owner==&fe && hw==&sw.hw);hw->open=false;owner->route_admitted=false;closures++;
}
static bool fe_switch_hw_arm(struct rtl_fe *owner,struct rtl_fe_switch_hw *hw,u32 native,u32 route){
 assert(owner==&fe && hw==&sw.hw && fe.lock && rtnl_held && !hw->open);
 assert(!(native&route) && !((native|route)&~31U));
 assert(!native || (hw->owned && sw.domain_owned && sw.offloaded==native));
 hw->open=!arm_failure;owner->route_admitted=!arm_failure && owner->enabled;return !arm_failure;
}
static void fe_switch_gate(void *private);
static bool fe_switch_arm(void *private);
static int fe_switch_atomic_event(struct notifier_block *,unsigned long,void *);
static bool switchdev_fdb_is_dynamically_learned(const struct switchdev_notifier_fdb_info *info){return !info->added_by_user && !info->is_local;}
static bool is_valid_ether_addr(const u8 *mac){unsigned int any=0;for(unsigned int i=0;i<6;i++)any|=mac[i];return any && !(mac[0]&1);}
static void ether_addr_copy(u8 *dst,const u8 *src){memcpy(dst,src,6);}
static bool ether_addr_equal(const u8 *a,const u8 *b){return !memcmp(a,b,6);}
static void rtl9617c_switch_guard_invalidate(struct rtl9617c_switch_guard *guard){
 assert(guard==&sw.guard);invalidates++;guard->generation++;fe_switch_gate(&sw);
}
static void rtl9617c_switch_guard_quiesce(struct rtl9617c_switch_guard *guard){assert(guard==&sw.guard);fe_switch_gate(&sw);}
static u64 rtl9617c_switch_guard_generation(struct rtl9617c_switch_guard *guard){assert(guard==&sw.guard);return guard->generation;}
static bool rtl9617c_switch_guard_blocked(struct rtl9617c_switch_guard *guard){return guard->blocked;}
static bool rtl9617c_switch_guard_try_arm(struct rtl9617c_switch_guard *guard,u64 generation){
 arms++;assert(guard==&sw.guard && fe.lock && rtnl_held);
 if(guard->blocked || generation!=guard->generation)return false;
 bool ret=fe_switch_arm(&sw);if(!ret)fe_switch_gate(&sw);return ret;
}
static int fe_switch_restore_locked(struct rtl_fe_bridge *owner){
 assert(owner==&sw && fe.lock && rtnl_held && !sw.hw.open && !sw.active && !sw.flow_allowed);
 restores++;if(restores==restore_fail_at){sw.error=-ETIMEDOUT;sw.reason=FE_SWITCH_IO_ERROR;return -ETIMEDOUT;}
 sw.hw.owned=sw.domain_owned=false;return 0;
}
static void fe_switch_unoffload(struct rtl_fe_bridge *owner){
 assert(owner==&sw && !fe.lock && rtnl_held);unoffloads++;sw.offloaded=0;
}
static enum fe_switch_reason fe_switch_snapshot(struct rtl_fe_bridge *owner,struct fe_switch_plan *plan){
 assert(owner==&sw && fe.lock && rtnl_held && !sw.hw.open);snapshots++;
 memset(plan,0,sizeof(*plan));plan->ports=online_ports;sw.master=&master;sw.route_mask=fe.enabled?31:0;
 for(unsigned int i=0;i<5;i++){
  sw.ports[i]=&ports[i];plan->flags[i]=BR_LEARNING;plan->state[i]=BR_STATE_FORWARDING;
 }
 plan->multi_bridge=policy_reason==FE_SWITCH_MULTI_BRIDGE;
 plan->mixed=policy_reason==FE_SWITCH_MIXED_PORTS;
 plan->vlan_filtering=policy_reason==FE_SWITCH_VLAN_UNSUPPORTED;
 plan->private_policy=policy_reason==FE_SWITCH_PRIVATE_POLICY;
 plan->promisc=policy_reason==FE_SWITCH_PROMISC;
 plan->software_policy=additional_policy || policy_reason==FE_SWITCH_GUARDED;
 if(policy_reason==FE_SWITCH_PORT_POLICY)plan->flags[0]=0;
 return policy_reason;
}
static void change_state(unsigned int kind){
 if(kind==1)sw.guard.generation++;
 if(kind==2)fe.engine_ready=false;
 if(kind==3)sw.stopping=true;
 if(kind==4)fe.shutting_down=true;
}
static void synchronize_net(void){assert(rtnl_held && !fe.lock && !sw.hw.open);syncs++;change_state(change_in_sync);}
static int fe_switch_flush_routes_locked(struct rtl_fe *owner){
 assert(owner==&fe && fe.lock && rtnl_held && !sw.hw.open);route_flushes++;return flush_error;
}
static clock_t br_get_ageing_time(struct net_device *dev){assert(dev==&master);return ageing;}
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
  int ret=atomic->notifier_call(atomic,SWITCHDEV_FDB_ADD_TO_DEVICE,&item);
  if(ret)return ret;
 }
 assert(!sw.native_mask && !sw.active && sw.replay_ports==online_ports);
 change_state(change_in_replay);return 0;
}
static int fe_switch_hw_prepare(struct rtl_fe *owner,struct rtl_fe_switch_hw *hw,u32 native,unsigned long seconds,bool snooping){
 assert(owner==&fe && hw==&sw.hw && fe.lock && rtnl_held && !hw->open && !sw.active);
 assert(fe.engine_ready && native==online_ports && seconds==(unsigned long)(ageing/USER_HZ) && snooping);prepares++;
 hw->owned=true;return hw_error;
}
static int fe_switch_domain_claim(struct rtl_fe_bridge *owner){
 assert(owner==&sw && fe.lock && rtnl_held && sw.hw.owned && !sw.hw.open);claims++;
 if(domain_error)return domain_error;
 sw.domain_owned=true;return 0;
}
static int fe_switch_fdb_write(struct rtl_fe_bridge *owner,enum rtl_l2_fdb_command command,const unsigned int *words){
 assert(owner==&sw && command==RTL_L2_FDB_APPEND && words && fe.lock && rtnl_held && sw.domain_owned && !sw.hw.open);
 assert(!sw.native_mask && !sw.replay_ports && !sw.replaying);
 assert(appends<32);rtl_l2_fdb_decode(words,&installed[appends]);
 appends++;if(epoch_during_append)sw.guard.generation++;
 return appends==append_fail_at?-ENOSPC:0;
}
static void mod_delayed_work(unsigned int queue,struct delayed_work *work,unsigned int delay){
 assert(queue==system_long_wq && work==&sw.scan_work && fe.lock && rtnl_held);
 scheduled++;last_delay=delay;
}
static void setup(void){
 fe=(struct rtl_fe){.enabled=true,.prepared=true,.engine_ready=true};memset(&sw,0,sizeof(sw));
 sw.fe=&fe;fe.bridge=&sw;sw.guard.owner=&sw;sw.guard.generation=1;sw.rules=rules;sw.requested=true;
 sw.atomic_nb.notifier_call=fe_switch_atomic_event;
 online_ports=3;static_port=1;offline_port=2;invalidates=0;memset(installed,0,sizeof(installed));
 policy_reason=FE_SWITCH_OK;ageing=300*USER_HZ;
 closures=restores=unoffloads=snapshots=syncs=route_flushes=offloads=prepares=claims=appends=arms=scheduled=last_delay=0;
 restore_fail_at=offload_fail_at=append_fail_at=replay_error_at=change_in_sync=change_in_replay=0;
 hw_error=domain_error=flush_error=0;rtnl_held=arm_failure=epoch_during_append=additional_policy=false;
}
static void run(void){fe_switch_work(&sw.work);assert(!fe.lock && !rtnl_held && !sw.replaying && !sw.replay_ports);cases++;}
'''

TEST = r'''
static void success_and_policy(void){
 setup();run();assert(sw.active && sw.hw.open && sw.flow_allowed && fe.route_admitted);
 assert(sw.native_mask==3 && sw.route_mask==28 && sw.armed_route_mask==28 && sw.offloaded==3);
 assert(prepares==1 && claims==1 && appends==2 && route_flushes==1 && sw.rebuilds==1 && last_delay==HZ && sw.local_target==25);
 assert(sw.route_generation_valid && sw.route_generation==1);
 run();assert(sw.active && sw.rebuilds==2 && route_flushes==1); /* Same epoch does not churn routed owners. */
 /* A queued scan can belong to the same policy epoch yet predate the
  * worker's complete hardware teardown/rebuild. It must start over. */
 sw.scan_running=sw.scan_complete=sw.scan_removed=true;
 sw.scan_start=17;sw.scan_count=9;sw.scan_cursor=5;sw.scan_old=3;sw.scan_generation=sw.guard.generation;
 run();assert(sw.active && !sw.scan_running && !sw.scan_complete && !sw.scan_removed &&
  !sw.scan_start && !sw.scan_count && !sw.scan_cursor && !sw.scan_old && route_flushes==1);
 sw.guard.generation++;run();assert(route_flushes==2 && sw.route_generation==2);
 setup();fe.enabled=fe.prepared=false;run();
 assert(sw.active && sw.hw.open && !sw.flow_allowed && !fe.route_admitted && !sw.armed_route_mask && sw.local_target==16);
 setup();sw.requested=false;run();
 assert(!sw.active && sw.hw.open && sw.flow_allowed && sw.reason==FE_SWITCH_REQUEST_OFF);
 assert(!prepares && !claims && !appends && !offloads && !scheduled && !sw.offloaded && sw.armed_route_mask==31);
 setup();policy_reason=FE_SWITCH_NO_BRIDGE;run();assert(sw.hw.open && !sw.active && !prepares && sw.armed_route_mask==31);
 const enum fe_switch_reason vetoes[]={FE_SWITCH_PRIVATE_POLICY,FE_SWITCH_PROMISC,FE_SWITCH_GUARDED,FE_SWITCH_PORT_POLICY};
 for(unsigned int i=0;i<sizeof(vetoes)/sizeof(vetoes[0]);i++){
  setup();policy_reason=vetoes[i];run();
  assert(!sw.hw.open && !sw.active && !sw.flow_allowed && !prepares && !route_flushes && !arms && sw.route_mask==0);
 }
 const enum fe_switch_reason capabilities[]={FE_SWITCH_MULTI_BRIDGE,FE_SWITCH_MIXED_PORTS,FE_SWITCH_VLAN_UNSUPPORTED};
 for(unsigned int i=0;i<sizeof(capabilities)/sizeof(capabilities[0]);i++)for(unsigned int requested=0;requested<2;requested++){
  setup();policy_reason=capabilities[i];sw.requested=requested;run();
  assert(sw.hw.open && sw.flow_allowed && !sw.active && !prepares && !offloads && sw.armed_route_mask==31);
  setup();policy_reason=capabilities[i];sw.requested=requested;additional_policy=true;run();
  assert(!sw.hw.open && !sw.flow_allowed && !arms && !route_flushes && !sw.route_mask);
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
 setup();run();assert(appends==2 && sw.native_mask==3 && !invalidates);
 assert(installed[0].mac[5]==10 && installed[0].destination==25);
 assert(installed[1].mac[5]==11 && installed[1].destination==1);
 for(unsigned int i=0;i<2;i++)assert(installed[i].valid && installed[i].is_static);
 /* New snapshot moves the static output and excludes the old/down port;
  * switchdev still replays the down port's entry for every online port. */
 online_ports=5;static_port=2;offline_port=1;sw.guard.generation++;run();
 assert(appends==4 && sw.native_mask==5 && sw.offloaded==5 && !invalidates);
 assert(installed[2].mac[5]==10 && installed[2].destination==25);
 assert(installed[3].mac[5]==11 && installed[3].destination==2);
 for(unsigned int i=0;i<appends;i++)assert(installed[i].mac[5]!=12 && installed[i].mac[5]!=13);
 /* A later failed rebuild cannot publish the pending mask or retain an
  * earlier active generation merely because its first local row worked. */
 append_fail_at=appends+2;sw.guard.generation++;run();
 assert(!sw.active && !sw.native_mask && !sw.hw.open && !sw.offloaded &&
        sw.reason==FE_SWITCH_FDB_CAPACITY && !sw.replay_ports);
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
 const clock_t invalid_age[]={0,-1,USER_HZ-1,((clock_t)1<<19)*USER_HZ};
 for(unsigned int i=0;i<4;i++){
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
 const clock_t valid_age[]={USER_HZ,((clock_t)((1U<<19)-1))*USER_HZ};
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
 setup();assert(!fe_switch_owns_device(&sw,&ports[0]));
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
int main(void){success_and_policy();replay_to_publication();released_lock_changes();transaction_failures();retry_classification();stable_owner_identity();
 printf("Native switch production worker: %u policy/RCU/actual-FDB-replay/rollback cases; static destinations survive staged publication, offline entries stay excluded, stale/failed snapshots never arm, route-only fallback and bounded retries PASS\n",cases);return 0;}
'''

definitions = "\n".join(re.search(pattern, source, re.S)[0] for pattern in [
    r"enum fe_switch_reason \{.*?\n\};", r"struct fe_switch_plan \{.*?\n\};",
    r"struct fe_switch_learned \{.*?\n\};", r"struct rtl_fe_bridge \{.*?\n\};",
])
functions = "\n".join(function(name) for name in [
    "fe_switch_scan_reset", "fe_switch_route_plan_validate", "fe_switch_needs_recovery", "fe_switch_track_port_locked", "fe_switch_owns_device", "fe_switch_port_index", "fe_switch_replay_fdb", "fe_switch_atomic_event",
    "fe_switch_gate", "fe_switch_arm", "fe_switch_work",
])
mutants = {
    "rebuild_retains_same_generation_scan": functions.replace(
        "\tfe_switch_scan_reset(sw);\n\t/* This operation", "\tif (0) fe_switch_scan_reset(sw);\n\t/* This operation", 1),
    "native_aging_disables_independent_routing": functions.replace(
        "\t\tsw->reason = FE_SWITCH_AGING_UNSUPPORTED;\n\t\tgoto arm;",
        "\t\tsw->reason = FE_SWITCH_AGING_UNSUPPORTED;\n\t\tgoto unlock;", 1),
    "native_capability_disables_routing": functions.replace(
        "if (fe_switch_route_plan_validate(&plan) != FE_SWITCH_OK)",
        "if ((fe_switch_route_plan_validate(&plan), sw->reason != FE_SWITCH_OK && sw->reason != FE_SWITCH_NO_BRIDGE))", 1),
    "capability_masks_real_policy": functions.replace(
        "if (fe_switch_route_plan_validate(&plan) != FE_SWITCH_OK)",
        "if ((fe_switch_route_plan_validate(&plan), sw->reason == FE_SWITCH_GUARDED || sw->reason == FE_SWITCH_PRIVATE_POLICY || sw->reason == FE_SWITCH_PROMISC || sw->reason == FE_SWITCH_PORT_POLICY))", 1),
    "replay_uses_unpublished_native_mask": functions.replace(
        "!(sw->replay_ports & BIT(port))", "!(sw->native_mask & BIT(port))", 1),
    "native_mask_published_before_static_fdb": functions.replace(
        "\tsw->native_mask = plan.ports;\n", "", 1).replace(
        "\tfor (i = 0; i < sw->rule_count; i++) {\n\t\tret = fe_switch_fdb_write",
        "\tsw->native_mask = plan.ports;\n\tfor (i = 0; i < sw->rule_count; i++) {\n\t\tret = fe_switch_fdb_write", 1),
    "failed_route_fallback_claimed_healthy": functions.replace(
        "\t\tret = sw->error = -EAGAIN;\n\t\tsw->reason = FE_SWITCH_GUARDED;",
        "\t\tret = 0;", 1),
}
for name, mutated in mutants.items():
    if mutated == functions:
        raise SystemExit(f"Mutation anchor missing: {name}")
environment = dict(os.environ)
environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
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
            print(f"Runtime regression mutant rejected: {name}")
(ROOT / "artifacts").mkdir(exist_ok=True)
(ROOT / "artifacts/l2-switch-worker.json").write_text(json.dumps({
    "production_functions_sha256": hashlib.sha256(functions.encode()).hexdigest(),
    "scope": "complete production reconciliation worker, atomic notifier, static FDB replay and admission callbacks; real records traverse replay before hardware publication; topology/guard/HW boundaries injected",
    "runtime_mutants_rejected": list(mutants),
    "hardware_verified": False,
}, indent=2) + "\n")
