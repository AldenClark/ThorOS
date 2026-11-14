#!/usr/bin/env python3
"""Execute native-switch production lifetime, notifier and FDB replay control.

Allocator/notifier/workqueue plumbing is a fault-injection fixture. The actual
constructor, destructor, event filtering and replay functions are compiled,
not reproduced. The whole reconciliation worker and hardware are separate
contracts; this test does not claim a silicon or throughput result.
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
#include <stdlib.h>
#include <string.h>
#include "rtl9617c-l2-format.h"
typedef uint32_t u32;typedef uint64_t u64;typedef unsigned char u8;
#define FE_LAN_PORTS 5
#define BIT(n) (1U << (n))
#define ETH_ALEN 6
#define GFP_KERNEL 0
#define system_long_wq 7
#define READ_ONCE(value) (value)
#define WRITE_ONCE(target,value) ((target)=(value))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define ERR_PTR(error) ((void *)(intptr_t)(error))
#define PTR_ERR(pointer) ((int)(intptr_t)(pointer))
#define IS_ERR(pointer) ((uintptr_t)(pointer)>(uintptr_t)-4096)
#define NOTIFY_DONE 0
enum { SWITCHDEV_FDB_ADD_TO_DEVICE=1,SWITCHDEV_FDB_DEL_TO_DEVICE,
 SWITCHDEV_FDB_ADD_TO_BRIDGE,SWITCHDEV_FDB_DEL_TO_BRIDGE,
 SWITCHDEV_PORT_OBJ_ADD,SWITCHDEV_PORT_OBJ_DEL,SWITCHDEV_PORT_ATTR_SET };
enum {SWITCHDEV_OBJ_ID_PORT_MDB=1,SWITCHDEV_OBJ_ID_HOST_MDB,SWITCHDEV_OBJ_ID_PORT_VLAN};
struct net_device {unsigned int port;};
struct notifier_block {int (*notifier_call)(struct notifier_block *,unsigned long,void *);};
struct list_head {bool initialized;};
#define INIT_LIST_HEAD(list) ((list)->initialized=true)
struct work_struct {bool initialized,queued,cancelled;void (*callback)(struct work_struct *);};
struct delayed_work {struct work_struct work;};
#define INIT_WORK(work,fn) do{(work)->initialized=true;(work)->callback=(fn);}while(0)
#define INIT_DELAYED_WORK(delayed,fn) INIT_WORK(&(delayed)->work,fn)
struct rtl9617c_switch_guard {struct list_head list;bool registered;void *owner;};
struct rtl_fe_switch_hw {bool owned;};
struct rtl_fe_bridge;
struct rtl_fe {bool lock,shutting_down;struct rtl_fe_bridge *bridge;};
struct switchdev_notifier_info {struct net_device *dev;const void *ctx;};
enum {NETDEV_UP=1,NETDEV_GOING_DOWN,NETDEV_DOWN,NETDEV_CHANGE,NETDEV_CHANGEADDR,
 NETDEV_CHANGEUPPER,NETDEV_CHANGEINFODATA,NETDEV_UNREGISTER,NETDEV_PRECHANGEUPPER};
struct netdev_notifier_info {struct net_device *dev;};
struct netdev_notifier_changeupper_info {struct netdev_notifier_info info;bool linking;};
static struct net_device *netdev_notifier_info_to_dev(void *p){return ((struct netdev_notifier_info *)p)->dev;}
struct switchdev_notifier_fdb_info {
 struct switchdev_notifier_info info;const u8 *addr;
 unsigned int vid;bool is_local,locked,added_by_user,offloaded;
};
struct switchdev_obj {unsigned int id;};
struct switchdev_notifier_port_obj_info {struct switchdev_notifier_info info;const struct switchdev_obj *obj;};
static bool switchdev_fdb_is_dynamically_learned(const struct switchdev_notifier_fdb_info *fdb){
 return !fdb->is_local && !fdb->added_by_user;
}
static bool is_valid_ether_addr(const u8 *mac){unsigned int any=0;for(unsigned int i=0;i<6;i++)any|=mac[i];return any && !(mac[0]&1);}
static void ether_addr_copy(u8 *to,const u8 *from){memcpy(to,from,6);}
static bool ether_addr_equal(const u8 *a,const u8 *b){return !memcmp(a,b,6);}
static int notifier_from_errno(int error){return error;}
static void fe_switch_work(struct work_struct *work){(void)work;assert(!"fixture does not execute worker");}
static void fe_switch_scan(struct work_struct *work){(void)work;assert(!"fixture does not execute scan");}
static const unsigned int fe_switch_guard_ops=7;
static unsigned int init_net;
'''

BACKEND = r'''
static struct rtl_fe fe;
static struct rtl_fe_bridge *live;
static struct net_device ports[5],master,foreign;
static struct {void *pointer;bool freed;} allocations[4];
static unsigned int allocated,allocation_calls,fail_allocation,registration_calls,fail_registration;
static bool registered[4],rtnl_held;
static unsigned int cancelled,freed,invalidates,queues,gates,restores,unoffloads,cases;
static int restore_error;
static void *allocate(size_t count,size_t bytes){
 allocation_calls++;if(allocation_calls==fail_allocation)return NULL;
 assert(allocated<4 && count && bytes);void *pointer=calloc(count,bytes);assert(pointer);
 allocations[allocated++].pointer=pointer;
 if(allocation_calls==1)live=pointer;
 return pointer;
}
static void *kzalloc(size_t bytes,unsigned int flags){assert(!flags);return allocate(1,bytes);}
static void *kvcalloc(size_t count,size_t bytes,unsigned int flags){assert(!flags);return allocate(count,bytes);}
static void release(void *pointer){
 if(!pointer)return;
 assert(live && live->stopping && !rtnl_held && !fe.lock);
 for(unsigned int i=0;i<4;i++)assert(!registered[i]);
 assert(live->work.cancelled && live->scan_work.work.cancelled);
 for(unsigned int i=0;i<allocated;i++)if(allocations[i].pointer==pointer){
  assert(!allocations[i].freed);allocations[i].freed=true;freed++;free(pointer);return;
 }
 assert(!"unowned free");
}
static void kvfree(void *pointer){release(pointer);}
static void kfree(void *pointer){release(pointer);live=NULL;}
static int register_callback(unsigned int kind){
 assert(live && !live->stopping && !registered[kind]);registration_calls++;
 if(registration_calls==fail_registration)return -EIO;
 registered[kind]=true;return 0;
}
static void unregister_callback(unsigned int kind){
 assert(live && live->stopping && registered[kind] && !fe.lock && !rtnl_held);
 registered[kind]=false;
}
static int register_switchdev_notifier(struct notifier_block *nb){assert(nb==&live->atomic_nb);return register_callback(0);}
static int register_switchdev_blocking_notifier(struct notifier_block *nb){assert(nb==&live->blocking_nb);return register_callback(1);}
static int register_netdevice_notifier(struct notifier_block *nb){assert(nb==&live->netdev_nb);return register_callback(2);}
static void unregister_switchdev_notifier(struct notifier_block *nb){assert(nb==&live->atomic_nb);unregister_callback(0);}
static void unregister_switchdev_blocking_notifier(struct notifier_block *nb){assert(nb==&live->blocking_nb);unregister_callback(1);}
static void unregister_netdevice_notifier(struct notifier_block *nb){assert(nb==&live->netdev_nb);unregister_callback(2);}
static int rtl9617c_switch_guard_register(struct rtl9617c_switch_guard *guard,unsigned int *net,
 const unsigned int *ops,void *owner){
 assert(guard==&live->guard && guard->list.initialized && net==&init_net && ops==&fe_switch_guard_ops && owner==live);
 int ret=register_callback(3);if(ret)return ret;
 guard->registered=true;guard->owner=owner;return 0;
}
static void rtl9617c_switch_guard_unregister(struct rtl9617c_switch_guard *guard){
 assert(guard==&live->guard && guard->registered);unregister_callback(3);guard->registered=false;
}
static void rtl9617c_switch_guard_invalidate(struct rtl9617c_switch_guard *guard){
 assert(guard==&live->guard && guard->registered);invalidates++;
}
static bool queue_work(unsigned int queue,struct work_struct *work){
 assert(queue==system_long_wq && work->initialized && live && !live->stopping);
 queues++;bool idle=!work->queued;work->queued=true;return idle;
}
static void cancel_work_sync(struct work_struct *work){
 assert(live && live->stopping && work->initialized && !rtnl_held && !fe.lock);
 for(unsigned int i=0;i<4;i++)assert(!registered[i]);
 work->queued=false;work->cancelled=true;cancelled++;
}
static void cancel_delayed_work_sync(struct delayed_work *work){cancel_work_sync(&work->work);}
static void rtnl_lock(void){assert(!rtnl_held);rtnl_held=true;}
static void rtnl_unlock(void){assert(rtnl_held);rtnl_held=false;}
static void mutex_lock(bool *lock){assert(!*lock);*lock=true;}
static void mutex_unlock(bool *lock){assert(*lock);*lock=false;}
static void fe_switch_gate(void *private){assert(private==live && fe.lock && rtnl_held);live->active=false;gates++;}
static int fe_switch_restore_locked(struct rtl_fe_bridge *sw){assert(sw==live && fe.lock && rtnl_held);restores++;return restore_error;}
static int fe_switch_quiesce_locked(struct rtl_fe *owner){assert(owner==&fe && fe.lock && rtnl_held);gates++;return restore_error;}
static void fe_switch_unoffload(struct rtl_fe_bridge *sw){assert(sw==live && !fe.lock && rtnl_held);unoffloads++;sw->offloaded=0;}
static void reset(void){
 assert(!live);memset(&fe,0,sizeof(fe));memset(allocations,0,sizeof(allocations));memset(registered,0,sizeof(registered));
 allocated=allocation_calls=fail_allocation=registration_calls=fail_registration=0;
 cancelled=freed=invalidates=queues=gates=restores=unoffloads=0;restore_error=0;rtnl_held=false;
}
'''

TEST = r'''
static void construction_and_stop(void){
 assert(!fe_bridge_stop(NULL));
 for(unsigned int phase=1;phase<=8;phase++){
  reset();if(phase<=4)fail_allocation=phase;else fail_registration=phase-4;
  struct rtl_fe_bridge *sw=fe_bridge_start(&fe);
  assert(IS_ERR(sw) && PTR_ERR(sw)==(phase<=4?-ENOMEM:-EIO));
  assert(!live && freed==allocated);
  assert(cancelled==(phase==1?0:2));
  for(unsigned int i=0;i<4;i++)assert(!registered[i]);
  cases++;
 }
 reset();struct rtl_fe_bridge *sw=fe_bridge_start(&fe);assert(sw==live && !IS_ERR(sw));fe.bridge=sw;
 assert(!sw->requested && sw->reason==FE_SWITCH_ENGINE_DOWN); /* Native L2 is explicit opt-in. */
 assert(allocated==4 && !freed && registration_calls==4);
 sw->work.queued=sw->scan_work.work.queued=true;sw->active=true;sw->offloaded=31;
 restore_error=-ETIMEDOUT;
 assert(fe_bridge_stop(sw)==-ETIMEDOUT && live==sw && !freed);
 assert(sw->stopping && !sw->guard.registered && !sw->netdev_registered && !sw->atomic_registered && !sw->blocking_registered);
 assert(!sw->work.queued && !sw->scan_work.work.queued && cancelled==2 && !sw->active && !sw->offloaded);
 unsigned int before_queues=queues,before_invalidates=invalidates;
 struct switchdev_notifier_fdb_info event={.info={.dev=&ports[0]},.added_by_user=true};
 assert(fe_switch_atomic_event(&sw->atomic_nb,SWITCHDEV_FDB_ADD_TO_DEVICE,&event)==NOTIFY_DONE);
 assert(fe_switch_blocking_event(&sw->blocking_nb,SWITCHDEV_PORT_ATTR_SET,&event)==NOTIFY_DONE);
 fe_switch_queue(sw);assert(queues==before_queues && invalidates==before_invalidates);
 restore_error=0;assert(!fe_bridge_stop(sw) && !live && freed==4 && cancelled==4);
 assert(gates==2 && restores==2 && unoffloads==2);cases++;
}
static void notifier_and_replay(void){
 reset();struct rtl_fe_bridge *sw=fe_bridge_start(&fe);assert(!IS_ERR(sw));fe.bridge=sw;
 for(unsigned int i=0;i<5;i++){ports[i].port=i;sw->ports[i]=&ports[i];}sw->master=&master;sw->local_target=25;
 u8 mac[6]={2,0,0,0,0,1};
 struct switchdev_notifier_fdb_info event={.info={.dev=&ports[0]},.addr=mac};
 for(unsigned int n=0;n<1024;n++){
  assert(!fe_switch_atomic_event(&sw->atomic_nb,SWITCHDEV_FDB_ADD_TO_DEVICE,&event));
  assert(!fe_switch_atomic_event(&sw->atomic_nb,SWITCHDEV_FDB_DEL_TO_DEVICE,&event));
 }
 assert(!invalidates && !queues && !sw->rule_count); /* First source learning must not flush/rebuild. */
 event.added_by_user=true;fe_switch_atomic_event(&sw->atomic_nb,SWITCHDEV_FDB_ADD_TO_DEVICE,&event);
 assert(invalidates==1 && !sw->rule_count);
 event.info.dev=&foreign;fe_switch_atomic_event(&sw->atomic_nb,SWITCHDEV_FDB_ADD_TO_DEVICE,&event);assert(invalidates==1);
 event.info.dev=&ports[0];event.info.ctx=sw;
 fe_switch_atomic_event(&sw->atomic_nb,SWITCHDEV_FDB_ADD_TO_DEVICE,&event);assert(!sw->rule_count && invalidates==1);
 sw->replaying=true;sw->native_mask=31; /* The worker selects its live domain before replay. */
 assert(!fe_switch_atomic_event(&sw->atomic_nb,SWITCHDEV_FDB_ADD_TO_DEVICE,&event));
 assert(sw->rule_count==1 && !sw->replay_error && invalidates==1);
 event.info.dev=&ports[3];assert(!fe_switch_replay_fdb(sw,&event));
 struct rtl_l2_fdb_entry decoded;rtl_l2_fdb_decode(sw->rules[0],&decoded);
 assert(sw->rule_count==1 && decoded.destination==3 && decoded.is_static && decoded.valid && !decoded.key_vid && !decoded.key_sc);
 event.is_local=true;event.info.dev=&master;assert(!fe_switch_replay_fdb(sw,&event));
 rtl_l2_fdb_decode(sw->rules[0],&decoded);assert(sw->rule_count==1 && decoded.destination==25);
 event.is_local=false;event.info.dev=&ports[0];event.locked=true;
 assert(fe_switch_atomic_event(&sw->atomic_nb,SWITCHDEV_FDB_ADD_TO_DEVICE,&event)==-EOPNOTSUPP && sw->replay_error==-EOPNOTSUPP);
 event.locked=false;event.vid=1;assert(!fe_switch_replay_fdb(sw,&event) && sw->rule_count==1);
 event.vid=0;event.added_by_user=false;assert(!fe_switch_replay_fdb(sw,&event) && sw->rule_count==1);
 event.added_by_user=true;event.info.dev=&foreign;assert(fe_switch_replay_fdb(sw,&event)==-EOPNOTSUPP);
 event.info.dev=&ports[0];mac[0]=1;assert(fe_switch_replay_fdb(sw,&event)==-EOPNOTSUPP);mac[0]=2;
 /* Replay capacity is keyed by MAC, so a move replaces its owner even when
  * every physical slot is occupied; a new key is rejected, not evicted. */
 for(unsigned int i=0;i<RTL_L2_FDB_ENTRIES;i++){
  struct rtl_l2_fdb_entry entry={.mac={2,0,0,0,i>>8,i},.valid=1,.is_static=1};
  assert(!rtl_l2_fdb_encode(sw->rules[i],&entry));
 }
 sw->rule_count=RTL_L2_FDB_ENTRIES;mac[4]=0xff;mac[5]=0xff;
 assert(fe_switch_replay_fdb(sw,&event)==-ENOSPC && sw->rule_count==RTL_L2_FDB_ENTRIES);
 mac[4]=0;mac[5]=1;event.info.dev=&ports[4];assert(!fe_switch_replay_fdb(sw,&event));
 rtl_l2_fdb_decode(sw->rules[1],&decoded);assert(decoded.destination==4 && sw->rule_count==RTL_L2_FDB_ENTRIES);
 sw->replaying=false;event.info.ctx=NULL;
 fe_switch_atomic_event(&sw->atomic_nb,SWITCHDEV_FDB_ADD_TO_BRIDGE,&event);assert(invalidates==1);
 struct switchdev_obj object={.id=SWITCHDEV_OBJ_ID_PORT_MDB};
 struct switchdev_notifier_port_obj_info port_event={.info={.dev=&ports[0]},.obj=&object};
 for(unsigned int kind=SWITCHDEV_OBJ_ID_PORT_MDB;kind<=SWITCHDEV_OBJ_ID_HOST_MDB;kind++){
  object.id=kind;fe_switch_blocking_event(&sw->blocking_nb,SWITCHDEV_PORT_OBJ_ADD,&port_event);
  fe_switch_blocking_event(&sw->blocking_nb,SWITCHDEV_PORT_OBJ_DEL,&port_event);
 }
 assert(!queues);object.id=SWITCHDEV_OBJ_ID_PORT_VLAN;
 fe_switch_blocking_event(&sw->blocking_nb,SWITCHDEV_PORT_OBJ_ADD,&port_event);assert(queues==1);
 assert(!fe_bridge_stop(sw) && !live && freed==4);cases++;
}
static void netdev_notifications(void){
 reset();struct rtl_fe_bridge *sw=fe_bridge_start(&fe);assert(!IS_ERR(sw));fe.bridge=sw;
 for(unsigned int i=0;i<5;i++)sw->ports[i]=&ports[i];
 sw->master=&master;
 struct netdev_notifier_changeupper_info event={.info={.dev=&ports[0]},.linking=true};
 const unsigned int changes[]={NETDEV_GOING_DOWN,NETDEV_DOWN,NETDEV_UP,NETDEV_CHANGE,
  NETDEV_CHANGEADDR,NETDEV_CHANGEUPPER,NETDEV_CHANGEINFODATA};
 /* Synchronous invalidation must happen in the early GOING_DOWN callback,
  * not just after ndo_stop in DOWN. Actual gate MMIO/races have own tests. */
 for(unsigned int i=0;i<sizeof(changes)/sizeof(changes[0]);i++){
  unsigned int before=invalidates;
  assert(!fe_switch_netdev_event(&sw->netdev_nb,changes[i],&event));
  assert(invalidates==before+1 && !fe.lock && !gates);
 }
 unsigned int before=invalidates;
 event.info.dev=&foreign;assert(!fe_switch_netdev_event(&sw->netdev_nb,NETDEV_GOING_DOWN,&event));
 assert(invalidates==before);
 event.info.dev=&master;assert(!fe_switch_netdev_event(&sw->netdev_nb,NETDEV_GOING_DOWN,&event));
 assert(invalidates==before+1);
 rtnl_lock();event.info.dev=&ports[0];event.linking=false;
 assert(!fe_switch_netdev_event(&sw->netdev_nb,NETDEV_PRECHANGEUPPER,&event));
 assert(gates==1 && unoffloads==1 && sw->ports[0]==&ports[0]);
 restore_error=-ETIMEDOUT;
 assert(fe_switch_netdev_event(&sw->netdev_nb,NETDEV_UNREGISTER,&event)==-ETIMEDOUT);
 assert(gates==2 && unoffloads==2 && !sw->ports[0]);
 rtnl_unlock();restore_error=0;
 assert(!fe_bridge_stop(sw) && !live && freed==4);cases++;
}
int main(void){construction_and_stop();notifier_and_replay();netdev_notifications();
 printf("Native switch production control: %u allocation/registration/stop/replay/early-down scenarios; 2048 ordinary-learning notifications do not rebuild; quarantine retains owners and cancels every callback before free PASS\n",cases);return 0;}
'''

definitions = "\n".join(re.search(pattern, source, re.S)[0] for pattern in [
    r"enum fe_switch_reason \{.*?\n\};",
    r"struct fe_switch_learned \{.*?\n\};",
    r"struct rtl_fe_bridge \{.*?\n\};",
])
functions = "\n".join(function(name) for name in [
    "fe_switch_queue", "fe_switch_port_index", "fe_switch_replay_fdb",
    "fe_switch_atomic_event", "fe_switch_blocking_event", "fe_switch_netdev_event", "fe_bridge_start", "fe_bridge_stop",
])
with tempfile.TemporaryDirectory(prefix="l2-switch-control-") as directory:
    temporary = Path(directory)
    (temporary / "test.c").write_text(COMMON + definitions + BACKEND + functions + TEST)
    subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-I", str(DRIVERS),
                    str(temporary / "test.c"), "-o", str(temporary / "test")], check=True)
    environment = dict(os.environ)
    environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
    subprocess.run([str(temporary / "test")], check=True, env=environment)
(ROOT / "artifacts").mkdir(exist_ok=True)
(ROOT / "artifacts/l2-switch-control.json").write_text(json.dumps({
    "production_functions_sha256": hashlib.sha256(functions.encode()).hexdigest(),
    "scope": "production constructor/destructor, notifier filtering and static replay; workqueue/HW operations stubbed",
    "hardware_verified": False,
}, indent=2) + "\n")
