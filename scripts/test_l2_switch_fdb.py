#!/usr/bin/env python3
"""Execute production native-domain rollback and bounded FDB reconciliation.

The backend represents hardware command outcomes, including a mutation whose
completion times out. No policy/ownership logic is copied into the backend.
The real table transport and SDK wire layout have separate regression gates.
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
SOURCE = DRIVERS / "rtl9617c-fe-switch.h"
source = SOURCE.read_text()


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
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "rtl9617c-l2-format.h"
typedef uint32_t u32; typedef uint64_t u64; typedef unsigned char u8;
/* Match Linux's task accessor macro: a local variable named current must
 * fail this host build just as it does in the real ARM64 kernel. */
struct task_struct {unsigned int unused;};
static inline struct task_struct *get_current(void){return NULL;}
#define current get_current()
#define FE_LAN_PORTS 5
#define ETH_ALEN 6
#define HZ 100
#define NSEC_PER_MSEC 1000000U
#define BIT(n) (1U<<(n))
#define READ_ONCE(value) (value)
#define WRITE_ONCE(target,value) ((target)=(value))
#define system_long_wq 7
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define to_delayed_work(p) container_of(p,struct delayed_work,work)
struct work_struct {unsigned int queued;};
struct delayed_work {struct work_struct work;};
struct net_device {unsigned int port; bool bridge;};
struct notifier_block {unsigned int unused;};
struct rtl_fe_bridge;
struct rtl_fe {int lock; bool shutting_down,engine_ready; struct rtl_fe_bridge *bridge;};
struct rtl_dq_io {struct rtl_fe *context;};
struct rtl_l2_fdb_result {unsigned int raw,status,index,words[4];};
struct rtl_fe_switch_hw {bool owned,drained; int drain_error,restore_error; unsigned int drains,restores;u32 learning_mask;};
struct rtl9617c_switch_guard {struct rtl_fe_bridge *owner;u64 generation;unsigned int invalidations;};
struct fe_switch_learned {u8 address[6];u8 port;};
struct fe_switch_published {u8 address[6];u8 destination;u64 cookie;};
'''

BACKEND = r'''
struct rtl_fe_bridge {
 struct rtl_fe *fe;struct rtl9617c_switch_guard guard;struct rtl_fe_switch_hw hw;
 struct net_device *ports[5],*master;struct delayed_work scan_work;struct work_struct work;
 struct fe_switch_published *published;unsigned int published_count;
 struct fe_switch_learned *learned,*next;unsigned int learned_count,pending_count;
 unsigned int scan_start,scan_count,scan_old,scan_cursor;u64 scan_generation;
 bool scan_running,scan_complete,scan_removed;
 struct notifier_block atomic_nb,blocking_nb;u32 offloaded;
 unsigned int rules[RTL_L2_FDB_ENTRIES][4],rule_count;
 bool stopping,active,domain_owned,requested;u32 native_mask;
 int error;enum fe_switch_reason reason;
 u64 polls,scan_errors,learned_adds,learned_deletes;
};
static struct rtl_fe fe;
static struct rtl_fe_bridge sw;
static struct net_device ports[5];
static struct fe_switch_learned first[RTL_L2_FDB_ENTRIES],second[RTL_L2_FDB_ENTRIES];
static unsigned int rows[RTL_L2_FDB_ENTRIES][4];static bool used[RTL_L2_FDB_ENTRIES];
static unsigned int scans,deletes,appends,fail_scan_at,fail_delete_at;
static int command_error,status_override;
static bool pending,epoch_change,rtnl_held,relocate_delete,retain_delete;
static bool policy_blocked;
static unsigned int learn_calls,fail_learn_at,epoch_on_learn,epoch_after_learn,epoch_on_forget,protected_mac,unoffloads;
static u64 nanoseconds,operation_ns;
static unsigned long last_delay;
static unsigned int max_slice_operations;
static unsigned int change_during_sort;
struct feedback {bool add;unsigned int port;u8 mac[6];};
static struct feedback events[RTL_L2_FDB_ENTRIES*4];static unsigned int event_count,cases;
static bool is_valid_ether_addr(const u8 *mac) {
 unsigned int any=0;for(unsigned int i=0;i<6;i++)any|=mac[i];return any && !(mac[0]&1);
}
static void ether_addr_copy(u8 *to,const u8 *from){memcpy(to,from,6);}
static u64 ktime_get_ns(void){return nanoseconds;}
static struct rtl_dq_io fe_io(struct rtl_fe *owner){return (struct rtl_dq_io){owner};}
static void mutex_lock(int *lock){assert(!*lock);*lock=1;}
static void mutex_unlock(int *lock){assert(*lock);*lock=0;}
static void rtnl_lock(void){assert(!rtnl_held);rtnl_held=true;}
static void rtnl_unlock(void){assert(rtnl_held);rtnl_held=false;}
static u64 rtl9617c_switch_guard_generation(struct rtl9617c_switch_guard *guard){return guard->generation;}
static bool rtl9617c_switch_guard_blocked(struct rtl9617c_switch_guard *guard){assert(guard==&sw.guard);return policy_blocked;}
static void fe_switch_queue(struct rtl_fe_bridge *owner){assert(owner==&sw && !owner->stopping);owner->work.queued++;}
static void rtl9617c_switch_guard_invalidate(struct rtl9617c_switch_guard *guard){
 guard->generation++;guard->invalidations++;guard->owner->active=false;
}
static int fe_switch_hw_drain(struct rtl_fe *owner,struct rtl_fe_switch_hw *hw){
 assert(owner->lock);hw->drains++;
 if(hw->drain_error)return hw->drain_error;
 if(pending)return -EBUSY;
 hw->drained=true;return 0;
}
static int fe_switch_hw_restore(struct rtl_fe *owner,struct rtl_fe_switch_hw *hw){
 assert(owner->lock && hw->drained && !pending && !sw.domain_owned);hw->restores++;
 if(hw->restore_error)return hw->restore_error;
 hw->owned=false;return 0;
}
static int rtl_l2_fdb_scan(const struct rtl_dq_io *io,unsigned int start,struct rtl_l2_fdb_result *out){
 assert(io->context->lock && start<RTL_L2_FDB_ENTRIES);scans++;nanoseconds+=operation_ns;
 if(pending)return -EBUSY;
 if(fail_scan_at && scans==fail_scan_at)return -ETIMEDOUT;
 if(epoch_change){epoch_change=false;rtl9617c_switch_guard_invalidate(&sw.guard);}
 for(unsigned int index=start;index<RTL_L2_FDB_ENTRIES;index++)if(used[index]){
  *out=(struct rtl_l2_fdb_result){.index=index,.status=5,.raw=index*16+5};
  memcpy(out->words,rows[index],sizeof(out->words));return 1;
 }
 return 0;
}
static bool same_key(const unsigned int *a,const unsigned int *b){
 struct rtl_l2_fdb_entry left,right;rtl_l2_fdb_decode(a,&left);rtl_l2_fdb_decode(b,&right);
 return !memcmp(left.mac,right.mac,6) && left.key_vid==right.key_vid &&
  left.key_sc==right.key_sc && left.key_dot1p==right.key_dot1p;
}
static int rtl_l2_fdb_command(const struct rtl_dq_io *io,enum rtl_l2_fdb_command command,
 unsigned int start,const unsigned int *words,struct rtl_l2_fdb_result *out){
 assert(io->context->lock && !start && (command==RTL_L2_FDB_APPEND || command==RTL_L2_FDB_DELETE));
 if(pending)return -EBUSY;
 unsigned int found=RTL_L2_FDB_ENTRIES,free_slot=RTL_L2_FDB_ENTRIES;
 for(unsigned int i=0;i<RTL_L2_FDB_ENTRIES;i++){
  if(used[i] && same_key(rows[i],words)){found=i;break;}
  if(!used[i] && free_slot==RTL_L2_FDB_ENTRIES)free_slot=i;
 }
 unsigned int status=5;
 if(command==RTL_L2_FDB_DELETE){
  assert(sw.hw.drained);deletes++;
  if(found<RTL_L2_FDB_ENTRIES){
   if(!retain_delete)used[found]=false;
   if(relocate_delete && !retain_delete){
    for(unsigned int i=found+1;i<RTL_L2_FDB_ENTRIES;i++)if(used[i]){
     memcpy(rows[found],rows[i],sizeof(rows[i]));used[found]=true;used[i]=false;break;
    }
   }
  }else status=15;
 } else {
  appends++;
  if(found==RTL_L2_FDB_ENTRIES)found=free_slot;
  if(found==RTL_L2_FDB_ENTRIES)status=10;
  else if(status_override!=10){used[found]=true;memcpy(rows[found],words,16);}
 }
 if(command_error || (fail_delete_at && deletes==fail_delete_at)){
  pending=true;return command_error?command_error:-ETIMEDOUT;
 }
 *out=(struct rtl_l2_fdb_result){.status=status_override<0?status:(unsigned int)status_override,.index=found};
 return 0;
}
static bool netif_is_bridge_port(struct net_device *dev){return dev->bridge;}
static int br_rtl9617c_fdb_learn(struct net_device *dev,const u8 *address,
 struct rtl9617c_switch_guard *guard,u64 generation){
 assert(rtnl_held && event_count<RTL_L2_FDB_ENTRIES*4);learn_calls++;nanoseconds+=operation_ns;
 if(epoch_on_learn && learn_calls==epoch_on_learn)rtl9617c_switch_guard_invalidate(guard);
 if(generation!=guard->generation || !guard->owner->active)return -EAGAIN;
 if(fail_learn_at && learn_calls==fail_learn_at)return -ENOMEM;
 events[event_count]=(struct feedback){.add=true,.port=dev->port};
 memcpy(events[event_count++].mac,address,6);
 if(epoch_after_learn && learn_calls==epoch_after_learn)rtl9617c_switch_guard_invalidate(guard);
 return 0;
}
static bool br_rtl9617c_fdb_forget(struct net_device *dev,const u8 *address){
 assert(rtnl_held && event_count<RTL_L2_FDB_ENTRIES*4);nanoseconds+=operation_ns;
 if(protected_mac && address[5]==protected_mac)return false;
 if(epoch_on_forget){epoch_on_forget=0;rtl9617c_switch_guard_invalidate(&sw.guard);}
 events[event_count]=(struct feedback){.add=false,.port=dev->port};
 memcpy(events[event_count++].mac,address,6);return true;
}
static bool br_rtl9617c_fdb_unoffload(const struct net_device *master,const u8 *address,
 unsigned short vid,struct rtl9617c_switch_guard *guard,u64 cookie){
 assert(rtnl_held && !fe.lock && master && address && !vid && guard==&sw.guard && cookie);
 /* Static-cookie publication has its own real-worker regression. None of
  * this dynamic scan test's rows has a published static owner. */
 assert(!"unexpected static publication in dynamic scan fixture");
 return false;
}
static void switchdev_bridge_port_unoffload(struct net_device *dev,struct rtl_fe_bridge *owner,
 struct notifier_block *atomic,struct notifier_block *blocking){
 assert(rtnl_held && !fe.lock && dev && owner==&sw && atomic==&sw.atomic_nb && blocking==&sw.blocking_nb);
 unoffloads++;
}
static void sort(void *base,size_t count,size_t bytes,int (*compare)(const void *,const void *),void *swap){
 assert(!swap && rtnl_held && !fe.lock);
 /* FE transactions can run while sorting without borrowing any device
  * pointer. An invalidation there must still prevent all feedback. */
 mutex_lock(&fe.lock);
 if(change_during_sort==1)rtl9617c_switch_guard_invalidate(&sw.guard);
 if(change_during_sort==2)sw.stopping=true;
 if(change_during_sort==3)fe.shutting_down=true;
 mutex_unlock(&fe.lock);
 qsort(base,count,bytes,compare);
}
static void mod_delayed_work(unsigned int queue,struct delayed_work *work,unsigned int delay){
 assert(queue==system_long_wq && (delay==HZ || delay==0) && fe.lock && rtnl_held);
 last_delay=delay;work->work.queued++;
}
static void setup(void){
 memset(&fe,0,sizeof(fe));memset(&sw,0,sizeof(sw));memset(first,0,sizeof(first));memset(second,0,sizeof(second));
 memset(rows,0,sizeof(rows));memset(used,0,sizeof(used));
 sw.fe=&fe;fe.bridge=&sw;fe.engine_ready=true;sw.requested=true;sw.guard.owner=&sw;sw.learned=first;sw.next=second;
 sw.native_mask=3;sw.active=true;sw.hw.owned=true;sw.hw.learning_mask=3;status_override=-1;
 scans=deletes=appends=fail_scan_at=fail_delete_at=event_count=0;
 learn_calls=fail_learn_at=epoch_on_learn=epoch_after_learn=epoch_on_forget=protected_mac=unoffloads=0;
 nanoseconds=operation_ns=last_delay=0;
 change_during_sort=0;
 command_error=0;pending=epoch_change=rtnl_held=relocate_delete=retain_delete=policy_blocked=false;
 for(unsigned int i=0;i<5;i++){ports[i]=(struct net_device){.port=i,.bridge=true};sw.ports[i]=&ports[i];}
}
static void put_row(unsigned int index,unsigned int mac,unsigned int port,unsigned int vid,bool permanent){
 struct rtl_l2_fdb_entry entry={.mac={2,0,0,0,mac>>8,mac},.valid=1,.destination=port,.key_vid=vid,
  .is_static=permanent,.sa_permit=1,.da_permit=1};
 assert(index<RTL_L2_FDB_ENTRIES && !rtl_l2_fdb_encode(rows[index],&entry));used[index]=true;
}
'''

TEST = r'''
static void domain_and_rollback(void){
 setup();put_row(0,1,0,0,false);mutex_lock(&fe.lock);
 assert(fe_switch_domain_claim(&sw)==-EEXIST && !sw.domain_owned && !deletes);
 assert(!fe_switch_domain_flush(&sw) && used[0]);mutex_unlock(&fe.lock);cases++;
 /* Global age-time ownership forbids every foreign dynamic domain too. */
 setup();put_row(1,2,7,100,false);mutex_lock(&fe.lock);
 assert(fe_switch_domain_claim(&sw)==-EEXIST && !sw.domain_owned && used[1] && !deletes);
 mutex_unlock(&fe.lock);cases++;
 setup();put_row(1,2,7,100,true);put_row(4127,3,63,4095,true);mutex_lock(&fe.lock);
 assert(!fe_switch_domain_claim(&sw) && sw.domain_owned);
 assert(!fe_switch_restore_locked(&sw));assert(used[1] && used[4127] && !deletes && !sw.hw.owned);mutex_unlock(&fe.lock);cases++;
 setup();put_row(1,2,7,100,true);fail_scan_at=2;mutex_lock(&fe.lock);
 assert(fe_switch_domain_claim(&sw)==-ETIMEDOUT && !sw.domain_owned && !deletes);mutex_unlock(&fe.lock);cases++;
 for(unsigned int phase=0;phase<4;phase++){
  setup();sw.domain_owned=true;put_row(0,1,0,0,false);put_row(4,2,1,0,true);put_row(11,3,7,100,false);
  if(phase==0)sw.hw.drain_error=-ETIMEDOUT;
  if(phase==1)fail_scan_at=1;
  if(phase==2)fail_delete_at=1;
  if(phase==3)sw.hw.restore_error=-EIO;
  mutex_lock(&fe.lock);assert(fe_switch_restore_locked(&sw)<0);
  assert(sw.hw.owned && sw.reason==FE_SWITCH_IO_ERROR && used[11]);
  if(phase<3)assert(sw.domain_owned);
  if(phase==0)assert(!scans && !deletes && !sw.hw.restores);
  if(phase==1)assert(!deletes && !sw.hw.restores);
  if(phase==2)assert(pending && !sw.hw.restores);
  sw.hw.drain_error=sw.hw.restore_error=0;fail_scan_at=fail_delete_at=0;pending=false;
  assert(!fe_switch_restore_locked(&sw));assert(!sw.domain_owned && !sw.hw.owned && used[11]);
  assert(!used[0] && !used[4]);mutex_unlock(&fe.lock);cases++;
 }
 for(unsigned int status=0;status<16;status++){
  setup();mutex_lock(&fe.lock);assert(!fe_switch_domain_claim(&sw));
  unsigned int words[4];put_row(0,1,0,0,true);memcpy(words,rows[0],16);used[0]=false;
  status_override=status;
  int ret=fe_switch_fdb_write(&sw,RTL_L2_FDB_APPEND,words);
  assert(ret==(status==5?0:status==10?-ENOSPC:-EIO));assert(sw.domain_owned);
  status_override=-1;assert(!fe_switch_restore_locked(&sw));assert(!used[0]);mutex_unlock(&fe.lock);cases++;
 }
 setup();mutex_lock(&fe.lock);assert(!fe_switch_domain_claim(&sw));
 unsigned int words[4];put_row(0,1,0,0,true);memcpy(words,rows[0],16);used[0]=false;command_error=-ETIMEDOUT;
 assert(fe_switch_fdb_write(&sw,RTL_L2_FDB_APPEND,words)==-ETIMEDOUT && sw.domain_owned && used[0]);
 assert(fe_switch_restore_locked(&sw)==-EBUSY && sw.domain_owned && sw.hw.owned);
 pending=false;command_error=0;assert(!fe_switch_restore_locked(&sw) && !used[0]);mutex_unlock(&fe.lock);cases++;
 /* Deleting a physical slot can relocate an unscanned overflow row. The
  * production flush must collect all keys before issuing the first delete. */
 setup();sw.domain_owned=true;relocate_delete=true;
 put_row(0,1,0,0,false);put_row(2,2,1,0,true);put_row(4,3,0,0,false);put_row(4127,9,7,4095,true);
 mutex_lock(&fe.lock);assert(!fe_switch_restore_locked(&sw));
 unsigned int retained=0;
 for(unsigned int i=0;i<RTL_L2_FDB_ENTRIES;i++)if(used[i]){
  struct rtl_l2_fdb_entry entry;rtl_l2_fdb_decode(rows[i],&entry);assert(entry.key_vid==4095);retained++;
 }
 assert(retained==1 && deletes==3 && !sw.domain_owned && !sw.hw.owned);mutex_unlock(&fe.lock);cases++;
 /* A mid-scan error must not partially delete already discovered keys. */
 setup();sw.domain_owned=true;put_row(0,1,0,0,false);put_row(4,2,1,0,true);fail_scan_at=2;
 mutex_lock(&fe.lock);assert(fe_switch_restore_locked(&sw)==-ETIMEDOUT);
 assert(!deletes && used[0] && used[4] && sw.domain_owned && sw.hw.owned);mutex_unlock(&fe.lock);cases++;
 /* Successful DELETE status is not proof the owned domain is empty. */
 setup();sw.domain_owned=true;put_row(0,1,0,0,false);retain_delete=true;
 mutex_lock(&fe.lock);assert(fe_switch_restore_locked(&sw)==-EIO);
 assert(deletes==1 && used[0] && sw.domain_owned && sw.hw.owned && !sw.hw.restores);
 retain_delete=false;assert(!fe_switch_restore_locked(&sw));
 assert(!sw.domain_owned && !sw.hw.owned);mutex_unlock(&fe.lock);cases++;
 /* Post-delete verification must itself complete before ownership releases. */
 setup();sw.domain_owned=true;put_row(0,1,0,0,false);fail_scan_at=3;
 mutex_lock(&fe.lock);assert(fe_switch_restore_locked(&sw)==-ETIMEDOUT);
 assert(deletes==1 && !used[0] && sw.domain_owned && sw.hw.owned && !sw.hw.restores);
 fail_scan_at=0;assert(!fe_switch_restore_locked(&sw));mutex_unlock(&fe.lock);cases++;
}

static void scan_reconciliation(void){
 setup();sw.learned[0]=(struct fe_switch_learned){.address={2,0,0,0,0,1},.port=0};
 sw.learned[1]=(struct fe_switch_learned){.address={2,0,0,0,0,9},.port=1};sw.learned_count=2;
 put_row(7,2,1,0,false);put_row(20,1,0,0,false);put_row(100,3,0,0,true);put_row(4000,4,7,100,false);
 fe_switch_scan(&sw.scan_work.work);
 assert(sw.polls==1 && sw.learned_count==2 && sw.learned[0].address[5]==1 && sw.learned[1].address[5]==2);
 assert(event_count==3 && !events[0].add && events[0].mac[5]==9 && events[1].add && events[2].add);
 assert(sw.scan_work.work.queued==1 && sw.learned_adds==2 && sw.learned_deletes==1);
 /* A moved key is re-added on its new port, never deleted AFTER that add. */
 event_count=0;used[7]=false;put_row(20,1,1,0,false);fe_switch_scan(&sw.scan_work.work);
 assert(event_count==2 && !events[0].add && events[0].mac[5]==2);
 assert(events[1].add && events[1].mac[5]==1 && events[1].port==1);
 assert(sw.learned_count==1 && sw.learned[0].port==1);cases++;
 /* A failed partial scan must not report any old key absent or refresh it. */
 event_count=0;fail_scan_at=scans+2;unsigned int queued=sw.scan_work.work.queued;
 fe_switch_scan(&sw.scan_work.work);
 assert(!event_count && sw.learned_count==1 && sw.scan_errors==1 && !sw.active);
 assert(sw.guard.invalidations==1 && sw.scan_work.work.queued==queued);cases++;
 sw.active=true;fail_scan_at=0;epoch_change=true;event_count=0;
 fe_switch_scan(&sw.scan_work.work);
 assert(!event_count && sw.learned_count==1 && !sw.active && sw.guard.invalidations==2);cases++;
 for(unsigned int state=0;state<3;state++){
  setup();if(state==0)sw.stopping=true;if(state==1)fe.shutting_down=true;if(state==2)sw.active=false;
  fe_switch_scan(&sw.scan_work.work);assert(!scans && !event_count && !sw.scan_work.work.queued);cases++;
 }
 for(unsigned int condition=0;condition<4;condition++){
  setup();sw.active=false;sw.reason=FE_SWITCH_FOREIGN_FDB;
  if(condition==1)sw.requested=false;
  if(condition==2)fe.engine_ready=false;
  if(condition==3)policy_blocked=true;
  fe_switch_scan(&sw.scan_work.work);assert(!scans && !event_count);
  assert(sw.work.queued==(condition==0));cases++;
 }
 /* A physical scan can see the same moving MAC twice; neither arbitrary
  * destination may overwrite the last committed mirror. */
 setup();sw.learned[0]=(struct fe_switch_learned){.address={2,0,0,0,0,9},.port=0};sw.learned_count=1;
 put_row(0,1,0,0,false);put_row(8,1,1,0,false);
 fe_switch_scan(&sw.scan_work.work);
 assert(!event_count && !sw.polls && sw.learned_count==1 && sw.learned[0].address[5]==9);
 assert(sw.active && sw.scan_work.work.queued==1 && !sw.pending_count);cases++;
 for(unsigned int failure=0;failure<2;failure++){
  setup();sw.learned[0]=(struct fe_switch_learned){.address={2,0,0,0,0,9},.port=0};sw.learned_count=1;
  put_row(0,1,0,0,false);put_row(8,2,1,0,false);
  if(failure)epoch_on_learn=2;else fail_learn_at=2;
  fe_switch_scan(&sw.scan_work.work);
  assert(!sw.active && !sw.polls && sw.pending_count==1 && sw.learned_count==1);
  assert(sw.learned[0].address[5]==9 && sw.next[0].address[5]==1 && sw.scan_errors==1);
  assert(event_count==2 && !events[0].add && events[1].add && events[1].mac[5]==1);
  assert(sw.error==(failure?-EAGAIN:-ENOMEM));
  /* A user converted old key9 to static while hardware was gated. Rollback
   * must preserve that user entry and still erase newly published prefix1. */
  protected_mac=9;event_count=0;sw.offloaded=3;rtnl_lock();fe_switch_unoffload(&sw);rtnl_unlock();
  assert(!sw.pending_count && !sw.learned_count && !sw.offloaded && unoffloads==2);
  assert(event_count==1 && !events[0].add && events[0].mac[5]==1);cases++;
 }
}
static void scan_slice(void){
 unsigned int before=scans,feedback=event_count;
 unsigned int queued=sw.scan_work.work.queued;
 const u64 previous_state[]={sw.scan_start,sw.scan_count,sw.scan_old,sw.scan_cursor,
  sw.scan_running,sw.scan_complete,sw.scan_removed,sw.scan_generation};
 fe_switch_scan(&sw.scan_work.work);
 assert(!fe.lock && !rtnl_held);
 assert(sw.scan_work.work.queued-queued<=1);
 if(sw.scan_work.work.queued!=queued && !last_delay){
  const u64 next_state[]={sw.scan_start,sw.scan_count,sw.scan_old,sw.scan_cursor,
   sw.scan_running,sw.scan_complete,sw.scan_removed,sw.scan_generation};
  assert(sw.active && sw.scan_running && memcmp(previous_state,next_state,sizeof(next_state)));
 }
 unsigned int operations=scans-before+event_count-feedback;
 if(operations>max_slice_operations)max_slice_operations=operations;
 /* The independent contract is 64 boundary operations, not a copied
  * driver constant. Merge-only work also consumes the driver's budget. */
 assert(operations<=64);
 /* A different FE/RTNL owner can run at every continuation boundary. */
 rtnl_lock();mutex_lock(&fe.lock);mutex_unlock(&fe.lock);rtnl_unlock();
}
static void finish_scan(void){
 u64 before=sw.polls;unsigned int slices=0;
 do {scan_slice();assert(++slices<20000);}while(sw.active && sw.polls==before && sw.scan_running);
}
static unsigned int address_id(const u8 *address){return (address[4]<<8)|address[5];}
static void put_old(unsigned int count){
 sw.learned_count=count;
 for(unsigned int i=0;i<count;i++){
  unsigned int key=8192+i;
  sw.learned[i]=(struct fe_switch_learned){.address={2,0,0,0,key>>8,key},.port=i&1};
 }
}
static void put_many(unsigned int count){
 for(unsigned int i=0;i<count;i++)put_row(i,i+1,i&1,0,false);
}
static void bounded_scale_and_moves(void){
 const unsigned int sizes[]={0,1,63,64,65,127,128,129,RTL_L2_FDB_ENTRIES-1,RTL_L2_FDB_ENTRIES};
 for(unsigned int size=0;size<sizeof(sizes)/sizeof(sizes[0]);size++){
  unsigned int count=sizes[size];setup();put_old(count);put_many(count);
  struct fe_switch_learned *committed=sw.learned;unsigned int slices=0;
  do {
   scan_slice();assert(++slices<1000);
   if(!sw.polls){
    assert(sw.learned==committed && sw.learned_count==count && sw.scan_running && last_delay==0);
    if(count)assert(address_id(sw.learned[0].address)==8192);
    /* No prefix can imply that any old MAC disappeared. */
    if(!sw.scan_complete)assert(!event_count && !sw.pending_count);
   }
  }while(!sw.polls);
  assert(sw.learned_count==count && sw.polls==1 && !sw.pending_count && !sw.scan_running);
  assert(!sw.scan_start && !sw.scan_count && !sw.scan_cursor && !sw.scan_old && last_delay==HZ);
  assert(event_count==count*2 && sw.learned_adds==count && sw.learned_deletes==count);
  for(unsigned int i=0;i<count;i++){
   assert(!events[i].add && address_id(events[i].mac)==8192+i);
   assert(events[count+i].add && address_id(events[count+i].mac)==i+1);
   assert(address_id(sw.learned[i].address)==i+1 && sw.learned[i].port==(i&1));
  }
  if(count>64)assert(slices>1);
  cases++;
 }
 /* A same-slot MAC move on the next complete poll must update its port,
  * never delete the newly moved key using the old committed destination. */
 setup();put_many(129);finish_scan();assert(sw.polls==1 && sw.learned[0].port==0);
 event_count=0;put_row(0,1,1,0,false);finish_scan();
 assert(sw.polls==2 && sw.learned_count==129 && sw.learned[0].port==1 && event_count==129);
 for(unsigned int i=0;i<event_count;i++)assert(events[i].add);
 cases++;
 /* A move which crosses slice boundaries can expose both old and new
  * slots. Reject the entire duplicate-key snapshot, not only its tail. */
 setup();put_old(1);put_many(129);scan_slice();assert(sw.scan_count==64 && !event_count);
 used[0]=false;put_row(128,1,1,0,false);finish_scan();
 assert(!sw.polls && sw.active && !sw.scan_running && !sw.pending_count && !event_count && last_delay==HZ);
 assert(sw.learned_count==1 && address_id(sw.learned[0].address)==8192);
 finish_scan();assert(sw.polls==1 && sw.learned_count==128 && sw.learned[0].port==1);cases++;
}
static void bounded_time_and_generation(void){
 /* Even a small table must yield when a single indirect operation uses
  * the elapsed-time budget. Elapsed monotonic nanoseconds work below one
  * HZ=100 tick and their unsigned difference also survives wrap. */
 for(unsigned int wrap=0;wrap<2;wrap++){
  setup();put_many(65);operation_ns=2*NSEC_PER_MSEC;
  if(wrap)nanoseconds=UINT64_MAX-1;
  scan_slice();assert(scans==1 && sw.scan_count==1 && !event_count && last_delay==0);
  finish_scan();assert(sw.polls==1 && sw.learned_count==65 && last_delay==HZ);cases++;
 }
 /* An inactive guard drops an unfinished physical scan, with the old
  * complete mirror retained until the normal unoffload withdrawal. */
 setup();put_old(1);put_many(129);scan_slice();assert(sw.scan_start==64 && sw.scan_count==64);
 rtl9617c_switch_guard_invalidate(&sw.guard);scan_slice();
 assert(!sw.scan_running && !sw.scan_start && !sw.scan_count && !event_count && sw.learned_count==1);
 rtnl_lock();fe_switch_unoffload(&sw);rtnl_unlock();
 assert(!sw.learned_count && !sw.pending_count);cases++;
 /* Defense in depth for an armed but different epoch: old buffered MACs
  * must not leak into the restarted physical scan. */
 setup();put_many(129);scan_slice();assert(sw.scan_count==64);
 for(unsigned int i=0;i<129;i++)put_row(i,1000+i,i&1,0,false);
 sw.guard.generation++;finish_scan();
 assert(sw.polls==1 && sw.learned_count==129 && address_id(sw.learned[0].address)==1000);
 for(unsigned int i=0;i<event_count;i++)assert(address_id(events[i].mac)>=1000);
 cases++;
 /* Rebuild/unoffload can replace the table without an epoch increment. */
 setup();put_many(129);scan_slice();u64 epoch=sw.guard.generation;
 rtnl_lock();fe_switch_unoffload(&sw);rtnl_unlock();
 assert(!sw.scan_running && !sw.scan_start && !sw.scan_count && sw.guard.generation==epoch);
 memset(used,0,sizeof(used));put_row(3,77,1,0,false);finish_scan();
 assert(sw.polls==1 && sw.learned_count==1 && address_id(sw.learned[0].address)==77);cases++;
 /* A feedback prefix is retained on invalidation until unoffload. In
  * particular resetting the phase must not erase its ownership count. */
 for(unsigned int armed=0;armed<2;armed++){
  setup();put_many(129);
  do {scan_slice();}while(!sw.pending_count);
  unsigned int prefix=sw.pending_count;assert(prefix && prefix<129 && !sw.polls);
  if(armed)sw.guard.generation++;else rtl9617c_switch_guard_invalidate(&sw.guard);
  scan_slice();assert(!sw.active && !sw.scan_running && sw.pending_count==prefix && !sw.polls);
  event_count=0;rtnl_lock();fe_switch_unoffload(&sw);rtnl_unlock();
  assert(!sw.pending_count && !sw.learned_count && event_count==prefix);
  for(unsigned int i=0;i<prefix;i++)assert(!events[i].add && address_id(events[i].mac)==i+1);
  cases++;
 }
 /* Policy can close after the last add succeeds, or in a delete-only
  * round. Neither boundary may swap the buffers or commit that epoch. */
 for(unsigned int adding=0;adding<2;adding++){
  setup();put_old(1);
  if(adding){put_many(65);epoch_after_learn=65;}else epoch_on_forget=1;
  finish_scan();
  assert(!sw.active && !sw.scan_running && !sw.polls && sw.learned_count==1 &&
   sw.pending_count==(adding?65:0) && address_id(sw.learned[0].address)==8192);
  event_count=0;rtnl_lock();fe_switch_unoffload(&sw);rtnl_unlock();
  assert(!sw.pending_count && !sw.learned_count && event_count==(adding?66:1));cases++;
 }
 for(unsigned int change=1;change<=3;change++){
  setup();put_old(1);put_many(65);change_during_sort=change;finish_scan();
  assert(!sw.scan_running && !sw.polls && sw.learned_count==1 && !sw.pending_count && !event_count);cases++;
 }
}
static void learning_mask_policy(void){
 /* Programmed learning permission and the native forwarding subset must
  * BOTH authorize a destination. A leftover dynamic row on a learning-off
  * or CPU-only STP port must never be published back into the bridge. */
 for(unsigned int native=1;native<32;native++)for(unsigned int learning=0;learning<32;learning++){
  setup();sw.native_mask=native;sw.hw.learning_mask=learning;
  unsigned int count=0;
  for(unsigned int port=0;port<5;port++){
   put_row(port,port+1,port,0,false);
   if((native&learning)&BIT(port))count++;
  }
  finish_scan();
  assert(sw.polls==1 && sw.learned_count==count && event_count==count && learn_calls==count);
  for(unsigned int i=0;i<count;i++){
   assert(events[i].add && ((native&learning)&BIT(events[i].port)));
   assert(sw.learned[i].port==events[i].port && address_id(events[i].mac)==events[i].port+1);
  }
  cases++;
 }
 /* Withdraw an old owned mirror when its source learning is disabled,
  * without treating the still-visible silicon row as fresh permission. */
 setup();put_row(0,1,0,0,false);put_row(1,2,1,0,false);finish_scan();
 assert(sw.learned_count==2 && learn_calls==2);
 event_count=0;learn_calls=0;sw.hw.learning_mask=1;finish_scan();
 assert(sw.learned_count==1 && sw.learned[0].port==0 && learn_calls==1);
 assert(event_count==2 && !events[0].add && events[0].port==1 && address_id(events[0].mac)==2);
 assert(events[1].add && events[1].port==0 && address_id(events[1].mac)==1);cases++;
}
static void batch_fault_matrix(void){
 const unsigned int positions[]={1,64,65,128,129,130};
 for(unsigned int i=0;i<sizeof(positions)/sizeof(positions[0]);i++){
  setup();put_old(1);put_many(129);fail_scan_at=positions[i];finish_scan();
  assert(!sw.active && !sw.scan_running && !sw.polls && !event_count && !sw.pending_count);
  assert(sw.error==-ETIMEDOUT && sw.scan_errors==1 && sw.learned_count==1);cases++;
 }
 for(unsigned int i=0;i<sizeof(positions)/sizeof(positions[0])-1;i++){
  setup();put_old(1);put_many(129);fail_learn_at=positions[i];finish_scan();
  assert(!sw.active && !sw.scan_running && !sw.polls && sw.pending_count==positions[i]-1);
  assert(sw.error==-ENOMEM && sw.scan_errors==1 && sw.learned_count==1);
  unsigned int prefix=sw.pending_count;event_count=0;
  rtnl_lock();fe_switch_unoffload(&sw);rtnl_unlock();
  assert(!sw.pending_count && !sw.learned_count && event_count==prefix+1);
  assert(!events[0].add && address_id(events[0].mac)==8192);
  for(unsigned int j=0;j<prefix;j++)assert(!events[j+1].add && address_id(events[j+1].mac)==j+1);
  cases++;
 }
}
int main(void){domain_and_rollback();scan_reconciliation();bounded_scale_and_moves();bounded_time_and_generation();learning_mask_policy();batch_fault_matrix();
 printf("Native switch production FDB: %u rollback/status/batched-scan scenarios; full 4128-row capacity, timed slices, generation/rebuild restart, partial feedback ownership and MAC moves passed (max %u boundary operations/slice)\n",cases,max_slice_operations);
 return 0;}
'''

enum = re.search(r"enum fe_switch_reason \{.*?\n\};", source, re.S)[0]
constants = "\n" + "\n".join(re.findall(r"^#define FE_SWITCH_SCAN_\w+ .+$", source, re.M)) + "\n"
functions = "\n".join(function(name) for name in [
    "fe_switch_scan_reset", "fe_switch_scan_slice_done", "fe_switch_native_key", "fe_switch_learned_owned", "fe_switch_fdb_write",
    "fe_switch_domain_claim", "fe_switch_domain_flush", "fe_switch_restore_locked",
    "fe_switch_feedback", "fe_switch_unoffload", "fe_switch_learned_compare", "fe_switch_scan",
])
mutants = {
    "scan_ignores_learning_mask": functions.replace(
        "sw->native_mask & sw->hw.learning_mask", "sw->native_mask", 1),
    "scan_ignores_native_subset": functions.replace(
        "sw->native_mask & sw->hw.learning_mask", "sw->hw.learning_mask", 1),
    "unbounded_mmio_batch": functions.replace(
        "\treturn operations >= FE_SWITCH_SCAN_BUDGET ||",
        "\treturn false ||", 1),
    "elapsed_time_ignored": functions.replace(
        "(operations && ktime_get_ns() - started >=",
        "(operations && false && ktime_get_ns() - started >=", 1),
    "sort_keeps_shared_fe_lock": functions.replace(
        "\t\tmutex_unlock(&sw->fe->lock);\n\t\tsort(sw->next, sw->scan_count, sizeof(*sw->next),\n\t\t     fe_switch_learned_compare, NULL);\n\t\tmutex_lock(&sw->fe->lock);",
        "\t\tsort(sw->next, sw->scan_count, sizeof(*sw->next),\n\t\t     fe_switch_learned_compare, NULL);", 1),
    "sort_policy_change_not_rechecked": functions.replace(
        "\t\tif (sw->stopping || sw->fe->shutting_down || !sw->active ||\n\t\t    generation != rtl9617c_switch_guard_generation(&sw->guard))\n\t\t\tgoto out;",
        "", 1),
    "budget_exhaustion_commits_partial_scan": functions.replace(
        "if (fe_switch_scan_slice_done(operations, started))\n\t\t\t\tgoto resume;",
        "if (fe_switch_scan_slice_done(operations, started))\n\t\t\t\tbreak;", 1),
    "epoch_change_reuses_partial_rows": functions.replace(
        "if (sw->scan_running && sw->scan_generation != generation)",
        "if (false && sw->scan_running && sw->scan_generation != generation)", 1),
    "unbounded_feedback_batch": functions.replace(
        "while (sw->scan_cursor < sw->scan_count) {\n\t\tif (fe_switch_scan_slice_done(operations, started))",
        "while (sw->scan_cursor < sw->scan_count) {\n\t\tif (false && fe_switch_scan_slice_done(operations, started))", 1),
    "phase_reset_loses_feedback_ownership": functions.replace(
        "\tsw->scan_running = false;", "\tsw->pending_count = 0;\n\tsw->scan_running = false;", 1),
    "unoffload_keeps_partial_cursor": functions.replace(
        "\tWRITE_ONCE(sw->pending_count, 0);\n\tfe_switch_scan_reset(sw);",
        "\tWRITE_ONCE(sw->pending_count, 0);", 1),
    "duplicate_mac_publishes_arbitrary_owner": functions.replace(
        "if (!fe_switch_learned_compare(&sw->next[cursor - 1],",
        "if (false && !fe_switch_learned_compare(&sw->next[cursor - 1],", 1),
    "last_feedback_epoch_not_checked": functions.replace(
        "\tif (!sw->active || generation !=\n\t    rtl9617c_switch_guard_generation(&sw->guard))\n\t\tgoto out;\n\tswap =",
        "\tswap =", 1),
    "full_poll_loses_hz_throttle": functions.replace(
        "\tsw->polls++;\n\tmod_delayed_work(system_long_wq, &sw->scan_work, HZ);",
        "\tsw->polls++;\n\tmod_delayed_work(system_long_wq, &sw->scan_work, 0);", 1),
    "continuation_without_forward_progress": functions.replace(
        "while (sw->scan_start < RTL_L2_FDB_ENTRIES) {",
        "while (sw->scan_start < RTL_L2_FDB_ENTRIES) {\n\t\t\tgoto resume;", 1),
}
for name, mutated in mutants.items():
    if mutated == functions:
        raise SystemExit(f"Mutation anchor missing: {name}")
environment = dict(os.environ)
environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
with tempfile.TemporaryDirectory(prefix="l2-switch-fdb-") as directory:
    temporary = Path(directory)
    for name, candidate in {"production": functions, **mutants}.items():
        (temporary / "test.c").write_text(COMMON + enum + constants + BACKEND + candidate + TEST)
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-I", str(DRIVERS),
                        str(temporary / "test.c"), "-o", str(temporary / "test")], check=True)
        if name == "production":
            subprocess.run([str(temporary / "test")], check=True, env=environment)
        else:
            result = subprocess.run([str(temporary / "test")], env=environment, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != -6 or "Assertion" not in result.stderr:
                raise SystemExit(f"{name}: expected a contract assertion, got {result.returncode}: {result.stderr}")
            print(f"Runtime regression mutant rejected: {name}", flush=True)
(ROOT / "artifacts").mkdir(exist_ok=True)
(ROOT / "artifacts/l2-switch-fdb.json").write_text(json.dumps({
    "production_functions_sha256": hashlib.sha256(functions.encode()).hexdigest(),
    "scope": "production FDB domain/restore/bounded-scan orchestration with hardware-command fault injection, 4128-row full capacity, 992 native/learning-mask combinations, timed slices, epoch/rebuild interruption and feedback ownership",
    "runtime_mutants_rejected": list(mutants),
    "hardware_verified": False,
}, indent=2) + "\n")
