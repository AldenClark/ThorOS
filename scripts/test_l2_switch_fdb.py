#!/usr/bin/env python3
"""Execute production native-domain rollback and full-scan FDB reconciliation.

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
#define FE_LAN_PORTS 5
#define ETH_ALEN 6
#define HZ 100
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
struct rtl_fe_switch_hw {bool owned,drained; int drain_error,restore_error; unsigned int drains,restores;};
struct rtl9617c_switch_guard {struct rtl_fe_bridge *owner;u64 generation;unsigned int invalidations;};
struct fe_switch_learned {u8 address[6];u8 port;};
'''

BACKEND = r'''
struct rtl_fe_bridge {
 struct rtl_fe *fe;struct rtl9617c_switch_guard guard;struct rtl_fe_switch_hw hw;
 struct net_device *ports[5];struct delayed_work scan_work;struct work_struct work;
 struct fe_switch_learned *learned,*next;unsigned int learned_count,pending_count;
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
static unsigned int learn_calls,fail_learn_at,epoch_on_learn,protected_mac,unoffloads;
struct feedback {bool add;unsigned int port;u8 mac[6];};
static struct feedback events[32];static unsigned int event_count,cases;
static bool is_valid_ether_addr(const u8 *mac) {
 unsigned int any=0;for(unsigned int i=0;i<6;i++)any|=mac[i];return any && !(mac[0]&1);
}
static void ether_addr_copy(u8 *to,const u8 *from){memcpy(to,from,6);}
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
 assert(io->context->lock && start<RTL_L2_FDB_ENTRIES);scans++;
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
 assert(rtnl_held && event_count<32);learn_calls++;
 if(epoch_on_learn && learn_calls==epoch_on_learn)rtl9617c_switch_guard_invalidate(guard);
 if(generation!=guard->generation || !guard->owner->active)return -EAGAIN;
 if(fail_learn_at && learn_calls==fail_learn_at)return -ENOMEM;
 events[event_count]=(struct feedback){.add=true,.port=dev->port};
 memcpy(events[event_count++].mac,address,6);return 0;
}
static bool br_rtl9617c_fdb_forget(struct net_device *dev,const u8 *address){
 assert(rtnl_held && event_count<32);
 if(protected_mac && address[5]==protected_mac)return false;
 events[event_count]=(struct feedback){.add=false,.port=dev->port};
 memcpy(events[event_count++].mac,address,6);return true;
}
static void switchdev_bridge_port_unoffload(struct net_device *dev,struct rtl_fe_bridge *owner,
 struct notifier_block *atomic,struct notifier_block *blocking){
 assert(rtnl_held && !fe.lock && dev && owner==&sw && atomic==&sw.atomic_nb && blocking==&sw.blocking_nb);
 unoffloads++;
}
static void sort(void *base,size_t count,size_t bytes,int (*compare)(const void *,const void *),void *swap){
 assert(!swap);qsort(base,count,bytes,compare);
}
static void mod_delayed_work(unsigned int queue,struct delayed_work *work,unsigned int delay){
 assert(queue==system_long_wq && delay==HZ && fe.lock && rtnl_held);work->work.queued++;
}
static void setup(void){
 memset(&fe,0,sizeof(fe));memset(&sw,0,sizeof(sw));memset(first,0,sizeof(first));memset(second,0,sizeof(second));
 memset(rows,0,sizeof(rows));memset(used,0,sizeof(used));
 sw.fe=&fe;fe.bridge=&sw;fe.engine_ready=true;sw.requested=true;sw.guard.owner=&sw;sw.learned=first;sw.next=second;
 sw.native_mask=3;sw.active=true;sw.hw.owned=true;status_override=-1;
 scans=deletes=appends=fail_scan_at=fail_delete_at=event_count=0;
 learn_calls=fail_learn_at=epoch_on_learn=protected_mac=unoffloads=0;
 command_error=0;pending=epoch_change=rtnl_held=relocate_delete=retain_delete=policy_blocked=false;
 for(unsigned int i=0;i<5;i++){ports[i]=(struct net_device){.port=i,.bridge=true};sw.ports[i]=&ports[i];}
}
static void put_row(unsigned int index,unsigned int mac,unsigned int port,unsigned int vid,bool permanent){
 struct rtl_l2_fdb_entry entry={.mac={2,0,0,0,0,mac},.valid=1,.destination=port,.key_vid=vid,
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
int main(void){domain_and_rollback();scan_reconciliation();
 printf("Native switch production FDB: %u rollback/status/scan scenarios; foreign-domain preservation, ambiguous mutation ownership, drain-before-delete, complete-scan-only ageing and move ordering passed\n",cases);
 return 0;}
'''

enum = re.search(r"enum fe_switch_reason \{.*?\n\};", source, re.S)[0]
functions = "\n".join(function(name) for name in [
    "fe_switch_native_key", "fe_switch_learned_owned", "fe_switch_fdb_write",
    "fe_switch_domain_claim", "fe_switch_domain_flush", "fe_switch_restore_locked",
    "fe_switch_feedback", "fe_switch_unoffload", "fe_switch_learned_compare", "fe_switch_scan",
])
with tempfile.TemporaryDirectory(prefix="l2-switch-fdb-") as directory:
    temporary = Path(directory)
    (temporary / "test.c").write_text(COMMON + enum + BACKEND + functions + TEST)
    subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-I", str(DRIVERS),
                    str(temporary / "test.c"), "-o", str(temporary / "test")], check=True)
    environment = dict(os.environ)
    environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
    subprocess.run([str(temporary / "test")], check=True, env=environment)
(ROOT / "artifacts").mkdir(exist_ok=True)
(ROOT / "artifacts/l2-switch-fdb.json").write_text(json.dumps({
    "production_functions_sha256": hashlib.sha256(functions.encode()).hexdigest(),
    "scope": "production FDB domain/restore/scan orchestration with hardware-command fault injection",
    "hardware_verified": False,
}, indent=2) + "\n")
