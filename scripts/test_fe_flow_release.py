#!/usr/bin/env python3
"""Exercise production flow withdrawal, route fault gating and shared resource release."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
drivers = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--revision', help='Run the same teardown oracle against an older production commit')
args = parser.parse_args()
relative = str((drivers / 'rtl9617c-fe.c').relative_to(root))
native = subprocess.check_output(['git', 'show', args.revision + ':' + relative], cwd=root, text=True) if args.revision else (drivers / 'rtl9617c-fe.c').read_text()
indexed = 'struct rtl_fe_destination {' in native
hash_indexed = 'struct rtl_fe_flow **hash_owners;' in native
def function(name):
    start = re.search(r'^.*\b' + name + r'\([^;]*?\)\s*\{',native,re.M).start()
    end = native.index('{',start)+1
    depth = 1
    while depth:
        depth += (native[end]=='{')-(native[end]=='}')
        end += 1
    return native[start:end]+'\n'

common = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "rtl9617c-fe-pipeline.h"
#include "rtl9617c_destination_tree.h"
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
typedef uint32_t __le32;typedef uint64_t u64;
#define ETH_ALEN 6
#define FE_INTERFACES 32
#define FE_SOURCE_MACS 15
#define BIT(n) (1U<<(n))
#define WRITE_ONCE(dst,value) ((dst)=(value))
struct spinlock {bool held;};
#define spin_lock_irqsave(lock,flags) do{(flags)=0;assert(!(lock)->held);(lock)->held=true;}while(0)
#define spin_unlock_irqrestore(lock,flags) do{(void)(flags);assert((lock)->held);(lock)->held=false;}while(0)
static unsigned int dma_barriers;
#define dma_wmb() (++dma_barriers)
#define readl_poll_timeout(address,status,condition,delay,timeout) ((void)(status=0),0)
#define kfree(p) free(p)
struct list_head {struct list_head *next,*prev;};
static void init_list(struct list_head *h){h->next=h->prev=h;}
static void list_add_tail(struct list_head *n,struct list_head *h){n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;}
#define list_for_each_entry_safe(p,n,h,m) for(struct list_head *cursor=(h)->next,*next_cursor=cursor->next;cursor!=(h) && ((p)=container_of(cursor,__typeof__(*(p)),m));cursor=next_cursor,next_cursor=cursor->next)
static void list_del(struct list_head *n){n->prev->next=n->next;n->next->prev=n->prev;}
static void list_move_tail(struct list_head *n,struct list_head *h){list_del(n);list_add_tail(n,h);}
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_first_entry(h,t,m) container_of((h)->next,t,m)
#define min(a,b) ((a)<(b)?(a):(b))
#define list_for_each_entry(p,h,m) for(struct list_head *cursor=(h)->next;cursor!=(h) && ((p)=container_of(cursor,__typeof__(*(p)),m));cursor=cursor->next)
static void __clear_bit(unsigned int bit,unsigned long *words){words[bit/64]&=~(1UL<<(bit%64));}
static void set_bit(unsigned int bit,unsigned long *words){words[bit/64]|=1UL<<(bit%64);}
static bool test_bit(unsigned int bit,unsigned long *words){return (words[bit/64]>>(bit%64))&1;}
static bool ether_addr_equal(const u8 *a,const u8 *b){return !memcmp(a,b,6);}
static bool list_empty(struct list_head *h){return h->next==h;}
struct rtl_fe;
struct net_device {};
struct rtl_fe_port {struct list_head list;struct rtl_fe *fe;struct net_device *netdev;unsigned int source,destination,llid,bindings;bool retired;};
struct rtl_fe_mac {unsigned int users,saved[5];bool ready;u8 address[6];};
struct rtl_fe_interface {unsigned int users,saved,source_mac,pppoe;bool counted,ready;};
struct rtl_fe_mtu {unsigned int users,size,saved;};
struct work_struct {int unused;};
struct delayed_work {struct work_struct work;unsigned int queued,modified,delay;};
#define to_delayed_work(w) container_of(w,struct delayed_work,work)
struct rtl_fe {
 struct list_head flows,ports,retries;
 struct rb_root cookies,destinations;
 unsigned int destination_count;
 struct rtl_fe_flow **hash_owners;
 void *memory;
 struct rtl_fe_mac source_macs[15];
 struct rtl_fe_interface interfaces[32];
 struct rtl_fe_mtu mtus[16];
 unsigned long hashes[RTL_FE_HASH_ENTRIES/64],counters[1];
 u64 deletes;
 unsigned int registers[0x4000/4],ages[RTL_FE_HASH_ENTRIES/32][4],cam[5];
 unsigned int deletes_FDB,restores_CAM,restores_IF,cache_invalidates;
 bool fail_CAM,fail_IF,fail_age,fail_age_write,fail_cache;
 unsigned int fail_IF_retries,oracle_hash_sequence[2],oracle_hash_count,oracle_hash_cursor;
 unsigned int oracle_hash_index,age_withdraw_barriers;
 struct delayed_work cleanup_work;
 unsigned int cleanup_delay;
 bool shutting_down;
 struct spinlock route_lock;
 bool enabled,prepared,engine_ready,route_gate_ready,route_admitted,route_gate_verified;
 unsigned int pending_withdrawals,reconciles,fail_gate_mask,selector_writes,route_opens;
 int lock;
};
#define system_wq 0
#define HZ 100
static void mod_delayed_work(int queue,struct delayed_work *work,unsigned int delay){assert(queue==0 && delay>=HZ && delay<=32U*HZ);work->modified++;work->delay=delay;}
static void queue_delayed_work(int queue,struct delayed_work *work,unsigned int delay){assert(queue==0 && delay>=HZ && delay<=32U*HZ);work->queued++;}
static void mutex_lock(int *lock){assert(!*lock);*lock=1;}
static void mutex_unlock(int *lock){assert(*lock);*lock=0;}
static unsigned int fe_read(void *context,unsigned int reg){return ((struct rtl_fe *)context)->registers[reg/4];}
static void fe_write(void *context,unsigned int reg,unsigned int value){
 struct rtl_fe *fe=context;
 if(reg==0x3418 || reg==0x3424){
  assert(fe->route_lock.held);fe->selector_writes++;
  unsigned int side=reg==0x3424;
  if(((value>>10)&15)==1 && (fe->fail_gate_mask&BIT(side)))return;
  if(((value>>10)&15)==0)fe->route_opens++;
 }
 fe->registers[reg/4]=value;
}
static void fe_switch_reconcile_locked(struct rtl_fe *fe){assert(!fe->shutting_down);fe->reconciles++;}
static int fe_access(void *context,unsigned int reg,unsigned int value){
 struct rtl_fe *fe=context;
 if(reg==0x3928){
  if(fe->fail_age || (fe->fail_age_write && (value&BIT(30)))){
   fe->fail_age=fe->fail_age_write=false;return -ETIMEDOUT;
  }
  if(value&BIT(30))fe->age_withdraw_barriers=dma_barriers;
  unsigned int row=value&(RTL_FE_HASH_ENTRIES/32-1);
  for(unsigned int i=0;i<4;i++) {
   if(value&BIT(30))fe->ages[row][i]=fe_read(fe,0x3938-i*4);
   else fe_write(fe,0x3938-i*4,fe->ages[row][i]);
  }
 } else if(reg==0x38b0){
  /* Independent hardware-spec oracle: G3_hash 3.3.2 Hash Entry Removal,
   * quoted by same-chip SDK aal_hash_delete at 8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0:
   * first clear Main Hash's32-bit DDR field, then invalidate the cache.
   * A completed DMA write barrier must publish the clear before this command. */
  unsigned int expected=fe->oracle_hash_index;
  if(fe->oracle_hash_count){
   assert(fe->oracle_hash_cursor<fe->oracle_hash_count);
   expected=fe->oracle_hash_sequence[fe->oracle_hash_cursor++];
  }
  assert(!((u32 *)fe->memory)[expected]);
  assert(dma_barriers>fe->age_withdraw_barriers);
  if(fe->fail_cache){fe->fail_cache=false;return -ETIMEDOUT;}
  fe->cache_invalidates++;
 }
 else if(reg==0x1ca0){assert((value&255)==0x85);fe->deletes_FDB++;fe_write(fe,0x1c2c,5);}
 else if(reg==0x3200){
  if(fe->fail_CAM){fe->fail_CAM=false;return -ETIMEDOUT;}
  fe->restores_CAM++;
  for(unsigned int i=0;i<5;i++)fe->cam[i]=fe_read(fe,0x3214-i*4);
 } else if(reg==0x3000){
  if(fe->fail_IF || fe->fail_IF_retries){
   fe->fail_IF=false;if(fe->fail_IF_retries)fe->fail_IF_retries--;return -ETIMEDOUT;
  }
  fe->restores_IF++;
 }
 else assert(0);
 return 0;
}
static struct rtl_dq_io fe_io(struct rtl_fe *fe){return (struct rtl_dq_io){fe,fe_read,fe_write,fe_access};}
'''
test = r'''
static void initialize(struct rtl_fe *fe){
 memset(fe,0,sizeof(*fe));init_list(&fe->flows);init_list(&fe->ports);init_list(&fe->retries);
 struct rtl_dq_io io=fe_io(fe);
 /* This teardown fixture receives the established cold owner. The complete
  * cold-prepare lifecycle has a separate oracle; here its real CMD handoff
  * still runs with learning stopped, then ordinary traffic resumes. */
 assert(rtl_l2_fdb_command_mode(&io)==-EBUSY);
 assert(!fe_read(fe,RTL_L2_FDB_CONTROL));
 fe_write(fe,RTL_L2_FDB_CONTROL,RTL_L2_FDB_LEARN_DISABLE);
 assert(!rtl_l2_fdb_command_mode(&io));
 assert(fe_read(fe,RTL_L2_FDB_CONTROL)==(RTL_L2_FDB_LEARN_DISABLE|RTL_L2_FDB_CMD_MODE));
 fe_write(fe,RTL_L2_FDB_CONTROL,fe_read(fe,RTL_L2_FDB_CONTROL)&~RTL_L2_FDB_LEARN_DISABLE);
 assert(!fe->deletes_FDB && !fe->restores_CAM && !fe->restores_IF && !fe->cache_invalidates);
 fe->deletes_FDB=fe->restores_CAM=fe->restores_IF=fe->cache_invalidates=0;
 fe->memory=calloc(1,RTL_FE_MEMORY_BYTES);assert(fe->memory);
 fe->enabled=fe->prepared=fe->engine_ready=fe->route_gate_ready=true;
 assert(fe_route_arm(fe) && fe->route_admitted && !fe->route_gate_verified);
}
static void check_gate(struct rtl_fe *fe){
 assert(!fe->route_admitted && fe->route_gate_verified);
 assert(((fe_read(fe,0x3418)>>10)&15)==1 && ((fe_read(fe,0x3424)>>10)&15)==1);
}
static void check_hash_owner(struct rtl_fe *fe,unsigned int index,struct rtl_fe_flow *owner){
 if(fe->hash_owners)assert(fe->hash_owners[index]==owner);
}
static struct rtl_fe_flow *new_flow(struct rtl_fe *fe,unsigned int index,bool published){
 struct rtl_fe_flow *flow=calloc(1,sizeof(*flow));assert(flow);
 flow->hash_index=index;flow->crc16=index;flow->published=published;
 init_list(&flow->retry);list_add_tail(&flow->list,&fe->flows);
 set_bit(index,fe->hashes);((u32 *)fe->memory)[index]=index+0x12345678U;
 return flow;
}
static void withdrawal_recovery_priority(void){
 struct rtl_fe fe;initialize(&fe);
 struct rtl_fe_flow *resource=new_flow(&fe,95,false);
 resource->interface_owned=true;resource->counter=0;
 fe.interfaces[0]=(struct rtl_fe_interface){.users=1,.ready=true};set_bit(0,fe.counters);
 fe.fail_IF=true;assert(fe_delete(&fe,resource)==-ETIMEDOUT);
 fe.cleanup_delay=32*HZ;mod_delayed_work(system_wq,&fe.cleanup_work,32*HZ);
 unsigned int modified=fe.cleanup_work.modified;
 struct rtl_fe_flow *route=new_flow(&fe,66,true);
 fe.oracle_hash_index=route->hash_index;fe.fail_age=true;
 assert(fe_delete(&fe,route)==-ETIMEDOUT && fe.pending_withdrawals==1);
 assert(fe.cleanup_delay==HZ && fe.cleanup_work.modified==modified+1);
 assert(fe.cleanup_work.delay==HZ);check_gate(&fe);
 /* Repeated destroy/cache failures keep the existing expedited timer. */
 fe.fail_cache=true;assert(fe_delete(&fe,route)==-ETIMEDOUT);
 assert(fe.cleanup_work.modified==modified+1 && fe.cleanup_delay==HZ);
 /* A later retry backoff is respected by both the same callback and a
  * newly failing second owner while the existing fault epoch is live. */
 fe.cleanup_delay=8*HZ;mod_delayed_work(system_wq,&fe.cleanup_work,8*HZ);
 modified=fe.cleanup_work.modified;
 fe.fail_cache=true;assert(fe_delete(&fe,route)==-ETIMEDOUT);
 assert(fe.cleanup_work.modified==modified && fe.cleanup_delay==8*HZ);
 struct rtl_fe_flow *second=new_flow(&fe,67,true);
 fe.oracle_hash_index=second->hash_index;fe.fail_age=true;
 assert(fe_delete(&fe,second)==-ETIMEDOUT && fe.pending_withdrawals==2);
 assert(fe.cleanup_work.modified==modified && fe.cleanup_delay==8*HZ);
 assert(!fe_delete(&fe,second) && fe.pending_withdrawals==1 && !fe.reconciles);
 fe.oracle_hash_index=route->hash_index;
 /* Actual worker must withdraw B first, then retry the still-failing
  * resource A. The route latch clears even though A stays quarantined. */
 fe.fail_IF=true;fe_cleanup_work(&fe.cleanup_work.work);
 assert(!fe.pending_withdrawals && fe.reconciles==1 && !test_bit(66,fe.hashes));
 assert(resource->interface_owned && fe.retries.next==&resource->retry);
 assert(!fe.fail_IF && fe.cleanup_delay==2*HZ);
 assert(fe_route_arm(&fe) && fe.route_admitted);
 fe_cleanup_work(&fe.cleanup_work.work);
 assert(list_empty(&fe.flows) && list_empty(&fe.retries) && !fe.cleanup_delay);
 free(fe.memory);
}
static void withdrawal_to_resource_progress(void){
 struct rtl_fe fe;initialize(&fe);
 struct rtl_fe_flow *a=new_flow(&fe,33,true),*b=new_flow(&fe,66,true);
 a->interface_owned=true;a->counter=0;
 fe.interfaces[0]=(struct rtl_fe_interface){.users=1,.ready=true};set_bit(0,fe.counters);
 fe.oracle_hash_index=a->hash_index;fe.fail_age=true;
 assert(fe_delete(&fe,a)==-ETIMEDOUT);
 fe.oracle_hash_index=b->hash_index;fe.fail_age=true;
 assert(fe_delete(&fe,b)==-ETIMEDOUT && fe.pending_withdrawals==2);
 fe.oracle_hash_sequence[0]=a->hash_index;fe.oracle_hash_sequence[1]=b->hash_index;
 fe.oracle_hash_count=2;fe.cleanup_delay=16*HZ;fe.fail_IF_retries=2;
 /* A's publication retires, but its EIF restoration fails. In the SAME
  * bounded batch B must still retire; A's unrelated resource error must
  * neither retain the global route latch nor make B wait another timer. */
 fe_cleanup_work(&fe.cleanup_work.work);
 assert(!fe.pending_withdrawals && fe.reconciles==1 && fe.oracle_hash_cursor==2);
 assert(!a->published && !a->withdrawal_pending && a->interface_owned);
 assert(!test_bit(66,fe.hashes) && fe.retries.next==&a->retry);
 assert(!fe.fail_IF_retries && fe.cleanup_delay==2*HZ);
 assert(fe_route_arm(&fe) && fe.route_admitted);
 fe_cleanup_work(&fe.cleanup_work.work);
 assert(list_empty(&fe.flows) && list_empty(&fe.retries));free(fe.memory);
}
static void withdrawal_faults(void){
 struct rtl_fe fe;
 /* Each failed owner latches once, including a partially published
  * install rollback. Recovery of one direction cannot reopen the other. */
 for(unsigned int first=0;first<2;first++){
  initialize(&fe);
  struct rtl_fe_flow *flow[2]={new_flow(&fe,33,true),new_flow(&fe,66,true)};
  flow[0]->installed=true;
  for(unsigned int i=0;i<2;i++){
   fe.oracle_hash_index=flow[i]->hash_index;fe.fail_age=true;
   assert(fe_delete(&fe,flow[i])==-ETIMEDOUT);
   assert(flow[i]->published && flow[i]->withdrawal_pending);
   assert(fe.pending_withdrawals==i+1 && !fe.reconciles);check_gate(&fe);
  }
  fe.oracle_hash_index=flow[0]->hash_index;fe.fail_cache=true;
  assert(fe_delete(&fe,flow[0])==-ETIMEDOUT && fe.pending_withdrawals==2);
  unsigned int opens=fe.route_opens;
  assert(fe_route_arm(&fe));check_gate(&fe); /* Native L2 remains eligible. */
  assert(fe.route_opens==opens && !fe.reconciles);
  fe.oracle_hash_index=flow[first]->hash_index;
  assert(!fe_delete(&fe,flow[first]));
  assert(fe.pending_withdrawals==1 && !fe.reconciles);
  assert(fe_route_arm(&fe));check_gate(&fe);assert(fe.route_opens==opens);
  fe.oracle_hash_index=flow[1-first]->hash_index;
  assert(!fe_delete(&fe,flow[1-first]));
  assert(!fe.pending_withdrawals && fe.reconciles==1);
  check_gate(&fe); /* Queuing reconciliation is not hardware readmission. */
  assert(fe_route_arm(&fe) && fe.route_admitted && !fe.route_gate_verified);
  assert(fe.deletes==1 && list_empty(&fe.flows) && list_empty(&fe.retries));
  free(fe.memory);
 }
 /* A failed selector write must remain distinguishable from a proved
  * gate. Age success alone never releases an uncertain cached action. */
 for(unsigned int side=0;side<2;side++){
  initialize(&fe);struct rtl_fe_flow *flow=new_flow(&fe,127,true);
  fe.oracle_hash_index=flow->hash_index;fe.fail_age=true;fe.fail_gate_mask=BIT(side);
  assert(fe_delete(&fe,flow)==-ETIMEDOUT && flow->withdrawal_pending);
  assert(fe.pending_withdrawals==1 && !fe.route_admitted && !fe.route_gate_verified);
  assert(((fe_read(&fe,0x3418+side*12)>>10)&15)==0);
  unsigned int opens=fe.route_opens;
  assert(!fe_route_arm(&fe) && !fe.route_gate_verified && fe.route_opens==opens);
  fe.fail_cache=true;
  assert(fe_delete(&fe,flow)==-ETIMEDOUT && flow->published);
  assert(flow->withdrawal_pending && fe.pending_withdrawals==1 && !fe.reconciles);
  assert(test_bit(flow->hash_index,fe.hashes) && !fe.cookies.erases);
  assert(!((u32 *)fe.memory)[flow->hash_index]);
  fe.fail_gate_mask=0;
  assert(fe_route_arm(&fe));check_gate(&fe);assert(fe.route_opens==opens);
  assert(!fe_delete(&fe,flow) && !fe.pending_withdrawals && fe.reconciles==1);
  assert(fe_route_arm(&fe) && fe.route_admitted);
  free(fe.memory);
 }
 /* Resource-only rollback cannot have forwarded a packet. Retain its
  * unfinished EIF but do not turn it into a global route withdrawal. */
 initialize(&fe);struct rtl_fe_flow *flow=new_flow(&fe,95,false);
 flow->interface_owned=true;flow->counter=0;
 fe.interfaces[0]=(struct rtl_fe_interface){.users=1,.ready=true};
 set_bit(0,fe.counters);fe.fail_IF=true;
 unsigned int writes=fe.selector_writes;
 assert(fe_delete(&fe,flow)==-ETIMEDOUT && flow->interface_owned);
 assert(!flow->withdrawal_pending && !fe.pending_withdrawals && fe.route_admitted);
 assert(fe.selector_writes==writes && !fe.reconciles);
 assert(!fe_delete(&fe,flow));free(fe.memory);
}
int main(void){
 withdrawal_faults();
 withdrawal_recovery_priority();
 withdrawal_to_resource_progress();
 struct rtl_fe fe;initialize(&fe);
#ifdef INDEXED_HASH_OWNERS
 fe.hash_owners=calloc(RTL_FE_HASH_ENTRIES,sizeof(*fe.hash_owners));assert(fe.hash_owners);
#endif
 struct rtl_fe_port *port=calloc(1,sizeof(*port));assert(port);port->retired=true;list_add_tail(&port->list,&fe.ports);
 fe.source_macs[0].users=2;
 for(unsigned int i=0;i<5;i++)fe.source_macs[0].saved[i]=0x51000000+i;
 struct rtl_fe_flow *a=calloc(1,sizeof(*a)),*b=calloc(1,sizeof(*b));assert(a&&b);
 *a=(struct rtl_fe_flow){.hash_index=1280,.counter=31,.source_mac=0,.crc16=0x5141,
#ifndef INDEXED_DESTINATIONS
  .destination_created=true,
#endif
  .published=true,.installed=true,.counted=true,.source_owned=true,.destination_owned=true,.interface_owned=true,
  .destination={2,0x77,0x66,0x55,0x44,0x33}};
 a->input=port;
 *b=*a;init_list(&a->retry);init_list(&b->retry);b->hash_index=65344;b->counter=30;b->crc16=0xff4b;
#ifdef INDEXED_DESTINATIONS
 struct rtl_fe_destination *destination=calloc(1,sizeof(*destination));assert(destination);
 destination->users=destination->live_users=2;destination->created=destination->ready=true;
 memcpy(destination->address,a->destination,ETH_ALEN);fe_destination_index(&fe,destination);
 a->destination_owner=b->destination_owner=destination;
 a->destination_live=b->destination_live=true;
#endif
 fe_write(&fe,0x3520,0x23451234);
 assert(!fe_mtu_get(&fe,a,1492) && !fe_mtu_get(&fe,b,1492));
 assert(a->mtu_index==b->mtu_index && fe.mtus[0].users==2);
 assert(fe_read(&fe,0x3520)==0x234505d4);
 fe.interfaces[31]=(struct rtl_fe_interface){.users=1,.counted=true,.ready=true};
 fe.interfaces[30]=(struct rtl_fe_interface){.users=1,.counted=true,.ready=true};
 list_add_tail(&a->list,&fe.flows);list_add_tail(&b->list,&fe.flows);
 set_bit(a->hash_index,fe.hashes);set_bit(b->hash_index,fe.hashes);
 if(fe.hash_owners){fe.hash_owners[a->hash_index]=a;fe.hash_owners[b->hash_index]=b;}
 set_bit(a->counter,fe.counters);set_bit(b->counter,fe.counters);
 ((u32 *)fe.memory)[1280]=0x12345678;((u32 *)fe.memory)[65344]=0x87654321;
 fe_collect_ports(&fe);assert(fe.ports.next==&port->list);
 fe.oracle_hash_index=a->hash_index;
 assert(!fe_delete(&fe,a));
 check_hash_owner(&fe,1280,NULL);check_hash_owner(&fe,65344,b);
 fe_collect_ports(&fe);assert(fe.ports.next==&port->list);
 assert(fe.source_macs[0].users==1 && !fe.deletes_FDB && !fe.restores_CAM);
 assert(!test_bit(1280,fe.hashes) && test_bit(65344,fe.hashes));
 /* FDB migration may meet a failed age/cache withdrawal. Keep every
  * live hardware owner until the existing cleanup can finish withdrawal. */
 fe.oracle_hash_index=b->hash_index;fe.fail_age=true;
 assert(fe_delete(&fe,b)==-ETIMEDOUT && b->published && b->deleting);
 check_hash_owner(&fe,65344,b);
 assert(b->withdrawal_pending && fe.pending_withdrawals==1);check_gate(&fe);
 assert(b->source_owned && b->destination_owned && b->interface_owned);
#ifdef INDEXED_DESTINATIONS
 assert(b->destination_owner->users==1 && !b->destination_owner->live_users);
 assert(!b->destination_live); /* Retirement precedes even failed withdrawal. */
#endif
 assert(test_bit(65344,fe.hashes) && test_bit(30,fe.counters));
 assert(((u32 *)fe.memory)[65344]==0x87654321); /* Failed withdrawal preserves the DDR key. */
 fe.fail_age_write=true;
 assert(fe_delete(&fe,b)==-ETIMEDOUT && b->published && b->destination_owned);
 check_hash_owner(&fe,65344,b);
 assert(fe.pending_withdrawals==1 && !fe.reconciles);check_gate(&fe);
 assert(((u32 *)fe.memory)[65344]==0x87654321 && !fe.deletes_FDB);
 fe.fail_cache=true;
 assert(fe_delete(&fe,b)==-ETIMEDOUT && b->published && b->destination_owned);
 check_hash_owner(&fe,65344,b);
 assert(fe.pending_withdrawals==1 && !fe.reconciles);check_gate(&fe);
 assert(!fe.deletes_FDB && fe.source_macs[0].users==1);
 assert(!((u32 *)fe.memory)[65344] && b->interface_owned && b->mtu_owned);
 assert(fe.interfaces[30].users==1 && fe.mtus[0].users==1);
 /* A failed EIF restore still names the source CAM: retain its reference
  * and the physical row reservation until restoration can be retried. */
 fe.fail_IF=true;
 assert(fe_delete(&fe,b)==-ETIMEDOUT && b->source_owned && b->interface_owned);
 check_hash_owner(&fe,65344,b);
 assert(!b->withdrawal_pending && !fe.pending_withdrawals && fe.reconciles==1);
 /* Cache withdrawal is complete even though EIF/CAM restoration is not.
  * A normal reconciliation can now recover unrelated routed flows. */
 assert(fe_route_arm(&fe) && fe.route_admitted);
 assert(fe.source_macs[0].users==1 && !fe.restores_CAM && fe.interfaces[30].users==1);
 assert(test_bit(30,fe.counters) && !fe.interfaces[30].ready);
 fe.fail_CAM=true;
 assert(fe_delete(&fe,b)==-ETIMEDOUT);
 check_hash_owner(&fe,65344,b);
 assert(!fe.pending_withdrawals && fe.reconciles==1 && fe.route_admitted);
 fe_collect_ports(&fe);assert(fe.ports.next==&port->list);
 assert(fe.deletes_FDB==1 && fe.source_macs[0].users==1);
 assert(!b->published && !b->destination_owned && b->source_owned && !b->interface_owned);
 assert(test_bit(65344,fe.hashes) && !test_bit(30,fe.counters));
 assert(!((u32 *)fe.memory)[65344]);
 port->bindings=1;
 assert(b->deleting && fe.cleanup_work.queued==5);
 assert(fe.retries.next==&b->retry && b->retry.next==&fe.retries);
 fe_cleanup_work(&fe.cleanup_work.work);
 check_hash_owner(&fe,65344,NULL);
 fe_collect_ports(&fe);assert(fe.ports.next==&port->list);
 port->bindings=0;
 fe_collect_ports(&fe);assert(fe.ports.next==&fe.ports);
 assert(fe.source_macs[0].users==0 && fe.deletes_FDB==1 && fe.restores_CAM==1);
 assert(!fe.destination_count && RB_EMPTY_ROOT(&fe.destinations));
 assert(fe.cache_invalidates==2 && fe.restores_IF==2 && fe.deletes==2);
 for(unsigned int i=0;i<5;i++)assert(fe.cam[i]==0x51000000+i);
 assert(fe.flows.next==&fe.flows && !test_bit(65344,fe.hashes) && !test_bit(30,fe.counters));
 assert(list_empty(&fe.retries) && fe.cookies.erases==2);
 /* A partial unpublished installation still clears its DDR slot, without
  * issuing invalidation or counting an installation as a normal delete. */
 struct rtl_fe_flow *c=calloc(1,sizeof(*c));assert(c);
 c->hash_index=1413;init_list(&c->retry);list_add_tail(&c->list,&fe.flows);
 if(fe.hash_owners)fe.hash_owners[c->hash_index]=c;
 set_bit(c->hash_index,fe.hashes);((u32 *)fe.memory)[c->hash_index]=0xaabbccdd;
 unsigned int before_invalidations=fe.cache_invalidates,before_barriers=dma_barriers;
 assert(!fe_delete(&fe,c));
 check_hash_owner(&fe,1413,NULL);
 assert(!((u32 *)fe.memory)[1413] && !test_bit(1413,fe.hashes));
 assert(fe.cache_invalidates==before_invalidations && dma_barriers>before_barriers);
 assert(fe.deletes==2 && fe.cookies.erases==3 && list_empty(&fe.flows));
 /* Removal can fail while the hardware is stuck. Once the FE owner is
  * quarantined, no retry may re-arm work or perform MMIO after unmapping. */
 struct rtl_fe_flow *d=calloc(1,sizeof(*d));assert(d);
 d->hash_index=1536;d->crc16=1536;d->published=true;
 if(fe.hash_owners)fe.hash_owners[d->hash_index]=d;
 init_list(&d->retry);list_add_tail(&d->list,&fe.flows);
 set_bit(d->hash_index,fe.hashes);((u32 *)fe.memory)[d->hash_index]=0xfeedbeef;
 fe.oracle_hash_index=d->hash_index;fe.shutting_down=true;fe.fail_age=true;
 unsigned int queued=fe.cleanup_work.queued,modified=fe.cleanup_work.modified;
 fe.cleanup_delay=32*HZ;
 unsigned int reconciles=fe.reconciles;
 assert(fe_delete(&fe,d)==-ETIMEDOUT && d->published);
 check_hash_owner(&fe,1536,d);
 assert(d->withdrawal_pending && fe.pending_withdrawals==1);check_gate(&fe);
 assert(fe.cleanup_work.queued==queued);
 assert(fe.cleanup_work.modified==modified); /* Shutdown must not expedite a timer. */
 fe.fail_age=true;fe_cleanup_work(&fe.cleanup_work.work);
 assert(fe.fail_age && d->published && fe.cleanup_work.queued==queued);
 fe.fail_age=false;assert(!fe_delete(&fe,d));
 check_hash_owner(&fe,1536,NULL);
 assert(!fe.pending_withdrawals && fe.reconciles==reconciles && fe.cleanup_work.queued==queued);
 assert(list_empty(&fe.flows) && list_empty(&fe.retries));
 if(fe.hash_owners)
  for(unsigned int i=0;i<RTL_FE_HASH_ENTRIES;i++)assert(!fe.hash_owners[i]);
 free(fe.hash_owners);
 free(fe.memory);
 assert(!fe.mtus[0].users && fe_read(&fe,0x3520)==0x23451234);
 puts("G3 removal order: DDR key zero and DMA barrier precede invalidation; age/cache failures retain ownership; unpublished rollback clears without invalidation");
 puts("Native FE teardown:shared FDB/source MAC,last-owner restore,failed CAM retry and DMA/hash/counter ownership passed");
 puts("Published withdrawal faults: route-only latch, two-owner recovery, selector readback refusal, partial-install rollback, resource-only isolation and shutdown passed");
}
'''
flow_struct = re.search(r'struct rtl_fe_flow \{.*?\n\};',native,re.S)[0]
if args.revision and 'withdrawal_pending' not in flow_struct:
    # Keep the old implementation executable under the same behavioral
    # oracle: an unused zero-initialized diagnostic field is not a fix.
    flow_struct = flow_struct.replace('\n};','\n bool withdrawal_pending;\n};')
owner_struct = re.search(r'struct rtl_fe_destination \{.*?\n\};',native,re.S)[0] if indexed else ''
parts = [('#define INDEXED_DESTINATIONS 1\n' if indexed else ''),
    ('#define INDEXED_HASH_OWNERS 1\n' if hash_indexed else ''),common,owner_struct,flow_struct]
if indexed:
    parts += [function(n) for n in ('fe_destination_index','fe_destination_retire')]
if 'static int fe_interface_transfer(' in native:
    parts += [function('fe_interface_transfer')]
parts += [function(n) for n in ('fe_route_select_locked','fe_route_gate','fe_route_arm',
    'fe_collect_ports','fe_source_put','fe_interface_put','fe_mtu_get','fe_mtu_put','fe_destination_put')]
for name in ('fe_withdrawal_failed','fe_withdrawal_completed'):
    if re.search(r'^static void '+name+r'\(',native,re.M):
        parts.append(function(name))
parts += [function(n) for n in ('fe_delete','fe_cleanup_work')]
parts.append(test)
with tempfile.TemporaryDirectory(dir=root/'artifacts',prefix='fe-release-') as work:
    source=Path(work)/'release.c';binary=Path(work)/'release'
    executable='\n'.join(parts)
    source.write_text(executable)
    subprocess.run(['cc','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',
        '-I'+str(drivers),'-I'+str(root/'scripts/fixtures'),str(source),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
    mutants = {
        'arm_ignores_pending_withdrawals': (
            'if(!fe->enabled || fe->pending_withdrawals)', 'if(!fe->enabled)'),
        'first_owner_recovers_too_soon': (
            'if(!--fe->pending_withdrawals && !fe->shutting_down)',
            'if((--fe->pending_withdrawals, !fe->shutting_down))'),
        'age_success_retires_before_cache_invalidation': (
            'if(flow->published) {\n  ret=rtl_fe_cache_command',
            'fe_withdrawal_completed(fe,flow);\n if(flow->published) {\n  ret=rtl_fe_cache_command'),
        'resource_only_failure_globally_gates_routes': (
            'if(flow->published)fe_withdrawal_failed(fe,flow);',
            'fe_withdrawal_failed(fe,flow);'),
        'resource_only_owner_blocks_pending_withdrawal': (
            'if(fe->pending_withdrawals)\n   list_for_each_entry(candidate',
            'if(false)\n   list_for_each_entry(candidate'),
        'new_fault_inherits_resource_only_backoff': (
            'if(expedite && !fe->shutting_down)',
            'if(false && expedite && !fe->shutting_down)'),
        'second_pending_owner_resets_existing_deadline': (
            'expedite=!fe->pending_withdrawals && fe->cleanup_delay>HZ;',
            'expedite=fe->cleanup_delay>HZ;'),
        'post_withdrawal_resource_failure_blocks_next_pending': (
            'if(was_pending && !flow->withdrawal_pending && fe->pending_withdrawals)',
            'if(false && was_pending && !flow->withdrawal_pending && fe->pending_withdrawals)'),
    }
    if indexed:
        mutants['failed_withdrawal_keeps_pin_shareable'] = (
            'flow->deleting=true;\n fe_destination_retire(flow);',
            'flow->deleting=true;')
    if hash_indexed:
        mutants['hash_index_released_before_withdrawal'] = (
            'flow->deleting=true;\n',
            'flow->deleting=true;\n if(fe->hash_owners)fe->hash_owners[flow->hash_index]=NULL;\n')
        mutants['completed_release_retains_hash_index'] = (
            'if(fe->hash_owners)fe->hash_owners[flow->hash_index]=NULL;',
            '/* incorrect: released flow remains in the owner index */')
    for name,(before,after) in mutants.items():
        assert executable.count(before)==1, name
        mutant=Path(work)/(name+'.c');program=Path(work)/name
        mutant.write_text(executable.replace(before,after,1))
        subprocess.run(['cc','-I'+str(drivers),'-I'+str(root/'scripts/fixtures'),str(mutant),'-o',str(program)],check=True)
        rejected=subprocess.run([str(program)],capture_output=True,text=True)
        assert rejected.returncode and 'Assertion' in rejected.stderr, name
        print('Withdrawal mutation rejected:',name)
(root/'logs/fe-flow-release.json').write_text(json.dumps({
    'production_source_sha256':hashlib.sha256(native.encode()).hexdigest(),
    'DDR_key_clear_and_barrier_before_cache_invalidation':True,
    'failed_age_read_and_write_preserve_DDR_key':True,
    'failed_cache_invalidation_retains_resource_owners':True,
    'published_withdrawal_failure_gates_both_L3_connectors':True,
    'uncertain_publication_count_is_idempotent_and_last_owner_recovers':True,
    'verified_CPU_gate_keeps_native_L2_eligible_without_routes':True,
    'failed_gate_readback_is_not_claimed_as_hardware_isolation':True,
    'age_success_alone_does_not_retire_uncertain_cache_owner':True,
    'partial_published_install_rollback_uses_same_fault_latch':True,
    'EIF_CAM_only_failure_does_not_hold_global_route_gate':True,
    'shutdown_never_schedules_recovery_or_retry':True,
    'first_pending_withdrawal_accelerates_old_resource_backoff_to_HZ':True,
    'repeated_pending_callbacks_do_not_rewrite_the_retry_deadline':True,
    'resource_only_failures_cannot_block_recovered_publication_withdrawal':True,
    'partial_withdrawal_progress_keeps_next_pending_in_same_bounded_batch':True,
    'independent_withdrawal_mutations_rejected':list(mutants),
    'failed_EIF_restore_retains_source_CAM_owner':True,
    'unpublished_rollback_clears_without_cache_command':True,
    'shared_MAC_last_owner_release':True,'retired_port_retained_until_failed_flow_cleanup_retries_finish':True,'CAM_restore_failure_retried_without_double_release':True,
    'hash_and_counter_slots_retained_until_release_completed':True,
    'optional_hash_owner_index_retained_through_all_failure_stages_and_cleared_before_free':hash_indexed,
    'sanitizers':['ASan','UBSan'],'hardware_fault_injection':False,
},indent=2)+'\n')
