#!/usr/bin/env python3
"""Execute the kernel's actual initial-publication and work-retirement paths.

Hash insertion, RCU grace periods, route validity and workqueue scheduling are
controlled boundaries. The add, lookup, GC, conntrack fixup, teardown/free,
work allocator and worker-lifetime functions are extracted unchanged from
the prepared kernel.
Interleavings run at reply publication, original publication, conntrack refresh
and the release of INITIALIZING. This proves the tested state transitions, not
CPU memory-ordering litmus results or packet delivery on an RTL9617C device.

The default run also executes targeted regressions and the pre-229 algorithm;
each must fail at a runtime assertion, not merely differ in source text.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile


def function(source: str, name: str) -> str:
    match = re.search(r"^.*\b" + re.escape(name) + r"\([^;]*?\)\s*\{", source, re.M)
    if not match:
        raise AssertionError(f"missing production function: {name}")
    start = match.start()
    # Linux puts the pointer return type on its own line for these helpers.
    if source[start:source.index("(", start)].strip() == name:
        start = source.rfind("\n", 0, start - 1) + 1
    end = source.index("{", match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end] + "\n"


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--kernel", type=Path, required=True, help="Prepared kernel including patch 229")
parser.add_argument("--no-negative-controls", action="store_true", help="Run only production code")
args = parser.parse_args()
core = (args.kernel / "net/netfilter/nf_flow_table_core.c").read_text()
offload = (args.kernel / "net/netfilter/nf_flow_table_offload.c").read_text()
header = (args.kernel / "include/net/netfilter/nf_flow_table.h").read_text()
flag_enum = re.search(r"enum nf_flow_flags \{.*?\n\};", header, re.S)
assert flag_enum, "missing production flow flags enum"
assert "NF_FLOW_INITIALIZING" in flag_enum.group(), "kernel must include patch 229"

CORE_NAMES = (
    "flow_offload_route_release", "flow_offload_free_rcu", "flow_offload_free",
    "nf_flow_has_expired", "flow_offload_fixup_tcp", "flow_offload_fixup_ct",
    "flow_offload_teardown", "flow_offload_del",
    "flow_offload_add", "flow_offload_refresh", "flow_offload_lookup",
    "nf_flow_offload_gc_step", "nf_flow_table_do_cleanup",
)
OFFLOAD_NAMES = (
    "flow_offload_work_del", "flow_offload_work_handler", "flow_offload_queue_work",
    "nf_flow_offload_work_alloc", "nf_flow_offload_add", "nf_flow_offload_del",
    "nf_flow_offload_stats",
)
functions = {name: function(core, name) for name in CORE_NAMES}
functions.update({name: function(offload, name) for name in OFFLOAD_NAMES})
order = CORE_NAMES[:8] + OFFLOAD_NAMES + CORE_NAMES[8:]

COMMON = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint32_t u32; typedef int32_t __s32; typedef int32_t s32;
typedef int64_t s64;
#define HZ 100U
#define NF_CT_DAY (86400U * HZ)
#define BIT(n) (1UL << (n))
#define READ_ONCE(v) (v)
#define WRITE_ONCE(v,n) ((v) = (n))
#define likely(v) (v)
#define unlikely(v) (v)
#define EXPORT_SYMBOL_GPL(n)
#define GFP_ATOMIC 0
#define nf_flowtable_time_stamp ((u32)jiffies)
#define container_of(p,t,m) ((t *)((char *)(p) - offsetof(t,m)))
#define smp_mb__before_atomic() __asm__ __volatile__("" ::: "memory")
#define smp_mb() __asm__ __volatile__("" ::: "memory")
#define WARN_ON_ONCE(v) assert(!(v))
enum flow_offload_tuple_dir { FLOW_OFFLOAD_DIR_ORIGINAL, FLOW_OFFLOAD_DIR_REPLY, FLOW_OFFLOAD_DIR_MAX };
enum flow_cls_command { FLOW_CLS_REPLACE, FLOW_CLS_DESTROY, FLOW_CLS_STATS };
enum { IPS_OFFLOAD_BIT, IPS_HW_OFFLOAD_BIT, IPS_SEEN_REPLY_BIT,
 IPS_FIXED_TIMEOUT_BIT, IPS_CONFIRMED_BIT };
enum { IPPROTO_TCP = 6, IPPROTO_UDP = 17 };
enum { TCP_CONNTRACK_ESTABLISHED = 3, TCP_CONNTRACK_CLOSE = 8, TCP_CONNTRACK_MAX = 10 };
enum udp_conntrack { UDP_CT_UNREPLIED, UDP_CT_REPLIED };
#define IP_CT_TCP_FLAG_MAXACK_SET 0x20U
#define IP_CT_TCP_FLAG_CLOSE_INIT 0x04U
enum { NF_FLOW_OFFLOAD_UNSPEC, NF_FLOW_OFFLOAD_ROUTE };
enum test_stage { REPLY_VISIBLE, ORIGINAL_VISIBLE, CT_REFRESHED, INITIAL_RELEASED };
struct nf_tcp_net { u32 timeouts[TCP_CONNTRACK_MAX], offload_timeout; };
struct nf_udp_net { u32 timeouts[2], offload_timeout; };
struct ip_ct_tcp { u8 state; struct { u32 td_maxwin; u8 flags; } seen[2]; };
struct net { unsigned int count_wq_add, count_wq_del, count_wq_stats;
 struct nf_tcp_net tcp; struct nf_udp_net udp; };
struct nf_conn { unsigned long status; u32 timeout; bool dying;
 unsigned int references, protonum, lock; struct net *net;
 union { struct ip_ct_tcp tcp; } proto; };
struct net_device { unsigned int ifindex; struct net *net; };
struct rhash_head { unsigned int unused; };
struct flow_offload_tuple { unsigned int dir, iifidx; };
struct flow_offload_tuple_rhash { struct rhash_head node; struct flow_offload_tuple tuple; };
struct rcu_head { void (*callback)(struct rcu_head *); };
struct flow_offload { struct nf_conn *ct; unsigned int type; unsigned long flags; u32 timeout;
 struct flow_offload_tuple_rhash tuplehash[2]; struct rcu_head rcu_head; };
struct rhashtable { struct flow_offload_tuple_rhash *slot[2]; };
struct nf_flowtable { struct rhashtable rhashtable; bool hardware; struct net *net; };
struct work_struct { void (*handler)(struct work_struct *); };
struct flow_offload_work { struct work_struct work; struct nf_flowtable *flowtable;
 struct flow_offload *flow; unsigned int cmd; };
static struct net ns;
static struct nf_conn ct;
static struct nf_flowtable table;
static struct flow_offload *live;
static struct rcu_head *deferred_rcu;
static struct work_struct *jobs[16];
static unsigned int job_count, allocations[3], completions[3], removals, retired, freed;
static unsigned int releases[2], fixup_refreshes, ct_refreshes, timeout_extensions, stages[4];
static unsigned int fail_insert, insertions, failed_allocations, admission_checks;
static unsigned long jiffies;
static bool direct_valid, bridge_changed, custom_gc, hook_running;
static void interleave(enum test_stage stage);
static void nf_flow_offload_gc_step(struct nf_flowtable *, struct flow_offload *, void *);
void nf_flow_offload_add(struct nf_flowtable *, struct flow_offload *);
void nf_flow_offload_del(struct nf_flowtable *, struct flow_offload *);
void nf_flow_offload_stats(struct nf_flowtable *, struct flow_offload *);
static bool test_bit(unsigned int bit, const unsigned long *word) { return !!(*word & BIT(bit)); }
static bool test_bit_acquire(unsigned int bit, const unsigned long *word) { return test_bit(bit, word); }
static void set_bit(unsigned int bit, unsigned long *word) { *word |= BIT(bit); }
static void __set_bit(unsigned int bit, unsigned long *word) { set_bit(bit, word); }
static bool test_and_set_bit(unsigned int bit, unsigned long *word) {
 bool old = test_bit(bit, word); set_bit(bit, word); return old;
}
static void clear_bit(unsigned int bit, unsigned long *word);
static bool try_cmpxchg(u32 *word, u32 *old, u32 new_value) {
 if (*word != *old) { *old = *word; return false; } *word = new_value; return true;
}
static bool nf_flowtable_hw_offload(const struct nf_flowtable *ft) { return ft->hardware; }
static unsigned long flow_offload_get_timeout(struct flow_offload *flow) { assert(flow == live); return 30 * HZ; }
static __s32 nf_flow_timeout_delta(unsigned int timeout) { return (__s32)(timeout - nf_flowtable_time_stamp); }
static bool nf_ct_is_dying(struct nf_conn *conn) { return conn->dying; }
static struct net *nf_ct_net(struct nf_conn *conn) { return conn->net; }
static int nf_ct_protonum(struct nf_conn *conn) { return conn->protonum; }
static struct nf_tcp_net *nf_tcp_pernet(struct net *net) { return &net->tcp; }
static struct nf_udp_net *nf_udp_pernet(struct net *net) { return &net->udp; }
static void spin_lock_bh(unsigned int *lock) { assert(!*lock); *lock = 1; }
static void spin_unlock_bh(unsigned int *lock) { assert(*lock == 1); *lock = 0; }
static struct net *dev_net(struct net_device *dev) { return dev->net; }
static bool net_eq(struct net *a, struct net *b) { return a == b; }
static bool nf_flow_tuple_uses_dev(const struct flow_offload_tuple *tuple, const struct net_device *dev) {
 return tuple->iifidx == dev->ifindex;
}
static bool nf_flow_direct_route_changed(const struct flow_offload *flow) { assert(flow == live); admission_checks++; return !direct_valid; }
static bool nf_flow_bridge_changed(const struct flow_offload *flow) { assert(flow == live); return bridge_changed; }
static bool nf_flow_dst_valid(struct nf_flowtable *ft, struct flow_offload *flow, int dir) {
 assert(ft == &table && flow == live && dir >= 0 && dir < 2); return direct_valid;
}
static bool nf_flow_custom_gc(struct nf_flowtable *ft, struct flow_offload *flow) {
 assert(ft == &table && flow == live); return custom_gc;
}
static void nf_flow_table_extend_ct_timeout(struct nf_conn *conn) { assert(conn == &ct); timeout_extensions++; }
static void nf_ct_refresh(struct nf_conn *conn, unsigned int timeout) {
 /* Same deadline/fixed-timeout rules as __nf_ct_refresh_acct; accounting
  * is absent because production nf_ct_refresh always passes zero bytes. */
 assert(conn == &ct);
 if (!test_bit(IPS_FIXED_TIMEOUT_BIT, &conn->status))
  conn->timeout = timeout + (test_bit(IPS_CONFIRMED_BIT, &conn->status) ? (u32)jiffies : 0);
 if (timeout == NF_CT_DAY) { ct_refreshes++; interleave(CT_REFRESHED); }
 else fixup_refreshes++;
}
static void nft_flow_dst_release(struct flow_offload *flow, unsigned int dir) {
 assert(flow == live && dir < 2); releases[dir]++; assert(releases[dir] == 1);
}
static void nf_ct_put(struct nf_conn *conn) { assert(conn == &ct && conn->references == 2); conn->references--; }
static void kfree(void *object) {
 if (object == live) { assert(retired == 1 && ct.references == 1); freed++; live = NULL; }
 free(object);
}
static void call_rcu(struct rcu_head *rcu, void (*callback)(struct rcu_head *)) {
 assert(!deferred_rcu && live && rcu == &live->rcu_head); retired++;
 rcu->callback = callback; deferred_rcu = rcu;
}
static int nf_flow_offload_rhash_params;
static int rhashtable_insert_fast(struct rhashtable *hash, struct rhash_head *node, int params) {
 struct flow_offload_tuple_rhash *tuple = container_of(node, struct flow_offload_tuple_rhash, node);
 assert(hash == &table.rhashtable && !params && live); insertions++;
 if (insertions == fail_insert) return -ENOMEM;
 assert(!hash->slot[tuple->tuple.dir]); hash->slot[tuple->tuple.dir] = tuple;
 interleave(tuple->tuple.dir ? REPLY_VISIBLE : ORIGINAL_VISIBLE); return 0;
}
static int rhashtable_remove_fast(struct rhashtable *hash, struct rhash_head *node, int params) {
 struct flow_offload_tuple_rhash *tuple = container_of(node, struct flow_offload_tuple_rhash, node);
 assert(hash == &table.rhashtable && !params && hash->slot[tuple->tuple.dir] == tuple);
 hash->slot[tuple->tuple.dir] = NULL; removals++; return 0;
}
static struct flow_offload_tuple_rhash *rhashtable_lookup(struct rhashtable *hash,
 const struct flow_offload_tuple *tuple, int params) {
 assert(hash == &table.rhashtable && !params && tuple->dir < 2); return hash->slot[tuple->dir];
}
static void *kmalloc(size_t bytes, int flags) {
 assert(bytes == sizeof(struct flow_offload_work) && flags == GFP_ATOMIC);
 if (failed_allocations) { failed_allocations--; return NULL; } return calloc(1, bytes);
}
#define INIT_WORK(work,fn) ((work)->handler = (fn))
static struct net *read_pnet(struct net **net) { return *net; }
#define NF_FLOW_TABLE_STAT_INC_ATOMIC(net,field) ((net)->field++)
#define NF_FLOW_TABLE_STAT_DEC_ATOMIC(net,field) do { assert((net)->field); (net)->field--; } while (0)
static unsigned int nf_flow_offload_add_wq = FLOW_CLS_REPLACE;
static unsigned int nf_flow_offload_del_wq = FLOW_CLS_DESTROY;
static unsigned int nf_flow_offload_stats_wq = FLOW_CLS_STATS;
static bool queue_work(unsigned int queue, struct work_struct *work) {
 struct flow_offload_work *job = container_of(work, struct flow_offload_work, work);
 assert(queue == job->cmd && queue < 3 && job_count < 16 && job->flow == live);
 allocations[queue]++; jobs[job_count++] = work; return true;
}
/* Driver rule construction/stats are outside this lifecycle test. The actual
 * handler, DELETE flags and PENDING-release sequence remain production code. */
static void flow_offload_work_add(struct flow_offload_work *job);
static void flow_offload_work_stats(struct flow_offload_work *job) {
 assert(job->flow == live && live && !retired); completions[FLOW_CLS_STATS]++;
}
static void flow_offload_tuple_del(struct flow_offload_work *job, enum flow_offload_tuple_dir dir) {
 assert(job->flow == live && live && !retired && dir < 2);
 if (dir == FLOW_OFFLOAD_DIR_ORIGINAL) completions[FLOW_CLS_DESTROY]++;
}
'''

AFTER_FLAGS = r'''
static void clear_bit(unsigned int bit, unsigned long *word) {
 *word &= ~BIT(bit);
 if (bit == NF_FLOW_INITIALIZING && live && word == &live->flags)
  interleave(INITIAL_RELEASED);
}
static void flow_offload_work_add(struct flow_offload_work *job) {
 assert(job->flow == live && live && !retired);
 assert(!test_bit(NF_FLOW_INITIALIZING, &live->flags));
 completions[FLOW_CLS_REPLACE]++; set_bit(IPS_HW_OFFLOAD_BIT, &live->ct->status);
}
'''

TESTS = r'''
enum mode { OBSERVE, GC_DYING, GC_ROUTE, GC_BRIDGE, GC_CUSTOM, DIRECT_ALLOC,
 DELAY_DEL_PENDING, DELAY_DEL_COMPLETE, DELAY_DEL_RETIRED,
 CLEANUP_BEFORE_REFRESH, CLEANUP_AFTER_REFRESH, CLEANUP_AFTER_RELEASE, SOFTWARE_RETIRE };
static enum mode mode;
static unsigned int cases;
static void run_jobs(void) {
 while (job_count) {
  struct work_struct *work = jobs[0];
  memmove(jobs, jobs + 1, (--job_count) * sizeof(*jobs));
  assert(live && !retired); work->handler(work);
 }
 assert(!ns.count_wq_add && !ns.count_wq_del && !ns.count_wq_stats);
}
static void grace_period(void) {
 assert(deferred_rcu && !job_count); struct rcu_head *rcu = deferred_rcu;
 deferred_rcu = NULL; rcu->callback(rcu); assert(!live && freed == 1);
}
static void setup(bool hardware, enum mode wanted, unsigned int fail) {
 assert(!live && !job_count && !deferred_rcu);
 memset(&table, 0, sizeof(table)); memset(&ct, 0, sizeof(ct)); memset(&ns, 0, sizeof(ns));
 memset(allocations, 0, sizeof(allocations)); memset(completions, 0, sizeof(completions));
 memset(stages, 0, sizeof(stages)); memset(releases, 0, sizeof(releases));
 removals = retired = freed = fixup_refreshes = ct_refreshes = timeout_extensions = 0;
 insertions = failed_allocations = admission_checks = 0; jiffies = 100000;
 direct_valid = true; bridge_changed = custom_gc = hook_running = false;
 table.hardware = hardware; table.net = &ns; ct.net = &ns; ct.references = 2;
 ct.status = BIT(IPS_OFFLOAD_BIT) | BIT(IPS_SEEN_REPLY_BIT) | BIT(IPS_CONFIRMED_BIT);
 ct.protonum = IPPROTO_UDP; ct.timeout = (u32)jiffies + 120 * HZ;
 ns.udp.timeouts[UDP_CT_UNREPLIED] = 30 * HZ;
 ns.udp.timeouts[UDP_CT_REPLIED] = 120 * HZ;
 ns.tcp.timeouts[TCP_CONNTRACK_ESTABLISHED] = 5 * NF_CT_DAY;
 ns.tcp.timeouts[TCP_CONNTRACK_CLOSE] = 10 * HZ;
 ns.udp.offload_timeout = ns.tcp.offload_timeout = 30 * HZ;
 ct.proto.tcp.state = TCP_CONNTRACK_ESTABLISHED;
 for (unsigned int dir = 0; dir < 2; dir++) {
  ct.proto.tcp.seen[dir].td_maxwin = 1000;
  ct.proto.tcp.seen[dir].flags = IP_CT_TCP_FLAG_MAXACK_SET;
 }
 live = calloc(1, sizeof(*live)); assert(live);
 live->ct = &ct; live->type = NF_FLOW_OFFLOAD_ROUTE;
 live->flags = BIT(NF_FLOW_HW_BIDIRECTIONAL);
 for (unsigned int dir = 0; dir < 2; dir++) live->tuplehash[dir].tuple.dir = dir;
 mode = wanted; fail_insert = fail; cases++;
}
static void checked_lookup(unsigned int dir, bool visible) {
 struct flow_offload_tuple key = { .dir = dir };
 struct flow_offload_tuple_rhash *found = flow_offload_lookup(&table, &key);
 /* Act-ct's real caller can request force-refresh on a half-published
  * reply. Exercise that production refresh if lookup exposes it. */
 if (!visible && found) {
  struct flow_offload *flow = container_of(found, struct flow_offload, tuplehash[dir]);
  flow_offload_refresh(&table, flow, true);
 }
 assert(!!found == visible);
 if (found) assert(found == &live->tuplehash[dir]);
}
static void interleave(enum test_stage stage) {
 if (hook_running) return;
 hook_running = true; stages[stage]++;
 if (stage != INITIAL_RELEASED) {
  if (mode == OBSERVE) {
   checked_lookup(0, false); checked_lookup(1, false);
   assert(!job_count && !admission_checks && !retired);
  }
  if (mode == DIRECT_ALLOC && stage == REPLY_VISIBLE) {
   for (unsigned int cmd = 0; cmd < 3; cmd++) {
    struct flow_offload_work *job = nf_flow_offload_work_alloc(&table, live, cmd);
    assert(job == NULL && !test_bit(NF_FLOW_PENDING, &live->flags));
   }
   assert(!job_count);
  }
  if (stage == ORIGINAL_VISIBLE && mode >= GC_DYING && mode <= GC_CUSTOM) {
   ct.dying = mode == GC_DYING; direct_valid = mode != GC_ROUTE;
   bridge_changed = mode == GC_BRIDGE; custom_gc = mode == GC_CUSTOM;
   nf_flow_offload_gc_step(&table, live, NULL);
   assert(!retired && !job_count && !test_bit(NF_FLOW_TEARDOWN, &live->flags));
   assert(ct.status & BIT(IPS_OFFLOAD_BIT));
   /* The sampled condition may disappear before initialization commits.
    * GC must not tear down a not-yet-published complete flow. */
   ct.dying = false; direct_valid = true; bridge_changed = custom_gc = false;
  }
  if ((stage == ORIGINAL_VISIBLE && mode == CLEANUP_BEFORE_REFRESH) ||
      (stage == CT_REFRESHED && mode == CLEANUP_AFTER_REFRESH)) {
   nf_flow_table_do_cleanup(&table, live, NULL);
   assert(test_bit(NF_FLOW_TEARDOWN, &live->flags) && !(ct.status & BIT(IPS_OFFLOAD_BIT)));
   nf_flow_offload_gc_step(&table, live, NULL);
   assert(!retired && !job_count);
  }
 } else if (mode == CLEANUP_AFTER_RELEASE) {
  nf_flow_table_do_cleanup(&table, live, NULL);
  assert(test_bit(NF_FLOW_TEARDOWN, &live->flags) && !(ct.status & BIT(IPS_OFFLOAD_BIT)));
 } else if (mode == DELAY_DEL_PENDING || mode == DELAY_DEL_COMPLETE || mode == DELAY_DEL_RETIRED) {
  ct.dying = true;
  nf_flow_offload_gc_step(&table, live, NULL);
  assert(!retired && allocations[FLOW_CLS_DESTROY] == 1);
  assert(test_bit(NF_FLOW_HW_DYING, &live->flags));
  if (mode != DELAY_DEL_PENDING) {
   run_jobs(); assert(test_bit(NF_FLOW_HW_DEAD, &live->flags));
   if (mode == DELAY_DEL_RETIRED) {
    nf_flow_offload_gc_step(&table, live, NULL);
    assert(retired == 1 && test_bit(NF_FLOW_PENDING, &live->flags));
   }
  }
 } else if (mode == SOFTWARE_RETIRE) {
  assert(!table.hardware); ct.dying = true;
  nf_flow_offload_gc_step(&table, live, NULL);
  assert(retired == 1 && !job_count);
 }
 hook_running = false;
}
static void retire_success(void) {
 assert(live && !retired); run_jobs();
 nf_flow_table_do_cleanup(&table, live, NULL);
 nf_flow_offload_gc_step(&table, live, NULL);
 if (table.hardware) {
  assert(job_count == 1 && test_bit(NF_FLOW_HW_DYING, &live->flags));
  run_jobs(); nf_flow_offload_gc_step(&table, live, NULL);
 }
 assert(retired == 1 && removals == 2); grace_period();
}
static void normal_and_failures(void) {
 for (unsigned int hardware = 0; hardware < 2; hardware++) {
  setup(hardware, OBSERVE, 0); assert(!flow_offload_add(&table, live));
  assert(stages[REPLY_VISIBLE] == 1 && stages[ORIGINAL_VISIBLE] == 1 &&
         stages[CT_REFRESHED] == 1 && stages[INITIAL_RELEASED] == 1);
  assert(!test_bit(NF_FLOW_INITIALIZING, &live->flags));
  assert(test_bit(NF_FLOW_HW, &live->flags) == !!hardware && ct_refreshes == 1);
  checked_lookup(0, true); checked_lookup(1, true);
  assert(allocations[FLOW_CLS_REPLACE] == hardware); retire_success();
  for (unsigned int fail = 1; fail <= 2; fail++) {
   setup(hardware, OBSERVE, fail); assert(flow_offload_add(&table, live) == -ENOMEM);
   assert(!table.rhashtable.slot[0] && !table.rhashtable.slot[1]);
   assert(test_bit(NF_FLOW_INITIALIZING, &live->flags) && !job_count && !ct_refreshes);
   assert(removals == fail - 1 && !retired && !allocations[FLOW_CLS_REPLACE]);
   /* Same owner-owned error unwind as nft/xt/act_ct: no worker may
    * retain the half-published object beyond this grace period. */
   flow_offload_free(live); grace_period();
  }
 }
}
static void gc_during_initialization(void) {
 for (unsigned int hardware = 0; hardware < 2; hardware++)
  for (enum mode candidate = GC_DYING; candidate <= GC_CUSTOM; candidate++) {
   setup(hardware, candidate, 0); assert(!flow_offload_add(&table, live));
   assert(stages[ORIGINAL_VISIBLE] && stages[INITIAL_RELEASED] && !retired && !fixup_refreshes);
   assert(allocations[FLOW_CLS_REPLACE] == hardware); retire_success();
  }
 setup(true, DIRECT_ALLOC, 0); assert(!flow_offload_add(&table, live));
 assert(allocations[FLOW_CLS_REPLACE] == 1 && !allocations[FLOW_CLS_DESTROY]); retire_success();
}
static void delayed_initial_add(void) {
 for (enum mode candidate = DELAY_DEL_PENDING; candidate <= DELAY_DEL_RETIRED; candidate++) {
  setup(true, candidate, 0); assert(!flow_offload_add(&table, live));
  assert(stages[INITIAL_RELEASED] && !allocations[FLOW_CLS_REPLACE]);
  if (!retired) { run_jobs(); nf_flow_offload_gc_step(&table, live, NULL); }
  assert(retired == 1 && test_bit(NF_FLOW_PENDING, &live->flags));
  assert(allocations[FLOW_CLS_DESTROY] == 1 && completions[FLOW_CLS_DESTROY] == 1);
  assert(!table.rhashtable.slot[0] && !table.rhashtable.slot[1]); grace_period();
 }
 setup(false, SOFTWARE_RETIRE, 0); assert(!flow_offload_add(&table, live));
 assert(stages[INITIAL_RELEASED] && retired == 1 && !job_count); grace_period();
}
static void cleanup_and_allocation_failure(void) {
 for (unsigned int hardware = 0; hardware < 2; hardware++)
  for (enum mode candidate = CLEANUP_BEFORE_REFRESH; candidate <= CLEANUP_AFTER_RELEASE; candidate++)
   for (unsigned int protocol_case = 0; protocol_case < 5; protocol_case++) {
    u32 expected;
    setup(hardware, candidate, 0);
    switch (protocol_case) {
    case 0: expected = (u32)jiffies + 120 * HZ; break; /* replied UDP */
    case 1:
     clear_bit(IPS_SEEN_REPLY_BIT, &ct.status);
     ct.timeout = expected = (u32)jiffies + 30 * HZ; break;
    case 2: /* A supported shorter TCP established sysctl timeout. */
     ct.protonum = IPPROTO_TCP;
     ns.tcp.timeouts[TCP_CONNTRACK_ESTABLISHED] = 180 * HZ;
     ct.timeout = expected = (u32)jiffies + 180 * HZ; break;
    case 3: /* Default established TCP must not be extended by fixup. */
     ct.protonum = IPPROTO_TCP; ct.timeout = (u32)jiffies + 5 * NF_CT_DAY;
     expected = (u32)jiffies + NF_CT_DAY; break;
    default: /* Fixed conntrack deadlines must survive both refreshes. */
     set_bit(IPS_FIXED_TIMEOUT_BIT, &ct.status);
     ct.timeout = expected = (u32)jiffies + 500 * HZ; break;
    }
    assert(!flow_offload_add(&table, live));
    assert(test_bit(NF_FLOW_TEARDOWN, &live->flags) && !test_bit(NF_FLOW_INITIALIZING, &live->flags));
    assert(!(ct.status & BIT(IPS_OFFLOAD_BIT)) && !retired && ct.timeout == expected);
    assert(ct_refreshes == 1);
    if (ct.protonum == IPPROTO_TCP) {
     assert(ct.proto.tcp.state == TCP_CONNTRACK_ESTABLISHED && !ct.lock);
     for (unsigned int dir = 0; dir < 2; dir++) {
      assert(!ct.proto.tcp.seen[dir].td_maxwin);
      assert(!(ct.proto.tcp.seen[dir].flags & IP_CT_TCP_FLAG_MAXACK_SET));
     }
    }
    checked_lookup(0, false); checked_lookup(1, false);
    nf_flow_table_do_cleanup(&table, live, NULL);
    assert(ct.timeout == expected); /* one-shot teardown remains idempotent */
    /* Initializing is not permission to discard concurrent cleanup. An
     * already requested ADD may still run before asynchronous GC deletes it;
     * this test does not claim a synchronous policy/packet barrier. */
    retire_success(); assert(ct.timeout == expected);
   }
 setup(true, OBSERVE, 0); failed_allocations = 1;
 assert(!flow_offload_add(&table, live));
 assert(!job_count && !test_bit(NF_FLOW_PENDING, &live->flags));
 checked_lookup(0, true); jiffies += HZ + 1;
 flow_offload_refresh(&table, live, false);
 assert(allocations[FLOW_CLS_REPLACE] == 1); retire_success();
}
int main(int argc, char **argv) {
 setbuf(stdout, NULL);
 if (argc == 2 && !strcmp(argv[1], "gc-first")) {
  /* Isolate the original-visible, not-yet-HW path from the independent
   * reply-reader failure so the full pre-229 algorithm proves both. */
  setup(true, GC_ROUTE, 0); assert(!flow_offload_add(&table, live)); retire_success();
  return 0;
 }
 normal_and_failures(); gc_during_initialization(); delayed_initial_add(); cleanup_and_allocation_failure();
 printf("Initial flow publication: %u executed insertion/lookup/GC/cleanup/late-ADD cases passed; "
        "production lifetime functions, controlled hash/RCU/workqueue boundaries.\n", cases);
 return 0;
}
'''


def replace_once(text: str, old: str, new: str) -> str:
    assert text.count(old) == 1, f"negative control must replace exactly once: {old!r}"
    return text.replace(old, new, 1)


variants = {"production": dict(functions)}
if not args.no_negative_controls:
    no_lookup = dict(functions)
    no_lookup["flow_offload_lookup"] = replace_once(
        no_lookup["flow_offload_lookup"],
        "\tif (test_bit_acquire(NF_FLOW_INITIALIZING, &flow->flags))\n\t\treturn NULL;\n", "")
    variants["exposed-partial-reply"] = no_lookup
    no_gc = dict(functions)
    no_gc["nf_flow_offload_gc_step"] = replace_once(
        no_gc["nf_flow_offload_gc_step"],
        "\tif (test_bit_acquire(NF_FLOW_INITIALIZING, &flow->flags))\n\t\treturn;\n", "")
    variants["unfenced-initial-gc"] = no_gc
    no_allocator = dict(functions)
    no_allocator["nf_flow_offload_work_alloc"] = replace_once(
        no_allocator["nf_flow_offload_work_alloc"],
        "\tif (test_bit_acquire(NF_FLOW_INITIALIZING, &flow->flags) ||\n\t    test_bit(NF_FLOW_HW_DYING, &flow->flags)) {",
        "\tif (test_bit(NF_FLOW_HW_DYING, &flow->flags)) {")
    variants["unfenced-initial-work"] = no_allocator
    late_hw = dict(functions)
    late_hw["flow_offload_add"] = replace_once(
        late_hw["flow_offload_add"],
        "\tif (nf_flowtable_hw_offload(flow_table))\n\t\t__set_bit(NF_FLOW_HW, &flow->flags);\n", "")
    late_hw["flow_offload_add"] = replace_once(
        late_hw["flow_offload_add"],
        "\tif (nf_flowtable_hw_offload(flow_table))\n\t\tnf_flow_offload_add(flow_table, flow);",
        "\tif (nf_flowtable_hw_offload(flow_table)) {\n\t\t__set_bit(NF_FLOW_HW, &flow->flags);\n\t\tnf_flow_offload_add(flow_table, flow);\n\t}")
    variants["late-hardware-lifetime-class"] = late_hw
    no_cleanup_fixup = dict(functions)
    no_cleanup_fixup["flow_offload_add"] = replace_once(
        no_cleanup_fixup["flow_offload_add"],
        "\tif (test_bit(NF_FLOW_TEARDOWN, &flow->flags))\n\t\tflow_offload_fixup_ct(flow);\n", "")
    variants["lost-cleanup-conntrack-timeout"] = no_cleanup_fixup
    before = dict(late_hw)
    before["flow_offload_lookup"] = no_lookup["flow_offload_lookup"]
    before["nf_flow_offload_gc_step"] = no_gc["nf_flow_offload_gc_step"]
    before["nf_flow_offload_work_alloc"] = no_allocator["nf_flow_offload_work_alloc"]
    before["flow_offload_add"] = replace_once(before["flow_offload_add"],
        "\t__set_bit(NF_FLOW_INITIALIZING, &flow->flags);\n", "")
    before["flow_offload_add"] = replace_once(before["flow_offload_add"],
        "\tsmp_mb__before_atomic();\n\tclear_bit(NF_FLOW_INITIALIZING, &flow->flags);\n", "")
    before["flow_offload_add"] = replace_once(before["flow_offload_add"],
        "\tsmp_mb();\n\tif (test_bit(NF_FLOW_TEARDOWN, &flow->flags))\n\t\tflow_offload_fixup_ct(flow);\n", "")
    variants["pre-229-publication"] = before

environment = os.environ.copy()
environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
environment.setdefault("UBSAN_OPTIONS", "halt_on_error=1")
production_hash = hashlib.sha256("".join(functions[name] for name in order).encode()).hexdigest()


def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


with tempfile.TemporaryDirectory(prefix="flowtable-initial-publication-") as directory:
    directory = Path(directory)
    for name, selected in variants.items():
        # The enum comes from the same prepared kernel as the function bodies.
        source = COMMON + flag_enum.group() + "\n" + AFTER_FLAGS
        source += "\n".join(selected[entry] for entry in order) + TESTS
        cfile, binary = directory / f"{name}.c", directory / name
        cfile.write_text(source)
        subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-parameter", "-Wno-unused-function", "-Wno-sign-compare",
                        "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                        str(cfile), "-o", str(binary)], check=True)
        command = [str(binary)] + (["gc-first"] if name == "pre-229-publication" else [])
        result = subprocess.run(command, capture_output=True, text=True, env=environment, preexec_fn=no_core)
        if name == "production":
            print(result.stdout, end="")
            if result.returncode:
                print(result.stderr, end="")
            result.check_returncode()
        else:
            assert result.returncode != 0 and "Assertion" in result.stderr, (name, result.stdout, result.stderr)
            diagnostic = next(line for line in result.stderr.splitlines() if "Assertion" in line)
            print(f"Runtime negative control rejected {name}: {diagnostic.split('Assertion', 1)[1].strip()}")
print("Extracted production lifecycle sha256:", production_hash)
