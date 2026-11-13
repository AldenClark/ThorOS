#!/usr/bin/env python3
"""Execute the complete production L2 admission gate with controlled races.

Linux list/net/qdisc plumbing is stubbed; the production .c and public header
are compiled unchanged. A real pthread mutex serializes the spinlock API and
barriers order competing installer/policy threads. This verifies the gate,
not the coverage/order of every Linux call site in patch 220 or silicon drain.
"""
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18"
SOURCE = OVERLAY / "net/core/rtl9617c-switch.c"
HEADER = OVERLAY / "include/linux/rtl9617c-switch.h"

HEADERS = {
    "linux/types.h": r'''
#pragma once
#include_next <linux/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
typedef uint64_t u64;
''',
    "linux/kconfig.h": "#pragma once\n#define CONFIG_RTL9617C_SWITCH_GUARD 1\n#define CONFIG_NET_XGRESS 1\n#define CONFIG_BRIDGE 1\n#define CONFIG_NET_SWITCHDEV 1\n#define IS_ENABLED(x) (x)\n#define IS_REACHABLE(x) (x)\n",
    "linux/cleanup.h": r'''
#pragma once
#define DEFINE_CLASS(name, type, exit, init, ...) \
 typedef type class_##name##_t; \
 static inline void class_##name##_destructor(class_##name##_t *p) { type _T = *p; exit; } \
 static inline class_##name##_t class_##name##_constructor(__VA_ARGS__) { return (init); }
#define CLASS(name, variable) class_##name##_t variable \
 __attribute__((cleanup(class_##name##_destructor))) = class_##name##_constructor
''',
    "linux/list.h": r'''
#pragma once
#include <stddef.h>
#include <stdbool.h>
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(name) struct list_head name = { &(name), &(name) }
#define container_of(p, type, member) ((type *)((char *)(p) - offsetof(type, member)))
#define list_for_each_entry(pos, head, member) \
 for (struct list_head *cursor = (head)->next; cursor != (head) && \
      ((pos) = container_of(cursor, __typeof__(*(pos)), member)); cursor = cursor->next)
static inline void list_add_tail(struct list_head *node, struct list_head *head) {
 node->prev = head->prev; node->next = head; head->prev->next = node; head->prev = node;
}
static inline void list_del_init(struct list_head *node) {
 node->next->prev = node->prev; node->prev->next = node->next; node->next = node->prev = node;
}
static inline bool list_empty(const struct list_head *head) { return head->next == head; }
''',
    "linux/export.h": "#pragma once\n#define EXPORT_SYMBOL_GPL(name)\n",
    "linux/spinlock.h": r'''
#pragma once
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
static _Thread_local unsigned int test_gate_depth;
static unsigned int test_warnings;
#define DEFINE_SPINLOCK(name) pthread_mutex_t name = PTHREAD_MUTEX_INITIALIZER
#define spin_lock_irqsave(lock, flags) do { \
 (flags) = 0; assert(test_gate_depth == 0); assert(!pthread_mutex_lock(lock)); test_gate_depth++; \
} while (0)
#define spin_unlock_irqrestore(lock, flags) do { \
 (void)(flags); assert(test_gate_depth == 1); test_gate_depth--; assert(!pthread_mutex_unlock(lock)); \
} while (0)
#define unlikely(value) (value)
static inline bool test_warn(bool value) { if (value) test_warnings++; return value; }
#define WARN_ON_ONCE(value) test_warn(!!(value))
''',
    "net/net_namespace.h": r'''
#pragma once
#include <assert.h>
#include <stdatomic.h>
#include <linux/rtl9617c-switch.h>
struct net { struct rtl9617c_switch_net rtl9617c_switch; atomic_uint references; };
static inline struct net *get_net(struct net *net) { atomic_fetch_add(&net->references, 1); return net; }
static inline void put_net(struct net *net) { assert(atomic_fetch_sub(&net->references, 1)); }
''',
    "linux/netdevice.h": r'''
#pragma once
#include <net/net_namespace.h>
struct Qdisc;
struct netdev_queue { struct Qdisc *qdisc_sleeping; };
struct net_device {
 struct net *net;
 struct Qdisc *qdisc;
 unsigned int num_tx_queues;
 unsigned int xdp_count;
 void *tcx_ingress, *tcx_egress;
 struct netdev_queue tx[4];
};
static inline struct net *dev_net(const struct net_device *dev) { return dev->net; }
static inline unsigned int dev_xdp_prog_count(const struct net_device *dev) { return dev->xdp_count; }
static inline struct netdev_queue *netdev_get_tx_queue(const struct net_device *dev, unsigned int i) {
 assert(i < 4); return (struct netdev_queue *)&dev->tx[i];
}
#define rtnl_dereference(value) (value)
#define rcu_access_pointer(value) (value)
static _Thread_local bool test_rtnl;
#define ASSERT_RTNL() assert(test_rtnl)
''',
    "net/sch_generic.h": r'''
#pragma once
struct Qdisc_ops { const char *id; };
struct Qdisc { unsigned int handle, flags; const struct Qdisc_ops *ops; };
#define TCQ_F_SW_POLICY (1U << 17)
''',
}

TEST = r'''
#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include "production.c"

struct switch_model { bool open, arm_succeeds; unsigned int closed, rebuilt, armed; };
static unsigned int cases;
static void close_gate(void *private) {
 struct switch_model *model = private; assert(test_gate_depth == 1);
 model->open = false; model->closed++;
}
static void rebuild(void *private) {
 struct switch_model *model = private; assert(test_gate_depth == 1); model->rebuilt++;
}
static bool arm(void *private) {
 struct switch_model *model = private; assert(test_gate_depth == 1);
 /* Model an arm which may have partly changed MMIO before reporting failure. */
 model->open = true; model->armed++; return model->arm_succeeds;
}
static const struct rtl9617c_switch_guard_ops operations = { close_gate, rebuild, arm };
struct publication { unsigned int writes; int result; };
static int publish_fdb(void *private) {
 struct publication *publication = private;
 assert(test_gate_depth == 1); publication->writes++; return publication->result;
}
static void attach(struct rtl9617c_switch_guard *guard, struct net *net, struct switch_model *model) {
 model->arm_succeeds = true;
 assert(!rtl9617c_switch_guard_register(guard, net, &operations, model));
 assert(guard->registered && !model->open && atomic_load(&net->references));
}
static void fresh_arm(struct rtl9617c_switch_guard *guard, struct switch_model *model) {
 assert(rtl9617c_switch_guard_try_arm(guard, rtl9617c_switch_guard_generation(guard)));
 assert(model->open);
}
static int scoped_change(struct net_device *dev, unsigned int branch) {
 CLASS(rtl9617c_switch_policy, scope)(dev);
 (void)scope;
 assert(dev->net->rtl9617c_switch.active == 1);
 if (branch == 0) return -EIO;
 if (branch == 1) { CLASS(rtl9617c_switch_policy, nested)(dev); (void)nested;
  assert(dev->net->rtl9617c_switch.active == 2); return -EINVAL; }
 return 0;
}

static void basic_and_nested(void) {
 struct net net = {0}; struct net_device dev = { .net = &net };
 struct rtl9617c_switch_guard guard = {0}; struct switch_model model = {0};
 assert(rtl9617c_switch_guard_blocked(&guard));
 assert(!rtl9617c_switch_guard_try_arm(&guard, 0));
 assert(!rtl9617c_switch_policy_begin(NULL)); rtl9617c_switch_policy_end(NULL);
 attach(&guard, &net, &model); fresh_arm(&guard, &model);
 u64 worker_epoch = rtl9617c_switch_guard_generation(&guard);
 unsigned int before_rebuild = model.rebuilt;
 rtl9617c_switch_guard_quiesce(&guard);
 assert(!model.open && model.rebuilt == before_rebuild);
 assert(rtl9617c_switch_guard_generation(&guard) == worker_epoch);
 fresh_arm(&guard, &model); /* Worker close must not queue itself or churn epochs. */
 unsigned int closed = model.closed, rebuilt = model.rebuilt;
 assert(rtl9617c_switch_guard_register(&guard, &net, &operations, &model) == -EBUSY);
 assert(model.closed == closed && model.rebuilt == rebuilt && atomic_load(&net.references) == 1);
 u64 old = rtl9617c_switch_guard_generation(&guard);
 struct net *first = rtl9617c_switch_policy_begin(&dev);
 assert(first == &net && net.rtl9617c_switch.active == 1 && !model.open);
 struct net *second = rtl9617c_switch_policy_begin(&dev);
 assert(second == first && net.rtl9617c_switch.active == 2);
 assert(!rtl9617c_switch_guard_try_arm(&guard, rtl9617c_switch_guard_generation(&guard)));
 rtl9617c_switch_policy_end(first);
 assert(net.rtl9617c_switch.active == 1);
 assert(!rtl9617c_switch_guard_try_arm(&guard, rtl9617c_switch_guard_generation(&guard)));
 rtl9617c_switch_policy_end(second);
 assert(!net.rtl9617c_switch.active && !model.open);
 assert(!rtl9617c_switch_guard_try_arm(&guard, old)); fresh_arm(&guard, &model);
 for (unsigned int branch = 0; branch < 3; branch++) {
  (void)scoped_change(&dev, branch);
  assert(!net.rtl9617c_switch.active && !model.open); fresh_arm(&guard, &model); cases++;
 }
 model.arm_succeeds = false; closed = model.closed;
 assert(!rtl9617c_switch_guard_try_arm(&guard, rtl9617c_switch_guard_generation(&guard)));
 assert(!model.open && model.closed == closed + 1);
 model.arm_succeeds = true; old = rtl9617c_switch_guard_generation(&guard);
 rtl9617c_switch_guard_invalidate(&guard);
 assert(!model.open && !rtl9617c_switch_guard_try_arm(&guard, old)); fresh_arm(&guard, &model);
 rtl9617c_switch_guard_unregister(&guard);
 assert(!guard.registered && !model.open && !atomic_load(&net.references));
 closed = model.closed; rebuilt = model.rebuilt;
 rtl9617c_switch_guard_unregister(&guard);
 rtl9617c_switch_nf_block(&net); rtl9617c_switch_nf_unblock(&net);
 rtl9617c_switch_policy_end(rtl9617c_switch_policy_begin(&dev));
 assert(model.closed == closed && model.rebuilt == rebuilt);
 assert(rtl9617c_switch_guard_blocked(&guard) && !rtl9617c_switch_guard_generation(&guard));
 assert(!rtl9617c_switch_guard_try_arm(&guard, 0));
 struct rtl9617c_switch_guard_ops invalid = operations; invalid.arm = NULL;
 assert(rtl9617c_switch_guard_register(&guard, &net, &invalid, &model) == -EINVAL);
 assert(!atomic_load(&net.references)); cases++;
}

static void persistent_vetoes(void) {
 struct net net = {0}; struct net_device a = {.net=&net}, b = {.net=&net};
 struct rtl9617c_switch_guard guard = {0}; struct switch_model model = {0};
 /* Firewall state predating probe remains authoritative after registration. */
 rtl9617c_switch_nf_block(&net); rtl9617c_switch_nf_block(&net);
 attach(&guard, &net, &model);
 assert(rtl9617c_switch_guard_blocked(&guard));
 assert(!rtl9617c_switch_guard_try_arm(&guard, rtl9617c_switch_guard_generation(&guard)));
 rtl9617c_switch_nf_unblock(&net);
 assert(net.rtl9617c_switch.nf_blockers == 1);
 assert(!rtl9617c_switch_guard_try_arm(&guard, rtl9617c_switch_guard_generation(&guard)));
 rtl9617c_switch_nf_unblock(&net); fresh_arm(&guard, &model);
 rtl9617c_switch_tcx_change(&a, false, true);
 rtl9617c_switch_tcx_change(&b, false, true);
 assert(!model.open && net.rtl9617c_switch.tcx_blockers == 2);
 u64 generation = rtl9617c_switch_guard_generation(&guard);
 rtl9617c_switch_tcx_change(&a, true, true);
 assert(rtl9617c_switch_guard_generation(&guard) == generation);
 rtl9617c_switch_tcx_change(&a, true, false);
 assert(net.rtl9617c_switch.tcx_blockers == 1 && rtl9617c_switch_guard_blocked(&guard));
 rtl9617c_switch_xdp_change(&a, false, true);
 rtl9617c_switch_tcx_change(&b, true, false);
 assert(!net.rtl9617c_switch.tcx_blockers && net.rtl9617c_switch.xdp_blockers == 1);
 assert(!rtl9617c_switch_guard_try_arm(&guard, rtl9617c_switch_guard_generation(&guard)));
 rtl9617c_switch_xdp_change(&a, true, false); fresh_arm(&guard, &model);
 rtl9617c_switch_guard_unregister(&guard);
 /* XDP/TCX also survive a driver unbind and late rebind. */
 rtl9617c_switch_xdp_change(&a, false, true); attach(&guard, &net, &model);
 assert(rtl9617c_switch_guard_blocked(&guard));
 rtl9617c_switch_xdp_change(&a, true, false); fresh_arm(&guard, &model);
 rtl9617c_switch_guard_unregister(&guard); cases++;
}

static void feedback_publication(void) {
 struct net net = {0}; struct net_device dev = {.net=&net};
 struct rtl9617c_switch_guard guard = {0}; struct switch_model model = {0};
 struct publication publication = {.result=17};
 assert(rtl9617c_switch_guard_publish(&guard, 0, publish_fdb, &publication)==-EAGAIN);
 assert(!publication.writes);attach(&guard,&net,&model);
 u64 epoch=rtl9617c_switch_guard_generation(&guard);
 assert(rtl9617c_switch_guard_publish(&guard,epoch,publish_fdb,&publication)==17 && publication.writes==1);
 publication.result=-ENOMEM;
 assert(rtl9617c_switch_guard_publish(&guard,epoch,publish_fdb,&publication)==-ENOMEM && publication.writes==2);
 struct net *scope=rtl9617c_switch_policy_begin(&dev);
 assert(rtl9617c_switch_guard_publish(&guard,epoch,publish_fdb,&publication)==-EAGAIN);
 assert(rtl9617c_switch_guard_publish(&guard,rtl9617c_switch_guard_generation(&guard),publish_fdb,&publication)==-EAGAIN);
 rtl9617c_switch_policy_end(scope);
 assert(rtl9617c_switch_guard_publish(&guard,epoch,publish_fdb,&publication)==-EAGAIN && publication.writes==2);
 for(unsigned int blocker=0;blocker<4;blocker++) {
  switch(blocker){
  case 0:rtl9617c_switch_nf_block(&net);break;
  case 1:rtl9617c_switch_tcx_change(&dev,false,true);break;
  case 2:rtl9617c_switch_xdp_change(&dev,false,true);break;
  case 3:net.rtl9617c_switch.poisoned=true;break;
  }
  assert(rtl9617c_switch_guard_publish(&guard,rtl9617c_switch_guard_generation(&guard),publish_fdb,&publication)==-EAGAIN);
  assert(publication.writes==2);
  switch(blocker){
  case 0:rtl9617c_switch_nf_unblock(&net);break;
  case 1:rtl9617c_switch_tcx_change(&dev,true,false);break;
  case 2:rtl9617c_switch_xdp_change(&dev,true,false);break;
  case 3:net.rtl9617c_switch.poisoned=false;break;
  }
 }
 rtl9617c_switch_guard_unregister(&guard);
 assert(rtl9617c_switch_guard_publish(&guard,0,publish_fdb,&publication)==-EAGAIN && publication.writes==2);
 cases++;
}

static void namespaces_and_poison(void) {
 struct net a = {0}, b = {0};
 struct rtl9617c_switch_guard ga = {0}, ga2 = {0}, gb = {0};
 struct switch_model ma = {0}, ma2 = {0}, mb = {0};
 attach(&ga, &a, &ma); attach(&ga2, &a, &ma2); attach(&gb, &b, &mb);
 fresh_arm(&ga, &ma); fresh_arm(&ga2, &ma2); fresh_arm(&gb, &mb);
 u64 before = rtl9617c_switch_guard_generation(&gb);
 rtl9617c_switch_nf_block(&a);
 assert(!ma.open && !ma2.open && mb.open);
 assert(rtl9617c_switch_guard_generation(&gb) == before);
 rtl9617c_switch_nf_unblock(&a);
 rtl9617c_switch_guard_unregister(&ga); rtl9617c_switch_guard_unregister(&ga2);
 rtl9617c_switch_guard_unregister(&gb);
 assert(!atomic_load(&a.references) && !atomic_load(&b.references));
 for (unsigned int fault = 0; fault < 8; fault++) {
  struct net net = {0}; struct net_device dev = {.net=&net};
  struct rtl9617c_switch_guard guard = {0}; struct switch_model model = {0};
  attach(&guard, &net, &model); fresh_arm(&guard, &model);
  switch (fault) {
  case 0: net.rtl9617c_switch.generation = UINT64_MAX; rtl9617c_switch_guard_invalidate(&guard); break;
  case 1: net.rtl9617c_switch.active = UINT_MAX; (void)rtl9617c_switch_policy_begin(&dev); break;
  case 2: net.rtl9617c_switch.nf_blockers = UINT_MAX; rtl9617c_switch_nf_block(&net); break;
  case 3: rtl9617c_switch_policy_end(&net); break;
  case 4: rtl9617c_switch_nf_unblock(&net); break;
  case 5: rtl9617c_switch_tcx_change(&dev, true, false); break;
  case 6: rtl9617c_switch_xdp_change(&dev, true, false); break;
  case 7: net.rtl9617c_switch.xdp_blockers = UINT_MAX; rtl9617c_switch_xdp_change(&dev, false, true); break;
  }
  assert(net.rtl9617c_switch.poisoned && rtl9617c_switch_guard_blocked(&guard));
  assert(!model.open); /* Poisoning an already armed gate must close it now. */
  assert(!rtl9617c_switch_guard_try_arm(&guard, rtl9617c_switch_guard_generation(&guard)));
  rtl9617c_switch_guard_unregister(&guard); cases++;
 }
}

struct race {
 pthread_barrier_t barrier;
 struct net net;
 struct net_device dev;
 struct rtl9617c_switch_guard guard;
 struct switch_model model;
 struct publication publication;
 unsigned int kind;
};
static void rendezvous(struct race *race) {
 int ret = pthread_barrier_wait(&race->barrier);
 assert(ret == 0 || ret == PTHREAD_BARRIER_SERIAL_THREAD);
}
static void *installer(void *private) {
 struct race *race = private;
 u64 epoch = rtl9617c_switch_guard_generation(&race->guard);
 rendezvous(race); rendezvous(race); /* Policy has begun, publication is pending. */
 assert(!race->model.open);
 assert(!rtl9617c_switch_guard_try_arm(&race->guard, epoch));
 assert(!rtl9617c_switch_guard_try_arm(&race->guard, rtl9617c_switch_guard_generation(&race->guard)));
 assert(rtl9617c_switch_guard_publish(&race->guard,epoch,publish_fdb,&race->publication)==-EAGAIN);
 assert(rtl9617c_switch_guard_publish(&race->guard,rtl9617c_switch_guard_generation(&race->guard),publish_fdb,&race->publication)==-EAGAIN);
 assert(!race->publication.writes);
 rendezvous(race); rendezvous(race); /* Policy has now ended/removal completed. */
 assert(!rtl9617c_switch_guard_try_arm(&race->guard, epoch));
 assert(rtl9617c_switch_guard_publish(&race->guard,epoch,publish_fdb,&race->publication)==-EAGAIN);
 if (race->kind != 4) {
  fresh_arm(&race->guard, &race->model);
  assert(!rtl9617c_switch_guard_publish(&race->guard,rtl9617c_switch_guard_generation(&race->guard),publish_fdb,&race->publication));
  assert(race->publication.writes==1);
 } else assert(!race->publication.writes);
 return NULL;
}
static void *publisher(void *private) {
 struct race *race = private; struct net *scope = NULL;
 rendezvous(race);
 switch (race->kind) {
 case 0: scope = rtl9617c_switch_policy_begin(&race->dev); break;
 case 1: rtl9617c_switch_nf_block(&race->net); break;
 case 2: rtl9617c_switch_tcx_change(&race->dev, false, true); break;
 case 3: rtl9617c_switch_xdp_change(&race->dev, false, true); break;
 case 4: rtl9617c_switch_guard_unregister(&race->guard); break;
 }
 rendezvous(race); rendezvous(race);
 switch (race->kind) {
 case 0: rtl9617c_switch_policy_end(scope); break;
 case 1: rtl9617c_switch_nf_unblock(&race->net); break;
 case 2: rtl9617c_switch_tcx_change(&race->dev, true, false); break;
 case 3: rtl9617c_switch_xdp_change(&race->dev, true, false); break;
 }
 rendezvous(race); return NULL;
}
static void threaded_interleavings(void) {
 for (unsigned int kind = 0; kind < 5; kind++) for (unsigned int repeat = 0; repeat < 16; repeat++) {
  struct race race = {.kind=kind}; race.dev.net = &race.net;
  attach(&race.guard, &race.net, &race.model); fresh_arm(&race.guard, &race.model);
  assert(!pthread_barrier_init(&race.barrier, NULL, 2));
  pthread_t install, publish;
  assert(!pthread_create(&install, NULL, installer, &race));
  assert(!pthread_create(&publish, NULL, publisher, &race));
  assert(!pthread_join(install, NULL)); assert(!pthread_join(publish, NULL));
  assert(!pthread_barrier_destroy(&race.barrier));
  rtl9617c_switch_guard_unregister(&race.guard);
  assert(!race.model.open && !atomic_load(&race.net.references)); cases++;
 }
}

static void qdisc_policy(void) {
 const struct Qdisc_ops fq_codel = {.id="fq_codel"};
 struct Qdisc plain = {.ops=&fq_codel}, custom = {.handle=0x10000,.ops=&fq_codel};
 struct Qdisc changed = {.flags=TCQ_F_SW_POLICY,.ops=&fq_codel};
 struct net_device dev = {.qdisc=&plain, .num_tx_queues=4};
 for (unsigned int i = 0; i < 4; i++) dev.tx[i].qdisc_sleeping = &plain;
 test_rtnl = true; assert(!rtl9617c_switch_device_has_policy(&dev));
 dev.qdisc = &custom; assert(rtl9617c_switch_device_has_policy(&dev));
 dev.qdisc = &changed; assert(rtl9617c_switch_device_has_policy(&dev)); dev.qdisc = &plain;
 for (unsigned int i = 0; i < 4; i++) {
  dev.tx[i].qdisc_sleeping = &custom; assert(rtl9617c_switch_device_has_policy(&dev));
  dev.tx[i].qdisc_sleeping = &changed; assert(rtl9617c_switch_device_has_policy(&dev));
  dev.tx[i].qdisc_sleeping = &plain; cases++;
 }
 const char *transparent[] = {"noop", "noqueue", "mq", "pfifo_fast", "fq_codel", "fq"};
 const char *policy[] = {"cake", "htb", "tbf", "clsact", "ingress", "unknown"};
 for (unsigned int i = 0; i < 6; i++) {
  const struct Qdisc_ops allowed = {.id=transparent[i]}, denied = {.id=policy[i]};
  struct Qdisc candidate = {.ops=&allowed}; dev.qdisc = &candidate;
  assert(!rtl9617c_switch_device_has_policy(&dev));
  candidate.ops = &denied; assert(rtl9617c_switch_device_has_policy(&dev));
  dev.qdisc = &plain; dev.tx[3].qdisc_sleeping = &candidate;
  assert(rtl9617c_switch_device_has_policy(&dev)); dev.tx[3].qdisc_sleeping = &plain; cases++;
 }
 test_rtnl = false;
}

static void namespace_move(void) {
 struct net old = {0}, next = {0};
 struct net_device dev = {.net=&old, .xdp_count=2, .tcx_ingress=&old, .tcx_egress=&next};
 struct rtl9617c_switch_guard ga = {0}, gb = {0};
 struct switch_model ma = {0}, mb = {0};
 attach(&ga, &old, &ma); attach(&gb, &next, &mb); fresh_arm(&gb, &mb);
 for (unsigned int i = 0; i < 2; i++) {
  rtl9617c_switch_tcx_change(&dev, false, true);
  rtl9617c_switch_xdp_change(&dev, false, true);
 }
 test_rtnl = true;
 assert(rtl9617c_switch_move_begin(&dev, &next) == &old);
 assert(old.rtl9617c_switch.active == 1 && next.rtl9617c_switch.active == 1);
 assert(!old.rtl9617c_switch.tcx_blockers && !old.rtl9617c_switch.xdp_blockers);
 assert(next.rtl9617c_switch.tcx_blockers == 2 && next.rtl9617c_switch.xdp_blockers == 2);
 assert(!ma.open && !mb.open);
 assert(!rtl9617c_switch_guard_try_arm(&ga, rtl9617c_switch_guard_generation(&ga)));
 assert(!rtl9617c_switch_guard_try_arm(&gb, rtl9617c_switch_guard_generation(&gb)));
 dev.net = &next; /* The real call site publishes after move_begin. */
 rtl9617c_switch_policy_end(&next); rtl9617c_switch_policy_end(&old);
 fresh_arm(&ga, &ma); assert(rtl9617c_switch_guard_blocked(&gb));
 for (unsigned int i = 0; i < 2; i++) {
  rtl9617c_switch_tcx_change(&dev, true, false);
  rtl9617c_switch_xdp_change(&dev, true, false);
 }
 fresh_arm(&gb, &mb);
 rtl9617c_switch_guard_unregister(&ga); rtl9617c_switch_guard_unregister(&gb);
 for (unsigned int overflow = 0; overflow < 2; overflow++) {
  old = (struct net){0}; next = (struct net){0}; ga = (struct rtl9617c_switch_guard){0}; gb = (struct rtl9617c_switch_guard){0};
  ma = (struct switch_model){0}; mb = (struct switch_model){0}; dev.net = &old;
  old.rtl9617c_switch.tcx_blockers = old.rtl9617c_switch.xdp_blockers = 2;
  if (overflow) next.rtl9617c_switch.xdp_blockers = UINT_MAX - 1;
  else next.rtl9617c_switch.tcx_blockers = UINT_MAX - 1;
  attach(&ga, &old, &ma); attach(&gb, &next, &mb);
  assert(rtl9617c_switch_move_begin(&dev, &next) == &old); dev.net = &next;
  rtl9617c_switch_policy_end(&old); rtl9617c_switch_policy_end(&next);
  assert(!old.rtl9617c_switch.poisoned && next.rtl9617c_switch.poisoned && !mb.open);
  fresh_arm(&ga, &ma);
  assert(!rtl9617c_switch_guard_try_arm(&gb, rtl9617c_switch_guard_generation(&gb)));
  rtl9617c_switch_guard_unregister(&ga); rtl9617c_switch_guard_unregister(&gb); cases++;
 }
 test_rtnl = false; cases++;
}

int main(void) {
 basic_and_nested(); persistent_vetoes(); feedback_publication(); namespaces_and_poison();
 threaded_interleavings(); qdisc_policy(); namespace_move();
 assert(list_empty(&rtl9617c_switch_guards));
 printf("L2 production gate: %u lifecycle/policy cases including 80 actual two-thread interleavings; stale epochs, nested scopes, late probe, persistent vetoes and namespace isolation PASS\n", cases);
 return 0;
}
'''


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    production = SOURCE.read_text()
    mutations = {
        "stale_epoch_arm": ("state->generation != generation", "((void)generation, false)"),
        "ignore_nested_policy": ("state->poisoned || state->active ||", "state->poisoned || false ||"),
        "partial_arm_not_closed": ("if (!armed)\n\t\tguard->ops->quiesce", "if (false && !armed)\n\t\tguard->ops->quiesce"),
        "stale_fdb_publish": ("state->generation == generation", "((void)generation, true)"),
    }
    environment = dict(os.environ)
    environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
    environment.setdefault("UBSAN_OPTIONS", "halt_on_error=1")
    with tempfile.TemporaryDirectory(prefix="l2-policy-races-") as directory:
        temporary = Path(directory)
        include = temporary / "include"
        for name, body in HEADERS.items():
            path = include / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body)
        (temporary / "test.c").write_text(TEST)
        for name in ["production", *mutations]:
            code = production
            if name != "production":
                old, new = mutations[name]
                if old not in code:
                    raise AssertionError(f"Mutation anchor changed: {name}")
                code = code.replace(old, new)
            (temporary / "production.c").write_text(code)
            binary = temporary / (name + ".bin")
            subprocess.run([
                os.environ.get("CC", "cc"), "-D_GNU_SOURCE", "-std=gnu11", "-O1", "-g",
                "-Wall", "-Wextra", "-Werror", "-pthread",
                "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer",
                "-I", str(include), "-I", str(OVERLAY / "include"),
                str(temporary / "test.c"), "-o", str(binary),
            ], check=True, cwd=temporary)
            result = subprocess.run([str(binary)], env=environment, cwd=temporary,
                                    text=True, capture_output=True, timeout=30)
            if name == "production":
                if result.returncode:
                    raise AssertionError(result.stdout + result.stderr)
                print(result.stdout, end="")
            elif result.returncode == 0 or "Assertion" not in result.stderr:
                raise AssertionError(f"Mutation was not rejected by a runtime invariant: {name}\n" + result.stderr)
    evidence = {
        "production_source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "production_header_sha256": hashlib.sha256(HEADER.read_bytes()).hexdigest(),
        "threaded_interleavings": 80,
        "mutations_rejected": list(mutations),
        "sanitizers": ["address", "undefined"],
        "scope": "production admission gate; Linux callsite coverage and silicon drain are separate tests",
        "hardware_verified": False,
    }
    (ROOT / "artifacts").mkdir(exist_ok=True)
    (ROOT / "artifacts/l2-policy-races.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"L2 policy oracle self-check: {len(mutations)} broken production gate/publication variants rejected")


if __name__ == "__main__":
    main()
