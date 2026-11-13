#!/usr/bin/env python3
"""Execute the real 220 bridge and netfilter L2 eligibility predicates.

The new functions are extracted verbatim from the production kernel patch,
not reimplemented as a Python model.  --kernel additionally checks that an
applied Linux source tree contains the identical functions before compiling.
This is a control-plane regression, not a hardware forwarding benchmark.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "port/overlay/target/linux/rtl9617c/patches-6.18/220-l2-switchdev-policy-gate.patch"
FUNCTIONS = {
    "br_rtl9617c_l2_eligible": "net/bridge/br_switchdev.c",
    "br_rtl9617c_l2_port_eligible": "net/bridge/br_switchdev.c",
    "br_rtl9617c_fdb_learn_publish": "net/bridge/br_fdb.c",
    "br_rtl9617c_fdb_learn": "net/bridge/br_fdb.c",
    "br_rtl9617c_fdb_forget": "net/bridge/br_fdb.c",
    "nf_hook_blocks_l2_switch": "net/netfilter/core.c",
}


def function(source: str, name: str) -> str:
    match = re.search(r"^(?:static\s+)?(?:__always_inline\s+)?(?:bool|int)\s+"
                      + name + r"\(", source, re.M)
    if not match:
        raise AssertionError(f"missing production function: {name}")
    brace = source.index("\n{", match.start()) + 1
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if not depth:
                return source[match.start():index + 1]
    raise AssertionError(f"unterminated production function: {name}")


STUBS = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BIT(n) (1UL << (n))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define rcu_access_pointer(x) (x)
#define ASSERT_RTNL() do { } while (0)
#define ETH_DATA_LEN 1500
#define IFF_UP 1
#define BR_HAIRPIN_MODE BIT(0)
#define BR_BPDU_GUARD BIT(1)
#define BR_ROOT_BLOCK BIT(2)
#define BR_MULTICAST_FAST_LEAVE BIT(3)
#define BR_ADMIN_COST BIT(4)
#define BR_LEARNING BIT(5)
#define BR_FLOOD BIT(6)
#define BR_PROMISC BIT(7)
#define BR_PROXYARP BIT(8)
#define BR_LEARNING_SYNC BIT(9)
#define BR_PROXYARP_WIFI BIT(10)
#define BR_MCAST_FLOOD BIT(11)
#define BR_MULTICAST_TO_UNICAST BIT(12)
#define BR_VLAN_TUNNEL BIT(13)
#define BR_BCAST_FLOOD BIT(14)
#define BR_NEIGH_SUPPRESS BIT(15)
#define BR_ISOLATED BIT(16)
#define BR_MRP_AWARE BIT(17)
#define BR_MRP_LOST_CONT BIT(18)
#define BR_MRP_LOST_IN_CONT BIT(19)
#define BR_TX_FWD_OFFLOAD BIT(20)
#define BR_PORT_LOCKED BIT(21)
#define BR_PORT_MAB BIT(22)
#define BR_NEIGH_VLAN_SUPPRESS BIT(23)
#define BR_BPDU_FILTER BIT(24)
enum {
 BROPT_VLAN_ENABLED, BROPT_VLAN_STATS_ENABLED, BROPT_NF_CALL_IPTABLES,
 BROPT_NF_CALL_IP6TABLES, BROPT_NF_CALL_ARPTABLES, BROPT_GROUP_ADDR_SET,
 BROPT_MULTICAST_ENABLED, BROPT_MULTICAST_QUERY_USE_IFADDR,
 BROPT_MULTICAST_STATS_ENABLED, BROPT_HAS_IPV6_ADDR,
 BROPT_NEIGH_SUPPRESS_ENABLED, BROPT_MTU_SET_BY_USER,
 BROPT_VLAN_STATS_PER_PORT, BROPT_NO_LL_LEARN, BROPT_VLAN_BRIDGE_BINDING,
 BROPT_MCAST_VLAN_SNOOPING_ENABLED, BROPT_MST_ENABLED,
 BROPT_MDB_OFFLOAD_FAIL_NOTIFICATION, BROPT_FDB_LOCAL_VLAN_0,
 BROPT_CFM_ENABLED, BROPT_MRP_ENABLED,
};
enum { BR_FDB_LOCAL, BR_FDB_STATIC, BR_FDB_ADDED_BY_USER,
       BR_FDB_ADDED_BY_EXT_LEARN, BR_FDB_OFFLOADED, BR_FDB_STICKY,
       BR_FDB_LOCKED };
struct net_bridge;
struct net_bridge_port {
 unsigned long flags;
 struct net_bridge_port *backup_port;
 unsigned int backup_nhid;
 struct net_bridge *br;
};
struct net_bridge_fdb_entry {
 unsigned long flags, updated, used;
 struct net_bridge_fdb_entry *next;
 struct net_bridge_port *dst;
 unsigned char addr[6];
};
struct hlist_head {
 struct net_bridge_fdb_entry *first;
};
struct net_bridge {
 unsigned long options;
 unsigned int fdb_max_learned;
 struct hlist_head fdb_list;
 int hash_lock;
};
struct net_device {
 bool master;
 unsigned int promiscuity;
 unsigned int mtu;
 unsigned int flags, hard_header_len;
 void *priv;
 struct net_bridge_port *port;
};
static bool netif_is_bridge_master(const struct net_device *dev)
{ return dev->master; }
static void *netdev_priv(const struct net_device *dev)
{ return dev->priv; }
static bool br_opt_get(const struct net_bridge *br, unsigned int bit)
{ return !!(br->options & BIT(bit)); }
static struct net_bridge_port *br_port_get_rtnl(const struct net_device *dev)
{ return dev->port; }
static int rcu_depth, deletes, notifies, publishing;
static bool allocation_fails;
static unsigned long jiffies = 456;
typedef uint64_t u64;
typedef uint32_t u32;
#ifdef HAVE_LINUX_MTU_TEST
struct sk_buff { unsigned int len; bool gso; };
static bool skb_is_gso(const struct sk_buff *skb) { return skb->gso; }
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#endif
static void rcu_read_lock(void) { rcu_depth++; }
static void rcu_read_unlock(void) { assert(rcu_depth > 0); rcu_depth--; }
#define hlist_for_each_entry_rcu(item, head, member) \
 for ((item) = (assert(rcu_depth), (head)->first); (item); (item) = (item)->next)
static bool test_bit(unsigned int bit, const unsigned long *word)
{ return !!(*word & BIT(bit)); }
static void set_bit(unsigned int bit, unsigned long *word)
{ *word |= BIT(bit); }
static void spin_lock_bh(int *lock) { assert(!*lock); *lock = 1; }
static void spin_unlock_bh(int *lock) { assert(*lock); *lock = 0; }
static struct net_bridge_fdb_entry *br_fdb_find(struct net_bridge *br,
                                             const unsigned char *addr,
                                             unsigned short vid)
{
 struct net_bridge_fdb_entry *fdb;
 assert(br->hash_lock && vid == 0);
 for (fdb = br->fdb_list.first; fdb; fdb = fdb->next)
  if (!memcmp(fdb->addr, addr, 6)) return fdb;
 return NULL;
}
static struct net_bridge_fdb_entry *fdb_create(struct net_bridge *br,
                                             struct net_bridge_port *port,
                                             const unsigned char *addr,
                                             unsigned short vid,
                                             unsigned long flags)
{
 static struct net_bridge_fdb_entry created;
 assert(br->hash_lock && publishing && vid == 0);
 if (allocation_fails) return NULL;
 created = (struct net_bridge_fdb_entry){ .dst = port, .flags = flags,
  .updated = jiffies, .used = jiffies, .next = br->fdb_list.first };
 memcpy(created.addr, addr, 6);
 br->fdb_list.first = &created;
 return &created;
}
static void fdb_delete(struct net_bridge *br, struct net_bridge_fdb_entry *fdb,
                       bool swdev_notify)
{
 assert(br->hash_lock && !swdev_notify && br->fdb_list.first == fdb);
 br->fdb_list.first = fdb->next;
 deletes++;
}
#define RTM_NEWNEIGH 28
static void fdb_notify(struct net_bridge *br, const struct net_bridge_fdb_entry *fdb,
                       int event, bool swdev_notify)
{
 assert(br->hash_lock && !publishing && fdb && !swdev_notify && event == RTM_NEWNEIGH);
 notifies++;
}
/* The full production gate's concurrency is separately executed by
 * test_l2_policy_races.py.  Here this external dependency checks the bridge
 * caller's lock order and that notification is OUTSIDE the publish section. */
struct rtl9617c_switch_guard { u64 generation; bool blocked; };
static int rtl9617c_switch_guard_publish(struct rtl9617c_switch_guard *guard,
                                        u64 generation, int (*publish)(void *),
                                        void *context)
{
 int ret;
 if (guard->blocked || generation != guard->generation) return -EAGAIN;
 assert(!publishing);
 publishing = 1;
 ret = publish(context);
 publishing = 0;
 return ret;
}

enum { NFPROTO_INET=1, NFPROTO_IPV4=2, NFPROTO_NETDEV=5,
       NFPROTO_BRIDGE=7, NFPROTO_IPV6=10 };
enum { NF_NETDEV_INGRESS=0, NF_NETDEV_EGRESS=1, NF_INET_INGRESS=5 };
enum { NF_HOOK_OP_UNDEFINED, NF_HOOK_OP_NF_TABLES, NF_HOOK_OP_BPF,
       NF_HOOK_OP_NFT_FT };
typedef unsigned int nf_hookfn(void);
struct nf_flowtable_type { unsigned int family; nf_hookfn *hook; };
struct nf_flowtable { const struct nf_flowtable_type *type; };
struct nf_hook_ops {
 unsigned int hooknum, hook_ops_type;
 void *priv;
 nf_hookfn *hook;
};
static unsigned int route_hook(void) { return 0; }
static unsigned int other_hook(void) { return 0; }
'''


TESTS = r'''
int main(void)
{
 struct net_bridge br = { .options = BIT(BROPT_MULTICAST_ENABLED) };
 struct net_device master = { .master = true, .priv = &br, .mtu = ETH_DATA_LEN };
 struct net_bridge_port p = {
  .flags = BR_LEARNING | BR_FLOOD | BR_MCAST_FLOOD | BR_BCAST_FLOOD,
  .br = &br,
 };
 struct net_bridge_port other_port = { .br = &br };
 struct net_device port = { .port = &p, .mtu = ETH_DATA_LEN };
 const unsigned int forbidden_opts[] = { BROPT_MRP_ENABLED, BROPT_CFM_ENABLED,
  BROPT_MST_ENABLED, BROPT_NEIGH_SUPPRESS_ENABLED, BROPT_NO_LL_LEARN,
  BROPT_VLAN_STATS_ENABLED };
 const unsigned long allowed_flags[] = { BR_LEARNING, BR_LEARNING_SYNC,
  BR_FLOOD, BR_MCAST_FLOOD, BR_BCAST_FLOOD, BR_BPDU_GUARD, BR_ROOT_BLOCK,
  BR_ADMIN_COST, BR_MULTICAST_FAST_LEAVE, BR_BPDU_FILTER };
 const unsigned long forbidden_flags[] = { BR_HAIRPIN_MODE, BR_PROXYARP,
  BR_PROXYARP_WIFI, BR_MULTICAST_TO_UNICAST, BR_VLAN_TUNNEL,
  BR_NEIGH_SUPPRESS, BR_ISOLATED, BR_MRP_AWARE, BR_MRP_LOST_CONT,
  BR_MRP_LOST_IN_CONT, BR_TX_FWD_OFFLOAD, BR_PORT_LOCKED, BR_PORT_MAB,
  BR_NEIGH_VLAN_SUPPRESS, BIT(31) };
 unsigned int i, mask, passed = 0;
 struct nf_flowtable_type type = { .family = NFPROTO_INET, .hook = route_hook };
 struct nf_flowtable ft = { .type = &type };
 struct nf_hook_ops ops = { .hooknum = NF_NETDEV_INGRESS,
  .hook_ops_type = NF_HOOK_OP_NFT_FT, .priv = &ft, .hook = route_hook };
 const unsigned int families[] = { NFPROTO_INET, NFPROTO_IPV4, NFPROTO_IPV6 };
 const unsigned char address[] = { 2, 3, 4, 5, 6, 7 };
 struct net_bridge_fdb_entry fdb = { .addr = { 2, 3, 4, 5, 6, 7 }, .dst = &p };
 struct rtl9617c_switch_guard guard = { .generation = 123 };

 /* Default snooping is compatible because multicast is trapped to CPU. */
 assert(br_rtl9617c_l2_eligible(&master));
 assert(br_rtl9617c_l2_port_eligible(&port));
 port.mtu = 1200;
 assert(!br_rtl9617c_l2_port_eligible(&port));
 port.mtu = 9000;
 assert(!br_rtl9617c_l2_port_eligible(&port));
 port.mtu = ETH_DATA_LEN;
 for (i = 0; i < sizeof(forbidden_opts)/sizeof(*forbidden_opts); ++i) {
  br.options |= BIT(forbidden_opts[i]);
  assert(!br_rtl9617c_l2_eligible(&master));
  br.options &= ~BIT(forbidden_opts[i]);
  assert(br_rtl9617c_l2_eligible(&master));
  passed++;
 }
 br.fdb_max_learned = 1;
 assert(!br_rtl9617c_l2_eligible(&master));
 br.fdb_max_learned = 0;
 master.promiscuity = 1;
 assert(!br_rtl9617c_l2_eligible(&master));
 master.promiscuity = 0;
 master.master = false;
 assert(!br_rtl9617c_l2_eligible(&master));
 master.master = true;

 br.fdb_list.first = &fdb;
 fdb.flags = BIT(BR_FDB_ADDED_BY_EXT_LEARN);
 assert(br_rtl9617c_l2_eligible(&master));
 fdb.flags |= BIT(BR_FDB_ADDED_BY_USER);
 assert(!br_rtl9617c_l2_eligible(&master));
 fdb.flags |= BIT(BR_FDB_STATIC);
 assert(!br_rtl9617c_l2_eligible(&master)); /* static != sticky in Linux */
 fdb.flags |= BIT(BR_FDB_STICKY);
 assert(br_rtl9617c_l2_eligible(&master));
 fdb.flags = BIT(BR_FDB_ADDED_BY_USER) | BIT(BR_FDB_LOCAL);
 assert(br_rtl9617c_l2_eligible(&master));
 fdb.flags = BIT(BR_FDB_ADDED_BY_USER) | BIT(BR_FDB_STICKY);
 assert(!br_rtl9617c_l2_eligible(&master));
 br.fdb_list.first = NULL;

 /* All combinations of supported flags remain eligible, not just one
  * magic default mask.  The driver must implement learning/flood bits. */
 for (mask = 0; mask < (1U << 10); ++mask) {
  p.flags = 0;
  for (i = 0; i < 10; ++i)
   if (mask & (1U << i)) p.flags |= allowed_flags[i];
  assert(br_rtl9617c_l2_port_eligible(&port));
  p.flags |= BR_PROMISC;
  port.promiscuity = 1;
  assert(br_rtl9617c_l2_port_eligible(&port));
  port.promiscuity = 2;
  assert(!br_rtl9617c_l2_port_eligible(&port));
  port.promiscuity = 0;
  passed += 3;
 }
 p.flags = BR_LEARNING | BR_FLOOD;
 for (i = 0; i < sizeof(forbidden_flags)/sizeof(*forbidden_flags); ++i) {
  p.flags |= forbidden_flags[i];
  assert(!br_rtl9617c_l2_port_eligible(&port));
  p.flags &= ~forbidden_flags[i];
  passed++;
 }
 p.backup_port = &p;
 assert(!br_rtl9617c_l2_port_eligible(&port));
 p.backup_port = NULL;
 p.backup_nhid = 1;
 assert(!br_rtl9617c_l2_port_eligible(&port));
 p.backup_nhid = 0;
 port.port = NULL;
 assert(!br_rtl9617c_l2_port_eligible(&port));
 port.port = &p;
 assert(br_rtl9617c_l2_port_eligible(&port));

 /* A later userspace/static/local/moved row is never erased by old scan
  * cleanup.  A still-owned hardware row can be removed without recursion. */
 br.fdb_list.first = &fdb;
 for (i = BR_FDB_LOCAL; i <= BR_FDB_LOCKED; ++i) {
  if (i == BR_FDB_ADDED_BY_EXT_LEARN || i == BR_FDB_OFFLOADED) continue;
  fdb.flags = BIT(BR_FDB_ADDED_BY_EXT_LEARN) | BIT(i);
  assert(!br_rtl9617c_fdb_forget(&port, address));
  assert(br.fdb_list.first == &fdb && !deletes);
 }
 fdb.flags = BIT(BR_FDB_ADDED_BY_EXT_LEARN);
 fdb.dst = &other_port;
 assert(!br_rtl9617c_fdb_forget(&port, address));
 fdb.dst = &p;
 fdb.flags = 0; /* a CPU move has taken ownership and cleared EXT_LEARN */
 assert(!br_rtl9617c_fdb_forget(&port, address));
 fdb.flags = BIT(BR_FDB_ADDED_BY_EXT_LEARN);
 assert(br_rtl9617c_fdb_forget(&port, address));
 assert(deletes == 1 && !br.fdb_list.first);
 assert(!br_rtl9617c_fdb_forget(&port, address));

 /* New/refresh/move feedback writes under both guards, then notifies after
  * the core lock is released.  Stale snapshots cannot overwrite a CPU move. */
 allocation_fails = true;
 assert(br_rtl9617c_fdb_learn(&port, address, &guard, 123) == -ENOMEM);
 allocation_fails = false;
 assert(br_rtl9617c_fdb_learn(&port, address, &guard, 122) == -EAGAIN);
 guard.blocked = true;
 assert(br_rtl9617c_fdb_learn(&port, address, &guard, 123) == -EAGAIN);
 guard.blocked = false;
 assert(!br_rtl9617c_fdb_learn(&port, address, &guard, 123));
 assert(br.fdb_list.first->dst == &p && notifies == 1);
 assert(test_bit(BR_FDB_ADDED_BY_EXT_LEARN, &br.fdb_list.first->flags));
 assert(test_bit(BR_FDB_OFFLOADED, &br.fdb_list.first->flags));
 jiffies++;
 assert(!br_rtl9617c_fdb_learn(&port, address, &guard, 123));
 assert(notifies == 1 && br.fdb_list.first->updated == jiffies);
 port.port = &other_port;
 assert(!br_rtl9617c_fdb_learn(&port, address, &guard, 123));
 assert(br.fdb_list.first->dst == &other_port && notifies == 2);
 guard.generation++;
 port.port = &p;
 assert(br_rtl9617c_fdb_learn(&port, address, &guard, 123) == -EAGAIN);
 assert(br.fdb_list.first->dst == &other_port && notifies == 2);
 for (i = BR_FDB_LOCAL; i <= BR_FDB_LOCKED; ++i) {
  if (i == BR_FDB_ADDED_BY_EXT_LEARN || i == BR_FDB_OFFLOADED) continue;
  br.fdb_list.first->flags = BIT(i);
  assert(br_rtl9617c_fdb_learn(&port, address, &guard, 124) == -EEXIST);
  assert(br.fdb_list.first->dst == &other_port && notifies == 2);
 }
 port.port = NULL;
 assert(br_rtl9617c_fdb_learn(&port, address, &guard, 124) == -ENODEV);
 assert(!br_rtl9617c_fdb_forget(&port, address));
 port.port = &p;
 br.fdb_list.first = NULL;

 /* fw4 software flowtable does not disable ordinary LAN switching. */
 for (i = 0; i < sizeof(families)/sizeof(*families); ++i) {
  type.family = families[i];
  assert(!nf_hook_blocks_l2_switch(NFPROTO_NETDEV, &ops));
  assert(nf_hook_blocks_l2_switch(NFPROTO_BRIDGE, &ops));
  ops.hooknum = NF_NETDEV_EGRESS;
  assert(nf_hook_blocks_l2_switch(NFPROTO_NETDEV, &ops));
  ops.hooknum = NF_NETDEV_INGRESS;
  passed += 3;
 }
 type.family = NFPROTO_BRIDGE;
 assert(nf_hook_blocks_l2_switch(NFPROTO_NETDEV, &ops));
 type.family = NFPROTO_INET;
 ft.type = NULL;
 assert(nf_hook_blocks_l2_switch(NFPROTO_NETDEV, &ops));
 ft.type = &type;
 ops.priv = NULL;
 assert(nf_hook_blocks_l2_switch(NFPROTO_NETDEV, &ops));
 ops.priv = &ft;
 ops.hook = other_hook;
 assert(nf_hook_blocks_l2_switch(NFPROTO_NETDEV, &ops));
 ops.hook = route_hook;
 for (i = NF_HOOK_OP_UNDEFINED; i <= NF_HOOK_OP_BPF; ++i) {
  ops.hook_ops_type = i;
  assert(nf_hook_blocks_l2_switch(NFPROTO_NETDEV, &ops));
  assert(nf_hook_blocks_l2_switch(NFPROTO_BRIDGE, &ops));
  ops.hooknum = NF_INET_INGRESS;
  assert(nf_hook_blocks_l2_switch(NFPROTO_INET, &ops));
  ops.hooknum = 2; /* ordinary routed FORWARD hook is not L2 policy */
  assert(!nf_hook_blocks_l2_switch(NFPROTO_INET, &ops));
  assert(!nf_hook_blocks_l2_switch(NFPROTO_IPV4, &ops));
  assert(!nf_hook_blocks_l2_switch(NFPROTO_IPV6, &ops));
  ops.hooknum = NF_NETDEV_INGRESS;
  passed += 6;
 }
#ifdef HAVE_LINUX_MTU_TEST
 {
  struct sk_buff skb = { .gso = false };
  struct net_device egress = {
   .flags = IFF_UP, .mtu = 1500, .hard_header_len = 14
  };
  for (i = 1490; i <= 1540; ++i) {
   skb.len = i;
   assert(__is_skb_forwardable(&egress, &skb, true) == (i <= 1518));
   passed++;
  }
  egress.mtu = 1200;
  skb.len = 1218;
  assert(__is_skb_forwardable(&egress, &skb, true));
  skb.len++;
  assert(!__is_skb_forwardable(&egress, &skb, true));
  egress.flags = 0;
  skb.len = 64;
  assert(!__is_skb_forwardable(&egress, &skb, true));
  puts("Linux non-GSO bridge egress MTU1500 boundary: <=1518 bytes without FCS (1522 with FCS) PASS");
 }
#endif
 printf("PASS: real bridge/native-L2 eligibility + ownership-safe FDB feedback + nft route-hook exemption; %u matrix checks plus boundary cases\n", passed);
 return 0;
}
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path)
    args = parser.parse_args()
    added = "\n".join(line[1:] for line in PATCH.read_text().splitlines()
                      if line.startswith("+") and not line.startswith("+++"))
    context = re.search(r"struct br_rtl9617c_learn_ctx \{[^}]+\};", added).group(0)
    if args.kernel:
        assert context in (args.kernel / "net/bridge/br_fdb.c").read_text()
    functions = [context]
    prefix = ""
    if args.kernel:
        functions.append(function((args.kernel / "include/linux/netdevice.h").read_text(),
                                  "__is_skb_forwardable"))
        prefix = "#define HAVE_LINUX_MTU_TEST 1\n"
    for name, relative in FUNCTIONS.items():
        source = function(added, name)
        if args.kernel:
            actual = function((args.kernel / relative).read_text(), name)
            assert actual == source, f"stale/mismatched applied kernel: {name}"
            source = actual
        functions.append(source)
    with tempfile.TemporaryDirectory(prefix="l2-bridge-eligibility-") as directory:
        directory = Path(directory)
        cfile, binary = directory / "test.c", directory / "test"
        cfile.write_text(prefix + STUBS + "\n" + "\n\n".join(functions) + "\n" + TESTS)
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g",
                        "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
                        "-fno-sanitize-recover=all", "-fno-omit-frame-pointer",
                        str(cfile), "-o", str(binary)], check=True)
        env = os.environ.copy()
        env.setdefault("ASAN_OPTIONS", "detect_leaks=0")
        subprocess.run([str(binary)], env=env, check=True)


if __name__ == "__main__":
    main()
