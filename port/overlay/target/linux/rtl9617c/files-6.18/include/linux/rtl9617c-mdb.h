/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_RTL9617C_MDB_H
#define _LINUX_RTL9617C_MDB_H

#include <linux/errno.h>
#include <linux/if_bridge.h>
#include <linux/rtl9617c-switch.h>
#include <linux/string.h>

/* An observation of a kernel timer, in raw jiffies. pending == false does
 * not mean a permanent membership: the callback may already be running.
 */
struct br_rtl9617c_mdb_timer {
	unsigned long expires;
	bool pending;
};

struct br_rtl9617c_mdb_family {
	struct br_ip querier_addr;
	struct br_rtl9617c_mdb_timer other_query;
	struct br_rtl9617c_mdb_timer query_delay;
	struct br_rtl9617c_mdb_timer local_router_timer;
	int querier_ifindex;
	u8 version;
	u8 router_type;
	bool supported;
	bool own_querier;
	bool querier_present;
	bool querier_time_dependent;
	bool local_router;
	bool local_router_time_dependent;
};

struct br_rtl9617c_mdb_snapshot {
	const struct net_device *master;
	u64 generation;
	unsigned long sampled_at;
	unsigned long earliest_deadline;
	unsigned int master_flags;
	u32 record_count;
	u16 vid;
	bool has_deadline;
	bool vlan_filtering;
	bool vlan_snooping;
	bool snooping;
	bool context_enabled;
	bool running;
	struct br_rtl9617c_mdb_family ip4;
	struct br_rtl9617c_mdb_family ip6;
};

enum br_rtl9617c_mdb_record_type {
	BR_RTL9617C_MDB_ENTRY,
	BR_RTL9617C_MDB_PORT,
	BR_RTL9617C_MDB_SOURCE,
	BR_RTL9617C_MDB_ROUTER,
};

enum br_rtl9617c_mdb_key_kind {
	BR_RTL9617C_MDB_L2,
	BR_RTL9617C_MDB_STAR_G,
	BR_RTL9617C_MDB_SOURCE_G,
};

struct br_rtl9617c_mdb_record {
	struct br_ip key;
	const struct net_device *dev;
	enum br_rtl9617c_mdb_record_type type;
	u32 id;
	u32 entry_id;
	u32 port_id;
	union {
		struct {
			struct br_rtl9617c_mdb_timer timer;
			enum br_rtl9617c_mdb_key_kind kind;
			bool host_joined;
		} entry;
		struct {
			struct br_rtl9617c_mdb_timer timer;
			unsigned long flags;
			unsigned char eth_addr[ETH_ALEN];
			u8 state;
			u8 filter_mode;
			u8 rt_protocol;
			bool permanent;
			bool blocked;
			bool star_excl;
			bool mcast_to_unicast;
			/* The PG branch of br_multicast_flood(), including its
			 * multicast-to-unicast precedence. NOT router override,
			 * STP/MST, ingress/hairpin, VLAN, isolation, or offload
			 * duplicate suppression. Apply those from the SAME epoch.
			 */
			bool forward;
		} port;
		struct {
			struct br_ip addr;
			struct br_rtl9617c_mdb_timer timer;
			bool installed;
			bool user_added;
		} source;
		struct {
			struct br_rtl9617c_mdb_timer timer;
			__be16 proto;
			u8 type;
		} router;
	};
};

typedef int (*br_rtl9617c_mdb_emit_t)(void *priv,
				     const struct br_rtl9617c_mdb_record *record);

/* RTNL held; the caller serializes guard registration/unregistration.
 * The bridge holds RCU and multicast_lock while emit copies records into a
 * caller-preallocated bounded array. emit must not sleep, perform MMIO,
 * mutate bridge/guard state, issue notifications, or retain the record
 * pointer. Device pointers are borrowed until RTNL is released; retain a
 * device reference separately if the resulting plan outlives that lock.
 *
 * work_budget counts all visited entries, PGs, sources and router rows,
 * INCLUDING entries skipped for another VID. Exhaustion returns -E2BIG;
 * emit should return -ENOSPC for insufficient destination capacity. On ANY
 * error the header is zeroed and ALL emitted records must be discarded.
 * Positive callback returns are invalid. IDs are unique only within this
 * successful snapshot and distinguish multiple hosts on the same port.
 *
 * ENTRY/PORT are Linux's materialized (*,G)/(S,G)/L2 forwarding state, not
 * lossy switchdev MAC aliases. Select S,G before *,G exactly as the bridge
 * does. SOURCE preserves filter/lease information; do not reconstruct a
 * second IGMP/MLD state machine or infer BLOCKED from its timer.
 *
 * Timer dequeue precedes callback execution and is not serialized by the
 * multicast lock. A deadline is an upper bound for returning safely to CPU,
 * NOT evidence that hardware expiry exists. In particular a time-dependent
 * querier/local-router policy cannot be authorized indefinitely by an epoch.
 * Use hardware-enforced expiry or CPU processing for that dependency. A
 * successful copy neither programs nor arms hardware: recheck deadlines
 * and finish publication with rtl9617c_switch_guard_try_arm(generation).
 * Policy BEGIN closes old admission before a writer, END queues rebuild;
 * these existing guard notifications also cover joins/leaves and expiry.
 */
#if IS_REACHABLE(CONFIG_BRIDGE) && IS_ENABLED(CONFIG_BRIDGE_IGMP_SNOOPING) && \
	IS_ENABLED(CONFIG_RTL9617C_SWITCH_GUARD)
int br_rtl9617c_mdb_snapshot(const struct net_device *master, u16 vid,
			   struct rtl9617c_switch_guard *guard,
			   unsigned int work_budget,
			   struct br_rtl9617c_mdb_snapshot *snapshot,
			   br_rtl9617c_mdb_emit_t emit, void *priv);
#else
static inline int
br_rtl9617c_mdb_snapshot(const struct net_device *master, u16 vid,
			struct rtl9617c_switch_guard *guard,
			unsigned int work_budget,
			struct br_rtl9617c_mdb_snapshot *snapshot,
			br_rtl9617c_mdb_emit_t emit, void *priv)
{
	if (snapshot)
		memset(snapshot, 0, sizeof(*snapshot));
	return -EOPNOTSUPP;
}
#endif

#endif
