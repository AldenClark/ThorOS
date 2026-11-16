// SPDX-License-Identifier: GPL-2.0-only
/* Exact, bounded bridge MDB control-plane snapshots for native replication. */
#include <linux/export.h>
#include <linux/rtl9617c-mdb.h>
#include <net/net_namespace.h>

#include "br_private.h"

#if IS_ENABLED(CONFIG_RTL9617C_SWITCH_GUARD)
struct br_rtl9617c_mdb_walk {
	struct br_rtl9617c_mdb_snapshot *snapshot;
	br_rtl9617c_mdb_emit_t emit;
	void *priv;
	unsigned int remaining;
};

static int br_rtl9617c_mdb_visit(struct br_rtl9617c_mdb_walk *walk)
{
	if (!walk->remaining)
		return -E2BIG;
	walk->remaining--;
	return 0;
}

static void
br_rtl9617c_mdb_timer(struct br_rtl9617c_mdb_snapshot *snapshot,
		      const struct timer_list *timer,
		      struct br_rtl9617c_mdb_timer *out)
{
	out->pending = timer_pending(timer);
	out->expires = READ_ONCE(timer->expires);
	if (out->pending &&
	    (!snapshot->has_deadline ||
	     time_before(out->expires, snapshot->earliest_deadline))) {
		snapshot->earliest_deadline = out->expires;
		snapshot->has_deadline = true;
	}
}

static void
br_rtl9617c_mdb_family(struct br_rtl9617c_mdb_snapshot *snapshot,
		       struct net_bridge_mcast *brmctx,
		       struct bridge_mcast_other_query *other,
		       const struct bridge_mcast_querier *querier,
		       const struct timer_list *router,
		       struct br_rtl9617c_mdb_family *out,
		       u8 version, bool ipv6)
{
	out->supported = true;
	out->version = version;
	out->router_type = brmctx->multicast_router;
	out->querier_addr = querier->addr;
	out->querier_ifindex = querier->port_ifidx;
	out->own_querier = brmctx->multicast_querier &&
		(!ipv6 || br_opt_get(brmctx->br, BROPT_HAS_IPV6_ADDR));
	br_rtl9617c_mdb_timer(snapshot, &other->timer, &out->other_query);
	br_rtl9617c_mdb_timer(snapshot, &other->delay_timer, &out->query_delay);
	br_rtl9617c_mdb_timer(snapshot, router, &out->local_router_timer);
	/* Derive from the captured timer values, not a second pending read. */
	out->querier_present = !out->query_delay.pending &&
		(out->own_querier || out->other_query.pending);
	out->querier_time_dependent = out->query_delay.pending ||
		(!out->own_querier && out->other_query.pending);
	out->local_router = out->router_type == MDB_RTR_TYPE_PERM ||
		(out->router_type == MDB_RTR_TYPE_TEMP_QUERY &&
		 out->local_router_timer.pending);
	out->local_router_time_dependent =
		out->router_type == MDB_RTR_TYPE_TEMP_QUERY &&
		out->local_router_timer.pending;
}

static int br_rtl9617c_mdb_emit(struct br_rtl9617c_mdb_walk *walk,
			      struct br_rtl9617c_mdb_record *record)
{
	int err;

	if (walk->snapshot->record_count == U32_MAX)
		return -EOVERFLOW;
	record->id = walk->snapshot->record_count + 1;
	err = walk->emit(walk->priv, record);
	if (err)
		return err < 0 ? err : -EINVAL;
	walk->snapshot->record_count++;
	return 0;
}

static bool br_rtl9617c_mdb_pg_forward(const struct net_bridge_mcast *brmctx,
				      const struct net_bridge_port_group *pg)
{
	if (READ_ONCE(pg->key.port->flags) & BR_MULTICAST_TO_UNICAST)
		return true;
	if (pg->flags & MDB_PG_FLAGS_BLOCKED)
		return false;
	return !(br_multicast_is_star_g(&pg->key.addr) &&
		 br_multicast_should_handle_mode(brmctx, pg->key.addr.proto) &&
		 pg->filter_mode == MCAST_INCLUDE);
}

static int br_rtl9617c_mdb_ports(struct br_rtl9617c_mdb_walk *walk,
			       struct net_bridge_mcast *brmctx,
			       const struct net_bridge_mdb_entry *mp,
			       u32 entry_id)
{
	const struct net_bridge_port_group *pg;

	for (pg = mlock_dereference(mp->ports, mp->br); pg;
	     pg = mlock_dereference(pg->next, mp->br)) {
		struct br_rtl9617c_mdb_record record = {
			.type = BR_RTL9617C_MDB_PORT,
			.key = mp->addr,
			.dev = pg->key.port->dev,
			.entry_id = entry_id,
		};
		const struct net_bridge_group_src *src;
		u32 port_id;
		int err;

		err = br_rtl9617c_mdb_visit(walk);
		if (err)
			return err;
		record.port_id = walk->snapshot->record_count + 1;
		record.port.flags = READ_ONCE(pg->key.port->flags);
		record.port.state = READ_ONCE(pg->key.port->state);
		record.port.filter_mode = pg->filter_mode;
		record.port.rt_protocol = pg->rt_protocol;
		record.port.permanent = !!(pg->flags & MDB_PG_FLAGS_PERMANENT);
		record.port.blocked = !!(pg->flags & MDB_PG_FLAGS_BLOCKED);
		record.port.star_excl = !!(pg->flags & MDB_PG_FLAGS_STAR_EXCL);
		record.port.mcast_to_unicast =
			!!(record.port.flags & BR_MULTICAST_TO_UNICAST);
		record.port.forward = br_rtl9617c_mdb_pg_forward(brmctx, pg);
		ether_addr_copy(record.port.eth_addr, pg->eth_addr);
		br_rtl9617c_mdb_timer(walk->snapshot, &pg->timer,
				      &record.port.timer);
		err = br_rtl9617c_mdb_emit(walk, &record);
		if (err)
			return err;
		port_id = record.id;

		hlist_for_each_entry(src, &pg->src_list, node) {
			struct br_rtl9617c_mdb_record source = {
				.type = BR_RTL9617C_MDB_SOURCE,
				.key = mp->addr,
				.dev = pg->key.port->dev,
				.entry_id = entry_id,
				.port_id = port_id,
			};

			err = br_rtl9617c_mdb_visit(walk);
			if (err)
				return err;
			source.source.addr = src->addr;
			source.source.installed = !!(src->flags & BR_SGRP_F_INSTALLED);
			source.source.user_added = !!(src->flags & BR_SGRP_F_USER_ADDED);
			br_rtl9617c_mdb_timer(walk->snapshot, &src->timer,
					      &source.source.timer);
			err = br_rtl9617c_mdb_emit(walk, &source);
			if (err)
				return err;
		}
	}
	return 0;
}

static int br_rtl9617c_mdb_entries(struct br_rtl9617c_mdb_walk *walk,
				 struct net_bridge_mcast *brmctx)
{
	const struct net_bridge_mdb_entry *mp;

	hlist_for_each_entry(mp, &brmctx->br->mdb_list, mdb_node) {
		struct br_rtl9617c_mdb_record record = {
			.type = BR_RTL9617C_MDB_ENTRY,
		};
		int err;

		err = br_rtl9617c_mdb_visit(walk);
		if (err)
			return err;
		if (mp->addr.vid != walk->snapshot->vid)
			continue;
		record.key = mp->addr;
		record.entry_id = walk->snapshot->record_count + 1;
		record.entry.kind = br_group_is_l2(&mp->addr) ?
			BR_RTL9617C_MDB_L2 : br_multicast_is_star_g(&mp->addr) ?
			BR_RTL9617C_MDB_STAR_G : BR_RTL9617C_MDB_SOURCE_G;
		record.entry.host_joined = mp->host_joined;
		br_rtl9617c_mdb_timer(walk->snapshot, &mp->timer,
				      &record.entry.timer);
		/* Empty entries still affect exact-before-wildcard lookup. */
		err = br_rtl9617c_mdb_emit(walk, &record);
		if (err)
			return err;
		err = br_rtl9617c_mdb_ports(walk, brmctx, mp, record.id);
		if (err)
			return err;
	}
	return 0;
}

static int br_rtl9617c_mdb_router(struct br_rtl9617c_mdb_walk *walk,
				const struct net_bridge_mcast_port *pmctx,
				const struct timer_list *timer, __be16 proto)
{
	struct br_rtl9617c_mdb_record record = {
		.type = BR_RTL9617C_MDB_ROUTER,
		.key = { .proto = proto, .vid = walk->snapshot->vid },
		.dev = pmctx->port->dev,
		.router = { .proto = proto, .type = pmctx->multicast_router },
	};
	int err;

	err = br_rtl9617c_mdb_visit(walk);
	if (err)
		return err;
	br_rtl9617c_mdb_timer(walk->snapshot, timer, &record.router.timer);
	return br_rtl9617c_mdb_emit(walk, &record);
}

int br_rtl9617c_mdb_snapshot(const struct net_device *master, u16 vid,
			   struct rtl9617c_switch_guard *guard,
			   unsigned int work_budget,
			   struct br_rtl9617c_mdb_snapshot *snapshot,
			   br_rtl9617c_mdb_emit_t emit, void *priv)
{
	struct br_rtl9617c_mdb_snapshot copy = {};
	struct br_rtl9617c_mdb_walk walk = {
		.snapshot = &copy,
		.emit = emit,
		.priv = priv,
		.remaining = work_budget,
	};
	const struct net_bridge_mcast_port *pmctx;
	struct net_bridge_mcast *brmctx;
	struct net_bridge_vlan *vlan;
	struct net_bridge *br;
	u64 generation;
	int err;

	ASSERT_RTNL();
	if (!snapshot)
		return -EINVAL;
	memset(snapshot, 0, sizeof(*snapshot));
	if (!master || !guard || !emit || !work_budget ||
	    !netif_is_bridge_master(master) || vid >= VLAN_VID_MASK)
		return -EINVAL;
	/* The caller keeps registration stable throughout this RTNL section. */
	if (guard->net != dev_net(master))
		return -EXDEV;
	if (rtl9617c_switch_guard_blocked(guard))
		return -EAGAIN;
	generation = rtl9617c_switch_guard_generation(guard);
	br = netdev_priv(master);
	brmctx = &br->multicast_ctx;
	copy.master = master;
	copy.vid = vid;
	copy.vlan_filtering = br_opt_get(br, BROPT_VLAN_ENABLED);
	copy.vlan_snooping = br_opt_get(br, BROPT_MCAST_VLAN_SNOOPING_ENABLED);
	copy.master_flags = master->flags;
	copy.running = netif_running(master);
	if (!copy.vlan_filtering && vid)
		return -EINVAL;

	rcu_read_lock();
	spin_lock_bh(&br->multicast_lock);
	if (copy.vlan_snooping) {
		vlan = br_vlan_find(br_vlan_group(br), vid);
		if (!vid || !vlan) {
			err = -ENOENT;
			goto out;
		}
		brmctx = &vlan->br_mcast_ctx;
	}
	copy.sampled_at = jiffies;
	copy.snooping = br_opt_get(br, BROPT_MULTICAST_ENABLED) &&
		!br_multicast_ctx_vlan_global_disabled(brmctx);
	copy.context_enabled = !br_multicast_ctx_vlan_disabled(brmctx);
	br_rtl9617c_mdb_family(&copy, brmctx, &brmctx->ip4_other_query,
			      &brmctx->ip4_querier, &brmctx->ip4_mc_router_timer,
			      &copy.ip4, brmctx->multicast_igmp_version, false);
#if IS_ENABLED(CONFIG_IPV6)
	br_rtl9617c_mdb_family(&copy, brmctx, &brmctx->ip6_other_query,
			      &brmctx->ip6_querier, &brmctx->ip6_mc_router_timer,
			      &copy.ip6, brmctx->multicast_mld_version, true);
#endif
	err = br_rtl9617c_mdb_entries(&walk, brmctx);
	if (err)
		goto out;
	hlist_for_each_entry(pmctx, &brmctx->ip4_mc_router_list, ip4_rlist) {
		err = br_rtl9617c_mdb_router(&walk, pmctx,
					    &pmctx->ip4_mc_router_timer,
					    htons(ETH_P_IP));
		if (err)
			goto out;
	}
#if IS_ENABLED(CONFIG_IPV6)
	hlist_for_each_entry(pmctx, &brmctx->ip6_mc_router_list, ip6_rlist) {
		err = br_rtl9617c_mdb_router(&walk, pmctx,
					    &pmctx->ip6_mc_router_timer,
					    htons(ETH_P_IPV6));
		if (err)
			goto out;
	}
#endif
	/* A writer can begin its scope before waiting for multicast_lock.
	 * Never publish a prefix, a partly changed report, or an expired sample.
	 */
	if (rtl9617c_switch_guard_blocked(guard) ||
	    rtl9617c_switch_guard_generation(guard) != generation ||
	    (copy.has_deadline && time_after_eq(jiffies, copy.earliest_deadline))) {
		err = -EAGAIN;
		goto out;
	}
	copy.generation = generation;
	*snapshot = copy;
	err = 0;
out:
	spin_unlock_bh(&br->multicast_lock);
	rcu_read_unlock();
	return err;
}
EXPORT_SYMBOL_GPL(br_rtl9617c_mdb_snapshot);
#endif
