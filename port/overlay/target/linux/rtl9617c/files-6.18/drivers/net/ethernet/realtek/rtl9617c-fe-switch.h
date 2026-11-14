/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Native LAN switching, not a packet-observation shortcut.  Linux bridge
 * owns topology and policy; switchdev supplies its FDB and the synchronous
 * guard closes admission BEFORE policy publication.  Only an unchanged,
 * fully programmed snapshot may reopen the hardware path.
 *
 * This first hardware contract is deliberately explicit: a single, native
 * untagged LAN bridge, hardware-learned unicast, and CPU-only BUM/control
 * packets.  VLAN filtering and complex bridge policy use the software path.
 * No skb is treated as an authorization and no CPU trap is marked forwarded.
 */
#include <linux/if_bridge.h>
#include <linux/jiffies.h>
#include <linux/rtl9617c-switch.h>
#include <linux/rtnetlink.h>
#include <linux/sort.h>
#include <linux/vmalloc.h>
#include <net/net_namespace.h>
#include <net/switchdev.h>

#include "rtl9617c-l2-table.h"

#if IS_REACHABLE(CONFIG_BRIDGE) && IS_ENABLED(CONFIG_NET_SWITCHDEV) && \
    IS_ENABLED(CONFIG_RTL9617C_SWITCH_GUARD)

#include "rtl9617c-fe-switch-hw.h"

enum fe_switch_reason {
	FE_SWITCH_OK,
	FE_SWITCH_REQUEST_OFF,
	FE_SWITCH_ENGINE_DOWN,
	FE_SWITCH_NO_BRIDGE,
	FE_SWITCH_MULTI_BRIDGE,
	FE_SWITCH_MIXED_PORTS,
	FE_SWITCH_VLAN_UNSUPPORTED,
	FE_SWITCH_PRIVATE_POLICY,
	FE_SWITCH_PORT_POLICY,
	FE_SWITCH_PROMISC,
	FE_SWITCH_GUARDED,
	FE_SWITCH_IO_ERROR,
	FE_SWITCH_FOREIGN_FDB,
	FE_SWITCH_FDB_CAPACITY,
	FE_SWITCH_HW_UNSUPPORTED,
};

struct fe_switch_plan {
	u32 ports;
	unsigned long flags[FE_LAN_PORTS];
	u8 state[FE_LAN_PORTS];
	bool vlan_filtering, mixed, multi_bridge, private_policy, promisc;
	bool software_policy;
};

/* A pure capability check, shared by the real worker and host regressions.
 * Multicast snooping is intentionally NOT a veto: every multicast frame is
 * trapped, so Linux retains its MDB, router-port and per-packet decisions.
 */
static enum fe_switch_reason
fe_switch_plan_validate(const struct fe_switch_plan *plan)
{
	const unsigned long allowed = BR_BPDU_GUARD | BR_ROOT_BLOCK |
		BR_MULTICAST_FAST_LEAVE | BR_ADMIN_COST | BR_LEARNING | BR_FLOOD |
		BR_PROMISC | BR_LEARNING_SYNC | BR_MCAST_FLOOD | BR_BCAST_FLOOD |
		BR_BPDU_FILTER;
	unsigned int port;

	if (plan->ports & ~GENMASK(FE_LAN_PORTS - 1, 0))
		return FE_SWITCH_PORT_POLICY;
	if (plan->software_policy)
		return FE_SWITCH_GUARDED;
	if (plan->multi_bridge)
		return FE_SWITCH_MULTI_BRIDGE;
	if (plan->mixed)
		return FE_SWITCH_MIXED_PORTS;
	if (plan->vlan_filtering)
		return FE_SWITCH_VLAN_UNSUPPORTED;
	if (plan->private_policy)
		return FE_SWITCH_PRIVATE_POLICY;
	if (plan->promisc)
		return FE_SWITCH_PROMISC;
	for (port = 0; port < FE_LAN_PORTS; port++) {
		if (!(plan->ports & BIT(port)))
			continue;
		if ((plan->flags[port] & ~allowed) ||
		    !(plan->flags[port] & BR_LEARNING) ||
		    plan->state[port] != BR_STATE_FORWARDING)
			return FE_SWITCH_PORT_POLICY;
	}
	return hweight32(plan->ports) >= 2 ? FE_SWITCH_OK : FE_SWITCH_NO_BRIDGE;
}

struct fe_switch_learned {
	u8 address[ETH_ALEN];
	u8 port;
};

struct rtl_fe_bridge {
	struct rtl_fe *fe;
	struct rtl9617c_switch_guard guard;
	struct rtl_fe_switch_hw hw;
	struct notifier_block netdev_nb, atomic_nb, blocking_nb;
	struct work_struct work;
	struct delayed_work scan_work;
	/* Borrowed under RTNL, not dev_hold(): unregister must not wait for a
	 * worker which in turn waits for RTNL. UNREGISTER clears these pointers.
	 * Atomic callbacks only compare them, never dereference a cached device.
	 */
	struct net_device *ports[FE_LAN_PORTS], *master;
	u32 offloaded, native_mask, route_mask, armed_route_mask;
	/* Synchronous switchdev replay belongs to the pending topology, not
	 * the published datapath. native_mask stays zero until preparation and
	 * every static FDB write have completed successfully. RTNL owns this
	 * immutable mask while replaying; ordinary notifications never use it.
	 */
	u32 replay_ports;
	unsigned int (*rules)[RTL_L2_FDB_WORDS];
	unsigned int rule_count, local_target, retry_count;
	struct fe_switch_learned *learned, *next;
	unsigned int learned_count, pending_count;
	bool requested, stopping, active, replaying, domain_owned, flow_allowed;
	bool route_generation_valid;
	bool netdev_registered, atomic_registered, blocking_registered;
	int replay_error, error;
	enum fe_switch_reason reason;
	u64 rebuilds, polls, learned_adds, learned_deletes, scan_errors;
	u64 route_generation;
};

static void fe_switch_queue(struct rtl_fe_bridge *sw)
{
	if (!READ_ONCE(sw->stopping))
		queue_work(system_long_wq, &sw->work);
}

static void fe_switch_gate(void *private)
{
	struct rtl_fe_bridge *sw = private;

	WRITE_ONCE(sw->active, false);
	WRITE_ONCE(sw->armed_route_mask, 0);
	WRITE_ONCE(sw->flow_allowed, false);
	fe_switch_hw_gate(sw->fe, &sw->hw);
}

static void fe_switch_rebuild(void *private)
{
	fe_switch_queue(private);
}

static bool fe_switch_arm(void *private)
{
	struct rtl_fe_bridge *sw = private;
	bool armed;

	if (READ_ONCE(sw->stopping) || READ_ONCE(sw->fe->shutting_down) ||
	    !READ_ONCE(sw->fe->engine_ready))
		return false;
	armed = fe_switch_hw_arm(sw->fe, &sw->hw,
				sw->native_mask, sw->route_mask);
	WRITE_ONCE(sw->active, armed && sw->native_mask);
	WRITE_ONCE(sw->armed_route_mask, armed ? sw->route_mask : 0);
	WRITE_ONCE(sw->flow_allowed, armed && sw->fe->enabled &&
		   READ_ONCE(sw->fe->route_admitted));
	return armed;
}

static const struct rtl9617c_switch_guard_ops fe_switch_guard_ops = {
	.quiesce = fe_switch_gate,
	.rebuild = fe_switch_rebuild,
	.arm = fe_switch_arm,
};

static int fe_switch_port_index(struct rtl_fe_bridge *sw,
				struct net_device *dev)
{
	unsigned int port;

	for (port = 0; port < FE_LAN_PORTS; port++)
		if (READ_ONCE(sw->ports[port]) == dev)
			return port;
	return -1;
}

static bool fe_switch_native_key(const struct rtl_l2_fdb_entry *entry)
{
	return entry->valid && !entry->key_vid && !entry->key_sc &&
	       !entry->key_dot1p;
}

static bool fe_switch_learned_owned(const struct rtl_l2_fdb_entry *entry,
				   u32 ports)
{
	return fe_switch_native_key(entry) && !entry->is_static &&
	       !entry->multicast && !entry->temporary &&
	       !entry->in_station_move && entry->destination < FE_LAN_PORTS &&
	       (ports & BIT(entry->destination)) && is_valid_ether_addr(entry->mac);
}

static int fe_switch_fdb_write(struct rtl_fe_bridge *sw,
			       enum rtl_l2_fdb_command command,
			       const unsigned int *words)
{
	struct rtl_dq_io io = fe_io(sw->fe);
	struct rtl_l2_fdb_result result;
	int ret = rtl_l2_fdb_command(&io, command, 0, words, &result);

	if (ret)
		return ret;
	if (result.status == RTL_L2_FDB_STATUS_HIT ||
	    (command == RTL_L2_FDB_DELETE &&
	     result.status == RTL_L2_FDB_STATUS_MISS))
		return 0;
	/* LIMIT and HIT_OVER_LIMIT may have mutated the table. The caller keeps
	 * domain ownership until a complete flush and hardware restore succeed.
	 */
	return result.status == RTL_L2_FDB_STATUS_FULL ? -ENOSPC : -EIO;
}

/* HW prepare first owns/installs the all-valid SCAN filter. Never infer an
 * empty domain from the boot firmware's possibly narrow scan predicate.
 * Unknown rows are not ours to discard, even if their port happens to be a
 * LAN: this also protects a bootloader/PON service with an unknown owner.
 */
static int fe_switch_domain_claim(struct rtl_fe_bridge *sw)
{
	struct rtl_dq_io io = fe_io(sw->fe);
	struct rtl_l2_fdb_result row;
	struct rtl_l2_fdb_entry entry;
	unsigned int start = 0;
	int ret;

	while (start < RTL_L2_FDB_ENTRIES) {
		ret = rtl_l2_fdb_scan(&io, start, &row);
		if (ret <= 0) {
			if (ret)
				return ret;
			break;
		}
		rtl_l2_fdb_decode(row.words, &entry);
		/* Aging time/enable is global. A foreign dynamic row would also
		 * be affected, even if its key cannot collide with native VID0.
		 * Static L3 pins in VID4095/SC1 remain untouched and eligible.
		 */
		if (fe_switch_native_key(&entry) ||
		    (entry.valid && !entry.is_static))
			return -EEXIST;
		start = row.index + 1;
	}
	/* Mark BEFORE the first APPEND; a timeout does not prove no mutation. */
	sw->domain_owned = true;
	return 0;
}

static int fe_switch_domain_flush(struct rtl_fe_bridge *sw)
{
	struct rtl_dq_io io = fe_io(sw->fe);
	struct rtl_l2_fdb_result row;
	struct rtl_l2_fdb_entry entry;
	unsigned int start = 0, count = 0, i;
	int ret;

	if (!sw->domain_owned)
		return 0;
	while (start < RTL_L2_FDB_ENTRIES) {
		ret = rtl_l2_fdb_scan(&io, start, &row);
		if (ret < 0)
			return ret;
		if (!ret)
			break;
		rtl_l2_fdb_decode(row.words, &entry);
		if (fe_switch_native_key(&entry))
			memcpy(sw->rules[count++], row.words, sizeof(row.words));
		start = row.index + 1;
	}
	/* Learning is disabled and the pipeline drained. Collect keys BEFORE
	 * deleting: deleting during a physical-index scan would rely on an
	 * undocumented guarantee that overflow entries are never relocated.
	 * Reuse the static replay buffer only while the entire domain is gated.
	 */
	for (i = 0; i < count; i++) {
		ret = fe_switch_fdb_write(sw, RTL_L2_FDB_DELETE, sw->rules[i]);
		if (ret)
			return ret;
	}
	/* Do not release ownership merely because DELETE returned completion. */
	start = 0;
	while (start < RTL_L2_FDB_ENTRIES) {
		ret = rtl_l2_fdb_scan(&io, start, &row);
		if (ret < 0)
			return ret;
		if (!ret)
			break;
		rtl_l2_fdb_decode(row.words, &entry);
		if (fe_switch_native_key(&entry))
			return -EIO;
		start = row.index + 1;
	}
	sw->domain_owned = false;
	sw->rule_count = 0;
	return 0;
}

/* Process context, FE mutex held. The hardware owner stops learning and
 * drains before we erase learned/static rows, and retains its SCAN filter
 * until that deletion is complete. A failure retains ALL ownership.
 */
static int fe_switch_restore_locked(struct rtl_fe_bridge *sw)
{
	int ret;

	ret = fe_switch_hw_drain(sw->fe, &sw->hw);
	if (!ret)
		ret = fe_switch_domain_flush(sw);
	if (!ret)
		ret = fe_switch_hw_restore(sw->fe, &sw->hw);
	if (ret) {
		sw->error = ret;
		sw->reason = FE_SWITCH_IO_ERROR;
	}
	return ret;
}

static int fe_switch_quiesce_locked(struct rtl_fe *fe)
{
	struct rtl_fe_bridge *sw = fe->bridge;

	if (!sw)
		return 0;
	if (sw->guard.registered)
		rtl9617c_switch_guard_invalidate(&sw->guard);
	else
		fe_switch_gate(sw);
	return fe_switch_restore_locked(sw);
}

static void fe_switch_reconcile_locked(struct rtl_fe *fe)
{
	if (fe->bridge)
		fe_switch_queue(fe->bridge);
}

static int fe_switch_request_locked(struct rtl_fe *fe, bool requested)
{
	int ret = 0;

	if (!fe->bridge)
		return -EOPNOTSUPP;
	WRITE_ONCE(fe->bridge->requested, requested);
	if (!requested)
		ret = fe_switch_quiesce_locked(fe);
	fe_switch_reconcile_locked(fe);
	return ret;
}

static bool fe_switch_requested(struct rtl_fe *fe)
{
	return fe->bridge && READ_ONCE(fe->bridge->requested);
}

static bool fe_switch_flow_allowed(struct rtl_fe *fe)
{
	return fe->bridge && READ_ONCE(fe->bridge->flow_allowed) &&
	       READ_ONCE(fe->route_admitted);
}

/* RTNL and FE mutex held. Each snapshot obtains current pointers afresh.
 * No device reference survives RTNL, so device unregister cannot wait on a
 * work item which needs RTNL. Atomic callbacks compare cached values only.
 */
static enum fe_switch_reason
fe_switch_snapshot(struct rtl_fe_bridge *sw, struct fe_switch_plan *plan)
{
	struct net_device *dev, *master, *lower;
	struct list_head *iter;
	struct rtl_fe_port *port;
	unsigned int i, bit;
	bool online;

	memset(plan, 0, sizeof(*plan));
	memset(sw->ports, 0, sizeof(sw->ports));
	sw->master = NULL;
	sw->route_mask = 0;
	list_for_each_entry(port, &sw->fe->ports, list) {
		if (port->retired || port->source >= FE_LAN_PORTS ||
		    port->netdev->reg_state != NETREG_REGISTERED ||
		    port->source != port->destination)
			continue;
		sw->ports[port->source] = port->netdev;
	}
	for (i = 0; i < FE_LAN_PORTS; i++) {
		dev = sw->ports[i];
		if (!dev)
			continue;
		online = netif_running(dev) && netif_carrier_ok(dev);
		if (rtl9617c_switch_device_has_policy(dev))
			plan->software_policy = true;
		if (online && sw->fe->enabled)
			sw->route_mask |= BIT(i);
		master = netdev_master_upper_dev_get(dev);
		if (!master || !netif_is_bridge_master(master))
			continue;
		if (sw->master && sw->master != master)
			plan->multi_bridge = true;
		sw->master = master;
		/* Offline members still identify the whole topology and every
		 * bridge's policy. Do not hide a second bridge or foreign lower
		 * merely because its native LAN has no carrier at this instant.
		 */
		plan->vlan_filtering |= br_vlan_enabled(master);
		plan->promisc |= !!(master->flags & IFF_PROMISC);
		if (!br_rtl9617c_l2_eligible(master))
			plan->private_policy = true;
		if (rtl9617c_switch_device_has_policy(master))
			plan->software_policy = true;
		netdev_for_each_lower_dev(master, lower, iter)
			if (fe_switch_port_index(sw, lower) < 0)
				plan->mixed = true;
		/* The worker has gated, drained and removed the old hardware
		 * domain before this snapshot. An unplugged/admin-down member is
		 * not a policy-blocked live member; leave it out of this generation
		 * so one connected LAN can retain its routed hardware path.
		 */
		if (!online)
			continue;
		plan->ports |= BIT(i);
		plan->state[i] = br_port_get_stp_state(dev);
		for (bit = 0; bit <= 24; bit++)
			if (br_port_flag_is_set(dev, BIT(bit)))
				plan->flags[i] |= BIT(bit);
		if (!br_rtl9617c_l2_port_eligible(dev))
			plan->private_policy = true;
	}
	if (!sw->master)
		return plan->software_policy ? FE_SWITCH_GUARDED : FE_SWITCH_NO_BRIDGE;
	return fe_switch_plan_validate(plan);
}

/* Replay is synchronous and supplies our non-NULL ctx. Ordinary FDB events
 * never program a table in atomic context; they invalidate the snapshot.
 */
static int fe_switch_replay_fdb(struct rtl_fe_bridge *sw,
			       const struct switchdev_notifier_fdb_info *info)
{
	struct rtl_l2_fdb_entry entry = { 0 }, previous;
	unsigned int words[RTL_L2_FDB_WORDS], i;
	int port = fe_switch_port_index(sw, info->info.dev);

	if (info->vid || switchdev_fdb_is_dynamically_learned(info))
		return 0;
	/* A full-bridge replay includes offline members too. Their old rows
	 * were flushed before this generation; do not recreate an output which
	 * the snapshot deliberately excluded. Local MACs still belong to CPU.
	 */
	if (!info->is_local && port >= 0 && !(sw->replay_ports & BIT(port)))
		return 0;
	if (info->locked || (!info->is_local && port < 0) ||
	    !is_valid_ether_addr(info->addr))
		return -EOPNOTSUPP;
	ether_addr_copy(entry.mac, info->addr);
	entry.is_static = 1;
	entry.valid = 1;
	entry.sa_permit = entry.da_permit = 1;
	entry.destination = info->is_local ? sw->local_target : (unsigned int)port;
	if (rtl_l2_fdb_encode(words, &entry))
		return -EINVAL;
	/* Replay covers the entire bridge for each port. Deduplicate keys, not
	 * destination, so moving a static entry cannot leave two owners behind.
	 */
	for (i = 0; i < sw->rule_count; i++) {
		rtl_l2_fdb_decode(sw->rules[i], &previous);
		if (ether_addr_equal(previous.mac, entry.mac))
			break;
	}
	if (i == RTL_L2_FDB_ENTRIES)
		return -ENOSPC;
	memcpy(sw->rules[i], words, sizeof(words));
	if (i == sw->rule_count)
		WRITE_ONCE(sw->rule_count, sw->rule_count + 1);
	return 0;
}

static int fe_switch_atomic_event(struct notifier_block *nb,
				 unsigned long event, void *pointer)
{
	struct rtl_fe_bridge *sw = container_of(nb, struct rtl_fe_bridge, atomic_nb);
	struct switchdev_notifier_info *info = pointer;
	struct switchdev_notifier_fdb_info *fdb = pointer;
	int ret;

	if (READ_ONCE(sw->stopping) ||
	    (event != SWITCHDEV_FDB_ADD_TO_DEVICE &&
	     event != SWITCHDEV_FDB_DEL_TO_DEVICE))
		return NOTIFY_DONE;
	if (info->ctx == sw) {
		if (!sw->replaying || event != SWITCHDEV_FDB_ADD_TO_DEVICE)
			return NOTIFY_DONE;
		ret = fe_switch_replay_fdb(sw, fdb);
		if (ret)
			sw->replay_error = ret;
		return notifier_from_errno(ret);
	}
	if (fe_switch_port_index(sw, info->dev) < 0 &&
	    info->dev != READ_ONCE(sw->master))
		return NOTIFY_DONE;
	/* New ordinary CPU-learned sources are not a configuration change.
	 * Rebuilding for each such source would flush the hardware learning we
	 * are trying to synchronize. The core guard already covers true MAC
	 * moves and deletion before publication, including user FDB flushes.
	 */
	if (switchdev_fdb_is_dynamically_learned(fdb))
		return NOTIFY_DONE;
	rtl9617c_switch_guard_invalidate(&sw->guard);
	return NOTIFY_DONE;
}

static int fe_switch_blocking_event(struct notifier_block *nb,
				   unsigned long event, void *pointer)
{
	struct rtl_fe_bridge *sw = container_of(nb, struct rtl_fe_bridge, blocking_nb);
	struct switchdev_notifier_info *info = pointer;

	if (READ_ONCE(sw->stopping) || info->ctx == sw)
		return NOTIFY_DONE;
	if (event == SWITCHDEV_PORT_OBJ_ADD || event == SWITCHDEV_PORT_OBJ_DEL) {
		struct switchdev_notifier_port_obj_info *object = pointer;

		if (object->obj->id == SWITCHDEV_OBJ_ID_PORT_MDB ||
		    object->obj->id == SWITCHDEV_OBJ_ID_HOST_MDB)
			return NOTIFY_DONE;
	}
	if (fe_switch_port_index(sw, info->dev) >= 0 ||
	    info->dev == READ_ONCE(sw->master))
		fe_switch_queue(sw);
	/* Do not claim MDB/VLAN objects were hardware-offloaded. Their packets
	 * stay on the CPU path, including default multicast snooping.
	 */
	return NOTIFY_DONE;
}

static int fe_switch_feedback(struct rtl_fe_bridge *sw,
			      const struct fe_switch_learned *entry, bool adding,
			      u64 generation)
{
	struct net_device *dev;
	int ret;

	if (entry->port >= FE_LAN_PORTS)
		return -ENODEV;
	dev = sw->ports[entry->port];
	if (!dev || !netif_is_bridge_port(dev))
		return -ENODEV;
	if (adding) {
		/* RTNL alone does not exclude a CPU softirq MAC move. The core
		 * helper validates the epoch and publishes under hash->gate locks,
		 * atomically with the move's pre-publication policy BEGIN.
		 */
		ret = br_rtl9617c_fdb_learn(dev, entry->address,
					  &sw->guard, generation);
		if (ret)
			return ret;
		WRITE_ONCE(sw->learned_adds, sw->learned_adds + 1);
	} else if (br_rtl9617c_fdb_forget(dev, entry->address)) {
		/* A user may have replaced a formerly learned key with a static
		 * or local entry. The helper validates current ownership and the
		 * old destination under the bridge hash lock before deleting it.
		 */
		WRITE_ONCE(sw->learned_deletes, sw->learned_deletes + 1);
	}
	return 0;
}

/* RTNL held, no FE mutex: unoffload may drain other deferred notifiers. */
static void fe_switch_unoffload(struct rtl_fe_bridge *sw)
{
	unsigned int i;

	for (i = 0; i < sw->learned_count; i++)
		fe_switch_feedback(sw, &sw->learned[i], false, 0);
	WRITE_ONCE(sw->learned_count, 0);
	/* A later feedback failure must not orphan the successful prefix of
	 * a scan. Such rows are not yet in the committed learned[] snapshot.
	 */
	for (i = 0; i < sw->pending_count; i++)
		fe_switch_feedback(sw, &sw->next[i], false, 0);
	WRITE_ONCE(sw->pending_count, 0);
	for (i = 0; i < FE_LAN_PORTS; i++) {
		if (!(sw->offloaded & BIT(i)))
			continue;
		if (sw->ports[i] && netif_is_bridge_port(sw->ports[i]))
			switchdev_bridge_port_unoffload(sw->ports[i], sw,
				&sw->atomic_nb, &sw->blocking_nb);
	}
	sw->offloaded = 0;
}

static int fe_switch_netdev_event(struct notifier_block *nb,
				 unsigned long event, void *pointer)
{
	struct rtl_fe_bridge *sw = container_of(nb, struct rtl_fe_bridge, netdev_nb);
	struct net_device *dev = netdev_notifier_info_to_dev(pointer);
	struct netdev_notifier_changeupper_info *upper = pointer;
	bool detaching;
	int port, ret = 0;

	if (READ_ONCE(sw->stopping))
		return NOTIFY_DONE;
	port = fe_switch_port_index(sw, dev);
	if (port < 0 && dev != READ_ONCE(sw->master))
		return NOTIFY_DONE;
	detaching = event == NETDEV_UNREGISTER ||
		(event == NETDEV_PRECHANGEUPPER && !upper->linking);
	if (detaching) {
		/* PRECHANGEUPPER still has a live br_port for unoffload. The core
		 * pre-publication gate has already closed ingress; restore before
		 * borrowing pointers can end or the netdevice can be freed.
		 */
		mutex_lock(&sw->fe->lock);
		ret = fe_switch_quiesce_locked(sw->fe);
		mutex_unlock(&sw->fe->lock);
		fe_switch_unoffload(sw);
		if (event == NETDEV_UNREGISTER) {
			if (port >= 0)
				WRITE_ONCE(sw->ports[port], NULL);
			if (dev == sw->master)
				WRITE_ONCE(sw->master, NULL);
		}
	}
	switch (event) {
	case NETDEV_UP:
	/* __dev_close_many() sends this before clearing RUNNING and before
	 * ndo_stop disables the MAC. Do not leave other ports forwarding to an
	 * output until the later NETDEV_DOWN notification. */
	case NETDEV_GOING_DOWN:
	case NETDEV_DOWN:
	case NETDEV_CHANGE:
	case NETDEV_CHANGEADDR:
	case NETDEV_CHANGEUPPER:
	case NETDEV_CHANGEINFODATA:
	case NETDEV_UNREGISTER:
		rtl9617c_switch_guard_invalidate(&sw->guard);
		break;
	default:
		break;
	}
	return notifier_from_errno(ret);
}

static void fe_switch_work(struct work_struct *work)
{
	struct rtl_fe_bridge *sw = container_of(work, struct rtl_fe_bridge, work);
	struct rtl_fe *fe = sw->fe;
	struct fe_switch_plan plan;
	clock_t age_ticks;
	unsigned long seconds;
	unsigned int i;
	u64 generation;
	int ret = 0;
	bool native = false;

	rtnl_lock();
	mutex_lock(&fe->lock);
	if (sw->stopping || fe->shutting_down)
		goto unlock;
	/* This operation does NOT increment the epoch or queue this work. A
	 * worker which invalidated itself here would rebuild forever.
	 */
	rtl9617c_switch_guard_quiesce(&sw->guard);
	ret = fe_switch_restore_locked(sw);
	if (ret)
		goto unlock;
	mutex_unlock(&fe->lock);
	fe_switch_unoffload(sw);
	mutex_lock(&fe->lock);
	sw->native_mask = 0;
	sw->error = 0;
	if (!fe->engine_ready) {
		sw->reason = FE_SWITCH_ENGINE_DOWN;
		goto unlock;
	}
	generation = rtl9617c_switch_guard_generation(&sw->guard);
	sw->reason = fe_switch_snapshot(sw, &plan);
	sw->local_target = fe->enabled && fe->prepared ? 25 : 16;
	/* A bridge port may be blocked or have software-only policy even when
	 * native switching is not requested. Do not resurrect old L3 rules past
	 * that policy merely because native-L2 eligibility failed.
	 */
	if (sw->reason != FE_SWITCH_OK && sw->reason != FE_SWITCH_NO_BRIDGE) {
		sw->route_mask = 0;
		goto unlock;
	}
	if (!sw->requested &&
	    (sw->reason == FE_SWITCH_OK || sw->reason == FE_SWITCH_NO_BRIDGE))
		sw->reason = FE_SWITCH_REQUEST_OFF;
	if (rtl9617c_switch_guard_blocked(&sw->guard)) {
		sw->reason = FE_SWITCH_GUARDED;
		sw->route_mask = 0;
		goto unlock;
	}
	/* A removed final hook/TCX policy may still have old RCU readers. Keep
	 * hardware admission closed across their grace period. No FE mutex is
	 * held while waiting for networking read-side sections to finish.
	 */
	mutex_unlock(&fe->lock);
	synchronize_net();
	mutex_lock(&fe->lock);
	if (sw->stopping || fe->shutting_down || !fe->engine_ready ||
	    generation != rtl9617c_switch_guard_generation(&sw->guard)) {
		sw->reason = FE_SWITCH_GUARDED;
		goto unlock;
	}
	if (!sw->route_generation_valid || sw->route_generation != generation) {
		ret = fe_switch_flush_routes_locked(fe);
		if (ret) {
			sw->error = ret;
			sw->reason = FE_SWITCH_IO_ERROR;
			goto unlock;
		}
		sw->route_generation = generation;
		sw->route_generation_valid = true;
		sw->retry_count = 0;
	}
	/* Routing is independently authorized through nft flowtable. Ordinary
	 * native-L2 ineligibility must not disable that existing datapath. A
	 * persistent core policy veto, in contrast, leaves every RX on CPU16.
	 */
	if (sw->reason != FE_SWITCH_OK)
		goto arm;
	age_ticks = br_get_ageing_time(sw->master);
	/* Linux exposes USER_HZ ticks; hardware exposes whole 19-bit seconds.
	 * Do not silently wrap jiffies_to_msecs() or round a sub-second policy.
	 */
	if (age_ticks <= 0 || age_ticks % USER_HZ ||
	    age_ticks / USER_HZ > GENMASK(18, 0)) {
		sw->reason = FE_SWITCH_PRIVATE_POLICY;
		goto unlock;
	}
	seconds = age_ticks / USER_HZ;
	sw->rule_count = 0;
	sw->replay_error = 0;
	sw->replay_ports = plan.ports;
	sw->replaying = true;
	/* switchdev's replay invokes our supplied notifier synchronously with
	 * ctx=sw. No live packet callback is permitted to append a static rule.
	 * Release the FE mutex while switchdev drains deferred control work.
	 */
	mutex_unlock(&fe->lock);
	for (i = 0; i < FE_LAN_PORTS; i++) {
		if (!(plan.ports & BIT(i)))
			continue;
		ret = switchdev_bridge_port_offload(sw->ports[i], sw->ports[i], sw,
			&sw->atomic_nb, &sw->blocking_nb, false, NULL);
		if (ret)
			break;
		sw->offloaded |= BIT(i);
	}
	mutex_lock(&fe->lock);
	sw->replaying = false;
	sw->replay_ports = 0;
	if (!ret)
		ret = sw->replay_error;
	if (ret)
		goto failure;
	if (sw->stopping || fe->shutting_down) {
		ret = -ESHUTDOWN;
		goto failure;
	}
	if (!fe->engine_ready || generation !=
	    rtl9617c_switch_guard_generation(&sw->guard)) {
		sw->reason = FE_SWITCH_GUARDED;
		ret = -EAGAIN;
		goto failure;
	}
	ret = fe_switch_hw_prepare(fe, &sw->hw, plan.ports, seconds,
				   br_multicast_enabled(sw->master));
	if (ret) {
		if (ret == -EOPNOTSUPP)
			sw->reason = FE_SWITCH_HW_UNSUPPORTED;
		goto failure;
	}
	ret = fe_switch_domain_claim(sw);
	if (ret) {
		sw->reason = ret == -EEXIST ? FE_SWITCH_FOREIGN_FDB : FE_SWITCH_IO_ERROR;
		goto failure;
	}
	for (i = 0; i < sw->rule_count; i++) {
		ret = fe_switch_fdb_write(sw, RTL_L2_FDB_APPEND, sw->rules[i]);
		if (ret)
			goto failure;
	}
	sw->native_mask = plan.ports;
	sw->route_mask &= ~sw->native_mask;
	native = true;
arm:
	if (!rtl9617c_switch_guard_try_arm(&sw->guard, generation)) {
		sw->reason = FE_SWITCH_GUARDED;
		ret = -EAGAIN;
		goto failure;
	}
	sw->rebuilds++;
	if (native)
		mod_delayed_work(system_long_wq, &sw->scan_work, HZ);
	goto unlock;
failure:
	sw->error = ret;
	if (sw->reason == FE_SWITCH_OK)
		sw->reason = ret == -ENOSPC ? FE_SWITCH_FDB_CAPACITY : FE_SWITCH_IO_ERROR;
	sw->native_mask = 0;
	/* A stale epoch never opens the old snapshot. The external change has
	 * queued another work iteration. Do not self-invalidate on failure.
	 */
	rtl9617c_switch_guard_quiesce(&sw->guard);
	ret = fe_switch_restore_locked(sw);
	if (!ret && (sw->reason == FE_SWITCH_FOREIGN_FDB ||
		     sw->reason == FE_SWITCH_HW_UNSUPPORTED))
		rtl9617c_switch_guard_try_arm(&sw->guard, generation);
	if (!ret && sw->reason == FE_SWITCH_FOREIGN_FDB && sw->retry_count < 8) {
		unsigned int delay = min(60U, 5U << min(sw->retry_count, 4U));

		/* A boot dynamic row may age naturally. Retry without deleting
		 * the foreign owner, with bounded backoff (up to 315 seconds).
		 * Permanent conflicts remain visible instead of looping forever.
		 */
		sw->retry_count++;
		mod_delayed_work(system_long_wq, &sw->scan_work, delay * HZ);
	}
unlock:
	mutex_unlock(&fe->lock);
	if (!sw->active)
		fe_switch_unoffload(sw);
	rtnl_unlock();
}

static int fe_switch_learned_compare(const void *a, const void *b)
{
	const struct fe_switch_learned *left = a, *right = b;

	return memcmp(left->address, right->address, ETH_ALEN);
}

static void fe_switch_scan(struct work_struct *work)
{
	struct rtl_fe_bridge *sw = container_of(to_delayed_work(work),
		struct rtl_fe_bridge, scan_work);
	struct rtl_dq_io io = fe_io(sw->fe);
	struct rtl_l2_fdb_result row;
	struct rtl_l2_fdb_entry entry;
	struct fe_switch_learned *swap;
	unsigned int start = 0, count = 0, old, cursor;
	u64 generation;
	int ret = 0;

	rtnl_lock();
	mutex_lock(&sw->fe->lock);
	if (sw->stopping || sw->fe->shutting_down)
		goto out;
	if (!sw->active) {
		if (sw->requested && sw->fe->engine_ready &&
		    sw->reason == FE_SWITCH_FOREIGN_FDB &&
		    !rtl9617c_switch_guard_blocked(&sw->guard))
			fe_switch_queue(sw);
		goto out;
	}
	generation = rtl9617c_switch_guard_generation(&sw->guard);
	while (start < RTL_L2_FDB_ENTRIES) {
		ret = rtl_l2_fdb_scan(&io, start, &row);
		if (ret <= 0)
			break;
		rtl_l2_fdb_decode(row.words, &entry);
		if (fe_switch_learned_owned(&entry, sw->native_mask)) {
			ether_addr_copy(sw->next[count].address, entry.mac);
			sw->next[count++].port = entry.destination;
		}
		start = row.index + 1;
	}
	if (ret < 0) {
		sw->scan_errors++;
		sw->error = ret;
		rtl9617c_switch_guard_invalidate(&sw->guard);
		goto out;
	}
	if (!sw->active || generation !=
	    rtl9617c_switch_guard_generation(&sw->guard))
		goto out;
	sort(sw->next, count, sizeof(*sw->next), fe_switch_learned_compare, NULL);
	for (cursor = 1; cursor < count; cursor++) {
		if (!fe_switch_learned_compare(&sw->next[cursor - 1],
					       &sw->next[cursor])) {
			/* A moving key observed twice is not a coherent new owner.
			 * Retain the last complete mirror and retry after learning
			 * settles, rather than picking an arbitrary physical slot.
			 */
			mod_delayed_work(system_long_wq, &sw->scan_work, HZ);
			goto out;
		}
	}
	/* Complete snapshot only. Delete absent KEYS before adding moves:
	 * br_fdb_external_learn_del() ignores the old port and deletes by key,
	 * so delete-after-add would erase a newly moved entry on its new port.
	 */
	for (old = 0, cursor = 0; old < sw->learned_count; old++) {
		while (cursor < count && fe_switch_learned_compare(
		       &sw->next[cursor], &sw->learned[old]) < 0)
			cursor++;
		if (cursor == count || fe_switch_learned_compare(
		    &sw->next[cursor], &sw->learned[old]))
			fe_switch_feedback(sw, &sw->learned[old], false, 0);
	}
	for (cursor = 0; cursor < count; cursor++) {
		ret = fe_switch_feedback(sw, &sw->next[cursor], true, generation);
		if (ret) {
			sw->error = ret;
			sw->scan_errors++;
			rtl9617c_switch_guard_invalidate(&sw->guard);
			goto out;
		}
		sw->pending_count = cursor + 1;
	}
	swap = sw->learned;
	sw->learned = sw->next;
	sw->next = swap;
	sw->learned_count = count;
	sw->pending_count = 0;
	sw->polls++;
	mod_delayed_work(system_long_wq, &sw->scan_work, HZ);
out:
	mutex_unlock(&sw->fe->lock);
	rtnl_unlock();
}

static struct rtl_fe_bridge *fe_bridge_start(struct rtl_fe *fe)
{
	struct rtl_fe_bridge *sw;
	int ret;

	sw = kzalloc(sizeof(*sw), GFP_KERNEL);
	if (!sw)
		return ERR_PTR(-ENOMEM);
	sw->fe = fe;
	/* The new silicon path has not yet passed board throughput/interop
	 * acceptance. Keep upgrades on the existing software bridge baseline;
	 * the separate runtime control explicitly opts into native switching.
	 */
	sw->requested = false;
	sw->reason = FE_SWITCH_ENGINE_DOWN;
	INIT_WORK(&sw->work, fe_switch_work);
	INIT_DELAYED_WORK(&sw->scan_work, fe_switch_scan);
	INIT_LIST_HEAD(&sw->guard.list);
	sw->netdev_nb.notifier_call = fe_switch_netdev_event;
	sw->atomic_nb.notifier_call = fe_switch_atomic_event;
	sw->blocking_nb.notifier_call = fe_switch_blocking_event;
	sw->rules = kvcalloc(RTL_L2_FDB_ENTRIES, sizeof(*sw->rules), GFP_KERNEL);
	sw->learned = kvcalloc(RTL_L2_FDB_ENTRIES, sizeof(*sw->learned), GFP_KERNEL);
	sw->next = kvcalloc(RTL_L2_FDB_ENTRIES, sizeof(*sw->next), GFP_KERNEL);
	if (!sw->rules || !sw->learned || !sw->next) {
		ret = -ENOMEM;
		goto fail;
	}
	ret = register_switchdev_notifier(&sw->atomic_nb);
	if (ret)
		goto fail;
	sw->atomic_registered = true;
	ret = register_switchdev_blocking_notifier(&sw->blocking_nb);
	if (ret)
		goto fail;
	sw->blocking_registered = true;
	ret = register_netdevice_notifier(&sw->netdev_nb);
	if (ret)
		goto fail;
	sw->netdev_registered = true;
	/* Physical netdevices cannot move namespaces. Register before ports are
	 * admitted so pre-existing netfilter/TCX/XDP policy is seen at probe.
	 */
	ret = rtl9617c_switch_guard_register(&sw->guard, &init_net,
					     &fe_switch_guard_ops, sw);
	if (ret)
		goto fail;
	return sw;
fail:
	WRITE_ONCE(sw->stopping, true);
	if (sw->guard.registered)
		rtl9617c_switch_guard_unregister(&sw->guard);
	if (sw->netdev_registered)
		unregister_netdevice_notifier(&sw->netdev_nb);
	if (sw->blocking_registered)
		unregister_switchdev_blocking_notifier(&sw->blocking_nb);
	if (sw->atomic_registered)
		unregister_switchdev_notifier(&sw->atomic_nb);
	cancel_work_sync(&sw->work);
	cancel_delayed_work_sync(&sw->scan_work);
	kvfree(sw->rules);
	kvfree(sw->learned);
	kvfree(sw->next);
	kfree(sw);
	return ERR_PTR(ret);
}

/* Stop ALL asynchronous users even when hardware restoration fails. The
 * owner then stays quarantined for the final synchronous cleanup attempt;
 * a later namespace policy change must never call MMIO after devm unmaps it.
 * The caller must not hold FE mutex or RTNL while cancelling these works.
 */
static int fe_bridge_stop(struct rtl_fe_bridge *sw)
{
	int ret;

	if (!sw)
		return 0;
	WRITE_ONCE(sw->stopping, true);
	if (sw->guard.registered)
		rtl9617c_switch_guard_unregister(&sw->guard);
	if (sw->netdev_registered) {
		unregister_netdevice_notifier(&sw->netdev_nb);
		sw->netdev_registered = false;
	}
	if (sw->blocking_registered) {
		unregister_switchdev_blocking_notifier(&sw->blocking_nb);
		sw->blocking_registered = false;
	}
	if (sw->atomic_registered) {
		unregister_switchdev_notifier(&sw->atomic_nb);
		sw->atomic_registered = false;
	}
	cancel_work_sync(&sw->work);
	cancel_delayed_work_sync(&sw->scan_work);
	rtnl_lock();
	mutex_lock(&sw->fe->lock);
	fe_switch_gate(sw);
	ret = fe_switch_restore_locked(sw);
	mutex_unlock(&sw->fe->lock);
	fe_switch_unoffload(sw);
	rtnl_unlock();
	if (ret)
		return ret;
	kvfree(sw->rules);
	kvfree(sw->learned);
	kvfree(sw->next);
	kfree(sw);
	return 0;
}

static ssize_t fe_bridge_stats(struct rtl_fe_bridge *sw,
			       char *buffer, size_t bytes)
{
	const struct fe_switch_hw_observed *observed;
	ssize_t length;

	if (!sw)
		return scnprintf(buffer, bytes, "l2_supported=0 l2_requested=0 l2_active=0\n");
	length = scnprintf(buffer, bytes,
		"l2_supported=1 l2_requested=%u l2_active=%u l2_reason=%u "
		"l2_hw_reason=%u l2_hw_reason_name=%s "
		"l2_error=%d l2_ports=%#x l2_route_ports=%#x l2_domain_owned=%u "
		"l2_flow_allowed=%u "
		"l2_static=%u l2_learned=%u l2_rebuilds=%llu l2_polls=%llu "
		"l2_learn_adds=%llu l2_learn_deletes=%llu l2_scan_errors=%llu "
		"l2_bum_hardware=0 l2_vlan_hardware=0 l2_local_target=%u "
		"l2_retries=%u\n",
		sw->requested, READ_ONCE(sw->active), sw->reason,
		sw->hw.reason, fe_switch_hw_reason_name(&sw->hw), sw->error, sw->native_mask,
		READ_ONCE(sw->armed_route_mask), sw->domain_owned,
		READ_ONCE(sw->flow_allowed), READ_ONCE(sw->rule_count),
		READ_ONCE(sw->learned_count), sw->rebuilds, sw->polls,
		READ_ONCE(sw->learned_adds), READ_ONCE(sw->learned_deletes),
		sw->scan_errors, sw->local_target, sw->retry_count);
	/* Read-only preflight evidence, not packet/FDB dumps: these are fixed
	 * hardware configuration values and physical-port IDs, never addresses
	 * learned from users or WAN/OMCI credentials. */
	observed = &sw->hw.observed;
	length += scnprintf(buffer + length, bytes - length,
		"l2_hw_vlan_mode=%#x l2_hw_hash_control=%#x l2_hw_aging=%#x "
		"l2_hw_packet_length=%#x l2_hw_tpid0=%#x l2_hw_tpid1=%#x "
		"l2_hw_tpid2=%#x l2_hw_tpid3=%#x l2_hw_oversize_allow=%#x "
		"l2_hw_source_port=%u l2_hw_source_logical=%u "
		"l2_hw_learning_port=%u l2_hw_learning_profile=%u\n",
		observed->vlan_mode, observed->hash_control, observed->aging,
		observed->packet_length, observed->tpid[0], observed->tpid[1],
		observed->tpid[2], observed->tpid[3], observed->rx_oversize_allow,
		observed->source_port, observed->source_logical,
		observed->learning_port, observed->learning_profile);
	return length;
}

#else
/* A built-in Ethernet driver must not refer to a modular bridge. Ordinary
 * management Ethernet remains usable; native hardware L2 is unavailable.
 */
static struct rtl_fe_bridge *fe_bridge_start(struct rtl_fe *fe) { return NULL; }
static int fe_bridge_stop(struct rtl_fe_bridge *sw) { return 0; }
static int fe_switch_quiesce_locked(struct rtl_fe *fe)
{
	unsigned int port, value;

	fe_route_gate(fe);
	for (port = 0; port < FE_LAN_PORTS; port++) {
		value = fe_read(fe, FE_LAN_RX_CTRL(port));
		fe_write(fe, FE_LAN_RX_CTRL(port),
			 (value & ~(0x3fU << 16)) | BIT(28) | (16U << 16));
	}
	fe_read(fe, FE_LAN_RX_CTRL(FE_LAN_PORTS - 1));
	return 0;
}
static void fe_switch_reconcile_locked(struct rtl_fe *fe)
{
	unsigned int port, value;

	/* Bridge-unreachable builds retain their former routed flowtable path.
	 * This is not native L2 support, and never clears the bypass bit.
	 */
	if (!fe->engine_ready || !fe->enabled || fe->shutting_down)
		return;
	for (port = 0; port < FE_LAN_PORTS; port++) {
		value = fe_read(fe, FE_LAN_RX_CTRL(port));
		fe_write(fe, FE_LAN_RX_CTRL(port),
			 (value & ~(0x3fU << 16)) | BIT(28) | (25U << 16));
	}
	fe_read(fe, FE_LAN_RX_CTRL(FE_LAN_PORTS - 1));
	fe_route_arm(fe);
}
static int fe_switch_request_locked(struct rtl_fe *fe, bool requested)
{
	return -EOPNOTSUPP;
}
static bool fe_switch_requested(struct rtl_fe *fe) { return false; }
static bool fe_switch_flow_allowed(struct rtl_fe *fe)
{
	return fe->engine_ready && fe->enabled && fe->route_admitted &&
	       !fe->shutting_down;
}
static ssize_t fe_bridge_stats(struct rtl_fe_bridge *sw, char *buffer, size_t bytes)
{
	return scnprintf(buffer, bytes, "l2_supported=0 l2_requested=0 l2_active=0\n");
}
#endif

void rtl_fe_switch_rx(struct rtl_fe *fe, struct sk_buff *skb,
		     unsigned int source, u32 header0, u32 header1)
{
	/* Every CPU-delivered native-L2 frame was TRAPPED, never also flooded
	 * by the ASIC. In particular Header-A BC/MC bits do not prove forwarding.
	 * Leave offload_fwd_mark clear so Linux forwards exactly one CPU copy.
	 */
	(void)fe;
	(void)skb;
	(void)source;
	(void)header0;
	(void)header1;
}

