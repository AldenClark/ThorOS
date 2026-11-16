/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Native LAN switching, not a packet-observation shortcut.  Linux bridge
 * owns topology and policy; switchdev supplies its FDB and the synchronous
 * guard closes admission BEFORE policy publication.  Only an unchanged,
 * fully programmed snapshot may reopen the hardware path.
 *
 * The admitted hardware contract is a single native untagged LAN bridge,
 * per-port learning/isolation and hardware unicast. An independently owned
 * MCE recipe may add eligible BUM replication; control packets stay on CPU.
 * Non-forwarding STP ports remain on CPU;
 * their control frames and software bridge state machine remain intact.
 * VID-aware control-plane support does not bypass the unverified IVL
 * parser/consumer contract: VLAN filtering still uses the software path.
 * No skb is treated as an authorization and ordinary traps are not marked
 * forwarded. MCE CPU copies have a separate immutable provenance extension.
 */
#include <linux/if_bridge.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/rtl9617c-switch.h>
#include <linux/rtnetlink.h>
#include <linux/sort.h>
#include <linux/vmalloc.h>
#include <net/net_namespace.h>
#include <net/switchdev.h>

#include "rtl9617c-l2-table.h"
#include "rtl9617c-l2-domain.h"

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
	FE_SWITCH_AGING_UNSUPPORTED,
};

struct fe_switch_plan {
	u32 ports;
	unsigned long flags[FE_LAN_PORTS];
	u8 state[FE_LAN_PORTS];
	bool vlan_filtering, mixed, multi_bridge, private_policy, promisc;
	bool software_policy;
};

/* A pure capability check, shared by the real worker and host regressions.
 * Multicast snooping is intentionally NOT a veto: unsupported multicast is
 * trapped. The separate bounded MDB/MCE snapshot governs any replication,
 * so this generic port check never guesses snooping/router-port policy.
 */
static enum fe_switch_reason
fe_switch_route_plan_validate(const struct fe_switch_plan *plan)
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
	return FE_SWITCH_OK;
}

static enum fe_switch_reason
fe_switch_plan_validate(const struct fe_switch_plan *plan)
{
	const unsigned long allowed = BR_BPDU_GUARD | BR_ROOT_BLOCK |
		BR_MULTICAST_FAST_LEAVE | BR_ADMIN_COST | BR_LEARNING | BR_FLOOD |
		BR_PROMISC | BR_LEARNING_SYNC | BR_MCAST_FLOOD | BR_BCAST_FLOOD |
		BR_BPDU_FILTER | BR_ISOLATED;
	unsigned int port, forwarding = 0;

	if (plan->ports & ~GENMASK(FE_LAN_PORTS - 1, 0))
		return FE_SWITCH_PORT_POLICY;
	if (plan->software_policy)
		return FE_SWITCH_GUARDED;
	if (plan->private_policy)
		return FE_SWITCH_PRIVATE_POLICY;
	if (plan->promisc)
		return FE_SWITCH_PROMISC;
	for (port = 0; port < FE_LAN_PORTS; port++) {
		if (!(plan->ports & BIT(port)))
			continue;
		if ((plan->flags[port] & ~allowed) ||
		    plan->state[port] > BR_STATE_BLOCKING)
			return FE_SWITCH_PORT_POLICY;
		if (plan->state[port] == BR_STATE_FORWARDING)
			forwarding++;
	}
	/* These limit native autonomous switching, not an exact routed flow
	 * already authorized by nft and its bridge/VLAN forwarding-path cookie.
	 * All actual software/port policy vetoes above remain fail closed. */
	if (plan->multi_bridge)
		return FE_SWITCH_MULTI_BRIDGE;
	if (plan->mixed)
		return FE_SWITCH_MIXED_PORTS;
	if (plan->vlan_filtering)
		return FE_SWITCH_VLAN_UNSUPPORTED;
	return forwarding >= 2 ? FE_SWITCH_OK : FE_SWITCH_NO_BRIDGE;
}

/* Keep plan.ports as the complete online topology. In particular, hiding a
 * blocked member here would make the independent route-policy check forget
 * its restriction. Only the final native mask excludes STP-blocked ports. */
static u32 fe_switch_forwarding_ports(const struct fe_switch_plan *plan)
{
	u32 ports = 0;
	unsigned int port;

	for (port = 0; port < FE_LAN_PORTS; port++)
		if ((plan->ports & BIT(port)) &&
		    plan->state[port] == BR_STATE_FORWARDING)
			ports |= BIT(port);
	return ports;
}

static u32 fe_switch_flag_ports(const struct fe_switch_plan *plan, u32 ports,
				 unsigned long flag)
{
	u32 selected = 0;
	unsigned int port;

	for (port = 0; port < FE_LAN_PORTS; port++)
		if ((ports & BIT(port)) && (plan->flags[port] & flag))
			selected |= BIT(port);
	return selected;
}

struct fe_switch_learned {
	u8 address[ETH_ALEN];
	u8 port;
	u16 vid;
};

struct fe_switch_published {
	u8 address[ETH_ALEN];
	u8 destination;
	u16 vid;
	u64 cookie;
};

/* A populated 4K table must not monopolize RTNL or the shared FE mutex.
 * Count every MMIO scan/merge/feedback operation, and also yield on elapsed
 * time: a slow indirect command must not consume a whole batch unchecked.
 */
#define FE_SWITCH_SCAN_BUDGET 64
#define FE_SWITCH_SCAN_SLICE_MS 2

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
	/* The IVL backend borrows the complete bridge topology under RTNL.
	 * VLAN IDs are globally unique across these masters: this silicon's
	 * FDB key has no independent bridge FID. Never retain device references
	 * past unoffload/unregister or use these pointers from packet context. */
	struct net_device *masters[FE_LAN_PORTS];
	struct rtl_l2_vlan_plan vlans;
	unsigned int master_count;
	bool vlan_domain;
	/* Stable physical owner identities, including PON/EPON outputs 32..63.
	 * Updated at add/remove under FE mutex, never cleared by a snapshot. */
	struct net_device *owned_devices[64];
	u32 offloaded, native_mask, route_mask, armed_route_mask;
	/* Synchronous switchdev replay belongs to the pending topology, not
	 * the published datapath. native_mask stays zero until preparation and
	 * every static FDB write have completed successfully. RTNL owns this
	 * immutable mask while replaying; ordinary notifications never use it.
	 */
	u32 replay_ports;
	unsigned int (*rules)[RTL_L2_FDB_WORDS];
	unsigned int rule_count, local_target, retry_count;
	/* A sticky/static destination outside this generation's forwarding
	 * subset must still pin its MAC against autonomous SA learning. Such
	 * rules trap to CPU16, where the current Linux port/STP state decides
	 * forwarding, and are deliberately never published as offloaded. Keep
	 * this bitmap independent of both the hardware-key scratch buffer and
	 * the compact publication journal. One bit per physical FDB slot. */
	unsigned int replay_traps[(RTL_L2_FDB_ENTRIES + 31) / 32];
	/* Separate from rules[], which domain_flush reuses. A failed publish
	 * must still withdraw every successful prefix by its unique FDB cookie. */
	struct fe_switch_published *published;
	unsigned int published_count;
	struct fe_switch_learned *learned, *next;
	unsigned int learned_count, pending_count;
	/* Only MACs/physical IDs survive a slice. Device pointers are always
	 * resolved under RTNL. next[] remains private until a complete scan,
	 * duplicate-key rejection and every feedback batch have succeeded.
	 */
	unsigned int scan_start, scan_count, scan_old, scan_cursor;
	u64 scan_generation;
	bool scan_running, scan_complete, scan_removed;
	bool requested, stopping, active, replaying, domain_owned, flow_allowed;
	bool route_generation_valid, route_policy_allowed;
	bool netdev_registered, atomic_registered, blocking_registered;
	int replay_error, error;
	enum fe_switch_reason reason;
	u64 rebuilds, polls, learned_adds, learned_deletes, scan_errors;
	u64 route_generation;
};

static void fe_switch_scan_reset(struct rtl_fe_bridge *sw)
{
	sw->scan_start = 0;
	sw->scan_count = 0;
	sw->scan_old = 0;
	sw->scan_cursor = 0;
	sw->scan_running = false;
	sw->scan_complete = false;
	sw->scan_removed = false;
	/* Do not clear pending_count: a partially published feedback prefix
	 * still belongs to next[] and must be forgotten during unoffload.
	 */
}

static void fe_switch_queue(struct rtl_fe_bridge *sw)
{
	if (!READ_ONCE(sw->stopping))
		queue_work(system_long_wq, &sw->work);
}

static bool fe_switch_needs_recovery(struct rtl_fe *fe)
{
	const struct rtl_fe_bridge *sw = fe->bridge;

	/* A repeated mode write may retry a failed transaction. Ordinary
	 * capability/policy fallback is not an error requiring a global flush. */
	return sw && sw->error && sw->reason != FE_SWITCH_HW_UNSUPPORTED &&
	       sw->reason != FE_SWITCH_FOREIGN_FDB;
}

static void fe_switch_track_port_locked(struct rtl_fe *fe,
					struct net_device *dev,
					unsigned int destination, bool adding)
{
	struct rtl_fe_bridge *sw = fe->bridge;

	if (!sw || destination >= ARRAY_SIZE(sw->owned_devices))
		return;
	if (adding)
		WRITE_ONCE(sw->owned_devices[destination], dev);
	else if (READ_ONCE(sw->owned_devices[destination]) == dev)
		WRITE_ONCE(sw->owned_devices[destination], NULL);
	rtl9617c_switch_guard_invalidate(&sw->guard);
}

static void fe_switch_gate(void *private)
{
	struct rtl_fe_bridge *sw = private;

	/* Revoke CPU-copy provenance before any old packet can enter Linux
	 * under a replacement bridge generation. No FE/guard lock is taken. */
	fe_mcast_revoke(sw->fe);
	WRITE_ONCE(sw->active, false);
	WRITE_ONCE(sw->armed_route_mask, 0);
	WRITE_ONCE(sw->flow_allowed, false);
	fe_switch_hw_gate(sw->fe, &sw->hw);
}

static void fe_switch_rebuild(void *private)
{
	fe_switch_queue(private);
}

/* Only compare identities here: the core holds its gate lock and RCU, not
 * RTNL or the FE mutex. It also walks the caller's lower-device graph, so a
 * bridge/VLAN upper is related without retaining borrowed upper refs.
 * PPP channels are covered by the core's conservative namespace policy.
 * A new port starts gated and is snapshotted before it can be admitted. */
static bool fe_switch_owns_device(void *private, const struct net_device *dev)
{
	struct rtl_fe_bridge *sw = private;
	unsigned int port;

	for (port = 0; port < ARRAY_SIZE(sw->owned_devices); port++)
		if (READ_ONCE(sw->owned_devices[port]) == dev)
			return true;
	return false;
}

static bool fe_switch_arm(void *private)
{
	struct rtl_fe_bridge *sw = private;
	bool armed;

	if (READ_ONCE(sw->stopping) || READ_ONCE(sw->fe->shutting_down) ||
	    !READ_ONCE(sw->fe->engine_ready))
		return false;
	/* try_arm holds the guard lock after validating the worker epoch. Make
	 * receive provenance ready before the first native selector opens, or
	 * a newly replicated CPU copy could be dropped in the partial-open
	 * window. Bridge delivery waits for this same guard to publish armed. */
	if (sw->native_mask)
		fe_mcast_arm(sw->fe, sw->route_generation);
	armed = fe_switch_hw_arm(sw->fe, &sw->hw,
				sw->native_mask, sw->route_mask,
				sw->route_policy_allowed);
	WRITE_ONCE(sw->active, armed && sw->native_mask);
	WRITE_ONCE(sw->armed_route_mask, armed ? sw->route_mask : 0);
	WRITE_ONCE(sw->flow_allowed, armed && sw->route_policy_allowed &&
		   sw->fe->enabled &&
		   READ_ONCE(sw->fe->route_admitted));
	/* The guard calls us with its lock held; never call the generation
	 * getter here. This is the exact worker generation already checked by
	 * try_arm(), not a fresh or guessed token for queued MCE copies. */
	if (!armed || !sw->native_mask)
		fe_mcast_revoke(sw->fe);
	return armed;
}

static const struct rtl9617c_switch_guard_ops fe_switch_guard_ops = {
	.quiesce = fe_switch_gate,
	.rebuild = fe_switch_rebuild,
	.arm = fe_switch_arm,
	.owns_device = fe_switch_owns_device,
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

static const struct rtl_l2_vlan_spec *
fe_switch_vlan_find(const struct rtl_fe_bridge *sw, unsigned int vid)
{
	unsigned int i;

	if (!sw->vlan_domain || !vid || vid >= RTL_L2_VLAN_IDS - 1)
		return NULL;
	for (i = 0; i < sw->vlans.count; i++)
		if (sw->vlans.vlans[i].vid == vid)
			return &sw->vlans.vlans[i];
	return NULL;
}

static struct net_device *
fe_switch_bridge_for_vid(const struct rtl_fe_bridge *sw, unsigned int vid)
{
	const struct rtl_l2_vlan_spec *vlan;

	if (!sw->vlan_domain)
		return vid ? NULL : sw->master;
	vlan = fe_switch_vlan_find(sw, vid);
	if (!vlan || !vlan->bridge || vlan->bridge > sw->master_count)
		return NULL;
	return sw->masters[vlan->bridge - 1];
}

/* Atomic notifiers may compare identities, but never dereference these
 * borrowed RTNL-owned bridge pointers. Unregister clears them after cleanup. */
static bool fe_switch_is_master(const struct rtl_fe_bridge *sw,
				const struct net_device *dev)
{
	unsigned int i;

	if (dev == READ_ONCE(sw->master))
		return true;
	for (i = 0; i < FE_LAN_PORTS; i++)
		if (dev == READ_ONCE(sw->masters[i]))
			return true;
	return false;
}

static bool fe_switch_domain_key(const struct rtl_fe_bridge *sw,
				 const struct rtl_l2_fdb_entry *entry)
{
	if (!sw->vlan_domain)
		return fe_switch_native_key(entry);
	return entry->valid && !entry->key_sc && !entry->key_dot1p &&
	       fe_switch_vlan_find(sw, entry->key_vid);
}

static bool fe_switch_learned_owned(const struct rtl_l2_fdb_entry *entry,
				   u32 ports)
{
	return fe_switch_native_key(entry) && !entry->is_static &&
	       !entry->multicast && !entry->temporary &&
	       !entry->in_station_move && entry->destination < FE_LAN_PORTS &&
	       (ports & BIT(entry->destination)) && is_valid_ether_addr(entry->mac);
}

static bool fe_switch_domain_learned(const struct rtl_fe_bridge *sw,
				     const struct rtl_l2_fdb_entry *entry,
				     unsigned int ports)
{
	const struct rtl_l2_vlan_spec *vlan;

	if (!sw->vlan_domain)
		return fe_switch_learned_owned(entry, ports);
	if (!fe_switch_domain_key(sw, entry) || entry->is_static ||
	    entry->multicast || entry->temporary || entry->in_station_move ||
	    entry->destination >= FE_LAN_PORTS ||
	    !(ports & BIT(entry->destination)) ||
	    !is_valid_ether_addr(entry->mac))
		return false;
	vlan = fe_switch_vlan_find(sw, entry->key_vid);
	return vlan && (vlan->learning & vlan->forwarding &
			BIT(entry->destination));
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
		if (fe_switch_domain_key(sw, &entry) ||
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
		if (fe_switch_domain_key(sw, &entry))
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
		if (fe_switch_domain_key(sw, &entry))
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
		ret = fe_mdb_withdraw(sw->fe);
	if (!ret)
		ret = fe_switch_hw_restore(sw->fe, &sw->hw);
	/* Both direct DFT and precise classifier consumers have disappeared.
	 * Retiring their aggregate active refs does not recycle published MCE
	 * rows/tokens or assert that old hardware/stack packets have drained. */
	if (!ret)
		ret = fe_mcast_retire_all(sw->fe);
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

static bool fe_switch_request_current(struct rtl_fe *fe, bool requested)
{
	struct rtl_fe_bridge *sw = fe->bridge;

	/* Only a completely committed matching generation is a cheap repeat.
	 * error==0 alone is insufficient: policy quiescence and a worker between
	 * snapshots can leave a clean-looking but unpublished or retained owner.
	 * Capability/conflict fallback deliberately remains explicitly retryable.
	 */
	if (!sw || sw->requested != requested || sw->stopping || sw->replaying ||
	    sw->error || sw->replay_error || fe->error || fe->pending_withdrawals ||
	    fe->shutting_down ||
	    !fe->engine_ready || !sw->guard.registered ||
	    !sw->route_generation_valid || rtl9617c_switch_guard_blocked(&sw->guard) ||
	    sw->route_generation != rtl9617c_switch_guard_generation(&sw->guard))
		return false;
	if (requested)
		return READ_ONCE(sw->active) && sw->hw.prepared &&
		       sw->hw.globals_owned && sw->domain_owned && sw->native_mask &&
		       sw->native_mask == READ_ONCE(sw->offloaded);
	/* unoffload drops the FE mutex while holding RTNL. Its counts only
	 * move towards zero, and its worker still owns the pending rebuild. */
	return !READ_ONCE(sw->active) && !sw->native_mask && !READ_ONCE(sw->offloaded) &&
	       !sw->domain_owned && !sw->hw.globals_owned && !sw->hw.prepared &&
	       !sw->hw.count && !READ_ONCE(sw->learned_count) &&
	       !READ_ONCE(sw->pending_count) && !READ_ONCE(sw->published_count);
}

static int fe_switch_request_locked(struct rtl_fe *fe, bool requested)
{
	int ret = 0;

	if (!fe->bridge)
		return -EOPNOTSUPP;
	if (fe_switch_request_current(fe, requested))
		return 0;
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
	plan->software_policy = rtl9617c_switch_net_has_ppp_policy(&init_net);
	memset(sw->ports, 0, sizeof(sw->ports));
	sw->master = NULL;
	sw->route_mask = 0;
	list_for_each_entry(port, &sw->fe->ports, list) {
		if (!port->retired &&
		    port->netdev->reg_state == NETREG_REGISTERED &&
		    rtl9617c_switch_device_has_policy(port->netdev))
			plan->software_policy = true;
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

#include "rtl9617c-fe-switch-vlan.h"

/* Replay is synchronous and supplies our non-NULL ctx. Ordinary FDB events
 * never program a table in atomic context; they invalidate the snapshot.
 */
static int fe_switch_replay_fdb(struct rtl_fe_bridge *sw,
			       const struct switchdev_notifier_fdb_info *info)
{
	struct rtl_l2_fdb_entry entry = { 0 }, previous;
	unsigned int words[RTL_L2_FDB_WORDS], i;
	int port = fe_switch_port_index(sw, info->info.dev);
	bool trap;

	if ((!sw->vlan_domain && info->vid) ||
	    switchdev_fdb_is_dynamically_learned(info))
		return 0;
	if (sw->vlan_domain && !fe_switch_vlan_replay_member(sw, info, port))
		return 0;
	if (info->locked || (!info->is_local && port < 0) ||
	    !is_valid_ether_addr(info->addr))
		return -EOPNOTSUPP;
	/* Omitting an offline/STP-blocked static destination would leave its
	 * MAC free for hardware SA learning on another, forwarding port. The
	 * next DA lookup could then bypass Linux's sticky destination policy.
	 * Protect the key with a static CPU trap instead: do not forward to an
	 * excluded physical egress, and do not send this bridged fallback into
	 * L3 connector25 even when ordinary local MACs use that connector.
	 */
	trap = !info->is_local && !(sw->replay_ports & BIT(port));
	ether_addr_copy(entry.mac, info->addr);
	entry.key_vid = info->vid;
	entry.is_static = 1;
	entry.valid = 1;
	entry.sa_permit = entry.da_permit = 1;
	entry.destination = info->is_local ? sw->local_target :
		trap ? 16 : (unsigned int)port;
	if (rtl_l2_fdb_encode(words, &entry))
		return -EINVAL;
	/* Replay covers the entire bridge for each port. Deduplicate keys, not
	 * destination, so moving a static entry cannot leave two owners behind.
	 */
	for (i = 0; i < sw->rule_count; i++) {
		rtl_l2_fdb_decode(sw->rules[i], &previous);
		if (previous.key_vid == entry.key_vid &&
		    ether_addr_equal(previous.mac, entry.mac))
			break;
	}
	if (i == RTL_L2_FDB_ENTRIES)
		return -ENOSPC;
	memcpy(sw->rules[i], words, sizeof(words));
	if (trap)
		sw->replay_traps[i / 32] |= BIT(i % 32);
	else
		sw->replay_traps[i / 32] &= ~BIT(i % 32);
	if (i == sw->rule_count)
		WRITE_ONCE(sw->rule_count, sw->rule_count + 1);
	return 0;
}

/* Stage under FE mutex before releasing it for bridge feedback. A concurrent
 * mode-disable may restore hardware and reuse rules[] while feedback runs;
 * it cannot overwrite this RTNL-owned, independently allocated journal. */
static void fe_switch_static_stage(struct rtl_fe_bridge *sw)
{
	struct rtl_l2_fdb_entry entry;
	unsigned int i, count = 0;

	for (i = 0; i < sw->rule_count; i++) {
		/* Trap-only protection does not implement the configured output.
		 * Leave that Linux FDB entry software-owned and unoffloaded. */
		if (sw->replay_traps[i / 32] & BIT(i % 32))
			continue;
		rtl_l2_fdb_decode(sw->rules[i], &entry);
		ether_addr_copy(sw->published[count].address, entry.mac);
		sw->published[count].destination = entry.destination;
		sw->published[count].vid = entry.key_vid;
		sw->published[count].cookie = 0;
		count++;
	}
	WRITE_ONCE(sw->published_count, count);
}

/* RTNL, but not FE mutex. The bridge serializes with its FDB hash lock and
 * the same generation gate as admission. It will not claim another owner's
 * flag, a replaced key, a movable static entry, or a stale policy epoch. */
static int fe_switch_static_publish(struct rtl_fe_bridge *sw, u64 generation)
{
	unsigned int i;
	int ret;

	for (i = 0; i < sw->published_count; i++) {
		struct fe_switch_published *row = &sw->published[i];
		struct net_device *master = fe_switch_bridge_for_vid(sw, row->vid);
		bool local = row->destination >= FE_LAN_PORTS;
		struct net_device *dev = local ? NULL : sw->ports[row->destination];

		if (!master || (!local && !dev))
			return -ENODEV;
		ret = br_rtl9617c_fdb_offload(master, dev, row->address, row->vid,
					   local, &sw->guard, generation, &row->cookie);
		if (ret)
			return ret;
	}
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
	    !fe_switch_is_master(sw, info->dev))
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
	    fe_switch_is_master(sw, info->dev))
		fe_switch_queue(sw);
	/* Notification receipt is not an offload acknowledgment. VID/MDB
	 * snapshots, retained hardware ownership and epoch publication are
	 * validated by the worker; unsupported objects keep the CPU path.
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
		ret = br_rtl9617c_fdb_learn_vid(dev, entry->address, entry->vid,
					      &sw->guard, generation);
		if (ret)
			return ret;
		WRITE_ONCE(sw->learned_adds, sw->learned_adds + 1);
	} else if (br_rtl9617c_fdb_forget_vid(dev, entry->address, entry->vid)) {
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

	for (i = 0; i < sw->published_count; i++) {
		struct fe_switch_published *row = &sw->published[i];
		struct net_device *master = fe_switch_bridge_for_vid(sw, row->vid);

		if (master && row->cookie)
			br_rtl9617c_fdb_unoffload(master, row->address, row->vid,
						 &sw->guard, row->cookie);
	}
	WRITE_ONCE(sw->published_count, 0);
	for (i = 0; i < sw->learned_count; i++)
		fe_switch_feedback(sw, &sw->learned[i], false, 0);
	WRITE_ONCE(sw->learned_count, 0);
	/* A later feedback failure must not orphan the successful prefix of
	 * a scan. Such rows are not yet in the committed learned[] snapshot.
	 */
	for (i = 0; i < sw->pending_count; i++)
		fe_switch_feedback(sw, &sw->next[i], false, 0);
	WRITE_ONCE(sw->pending_count, 0);
	fe_switch_scan_reset(sw);
	for (i = 0; i < FE_LAN_PORTS; i++) {
		if (!(sw->offloaded & BIT(i)))
			continue;
		if (sw->ports[i] && netif_is_bridge_port(sw->ports[i]))
			switchdev_bridge_port_unoffload(sw->ports[i], sw,
				&sw->atomic_nb, &sw->blocking_nb);
	}
	WRITE_ONCE(sw->offloaded, 0);
}

static int fe_switch_netdev_event(struct notifier_block *nb,
				 unsigned long event, void *pointer)
{
	struct rtl_fe_bridge *sw = container_of(nb, struct rtl_fe_bridge, netdev_nb);
	struct net_device *dev = netdev_notifier_info_to_dev(pointer);
	struct netdev_notifier_changeupper_info *upper = pointer;
	bool detaching, native;
	int port, ret = 0;

	if (READ_ONCE(sw->stopping))
		return NOTIFY_DONE;
	port = fe_switch_port_index(sw, dev);
	native = port >= 0 || fe_switch_is_master(sw, dev);
	/* Routing also owns PON logical netdevices, which are deliberately not
	 * native LAN bridge ports. Their carrier/address/MTU/upper changes must
	 * invalidate the route generation too, including linkwatch events that
	 * do not enter a bridge callback. Keep the ownership test identity-only:
	 * rtl_fe_remove_port() clears its entry before releasing that owner.
	 */
	if (!native && !fe_switch_owns_device(sw, dev))
		return NOTIFY_DONE;
	detaching = event == NETDEV_UNREGISTER ||
		(event == NETDEV_PRECHANGEUPPER && !upper->linking);
	if (native && detaching) {
		/* PRECHANGEUPPER still has a live br_port for unoffload. The core
		 * pre-publication gate has already closed ingress; restore before
		 * borrowing pointers can end or the netdevice can be freed.
		 */
		mutex_lock(&sw->fe->lock);
		ret = fe_switch_quiesce_locked(sw->fe);
		mutex_unlock(&sw->fe->lock);
		fe_switch_unoffload(sw);
		if (event == NETDEV_UNREGISTER) {
			unsigned int i;

			if (port >= 0)
				WRITE_ONCE(sw->ports[port], NULL);
			if (dev == sw->master)
				WRITE_ONCE(sw->master, NULL);
			for (i = 0; i < FE_LAN_PORTS; i++)
				if (dev == sw->masters[i])
					WRITE_ONCE(sw->masters[i], NULL);
		}
	}
	switch (event) {
	case NETDEV_PRECHANGEUPPER:
		if (upper->linking)
			break;
		fallthrough;
	case NETDEV_UP:
	/* __dev_close_many() sends this before clearing RUNNING and before
	 * ndo_stop disables the MAC. Do not leave other ports forwarding to an
	 * output until the later NETDEV_DOWN notification. */
	case NETDEV_GOING_DOWN:
	case NETDEV_DOWN:
	case NETDEV_CHANGE:
	case NETDEV_CHANGEADDR:
	case NETDEV_CHANGEMTU:
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
	struct rtl_mcast_groups groups;
	unsigned long age_ticks, seconds;
	unsigned int i, mdb_ports;
	u32 native_ports;
	u64 generation;
	int ret = 0;
	bool native = false;

	rtnl_lock();
	mutex_lock(&fe->lock);
	if (sw->stopping || fe->shutting_down)
		goto unlock;
	/* Rebuild can quiesce/re-arm without changing the policy generation.
	 * Never resume a partial physical scan across that table replacement.
	 */
	fe_switch_scan_reset(sw);
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
	sw->reason = fe_switch_vlan_snapshot(sw, &plan, sw->reason);
	sw->route_policy_allowed =
		fe_switch_route_plan_validate(&plan) == FE_SWITCH_OK;
	sw->local_target = sw->route_policy_allowed &&
		fe->enabled && fe->prepared ? 25 : 16;
	/* A bridge port may be blocked or have software-only policy even when
	 * native switching is not requested. Do not resurrect old L3 rules past
	 * that policy merely because native-L2 eligibility failed.
	 */
	if (!sw->route_policy_allowed) {
		sw->route_mask = 0;
		/* Native learning-off/isolation and a forwarding STP subset do
		 * not authorize the L3 engine. Keep both its ingress profiles on
		 * the verified CPU gate, including PON, while native L2 runs. */
		if (sw->reason != FE_SWITCH_OK || !sw->requested)
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
	ret = fe_switch_age_ticks(sw, &age_ticks);
	/* Read the actual FDB hold_time in jiffies, including topology-change
	 * forward_delay. Hardware exposes whole 19-bit seconds. In particular,
	 * never round a positive sub-second policy into no-learning zero.
	 */
	if (ret || age_ticks % HZ || age_ticks / HZ > GENMASK(18, 0)) {
		/* This timer belongs to autonomous L2 learning only. The earlier
		 * route-policy checks still govern independently authorized L3
		 * flows, just as for an unsupported native VLAN/bridge topology.
		 */
		sw->reason = FE_SWITCH_AGING_UNSUPPORTED;
		ret = 0;
		goto arm;
	}
	seconds = age_ticks / HZ;
	native_ports = fe_switch_forwarding_ports(&plan);
	sw->rule_count = 0;
	sw->replay_error = 0;
	sw->replay_ports = native_ports;
	sw->replaying = true;
	/* switchdev's replay invokes our supplied notifier synchronously with
	 * ctx=sw. No live packet callback is permitted to append a static rule.
	 * Release the FE mutex while switchdev drains deferred control work.
	 */
	mutex_unlock(&fe->lock);
	for (i = 0; i < FE_LAN_PORTS; i++) {
		if (!(native_ports & BIT(i)))
			continue;
		ret = switchdev_bridge_port_offload(sw->ports[i], sw->ports[i], sw,
			&sw->atomic_nb, &sw->blocking_nb, false, NULL);
		if (ret)
			break;
		WRITE_ONCE(sw->offloaded, READ_ONCE(sw->offloaded) | BIT(i));
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
	sw->hw.vlan_plan = sw->vlan_domain ? &sw->vlans : NULL;
	ret = fe_switch_hw_prepare(fe, &sw->hw, native_ports, seconds,
				   br_multicast_enabled(sw->master),
				   sw->route_policy_allowed);
	if (ret) {
		if (ret == -EOPNOTSUPP)
			sw->reason = FE_SWITCH_HW_UNSUPPORTED;
		goto failure;
	}
	ret = fe_switch_hw_port_policy(fe, &sw->hw,
		/* Linux hold_time()==0 means always flood dynamic destinations:
		 * br_fdb_update() must not learn. Static/local keys remain useful,
		 * so retain exact unicast offload with every native SA learner off. */
		seconds ? fe_switch_flag_ports(&plan, native_ports, BR_LEARNING) : 0,
		fe_switch_flag_ports(&plan, native_ports, BR_ISOLATED));
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
	/* The first MCE contract is the unchanged SVL/VID0 domain. Tagged
	 * VLANs still need a separate proof of late MCE VE/ELPB consumption;
	 * a local parser drain is not permission to repurpose those rows. */
	if (!sw->vlan_domain) {
		ret = fe_mcast_prepare_bum(fe, &sw->guard, generation, sw->master,
					   sw->ports, plan.flags, native_ports, &groups);
		if (!ret)
			ret = fe_switch_hw_mcast_groups(fe, &sw->hw, &groups);
		else if (ret == -EOPNOTSUPP || ret == -ENOSPC)
			ret = 0; /* Keep exact unicast and the existing CPU BUM path. */
		if (ret)
			goto failure;
		/* Until an independently gated classifier-only profile exists,
		 * exact MDB uses the already-authorized routed engine. Native L2
		 * isolation/learning-off may not reopen that engine by implication. */
		if (sw->route_policy_allowed && fe->enabled && fe->prepared) {
			mdb_ports = 0;
			ret = fe_mdb_prepare(fe, &sw->guard, generation, sw->master,
					     sw->ports, plan.flags, native_ports, &mdb_ports);
			if (!ret)
				ret = fe_switch_hw_mdb_steer(fe, &sw->hw, mdb_ports);
			else if (ret == -EOPNOTSUPP || ret == -ENOSPC)
				ret = 0; /* Helper returns clean fallback, never a live prefix. */
			if (ret)
				goto failure;
		}
	}
	for (i = 0; i < sw->rule_count; i++) {
		ret = fe_switch_fdb_write(sw, RTL_L2_FDB_APPEND, sw->rules[i]);
		if (ret)
			goto failure;
	}
	fe_switch_static_stage(sw);
	sw->native_mask = native_ports;
	sw->route_mask &= ~sw->native_mask;
	native = true;
arm:
	if (!rtl9617c_switch_guard_try_arm(&sw->guard, generation)) {
		sw->reason = FE_SWITCH_GUARDED;
		ret = -EAGAIN;
		goto failure;
	}
	if (native) {
		mutex_unlock(&fe->lock);
		ret = fe_switch_static_publish(sw, generation);
		mutex_lock(&fe->lock);
		if (!ret && (!sw->active || generation !=
		    rtl9617c_switch_guard_generation(&sw->guard)))
			ret = -EAGAIN;
		if (ret)
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
		     sw->reason == FE_SWITCH_HW_UNSUPPORTED) &&
	    !rtl9617c_switch_guard_try_arm(&sw->guard, generation)) {
		/* A supported route-only fallback is not a successful fallback
		 * until its gate actually arms. The same false return can mean a
		 * newer policy epoch or an MMIO failure; keep it retryable instead
		 * of leaving a permanent capability/conflict diagnosis which a
		 * repeated mode write would correctly otherwise treat as a noop.
		 */
		ret = sw->error = -EAGAIN;
		sw->reason = FE_SWITCH_GUARDED;
	}
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

	if (left->vid != right->vid)
		return left->vid < right->vid ? -1 : 1;
	return memcmp(left->address, right->address, ETH_ALEN);
}

static bool fe_switch_scan_slice_done(unsigned int operations, u64 started)
{
	return operations >= FE_SWITCH_SCAN_BUDGET ||
	       (operations && ktime_get_ns() - started >=
		FE_SWITCH_SCAN_SLICE_MS * NSEC_PER_MSEC);
}

static void fe_switch_scan(struct work_struct *work)
{
	struct rtl_fe_bridge *sw = container_of(to_delayed_work(work),
		struct rtl_fe_bridge, scan_work);
	struct rtl_dq_io io = fe_io(sw->fe);
	struct rtl_l2_fdb_result row;
	struct rtl_l2_fdb_entry entry;
	struct fe_switch_learned *swap;
	unsigned int operations = 0, cursor;
	u64 generation, started;
	int ret = 0;

	rtnl_lock();
	mutex_lock(&sw->fe->lock);
	started = ktime_get_ns();
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
	if (sw->scan_running && sw->scan_generation != generation) {
		/* No old next[] prefix may be overwritten before its withdrawal.
		 * Normally the invalidation/rebuild has already gated and reset
		 * us; also fail closed if a stale slice ever finds itself armed.
		 */
		if (sw->pending_count) {
			ret = -EAGAIN;
			goto failure;
		}
		fe_switch_scan_reset(sw);
	}
	if (!sw->scan_running) {
		sw->scan_generation = generation;
		sw->scan_running = true;
	}
	if (!sw->scan_complete) {
		while (sw->scan_start < RTL_L2_FDB_ENTRIES) {
			if (fe_switch_scan_slice_done(operations, started))
				goto resume;
			ret = rtl_l2_fdb_scan(&io, sw->scan_start, &row);
			operations++;
			if (ret < 0)
				goto failure;
			if (!ret)
				break;
			rtl_l2_fdb_decode(row.words, &entry);
			if (fe_switch_domain_learned(sw, &entry,
					sw->native_mask & sw->hw.learning_mask)) {
				ether_addr_copy(sw->next[sw->scan_count].address, entry.mac);
				sw->next[sw->scan_count].vid = entry.key_vid;
				sw->next[sw->scan_count++].port = entry.destination;
			}
			sw->scan_start = row.index + 1;
		}
		if (!sw->active || generation !=
		    rtl9617c_switch_guard_generation(&sw->guard))
			goto out;
		/* Sorting touches only this worker's MAC snapshot. RTNL excludes
		 * rebuild/unoffload and stop waits for this work before freeing it;
		 * do not block unrelated FE flow/stat operations on that CPU work.
		 */
		mutex_unlock(&sw->fe->lock);
		sort(sw->next, sw->scan_count, sizeof(*sw->next),
		     fe_switch_learned_compare, NULL);
		mutex_lock(&sw->fe->lock);
		if (sw->stopping || sw->fe->shutting_down || !sw->active ||
		    generation != rtl9617c_switch_guard_generation(&sw->guard))
			goto out;
		for (cursor = 1; cursor < sw->scan_count; cursor++) {
			if (!fe_switch_learned_compare(&sw->next[cursor - 1],
						       &sw->next[cursor])) {
				/* A moving key observed twice is not a coherent new
				 * owner. Keep the last complete mirror and restart
				 * after learning settles; never publish this prefix.
				 */
				fe_switch_scan_reset(sw);
				mod_delayed_work(system_long_wq, &sw->scan_work, HZ);
				goto out;
			}
		}
		sw->scan_complete = true;
	}
	/* Complete snapshot only. Delete absent KEYS before adding moves:
	 * br_fdb_external_learn_del() ignores the old port and deletes by key,
	 * so delete-after-add would erase a newly moved entry on its new port.
	 */
	if (!sw->scan_removed) {
		while (sw->scan_old < sw->learned_count) {
			if (fe_switch_scan_slice_done(operations, started))
				goto resume;
			operations++;
			ret = sw->scan_cursor < sw->scan_count ?
				fe_switch_learned_compare(&sw->next[sw->scan_cursor],
							 &sw->learned[sw->scan_old]) : 1;
			if (ret < 0) {
				sw->scan_cursor++;
				continue;
			}
			if (ret)
				fe_switch_feedback(sw, &sw->learned[sw->scan_old], false, 0);
			sw->scan_old++;
		}
		sw->scan_removed = true;
		sw->scan_cursor = 0;
	}
	while (sw->scan_cursor < sw->scan_count) {
		if (fe_switch_scan_slice_done(operations, started))
			goto resume;
		ret = fe_switch_feedback(sw, &sw->next[sw->scan_cursor], true, generation);
		operations++;
		if (ret)
			goto failure;
		sw->pending_count = ++sw->scan_cursor;
	}
	/* An epoch can close immediately after the final feedback (or during a
	 * delete-only round). Retain that prefix for withdrawal, not as a newly
	 * committed snapshot of the replacement policy.
	 */
	if (!sw->active || generation !=
	    rtl9617c_switch_guard_generation(&sw->guard))
		goto out;
	swap = sw->learned;
	sw->learned = sw->next;
	sw->next = swap;
	sw->learned_count = sw->scan_count;
	sw->pending_count = 0;
	fe_switch_scan_reset(sw);
	sw->polls++;
	mod_delayed_work(system_long_wq, &sw->scan_work, HZ);
	goto out;
resume:
	if (sw->active && generation == rtl9617c_switch_guard_generation(&sw->guard))
		/* Every slice advances at least one bounded operation. Requeue
		 * after dropping the locks without adding one HZ=100 tick per
		 * batch (over a second of artificial full-table mirror latency).
		 */
		mod_delayed_work(system_long_wq, &sw->scan_work, 0);
	goto out;
failure:
	sw->error = ret;
	sw->scan_errors++;
	rtl9617c_switch_guard_invalidate(&sw->guard);
out:
	if (!sw->active || sw->stopping || sw->fe->shutting_down)
		fe_switch_scan_reset(sw);
	mutex_unlock(&sw->fe->lock);
	rtnl_unlock();
}

static struct rtl_fe_bridge *fe_bridge_start(struct rtl_fe *fe)
{
	struct rtl_fe_bridge *sw;
	unsigned short *row_index = NULL;
	unsigned int index_count = rtl_l2_journal_index_count();
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
	sw->published = kvcalloc(RTL_L2_FDB_ENTRIES, sizeof(*sw->published), GFP_KERNEL);
	sw->learned = kvcalloc(RTL_L2_FDB_ENTRIES, sizeof(*sw->learned), GFP_KERNEL);
	sw->next = kvcalloc(RTL_L2_FDB_ENTRIES, sizeof(*sw->next), GFP_KERNEL);
	sw->hw.rows = kvcalloc(FE_SW_SNAPSHOTS, sizeof(*sw->hw.rows), GFP_KERNEL);
	row_index = kvcalloc(index_count, sizeof(*row_index), GFP_KERNEL);
	if (!sw->rules || !sw->published || !sw->learned || !sw->next ||
	    !sw->hw.rows || !row_index) {
		ret = -ENOMEM;
		goto fail;
	}
	ret = rtl_l2_journal_init(&sw->hw.journal, row_index, index_count,
				  FE_SW_SNAPSHOTS);
	if (ret)
		goto fail;
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
	if (!sw->hw.journal.row_index)
		kvfree(row_index);
	kvfree(sw->rules);
	kvfree(sw->published);
	kvfree(sw->learned);
	kvfree(sw->next);
	kvfree(sw->hw.rows);
	kvfree(sw->hw.journal.row_index);
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
	unsigned int port;
	int ret;

	if (!sw)
		return 0;
	/* The notifier keeps borrowed bridge/port pointers live until RTNL is
	 * acquired. Do not stop that notifier first: a simultaneous unregister
	 * could otherwise destroy the bridge FDB before cookie withdrawal.
	 * Queued workers take RTNL too and will observe stopping after release.
	 */
	rtnl_lock();
	WRITE_ONCE(sw->stopping, true);
	mutex_lock(&sw->fe->lock);
	fe_switch_gate(sw);
	ret = fe_switch_restore_locked(sw);
	mutex_unlock(&sw->fe->lock);
	fe_switch_unoffload(sw);
	for (port = 0; port < FE_LAN_PORTS; port++) {
		WRITE_ONCE(sw->ports[port], NULL);
		WRITE_ONCE(sw->masters[port], NULL);
	}
	WRITE_ONCE(sw->master, NULL);
	rtnl_unlock();
	/* Drain callbacks/work only outside RTNL and the FE mutex. Even an
	 * uncertain hardware restore retains no borrowed device pointer: retry
	 * needs the hardware journal and FDB keys, not a torn-down bridge.
	 */
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
	if (ret)
		return ret;
	kvfree(sw->rules);
	kvfree(sw->published);
	kvfree(sw->learned);
	kvfree(sw->next);
	kvfree(sw->hw.rows);
	kvfree(sw->hw.journal.row_index);
	kfree(sw);
	return 0;
}

static ssize_t fe_bridge_stats(struct rtl_fe_bridge *sw,
			       char *buffer, size_t bytes)
{
	const struct fe_switch_hw_observed *observed;
	unsigned int port, bum = 0;
	ssize_t length;

	if (!sw)
		return scnprintf(buffer, bytes, "l2_supported=0 l2_requested=0 l2_active=0\n");
	if (READ_ONCE(sw->active))
		for (port = 0; port < FE_LAN_PORTS; port++)
			bum |= sw->hw.bum_enabled[port];
	length = scnprintf(buffer, bytes,
		"l2_supported=1 l2_requested=%u l2_active=%u l2_reason=%u "
		"l2_hw_reason=%u l2_hw_reason_name=%s "
		"l2_error=%d l2_ports=%#x l2_route_ports=%#x l2_domain_owned=%u "
		"l2_flow_allowed=%u l2_route_policy_allowed=%u "
		"l2_static=%u l2_static_published=%u l2_learned=%u l2_rebuilds=%llu l2_polls=%llu "
		"l2_learn_adds=%llu l2_learn_deletes=%llu l2_scan_errors=%llu "
		"l2_bum_hardware=%u l2_bum_classes=%#x l2_vlan_hardware=0 l2_mdb_hardware=%u "
		"l2_multibridge_hardware=0 l2_local_target=%u l2_rx_gate_verified=%u "
		"l2_learning_ports=%#x l2_isolated_ports=%#x "
		"l2_journal_used=%u l2_journal_capacity=%u "
		"l2_journal_quarantined=%u l2_retries=%u\n",
		sw->requested, READ_ONCE(sw->active), sw->reason,
		sw->hw.reason, fe_switch_hw_reason_name(&sw->hw), sw->error, sw->native_mask,
		READ_ONCE(sw->armed_route_mask), sw->domain_owned,
		READ_ONCE(sw->flow_allowed), sw->route_policy_allowed,
		READ_ONCE(sw->rule_count),
		READ_ONCE(sw->published_count),
		READ_ONCE(sw->learned_count), sw->rebuilds, sw->polls,
		READ_ONCE(sw->learned_adds), READ_ONCE(sw->learned_deletes),
		sw->scan_errors, !!bum, bum, !!(READ_ONCE(sw->active) && sw->hw.mdb_ports),
		sw->local_target, READ_ONCE(sw->hw.rx_gate_verified),
		sw->hw.learning_mask,
		sw->hw.isolated_mask, sw->hw.count, sw->hw.journal.capacity,
		sw->hw.journal.quarantined, sw->retry_count);
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
static bool fe_switch_needs_recovery(struct rtl_fe *fe)
{
	return fe->enabled && !READ_ONCE(fe->route_admitted);
}
static void fe_switch_track_port_locked(struct rtl_fe *fe,
	struct net_device *dev, unsigned int destination, bool adding) { }
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
	/* Close existing RX25 as well as preserving an earlier port flush.
	 * A failed withdrawal can still own a cached route: prove the L3
	 * selection BEFORE opening RX25. Pending owners need CPU profile1,
	 * otherwise route0; failed readback leaves every LAN on CPU16. */
	fe_switch_quiesce_locked(fe);
	if (!fe_route_arm(fe))
		return;
	for (port = 0; port < FE_LAN_PORTS; port++) {
		value = fe_read(fe, FE_LAN_RX_CTRL(port));
		fe_write(fe, FE_LAN_RX_CTRL(port),
			 (value & ~(0x3fU << 16)) | BIT(28) | (25U << 16));
	}
	fe_read(fe, FE_LAN_RX_CTRL(FE_LAN_PORTS - 1));
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
	/* Ordinary CPU traps are not proof of autonomous forwarding: Header-A
	 * BC/MC bits alone must never set offload_fwd_mark. MCE copies are handled
	 * before demux by rtl_fe_mcast_rx(), using an immutable token plus an skb
	 * extension whose epoch is revalidated by the bridge before delivery.
	 * Leave both kinds' metadata intact here; never manufacture provenance.
	 */
	(void)fe;
	(void)skb;
	(void)source;
	(void)header0;
	(void)header1;
}

