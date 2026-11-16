/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTL9617C_FE_MDB_H
#define RTL9617C_FE_MDB_H

#include <linux/rtl9617c-mdb.h>
#include <linux/vmalloc.h>
#include "rtl9617c-mdb-offload.h"

/* The bridge is authoritative. This adapter copies one bounded, coherent
 * snapshot, validates the COMPLETE lookup domain and only then creates exact
 * CLS keys and immutable MCE dependencies. It never runs an IGMP/MLD state
 * machine or substitutes an Ethernet multicast alias for an IP address.
 *
 * Included after fe-switch.h: RTNL and fe->lock protect actual topology and
 * the one FE/CLS owner. Preparation happens with every LAN/L3 gate closed;
 * the worker alone publishes CF steering and finally arms the same epoch.
 */
#define FE_MDB_RECORDS 256U
#define FE_MDB_WORK_BUDGET 4096U

enum fe_mdb_reason {
	FE_MDB_OK, FE_MDB_COLD_CONTRACT, FE_MDB_PROFILE, FE_MDB_TOPOLOGY,
	FE_MDB_GATE, FE_MDB_HARDWARE, FE_MDB_SNAPSHOT, FE_MDB_MEMBERSHIP,
	FE_MDB_QUERIER, FE_MDB_OVERLAP, FE_MDB_CAPACITY, FE_MDB_EPOCH,
	FE_MDB_TRANSACTION, FE_MDB_WITHDRAWAL, FE_MDB_RETIRED_EPOCH,
};

struct rtl_fe_mdb {
	struct rtl_mdb_tcam tcam;
	enum fe_mdb_reason reason;
	u64 generation, attempts, publications, withdrawals;
	unsigned int records, planned, steer_ports, bad_register, bad_value;
	bool window_retained;
	int error;
};

static const char *fe_mdb_reason_name(enum fe_mdb_reason reason)
{
	static const char * const names[] = {
		"ok", "cold-mce-contract", "owned-classifier-profile", "topology",
		"ingress-gate", "hardware-readback", "snapshot", "membership",
		"time-dependent-querier", "asm-ssm-overlap", "capacity", "epoch",
		"transaction", "withdrawal", "pre-cls-retirement-unproven",
	};

	return (unsigned int)reason < ARRAY_SIZE(names) ? names[reason] : "unknown";
}

static bool fe_mdb_retained(struct rtl_fe *fe)
{
	/* Empty keys are not an L3/AXI/MCE drain. A once-exposed result index
	 * cannot be reused, nor its snapshot discarded on module remove. */
	return fe->mdb && (fe->mdb->tcam.exposed || fe->mdb->tcam.prepared ||
		fe->mdb->tcam.poisoned || fe->mdb->tcam.active ||
		fe->mdb->tcam.guard_exposed || fe->mdb->window_retained);
}

static void fe_mdb_free(struct rtl_fe *fe)
{
	if (fe_mdb_retained(fe))
		return;
	kvfree(fe->mdb);
	fe->mdb = NULL;
}

static ssize_t fe_mdb_stats(struct rtl_fe *fe, char *buffer, size_t bytes)
{
	const struct rtl_fe_mdb *mdb = fe->mdb;

	if (!mdb)
		return scnprintf(buffer, bytes, "mdb_state=not-prepared\n");
	return scnprintf(buffer, bytes,
		"mdb_state=%s mdb_error=%d mdb_register=0x%x mdb_value=0x%x "
		"mdb_generation=%llu mdb_records=%u mdb_planned=%u "
		"mdb_active=%u mdb_used=%u mdb_exposed=%u mdb_guards=%u "
		"mdb_guard_exposed=%u mdb_window=%u mdb_steer=0x%x "
		"mdb_attempts=%llu mdb_publications=%llu mdb_withdrawals=%llu\n",
		fe_mdb_reason_name(mdb->reason), mdb->error,
		mdb->bad_register, mdb->bad_value,
		(unsigned long long)mdb->generation, mdb->records, mdb->planned,
		mdb->tcam.active, mdb->tcam.used, mdb->tcam.exposed,
		mdb->tcam.guards_ready, mdb->tcam.guard_exposed, mdb->window_retained,
		mdb->steer_ports, (unsigned long long)mdb->attempts,
		(unsigned long long)mdb->publications,
		(unsigned long long)mdb->withdrawals);
}

#if IS_REACHABLE(CONFIG_BRIDGE) && IS_ENABLED(CONFIG_NET_SWITCHDEV) && \
	IS_ENABLED(CONFIG_RTL9617C_SWITCH_GUARD)

struct fe_mdb_entry {
	struct rtl_mdb_rule key;
	unsigned int egress;
};

struct fe_mdb_plan {
	struct br_rtl9617c_mdb_snapshot snapshot;
	struct br_rtl9617c_mdb_record records[FE_MDB_RECORDS];
	struct fe_mdb_entry entries[RTL_MDB_TCAM_SLOTS];
	struct rtl_mdb_rule rules[RTL_MDB_TCAM_SLOTS];
	unsigned int egress[RTL_MDB_TCAM_SLOTS];
	unsigned short record_entry[FE_MDB_RECORDS]; /* entry index + 1 */
	unsigned int count, entry_count, rule_count, router[2];
};

static int fe_mdb_fail(struct rtl_fe *fe, enum fe_mdb_reason reason, int error)
{
	fe->mdb->reason = reason;
	fe->mdb->error = error;
	return error;
}

static int fe_mdb_epoch(struct rtl9617c_switch_guard *guard, u64 generation)
{
	return guard->registered && guard->identity && !READ_ONCE(guard->armed) &&
		!rtl9617c_switch_guard_blocked(guard) &&
		rtl9617c_switch_guard_generation(guard) == generation ? 0 : -EAGAIN;
}

static int fe_mdb_capture(void *priv, const struct br_rtl9617c_mdb_record *row)
{
	struct fe_mdb_plan *plan = priv;

	/* Called with the bridge multicast lock held: bounded copy ONLY. */
	if (plan->count == FE_MDB_RECORDS)
		return -ENOSPC;
	plan->records[plan->count++] = *row;
	return 0;
}

static int fe_mdb_port_index(struct net_device *const ports[5],
			     const struct net_device *port)
{
	unsigned int i;

	for (i = 0; i < 5; i++)
		if (port && ports[i] == port)
			return i;
	return -1;
}

static int fe_mdb_topology(struct rtl_fe *fe,
		struct rtl9617c_switch_guard *guard,
		const struct net_device *master, struct net_device *const ports[5],
		const unsigned long flags[5], unsigned int forwarding)
{
	struct rtl_fe_bridge *sw = fe->bridge;
	struct fe_switch_plan policy = { .ports = forwarding };
	struct net_device *lower;
	struct list_head *iter;
	unsigned int i, bit;

	if (!sw || guard != &sw->guard || sw->master != master || sw->stopping ||
	    sw->vlan_domain || !sw->route_policy_allowed || !sw->hw.prepared ||
	    sw->hw.ports != forwarding || guard->net != dev_net(master) ||
	    !netif_running(master) || !netif_is_bridge_master(master) ||
	    !br_rtl9617c_l2_eligible(master) || br_vlan_enabled(master) ||
	    (master->flags & IFF_PROMISC))
		return -EOPNOTSUPP;
	netdev_for_each_lower_dev(sw->master, lower, iter)
		if (fe_mdb_port_index(ports, lower) < 0)
			return -EOPNOTSUPP;
	for (i = 0; i < 5; i++) {
		struct rtl_fe_port *port;
		unsigned long actual = 0;

		if (ports[i] != sw->ports[i])
			return -EAGAIN;
		if (!(forwarding & BIT(i)))
			continue;
		if (!ports[i] || guard->net != dev_net(ports[i]) ||
		    !netif_running(ports[i]) || !netif_carrier_ok(ports[i]) ||
		    netdev_master_upper_dev_get(ports[i]) != master ||
		    !br_rtl9617c_l2_port_eligible(ports[i]))
			return -EOPNOTSUPP;
		port = fe_port(fe, ports[i]);
		if (!port || port->source != i || port->destination != i)
			return -EOPNOTSUPP;
		for (bit = 0; bit <= 24; bit++)
			if (br_port_flag_is_set(ports[i], BIT(bit)))
				actual |= BIT(bit);
		if (actual != flags[i])
			return -EAGAIN;
		policy.flags[i] = actual;
		policy.state[i] = br_port_get_stp_state(ports[i]);
	}
	return fe_switch_route_plan_validate(&policy) == FE_SWITCH_OK ? 0 : -EOPNOTSUPP;
}

static int fe_mdb_register(struct rtl_fe *fe, unsigned int reg,
			   unsigned int mask, unsigned int expected)
{
	unsigned int value = fe_read(fe, reg);

	if (value != ~0U && (value & mask) == expected)
		return 0;
	fe->mdb->bad_register = reg;
	fe->mdb->bad_value = value;
	return value == ~0U ? -EIO : -EOPNOTSUPP;
}

static int fe_mdb_hardware(struct rtl_fe *fe)
{
	struct rtl_dq_io io = fe_io(fe);
	unsigned int lpb[3], expected[7], actual[7], i, type, row, word;
	int ret;

	/* These guards are FE-lifetime state, installed before the global
	 * my-MAC bypass is cleared, not only when a bridge asks for MDB. */
	ret = rtl_mdb_profile_check(&io, &fe->mdb->tcam);
	if (ret)
		return ret;

	/* Type0 must be able to win; my-MAC failure must not bypass CLS.
	 * Checking the live bytes is essential even with the frozen owner flag.
	 * LSPID mapping selects connector25 while preserving true LAN ingress. */
	ret = fe_mdb_register(fe, 0x3400,
		BIT(0) | BIT(2) | BIT(3) | BIT(10) | BIT(19) | BIT(20),
		BIT(2) | BIT(3) | BIT(19));
	if (!ret)
		ret = fe_mdb_register(fe, 0x3404, 0x03ffffffU,
			7U | (25U << 8) | (1U << 14) | (24U << 16) |
			(2U << 22) | (3U << 24));
	if (ret)
		return ret;
	for (i = 0; i < 2; i++) {
		rtl_fe_ingress_lpb(lpb, i ? 7 : 0, 16);
		rtl_fe_bits_set(lpb, 42, 4, 1);
		for (word = 0; word < 3; word++) {
			ret = fe_mdb_register(fe, 0x3414 + i * 12 + word * 4,
				word == 2 ? 0x3fffffffU : ~0U, lpb[word]);
			if (ret)
				return ret;
		}
		for (type = 0; type < 4; type++) {
			for (row = 0; row < 2; row++) {
				memset(expected, 0, sizeof(expected));
				if (!row)
					rtl_fe_classifier_default(expected, i, type, 1);
				ret = rtl_mdb_row_read(&io, 0x33b0, 0x33cc,
					fe_classifier_default_index(i, type, row), actual, 7);
				if (ret)
					return ret;
				for (word = 0; word < 7; word++) {
					if (actual[word] == expected[word])
						continue;
					fe->mdb->bad_register = 0x33cc - word * 4;
					fe->mdb->bad_value = actual[word];
					return -EOPNOTSUPP;
				}
			}
		}
	}
	return rtl_fe_pp_exceptions_check(&io, &fe->mdb->bad_register,
					 &fe->mdb->bad_value);
}

static int fe_mdb_key(const struct br_ip *key, struct rtl_mdb_rule *rule)
{
	unsigned int i, source = 0;

	memset(rule, 0, sizeof(*rule));
	rule->group = 1; /* validator placeholder, replaced by leased MCE group */
	rule->protocol = IPPROTO_UDP;
	rule->vid = key->vid;
	if (key->proto == htons(ETH_P_IP)) {
		rule->destination[0] = be32_to_cpu(key->dst.ip4);
		rule->source[0] = be32_to_cpu(key->src.ip4);
	} else if (key->proto == htons(ETH_P_IPV6)) {
#if IS_ENABLED(CONFIG_IPV6)
		rule->ipv6 = 1;
		for (i = 0; i < 4; i++) {
			rule->destination[i] = be32_to_cpu(key->dst.ip6.s6_addr32[i]);
			rule->source[i] = be32_to_cpu(key->src.ip6.s6_addr32[i]);
		}
#else
		return -EOPNOTSUPP;
#endif
	} else {
		return -EOPNOTSUPP;
	}
	for (i = 0; i < 4; i++)
		source |= rule->source[i];
	rule->source_specific = !!source;
	return rtl_mdb_rule_valid(rule);
}

static bool fe_mdb_key_equal(const struct rtl_mdb_rule *a,
			     const struct rtl_mdb_rule *b)
{
	return a->ipv6 == b->ipv6 && a->vid == b->vid &&
		a->source_specific == b->source_specific &&
		rtl_mdb_words_equal(a->source, b->source, 4) &&
		rtl_mdb_words_equal(a->destination, b->destination, 4);
}

static int fe_mdb_compile(struct rtl_fe *fe, struct fe_mdb_plan *plan,
		struct net_device *const ports[5], const unsigned long flags[5],
		unsigned int forwarding)
{
	struct br_rtl9617c_mdb_snapshot *snapshot = &plan->snapshot;
	unsigned int i, j, p, protocol;

	if (snapshot->record_count != plan->count || snapshot->vid ||
	    snapshot->vlan_filtering || snapshot->vlan_snooping ||
	    !snapshot->snooping || !snapshot->running || !snapshot->context_enabled)
		return fe_mdb_fail(fe, FE_MDB_SNAPSHOT, -EOPNOTSUPP);
	/* Validate every record, including empty or non-forwarding S,G entries.
	 * Silently omitting such a record could expose a broader *,G rule. */
	for (i = 0; i < plan->count; i++) {
		const struct br_rtl9617c_mdb_record *record = &plan->records[i];
		struct fe_mdb_entry *entry;
		struct rtl_mdb_rule key;
		const struct br_rtl9617c_mdb_family *family;
		unsigned int parent;
		int index, ret;

		if (record->id != i + 1)
			return fe_mdb_fail(fe, FE_MDB_SNAPSHOT, -EINVAL);
		if (record->type == BR_RTL9617C_MDB_ROUTER) {
			if (record->entry_id || record->port_id ||
			    record->key.vid || record->key.proto != record->router.proto ||
			    record->router.type != MDB_RTR_TYPE_PERM ||
			    record->router.timer.pending)
				return fe_mdb_fail(fe, FE_MDB_MEMBERSHIP, -EOPNOTSUPP);
			if (record->router.proto == htons(ETH_P_IP))
				p = 0;
			else if (record->router.proto == htons(ETH_P_IPV6))
				p = 1;
			else
				return fe_mdb_fail(fe, FE_MDB_MEMBERSHIP, -EOPNOTSUPP);
			index = fe_mdb_port_index(ports, record->dev);
			if (index < 0)
				return fe_mdb_fail(fe, FE_MDB_TOPOLOGY, -EOPNOTSUPP);
			plan->router[p] |= BIT(index);
			continue;
		}
		ret = fe_mdb_key(&record->key, &key);
		if (ret)
			return fe_mdb_fail(fe, FE_MDB_MEMBERSHIP, ret);
		if (record->type == BR_RTL9617C_MDB_ENTRY) {
			if (record->entry_id != record->id || record->port_id || record->dev ||
			    (record->entry.kind != BR_RTL9617C_MDB_STAR_G &&
			     record->entry.kind != BR_RTL9617C_MDB_SOURCE_G) ||
			    key.source_specific != (record->entry.kind == BR_RTL9617C_MDB_SOURCE_G))
				return fe_mdb_fail(fe, FE_MDB_SNAPSHOT, -EINVAL);
			family = key.ipv6 ? &snapshot->ip6 : &snapshot->ip4;
			/* Even a permanent IP MDB needs a querier. A pending=false
			 * remote timer is not a permanent router/querier certificate.
			 * CPU receives every copy and retains local host decisions. */
			if (!family->supported || !family->own_querier ||
			    !family->querier_present || family->querier_time_dependent ||
			    family->query_delay.pending || family->local_router_time_dependent ||
			    (family->version != (key.ipv6 ? 1 : 2) &&
			     family->version != (key.ipv6 ? 2 : 3)) ||
			    (key.source_specific && family->version != (key.ipv6 ? 2 : 3)))
				return fe_mdb_fail(fe, FE_MDB_QUERIER, -EOPNOTSUPP);
			if (plan->entry_count == RTL_MDB_TCAM_SLOTS)
				return fe_mdb_fail(fe, FE_MDB_CAPACITY, -ENOSPC);
			for (j = 0; j < plan->entry_count; j++) {
				if (rtl_mdb_rules_overlap(&plan->entries[j].key, &key))
					return fe_mdb_fail(fe, FE_MDB_OVERLAP, -EOPNOTSUPP);
			}
			plan->entries[plan->entry_count].key = key;
			plan->record_entry[i] = ++plan->entry_count;
			continue;
		}
		if (!record->entry_id || record->entry_id > i ||
		    plan->records[record->entry_id - 1].type != BR_RTL9617C_MDB_ENTRY)
			return fe_mdb_fail(fe, FE_MDB_SNAPSHOT, -EINVAL);
		parent = plan->record_entry[record->entry_id - 1];
		if (!parent || parent > plan->entry_count)
			return fe_mdb_fail(fe, FE_MDB_SNAPSHOT, -EINVAL);
		entry = &plan->entries[parent - 1];
		if (!fe_mdb_key_equal(&entry->key, &key))
			return fe_mdb_fail(fe, FE_MDB_SNAPSHOT, -EINVAL);
		if (record->type == BR_RTL9617C_MDB_PORT) {
			if (record->port_id != record->id || !record->port.permanent ||
			    record->port.timer.pending || record->port.mcast_to_unicast)
				return fe_mdb_fail(fe, FE_MDB_MEMBERSHIP, -EOPNOTSUPP);
			index = fe_mdb_port_index(ports, record->dev);
			if (index < 0)
				return fe_mdb_fail(fe, FE_MDB_TOPOLOGY, -EOPNOTSUPP);
			if ((forwarding & BIT(index)) &&
			    (record->port.flags != flags[index] ||
			     record->port.state != BR_STATE_FORWARDING))
				return fe_mdb_fail(fe, FE_MDB_EPOCH, -EAGAIN);
			if (record->port.forward)
				entry->egress |= BIT(index);
		} else if (record->type == BR_RTL9617C_MDB_SOURCE) {
			const struct br_rtl9617c_mdb_record *pg;

			if (!record->port_id || record->port_id > i)
				return fe_mdb_fail(fe, FE_MDB_SNAPSHOT, -EINVAL);
			pg = &plan->records[record->port_id - 1];
			if (pg->type != BR_RTL9617C_MDB_PORT ||
			    pg->entry_id != record->entry_id || pg->dev != record->dev)
				return fe_mdb_fail(fe, FE_MDB_SNAPSHOT, -EINVAL);
			if (!record->source.user_added || record->source.timer.pending)
				return fe_mdb_fail(fe, FE_MDB_MEMBERSHIP, -EOPNOTSUPP);
			/* The materialized PG.forward above already contains source
			 * filtering. Do not invent another timer-driven IGMP state. */
		} else {
			return fe_mdb_fail(fe, FE_MDB_SNAPSHOT, -EINVAL);
		}
	}
	for (i = 0; i < plan->entry_count; i++) {
		struct fe_mdb_entry *entry = &plan->entries[i];

		for (p = 0; p < 5; p++) {
			unsigned int egress;

			if (!(forwarding & BIT(p)))
				continue;
			egress = (entry->egress | plan->router[entry->key.ipv6]) &
				forwarding & ~BIT(p);
			/* An empty set remains CPU-only, not a wildcard fallback. */
			if (!egress)
				continue;
			for (protocol = 0; protocol < 2; protocol++) {
				unsigned int slot = plan->rule_count;

				if (slot == RTL_MDB_TCAM_SLOTS)
					return fe_mdb_fail(fe, FE_MDB_CAPACITY, -ENOSPC);
				plan->rules[slot] = entry->key;
				plan->rules[slot].ingress = p;
				plan->rules[slot].protocol = protocol ? IPPROTO_UDP : IPPROTO_TCP;
				plan->egress[slot] = egress;
				plan->rule_count++;
			}
		}
	}
	return 0;
}

static int fe_mdb_pin(void *context, unsigned int group)
{
	return fe_mcast_publish(context, group);
}

static int fe_mdb_windows(struct rtl_fe *fe)
{
	struct rtl_dq_io io = fe_io(fe);
	static const unsigned int access[] = { 0x3200, 0x3380, 0x33b0 };
	unsigned int i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(access); i++) {
		ret = rtl_fe_window_idle(&io, access[i]);
		if (ret) {
			fe->mdb->window_retained = true;
			return ret;
		}
	}
	fe->mdb->window_retained = false;
	return 0;
}

static int fe_mdb_profile_prepare(struct rtl_fe *fe)
{
	struct rtl_dq_io io = fe_io(fe);
	int ret, undo;

	lockdep_assert_held(&fe->lock);
	/* Called from first FE prepare, before engine/base_ready or the global
	 * my-MAC-failure bit can authorize any profile0 multicast lookup. */
	if (!fe->native_mdb_profile || !fe->prepared || !fe->mcast ||
	    !fe->mcast->state.contract_ready ||
	    !rtl_l2_owner_ready(fe->l2_owner, RTL_L2_SHARED_MC_VECTOR) ||
	    !rtl_l2_owner_ready(fe->l2_owner, RTL_L2_SHARED_MC_FIB))
		return -EOPNOTSUPP;
	if (!fe->mdb) {
		fe->mdb = kvzalloc(sizeof(*fe->mdb), GFP_KERNEL);
		if (!fe->mdb)
			return -ENOMEM;
	}
	if (READ_ONCE(fe->route_admitted) ||
	    smp_load_acquire(&fe->mcast->state.rx_active) ||
	    !fe_switch_hw_rx_check(fe, 0, 0) || !fe_switch_hw_route_closed(fe))
		return fe_mdb_fail(fe, FE_MDB_GATE, -EBUSY);
	if (fe->mdb->tcam.initialized || fe->mdb->tcam.prepared ||
	    fe->mdb->tcam.guard_exposed || fe->mdb->window_retained)
		return fe_mdb_fail(fe, FE_MDB_PROFILE, -EBUSY);
	ret = rtl_mdb_tcam_init(&io, &fe->mdb->tcam);
	if (!ret)
		ret = rtl_mdb_profile_prepare(&io, &fe->mdb->tcam);
	if (!ret)
		ret = rtl_mdb_profile_check(&io, &fe->mdb->tcam);
	if (!ret)
		return fe_mdb_fail(fe, FE_MDB_OK, 0);
	/* A never-valid partial prepare can roll back; a possibly published
	 * guard is immutable even if the other guard failed. FE must stay
	 * gated and retain this owner. Do not restore it under a live packet. */
	undo = fe_mdb_windows(fe);
	if (!undo && !fe->mdb->tcam.guard_exposed && !fe->mdb->tcam.exposed)
		undo = rtl_mdb_tcam_restore(&io, &fe->mdb->tcam);
	if (undo) {
		fe_mdb_windows(fe);
		ret = undo;
	}
	return fe_mdb_fail(fe, FE_MDB_PROFILE, ret);
}

static int fe_mdb_profile_check(struct rtl_fe *fe)
{
	struct rtl_dq_io io = fe_io(fe);
	int ret, pending;

	lockdep_assert_held(&fe->lock);
	if (!fe->native_mdb_profile || !fe->mdb)
		return -EOPNOTSUPP;
	ret = rtl_mdb_profile_check(&io, &fe->mdb->tcam);
	if (ret) {
		pending = fe_mdb_windows(fe);
		if (pending)
			ret = pending;
		return fe_mdb_fail(fe, FE_MDB_PROFILE, ret);
	}
	return 0;
}

static int __maybe_unused fe_mdb_withdraw(struct rtl_fe *fe)
{
	struct rtl_dq_io io = fe_io(fe);
	struct rtl_fe_mdb *mdb = fe->mdb;
	int ret;

	lockdep_assert_held(&fe->lock);
	if (!mdb)
		return 0;
	/* Even a failed preflight READ can retain ACCESS/DATA ownership. It
	 * must finish before a warm teardown discards that outstanding lease. */
	if (mdb->window_retained) {
		ret = fe_mdb_windows(fe);
		if (ret)
			return fe_mdb_fail(fe, FE_MDB_WITHDRAWAL, ret);
	}
	if (!mdb->tcam.prepared && !mdb->tcam.used && !mdb->tcam.poisoned)
		return 0;
	if ((fe->mcast && smp_load_acquire(&fe->mcast->state.rx_active)) ||
	    !fe_switch_hw_rx_check(fe, 0, 0) || !fe_switch_hw_route_closed(fe))
		return fe_mdb_fail(fe, FE_MDB_WITHDRAWAL, -EBUSY);
	ret = rtl_mdb_tcam_withdraw(&io, &mdb->tcam);
	if (!ret && !mdb->tcam.exposed && !mdb->tcam.guard_exposed)
		ret = rtl_mdb_tcam_restore(&io, &mdb->tcam);
	if (ret) {
		fe_mdb_windows(fe);
		return fe_mdb_fail(fe, FE_MDB_WITHDRAWAL, ret);
	}
	mdb->steer_ports = 0;
	mdb->withdrawals++;
	/* MCE references are aggregate across DFT and CLS. The worker retires
	 * them only AFTER both producers have been withdrawn/read back. */
	return 0;
}

static int __maybe_unused fe_mdb_prepare(struct rtl_fe *fe, struct rtl9617c_switch_guard *guard,
		u64 generation, const struct net_device *master,
		struct net_device *const ports[5], const unsigned long flags[5],
		unsigned int forwarding, unsigned int *steer_ports)
{
	struct rtl_dq_io io = fe_io(fe);
	struct rtl_mdb_dependency dependency = { .context = fe, .publish = fe_mdb_pin };
	struct fe_mdb_plan *plan;
	struct rtl_fe_mdb *mdb;
	unsigned int i, slot, steer = 0;
	int ret, undo;

	lockdep_assert_held(&fe->lock);
	ASSERT_RTNL();
	if (!steer_ports)
		return -EINVAL;
	*steer_ports = 0;
	if (!guard || !master || !ports || !flags || !generation ||
	    !forwarding || (forwarding & ~31U))
		return -EINVAL;
	if (!fe->mdb) {
		fe->mdb = kvzalloc(sizeof(*fe->mdb), GFP_KERNEL);
		if (!fe->mdb)
			return -ENOMEM;
	}
	mdb = fe->mdb;
	mdb->attempts++;
	mdb->records = mdb->planned = mdb->bad_register = mdb->bad_value = 0;
	if (mdb->tcam.active || mdb->tcam.poisoned || mdb->steer_ports ||
	    mdb->window_retained)
		return fe_mdb_fail(fe, FE_MDB_TRANSACTION, -EBUSY);
	/* Immutable results protect packets which ALREADY chose a key. A
	 * closed LAN gate and local L2 drain do not prove that older packets
	 * cannot still reach L3/CLS and match a NEW generation. Until there is
	 * a real pre-CLS consumer barrier, only this first exposed epoch may
	 * publish. Later policy epochs remain on CPU, even with free slots. */
	if (mdb->tcam.exposed && mdb->generation != generation)
		return fe_mdb_fail(fe, FE_MDB_RETIRED_EPOCH, -EOPNOTSUPP);
	if (mdb->tcam.used > RTL_MDB_TCAM_SLOTS)
		return fe_mdb_fail(fe, FE_MDB_TRANSACTION, -EIO);
	/* Reject BEFORE any register read or command on an unowned cold MCE.
	 * No booleans supplied by callers can waive the producer/drain proof. */
	if (!fe->mcast || !fe->mcast->state.contract_ready ||
	    !rtl_l2_owner_ready(fe->l2_owner, RTL_L2_SHARED_MC_VECTOR) ||
	    !rtl_l2_owner_ready(fe->l2_owner, RTL_L2_SHARED_MC_FIB))
		return fe_mdb_fail(fe, FE_MDB_COLD_CONTRACT, -EOPNOTSUPP);
	if (!fe->native_mdb_profile || !fe->enabled || !fe->prepared ||
	    !fe->base_ready || fe->base_failed || !fe->engine_ready || fe->shutting_down ||
	    !mdb->tcam.guards_ready || !mdb->tcam.guard_exposed)
		return fe_mdb_fail(fe, FE_MDB_PROFILE, -EOPNOTSUPP);
	ret = fe_mdb_epoch(guard, generation);
	if (ret)
		return fe_mdb_fail(fe, FE_MDB_EPOCH, ret);
	ret = fe_mdb_topology(fe, guard, master, ports, flags, forwarding);
	if (ret)
		return fe_mdb_fail(fe, FE_MDB_TOPOLOGY, ret);
	if (READ_ONCE(fe->route_admitted) ||
	    smp_load_acquire(&fe->mcast->state.rx_active) ||
	    !fe_switch_hw_rx_check(fe, 0, 0) || !fe_switch_hw_route_closed(fe))
		return fe_mdb_fail(fe, FE_MDB_GATE, -EBUSY);
	plan = kvzalloc(sizeof(*plan), GFP_KERNEL);
	if (!plan)
		return fe_mdb_fail(fe, FE_MDB_SNAPSHOT, -ENOMEM);
	ret = br_rtl9617c_mdb_snapshot(master, 0, guard, FE_MDB_WORK_BUDGET,
			&plan->snapshot, fe_mdb_capture, plan);
	if (ret) {
		fe_mdb_fail(fe, FE_MDB_SNAPSHOT, ret);
		goto out;
	}
	if (plan->snapshot.master != master || plan->snapshot.generation != generation) {
		ret = fe_mdb_fail(fe, FE_MDB_EPOCH, -EAGAIN);
		goto out;
	}
	mdb->records = plan->count;
	ret = fe_mdb_compile(fe, plan, ports, flags, forwarding);
	if (ret)
		goto out;
	mdb->planned = plan->rule_count;
	if (plan->rule_count > RTL_MDB_TCAM_SLOTS - mdb->tcam.used) {
		ret = fe_mdb_fail(fe, FE_MDB_CAPACITY, -ENOSPC);
		goto out;
	}
	if (!plan->rule_count) {
		ret = fe_mdb_fail(fe, FE_MDB_OK, 0);
		goto out;
	}
	ret = fe_mdb_hardware(fe);
	if (ret) {
		undo = fe_mdb_windows(fe);
		if (undo)
			ret = undo;
		fe_mdb_fail(fe, FE_MDB_HARDWARE, ret);
		goto out;
	}
	ret = fe_mdb_epoch(guard, generation);
	if (ret) {
		fe_mdb_fail(fe, FE_MDB_EPOCH, ret);
		goto out;
	}
	/* Record before the first possible VALID attempt, including timeout.
	 * Never lose the epoch merely because the batch later rolls back. */
	mdb->generation = generation;
	for (i = 0; i < plan->rule_count; i++) {
		struct rtl_mdb_rule *rule = &plan->rules[i];
		u16 group;

		ret = fe_mdb_epoch(guard, generation);
		if (ret)
			goto rollback;
		ret = fe_mcast_group(fe, guard, generation, rule->ingress,
			ports[rule->ingress], master, 0, plan->egress[i], &group);
		if (ret)
			goto rollback;
		rule->group = group;
		ret = rtl_mdb_tcam_install(&io, &mdb->tcam, rule, &dependency, &slot);
		if (ret)
			goto rollback;
		steer |= BIT(rule->ingress);
	}
	ret = fe_mdb_epoch(guard, generation);
	if (ret)
		goto rollback;
	mdb->generation = generation;
	mdb->steer_ports = steer;
	mdb->publications += plan->rule_count;
	*steer_ports = steer;
	ret = fe_mdb_fail(fe, FE_MDB_OK, 0);
	goto out;
rollback:
	fe_mdb_windows(fe);
	fe_mdb_fail(fe, ret == -EAGAIN ? FE_MDB_EPOCH : FE_MDB_TRANSACTION, ret);
	undo = fe_mdb_withdraw(fe);
	if (undo)
		ret = undo;
	/* No EOPNOTSUPP/ENOSPC fallback is permitted with a live CLS prefix.
	 * Sticky exposed indices and MCE dependencies survive clean fallback. */
out:
	kvfree(plan);
	return ret;
}

#else

static int fe_mdb_profile_prepare(struct rtl_fe *fe)
{
	return -EOPNOTSUPP;
}

static int fe_mdb_profile_check(struct rtl_fe *fe)
{
	return -EOPNOTSUPP;
}

static int fe_mdb_withdraw(struct rtl_fe *fe)
{
	return fe_mdb_retained(fe) ? -EBUSY : 0;
}

static int fe_mdb_prepare(struct rtl_fe *fe, struct rtl9617c_switch_guard *guard,
		u64 generation, const struct net_device *master,
		struct net_device *const ports[5], const unsigned long flags[5],
		unsigned int forwarding, unsigned int *steer_ports)
{
	if (steer_ports)
		*steer_ports = 0;
	return -EOPNOTSUPP;
}

#endif
#endif
