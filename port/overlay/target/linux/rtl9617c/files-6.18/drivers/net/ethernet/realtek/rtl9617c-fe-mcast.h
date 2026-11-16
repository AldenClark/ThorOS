/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTL9617C_FE_MCAST_H
#define RTL9617C_FE_MCAST_H

#include <linux/rtl9617c-mcast.h>
#include <linux/rtl9617c-mdb.h>
#include <linux/vmalloc.h>
#include "rtl9617c-mcast-cold.h"

/* Included by fe.c after its complete owner and MMIO helpers. */
struct rtl_fe_mcast {
	struct rtl_mcast_state state;
};

static int fe_mcast_inherited_l3_check(struct rtl_fe *fe);

/* Cached preflight/resource evidence, separate from the crowded legacy
 * l2_state page. The caller holds fe->lock; this performs no MMIO at all.
 * A missing owner/sample is unavailable, never a zero-valued success. */
static ssize_t fe_mcast_evidence(struct rtl_fe *fe, char *buffer, size_t bytes)
{
	const struct rtl_mcast_state *state;

	if (!fe->mcast)
		return scnprintf(buffer, bytes,
			"mce_preflight=not-attempted mce_sample_valid=0x0\n");
	state = &fe->mcast->state;
	return scnprintf(buffer, bytes,
		"mce_preflight=cached mce_cold_handoff_verified=0 "
		"mce_missing_contracts=0x%x mce_sample_valid=0x%x "
		"mce_cold_reads=%u mce_cold_register=0x%x mce_cold_value=0x%x "
		"mce_xram_cfg=0x%x mce_stg0_ctrl=0x%x mce_hash_ini=0x%x "
		"mce_cache_ini=0x%x mce_cold_control=0x%x "
		"mce_capacity_fallbacks=%u mce_unpublished_aborts=%u\n",
		state->handoff.missing, state->handoff.valid_mask,
		state->cold_reads, state->cold_register, state->cold_value,
		state->handoff.value[RTL_MCAST_HANDOFF_XRAM],
		state->handoff.value[RTL_MCAST_HANDOFF_STG0],
		state->handoff.value[RTL_MCAST_HANDOFF_HASH],
		state->handoff.value[RTL_MCAST_HANDOFF_CACHE],
		state->handoff.value[RTL_MCAST_HANDOFF_MCE],
		state->capacity_fallbacks, state->unpublished_aborts);
}

static int fe_mcast_cold_prepare(struct rtl_fe *fe)
{
	struct rtl_dq_io io = fe_io(fe);
	struct rtl_mcast_state *state;
	int ret;

	lockdep_assert_held(&fe->lock);
	if (!fe->l2_owner || !fe->fabric.ready || fe->engine_ready ||
	    fe->prepared || fe->dma_exposed || fe->shutting_down)
		return -EBUSY;
	if (fe->mcast)
		return -EBUSY;
	fe->mcast = kvzalloc(sizeof(*fe->mcast), GFP_KERNEL);
	if (!fe->mcast)
		return -ENOMEM;
	state = &fe->mcast->state;
	/* CPU injection/L3 hash/classifier/DDR roots cannot be discovered by
	 * scanning only L2 tables. The existing FE owner supplies that actual
	 * cold check before this helper touches the multicast control bit.
	 */
	ret = fe_mcast_inherited_l3_check(fe);
	/* This preflight is strictly read-only: it has not acquired a command
	 * window, changed a shared register or published an MCE consumer. A
	 * failed optional diagnostic closes MCE without poisoning the already
	 * verified SVL/CPU/routing baseline. */
	if (ret)
		goto out;
	ret = rtl_mcast_cold_prepare(state, fe->l2_owner, &io);
	/* A failed command can retain the global ACCESS/DATA/filter lease.
	 * Only a clean unsupported-contract refusal is optional fallback. */
	if (ret && ret != -EOPNOTSUPP)
		rtl_l2_owner_fault(fe->l2_owner, ret);
out:
	state->error = ret;
	if (ret)
		fe->l2_owner->mc_error = ret;
	return ret;
}

static void fe_mcast_free(struct rtl_fe *fe)
{
	/* Called only by final FE teardown after all callback/DMA/resource
	 * retention checks, never by a policy rebuild or ordinary ndo_stop.
	 */
	kvfree(fe->mcast);
	fe->mcast = NULL;
}

static bool fe_mcast_retained(struct rtl_fe *fe)
{
	/* Global metadata mode/filter ownership is independent of whether
	 * any new vector was allocated. Do not lose its snapshot on unload. */
	return fe->mcast && (fe->mcast->state.fdb_filter_owned ||
			     fe->mcast->state.mce_control_owned);
}

static void __maybe_unused fe_mcast_revoke(struct rtl_fe *fe)
{
	if (fe->mcast)
		smp_store_release(&fe->mcast->state.rx_active, 0);
}

static void __maybe_unused fe_mcast_arm(struct rtl_fe *fe, u64 generation)
{
	struct rtl_mcast_state *state;

	if (!fe->mcast)
		return;
	state = &fe->mcast->state;
	if (state->contract_ready && state->active_owner &&
	    state->active_generation == generation)
		smp_store_release(&state->rx_active, 1);
}

/* RTNL + FE mutex, while the synchronous policy gate is closed. */
static int fe_mcast_group(struct rtl_fe *fe,
		struct rtl9617c_switch_guard *guard, u64 generation,
		unsigned int ingress, const struct net_device *port,
		const struct net_device *master, u16 vid, unsigned int egress,
		u16 *group)
{
	struct rtl_dq_io io = fe_io(fe);
	struct rtl_mcast_state *state;
	unsigned int control, mode, ni;
	int ret;

	lockdep_assert_held(&fe->lock);
	ASSERT_RTNL();
	if (!guard || !guard->registered || !guard->identity || !port || !master ||
	    guard->net != dev_net(port) || guard->net != dev_net(master))
		return -EINVAL;
	if (!fe->mcast || !fe->l2_owner)
		return -EOPNOTSUPP;
	state = &fe->mcast->state;
	if (smp_load_acquire(&state->rx_active))
		return -EBUSY;
	control = fe_read(fe, RTL_MCAST_CONTROL);
	mode = fe_read(fe, RTL_L2_VLAN_MODE_CONTROL);
	ni = fe_read(fe, RTL_MCAST_NI_SOURCE);
	if (control == ~0U || mode == ~0U || ni == ~0U)
		return -EIO;
	if ((control & (RTL_MCAST_COPY_LSPID_TO_POL | RTL_MCAST_BUFFER_FLUSH)) ||
	    (mode & RTL_MCAST_ELPB_RELOOKUP) ||
	    (ni & (63U | (1U << 7) | 0xff00U)) != (RTL_MCAST_SOURCE | (1U << 7)))
		return -EOPNOTSUPP;
	ret = rtl_mcast_group_prepare(state, fe->l2_owner, &io,
			guard->identity, generation, ingress, port->ifindex,
			master->ifindex, vid, egress, group);
	if (!ret) {
		state->active_owner = guard->identity;
		state->active_generation = generation;
	} else {
		state->fallbacks++;
		state->error = ret;
	}
	return ret;
}

static int fe_mcast_publish(struct rtl_fe *fe, u16 group)
{
	if (!fe->mcast)
		return -EOPNOTSUPP;
	return rtl_mcast_group_publish(&fe->mcast->state, fe->l2_owner, group);
}

/* Consumer calls only after its last producer key/DFT row is withdrawn
 * and read back. Neither this nor revoke claims an MCE packet drain.
 */
static int __maybe_unused fe_mcast_retire(struct rtl_fe *fe, u16 group)
{
	if (!fe->mcast)
		return -EOPNOTSUPP;
	return rtl_mcast_group_retire(&fe->mcast->state, fe->l2_owner, group);
}

static int __maybe_unused fe_mcast_retire_all(struct rtl_fe *fe)
{
	struct rtl_mcast_state *state;
	struct rtl_dq_io io = fe_io(fe);
	unsigned int group;
	int ret;

	lockdep_assert_held(&fe->lock);
	if (!fe->mcast)
		return 0;
	state = &fe->mcast->state;
	if (smp_load_acquire(&state->rx_active))
		return -EBUSY;
	/* Caller has verified withdrawal of EVERY DFT/FDB/CLS producer.
	 * These are aggregate references, not one reference per DFT row. */
	for (group = 1; group < RTL_L2_MC_VECTOR_ENTRIES; group++) {
		if (!state->vector[group].active)
			continue;
		ret = rtl_mcast_group_retire(state, fe->l2_owner, group);
		if (ret)
			return ret;
	}
	return rtl_mcast_abort_unpublished(state, fe->l2_owner, &io);
}

static int fe_mcast_snapshot_ignore(void *priv,
				   const struct br_rtl9617c_mdb_record *record)
{
	return 0;
}

static int __maybe_unused fe_mcast_prepare_bum(struct rtl_fe *fe,
		struct rtl9617c_switch_guard *guard, u64 generation,
		const struct net_device *master, struct net_device *const ports[5],
		const unsigned long flags[5], unsigned int forwarding,
		struct rtl_mcast_groups *groups)
{
	struct br_rtl9617c_mdb_snapshot snapshot;
	struct rtl_mcast_groups prepared = { };
	struct rtl_dq_io io = fe_io(fe);
	unsigned int source, destination, kind, egress;
	bool multicast = false;
	int ret;

	if (!groups || !master || !ports || !flags || (forwarding & ~31U))
		return -EINVAL;
	memset(groups, 0, sizeof(*groups));
	if (!fe->mcast || !fe->mcast->state.contract_ready)
		return -EOPNOTSUPP;
	fe->mcast->state.preparations++;
	/* Do not confuse default unknown-MC flooding with exact MDB offload.
	 * A coherent bounded snapshot supplies the actual snooping state.
	 * If the query cannot prove it disabled, keep multicast CPU-owned.
	 */
	ret = br_rtl9617c_mdb_snapshot(master, 0, guard, 4096, &snapshot,
				     fe_mcast_snapshot_ignore, NULL);
	if (!ret) {
		if (snapshot.generation != generation)
			return -EAGAIN;
		multicast = !snapshot.snooping && !snapshot.vlan_filtering;
	} else if (ret == -EAGAIN) {
		return ret;
	}
	for (source = 0; source < 5; source++) {
		if (!(forwarding & BIT(source)) || !ports[source])
			continue;
		for (kind = 0; kind < 4; kind++) {
			unsigned long flood_flag = kind == RTL_L2_FLOOD_BROADCAST ?
				BR_BCAST_FLOOD : kind == RTL_L2_FLOOD_UNKNOWN_UNICAST ?
				BR_FLOOD : BR_MCAST_FLOOD;

			if (kind >= RTL_L2_FLOOD_UNKNOWN_L2_MULTICAST && !multicast)
				continue;
			egress = 0;
			for (destination = 0; destination < 5; destination++) {
				if (source == destination || !(forwarding & BIT(destination)) ||
				    !(flags[destination] & flood_flag) ||
				    ((flags[source] & BR_ISOLATED) &&
				     (flags[destination] & BR_ISOLATED)))
					continue;
				egress |= BIT(destination);
			}
			if (!egress)
				continue;
			ret = fe_mcast_group(fe, guard, generation, source, ports[source],
					     master, 0, egress, &prepared.group[source][kind]);
			if (ret) {
				/* The BUM batch has not published any DFT reference yet.
				 * Capacity/eligibility fallback must not strand a partial
				 * never-published action graph. Ambiguous I/O keeps it. */
				if (ret == -ENOSPC || ret == -EOPNOTSUPP) {
					int undo = rtl_mcast_abort_unpublished(&fe->mcast->state,
							fe->l2_owner, &io);

					if (undo)
						return undo;
				}
				return ret;
			}
			prepared.enabled[source] |= BIT(kind);
		}
	}
	*groups = prepared;
	return 0;
}

/* A positive return means an authenticated immutable CPU-copy recipe,
 * zero means an ordinary source, negative means DROP (never CPU reflood).
 * The caller already owns and validated HeaderA and the complete frame.
 */
int rtl_fe_mcast_rx(struct rtl_fe *fe, struct sk_buff *skb,
		   u32 header0, u32 header1, unsigned int *source)
{
	const struct rtl_mcast_token *token;
	struct rtl9617c_mcast_copy *copy;
	struct rtl_mcast_state *state;
	unsigned int id;

	if (((header1 >> 9) & 63U) != RTL_MCAST_SOURCE)
		return 0;
	if (!fe || !fe->mcast || !source)
		return -EACCES;
	state = &fe->mcast->state;
	/* PTP overloads packet-info; mirrored packets are not our recipe.
	 * Packet type is not part of this contract: a copied UC/BC/MC/UUC
	 * classification is not the immutable recipe's provenance.  Do not
	 * infer provenance from the BUM flag or token 56 convention either.
	 */
	if ((header1 >> 30) == 3 || (header0 & BIT(14)) ||
	    !smp_load_acquire(&state->rx_active))
		goto reject;
	/* The current native recipe retains both C/S-tag CF traps.  The
	 * special receive dispatch intentionally precedes generic VLAN demux,
	 * so fail closed if a tagged frame contradicts that live contract.
	 * SVL alone would NOT prove a packet had no VLAN header.
	 */
	if (((skb->data[12] << 8) | skb->data[13]) == ETH_P_8021Q ||
	    ((skb->data[12] << 8) | skb->data[13]) == ETH_P_8021AD)
		goto reject;
	id = (header0 >> 18) & 511U;
	if (!id)
		goto reject;
	token = &state->token[id];
	if (!token->allocated || !token->published ||
	    token->owner != READ_ONCE(state->active_owner) ||
	    token->generation != READ_ONCE(state->active_generation) ||
	    token->ingress >= 5 || token->vid ||
	    is_link_local_ether_addr(skb->data))
		goto reject;
	copy = skb_ext_add(skb, SKB_EXT_RTL9617C_MCAST);
	if (!copy) {
		state->rx_no_memory++;
		goto reject;
	}
	*copy = (struct rtl9617c_mcast_copy) {
		.owner = token->owner, .generation = token->generation,
		.ingress_ifindex = token->ingress_ifindex,
		.master_ifindex = token->master_ifindex,
		.vid = token->vid, .token = id,
	};
	*source = token->ingress;
	state->rx_copies++;
	return 1;
reject:
	state->rx_rejected++;
	return -EACCES;
}

#endif
