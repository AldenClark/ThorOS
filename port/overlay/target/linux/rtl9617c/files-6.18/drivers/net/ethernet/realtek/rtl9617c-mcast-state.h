/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTL9617C_MCAST_STATE_H
#define RTL9617C_MCAST_STATE_H

#include "rtl9617c-l2-owner.h"

#define RTL_MCAST_LAN_PORTS 5U
#define RTL_MCAST_LAN_MASK 31U
#define RTL_MCAST_TOKEN_COUNT 512U
#define RTL_MCAST_SOURCE 27U
#define RTL_MCAST_CPU 16U

/* The POL token belongs to an immutable per-ingress action, not to a
 * mutable bridge slot.  Old tokens and their vector/action rows are never
 * recycled after publication, including timeout and rollback paths.
 * Exhaustion is an ordinary CPU-fallback result, not a reason to guess
 * that an MCE FIFO or a queued network-stack skb has drained.
 */
struct rtl_mcast_token {
	unsigned long long owner, generation;
	int ingress_ifindex, master_ifindex;
	unsigned short action, vid;
	unsigned char ingress, allocated, published;
};

struct rtl_mcast_vector {
	unsigned short token;
	unsigned char egress, allocated, published, active;
};

struct rtl_mcast_groups {
	unsigned short group[RTL_MCAST_LAN_PORTS][4];
	unsigned char enabled[RTL_MCAST_LAN_PORTS];
};

struct rtl_mcast_state {
	struct rtl_mcast_token token[RTL_MCAST_TOKEN_COUNT];
	struct rtl_mcast_vector vector[RTL_L2_MC_VECTOR_ENTRIES];
	unsigned int forbidden_token[RTL_MCAST_TOKEN_COUNT / 32U];
	unsigned short lan_action[RTL_MCAST_LAN_PORTS];
	unsigned char lan_ready, contract_ready, rx_active;
	unsigned long long active_owner, active_generation;
	unsigned long long rx_copies, rx_rejected, rx_no_memory;
	unsigned int groups, tokens, preparations, fallbacks, publications;
	unsigned int cold_reads, cold_register, cold_value;
	unsigned int saved_fdb_filter[RTL_L2_FDB_FILTER_WORDS];
	unsigned int saved_mce_control;
	unsigned char fdb_filter_owned, mce_control_owned;
	int error;
};

static inline int rtl_mcast_recipe(unsigned int words[3],
		unsigned int destination, unsigned int token)
{
	if (!words || destination > RTL_MCAST_CPU ||
	    (destination >= RTL_MCAST_LAN_PORTS && destination != RTL_MCAST_CPU) ||
	    token >= RTL_MCAST_TOKEN_COUNT ||
	    (destination == RTL_MCAST_CPU ? !token : !!token))
		return -EINVAL;
	words[0] = token << 23;
	words[1] = (destination << 24) | (RTL_L2_MC_COS_KEEP << 30);
	/* Explicit egress vectors exclude ingress.  Do not rely on the
	 * ambiguous original-LSPID/policer-copy ordering to suppress a port.
	 * Tags, priorities, DEI, SA and TTL all keep their incoming values.
	 */
	words[2] = 1U;
	return 0;
}

static inline int rtl_mcast_lan_prepare(struct rtl_mcast_state *state,
		struct rtl_l2_owner *owner, const struct rtl_dq_io *io)
{
	unsigned short ids[RTL_MCAST_LAN_PORTS];
	unsigned int words[3], port, undo;
	int ret, abort_ret;

	if (state->lan_ready)
		return 0;
	ret = rtl_l2_owner_reserve(owner, RTL_L2_SHARED_MC_FIB,
				 RTL_MCAST_LAN_PORTS, ids);
	if (ret)
		return ret;
	for (port = 0; port < RTL_MCAST_LAN_PORTS; port++) {
		rtl_mcast_recipe(words, port, 0);
		ret = rtl_l2_owner_write(owner, io, RTL_L2_SHARED_MC_FIB,
					 ids[port], words);
		if (ret)
			goto abort;
	}
	for (port = 0; port < RTL_MCAST_LAN_PORTS; port++)
		state->lan_action[port] = ids[port];
	state->lan_ready = 1;
	return 0;
abort:
	/* No external consumer was published.  Restore only these exact
	 * reservations; an ambiguous journal prevents any further allocation.
	 */
	for (undo = 0; undo < RTL_MCAST_LAN_PORTS; undo++) {
		abort_ret = rtl_l2_owner_abort(owner, io, RTL_L2_SHARED_MC_FIB,
					     ids[undo]);
		if (abort_ret)
			ret = abort_ret;
	}
	return ret;
}

static inline int rtl_mcast_group_prepare(struct rtl_mcast_state *state,
		struct rtl_l2_owner *owner, const struct rtl_dq_io *io,
		unsigned long long identity, unsigned long long generation,
		unsigned int ingress, int ingress_ifindex, int master_ifindex,
		unsigned short vid, unsigned int egress, unsigned short *group)
{
	struct rtl_mcast_token *copy = 0;
	unsigned int token, index, port, words[3];
	unsigned long long actions;
	unsigned short action_id, vector_id;
	int ret;

	if (!state || !owner || !group || !identity ||
	    ingress >= RTL_MCAST_LAN_PORTS || ingress_ifindex <= 0 ||
	    master_ifindex <= 0 || ingress_ifindex == master_ifindex ||
	    (egress & ~RTL_MCAST_LAN_MASK) || (egress & (1U << ingress)))
		return -EINVAL;
	/* First live contract is transparent SVL.  VID/PVID/egress edits
	 * need their own immutable edit and downstream-consumer contract.
	 */
	if (vid || !egress || !state->contract_ready ||
	    !rtl_l2_owner_ready(owner, RTL_L2_SHARED_MC_VECTOR))
		return -EOPNOTSUPP;
	ret = rtl_mcast_lan_prepare(state, owner, io);
	if (ret)
		return ret;
	for (token = 1; token < RTL_MCAST_TOKEN_COUNT; token++) {
		copy = &state->token[token];
		if (copy->allocated && copy->owner == identity &&
		    copy->generation == generation && copy->ingress == ingress &&
		    copy->ingress_ifindex == ingress_ifindex &&
		    copy->master_ifindex == master_ifindex && copy->vid == vid)
			break;
	}
	if (token == RTL_MCAST_TOKEN_COUNT) {
		for (token = 1; token < RTL_MCAST_TOKEN_COUNT; token++)
			if (!state->token[token].allocated &&
			    !rtl_l2_owner_has(state->forbidden_token, token))
				break;
		if (token == RTL_MCAST_TOKEN_COUNT)
			return -ENOSPC;
		ret = rtl_l2_owner_reserve(owner, RTL_L2_SHARED_MC_FIB, 1, &action_id);
		if (ret)
			return ret;
		rtl_mcast_recipe(words, RTL_MCAST_CPU, token);
		ret = rtl_l2_owner_write(owner, io, RTL_L2_SHARED_MC_FIB,
					 action_id, words);
		if (ret) {
			rtl_l2_owner_abort(owner, io, RTL_L2_SHARED_MC_FIB, action_id);
			return ret;
		}
		copy = &state->token[token];
		*copy = (struct rtl_mcast_token) {
			.owner = identity, .generation = generation,
			.ingress_ifindex = ingress_ifindex,
			.master_ifindex = master_ifindex,
			.action = action_id, .vid = vid, .ingress = ingress,
			.allocated = 1,
		};
		state->tokens++;
	}
	for (index = 1; index < RTL_L2_MC_VECTOR_ENTRIES; index++)
		if (state->vector[index].allocated &&
		    state->vector[index].token == token &&
		    state->vector[index].egress == egress) {
			*group = index;
			return 0;
		}
	ret = rtl_l2_owner_reserve(owner, RTL_L2_SHARED_MC_VECTOR, 1, &vector_id);
	if (ret)
		return ret;
	actions = 1ULL << copy->action;
	for (port = 0; port < RTL_MCAST_LAN_PORTS; port++)
		if (egress & (1U << port))
			actions |= 1ULL << state->lan_action[port];
	rtl_l2_bitmap_encode(words, actions);
	ret = rtl_l2_owner_write(owner, io, RTL_L2_SHARED_MC_VECTOR, vector_id, words);
	if (ret) {
		rtl_l2_owner_abort(owner, io, RTL_L2_SHARED_MC_VECTOR, vector_id);
		return ret;
	}
	state->vector[vector_id] = (struct rtl_mcast_vector) {
		.token = token, .egress = egress, .allocated = 1,
	};
	state->groups++;
	*group = vector_id;
	return 0;
}

/* Call BEFORE the first externally reachable producer write, including a
 * valid TCAM key.  A failed/uncertain write still pins the complete graph.
 * One aggregate active reference covers all consumers of this vector;
 * release it only after EVERY consumer has been withdrawn and read back.
 */
static inline int rtl_mcast_group_publish(struct rtl_mcast_state *state,
		struct rtl_l2_owner *owner, unsigned short group)
{
	struct rtl_mcast_vector *vector;
	int ret;

	if (!state || !group || group >= RTL_L2_MC_VECTOR_ENTRIES)
		return -EINVAL;
	vector = &state->vector[group];
	if (!vector->allocated || !vector->token ||
	    !state->token[vector->token].allocated)
		return -EPERM;
	if (vector->active)
		return 0;
	ret = rtl_l2_owner_publish(owner, RTL_L2_SHARED_MC_VECTOR, group);
	if (ret)
		return ret;
	vector->active = 1;
	vector->published = 1;
	state->token[vector->token].published = 1;
	state->publications++;
	return 0;
}

static inline int rtl_mcast_group_retire(struct rtl_mcast_state *state,
		struct rtl_l2_owner *owner, unsigned short group)
{
	int ret;

	if (!state || !group || group >= RTL_L2_MC_VECTOR_ENTRIES ||
	    !state->vector[group].allocated)
		return -EINVAL;
	if (!state->vector[group].active)
		return 0;
	ret = rtl_l2_owner_retire(owner, RTL_L2_SHARED_MC_VECTOR, group);
	if (!ret)
		state->vector[group].active = 0;
	/* published remains sticky, as do the token and all action words. */
	return ret;
}

/* Roll back preparation only; this function can NEVER reclaim a published
 * vector, CPU token, or shared LAN action. Withdrawn is not unpublished.
 * Vectors must be restored before the actions they reference.
 */
static inline int rtl_mcast_abort_unpublished(struct rtl_mcast_state *state,
		struct rtl_l2_owner *owner, const struct rtl_dq_io *io)
{
	unsigned int index, port;
	int ret;

	if (!state || !owner)
		return -EINVAL;
	for (index = 1; index < RTL_L2_MC_VECTOR_ENTRIES; index++) {
		if (!state->vector[index].allocated || state->vector[index].published)
			continue;
		ret = rtl_l2_owner_abort(owner, io, RTL_L2_SHARED_MC_VECTOR, index);
		if (ret)
			return ret;
		state->vector[index] = (struct rtl_mcast_vector) { 0 };
		state->groups--;
	}
	for (index = 1; index < RTL_MCAST_TOKEN_COUNT; index++) {
		if (!state->token[index].allocated || state->token[index].published)
			continue;
		ret = rtl_l2_owner_abort(owner, io, RTL_L2_SHARED_MC_FIB,
					 state->token[index].action);
		if (ret)
			return ret;
		state->token[index] = (struct rtl_mcast_token) { 0 };
		state->tokens--;
	}
	if (!state->lan_ready)
		return 0;
	for (port = 0; port < RTL_MCAST_LAN_PORTS; port++)
		if (rtl_l2_owner_has(owner->published[RTL_L2_SHARED_MC_FIB],
				     state->lan_action[port]))
			return 0;
	for (port = 0; port < RTL_MCAST_LAN_PORTS; port++) {
		ret = rtl_l2_owner_abort(owner, io, RTL_L2_SHARED_MC_FIB,
					 state->lan_action[port]);
		if (ret)
			return ret;
	}
	state->lan_ready = 0;
	return 0;
}

#endif
