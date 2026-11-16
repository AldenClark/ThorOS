/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTL9617C_L2_DOMAIN_H
#define RTL9617C_L2_DOMAIN_H

#include <linux/errno.h>
#include <linux/string.h>

#include "rtl9617c-l2-format.h"

/* The VLAN/MCE tables are shared by UNI, PON and FE. A zero row is not a
 * free row, and an unreferenced row is not necessarily unowned: PON may be
 * preparing an unpublished consumer. Only the shared fabric owner, holding
 * its exclusion lock, can supply a verified-free bit after checking every
 * relevant producer and consumer. This ledger never takes that proof itself.
 * Initialize the ledger in zeroed owner storage; never reinitialize a live
 * generation to erase a retained or uncertain lease.
 *
 * In particular, do not use it to turn on hardware BUM. Reusing an MCE
 * action additionally requires proof that old hardware references and old
 * CPU copies have both retired. An ambiguous transaction keeps ALL leases.
 */
enum rtl_l2_shared_kind {
	RTL_L2_SHARED_VLAN_FIB,
	RTL_L2_SHARED_MC_FIB,
	RTL_L2_SHARED_MC_VECTOR,
	RTL_L2_SHARED_COUNT,
};

#define RTL_L2_SHARED_WORDS (RTL_L2_MC_VECTOR_ENTRIES / 32U)

struct rtl_l2_shared_bank {
	unsigned int foreign[RTL_L2_SHARED_WORDS];
	unsigned int verified_free[RTL_L2_SHARED_WORDS];
	unsigned int leased[RTL_L2_SHARED_WORDS];
	unsigned int capacity;
};

struct rtl_l2_shared_ledger {
	struct rtl_l2_shared_bank bank[RTL_L2_SHARED_COUNT];
	unsigned long long generation;
	unsigned char quarantined;
};

static inline unsigned int rtl_l2_shared_capacity(enum rtl_l2_shared_kind kind)
{
	switch (kind) {
	case RTL_L2_SHARED_VLAN_FIB:
		return RTL_L2_VLAN_FIB_ENTRIES;
	case RTL_L2_SHARED_MC_FIB:
		return RTL_L2_MC_FIB_ENTRIES;
	case RTL_L2_SHARED_MC_VECTOR:
		return RTL_L2_MC_VECTOR_ENTRIES;
	default:
		return 0;
	}
}

static inline unsigned int rtl_l2_shared_popcount(unsigned int value)
{
	/* No libgcc __popcountsi2 helper dependency in a freestanding kernel. */
	value -= (value >> 1) & 0x55555555U;
	value = (value & 0x33333333U) + ((value >> 2) & 0x33333333U);
	value = (value + (value >> 4)) & 0x0f0f0f0fU;
	return (value * 0x01010101U) >> 24;
}

static inline int rtl_l2_shared_init(struct rtl_l2_shared_ledger *ledger,
				     unsigned long long generation)
{
	unsigned int kind;

	if (!ledger || !generation)
		return -EINVAL;
	if (ledger->generation)
		return -EBUSY; /* A retained transaction cannot be reinitialized. */
	memset(ledger, 0, sizeof(*ledger));
	ledger->generation = generation;
	for (kind = 0; kind < RTL_L2_SHARED_COUNT; kind++)
		ledger->bank[kind].capacity = rtl_l2_shared_capacity(kind);
	return 0;
}

static inline int rtl_l2_shared_mark(struct rtl_l2_shared_ledger *ledger,
				     enum rtl_l2_shared_kind kind,
				     unsigned int index, unsigned int is_foreign)
{
	struct rtl_l2_shared_bank *bank;
	unsigned int word, mask;

	if (!ledger || !ledger->generation ||
	    (unsigned int)kind >= RTL_L2_SHARED_COUNT || is_foreign > 1)
		return -EINVAL;
	if (ledger->quarantined)
		return -EBUSY;
	bank = &ledger->bank[kind];
	if (index >= bank->capacity)
		return -ERANGE;
	word = index / 32;
	mask = 1U << (index % 32);
	if (bank->leased[word] & mask) {
		/* A new foreign claimant after allocation is a shared-owner fault.
		 * Keep all leases and block further writes/allocations. */
		if (is_foreign)
			ledger->quarantined = 1;
		return -EBUSY;
	}
	if (is_foreign) {
		if (bank->verified_free[word] & mask) {
			/* A newer consumer invalidates the free proof, even if the
			 * caller ignores EAGAIN and retries allocation. */
			bank->verified_free[word] &= ~mask;
			bank->foreign[word] |= mask;
			return -EAGAIN;
		}
		bank->foreign[word] |= mask;
	} else {
		if (bank->foreign[word] & mask)
			return -EBUSY;
		bank->verified_free[word] |= mask;
	}
	return 0;
}

static inline int rtl_l2_shared_claim(struct rtl_l2_shared_ledger *ledger,
				      enum rtl_l2_shared_kind kind,
				      unsigned int *index)
{
	struct rtl_l2_shared_bank *bank;
	unsigned int i, word, mask;

	if (!ledger || !index || !ledger->generation ||
	    (unsigned int)kind >= RTL_L2_SHARED_COUNT)
		return -EINVAL;
	if (ledger->quarantined)
		return -EBUSY;
	bank = &ledger->bank[kind];
	for (i = 0; i < bank->capacity; i++) {
		word = i / 32;
		mask = 1U << (i % 32);
		if (!(bank->verified_free[word] & mask) ||
		    ((bank->foreign[word] | bank->leased[word]) & mask))
			continue;
		bank->leased[word] |= mask;
		*index = i;
		return 0;
	}
	return -ENOSPC;
}

static inline unsigned int rtl_l2_shared_leased(const struct rtl_l2_shared_ledger *ledger,
						 enum rtl_l2_shared_kind kind)
{
	unsigned int count = 0, i;

	if (!ledger || (unsigned int)kind >= RTL_L2_SHARED_COUNT)
		return 0;
	for (i = 0; i < RTL_L2_SHARED_WORDS; i++)
		count += rtl_l2_shared_popcount(ledger->bank[kind].leased[i]);
	return count;
}

/* A preflight may need several MC_FIB actions and one vector, or one FIB per
 * VLAN. Check the entire demand BEFORE the first lease. No partial resource
 * ownership may escape an ENOSPC from planning. Locking is external. */
static inline unsigned int rtl_l2_shared_available(const struct rtl_l2_shared_ledger *ledger,
						   enum rtl_l2_shared_kind kind)
{
	const struct rtl_l2_shared_bank *bank;
	unsigned int i, available = 0;

	if (!ledger || ledger->quarantined || !ledger->generation ||
	    (unsigned int)kind >= RTL_L2_SHARED_COUNT)
		return 0;
	bank = &ledger->bank[kind];
	for (i = 0; i < RTL_L2_SHARED_WORDS; i++)
		available += rtl_l2_shared_popcount(bank->verified_free[i] &
			~(bank->foreign[i] | bank->leased[i]));
	return available;
}

static inline int rtl_l2_shared_claim_many(struct rtl_l2_shared_ledger *ledger,
					   enum rtl_l2_shared_kind kind,
					   unsigned int count,
					   unsigned short *indices)
{
	unsigned int i, index;
	int ret;

	if (!ledger || (!indices && count) ||
	    (unsigned int)kind >= RTL_L2_SHARED_COUNT)
		return -EINVAL;
	if (count > rtl_l2_shared_available(ledger, kind))
		return -ENOSPC;
	for (i = 0; i < count; i++) {
		ret = rtl_l2_shared_claim(ledger, kind, &index);
		if (ret)
			return ret; /* Impossible while the external owner lock is held. */
		indices[i] = index;
	}
	return 0;
}

static inline int rtl_l2_shared_mc_group_claim(struct rtl_l2_shared_ledger *ledger,
						unsigned int actions,
						unsigned short *vector,
						unsigned short *action_indices)
{
	int ret;

	if (!ledger || !vector || !action_indices || !actions ||
	    actions > RTL_L2_MC_FIB_ENTRIES)
		return -EINVAL;
	if (!rtl_l2_shared_available(ledger, RTL_L2_SHARED_MC_VECTOR) ||
	    actions > rtl_l2_shared_available(ledger, RTL_L2_SHARED_MC_FIB))
		return -ENOSPC;
	ret = rtl_l2_shared_claim_many(ledger, RTL_L2_SHARED_MC_VECTOR, 1, vector);
	if (!ret)
		ret = rtl_l2_shared_claim_many(ledger, RTL_L2_SHARED_MC_FIB,
					      actions, action_indices);
	return ret;
}

static inline int rtl_l2_shared_release(struct rtl_l2_shared_ledger *ledger,
					unsigned int tables_restored,
					unsigned int datapath_drained,
					unsigned int cpu_copies_retired)
{
	unsigned int kind;

	if (!ledger || !ledger->generation)
		return -EINVAL;
	/* Keep the leases even after an apparently successful MMIO rollback:
	 * stale MCE references or EPP/GRO CPU copies can outlive that command. */
	if (!tables_restored || !datapath_drained || !cpu_copies_retired ||
	    ledger->quarantined)
		return -EBUSY;
	for (kind = 0; kind < RTL_L2_SHARED_COUNT; kind++) {
		memset(ledger->bank[kind].leased, 0,
		       sizeof(ledger->bank[kind].leased));
		/* A previous free-row proof is invalid after an owner transition. */
		memset(ledger->bank[kind].verified_free, 0,
		       sizeof(ledger->bank[kind].verified_free));
	}
	return 0;
}

/* Pure Linux-bridge -> silicon VLAN table compiler. This emits row contents,
 * not an authorization to write shared tables. The caller must prove IVL
 * namespace ownership, acquire each row above and use the verified rollback
 * journal. It is deliberately independent of the running SVL/VID0 backend.
 */
#define RTL_L2_DOMAIN_LAN_PORTS 5U
#define RTL_L2_DOMAIN_LAN_MASK ((1U << RTL_L2_DOMAIN_LAN_PORTS) - 1U)
#define RTL_L2_DOMAIN_MAX_VLANS RTL_L2_VLAN_FIB_ENTRIES

struct rtl_l2_vlan_spec {
	unsigned short vid, bridge;
	unsigned short members, untagged, pvid;
	unsigned short forwarding, learning, isolated;
};

struct rtl_l2_vlan_plan {
	struct rtl_l2_vlan_spec vlans[RTL_L2_DOMAIN_MAX_VLANS];
	unsigned short count;
	unsigned short port_bridge[RTL_L2_DOMAIN_LAN_PORTS];
	unsigned short port_pvid[RTL_L2_DOMAIN_LAN_PORTS];
};

static inline int rtl_l2_vlan_plan_claim(struct rtl_l2_shared_ledger *ledger,
					 const struct rtl_l2_vlan_plan *plan,
					 unsigned short *fib_indices)
{
	if (!plan || !plan->count || plan->count > RTL_L2_DOMAIN_MAX_VLANS ||
	    !fib_indices)
		return -EINVAL;
	return rtl_l2_shared_claim_many(ledger, RTL_L2_SHARED_VLAN_FIB,
					      plan->count, fib_indices);
}

static inline int rtl_l2_vlan_spec_validate(const struct rtl_l2_vlan_spec *spec)
{
	if (!spec || !spec->vid || spec->vid >= RTL_L2_VLAN_IDS - 1 ||
	    !spec->bridge || !spec->members ||
	    (spec->members & ~RTL_L2_DOMAIN_LAN_MASK) ||
	    (spec->untagged & ~spec->members) ||
	    (spec->pvid & ~spec->untagged) ||
	    (spec->forwarding & ~spec->members) ||
	    (spec->learning & ~spec->forwarding) ||
	    (spec->isolated & ~spec->members))
		return -EINVAL;
	return 0;
}

static inline int rtl_l2_vlan_plan_add(struct rtl_l2_vlan_plan *plan,
				       const struct rtl_l2_vlan_spec *spec)
{
	struct rtl_l2_vlan_spec merged;
	unsigned int port, i;

	if (!plan || plan->count > RTL_L2_DOMAIN_MAX_VLANS ||
	    rtl_l2_vlan_spec_validate(spec))
		return -EINVAL;
	for (i = 0; i < plan->count; i++)
		if (plan->vlans[i].vid == spec->vid)
			break;
	if (i < plan->count && plan->vlans[i].bridge != spec->bridge)
		return -EADDRINUSE; /* The FDB key has no separate bridge FID. */
	if (i == plan->count && plan->count == RTL_L2_DOMAIN_MAX_VLANS)
		return -ENOSPC;
	merged = i == plan->count ? *spec : plan->vlans[i];
	if (i < plan->count) {
		/* Two separate port-object notifications for the same VID form one
		 * VLAN, but contradictory flags on an existing port are invalid. */
		unsigned int common = merged.members & spec->members;

		if (((merged.untagged ^ spec->untagged) & common) ||
		    ((merged.pvid ^ spec->pvid) & common) ||
		    ((merged.forwarding ^ spec->forwarding) & common) ||
		    ((merged.learning ^ spec->learning) & common) ||
		    ((merged.isolated ^ spec->isolated) & common))
			return -EINVAL;
		merged.members |= spec->members;
		merged.untagged |= spec->untagged;
		merged.pvid |= spec->pvid;
		merged.forwarding |= spec->forwarding;
		merged.learning |= spec->learning;
		merged.isolated |= spec->isolated;
	}
	for (port = 0; port < RTL_L2_DOMAIN_LAN_PORTS; port++) {
		if (!(spec->members & (1U << port)))
			continue;
		if (plan->port_bridge[port] && plan->port_bridge[port] != spec->bridge)
			return -EADDRINUSE;
		if ((spec->pvid & (1U << port)) && plan->port_pvid[port] &&
		    plan->port_pvid[port] != spec->vid)
			return -EADDRINUSE;
	}
	for (port = 0; port < RTL_L2_DOMAIN_LAN_PORTS; port++) {
		if (spec->members & (1U << port))
			plan->port_bridge[port] = spec->bridge;
		if (spec->pvid & (1U << port))
			plan->port_pvid[port] = spec->vid;
	}
	plan->vlans[i] = merged;
	if (i == plan->count)
		plan->count++;
	return 0;
}

/* Ingress egress eligibility: port membership and STP (including isolation)
 * are still independently enforced by the owner. VLAN_FIB membership alone
 * is insufficient for either full STP semantics or per-source filtering. */
static inline int rtl_l2_vlan_fib_build(const struct rtl_l2_vlan_spec *spec,
				       unsigned int group,
				       const unsigned int original[2],
				       unsigned int result[2])
{
	if (!original || !result || rtl_l2_vlan_spec_validate(spec) ||
	    group > 1023)
		return -EINVAL;
	result[0] = original[0];
	result[1] = original[1];
	rtl_l2_field_set(result, RTL_L2_VLAN_FIB_UNTAG, spec->untagged);
	rtl_l2_field_set(result, RTL_L2_VLAN_FIB_MEMBERS, spec->members);
	rtl_l2_field_set(result, RTL_L2_VLAN_FIB_GROUP, group);
	return 0;
}

static inline int rtl_l2_vlan_index_build(unsigned int fib,
					 unsigned int valid, unsigned int original,
					 unsigned int *result)
{
	unsigned int word;

	if (!result || fib >= RTL_L2_VLAN_FIB_ENTRIES || valid > 1)
		return -EINVAL;
	word = original;
	rtl_l2_field_set(&word, RTL_L2_VLAN_INDEX_FIB, fib);
	rtl_l2_field_set(&word, RTL_L2_VLAN_INDEX_VALID, valid);
	*result = word;
	return 0;
}

/* Exact no-edit multicast action: the bitmap points to MCFIB ACTION slots,
 * not ports. No CPU-copy action may be published before its provenance and
 * retirement contract are independently verified by the datapath owner. */
static inline int rtl_l2_mc_noedit_build(unsigned int destination,
				unsigned int keep_source,
				unsigned int policer_id,
				unsigned int cpu_copy_verified,
				unsigned int words[3])
{
	unsigned int output[3] = { 0 };

	if (!words || destination >= RTL_L2_LOGICAL_PORTS || keep_source > 1 ||
	    policer_id > 511 || cpu_copy_verified > 1)
		return -EINVAL;
	if (destination == 16 && !cpu_copy_verified)
		return -EOPNOTSUPP;
	rtl_l2_field_set(output, RTL_L2_MC_DESTINATION, destination);
	rtl_l2_field_set(output, RTL_L2_MC_POLICER_ID, policer_id);
	rtl_l2_field_set(output, RTL_L2_MC_COS_COMMAND, RTL_L2_MC_COS_KEEP);
	rtl_l2_field_set(output, RTL_L2_MC_KEEP_ORIGINAL_SOURCE_PORT, keep_source);
	memcpy(words, output, sizeof(output));
	return 0;
}

static inline int rtl_l2_mc_vector_build(unsigned long long action_mask,
					  unsigned int words[2])
{
	if (!words || !action_mask)
		return -EINVAL;
	rtl_l2_bitmap_encode(words, action_mask);
	return 0;
}

static inline int rtl_l2_dft_flood_build(unsigned int vector,
					 unsigned int original,
					 unsigned int *result)
{
	unsigned int word = original;

	if (!result || vector >= RTL_L2_MC_VECTOR_ENTRIES)
		return -EINVAL;
	rtl_l2_field_set(&word, RTL_L2_DFT_DENY, 0);
	rtl_l2_field_set(&word, RTL_L2_DFT_GROUP, vector);
	rtl_l2_field_set(&word, RTL_L2_DFT_REDIRECT, 0);
	rtl_l2_field_set(&word, RTL_L2_DFT_GROUP_VALID, 1);
	*result = word;
	return 0;
}

#endif
