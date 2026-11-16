/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTL9617C_L2_OWNER_H
#define RTL9617C_L2_OWNER_H

#include "rtl9617c-l2-domain.h"
#include "rtl9617c-l2-resources.h"

/* FE-lifetime owner of the shared VLAN/MCE tables, serialized by fe->lock.
 * The caller allocates the journal before entering the cold handoff. Cold
 * discovery runs only while NI has fenced LAN/PON admission and before NI
 * publishes any Linux producer. It is NOT a warm free-space scan.
 *
 * A VLAN slot proof says nothing about which logical ingress/egress may use
 * the LAN VID map. The native policy compiler must separately prove that
 * consumer-domain permission before calling vlan_install/retire, with its
 * actual gate and stage-drain held. Boot-valid LAN maps remain foreign.
 *
 * Published MCE recipes, vectors and their CPU provenance are immutable for
 * the entire owner lifetime. Retire drops an active producer reference, not
 * a hardware/CPU retirement proof. Capacity exhaustion returns to CPU; it
 * never clears old recipes to manufacture more capacity.
 */
#define RTL_L2_OWNER_ROWS (2U * RTL_L2_VLAN_FIB_ENTRIES + \
	RTL_L2_MC_FIB_ENTRIES + RTL_L2_MC_VECTOR_ENTRIES)
#define RTL_L2_OWNER_MC_READY ((1U << RTL_L2_SHARED_MC_FIB) | \
	(1U << RTL_L2_SHARED_MC_VECTOR))

struct rtl_l2_owner {
	struct rtl_l2_shared_ledger ledger;
	struct rtl_l2_journal journal;
	struct rtl_l2_snapshot *rows;
	unsigned int count, ready_mask;
	unsigned int installed[RTL_L2_SHARED_COUNT][RTL_L2_SHARED_WORDS];
	unsigned int published[RTL_L2_SHARED_COUNT][RTL_L2_SHARED_WORDS];
	unsigned short active[RTL_L2_SHARED_COUNT][RTL_L2_MC_VECTOR_ENTRIES];
	unsigned long long vector_actions[RTL_L2_MC_VECTOR_ENTRIES];
	unsigned short action_vectors[RTL_L2_MC_FIB_ENTRIES];
	/* fib+1, so zero denotes no reservation, including physical FIB zero. */
	unsigned short vlan_fib[RTL_L2_VLAN_IDS];
	unsigned short fib_vid[RTL_L2_VLAN_FIB_ENTRIES];
	unsigned short vlan_group[RTL_L2_VLAN_FIB_ENTRIES];
	unsigned int foreign_lan[RTL_L2_VLAN_IDS / 32U];
	unsigned int scan_reads, publications, withdrawals, aborts, failures;
	int error, mc_error;
	unsigned char sealed;
};

static inline int rtl_l2_owner_init(struct rtl_l2_owner *owner,
		struct rtl_l2_snapshot *rows, unsigned short *row_index,
		unsigned int index_count, unsigned long long generation)
{
	int ret;

	if (!owner || !rows || !row_index || !generation)
		return -EINVAL;
	if (owner->ledger.generation || owner->rows)
		return -EBUSY;
	ret = rtl_l2_journal_init(&owner->journal, row_index, index_count,
				   RTL_L2_OWNER_ROWS);
	if (ret)
		return ret;
	ret = rtl_l2_shared_init(&owner->ledger, generation);
	if (ret)
		return ret;
	owner->rows = rows;
	owner->mc_error = -EOPNOTSUPP;
	return 0;
}

static inline int rtl_l2_owner_fault(struct rtl_l2_owner *owner, int error)
{
	owner->ledger.quarantined = 1;
	owner->error = error ? error : -EIO;
	owner->failures++;
	return owner->error;
}

static inline int rtl_l2_owner_ready(const struct rtl_l2_owner *owner,
				    enum rtl_l2_shared_kind kind)
{
	return owner && owner->rows && owner->ledger.generation &&
		!owner->ledger.quarantined && !owner->journal.quarantined &&
		(unsigned int)kind < RTL_L2_SHARED_COUNT &&
		(owner->ready_mask & (1U << kind));
}

static inline int rtl_l2_owner_has(const unsigned int *bits, unsigned int index)
{
	return !!(bits[index / 32U] & (1U << (index % 32U)));
}

static inline void rtl_l2_owner_set(unsigned int *bits, unsigned int index)
{
	bits[index / 32U] |= 1U << (index % 32U);
}

static inline void rtl_l2_owner_clear(unsigned int *bits, unsigned int index)
{
	bits[index / 32U] &= ~(1U << (index % 32U));
}

static inline enum rtl_l2_table rtl_l2_owner_table(enum rtl_l2_shared_kind kind)
{
	switch (kind) {
	case RTL_L2_SHARED_VLAN_FIB: return RTL_L2_TBL_VLAN_FIB;
	case RTL_L2_SHARED_MC_FIB: return RTL_L2_TBL_MC_FIB;
	case RTL_L2_SHARED_MC_VECTOR: return RTL_L2_TBL_MC_VECTOR;
	default: return RTL_L2_TBL_COUNT;
	}
}

/* Discover ALL published direct references to the one physical FIB bank.
 * No free bits are published until all 12288 index reads have completed.
 * In particular, stale fib_idx bits under valid=0 and FIB row contents are
 * not allocation state. The cold caller excludes unpublished reservations.
 */
static inline int rtl_l2_owner_vlan_cold_scan(struct rtl_l2_owner *owner,
					     const struct rtl_dq_io *io)
{
	static const enum rtl_l2_table maps[] = {
		RTL_L2_TBL_VLAN_LAN_INDEX, RTL_L2_TBL_VLAN_WAN_S_INDEX,
		RTL_L2_TBL_VLAN_WAN_C_INDEX,
	};
	unsigned int foreign[RTL_L2_VLAN_FIB_ENTRIES / 32U] = { 0 };
	unsigned int bank, vid, word, fib;
	int ret;

	if (!owner || !owner->rows || !rtl_l2_io_valid(io))
		return -EINVAL;
	if (owner->sealed || owner->ledger.quarantined ||
	    (owner->ready_mask & (1U << RTL_L2_SHARED_VLAN_FIB)))
		return -EBUSY;
	for (bank = 0; bank < sizeof(maps) / sizeof(maps[0]); bank++) {
		for (vid = 0; vid < RTL_L2_VLAN_IDS; vid++) {
			ret = rtl_l2_table_read(io, maps[bank], vid, &word);
			if (ret)
				return rtl_l2_owner_fault(owner, ret);
			owner->scan_reads++;
			if (!(word & 1U))
				continue;
			fib = (word >> 1) & 127U;
			rtl_l2_owner_set(foreign, fib);
			if (!bank)
				rtl_l2_owner_set(owner->foreign_lan, vid);
		}
	}
	for (fib = 0; fib < RTL_L2_VLAN_FIB_ENTRIES; fib++) {
		ret = rtl_l2_shared_mark(&owner->ledger, RTL_L2_SHARED_VLAN_FIB,
					 fib, rtl_l2_owner_has(foreign, fib));
		if (ret)
			return rtl_l2_owner_fault(owner, ret);
	}
	owner->ready_mask |= 1U << RTL_L2_SHARED_VLAN_FIB;
	return 0;
}

/* The actual cold producer audit supplies every referenced vector, including
 * DFT/VLAN/FDB/CF/L3/CPU roots. This helper is not that root audit and must not
 * be called from runtime policy reconciliation. It independently reads all
 * vectors and preserves EVERY old action reference, even in an unreferenced
 * vector; neither zero action contents nor missing software users are free
 * evidence. Vector zero is the SDK's permanent empty-group sentinel.
 */
static inline int rtl_l2_owner_mc_cold_scan(struct rtl_l2_owner *owner,
		const struct rtl_dq_io *io, const unsigned int foreign_vectors[8])
{
	unsigned long long action_refs = 0;
	unsigned int vector, action, words[2];
	int ret;

	if (!owner || !owner->rows || !rtl_l2_io_valid(io) || !foreign_vectors)
		return -EINVAL;
	if (owner->sealed || owner->ledger.quarantined ||
	    (owner->ready_mask & RTL_L2_OWNER_MC_READY))
		return -EBUSY;
	for (vector = 0; vector < RTL_L2_MC_VECTOR_ENTRIES; vector++) {
		ret = rtl_l2_table_read(io, RTL_L2_TBL_MC_VECTOR, vector, words);
		if (ret) {
			owner->mc_error = ret;
			return rtl_l2_owner_fault(owner, ret);
		}
		owner->scan_reads++;
		owner->vector_actions[vector] = words[0] | ((unsigned long long)words[1] << 32);
		if (!vector && owner->vector_actions[vector]) {
			owner->mc_error = -EOPNOTSUPP;
			return -EOPNOTSUPP;
		}
		action_refs |= owner->vector_actions[vector];
	}
	for (vector = 0; vector < RTL_L2_MC_VECTOR_ENTRIES; vector++) {
		ret = rtl_l2_shared_mark(&owner->ledger, RTL_L2_SHARED_MC_VECTOR,
					 vector, !vector || rtl_l2_owner_has(foreign_vectors, vector));
		if (ret)
			return rtl_l2_owner_fault(owner, ret);
	}
	for (action = 0; action < RTL_L2_MC_FIB_ENTRIES; action++) {
		ret = rtl_l2_shared_mark(&owner->ledger, RTL_L2_SHARED_MC_FIB,
					 action, !!(action_refs & (1ULL << action)));
		if (ret)
			return rtl_l2_owner_fault(owner, ret);
	}
	owner->ready_mask |= RTL_L2_OWNER_MC_READY;
	owner->mc_error = 0;
	return 0;
}

static inline void rtl_l2_owner_seal(struct rtl_l2_owner *owner)
{
	if (owner)
		owner->sealed = 1;
}

static inline int rtl_l2_owner_reserve(struct rtl_l2_owner *owner,
		enum rtl_l2_shared_kind kind, unsigned int count, unsigned short *indices)
{
	if (!rtl_l2_owner_ready(owner, kind))
		return -EOPNOTSUPP;
	return rtl_l2_shared_claim_many(&owner->ledger, kind, count, indices);
}

static inline int rtl_l2_owner_lease(const struct rtl_l2_owner *owner,
				    enum rtl_l2_shared_kind kind, unsigned int index)
{
	if (!rtl_l2_owner_ready(owner, kind))
		return -EOPNOTSUPP;
	if (index >= rtl_l2_shared_capacity(kind))
		return -ERANGE;
	if (!rtl_l2_owner_has(owner->ledger.bank[kind].leased, index))
		return -EPERM;
	return 0;
}

/* Immutable recipe installation, before any producer publishes its index.
 * Vector dependencies are reserved before MMIO, so a timed-out vector write
 * cannot free its actions. A repeat write is not an implicit in-place update.
 */
static inline int rtl_l2_owner_write(struct rtl_l2_owner *owner,
		const struct rtl_dq_io *io, enum rtl_l2_shared_kind kind,
		unsigned int index, const unsigned int *words)
{
	unsigned long long mask = 0;
	unsigned int action;
	int ret = rtl_l2_owner_lease(owner, kind, index);

	if (ret)
		return ret;
	if (!rtl_l2_io_valid(io) || !words)
		return -EINVAL;
	if (rtl_l2_owner_has(owner->published[kind], index) ||
	    rtl_l2_owner_has(owner->installed[kind], index))
		return -EBUSY;
	if (kind == RTL_L2_SHARED_MC_FIB && owner->action_vectors[index])
		return -EBUSY;
	if (kind == RTL_L2_SHARED_MC_VECTOR) {
		mask = words[0] | ((unsigned long long)words[1] << 32);
		if (!mask || !index)
			return -EINVAL;
		for (action = 0; action < RTL_L2_MC_FIB_ENTRIES; action++) {
			if (!(mask & (1ULL << action)))
				continue;
			ret = rtl_l2_owner_lease(owner, RTL_L2_SHARED_MC_FIB, action);
			if (ret || !rtl_l2_owner_has(owner->installed[RTL_L2_SHARED_MC_FIB], action))
				return ret ? ret : -EINVAL;
		}
		owner->vector_actions[index] = mask;
		for (action = 0; action < RTL_L2_MC_FIB_ENTRIES; action++)
			if (mask & (1ULL << action))
				owner->action_vectors[action]++;
	}
	ret = rtl_l2_journal_replace(&owner->journal, io, owner->rows, &owner->count,
				     rtl_l2_owner_table(kind), index, words);
	if (ret)
		return rtl_l2_owner_fault(owner, ret);
	rtl_l2_owner_set(owner->installed[kind], index);
	return 0;
}

/* Must precede the producer's FIRST possible MMIO publication, not follow
 * its success return. A timeout may have published it and permanently pins
 * the complete dependency chain. Active counts are bookkeeping, not drain.
 */
static inline int rtl_l2_owner_publish(struct rtl_l2_owner *owner,
				      enum rtl_l2_shared_kind kind, unsigned int index)
{
	unsigned int action;
	int ret = rtl_l2_owner_lease(owner, kind, index);

	if (ret)
		return ret;
	if (!rtl_l2_owner_has(owner->installed[kind], index))
		return -EINVAL;
	if (owner->active[kind][index] == 0xffffU)
		return -EOVERFLOW;
	if (kind == RTL_L2_SHARED_MC_VECTOR) {
		for (action = 0; action < RTL_L2_MC_FIB_ENTRIES; action++)
			if ((owner->vector_actions[index] & (1ULL << action)) &&
			    owner->active[RTL_L2_SHARED_MC_FIB][action] == 0xffffU)
				return -EOVERFLOW;
		for (action = 0; action < RTL_L2_MC_FIB_ENTRIES; action++) {
			if (!(owner->vector_actions[index] & (1ULL << action)))
				continue;
			rtl_l2_owner_set(owner->published[RTL_L2_SHARED_MC_FIB], action);
			owner->active[RTL_L2_SHARED_MC_FIB][action]++;
		}
	}
	rtl_l2_owner_set(owner->published[kind], index);
	owner->active[kind][index]++;
	owner->publications++;
	return 0;
}

/* Call only AFTER that exact producer was withdrawn and read back. This
 * never releases a slot or authorizes reusing an old CPU-copy identity. */
static inline int rtl_l2_owner_retire(struct rtl_l2_owner *owner,
				     enum rtl_l2_shared_kind kind, unsigned int index)
{
	unsigned int action;
	int ret = rtl_l2_owner_lease(owner, kind, index);

	if (ret)
		return ret;
	if (!owner->active[kind][index])
		return -ENOENT;
	if (kind == RTL_L2_SHARED_MC_VECTOR) {
		for (action = 0; action < RTL_L2_MC_FIB_ENTRIES; action++)
			if ((owner->vector_actions[index] & (1ULL << action)) &&
			    !owner->active[RTL_L2_SHARED_MC_FIB][action])
				return rtl_l2_owner_fault(owner, -EUCLEAN);
		for (action = 0; action < RTL_L2_MC_FIB_ENTRIES; action++)
			if (owner->vector_actions[index] & (1ULL << action))
				owner->active[RTL_L2_SHARED_MC_FIB][action]--;
	}
	owner->active[kind][index]--;
	owner->withdrawals++;
	return 0;
}

/* Only a never-published, unreferenced preparation can be rolled back and
 * unreserved. A failed/uncertain command keeps the journal and every lease.
 * The original snapshot remains indexed for a later reservation of this row.
 */
static inline int rtl_l2_owner_abort(struct rtl_l2_owner *owner,
		const struct rtl_dq_io *io, enum rtl_l2_shared_kind kind, unsigned int index)
{
	struct rtl_l2_snapshot *snapshot;
	unsigned int action;
	int ret = rtl_l2_owner_lease(owner, kind, index);

	if (ret)
		return ret;
	if (!rtl_l2_io_valid(io))
		return -EINVAL;
	if (rtl_l2_owner_has(owner->published[kind], index) || owner->active[kind][index] ||
	    (kind == RTL_L2_SHARED_MC_FIB && owner->action_vectors[index]))
		return -EBUSY;
	if (rtl_l2_owner_has(owner->installed[kind], index)) {
		ret = rtl_l2_journal_find(&owner->journal, owner->rows, owner->count,
					 rtl_l2_owner_table(kind), index, &snapshot);
		if (!ret)
			ret = rtl_l2_snapshot_restore(io, snapshot);
		if (!ret)
			ret = rtl_l2_journal_verify(io, snapshot->table, snapshot->index, snapshot->words);
		if (ret)
			return rtl_l2_owner_fault(owner, ret);
		if (kind == RTL_L2_SHARED_MC_VECTOR) {
			for (action = 0; action < RTL_L2_MC_FIB_ENTRIES; action++)
				if (owner->vector_actions[index] & (1ULL << action))
					owner->action_vectors[action]--;
			owner->vector_actions[index] = 0;
		}
	}
	rtl_l2_owner_clear(owner->installed[kind], index);
	rtl_l2_owner_clear(owner->ledger.bank[kind].leased, index);
	if (kind == RTL_L2_SHARED_VLAN_FIB && owner->fib_vid[index]) {
		owner->vlan_fib[owner->fib_vid[index]] = 0;
		owner->fib_vid[index] = 0;
	}
	owner->aborts++;
	return 0;
}

/* Reserve an entire VLAN plan atomically. The same VID keeps its physical
 * FIB across native stop/start; it is never reassigned to a different VID.
 * No table writes occur on allocation or capacity failure. */
static inline int rtl_l2_owner_vlan_reserve(struct rtl_l2_owner *owner,
		const struct rtl_l2_vlan_plan *plan, unsigned short *indices)
{
	unsigned short claimed[RTL_L2_VLAN_FIB_ENTRIES];
	unsigned int i, j, needed = 0, next = 0, vid;
	int ret;

	if (!rtl_l2_owner_ready(owner, RTL_L2_SHARED_VLAN_FIB))
		return -EOPNOTSUPP;
	if (!plan || !indices || !plan->count || plan->count > RTL_L2_VLAN_FIB_ENTRIES)
		return -EINVAL;
	for (i = 0; i < plan->count; i++) {
		vid = plan->vlans[i].vid;
		if (!vid || vid >= RTL_L2_VLAN_IDS - 1)
			return -EINVAL;
		if (rtl_l2_owner_has(owner->foreign_lan, vid))
			return -EADDRINUSE;
		for (j = 0; j < i; j++)
			if (plan->vlans[j].vid == vid)
				return -EINVAL;
		if (!owner->vlan_fib[vid])
			needed++;
		else if (rtl_l2_owner_lease(owner, RTL_L2_SHARED_VLAN_FIB,
					    owner->vlan_fib[vid] - 1))
			return rtl_l2_owner_fault(owner, -EUCLEAN);
	}
	ret = rtl_l2_owner_reserve(owner, RTL_L2_SHARED_VLAN_FIB, needed, claimed);
	if (ret)
		return ret;
	for (i = 0; i < plan->count; i++) {
		vid = plan->vlans[i].vid;
		if (!owner->vlan_fib[vid]) {
			owner->vlan_fib[vid] = claimed[next++] + 1;
			owner->fib_vid[owner->vlan_fib[vid] - 1] = vid;
		}
		indices[i] = owner->vlan_fib[vid] - 1;
	}
	return 0;
}

/* The policy owner has gated actual consumers and drained the VLAN lookup
 * stages before entry. An active index must be retired first. Snapshot and
 * install the FIB BEFORE making the LAN map valid; the reverse dependency
 * order is retained by the journal. Never touch WAN index tables here.
 */
static inline int rtl_l2_owner_vlan_install(struct rtl_l2_owner *owner,
		const struct rtl_dq_io *io, unsigned int vid, const unsigned int words[2])
{
	struct rtl_l2_snapshot *fib_before, *map_before;
	unsigned int fib, current, index_word, value[2], group;
	int ret;

	if (!owner || !rtl_l2_io_valid(io) || !words || !vid ||
	    vid >= RTL_L2_VLAN_IDS - 1 || !owner->vlan_fib[vid])
		return -EINVAL;
	fib = owner->vlan_fib[vid] - 1;
	ret = rtl_l2_owner_lease(owner, RTL_L2_SHARED_VLAN_FIB, fib);
	if (ret)
		return ret;
	if (owner->active[RTL_L2_SHARED_VLAN_FIB][fib])
		return -EBUSY;
	group = words[1] & 1023U;
	if (group && (group >= RTL_L2_MC_VECTOR_ENTRIES ||
	    rtl_l2_owner_lease(owner, RTL_L2_SHARED_MC_VECTOR, group) ||
	    !rtl_l2_owner_has(owner->installed[RTL_L2_SHARED_MC_VECTOR], group)))
		return -EOPNOTSUPP;
	ret = rtl_l2_table_read(io, RTL_L2_TBL_VLAN_LAN_INDEX, vid, &current);
	if (ret)
		return rtl_l2_owner_fault(owner, ret);
	if (current & 1U)
		return rtl_l2_owner_fault(owner, -EADDRINUSE);
	ret = rtl_l2_journal_snapshot(&owner->journal, io, owner->rows, &owner->count,
				      RTL_L2_TBL_VLAN_FIB, fib, &fib_before);
	if (!ret)
		ret = rtl_l2_journal_snapshot(&owner->journal, io, owner->rows, &owner->count,
					      RTL_L2_TBL_VLAN_LAN_INDEX, vid, &map_before);
	if (ret)
		return rtl_l2_owner_fault(owner, ret);
	if (map_before->words[0] & 1U)
		return rtl_l2_owner_fault(owner, -EADDRINUSE);
	value[0] = words[0];
	value[1] = (fib_before->words[1] & ~1023U) | group;
	ret = rtl_l2_journal_replace(&owner->journal, io, owner->rows, &owner->count,
				     RTL_L2_TBL_VLAN_FIB, fib, value);
	if (ret)
		return rtl_l2_owner_fault(owner, ret);
	rtl_l2_owner_set(owner->installed[RTL_L2_SHARED_VLAN_FIB], fib);
	ret = rtl_l2_vlan_index_build(fib, 1, map_before->words[0], &index_word);
	if (!ret && group)
		ret = rtl_l2_owner_publish(owner, RTL_L2_SHARED_MC_VECTOR, group);
	if (!ret)
		ret = rtl_l2_owner_publish(owner, RTL_L2_SHARED_VLAN_FIB, fib);
	if (ret)
		return rtl_l2_owner_fault(owner, ret);
	owner->vlan_group[fib] = group;
	ret = rtl_l2_journal_replace(&owner->journal, io, owner->rows, &owner->count,
				     RTL_L2_TBL_VLAN_LAN_INDEX, vid, &index_word);
	return ret ? rtl_l2_owner_fault(owner, ret) : 0;
}

static inline int rtl_l2_owner_vlan_retire(struct rtl_l2_owner *owner,
					 const struct rtl_dq_io *io, unsigned int vid)
{
	struct rtl_l2_snapshot *original;
	unsigned int fib, current, group;
	int ret;

	if (!owner || !rtl_l2_io_valid(io) || !vid || vid >= RTL_L2_VLAN_IDS - 1 ||
	    !owner->vlan_fib[vid])
		return -EINVAL;
	fib = owner->vlan_fib[vid] - 1;
	ret = rtl_l2_owner_lease(owner, RTL_L2_SHARED_VLAN_FIB, fib);
	if (ret)
		return ret;
	if (!owner->active[RTL_L2_SHARED_VLAN_FIB][fib])
		return 0;
	ret = rtl_l2_table_read(io, RTL_L2_TBL_VLAN_LAN_INDEX, vid, &current);
	if (ret)
		return rtl_l2_owner_fault(owner, ret);
	if (!(current & 1U) || ((current >> 1) & 127U) != fib)
		return rtl_l2_owner_fault(owner, -EUCLEAN);
	ret = rtl_l2_journal_find(&owner->journal, owner->rows, owner->count,
				 RTL_L2_TBL_VLAN_LAN_INDEX, vid, &original);
	if (!ret)
		ret = rtl_l2_journal_replace(&owner->journal, io, owner->rows, &owner->count,
					     RTL_L2_TBL_VLAN_LAN_INDEX, vid, original->words);
	if (ret)
		return rtl_l2_owner_fault(owner, ret);
	group = owner->vlan_group[fib];
	if (group) {
		ret = rtl_l2_owner_retire(owner, RTL_L2_SHARED_MC_VECTOR, group);
		if (ret)
			return ret;
	}
	return rtl_l2_owner_retire(owner, RTL_L2_SHARED_VLAN_FIB, fib);
}

/* Final software-memory release is allowed only when no reserved/published
 * hardware object can depend on it. This is additional to FE's existing
 * DMA/prepared/callback lifetime checks, never a replacement for them. */
static inline int rtl_l2_owner_retained(const struct rtl_l2_owner *owner)
{
	unsigned int kind;

	if (!owner)
		return 0;
	if (owner->ledger.quarantined || owner->journal.quarantined)
		return 1;
	for (kind = 0; kind < RTL_L2_SHARED_COUNT; kind++)
		if (rtl_l2_shared_leased(&owner->ledger, kind))
			return 1;
	return 0;
}

#endif
