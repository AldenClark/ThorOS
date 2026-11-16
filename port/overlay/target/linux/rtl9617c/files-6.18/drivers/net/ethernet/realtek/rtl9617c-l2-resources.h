/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTL9617C_L2_RESOURCES_H
#define RTL9617C_L2_RESOURCES_H

#include <linux/string.h>

#include "rtl9617c-l2-table.h"

/* The fabric owner allocates rows and row_index with kvcalloc, outside its
 * spinlocked admission path, and serializes all journal access with fe->lock.
 * rows/count remain in that owner so retaining a failed transaction never
 * depends on a temporary plan's lifetime.  The index stores snapshot+1: zero
 * means unowned, NOT that the corresponding hardware row is unused.
 *
 * This is a rollback journal, not a free-resource detector.  In particular,
 * VLAN_FIB is shared by LAN/WAN-S/WAN-C index tables, and a zero MC_FIB may
 * still be referenced by a vector.  The policy owner must establish exclusive
 * ownership before calling replace; this helper never scans, clears or claims
 * foreign rows on its own.  FDB rows/route-DMAC pins have their own lifetime.
 */
struct rtl_l2_journal {
	unsigned short *row_index;
	unsigned int index_count, capacity;
	unsigned int table_offset[RTL_L2_TBL_COUNT];
	unsigned char quarantined, restoring, restored;
};

static inline unsigned int rtl_l2_journal_index_count(void)
{
	struct rtl_l2_table_layout layout;
	unsigned int table, count = 0;

	for (table = 0; table < RTL_L2_TBL_COUNT; table++) {
		if (rtl_l2_table_layout(table, &layout))
			return 0;
		count += layout.entries;
	}
	return count;
}

static inline int rtl_l2_journal_init(struct rtl_l2_journal *journal,
				     unsigned short *row_index,
				     unsigned int index_count,
				     unsigned int capacity)
{
	struct rtl_l2_journal next = { 0 };
	struct rtl_l2_table_layout layout;
	unsigned int table, count = 0;

	if (!journal || !row_index || !capacity || capacity > 0xffffU ||
	    index_count != rtl_l2_journal_index_count() || capacity > index_count)
		return -EINVAL;
	/* init is for a fresh, zero-initialized owner, never a way to forget a
	 * retained timeout.  release keeps the allocation attached for reuse. */
	if (journal->row_index)
		return -EBUSY;
	for (table = 0; table < RTL_L2_TBL_COUNT; table++) {
		if (rtl_l2_table_layout(table, &layout))
			return -EINVAL;
		next.table_offset[table] = count;
		count += layout.entries;
	}
	memset(row_index, 0, index_count * sizeof(*row_index));
	next.row_index = row_index;
	next.index_count = index_count;
	next.capacity = capacity;
	*journal = next;
	return 0;
}

static inline int rtl_l2_journal_slot(const struct rtl_l2_journal *journal,
				     enum rtl_l2_table table,
				     unsigned int index, unsigned int *slot)
{
	struct rtl_l2_table_layout layout;
	unsigned int offset;

	if (!journal || !journal->row_index || !slot ||
	    rtl_l2_table_layout(table, &layout) || index >= layout.entries)
		return -EINVAL;
	offset = journal->table_offset[table];
	if (offset >= journal->index_count ||
	    index >= journal->index_count - offset)
		return -EINVAL;
	*slot = offset + index;
	return 0;
}

static inline int rtl_l2_journal_find(const struct rtl_l2_journal *journal,
				     struct rtl_l2_snapshot *rows,
				     unsigned int count,
				     enum rtl_l2_table table, unsigned int index,
				     struct rtl_l2_snapshot **snapshot)
{
	unsigned int slot, entry;
	int ret;

	if (!rows || !snapshot || !journal || count > journal->capacity)
		return -EINVAL;
	ret = rtl_l2_journal_slot(journal, table, index, &slot);
	if (ret)
		return ret;
	entry = journal->row_index[slot];
	if (!entry)
		return -ENOENT;
	if (entry > count || !rows[entry - 1].valid ||
	    rows[entry - 1].table != table || rows[entry - 1].index != index)
		return -EUCLEAN;
	*snapshot = &rows[entry - 1];
	return 0;
}

static inline int rtl_l2_journal_snapshot(struct rtl_l2_journal *journal,
					 const struct rtl_dq_io *io,
					 struct rtl_l2_snapshot *rows,
					 unsigned int *count,
					 enum rtl_l2_table table,
					 unsigned int index,
					 struct rtl_l2_snapshot **snapshot)
{
	struct rtl_l2_snapshot next = { 0 }, *original;
	unsigned int slot;
	int ret;

	if (!journal || !count || !rows || !snapshot || !rtl_l2_io_valid(io) ||
	    *count > journal->capacity)
		return -EINVAL;
	if (journal->quarantined || journal->restoring)
		return -EBUSY;
	ret = rtl_l2_journal_find(journal, rows, *count, table, index, &original);
	if (!ret) {
		*snapshot = original;
		return 0;
	}
	if (ret != -ENOENT)
		return ret;
	if (*count == journal->capacity)
		return -ENOSPC;
	ret = rtl_l2_journal_slot(journal, table, index, &slot);
	if (ret)
		return ret;
	ret = rtl_l2_snapshot_take(io, &next, table, index);
	if (ret) {
		/* Even a failed READ may own the shared ACCESS/DATA window until
		 * it completes.  No later plan may overwrite its staging words. */
		journal->quarantined = 1;
		return ret;
	}
	rows[*count] = next;
	journal->row_index[slot] = *count + 1;
	*snapshot = &rows[(*count)++];
	journal->restored = 0;
	return 0;
}

static inline int rtl_l2_journal_verify(const struct rtl_dq_io *io,
				       enum rtl_l2_table table, unsigned int index,
				       const unsigned int *expected)
{
	struct rtl_l2_table_layout layout;
	unsigned int observed[RTL_L2_TABLE_MAX_WORDS], word;
	int ret;

	if (!expected || rtl_l2_table_layout(table, &layout))
		return -EINVAL;
	ret = rtl_l2_table_read(io, table, index, observed);
	if (ret)
		return ret;
	for (word = 0; word < layout.words; word++) {
		unsigned int mask = ~0U;

		/* Pinned RTL8277C L2FE_PONCLE_{KEY,FIB}_DATA2 unions.
		 * TCAM generators fill don't-care bits with ones, but reserved
		 * bits can read as zero. Verify every defined bit, not RAZ space;
		 * snapshots still retain the original raw words for restoration. */
		if (word == 2 && table == RTL_L2_TBL_CF_KEY)
			mask = 0x1f8ffU;
		else if (word == 2 && table == RTL_L2_TBL_CF_FIB)
			mask = 0x3ffU;
		if ((observed[word] ^ expected[word]) & mask)
			return -EIO;
	}
	return 0;
}

static inline int rtl_l2_journal_replace(struct rtl_l2_journal *journal,
					const struct rtl_dq_io *io,
					struct rtl_l2_snapshot *rows,
					unsigned int *count,
					enum rtl_l2_table table, unsigned int index,
					const unsigned int *words)
{
	struct rtl_l2_snapshot *snapshot;
	int ret;

	if (!words)
		return -EINVAL;
	ret = rtl_l2_journal_snapshot(journal, io, rows, count, table, index, &snapshot);
	if (ret)
		return ret;
	/* The original snapshot is owned BEFORE issuing the first DATA write.
	 * ACCESS completion alone is insufficient proof of the intended row. */
	ret = rtl_l2_table_write(io, table, index, words);
	if (!ret)
		ret = rtl_l2_journal_verify(io, table, index, words);
	if (ret)
		journal->quarantined = 1;
	return ret;
}

static inline int rtl_l2_journal_restore(struct rtl_l2_journal *journal,
					const struct rtl_dq_io *io,
					const struct rtl_l2_snapshot *rows,
					unsigned int count, unsigned int drained)
{
	struct rtl_l2_table_layout layout;
	unsigned int table, i, slot;
	int ret;

	if (!journal || !journal->row_index || !rows || !rtl_l2_io_valid(io) ||
	    count > journal->capacity)
		return -EINVAL;
	if (!drained)
		return -EBUSY;
	journal->restoring = 1;
	journal->restored = 0;
	/* A timed-out initial snapshot can leave count==0 but still own a
	 * window.  Check every journalled table window before any rollback. */
	for (table = 0; table < RTL_L2_TBL_COUNT; table++) {
		ret = rtl_l2_table_layout(table, &layout);
		if (ret)
			goto retained;
		if (io->read(io->context, layout.access) & RTL_L2_ACCESS_BUSY) {
			ret = -EBUSY;
			goto retained;
		}
	}
	/* Validate the complete ownership map before the first restoring write.
	 * Corrupt bookkeeping must never turn a foreign row into a rollback. */
	for (i = 0; i < count; i++) {
		ret = rtl_l2_journal_slot(journal, rows[i].table, rows[i].index, &slot);
		if (ret || !rows[i].valid || journal->row_index[slot] != i + 1) {
			ret = -EUCLEAN;
			goto retained;
		}
	}
	for (i = count; i; i--) {
		const struct rtl_l2_snapshot *row = &rows[i - 1];

		ret = rtl_l2_snapshot_restore(io, row);
		if (!ret)
			ret = rtl_l2_journal_verify(io, row->table, row->index, row->words);
		if (ret)
			goto retained;
	}
	/* Keep ALL snapshots, including already restored rows, until the owner
	 * also restores dependent globals/selectors and explicitly releases. */
	journal->restored = 1;
	return 0;

retained:
	journal->quarantined = 1;
	return ret;
}

static inline int rtl_l2_journal_release(struct rtl_l2_journal *journal,
					struct rtl_l2_snapshot *rows,
					unsigned int *count)
{
	if (!journal || !journal->row_index || !rows || !count ||
	    *count > journal->capacity)
		return -EINVAL;
	if (!journal->restored)
		return -EBUSY;
	memset(rows, 0, *count * sizeof(*rows));
	memset(journal->row_index, 0,
	       journal->index_count * sizeof(*journal->row_index));
	*count = 0;
	journal->quarantined = journal->restoring = journal->restored = 0;
	return 0;
}

#endif
