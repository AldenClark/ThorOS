/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_FE_AGE_H
#define RTL9617C_FE_AGE_H

#include "rtl9617c-fe-table.h"

/* The pinned RTL77C SDK aal_hash_traffic_status_get() reads and acknowledges
 * one 32-entry age row. This is a serialized read/modify/write, NOT an atomic
 * hardware read-and-clear. Only acknowledge active slots whose live software
 * owners were selected under the same FE mutex. Preserve invalid, retiring,
 * unowned and idle slots, including their complete four-bit age values.
 *
 * The caller may publish the returned activity only after the write completed.
 * A timeout leaves its DATA window owned by the in-flight command; the next
 * indirect access must enforce the usual idle-before-command rule.
 */
static inline int rtl_fe_main_age_batch(const struct rtl_dq_io *io,
		unsigned int first, unsigned int owned, unsigned int probe,
		unsigned int *activity)
{
	unsigned int words[4], hits = 0, dirty = 0, i, age, shift;
	int ret;

	if (!io || !io->read || !io->write || !io->indirect || !activity ||
	    first >= RTL_FE_HASH_ENTRIES || (first & 31U) || !owned ||
	    probe >= 32 || !(owned & (1U << probe)))
		return -EINVAL;
	ret = io->indirect(io->context, 0x3928, 0x80000000U | (first >> 5));
	if (ret)
		return ret;
	/* Preserve the old idle cost: one command and one DATA read. Do not
	 * acknowledge another owner's activity just because this probe is idle.
	 * aal_hash_age_set() confirms that a completed row READ populates all
	 * DATA words, and a subsequent WRITE may modify only selected words.
	 */
	words[probe >> 3] = io->read(io->context, 0x3938 - (probe >> 3) * 4);
	if (((words[probe >> 3] >> ((probe & 7U) * 4)) & 15U) <= 1) {
		*activity = 0;
		return 0;
	}
	for (i = 0; i < 4; i++)
		if (i != (probe >> 3) && (owned & (255U << (i * 8))))
			words[i] = io->read(io->context, 0x3938 - i * 4);
	for (i = 0; i < 32; i++) {
		if (!(owned & (1U << i)))
			continue;
		shift = (i & 7U) * 4;
		age = (words[i >> 3] >> shift) & 15U;
		if (age <= 1)
			continue;
		hits |= 1U << i;
		words[i >> 3] = (words[i >> 3] & ~(15U << shift)) | (1U << shift);
		dirty |= 1U << (i >> 3);
	}
	/* An entirely idle row requires no write transaction. */
	if (hits) {
		for (i = 0; i < 4; i++)
			if (dirty & (1U << i))
				io->write(io->context, 0x3938 - i * 4, words[i]);
		ret = io->indirect(io->context, 0x3928, 0xc0000000U | (first >> 5));
		if (ret)
			return ret;
	}
	*activity = hits;
	return 0;
}

#endif
