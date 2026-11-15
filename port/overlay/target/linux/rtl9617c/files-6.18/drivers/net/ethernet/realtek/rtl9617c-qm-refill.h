/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_QM_REFILL_H
#define RTL9617C_QM_REFILL_H

#include "rtl9617c-qm-resources.h"

struct rtl_qm_refill {
	unsigned int address[RTL_QM_CPU_EQ_COUNT][RTL_QM_REFILL_SIZE];
	unsigned int head[RTL_QM_CPU_EQ_COUNT], count[RTL_QM_CPU_EQ_COUNT], pending;
	unsigned int retries, returned, peak;
	unsigned int credit[RTL_QM_CPU_EQ_COUNT];
};

/* Each queue holds at most all of its hardware pool's buffers. The caller checks
 * space before retiring an EPP entry; only NAPI changes queue ownership. */
static inline void rtl_qm_refill_add(struct rtl_qm_refill *queue, unsigned int command)
{
	unsigned int eq = (command & 15) - RTL_QM_CPU_EQ_FIRST;
	unsigned int tail = (queue->head[eq] + queue->count[eq]) % RTL_QM_REFILL_SIZE;

	queue->address[eq][tail] = command & 0xffffff80U;
	queue->count[eq]++;
	queue->pending++;
	if (queue->pending > queue->peak)
		queue->peak = queue->pending;
}

static inline void rtl_qm_refill_drain(struct rtl_qm_refill *queue, void *context,
	int (*push)(void *context, unsigned int address, unsigned int eq), unsigned int budget)
{
	unsigned int eq, attempted = 0;

	/* Credit is valid only within this serialized drain, never across polls. */
	queue->credit[0] = queue->credit[1] = 0;
	/* A stalled EQ4 must not prevent EQ5 from returning its buffers. */
	for (eq = 0; eq < RTL_QM_CPU_EQ_COUNT; eq++) {
		unsigned int limit = budget - attempted;
		/* Reserve only the other queue's share; idle capacity is reusable. */
		if (!eq)
			limit -= queue->count[1] < budget / 2 ? queue->count[1] : budget / 2;

		while (queue->count[eq] && limit--) {
			attempted++;
			if (push(context, queue->address[eq][queue->head[eq]], eq + RTL_QM_CPU_EQ_FIRST)) {
				queue->retries++;
				break;
			}
			queue->head[eq] = (queue->head[eq] + 1) % RTL_QM_REFILL_SIZE;
			queue->count[eq]--;
			queue->pending--;
			queue->returned++;
		}
	}
}
#endif
