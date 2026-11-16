/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTL9617C_MCAST_HANDOFF_H
#define RTL9617C_MCAST_HANDOFF_H

#include "rtl9617c-l2-table.h"

/* Missing ownership/completion contracts, NOT observed register errors.
 * Sampling a disabled producer or an idle command window never clears one.
 * DMALSO is a separate register aperture; do not turn an FE-relative read
 * at the same low offset into evidence that its DMA producer is fenced.
 */
#define RTL_MCAST_NEEDS_XRAM_FENCE (1U << 0)
#define RTL_MCAST_NEEDS_DMALSO_FENCE (1U << 1)
#define RTL_MCAST_NEEDS_CLS_ROOTS (1U << 2)
#define RTL_MCAST_NEEDS_DDR_RETIRE (1U << 3)
#define RTL_MCAST_NEEDS_MCE_RETIRE (1U << 4)
#define RTL_MCAST_HANDOFF_MISSING (RTL_MCAST_NEEDS_XRAM_FENCE | \
	RTL_MCAST_NEEDS_DMALSO_FENCE | RTL_MCAST_NEEDS_CLS_ROOTS | \
	RTL_MCAST_NEEDS_DDR_RETIRE | RTL_MCAST_NEEDS_MCE_RETIRE)

enum rtl_mcast_handoff_sample {
	RTL_MCAST_HANDOFF_XRAM, RTL_MCAST_HANDOFF_STG0,
	RTL_MCAST_HANDOFF_HASH, RTL_MCAST_HANDOFF_CACHE,
	RTL_MCAST_HANDOFF_MCE, RTL_MCAST_HANDOFF_SAMPLES,
};

struct rtl_mcast_handoff {
	unsigned int value[RTL_MCAST_HANDOFF_SAMPLES];
	unsigned int valid_mask, missing, reads, bad_register, bad_value;
};

/* Pinned RTL8277C configuration words only: no read-clear counters,
 * ACCESS/DATA acquisitions, reset/flush requests or foreign DDR reads.
 * NI's LAN/PON gate and local L2 stage drain do not establish any of the
 * five contracts above. The SDK register unions expose buf_flush_en but
 * no documented MCE packet-retirement ACK; HASH_INI.ht_size=0 is 512
 * entries, not a disabled table. Preserve refusal while exposing all
 * actual samples (including independent validity) for the next lab run.
 */
static inline int rtl_mcast_handoff_probe(struct rtl_mcast_handoff *state,
		const struct rtl_dq_io *io)
{
	static const unsigned int registers[RTL_MCAST_HANDOFF_SAMPLES] = {
		0xaa28, 0x3400, 0x3834, 0x38a0, 0xaa60,
	};
	unsigned int i, value;
	int ret = -EOPNOTSUPP;

	if (!state || !rtl_l2_io_valid(io))
		return -EINVAL;
	*state = (struct rtl_mcast_handoff) {
		.missing = RTL_MCAST_HANDOFF_MISSING,
	};
	for (i = 0; i < RTL_MCAST_HANDOFF_SAMPLES; i++) {
		value = io->read(io->context, registers[i]);
		state->reads++;
		state->value[i] = value;
		if (value == ~0U) {
			if (ret != -EIO) {
				state->bad_register = registers[i];
				state->bad_value = value;
			}
			ret = -EIO;
		} else {
			state->valid_mask |= 1U << i;
		}
	}
	return ret;
}

#endif
