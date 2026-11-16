/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_L2QM_H
#define RTL9617C_L2QM_H

#include <linux/errno.h>

/* RTL77C's L2 packet SRAM is distinct from the CPU and WAN DDR pools.
 * Pinned aal_l2_qm.h / aal_l2_tm.c describe 4096 cells of 64 bytes. The
 * wider register encoding is not evidence that a larger SRAM exists.
 */
#define RTL_L2QM_CELLS 4096U
#define RTL_L2QM_CELL_BYTES 64U
#define RTL_L2QM_PORTS 16U
#define RTL_L2QM_PRIVATE_CELLS 29U
#define RTL_L2QM_RESERVED_CELLS (RTL_L2QM_PORTS * RTL_L2QM_PRIVATE_CELLS)
#define RTL_L2QM_SHARED_CELLS (RTL_L2QM_CELLS - RTL_L2QM_RESERVED_CELLS)
#define RTL_L2QM_NODROP_CELLS 33U
/* ca-scfg's scfg-77c.txt overrides the generic SDK fallback with 0x800. */
#define RTL_L2QM_NONCONGESTION_CELLS 2048U
#define RTL_L2QM_EQ_CONFIG ((1U << 31) | ((RTL_L2QM_CELLS / 1024U) << 16) | \
	(RTL_L2QM_PRIVATE_CELLS << 20))
#define RTL_L2QM_BUFFER_CONFIG ((RTL_L2QM_NONCONGESTION_CELLS << 16) | \
	(1U << 15) | RTL_L2QM_NODROP_CELLS)
/* EQ0 is disabled. Both credit MSBs must be valid; EQ1's credits exclude
 * the private reservation. Keep this tied to the actual allocation above. */
#define RTL_L2QM_PORT_FREE_CREDIT ((1U << 31) | (1U << 15) | \
	(RTL_L2QM_SHARED_CELLS << 16))

struct rtl_l2qm_io {
	void *context;
	unsigned int (*read)(void *context, unsigned int reg);
	void (*write)(void *context, unsigned int reg, unsigned int value);
};

/* One-time native owner setup, before publishing its scheduler/host path.
 * This establishes the existing 4K-cell allocation, not a live resize or
 * reset. It neither touches BID/queue state nor promotes traffic to No-Drop.
 *
 * The SDK init assumes reset selectors (all ports use profile 0). An inherited
 * nonzero selector violates that assumption: profile 1 can reserve less than
 * one frame, while larger profiles can overcommit the fixed private pool.
 * Normalize all sixteen selectors, including ports 8..15, preserving every
 * reserved nibble bit and the unrelated profile 1 in the profile-0 word.
 * Do not copy the SDK selector setter's 0xfff mask / SELECT0-only write.
 * An incomplete/ignored write is fatal to this owner; the caller must not
 * start DMA/schedulers or publish the host after an error.
 */
static inline int rtl_l2qm_prepare(const struct rtl_l2qm_io *io)
{
	static const unsigned int reg[] = {0x2208U, 0x2218U, 0x2228U,
		0x222cU, 0x2210U};
	unsigned int expected[5], i;

	if (!io || !io->read || !io->write)
		return -EINVAL;
	/* Validate the entire direct-register window before its first write. */
	for (i = 0; i < 5; i++) {
		expected[i] = io->read(io->context, reg[i]);
		if (expected[i] == ~0U)
			return -EIO;
	}
	expected[0] = RTL_L2QM_EQ_CONFIG;
	expected[1] = (expected[1] & ~0x7fffU) | RTL_L2QM_PRIVATE_CELLS;
	expected[2] &= ~0x77777777U;
	expected[3] &= ~0x77777777U;
	expected[4] = RTL_L2QM_BUFFER_CONFIG;
	for (i = 0; i < 5; i++) {
		io->write(io->context, reg[i], expected[i]);
		if (io->read(io->context, reg[i]) != expected[i])
			return -EIO;
	}
	/* A later write must not silently disturb an earlier committed word. */
	for (i = 0; i < 5; i++)
		if (io->read(io->context, reg[i]) != expected[i])
			return -EIO;
	return 0;
}

#endif
