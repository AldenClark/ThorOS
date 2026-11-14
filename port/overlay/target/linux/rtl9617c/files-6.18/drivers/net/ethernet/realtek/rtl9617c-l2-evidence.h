/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_L2_EVIDENCE_H
#define RTL9617C_L2_EVIDENCE_H

#include "rtl9617c-qm-deepq.h"

/* Explicitly bounded, passive register allowlist. In particular do NOT read
 * MCE packet/drop counters or LAST_* headers: their read/clear and coherency
 * contracts have not been established. ACCESS is only observed, never issued;
 * DATA windows and the global debug selector are never touched.
 *
 * Offsets/fields are checked against the pinned RTL8277C generated header.
 * A sampled idle command window is NOT an in-flight packet retirement fence.
 */
#define RTL_L2_EVIDENCE_REGISTERS(X) \
	X(MCE_CONTROL, 0xaa60U, "mce_control") \
	X(MCE_ACCESS, 0xaa64U, "mce_access") \
	X(MCFIB_ACCESS, 0x1634U, "mcfib_access") \
	X(ARB_CONTROL, 0x1600U, "arb_control") \
	X(ARB_EXT, 0x160cU, "arb_ext") \
	X(FDB_CONTROL, 0x1c00U, "fdb_control") \
	X(FDB_AGING, 0x1c04U, "fdb_aging") \
	X(FDB_ACCESS, 0x1ca0U, "fdb_access") \
	X(FDB_LIMIT_ACCESS, 0x1cb4U, "fdb_limit_access") \
	X(VLAN_MODE, 0x1414U, "vlan_mode") \
	X(HASH_CONTROL, 0x1400U, "hash_control") \
	X(FLOOD_ACCESS, 0x1564U, "flood_access")

enum rtl_l2_evidence_register {
#define RTL_L2_EVIDENCE_ENUM(name, offset, label) RTL_L2_EVIDENCE_##name,
	RTL_L2_EVIDENCE_REGISTERS(RTL_L2_EVIDENCE_ENUM)
#undef RTL_L2_EVIDENCE_ENUM
	RTL_L2_EVIDENCE_REG_COUNT,
};

#define RTL_L2_EVIDENCE_LAN_PORTS 5U
#define RTL_L2_EVIDENCE_LAN_BASE 0xa5f8U
#define RTL_L2_EVIDENCE_LAN_STRIDE 0x90U

struct rtl_l2_evidence {
	unsigned int words[RTL_L2_EVIDENCE_REG_COUNT];
	unsigned int lan_rx[RTL_L2_EVIDENCE_LAN_PORTS];
	unsigned int mce_copy_lspid_to_pol, mce_flush_requested;
	unsigned int arb_keep_original_lspid, arb_mc_membership_check;
};

static inline int rtl_l2_evidence_read(const struct rtl_dq_io *io,
				      struct rtl_l2_evidence *sample)
{
	static const unsigned int offsets[] = {
#define RTL_L2_EVIDENCE_OFFSET(name, offset, label) offset,
		RTL_L2_EVIDENCE_REGISTERS(RTL_L2_EVIDENCE_OFFSET)
#undef RTL_L2_EVIDENCE_OFFSET
	};
	unsigned int i;

	if (!io || !io->read || !sample)
		return -EINVAL;
	for (i = 0; i < RTL_L2_EVIDENCE_REG_COUNT; i++)
		sample->words[i] = io->read(io->context, offsets[i]);
	for (i = 0; i < RTL_L2_EVIDENCE_LAN_PORTS; i++)
		sample->lan_rx[i] = io->read(io->context,
			RTL_L2_EVIDENCE_LAN_BASE + RTL_L2_EVIDENCE_LAN_STRIDE * i);
	sample->mce_copy_lspid_to_pol =
		(sample->words[RTL_L2_EVIDENCE_MCE_CONTROL] >> 17) & 1U;
	sample->mce_flush_requested =
		(sample->words[RTL_L2_EVIDENCE_MCE_CONTROL] >> 18) & 1U;
	sample->arb_keep_original_lspid =
		(sample->words[RTL_L2_EVIDENCE_ARB_CONTROL] >> 31) & 1U;
	sample->arb_mc_membership_check =
		sample->words[RTL_L2_EVIDENCE_ARB_EXT] & 1U;
	return 0;
}

#endif
