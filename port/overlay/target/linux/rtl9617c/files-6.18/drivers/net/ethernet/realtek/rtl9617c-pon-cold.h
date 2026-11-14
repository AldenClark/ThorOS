/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_PON_COLD_H
#define RTL9617C_PON_COLD_H

#include "rtl9617c-qm-deepq.h"

/* aal-77c/aal_pon.c aal_pon_mac_enable_set(rx_en=false), checked against
 * the RTL8277C generated unions. Cold handoff cannot dispatch on the native
 * driver's default mode: the inherited hardware may be running any family.
 * These fields stop new MAC receive admission; they do not prove that old
 * PDC/NI/DDR work has retired. The caller separately checks the PDC FIFO and
 * NI's initial barrier before publishing any native data-plane user.
 */
#define RTL_PON_COLD_RX_GATES(X) \
	X(EPON_1G, 0x088cU, 1U) \
	X(EPON_10G, 0x10b4U, 1U << 7) \
	X(GPON, 0x6114U, 1U << 1) \
	X(XGPON, 0x4004U, 3U)

#define RTL_PON_COLD_PDC_FIFO_STATUS 0x9010U
#define RTL_PON_COLD_PDC_FIFO_DEPTH 31U

static inline int rtl_pon_cold_rx_gate(const struct rtl_dq_io *io)
{
	static const struct {
		unsigned int reg, mask;
	} gates[] = {
#define RTL_PON_COLD_GATE_ENTRY(name, reg, mask) { reg, mask },
		RTL_PON_COLD_RX_GATES(RTL_PON_COLD_GATE_ENTRY)
#undef RTL_PON_COLD_GATE_ENTRY
	};
	unsigned int i;

	if (!io || !io->read || !io->write)
		return -EINVAL;
	/* Attempt every gate before returning a readback error, so a stuck
	 * family cannot leave the other inherited receive families enabled. */
	for (i = 0; i < sizeof(gates) / sizeof(gates[0]); i++)
		io->write(io->context, gates[i].reg,
			  io->read(io->context, gates[i].reg) & ~gates[i].mask);
	for (i = 0; i < sizeof(gates) / sizeof(gates[0]); i++)
		if (io->read(io->context, gates[i].reg) & gates[i].mask)
			return -EIO;
	/* No restore: later native mode initialization owns explicit reopen. */
	return 0;
}

#endif
