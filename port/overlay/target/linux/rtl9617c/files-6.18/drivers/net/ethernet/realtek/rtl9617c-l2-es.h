/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_L2_ES_H
#define RTL9617C_L2_ES_H

#include "rtl9617c-qm-deepq.h"

/* The physical ES port IDs skip 14; port15 uses register instance14.
 * The LAN owner may prepare its published LAN0..4 and the discard sink15,
 * but may not take over PON/CPU/foreign schedulers with this helper.
 *
 * Reference: ca-network-drivers@8b4f4882, aal_l2_tm.c's VOQ enable/flush
 * functions; RTL8277C generated L2TM_L2TM_ES_SCH_CFG0 fields. A surviving
 * flush_en is a command, not a status indication: enabling a VOQ while
 * keeping it set can keep discarding that VOQ's packets. Do not issue a
 * new flush to clear it. Preserve the selected VOQ, speed and other fields.
 *
 * Call once, before publishing this owner's ES enable bits. This is NOT a
 * runtime queue reset or a packet-drain proof. ndo_open must not replay it.
 */
static inline int rtl_l2_es_cold_prepare(const struct rtl_dq_io *io,
				       unsigned int ports)
{
	unsigned int saved[16], port, reg, value;

	if (!io || !io->read || !io->write || (ports & ~0x801fU))
		return -EINVAL;
	/* Validate every selected register before the first write. */
	for (port = 0; port < 16; port++) {
		if (!(ports & (1U << port)))
			continue;
		reg = 0x2304U + 12U * (port == 15 ? 14 : port);
		saved[port] = io->read(io->context, reg);
		if (saved[port] == ~0U)
			return -EIO;
	}
	for (port = 0; port < 16; port++) {
		if (!(ports & (1U << port)))
			continue;
		reg = 0x2304U + 12U * (port == 15 ? 14 : port);
		value = (saved[port] & ~0x8000U) | 0xffU;
		io->write(io->context, reg, value);
	}
	/* Read back all owned words before the caller enables the ES ports.
	 * Do not publish a partially accepted configuration or a stuck flush.
	 */
	for (port = 0; port < 16; port++) {
		if (!(ports & (1U << port)))
			continue;
		reg = 0x2304U + 12U * (port == 15 ? 14 : port);
		value = (saved[port] & ~0x8000U) | 0xffU;
		if (io->read(io->context, reg) != value)
			return -EIO;
	}
	return 0;
}

#endif
