/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_FABRIC_H
#define RTL9617C_FABRIC_H

#include <linux/delay.h>
#include "rtl9617c-l2-table.h"

/* Cold provider handoff only: no Linux LAN or FE DMA base is published,
 * all PON RX modes are gated by the PON owner, and its PDC FIFO is empty.
 * The caller owns the shared FE mutex. This local L2 drain is not a fence
 * for L3/DDR resource retirement. No table is flushed or inherited row erased.
 */
#define RTL_FABRIC_LAN_PORTS 5U
#define RTL_FABRIC_RX(port) (0xa5f8U + 0x90U * (port))
#define RTL_FABRIC_RX_SELECTOR ((1U << 28) | (63U << 16))
#define RTL_FABRIC_RX_CPU ((1U << 28) | (16U << 16))
#define RTL_FABRIC_FRAME_LENGTH 0xa034U
#define RTL_FABRIC_STORAGE_LENGTH 0xa038U
#define RTL_FABRIC_NATIVE_MAX_FRAME 1522U
#define RTL_FABRIC_RX_OVERSIZE_ALLOW (1U << 5)

struct rtl_fabric {
	unsigned int vlan_mode, packet_length, storage_length, tpid[4];
	unsigned int original_vlan_mode, original_packet_length, saved_control;
	unsigned int original_rx[RTL_FABRIC_LAN_PORTS];
	unsigned int saved_filter[RTL_L2_FDB_FILTER_WORDS];
	unsigned int rejected_register, rejected_value;
	int error;
	unsigned char ready, poisoned, changed, refusal;
};

static inline int rtl_fabric_match(const struct rtl_dq_io *io,
		struct rtl_fabric *fabric, unsigned int reg, unsigned int mask,
		unsigned int expected)
{
	unsigned int value = io->read(io->context, reg);

	if ((value & mask) == (expected & mask))
		return 0;
	if (!fabric->rejected_register) {
		fabric->rejected_register = reg;
		fabric->rejected_value = value;
	}
	return -EIO;
}

static inline int rtl_fabric_check(const struct rtl_dq_io *io,
				   struct rtl_fabric *fabric)
{
	unsigned int i;
	int ret;

	if (!rtl_l2_io_valid(io) || !fabric)
		return -EINVAL;
	if (!fabric->ready || fabric->poisoned)
		return -EIO;
	ret = rtl_fabric_match(io, fabric, RTL_L2_VLAN_MODE_CONTROL, 0x1fU,
			       fabric->vlan_mode);
	if (!ret)
		ret = rtl_fabric_match(io, fabric, RTL_FABRIC_FRAME_LENGTH,
				       0x03ff3fffU, fabric->packet_length);
	if (!ret)
		ret = rtl_fabric_match(io, fabric, RTL_FABRIC_STORAGE_LENGTH,
				       0x3fffU, fabric->storage_length);
	for (i = 0; !ret && i < 4; i++)
		ret = rtl_fabric_match(io, fabric, 0x1108U + i * 4, 0xffffU,
				       fabric->tpid[i]);
	for (i = 0; !ret && i < RTL_FABRIC_LAN_PORTS; i++)
		ret = rtl_fabric_match(io, fabric, RTL_FABRIC_RX(i),
			RTL_FABRIC_RX_OVERSIZE_ALLOW, fabric->original_rx[i]);
	fabric->error = ret;
	return ret;
}

/* Read-only classification of the captured physical baseline, not a full
 * native-L2 admission verdict. In particular, preserving a larger envelope
 * is required for tagged software fallback; it must not be shrunk simply to
 * make this check true. The hardware recipe separately checks live state. */
static inline int rtl_fabric_native_mtu_compatible(const struct rtl_fabric *fabric)
{
	unsigned int i, minimum, maximum;

	if (!fabric || !fabric->ready || fabric->poisoned)
		return 0;
	minimum = (fabric->packet_length >> 16) & 0x3ffU;
	maximum = fabric->packet_length & 0x3fffU;
	if (minimum < 64 || maximum < minimum ||
	    maximum > RTL_FABRIC_NATIVE_MAX_FRAME ||
	    (fabric->storage_length & 0x3fffU) < maximum)
		return 0;
	for (i = 0; i < RTL_FABRIC_LAN_PORTS; i++)
		if (fabric->original_rx[i] & RTL_FABRIC_RX_OVERSIZE_ALLOW)
			return 0;
	return 1;
}

static inline int rtl_fabric_pending(const struct rtl_dq_io *io)
{
	unsigned int packets = io->read(io->context, 0x11c0);

	return (packets & 0xffffU) != (packets >> 16) ||
		(io->read(io->context, 0x1534) & 0x3fU) ||
		(io->read(io->context, 0x175c) & 0xffU) ||
		(io->read(io->context, 0x1904) & 0x7ffffU);
}

static inline int rtl_fabric_drain(const struct rtl_dq_io *io)
{
	unsigned int attempt, stable = 0;

	/* Always execute this initial barrier, even before an L2 owner exists. */
	for (attempt = 0; attempt < 10000; attempt++) {
		if (!rtl_fabric_pending(io)) {
			if (++stable == 3)
				return 0;
		} else {
			stable = 0;
		}
		usleep_range(10, 20);
	}
	return -ETIMEDOUT;
}

/* Restore the command lease only while BOTH shared windows are idle.
 * In particular, a timed-out SCAN has not cancelled its hardware command.
 */
static inline int rtl_fabric_restore_command(const struct rtl_dq_io *io,
					    struct rtl_fabric *fabric,
					    unsigned int control)
{
	unsigned int i;
	int ret;

	ret = rtl_l2_fdb_mode_idle(io);
	if (ret)
		return ret;
	for (i = 0; i < RTL_L2_FDB_FILTER_WORDS; i++) {
		unsigned int reg = RTL_L2_FDB_FILTER_WORD0 - i * 4;

		io->write(io->context, reg, fabric->saved_filter[i]);
		ret = rtl_fabric_match(io, fabric, reg, ~0U,
				       fabric->saved_filter[i]);
		if (ret)
			return ret;
	}
	io->write(io->context, RTL_L2_FDB_CONTROL, control);
	return rtl_fabric_match(io, fabric, RTL_L2_FDB_CONTROL, ~0U,
				 control);
}

static inline int rtl_fabric_cold_prepare(const struct rtl_dq_io *io,
					 struct rtl_fabric *fabric)
{
	struct rtl_l2_fdb_result row;
	unsigned int filter[RTL_L2_FDB_FILTER_WORDS], control, i, minimum, maximum;
	unsigned int vlan_written = 0;
	unsigned int lease = 0;
	int ret, cleanup;

	if (!rtl_l2_io_valid(io) || !fabric)
		return -EINVAL;
	if (fabric->poisoned)
		return -EIO;
	if (fabric->ready)
		return rtl_fabric_check(io, fabric);
	fabric->refusal = 0;
	fabric->changed = 0;
	fabric->rejected_register = fabric->rejected_value = 0;
	control = io->read(io->context, RTL_L2_FDB_CONTROL);
	if ((control & (1U << 30)) ||
	    ((io->read(io->context, RTL_L2_FDB_ACCESS) |
	      io->read(io->context, RTL_L2_FDB_LIMIT_ACCESS)) & RTL_L2_ACCESS_BUSY)) {
		ret = -EBUSY;
		goto refuse;
	}
	fabric->original_vlan_mode = io->read(io->context, RTL_L2_VLAN_MODE_CONTROL);
	fabric->original_packet_length = io->read(io->context, RTL_FABRIC_FRAME_LENGTH);
	fabric->storage_length = io->read(io->context, RTL_FABRIC_STORAGE_LENGTH);
	for (i = 0; i < 4; i++)
		fabric->tpid[i] = io->read(io->context, 0x1108U + i * 4);
	minimum = (fabric->original_packet_length >> 16) & 0x3ffU;
	maximum = fabric->original_packet_length & 0x3fffU;
	if (minimum < 64 || maximum < minimum ||
	    (fabric->storage_length & 0x3fffU) < maximum) {
		ret = -EOPNOTSUPP;
		goto refuse;
	}
	/* Keep the inherited physical receive envelope, including valid tagged
	 * CPU-fallback traffic. A fixed 1522-byte cap would discard QinQ1500
	 * frames before software can handle them, even with native L2 off. */
	fabric->packet_length = fabric->original_packet_length;
	/* New LAN ingress bypasses L2 throughout acquisition and afterwards.
	 * Never restore an inherited native/FE selector as part of cleanup. */
	for (i = 0; i < RTL_FABRIC_LAN_PORTS; i++) {
		unsigned int reg = RTL_FABRIC_RX(i);
		unsigned int value = io->read(io->context, reg);

		fabric->original_rx[i] = value;
		io->write(io->context, reg,
			(value & ~RTL_FABRIC_RX_SELECTOR) | RTL_FABRIC_RX_CPU);
		ret = rtl_fabric_match(io, fabric, reg, RTL_FABRIC_RX_SELECTOR,
				       RTL_FABRIC_RX_CPU);
		if (ret) {
			fabric->poisoned = 1;
			goto refuse;
		}
	}
	fabric->saved_control = control;
	for (i = 0; i < RTL_L2_FDB_FILTER_WORDS; i++)
		fabric->saved_filter[i] = io->read(io->context,
			RTL_L2_FDB_FILTER_WORD0 - i * 4);
	/* Claim before the first global write, so partial setup is accounted for. */
	lease = 1;
	io->write(io->context, RTL_L2_FDB_CONTROL,
		control | RTL_L2_FDB_LEARN_DISABLE);
	ret = rtl_fabric_match(io, fabric, RTL_L2_FDB_CONTROL,
		RTL_L2_FDB_LEARN_DISABLE, RTL_L2_FDB_LEARN_DISABLE);
	if (ret)
		goto restore;
	ret = rtl_fabric_drain(io);
	if (ret)
		goto restore;
	if (!(fabric->original_vlan_mode & RTL_L2_VLAN_MODE_SVL)) {
		ret = rtl_l2_fdb_command_mode(io);
		if (ret)
			goto restore;
		for (i = 0; i < RTL_L2_FDB_FILTER_WORDS; i++)
			filter[i] = fabric->saved_filter[i];
		rtl_l2_fdb_scan_filter(filter);
		for (i = 0; i < RTL_L2_FDB_FILTER_WORDS; i++) {
			unsigned int reg = RTL_L2_FDB_FILTER_WORD0 - i * 4;

			io->write(io->context, reg, filter[i]);
			ret = rtl_fabric_match(io, fabric, reg, ~0U, filter[i]);
			if (ret)
				goto restore;
		}
		/* Every inherited valid row vetoes reinterpretation, including a
		 * static or multicast IVL key. A complete all-valid MISS proves empty. */
		ret = rtl_l2_fdb_scan(io, 0, &row);
		if (ret > 0)
			ret = -EOPNOTSUPP;
		if (ret)
			goto restore;
		ret = rtl_l2_fdb_mode_idle(io);
		if (ret)
			goto restore;
		if (rtl_fabric_pending(io)) {
			ret = -EBUSY;
			goto restore;
		}
		vlan_written = 1;
		io->write(io->context, RTL_L2_VLAN_MODE_CONTROL,
			fabric->original_vlan_mode | RTL_L2_VLAN_MODE_SVL);
		ret = rtl_fabric_match(io, fabric, RTL_L2_VLAN_MODE_CONTROL, ~0U,
			fabric->original_vlan_mode | RTL_L2_VLAN_MODE_SVL);
		if (ret)
			goto restore;
	}
restore:
	/* Rollback is allowed only with the same stopped-learning idle lease.
	 * On ambiguous completion retain/quarantine; never reuse DATA or expose
	 * a provider whose shared baseline has not been read back consistently. */
	if (ret && vlan_written) {
		cleanup = rtl_l2_fdb_mode_idle(io);
		if (!cleanup) {
			unsigned int value = io->read(io->context, RTL_L2_VLAN_MODE_CONTROL);

			io->write(io->context, RTL_L2_VLAN_MODE_CONTROL,
				(value & ~RTL_L2_VLAN_MODE_SVL) |
				(fabric->original_vlan_mode & RTL_L2_VLAN_MODE_SVL));
			cleanup = rtl_fabric_match(io, fabric, RTL_L2_VLAN_MODE_CONTROL,
				~0U, fabric->original_vlan_mode);
		}
		if (cleanup)
			fabric->poisoned = 1;
	}
	/* A successful shared baseline keeps learning stopped. The native
	 * owner may later enable only its prepared ports; software-only paths
	 * remain on CPU bypass. Failed acquisition restores inherited policy. */
	if (lease && rtl_fabric_restore_command(io, fabric, ret ?
		fabric->saved_control : fabric->saved_control | RTL_L2_FDB_LEARN_DISABLE))
		fabric->poisoned = 1;
	if (fabric->poisoned) {
		fabric->error = ret ? ret : -EIO;
		return fabric->error;
	}
	if (ret)
		goto refuse;
	fabric->vlan_mode = fabric->original_vlan_mode | RTL_L2_VLAN_MODE_SVL;
	fabric->ready = 1;
	fabric->changed = !!vlan_written;
	fabric->error = 0;
	return 0;
refuse:
	fabric->refusal = !fabric->poisoned;
	fabric->error = ret;
	return ret;
}

#endif
