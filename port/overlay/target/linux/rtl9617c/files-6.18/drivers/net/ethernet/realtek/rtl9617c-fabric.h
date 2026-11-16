/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_FABRIC_H
#define RTL9617C_FABRIC_H

#include <linux/delay.h>
#include "rtl9617c-l2-table.h"
#include "rtl9617c-frame.h"

/* Cold provider handoff only: no Linux LAN or FE DMA base is published.
 * NI's local bootstrap has gated the selected, released PON RX family and
 * verified PDC empty (or PDC is held in reset); no PON probe is required.
 * The caller owns the shared FE mutex. This local L2 drain is not a fence
 * for L3/DDR resource retirement. No table is flushed or inherited row erased.
 */
#define RTL_FABRIC_LAN_PORTS 5U
#define RTL_FABRIC_RX_MAC(port) (0xa5c8U + 0x90U * (port))
#define RTL_FABRIC_RX_MAC_ENABLE 1U
#define RTL_FABRIC_RX(port) (0xa5f8U + 0x90U * (port))
#define RTL_FABRIC_RX_SELECTOR ((1U << 28) | (63U << 16))
#define RTL_FABRIC_RX_CPU ((1U << 28) | (16U << 16))
#define RTL_FABRIC_FRAME_LENGTH 0xa034U
#define RTL_FABRIC_STORAGE_LENGTH 0xa038U
#define RTL_FABRIC_NATIVE_MAX_FRAME RTL_NI_FRAME_WIRE_BYTES
#define RTL_FABRIC_RX_OVERSIZE_ALLOW (1U << 5)

struct rtl_fabric {
	unsigned int vlan_mode, packet_length, storage_length, tpid[4];
	unsigned int original_vlan_mode, original_packet_length, saved_control;
	unsigned int original_rx[RTL_FABRIC_LAN_PORTS];
	unsigned int original_mac_rx[RTL_FABRIC_LAN_PORTS], cold_rx_gated;
	unsigned int saved_filter[RTL_L2_FDB_FILTER_WORDS];
	unsigned int inherited_fdb_index, inherited_fdb_words[RTL_L2_FDB_WORDS];
	unsigned int rejected_register, rejected_value;
	int error;
	unsigned char ready, poisoned, changed, refusal, inherited_fdb_present;
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
	unsigned int i, control;
	int ret;

	if (!rtl_l2_io_valid(io) || !fabric)
		return -EINVAL;
	if (!fabric->ready || fabric->poisoned)
		return -EIO;
	/* Native L2 may enable autonomous learning, but the FE lifetime keeps
	 * CMD mode. Never recover a late MAC-limit lease from a warm observer. */
	ret = rtl_l2_fdb_control_read(io, &control);
	if (!ret && !(control & RTL_L2_FDB_CMD_MODE))
		ret = -EOPNOTSUPP;
	if (!ret)
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
			RTL_FABRIC_RX_OVERSIZE_ALLOW, 0);
	fabric->error = ret;
	return ret;
}

/* Classification of the managed cold baseline, not an IP/MTU ACL or a
 * tag-aware length check. A ready owner has read back all five UNI oversize
 * overrides disabled; warm checking verifies that contract without writes. */
static inline int rtl_fabric_native_mtu_compatible(const struct rtl_fabric *fabric)
{
	unsigned int minimum, maximum;

	if (!fabric || !fabric->ready || fabric->poisoned || fabric->error)
		return 0;
	minimum = (fabric->packet_length >> 16) & 0x3ffU;
	maximum = fabric->packet_length & 0x3fffU;
	return minimum == 64 && maximum == RTL_FABRIC_NATIVE_MAX_FRAME &&
		(fabric->storage_length & 0x3fffU) >= maximum;
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
	unsigned int i, live;
	unsigned int owned = RTL_L2_FDB_CMD_MODE | RTL_L2_FDB_LEARN_DISABLE;
	int ret;

	ret = rtl_l2_fdb_mode_control(io, &live);
	if (ret)
		return ret;
	if ((live ^ control) & ~(owned | RTL_L2_FDB_SW_AGE_SCAN))
		return -EIO;
	for (i = 0; i < RTL_L2_FDB_FILTER_WORDS; i++) {
		unsigned int reg = RTL_L2_FDB_FILTER_WORD0 - i * 4;

		io->write(io->context, reg, fabric->saved_filter[i]);
		ret = rtl_fabric_match(io, fabric, reg, ~0U,
				       fabric->saved_filter[i]);
		if (ret)
			return ret;
	}
	/* The SDK toggles sw_age_entry_scan to request a scan. It is live edge
	 * state, not a setting to replay from the pre-lease snapshot. Recheck
	 * after restoring filters and only return the CMD/learning bits owned
	 * by this transaction; unrelated stable control drift is not repairable
	 * by overwriting the whole register with an old value. */
	ret = rtl_l2_fdb_mode_control(io, &live);
	if (ret)
		return ret;
	if ((live ^ control) & ~(owned | RTL_L2_FDB_SW_AGE_SCAN))
		return -EIO;
	control = (live & ~owned) | (control & owned);
	io->write(io->context, RTL_L2_FDB_CONTROL, control);
	/* A failed acquisition may restore learning enabled, so use the idle
	 * control reader rather than demanding a stopped-learning lease here. */
	ret = rtl_l2_fdb_control_read(io, &live);
	if (ret)
		return ret;
	if ((live ^ control) & ~RTL_L2_FDB_SW_AGE_SCAN) {
		if (!fabric->rejected_register) {
			fabric->rejected_register = RTL_L2_FDB_CONTROL;
			fabric->rejected_value = live;
		}
		return -EIO;
	}
	return 0;
}

static inline int rtl_fabric_cold_prepare(const struct rtl_dq_io *io,
					 struct rtl_fabric *fabric)
{
	struct rtl_l2_fdb_result row;
	unsigned int filter[RTL_L2_FDB_FILTER_WORDS], control, live, i, minimum, maximum;
	unsigned int vlan_written = 0, frame_written = 0, oversize_written = 0;
	unsigned int selector_changed = 0;
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
	fabric->cold_rx_gated = 0;
	fabric->inherited_fdb_present = 0;
	fabric->inherited_fdb_index = ~0U;
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
	if (minimum != 64 || maximum < minimum ||
	    (fabric->storage_length & 0x3fffU) < RTL_FABRIC_NATIVE_MAX_FRAME) {
		ret = -EOPNOTSUPP;
		goto refuse;
	}
	/* Coarse UNI RX envelope for MTU1500 + two VLANs + FCS. This is not
	 * tag-aware: it intentionally does not claim exact skb/IP MTU filtering.
	 * The independent processing/PON storage budget is never rewritten. */
	fabric->packet_length = (fabric->original_packet_length & ~0x3fffU) |
		RTL_FABRIC_NATIVE_MAX_FRAME;
	/* A CPU destination is NOT a receive fence. The SDK's __ni_rx_init()
	 * closes GE RXMAC.rx_en before configuring NI; RX_CNTRL.rxctrl_byp_en
	 * only carries an FE-bypass/destination policy. In particular, CPU16's
	 * QM has not been started yet: admitting frames there can backpressure
	 * the very local pipeline that this cold transaction must drain.
	 * Snapshot every port before the first write, close real MAC receive,
	 * and leave TX untouched so already accepted frames can leave.
	 * Both success and safe refusal leave RX closed for normal ndo_open.
	 * Neither path may restore an inherited native/FE admission policy. */
	for (i = 0; i < RTL_FABRIC_LAN_PORTS; i++) {
		fabric->original_mac_rx[i] = io->read(io->context, RTL_FABRIC_RX_MAC(i));
		fabric->original_rx[i] = io->read(io->context, RTL_FABRIC_RX(i));
	}
	for (i = 0; i < RTL_FABRIC_LAN_PORTS; i++) {
		unsigned int reg = RTL_FABRIC_RX_MAC(i);

		io->write(io->context, reg,
			fabric->original_mac_rx[i] & ~RTL_FABRIC_RX_MAC_ENABLE);
		ret = rtl_fabric_match(io, fabric, reg, RTL_FABRIC_RX_MAC_ENABLE, 0);
		if (ret) {
			/* No selector or shared baseline has been written yet. A
			 * completely ignored gate write is a clean native refusal,
			 * just like the read-only preflight: software LAN startup
			 * retains the exact inherited state of this port. Earlier
			 * closed ports stay closed until their normal ndo_open.
			 * Any changed/unknown word is not this recoverable case. */
			if (io->read(io->context, reg) == fabric->original_mac_rx[i])
				goto refuse;
			fabric->poisoned = 1;
			goto refuse;
		}
		fabric->cold_rx_gated |= 1U << i;
	}
	for (i = 0; i < RTL_FABRIC_LAN_PORTS; i++) {
		unsigned int reg = RTL_FABRIC_RX(i);
		unsigned int value = io->read(io->context, reg);

		selector_changed |= (value & RTL_FABRIC_RX_SELECTOR) != RTL_FABRIC_RX_CPU;
		io->write(io->context, reg,
			(value & ~RTL_FABRIC_RX_SELECTOR) | RTL_FABRIC_RX_CPU);
		ret = rtl_fabric_match(io, fabric, reg, RTL_FABRIC_RX_SELECTOR,
				       RTL_FABRIC_RX_CPU);
		if (ret) {
			fabric->poisoned = 1;
			goto refuse;
		}
	}
	for (i = 0; i < RTL_L2_FDB_FILTER_WORDS; i++)
		fabric->saved_filter[i] = io->read(io->context,
			RTL_L2_FDB_FILTER_WORD0 - i * 4);
	/* RX gating and filter snapshots may span a software age-scan toggle.
	 * Refresh that edge before the first CTRL write, without accepting stable policy
	 * changes or a newly busy command window as part of our old snapshot. */
	ret = rtl_l2_fdb_control_read(io, &live);
	if (ret)
		goto refuse;
	if ((live ^ control) & ~RTL_L2_FDB_SW_AGE_SCAN) {
		ret = -EIO;
		goto refuse;
	}
	control = live;
	fabric->saved_control = control;
	/* Claim before the first global write, so partial setup is accounted for. */
	lease = 1;
	io->write(io->context, RTL_L2_FDB_CONTROL,
		control | RTL_L2_FDB_LEARN_DISABLE);
	ret = rtl_fabric_match(io, fabric, RTL_L2_FDB_CONTROL,
		RTL_L2_FDB_LEARN_DISABLE, RTL_L2_FDB_LEARN_DISABLE);
	if (ret) {
		/* An ignored first write has not acquired the shared command lease.
		 * If the original stable control and both idle windows are intact,
		 * there is nothing to restore and no ambiguous command to retire.
		 * Requiring a stopped-learning lease to restore this unchanged state
		 * would turn an optional native failure into a dead management LAN. */
		cleanup = rtl_l2_fdb_control_read(io, &live);
		if (!cleanup && !((live ^ control) & ~RTL_L2_FDB_SW_AGE_SCAN)) {
			lease = 0;
			goto refuse;
		}
		goto restore;
	}
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
		if (ret > 0) {
			fabric->inherited_fdb_present = 1;
			fabric->inherited_fdb_index = row.index;
			for (i = 0; i < RTL_L2_FDB_WORDS; i++)
				fabric->inherited_fdb_words[i] = row.words[i];
			ret = -EOPNOTSUPP;
		}
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
	ret = rtl_l2_fdb_mode_idle(io);
	if (ret)
		goto restore;
	if (rtl_fabric_pending(io)) {
		ret = -EBUSY;
		goto restore;
	}
	/* Vendor aal_ni_pkt_len_set requires settling after updating the UNI
	 * size. This delay is not used as a pipeline or DDR retirement fence. */
	if (fabric->packet_length != fabric->original_packet_length) {
		frame_written = 1;
		io->write(io->context, RTL_FABRIC_FRAME_LENGTH, fabric->packet_length);
		usleep_range(1000, 2000);
		ret = rtl_fabric_match(io, fabric, RTL_FABRIC_FRAME_LENGTH,
			~0U, fabric->packet_length);
		if (ret)
			goto restore;
	}
	for (i = 0; i < RTL_FABRIC_LAN_PORTS; i++) {
		unsigned int reg = RTL_FABRIC_RX(i);
		unsigned int value = io->read(io->context, reg);

		if (value & RTL_FABRIC_RX_OVERSIZE_ALLOW) {
			oversize_written |= 1U << i;
			io->write(io->context, reg, value & ~RTL_FABRIC_RX_OVERSIZE_ALLOW);
		}
		ret = rtl_fabric_match(io, fabric, reg, RTL_FABRIC_RX_OVERSIZE_ALLOW, 0);
		if (ret)
			goto restore;
	}

restore:
	/* Rollback is allowed only with the same stopped-learning idle lease.
	 * On ambiguous completion retain/quarantine; never reuse DATA or expose
	 * a provider whose shared baseline has not been read back consistently. */
	if (ret && (vlan_written || frame_written || oversize_written)) {
		cleanup = rtl_l2_fdb_mode_idle(io);
		if (!cleanup)
			cleanup = rtl_fabric_drain(io);
		if (!cleanup) {
			for (i = 0; i < RTL_FABRIC_LAN_PORTS; i++) {
				unsigned int reg, value;

				if (!(oversize_written & (1U << i)))
					continue;
				reg = RTL_FABRIC_RX(i);
				value = io->read(io->context, reg);
				io->write(io->context, reg,
					(value & ~RTL_FABRIC_RX_OVERSIZE_ALLOW) |
					(fabric->original_rx[i] & RTL_FABRIC_RX_OVERSIZE_ALLOW));
				if (rtl_fabric_match(io, fabric, reg, RTL_FABRIC_RX_OVERSIZE_ALLOW,
					fabric->original_rx[i]))
					cleanup = -EIO;
			}
			if (frame_written) {
				io->write(io->context, RTL_FABRIC_FRAME_LENGTH,
					fabric->original_packet_length);
				usleep_range(1000, 2000);
				if (rtl_fabric_match(io, fabric, RTL_FABRIC_FRAME_LENGTH,
					~0U, fabric->original_packet_length))
					cleanup = -EIO;
			}
			if (vlan_written) {
				unsigned int value = io->read(io->context, RTL_L2_VLAN_MODE_CONTROL);

				io->write(io->context, RTL_L2_VLAN_MODE_CONTROL,
					(value & ~RTL_L2_VLAN_MODE_SVL) |
					(fabric->original_vlan_mode & RTL_L2_VLAN_MODE_SVL));
				if (rtl_fabric_match(io, fabric, RTL_L2_VLAN_MODE_CONTROL,
					~0U, fabric->original_vlan_mode))
					cleanup = -EIO;
			}
		}
		if (cleanup)
			fabric->poisoned = 1;
	}
	/* Successful cold handoff belongs to the FE lifetime, including route-
	 * only configurations which never prepare native L2. Keep CMD leased
	 * while learning is stopped and both windows are idle. Native L2 takes
	 * its later snapshot from this CMD baseline and returns to it on exit.
	 * Only final, proven-unexposed FE release may return the boot CMD bit.
	 * Failed acquisition still restores inherited policy, not the new lease. */
	if (lease && !fabric->poisoned && rtl_fabric_restore_command(io, fabric, ret ?
		fabric->saved_control : fabric->saved_control |
		RTL_L2_FDB_LEARN_DISABLE | RTL_L2_FDB_CMD_MODE))
		fabric->poisoned = 1;
	if (fabric->poisoned) {
		fabric->error = ret ? ret : -EIO;
		return fabric->error;
	}
	if (ret)
		goto refuse;
	fabric->vlan_mode = fabric->original_vlan_mode | RTL_L2_VLAN_MODE_SVL;
	fabric->ready = 1;
	fabric->changed = !!(vlan_written || frame_written || oversize_written ||
		selector_changed || !(fabric->saved_control & RTL_L2_FDB_LEARN_DISABLE) ||
		!(fabric->saved_control & RTL_L2_FDB_CMD_MODE));
	for (i = 0; i < RTL_FABRIC_LAN_PORTS; i++)
		fabric->changed |= !!(fabric->original_mac_rx[i] & RTL_FABRIC_RX_MAC_ENABLE);
	fabric->error = 0;
	return 0;
refuse:
	fabric->refusal = !fabric->poisoned;
	fabric->error = ret;
	return ret;
}

#endif
