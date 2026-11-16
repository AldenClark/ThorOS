/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTL9617C_FE_SWITCH_HW_H
#define RTL9617C_FE_SWITCH_HW_H

#include "rtl9617c-frame.h"

#include <linux/delay.h>

#include "rtl9617c-l2-table.h"
#include "rtl9617c-l2-resources.h"
#include "rtl9617c-l2-port-policy.h"
#include "rtl9617c-mcast-state.h"

/* Native LAN admission and its reversible L2 resources have one owner.
 * The policy compiler holds fe->lock for prepare/drain/restore. The core
 * guard calls gate/arm under its spinlock: those two functions do direct
 * MMIO only, never an indirect command, allocation or sleeping wait.
 *
 * Reference: ca-network-drivers 8b4f4882, aal-77c/aal_{port,ni,fdb,arb}.c;
 * RTL8277C generated registers, GPL-for-GP3000 5090fbcb. These recipes do
 * not constitute an ASIC throughput measurement or a wire-zero-in-flight
 * guarantee. Gate stops NEW admission; a completed old forwarding decision
 * already queued in a MAC may finish. Tables are not rewritten until the
 * parser/PLE/PE/LF pending state is drained with a bounded wait.
 */
#define FE_SW_LAN_MASK ((1U << FE_LAN_PORTS) - 1U)
#define FE_SW_RX_DEST_MASK (0x3fU << 16)
#define FE_SW_RX_BYPASS BIT(28)
#define FE_SW_RX_CPU (FE_SW_RX_BYPASS | (16U << 16))
#define FE_SW_SNAPSHOTS 256
#define FE_SW_CF_PER_PORT 5
#define FE_SW_CF_RULES (FE_LAN_PORTS * FE_SW_CF_PER_PORT)
#define FE_SW_FDB_OVERFLOW_RECYCLE BIT(29)
/* SDK toggles CTRL bit12 to request a software aging scan; either steady
 * value is legal and restoring an old value could issue a new scan. Bit30
 * names FIFO initialization but lacks a proven completion contract: refuse
 * it while high. Neither bit is owned/replayed by this native transaction. */
#define FE_SW_FDB_COMMAND_BITS (BIT(12) | BIT(30))
#define FE_SW_FDB_INIT BIT(30)
#define FE_SW_FDB_OWNED_CONTROL (RTL_L2_FDB_CMD_MODE | RTL_L2_FDB_LEARN_DISABLE | \
	RTL_L2_FDB_LEARN_MODE_MASK | RTL_L2_FDB_COLLISION_OVERWRITE | \
	FE_SW_FDB_OVERFLOW_RECYCLE | BIT(11) | 0x7f8U | BIT(2) | BIT(0))
/* aal_port.h defines ILPB match bits, not indices into CMP_S/C/O/USER:
 * bit3=8100, bit2=9100, bit1=88a8; bit0 uses that tag class's user CSR.
 * Keep the existing user comparator and trap every recognised C tag. */
#define FE_SW_TPID_STANDARD (BIT(3) | BIT(2) | BIT(1))
#define FE_SW_TPID_USER BIT(0)
#define FE_SW_TPID_ALL (FE_SW_TPID_STANDARD | FE_SW_TPID_USER)

enum fe_switch_hw_reason {
	FE_SW_HW_OK,
	FE_SW_HW_VLAN_MODE,
	FE_SW_HW_PRIORITY_KEY,
	FE_SW_HW_TPID,
	FE_SW_HW_CPU_EGRESS,
	FE_SW_HW_QUEUE,
	FE_SW_HW_IDENTITY,
	FE_SW_HW_SOURCE_ALIAS,
	FE_SW_HW_TIMER,
	FE_SW_HW_CLASSIFIER,
	FE_SW_HW_LEARNING,
	FE_SW_HW_PROFILE,
	FE_SW_HW_LIMIT,
	FE_SW_HW_TABLE,
	FE_SW_HW_BUSY,
	FE_SW_HW_DRAIN,
	FE_SW_HW_MTU,
	FE_SW_HW_CONTROL_PACKETS,
	FE_SW_HW_PORT_POLICY,
	FE_SW_HW_ISOLATION,
	FE_SW_HW_REDIRECT,
	FE_SW_HW_ADMISSION,
	FE_SW_HW_IVL_CONTRACT,
};

struct fe_switch_hw_observed {
	unsigned int vlan_mode, hash_control, aging, packet_length;
	unsigned int tpid[4], rx_oversize_allow;
	unsigned int source_port, source_logical, learning_port, learning_profile;
};

struct rtl_fe_switch_hw {
	struct rtl_l2_snapshot *rows;
	struct rtl_l2_journal journal;
	unsigned int count, ports, special_profile;
	unsigned int cf[FE_SW_CF_RULES], cf_count;
	unsigned int control, aging, requested_aging, learning;
	unsigned int learn_forward, learn_exception;
	unsigned int demux;
	unsigned int limits[FE_LAN_PORTS], limits_owned;
	unsigned int filter[RTL_L2_FDB_FILTER_WORDS];
	unsigned int run_control;
	unsigned int learning_mask, isolated_mask, local_target;
	/* Non-NULL only for an explicitly requested IVL control-plane snapshot.
	 * It is not evidence that the hardware VLAN/parser contract is supported. */
	const struct rtl_l2_vlan_plan *vlan_plan;
	unsigned char bum_enabled[FE_LAN_PORTS];
	unsigned int mdb_ports;
	enum fe_switch_hw_reason reason;
	struct fe_switch_hw_observed observed;
	bool globals_owned, prepared, drained, port_policy_ready;
	bool route_policy_allowed;
	bool rx_gate_verified;
};

static const char *fe_switch_hw_reason_text(unsigned int reason)
{
	static const char * const names[] = {
		"ok", "requires-existing-svl", "priority-fdb-key", "tpid-profile",
		"cpu-egress-edit", "queue-baseline", "lan-source-map",
		"foreign-source-alias", "aging-timebase", "foreign-classifier",
		"foreign-learning", "special-profile-capacity", "mac-limit-io",
		"table-io", "shared-command-busy", "pipeline-drain-timeout",
		"native-mtu-baseline", "control-packet-classification",
		"port-policy-transaction", "isolation-baseline", "redirect-baseline",
		"admission-readback",
		"ivl-parser-consumer-unverified",
	};

	return reason < ARRAY_SIZE(names) ? names[reason] : "unknown";
}

static const char *fe_switch_hw_reason_name(const struct rtl_fe_switch_hw *hw)
{
	return fe_switch_hw_reason_text(hw->reason);
}

/* No MAC TX disable: software forwarding must continue under a persistent
 * policy veto. Clearing a destination's TX enable is neither a proven GE
 * FIFO flush nor a safe way to restore the software fallback afterwards.
 */
static bool fe_switch_hw_rx_check(struct rtl_fe *fe, unsigned int native,
				   unsigned int route)
{
	unsigned int port, expected, value;
	bool verified = true;

	for (port = 0; port < FE_LAN_PORTS; port++) {
		expected = FE_SW_RX_CPU;
		if (native & BIT(port))
			expected &= ~FE_SW_RX_BYPASS;
		else if (route & BIT(port))
			expected = FE_SW_RX_BYPASS | (25U << 16);
		value = fe_read(fe, FE_LAN_RX_CTRL(port));
		if (value == ~0U ||
		    (value & (FE_SW_RX_DEST_MASK | FE_SW_RX_BYPASS)) != expected)
			verified = false;
	}
	return verified;
}

static bool fe_switch_hw_route_closed(struct rtl_fe *fe)
{
	unsigned int i, value;

	/* Disable clears enabled before deleting cached flows. Admission proof
	 * must outlive that administrative flag, until all prepared/DMA/route
	 * exposure and retained withdrawals have actually disappeared. */
	if (!(READ_ONCE(fe->route_gate_ready) || READ_ONCE(fe->prepared) ||
	      READ_ONCE(fe->dma_exposed) || READ_ONCE(fe->enabled) ||
	      READ_ONCE(fe->pending_withdrawals)))
		return true;
	if (!READ_ONCE(fe->route_gate_verified))
		return false;
	/* The latch records the last gate operation, not future MMIO state.
	 * Recheck both L3 connectors without touching a cold foreign engine. */
	for (i = 0; i < 2; i++) {
		value = fe_read(fe, 0x3418 + i * 12);
		if (value == ~0U || ((value >> 10) & 15U) != 1U)
			return false;
	}
	return true;
}

static void fe_switch_hw_gate(struct rtl_fe *fe, struct rtl_fe_switch_hw *hw)
{
	unsigned int port, value;
	bool verified = true;

	/* This also closes PON -> L3 -> LAN old-flow admission. LAN selectors
	 * alone cannot guard an ingress physically coming from the PON. */
	fe_route_gate(fe);
	WRITE_ONCE(hw->rx_gate_verified, false);
	for (port = 0; port < FE_LAN_PORTS; port++) {
		value = fe_read(fe, FE_LAN_RX_CTRL(port));
		if (value == ~0U) {
			verified = false;
			continue;
		}
		value = (value & ~FE_SW_RX_DEST_MASK) | FE_SW_RX_CPU;
		fe_write(fe, FE_LAN_RX_CTRL(port), value);
	}
	/* A posted read alone is not proof the selector accepted the write.
	 * Check every owned port, even if one earlier RMW read was invalid. */
	if (!fe_switch_hw_rx_check(fe, 0, 0))
		verified = false;
	WRITE_ONCE(hw->rx_gate_verified, verified);
	WRITE_ONCE(hw->drained, false);
}

static bool fe_switch_hw_pending(struct rtl_fe *fe)
{
	unsigned int packets = fe_read(fe, 0x11c0);

	/* PP counts are 16-bit SOP/EOP, not the unrelated PP ready bit. The
 	 * other fields are occupancy (not cumulative packet counters). */
	return (packets & 0xffffU) != (packets >> 16) ||
	       (fe_read(fe, 0x1534) & 0x3fU) ||
	       (fe_read(fe, 0x175c) & 0xffU) ||
	       (fe_read(fe, 0x1904) & 0x7ffffU);
}

static int fe_switch_hw_drain(struct rtl_fe *fe, struct rtl_fe_switch_hw *hw)
{
	struct rtl_dq_io io = fe_io(fe);
	unsigned int attempt, stable = 0, control;
	int ret;

	fe_switch_hw_gate(fe, hw);
	if (!hw->globals_owned && !hw->count && !hw->limits_owned && !hw->journal.quarantined &&
	    !hw->journal.restoring)
		return 0;
	if (!READ_ONCE(hw->rx_gate_verified) || !fe_switch_hw_route_closed(fe)) {
		hw->reason = FE_SW_HW_ADMISSION;
		return -EIO;
	}
	if ((fe_read(fe, RTL_L2_FDB_ACCESS) |
	     fe_read(fe, RTL_L2_FDB_LIMIT_ACCESS)) & RTL_L2_ACCESS_BUSY) {
		hw->reason = FE_SW_HW_BUSY;
		return -EBUSY;
	}
	if (hw->globals_owned) {
		control = fe_read(fe, RTL_L2_FDB_CONTROL);
		if (control == ~0U || (control & FE_SW_FDB_INIT))
			return -EBUSY;
		fe_write(fe, RTL_L2_FDB_CONTROL,
			 control | RTL_L2_FDB_LEARN_DISABLE);
		control = fe_read(fe, RTL_L2_FDB_CONTROL);
		if (control == ~0U || !(control & RTL_L2_FDB_LEARN_DISABLE))
			return -EIO;
	}
	/* Do not substitute a fixed sleep or return success on timeout. Three
	 * empty observations cover the independently sampled stage counters.
	 * Non-LAN traffic can delay this shared-pipeline barrier; timeout keeps
	 * our ownership and admission closed rather than changing live tables.
	 */
	for (attempt = 0; attempt < 10000; attempt++) {
		if (!fe_switch_hw_pending(fe)) {
			if (++stable == 3) {
				/* A late limit transaction may have retained mode0.
				 * Recover only our owned, idle, learning-stopped lease,
				 * before the bridge uses SCAN to delete its own rows. */
				ret = hw->globals_owned ? rtl_l2_fdb_command_mode(&io) : 0;
				if (ret)
					return ret;
				WRITE_ONCE(hw->drained, true);
				return 0;
			}
		} else {
			stable = 0;
		}
		usleep_range(10, 20);
	}
	hw->reason = FE_SW_HW_DRAIN;
	return -ETIMEDOUT;
}

static struct rtl_l2_snapshot *
fe_switch_hw_snapshot_find(struct rtl_fe_switch_hw *hw,
			  enum rtl_l2_table table, unsigned int index)
{
	struct rtl_l2_snapshot *snapshot;

	return rtl_l2_journal_find(&hw->journal, hw->rows, hw->count,
				   table, index, &snapshot) ? NULL : snapshot;
}

static int fe_switch_hw_snapshot(struct rtl_fe *fe, struct rtl_fe_switch_hw *hw,
				enum rtl_l2_table table, unsigned int index,
				struct rtl_l2_snapshot **snapshot)
{
	struct rtl_dq_io io = fe_io(fe);

	return rtl_l2_journal_snapshot(&hw->journal, &io, hw->rows, &hw->count,
				       table, index, snapshot);
}

static int fe_switch_hw_replace(struct rtl_fe *fe, struct rtl_fe_switch_hw *hw,
			       enum rtl_l2_table table, unsigned int index,
			       const unsigned int *words)
{
	struct rtl_dq_io io = fe_io(fe);

	return rtl_l2_journal_replace(&hw->journal, &io, hw->rows, &hw->count,
				      table, index, words);
}

static unsigned int fe_switch_hw_field(const unsigned int *words,
				      enum rtl_l2_field field)
{
	unsigned int value = 0;

	rtl_l2_field_get(words, field, &value);
	return value;
}

static bool fe_switch_hw_cf_source(const unsigned int *x, const unsigned int *y,
				   unsigned int source)
{
	unsigned int care = (x[0] ^ y[0]) & (0x3fU << 6);
	unsigned int data = ~x[0] & y[0];

	return !(((source << 6) ^ data) & care);
}

static int fe_switch_hw_cf_claim(struct rtl_fe *fe, struct rtl_fe_switch_hw *hw)
{
	struct rtl_dq_io io = fe_io(fe);
	unsigned int x[3], y[3], fib[3], index, port, needed = 0;
	unsigned int free_slots[FE_SW_CF_RULES], free_count = 0;
	int ret;

	hw->reason = FE_SW_HW_CLASSIFIER;
	/* Existing QM catchalls p=0..4 are already explicitly owned by this
	 * driver. Every other valid rule intersecting these sources is foreign.
	 * Do not assume a high rule number is free or wins TCAM priority. */
	for (index = 0; index < RTL_L2_CF_ENTRIES; index++) {
		ret = rtl_l2_table_read(&io, RTL_L2_TBL_CF_KEY, index, x);
		if (!ret)
			ret = rtl_l2_table_read(&io, RTL_L2_TBL_CF_KEY,
						index + RTL_L2_CF_ENTRIES, y);
		if (ret)
			return ret;
		if (!((x[2] | y[2]) & BIT(16))) {
			if (index >= FE_LAN_PORTS && free_count < FE_SW_CF_RULES)
				free_slots[free_count++] = index;
			continue;
		}
		for (port = 0; port < FE_LAN_PORTS; port++) {
			if (!(hw->ports & BIT(port)) ||
			    !fe_switch_hw_cf_source(x, y, port))
				continue;
			/* KEY2 reserved bits need not read back the written ones. */
			if (index != port || x[0] != ~(port << 6) ||
			    y[0] != (~0xfc0U | (port << 6)) ||
			    x[1] != ~0U || y[1] != ~0U ||
			    (x[2] & 0x1f8ffU) != 0x1f8ffU ||
			    (y[2] & 0x1f8ffU) != 0x1f8ffU)
				return -EBUSY;
			ret = rtl_l2_table_read(&io, RTL_L2_TBL_CF_FIB, index, fib);
			if (ret)
				return ret;
			if (fib[0] || fib[1] != ((3U << 5) | (16U << 8)) ||
			    (fib[2] & 0x3ffU) != BIT(6))
				return -EBUSY;
		}
	}
	for (port = 0; port < FE_LAN_PORTS; port++) {
		if (!(hw->ports & BIT(port)))
			continue;
		if (needed + FE_SW_CF_PER_PORT - 1 > free_count)
			return -ENOSPC;
		hw->cf[hw->cf_count++] = port;
		for (index = 1; index < FE_SW_CF_PER_PORT; index++)
			hw->cf[hw->cf_count++] = free_slots[needed++];
	}
	return 0;
}

static int fe_switch_hw_cf_install(struct rtl_fe *fe, struct rtl_fe_switch_hw *hw)
{
	struct rtl_l2_snapshot *xrow, *yrow, *frow;
	unsigned int x[3], y[3], fib[3], port, kind, id, slot = 0;
	int ret;

	for (port = 0; port < FE_LAN_PORTS; port++) {
		if (!(hw->ports & BIT(port)))
			continue;
		for (kind = 0; kind < FE_SW_CF_PER_PORT; kind++) {
			id = hw->cf[slot++];
			ret = fe_switch_hw_snapshot(fe, hw, RTL_L2_TBL_CF_KEY, id, &xrow);
			if (!ret)
				ret = fe_switch_hw_snapshot(fe, hw, RTL_L2_TBL_CF_KEY,
							id + RTL_L2_CF_ENTRIES, &yrow);
			if (!ret)
				ret = fe_switch_hw_snapshot(fe, hw, RTL_L2_TBL_CF_FIB, id, &frow);
			if (ret)
				return ret;
			if (kind < 2)
				ret = rtl_l2_cf_tag_key(x, y, port, kind);
			else
				ret = rtl_l2_cf_pkt_type_key(x, y, port,
					kind == 2 ? RTL_L2_CF_BROADCAST :
					kind == 3 ? RTL_L2_CF_MULTICAST :
					RTL_L2_CF_UNKNOWN_MULTICAST);
			if (ret)
				return ret;
			rtl_l2_cf_destination(fib, 16);
			/* Ingress is closed and drained. Program the action before the
			 * replacement valid keys; retain originals on any timeout. */
			ret = fe_switch_hw_replace(fe, hw, RTL_L2_TBL_CF_FIB, id, fib);
			if (!ret)
				ret = fe_switch_hw_replace(fe, hw, RTL_L2_TBL_CF_KEY, id, x);
			if (!ret)
				ret = fe_switch_hw_replace(fe, hw, RTL_L2_TBL_CF_KEY,
							id + RTL_L2_CF_ENTRIES, y);
			if (ret)
				return ret;
		}
	}
	return 0;
}

static void fe_switch_hw_native_ilpb(unsigned int *words, unsigned int profile)
{
	static const enum rtl_l2_field zero[] = {
		RTL_L2_ILPB_INGRESS_FILTER, RTL_L2_ILPB_DSCP_MARK,
		RTL_L2_ILPB_DSCP_MODE, RTL_L2_ILPB_DSCP_MARKDOWN,
		RTL_L2_ILPB_DEFAULT_DSCP, RTL_L2_ILPB_DEFAULT_PRIORITY,
		RTL_L2_ILPB_PRIORITY_MARK_LOW, RTL_L2_ILPB_PRIORITY_MARK_HIGH,
		RTL_L2_ILPB_INNER_PRIORITY_MODE, RTL_L2_ILPB_TOP_PRIORITY_MODE,
		RTL_L2_ILPB_CHANGE_PRIORITY_ON_POP, RTL_L2_ILPB_DA_SA_SWAP,
		RTL_L2_ILPB_CLASSIFIER_ENABLE, RTL_L2_ILPB_CLASSIFIER_LENGTH,
		RTL_L2_ILPB_CLASSIFIER_START, RTL_L2_ILPB_LOOP_ENABLE,
		RTL_L2_ILPB_SA_MOVE_DISABLE_FORWARD, RTL_L2_ILPB_WAN,
		RTL_L2_ILPB_CPU_PORT, RTL_L2_ILPB_SC_IND, RTL_L2_ILPB_DEFAULT_VID,
		RTL_L2_ILPB_INNER_S_TPID_ENABLE, RTL_L2_ILPB_TOP_S_TPID_ENABLE,
		RTL_L2_ILPB_S_TPID_MATCH, RTL_L2_ILPB_DROP_DOUBLE_TAG,
		RTL_L2_ILPB_DROP_PRIORITY_TAG, RTL_L2_ILPB_DROP_UNTAGGED,
		RTL_L2_ILPB_DROP_C_TAG, RTL_L2_ILPB_DROP_S_TAG,
		RTL_L2_ILPB_DROP_SINGLE_TAG, RTL_L2_ILPB_NON_INNER_TAG_COMMAND,
		RTL_L2_ILPB_INNER_VLAN_COMMAND, RTL_L2_ILPB_UNTAG_COMMAND,
		RTL_L2_ILPB_TOP_VLAN_COMMAND, RTL_L2_ILPB_VLAN_COMMAND_SELECT,
		RTL_L2_ILPB_INNER_VID_SELECT, RTL_L2_ILPB_SA_LIMIT_DROP,
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(zero); i++)
		rtl_l2_field_set(words, zero[i], 0);
	rtl_l2_field_set(words, RTL_L2_ILPB_STP, RTL_L2_STP_FORWARD_AND_LEARN);
	rtl_l2_field_set(words, RTL_L2_ILPB_STATION_MOVE_ENABLE, 1);
	rtl_l2_field_set(words, RTL_L2_ILPB_SA_MISS_FORWARD, 1);
	rtl_l2_field_set(words, RTL_L2_ILPB_SPECIAL_PROFILE, profile);
	/* __aal_fdb_sc_ind_get(): top C=1/S=0 selects SC0; enabling both
	 * does NOT. Recognise built-ins plus the C user comparator as C tags.
	 * CMP_S/C/O/USER are class-specific user comparators, not four slots
	 * replacing the built-in 8100/9100/88a8 recognition (SDK vlan.c).
	 * ILPB.sc_ind alone is only the PVID default, not a tagged-S override.
	 */
	rtl_l2_field_set(words, RTL_L2_ILPB_INNER_C_TPID_ENABLE, 1);
	rtl_l2_field_set(words, RTL_L2_ILPB_TOP_C_TPID_ENABLE, 1);
	rtl_l2_field_set(words, RTL_L2_ILPB_C_TPID_MATCH, FE_SW_TPID_ALL);
	rtl_l2_field_set(words, RTL_L2_ILPB_OTHER_TPID_MATCH, FE_SW_TPID_ALL);
}

static void fe_switch_hw_native_elpb(unsigned int *words)
{
	unsigned int field;

	/* All documented ELPB edits/classifiers are disabled, preserving any
	 * reserved bits from the snapshot. This is an untagged LAN contract. */
	for (field = RTL_L2_ELPB_VLAN_AWARE;
	     field <= RTL_L2_ELPB_USE_TX_VLAN_ACL; field++)
		rtl_l2_field_set(words, field, 0);
	rtl_l2_field_set(words, RTL_L2_ELPB_STP_FORWARD, 1);
}

static int fe_switch_hw_profile_no_learning(struct rtl_fe *fe,
					   unsigned int profile)
{
	struct rtl_dq_io io = fe_io(fe);
	unsigned int words[RTL_L2_TABLE_MAX_WORDS], type;
	int ret;

	for (type = 0; type < RTL_L2_SPB_PACKET_TYPES; type++) {
		ret = rtl_l2_table_read(&io, RTL_L2_TBL_SPB,
					profile * RTL_L2_SPB_PACKET_TYPES + type, words);
		if (ret)
			return ret;
		if (!fe_switch_hw_field(words, RTL_L2_SPB_LEARN_DISABLE))
			return 0;
	}
	return 1;
}

static int fe_switch_hw_ports(struct rtl_fe *fe, struct rtl_fe_switch_hw *hw)
{
	struct rtl_dq_io io = fe_io(fe);
	struct rtl_l2_snapshot *snapshot;
	unsigned int words[RTL_L2_TABLE_MAX_WORDS], used = 0, profile;
	unsigned int no_learning = 0;
	unsigned int port, type, stp, i;
	unsigned int target = hw->route_policy_allowed && fe->enabled && fe->prepared ? 25 : 16;
	int ret;

	hw->reason = FE_SW_HW_LEARNING;
	/* No global HW-learning enable may start learning from PON, CPUs or
	 * a different LAN domain. If global learning was disabled, clearing
	 * only outside STP's learning bit preserves its old forward behaviour.
	 * Otherwise an outside learning-capable port is an ownership conflict.
	 */
	for (port = 0; port < RTL_L2_LOGICAL_PORTS; port++) {
		ret = rtl_l2_table_read(&io, RTL_L2_TBL_ILPB, port, words);
		if (ret)
			return ret;
		if (port < FE_LAN_PORTS && (hw->ports & BIT(port)))
			continue;
		profile = fe_switch_hw_field(words, RTL_L2_ILPB_SPECIAL_PROFILE);
		if (profile >= RTL_L2_SPB_PROFILES)
			return -EOPNOTSUPP;
		used |= BIT(profile);
		stp = fe_switch_hw_field(words, RTL_L2_ILPB_STP);
		if (!(stp & 1))
			continue;
		if (port >= FE_LAN_PORTS && !(hw->control & RTL_L2_FDB_LEARN_DISABLE)) {
			if (!(no_learning & BIT(profile))) {
				ret = fe_switch_hw_profile_no_learning(fe, profile);
				if (ret <= 0) {
					hw->observed.learning_port = port;
					hw->observed.learning_profile = profile;
					return ret ? ret : -EBUSY;
				}
				no_learning |= BIT(profile);
			}
			continue;
		}
		/* Other physical LANs are also this NI owner's ports. Its sole RX
		 * owner keeps them on bypass CPU/L3, so temporarily disabling their
		 * latent native-L2 learning is safe even if old global learning ran.
		 * No such exception is inferred for PON or CPU/recirculation ports. */
		rtl_l2_field_set(words, RTL_L2_ILPB_STP, stp & ~1U);
		ret = fe_switch_hw_replace(fe, hw, RTL_L2_TBL_ILPB, port, words);
		if (ret)
			return ret;
	}
	for (profile = RTL_L2_SPB_PROFILES; profile; profile--)
		if (!(used & BIT(profile - 1)))
			break;
	if (!profile) {
		hw->reason = FE_SW_HW_PROFILE;
		return -ENOSPC;
	}
	hw->reason = FE_SW_HW_TABLE;
	hw->special_profile = --profile;
	hw->local_target = target;
	for (type = 0; type < RTL_L2_SPB_PACKET_TYPES; type++) {
		ret = fe_switch_hw_snapshot(fe, hw, RTL_L2_TBL_SPB,
					   profile * RTL_L2_SPB_PACKET_TYPES + type, &snapshot);
		if (ret)
			return ret;
		memcpy(words, snapshot->words, sizeof(words));
		/* Every field is defined in this word; normal packets continue to
		 * the ordinary FDB/DFT result. All special/control packets trap. */
		words[0] = 0;
		rtl_l2_field_set(words, RTL_L2_SPB_NO_EDIT, 1);
		if (type) {
			rtl_l2_field_set(words, RTL_L2_SPB_LEARN_DISABLE, 1);
			rtl_l2_field_set(words, RTL_L2_SPB_SPECIAL_FORWARD, 1);
			rtl_l2_field_set(words, RTL_L2_SPB_DESTINATION, type == 12 ? target : 16);
		}
		ret = fe_switch_hw_replace(fe, hw, RTL_L2_TBL_SPB,
					 profile * RTL_L2_SPB_PACKET_TYPES + type, words);
		if (ret)
			return ret;
	}
	for (port = 0; port < FE_LAN_PORTS; port++) {
		if (!(hw->ports & BIT(port)))
			continue;
		ret = fe_switch_hw_snapshot(fe, hw, RTL_L2_TBL_ILPB, port, &snapshot);
		if (ret)
			return ret;
		memcpy(words, snapshot->words, sizeof(words));
		fe_switch_hw_native_ilpb(words, profile);
		ret = fe_switch_hw_replace(fe, hw, RTL_L2_TBL_ILPB, port, words);
		if (ret)
			return ret;
		ret = fe_switch_hw_snapshot(fe, hw, RTL_L2_TBL_ELPB, port, &snapshot);
		if (ret)
			return ret;
		memcpy(words, snapshot->words, sizeof(words));
		fe_switch_hw_native_elpb(words);
		ret = fe_switch_hw_replace(fe, hw, RTL_L2_TBL_ELPB, port, words);
		if (ret)
			return ret;
		/* aal_port_mmshp_check_set(source, destination bitmap). Do not
		 * change the unrelated 4-bit VLAN membership-ID map. */
		words[0] = (hw->ports & ~BIT(port)) | BIT(16) | BIT(target);
		words[1] = 0;
		ret = fe_switch_hw_replace(fe, hw, RTL_L2_TBL_PORT_MEMBERSHIP, port, words);
		if (ret)
			return ret;
		for (i = 0; i < 4; i++) {
			/* Exact RTL8277C DAL ACTION_TRAP2CPU recipe: the group-valid
			 * field is also set for this direct LDPID redirect. No MCE. */
			words[0] = 0;
			rtl_l2_field_set(words, RTL_L2_DFT_GROUP, 16);
			rtl_l2_field_set(words, RTL_L2_DFT_REDIRECT, 1);
			rtl_l2_field_set(words, RTL_L2_DFT_GROUP_VALID, 1);
			ret = fe_switch_hw_replace(fe, hw, RTL_L2_TBL_DFT_FWD, port * 4 + i, words);
			if (ret)
				return ret;
		}
	}
	return 0;
}

/* Foreign redirects may defeat an otherwise correct membership matrix.
 * There is no documented drop-reason ID for port isolation in this SDK,
 * so do not guess one: require all drop redirects disabled, plus the
 * redirects of every destination this native domain can select. These
 * shared tables and the multicast-check enable remain foreign-owned.
 */
static int fe_switch_hw_redirects_check(struct rtl_fe *fe,
					struct rtl_fe_switch_hw *hw)
{
	struct rtl_dq_io io = fe_io(fe);
	unsigned int words[RTL_L2_TABLE_MAX_WORDS], index;
	unsigned int destinations = hw->ports | BIT(16) | BIT(hw->local_target);
	int ret;

	hw->reason = FE_SW_HW_REDIRECT;
	for (index = 0; index < 32; index++) {
		ret = rtl_l2_table_read(&io, RTL_L2_TBL_REDIR_DROP, index, words);
		if (ret)
			return ret;
		if (words[0] & RTL_L2_POLICY_REDIRECT_ENABLE)
			return -EOPNOTSUPP;
		if (!(destinations & BIT(index)))
			continue;
		ret = rtl_l2_table_read(&io, RTL_L2_TBL_REDIR_LDPID, index, words);
		if (ret)
			return ret;
		if (words[0] & RTL_L2_POLICY_REDIRECT_ENABLE)
			return -EOPNOTSUPP;
	}
	return 0;
}

/* Apply only after prepare, while all ingress is gated and drained. The
 * original snapshots belong to the existing native transaction; never
 * overwrite them with an intermediate learning/isolation configuration.
 * A failed command is not cancellation. Retain ownership and leave arm
 * disabled until retry succeeds or the caller drains/restores everything.
 */
static int fe_switch_hw_port_policy(struct rtl_fe *fe,
				    struct rtl_fe_switch_hw *hw,
				    unsigned int learning_mask,
				    unsigned int isolated_mask)
{
	struct rtl_l2_port_policy policy[FE_LAN_PORTS];
	struct rtl_l2_snapshot *snapshot;
	unsigned int words[RTL_L2_TABLE_MAX_WORDS];
	unsigned int port;
	int ret;

	if (!hw->globals_owned || !READ_ONCE(hw->prepared) ||
	    !READ_ONCE(hw->drained) || hw->journal.quarantined || hw->journal.restoring)
		return -EBUSY;
	WRITE_ONCE(hw->port_policy_ready, false);
	hw->reason = FE_SW_HW_PORT_POLICY;
	if (!hw->ports || (hw->ports & ~FE_SW_LAN_MASK) ||
	    ((learning_mask | isolated_mask) & ~hw->ports))
		return -EINVAL;
	/* Validate every row's existing ownership before the first mutation. */
	for (port = 0; port < FE_LAN_PORTS; port++) {
		if (!(hw->ports & BIT(port)))
			continue;
		ret = rtl_l2_port_policy_build(hw->ports, learning_mask,
			isolated_mask, port, hw->local_target, &policy[port]);
		if (ret)
			return ret;
		snapshot = fe_switch_hw_snapshot_find(hw, RTL_L2_TBL_ILPB, port);
		if (!snapshot || !snapshot->valid)
			return -EIO;
		snapshot = fe_switch_hw_snapshot_find(hw, RTL_L2_TBL_PORT_MEMBERSHIP, port);
		if (!snapshot || !snapshot->valid)
			return -EIO;
	}
	if (isolated_mask) {
		hw->reason = FE_SW_HW_ISOLATION;
		if (!rtl_l2_port_policy_mc_check(fe_read(fe, RTL_L2_POLICY_ARB_EXT)))
			return -EOPNOTSUPP;
	}
	/* CPU traps and native known-unicast destinations need this proof even
	 * without port isolation. A redirect on CPU16 can otherwise turn BUM,
	 * BPDU/control or a software fallback into a foreign/PON egress. */
	ret = fe_switch_hw_redirects_check(fe, hw);
	if (ret)
		return ret;
	hw->reason = FE_SW_HW_PORT_POLICY;
	for (port = 0; port < FE_LAN_PORTS; port++) {
		if (!(hw->ports & BIT(port)))
			continue;
		snapshot = fe_switch_hw_snapshot_find(hw, RTL_L2_TBL_ILPB, port);
		memcpy(words, snapshot->words, sizeof(words));
		fe_switch_hw_native_ilpb(words, hw->special_profile);
		rtl_l2_field_set(words, RTL_L2_ILPB_STP, policy[port].stp);
		ret = fe_switch_hw_replace(fe, hw, RTL_L2_TBL_ILPB, port, words);
		if (ret)
			return ret;
		ret = fe_switch_hw_replace(fe, hw, RTL_L2_TBL_PORT_MEMBERSHIP,
					 port, policy[port].members);
		if (ret)
			return ret;
	}
	if (isolated_mask &&
	    !rtl_l2_port_policy_mc_check(fe_read(fe, RTL_L2_POLICY_ARB_EXT))) {
		hw->reason = FE_SW_HW_ISOLATION;
		return -EOPNOTSUPP;
	}
	hw->learning_mask = learning_mask;
	hw->isolated_mask = isolated_mask;
	hw->reason = FE_SW_HW_OK;
	WRITE_ONCE(hw->port_policy_ready, true);
	return 0;
}

/* Replace only the native owner's existing CPU DFT producers. MCE rows
 * have an independent FE-lifetime owner because a local L2 drain does not
 * prove that copies already queued in MCE/NI have disappeared. Mark each
 * immutable group published BEFORE exposing its number in a producer; a
 * command timeout can never turn that number into a reusable allocation.
 */
static int fe_switch_hw_mcast_groups(struct rtl_fe *fe,
		struct rtl_fe_switch_hw *hw, const struct rtl_mcast_groups *groups)
{
	struct rtl_l2_snapshot *snapshot;
	unsigned int words[RTL_L2_TABLE_MAX_WORDS], x[3], y[3];
	unsigned int port, kind, slot = 0, id, enabled;
	int ret;

	if (!groups || hw->vlan_plan || !hw->globals_owned ||
	    !READ_ONCE(hw->prepared) || !READ_ONCE(hw->drained) ||
	    !READ_ONCE(hw->port_policy_ready) || hw->journal.quarantined ||
	    hw->journal.restoring)
		return -EBUSY;
	/* Validate the complete producer set before the first publication. */
	for (port = 0; port < FE_LAN_PORTS; port++) {
		enabled = groups->enabled[port];
		if ((enabled & ~15U) || (enabled && !(hw->ports & BIT(port))))
			return -EINVAL;
		/* CF distinguishes known/unknown multicast, not L2/L3 DFT class.
		 * Both classes must have a safe vector before either trap is removed. */
		if ((enabled & 12U) && (enabled & 12U) != 12U)
			return -EINVAL;
		for (kind = 0; kind < 4; kind++) {
			if (!(enabled & BIT(kind)))
				continue;
			if (groups->group[port][kind] >= RTL_L2_MC_VECTOR_ENTRIES)
				return -EINVAL;
			snapshot = fe_switch_hw_snapshot_find(hw, RTL_L2_TBL_DFT_FWD,
							port * 4 + kind);
			if (!snapshot || !snapshot->valid)
				return -EIO;
		}
	}
	WRITE_ONCE(hw->port_policy_ready, false);
	for (port = 0; port < FE_LAN_PORTS; port++) {
		if (!(hw->ports & BIT(port)))
			continue;
		enabled = groups->enabled[port];
		for (kind = 0; kind < 4; kind++) {
			if (!(enabled & BIT(kind)))
				continue;
			snapshot = fe_switch_hw_snapshot_find(hw, RTL_L2_TBL_DFT_FWD,
							port * 4 + kind);
			memcpy(words, snapshot->words, sizeof(words));
			ret = rtl_l2_dft_flood_build(groups->group[port][kind],
						    words[0], words);
			if (ret)
				return ret;
			ret = fe_mcast_publish(fe, groups->group[port][kind]);
			if (!ret)
				ret = fe_switch_hw_replace(fe, hw, RTL_L2_TBL_DFT_FWD,
							   port * 4 + kind, words);
			if (ret)
				return ret;
		}
		/* Keep tagged frames and special/control packets on CPU. Those
		 * traps are independent of ordinary broadcast/multicast flooding. */
		for (kind = 2; kind < FE_SW_CF_PER_PORT; kind++) {
			if (!(kind == 2 ? enabled & BIT(0) : (enabled & 12U) == 12U))
				continue;
			id = hw->cf[slot + kind];
			ret = rtl_l2_cf_pkt_type_key(x, y, port,
				kind == 2 ? RTL_L2_CF_BROADCAST :
				kind == 3 ? RTL_L2_CF_MULTICAST :
				RTL_L2_CF_UNKNOWN_MULTICAST);
			if (ret)
				return ret;
			x[2] &= ~BIT(16);
			y[2] &= ~BIT(16);
			ret = fe_switch_hw_replace(fe, hw, RTL_L2_TBL_CF_KEY, id, x);
			if (!ret)
				ret = fe_switch_hw_replace(fe, hw, RTL_L2_TBL_CF_KEY,
							   id + RTL_L2_CF_ENTRIES, y);
			if (ret)
				return ret;
		}
		hw->bum_enabled[port] = enabled;
		slot += FE_SW_CF_PER_PORT;
	}
	WRITE_ONCE(hw->port_policy_ready, true);
	return 0;
}

/* Exact MDB keys/actions are already installed and verified by the FE
 * classifier owner. Only then may MC packets from those ingress ports be
 * directed to the normal LAN L3 connector. Its misses must retain the
 * original CPU packet; this helper never opens that engine on its own.
 */
static int fe_switch_hw_mdb_steer(struct rtl_fe *fe,
				struct rtl_fe_switch_hw *hw, unsigned int ports)
{
	unsigned int port, kind, slot = 0, fib[3];
	int ret;

	if (!ports)
		return 0;
	if ((ports & ~hw->ports) || hw->vlan_plan || !hw->globals_owned ||
	    !READ_ONCE(hw->prepared) || !READ_ONCE(hw->drained) ||
	    !READ_ONCE(hw->port_policy_ready) || hw->journal.quarantined ||
	    hw->journal.restoring)
		return -EBUSY;
	if (!hw->route_policy_allowed || !fe->enabled || !fe->prepared ||
	    hw->local_target != 25)
		return -EOPNOTSUPP;
	/* Snooping-off generic MC and exact MDB are mutually exclusive. */
	for (port = 0; port < FE_LAN_PORTS; port++)
		if ((ports & BIT(port)) && (hw->bum_enabled[port] & 12U))
			return -EINVAL;
	WRITE_ONCE(hw->port_policy_ready, false);
	rtl_l2_cf_destination(fib, 25);
	for (port = 0; port < FE_LAN_PORTS; port++) {
		if (!(hw->ports & BIT(port)))
			continue;
		if (ports & BIT(port))
			for (kind = 3; kind < FE_SW_CF_PER_PORT; kind++) {
				ret = fe_switch_hw_replace(fe, hw, RTL_L2_TBL_CF_FIB,
							   hw->cf[slot + kind], fib);
				if (ret)
					return ret;
			}
		slot += FE_SW_CF_PER_PORT;
	}
	hw->mdb_ports = ports;
	WRITE_ONCE(hw->port_policy_ready, true);
	return 0;
}

static int fe_switch_hw_limit_write(struct rtl_fe *fe, unsigned int port,
				    unsigned int expected)
{
	struct rtl_dq_io io = fe_io(fe);
	unsigned int actual;
	int ret;

	ret = rtl_l2_port_limit_write(&io, port, expected);
	if (!ret)
		ret = rtl_l2_port_limit_read(&io, port, &actual);
	if (ret)
		return ret;
	return (actual ^ expected) & RTL_L2_FDB_LIMIT_MAX ? -EIO : 0;
}

/* All direct registers below are configuration words owned only under the
 * specified mask. Full-width scan-filter data may legitimately be all ones;
 * control/status words may not use a failed all-ones read as an RMW base.
 * Readback verifies persistent fields, never self-clearing command bits. */
static int fe_switch_hw_config_write(struct rtl_fe *fe, unsigned int address,
				     unsigned int expected, unsigned int mask)
{
	unsigned int value, actual;

	if (mask == ~0U) {
		value = expected;
	} else {
		value = fe_read(fe, address);
		if (value == ~0U)
			return -EIO;
		if (address == RTL_L2_FDB_CONTROL && (value & FE_SW_FDB_INIT))
			return -EBUSY;
		value = (value & ~mask) | (expected & mask);
	}
	fe_write(fe, address, value);
	actual = fe_read(fe, address);
	if ((mask != ~0U && actual == ~0U) || ((actual ^ value) & mask))
		return -EIO;
	return 0;
}

static int fe_switch_hw_limits(struct rtl_fe *fe, struct rtl_fe_switch_hw *hw)
{
	struct rtl_dq_io io = fe_io(fe);
	unsigned int port;
	int ret;

	hw->reason = FE_SW_HW_LIMIT;
	for (port = 0; port < FE_LAN_PORTS; port++) {
		if (!(hw->ports & BIT(port)))
			continue;
		ret = rtl_l2_port_limit_read(&io, port, &hw->limits[port]);
		if (ret)
			return ret;
		hw->limits_owned |= BIT(port);
		/* SDK initializes 0x1fff. Zero means zero learning, not unlimited.
		 * Never initialize the live count or flush a different domain. */
		ret = fe_switch_hw_limit_write(fe, port,
					      hw->limits[port] | RTL_L2_FDB_LIMIT_MAX);
		if (ret) {
			hw->journal.quarantined = 1;
			return ret;
		}
	}
	return 0;
}

/* Direct, read-only configuration evidence. This intentionally does not
 * issue indirect table commands or touch PON consumers. A CPU-FDB veto must
 * not hide an independent VLAN/hash/MRU contract failure from diagnostics.
 * Passing this check is not table ownership or permission to enable RX. */
static int fe_switch_hw_preflight(struct rtl_fe *fe, struct rtl_fe_switch_hw *hw,
				  unsigned int ports)
{
	unsigned int i;

	hw->reason = FE_SW_HW_OK;
	if (!ports || (ports & ~FE_SW_LAN_MASK))
		return -EINVAL;
	memset(&hw->observed, 0, sizeof(hw->observed));
	hw->observed.source_port = hw->observed.source_logical = ~0U;
	hw->observed.learning_port = hw->observed.learning_profile = ~0U;
	hw->observed.vlan_mode = fe_read(fe, RTL_L2_VLAN_MODE_CONTROL);
	hw->observed.hash_control = fe_read(fe, RTL_L2_FDB_HASH_CONTROL);
	hw->observed.aging = fe_read(fe, 0x1c04);
	hw->observed.packet_length = fe_read(fe, 0xa034);
	for (i = 0; i < FE_LAN_PORTS; i++)
		if (fe_read(fe, FE_LAN_RX_CTRL(i)) & BIT(5))
			hw->observed.rx_oversize_allow |= BIT(i);
	for (i = 0; i < 4; i++)
		hw->observed.tpid[i] = fe_read(fe, 0x1108 + i * 4);
	/* aal_fdb.c's actual SVL key builders force VID0/SC0. Do not infer
	 * this from ILPB PVID fields or from a late classifier tag redirect.
	 * Preserve PON's global mode: an existing IVL engine is unsupported,
	 * never silently converted and never globally flushed. */
	/* The VID-aware Linux control plane and the cold table owner are not
	 * a packet-parser contract. The pinned Taurus target does not compile
	 * generic vlan.c; its apparent IVL recipe cannot prove HASH_CTRL bits
	 * 0..2 or foreign LAN-index consumers. Keep this explicit even if a
	 * stale/corrupted mode read happens to show SVL for an IVL snapshot. */
	if (hw->vlan_plan || hw->observed.vlan_mode == ~0U ||
	    !(hw->observed.vlan_mode & RTL_L2_VLAN_MODE_SVL)) {
		hw->reason = hw->vlan_plan ? FE_SW_HW_IVL_CONTRACT : FE_SW_HW_VLAN_MODE;
		/* All-ones is not proof of SVL merely because that bit is set.
		 * Unknown shared lookup state is a retryable read failure, never
		 * permission to own the VID0 namespace or rewrite global mode. */
		return hw->observed.vlan_mode == ~0U ? -EIO : -EOPNOTSUPP;
	}
	if (hw->observed.hash_control == ~0U ||
	    (hw->observed.hash_control & RTL_L2_FDB_HASH_USE_PRIORITY)) {
		hw->reason = FE_SW_HW_PRIORITY_KEY;
		return hw->observed.hash_control == ~0U ? -EIO : -EOPNOTSUPP;
	}
	/* ILPB match bits1..3 select fixed 88a8/9100/8100 recognisers.
	 * All are enabled by native_ilpb, regardless of the user comparator
	 * values sampled above. Do not overwrite shared CMP registers or
	 * reject the reset baseline merely because none contains 88a8. */
	/* Cold fabric owns a bounded UNI MRU: MTU1500 plus two VLAN tags
	 * and FCS. GE has no proven tag-aware AUTO/oversize-only CPU trap.
	 * Tagged frames retain the CF CPU path; ordinary untagged frames use
	 * this physical envelope, including its small oversize allowance.
	 * Never admit the inherited 9201-byte jumbo envelope by accident. */
	if (((hw->observed.packet_length >> 16) & 0x3ffU) != 64 ||
	    (hw->observed.packet_length & 0x3fffU) != RTL_NI_FRAME_WIRE_BYTES ||
	    (hw->observed.rx_oversize_allow & ports)) {
		hw->reason = FE_SW_HW_MTU;
		return -EOPNOTSUPP;
	}
	return 0;
}

static int fe_switch_hw_prepare(struct rtl_fe *fe, struct rtl_fe_switch_hw *hw,
			       unsigned int ports, unsigned long ageing,
			       bool snooping, bool route_policy_allowed)
{
	struct rtl_dq_io io = fe_io(fe);
	unsigned int words[RTL_L2_TABLE_MAX_WORDS], filter[RTL_L2_FDB_FILTER_WORDS];
	unsigned int i, field;
	int ret;

	(void)snooping; /* Initial recipe traps MC; a separate snapshot may add MCE. */
	hw->reason = FE_SW_HW_OK;
	if (!ports || (ports & ~FE_SW_LAN_MASK) || ageing > 0x7ffffUL)
		return -EINVAL;
	if (hw->globals_owned || hw->count || hw->prepared || hw->limits_owned ||
	    hw->journal.quarantined || hw->journal.restoring)
		return -EALREADY;
	if (!hw->rows || !hw->journal.row_index ||
	    hw->journal.capacity != FE_SW_SNAPSHOTS ||
	    hw->journal.index_count != rtl_l2_journal_index_count())
		return -EINVAL;
	hw->route_policy_allowed = route_policy_allowed;
	fe_switch_hw_gate(fe, hw);
	if (!READ_ONCE(hw->rx_gate_verified) || !fe_switch_hw_route_closed(fe)) {
		hw->reason = FE_SW_HW_ADMISSION;
		return -EIO;
	}
	/* Recheck immediately before ownership; the earlier read-only worker
	 * sample is evidence, never a cached permission to use shared state. */
	ret = fe_switch_hw_preflight(fe, hw, ports);
	if (ret)
		return ret;
	/* IPPB precedes the ILPB learning decision. A foreign physical source
	 * aliasing a native LPID is not protected by that foreign LPID's STP.
	 * Validate all mappings; never rewrite PON/CPU mappings to claim them. */
	for (i = 0; i < RTL_L2_LOGICAL_PORTS; i++) {
		unsigned int source;

		hw->reason = FE_SW_HW_TABLE;
		ret = rtl_l2_table_read(&io, RTL_L2_TBL_IPPB, i, words);
		if (ret)
			return ret;
		source = fe_switch_hw_field(words, RTL_L2_IPPB_SOURCE);
		if (i < FE_LAN_PORTS) {
			if (source != i) {
				hw->observed.source_port = i;
				hw->observed.source_logical = source;
				hw->reason = FE_SW_HW_IDENTITY;
				return -EOPNOTSUPP;
			}
		} else if (source < FE_LAN_PORTS && (ports & BIT(source))) {
			hw->observed.source_port = i;
			hw->observed.source_logical = source;
			hw->reason = FE_SW_HW_SOURCE_ALIAS;
			return -EOPNOTSUPP;
		}
	}
	/* CPU16 is shared with PON and installed by QM. Validate rather than
	 * overwriting it: a tagged trap must not be edited on the CPU egress. */
	hw->reason = FE_SW_HW_CPU_EGRESS;
	ret = rtl_l2_table_read(&io, RTL_L2_TBL_ELPB, 16, words);
	if (ret)
		return ret;
	for (field = RTL_L2_ELPB_VLAN_AWARE;
	     field <= RTL_L2_ELPB_USE_TX_VLAN_ACL; field++)
		if (fe_switch_hw_field(words, field) != (field == RTL_L2_ELPB_STP_FORWARD))
			return -EOPNOTSUPP;
	/* NI demux remains 3 (L2TM), the ACTUAL aal_ni.c programmed default,
	 * not the unused temporary L2FE=2 value in that SDK function. */
	hw->reason = FE_SW_HW_QUEUE;
	if ((fe_read(fe, 0xa1dc) & 0xffffU) ||
	    (fe_read(fe, 0x2300) & (BIT(31) | ports | BIT(8) | BIT(9))) !=
				 (BIT(31) | ports | BIT(8) | BIT(9)))
		return -EOPNOTSUPP;
	hw->reason = FE_SW_HW_BUSY;
	if ((fe_read(fe, RTL_L2_FDB_ACCESS) |
	     fe_read(fe, RTL_L2_FDB_LIMIT_ACCESS)) & RTL_L2_ACCESS_BUSY)
		return -EBUSY;
	hw->ports = ports;
	hw->control = fe_read(fe, RTL_L2_FDB_CONTROL);
	if (hw->control == ~0U)
		return -EIO;
	if (hw->control & FE_SW_FDB_INIT)
		return -EBUSY; /* Unknown inherited FIFO initialization state. */
	hw->aging = fe_read(fe, 0x1c04);
	hw->requested_aging = (hw->aging & ~0x7ffffU) | (unsigned int)ageing;
	hw->learning = fe_read(fe, 0x1410);
	hw->learn_forward = fe_read(fe, 0x1408);
	hw->learn_exception = fe_read(fe, 0x140c);
	hw->demux = fe_read(fe, 0xa1e0) & 0x3ffU;
	if (hw->aging == ~0U || hw->learning == ~0U ||
	    hw->learn_forward == ~0U || hw->learn_exception == ~0U ||
	    fe_read(fe, 0xa1e0) == ~0U)
		return -EIO;
	hw->reason = FE_SW_HW_TIMER;
	if (!(hw->aging >> 19))
		return -EOPNOTSUPP;
	/* Preserve the firmware's nonzero timer divisor. This sanity check is
	 * not proof of its calibration: confirm actual aging time on the board.
	 * Do not substitute a guessed CPU/core clock or hard-coded 3830. */
	for (i = 0; i < RTL_L2_FDB_FILTER_WORDS; i++)
		hw->filter[i] = fe_read(fe, RTL_L2_FDB_FILTER_WORD0 - i * 4);
	/* Mark ownership BEFORE writes; a partial failure must be reversible. */
	hw->globals_owned = true;
	ret = fe_switch_hw_drain(fe, hw);
	if (ret)
		return ret;
	/* Own only physical LAN0..4 destination selectors. Standalone L2 does
	 * not require an earlier L3 prepare; all PON/other-port bits survive. */
	ret = fe_switch_hw_config_write(fe, 0xa1e0, 0x3ffU, 0x3ffU);
	if (ret)
		goto retained;
	hw->run_control = (hw->control & ~(RTL_L2_FDB_LEARN_MODE_MASK |
		RTL_L2_FDB_LEARN_DISABLE | RTL_L2_FDB_COLLISION_OVERWRITE |
		FE_SW_FDB_OVERFLOW_RECYCLE | BIT(2) | 0x7f8U | BIT(0))) |
		RTL_L2_FDB_CMD_MODE | RTL_L2_FDB_LEARN_HW | BIT(11) | 0x7f8U;
	if (ageing)
		hw->run_control |= BIT(0);
	/* Keep the original aging policy until the owner's complete SCAN has
	 * proved there is no foreign dynamic domain. arm applies the new time. */
	ret = fe_switch_hw_config_write(fe, RTL_L2_FDB_CONTROL,
		 (hw->control | RTL_L2_FDB_CMD_MODE | RTL_L2_FDB_LEARN_DISABLE) &
		 ~(RTL_L2_FDB_COLLISION_OVERWRITE | FE_SW_FDB_OVERFLOW_RECYCLE),
		 FE_SW_FDB_OWNED_CONTROL);
	/* Learn valid untagged/unknown-EtherType frames, never invalid source
	 * addresses, loops or ingress-dropped traffic. Preserve reserved bits. */
	if (!ret)
		ret = fe_switch_hw_config_write(fe, 0x1410, BIT(0) | BIT(2) | BIT(6), 0x7fU);
	memcpy(filter, hw->filter, sizeof(filter));
	rtl_l2_fdb_scan_filter(filter);
	for (i = 0; !ret && i < RTL_L2_FDB_FILTER_WORDS; i++)
		ret = fe_switch_hw_config_write(fe, RTL_L2_FDB_FILTER_WORD0 - i * 4,
						filter[i], ~0U);
	if (ret)
		goto retained;
	ret = fe_switch_hw_cf_claim(fe, hw);
	if (!ret)
		ret = fe_switch_hw_ports(fe, hw);
	if (!ret)
		ret = fe_switch_hw_redirects_check(fe, hw);
	if (!ret)
		ret = fe_switch_hw_limits(fe, hw);
	if (!ret) {
		/* SDK aal_fdb_init permits forwarding on a static-SA move. A
		 * Linux static destination FDB row is not source-port locking. */
		ret = fe_switch_hw_config_write(fe, 0x1408, hw->learn_forward | BIT(29), BIT(29));
		/* A full/busy FDB bucket must fall back, not inherit reset DROP.
		 * SDK enum REDIRECT=1, CPU0 LDPID=16, COS=0. Keep all unspecified
		 * keep-old flags; their names alone do not prove edit semantics. */
		if (!ret)
			ret = fe_switch_hw_config_write(fe, 0x140c,
				16U | (1U << 9) | (16U << 16) | (1U << 25),
				0x7ffU | (0x7ffU << 16));
	}
	if (!ret)
		ret = fe_switch_hw_cf_install(fe, hw);
	if (ret)
		goto retained;
	hw->reason = FE_SW_HW_OK;
	hw->learning_mask = ports;
	hw->isolated_mask = 0;
	WRITE_ONCE(hw->port_policy_ready, true);
	WRITE_ONCE(hw->prepared, true);
	return 0;

retained:
	hw->journal.quarantined = 1;
	return ret;
}

static int fe_switch_hw_restore(struct rtl_fe *fe, struct rtl_fe_switch_hw *hw)
{
	struct rtl_dq_io io = fe_io(fe);
	struct rtl_l2_snapshot *rows = hw->rows;
	struct rtl_l2_journal journal;
	enum fe_switch_hw_reason reason = hw->reason;
	struct fe_switch_hw_observed observed = hw->observed;
	unsigned int i, control;
	int ret;

	/* Caller has first drained and deleted only its claimed FDB domain.
	 * SCAN filter remains ours until those deletes finish. */
	if (!hw->globals_owned && !hw->count && !hw->limits_owned &&
	    !hw->journal.quarantined && !hw->journal.restoring) {
		WRITE_ONCE(hw->prepared, false);
		WRITE_ONCE(hw->port_policy_ready, false);
		return 0;
	}
	if (!READ_ONCE(hw->drained))
		return -EBUSY;
	WRITE_ONCE(hw->port_policy_ready, false);
	/* A recorded drain is not a lease on future selector state. Recheck
	 * closed LAN admission and the shared L3 gate before the first restore.
	 * Never free retained rows merely because momentary occupancy is zero. */
	if (!READ_ONCE(hw->rx_gate_verified) || !fe_switch_hw_rx_check(fe, 0, 0) ||
	    !fe_switch_hw_route_closed(fe)) {
		WRITE_ONCE(hw->rx_gate_verified, false);
		WRITE_ONCE(hw->drained, false);
		hw->reason = FE_SW_HW_ADMISSION;
		ret = -EIO;
		goto retained;
	}
	if ((fe_read(fe, RTL_L2_FDB_ACCESS) |
	     fe_read(fe, RTL_L2_FDB_LIMIT_ACCESS)) & RTL_L2_ACCESS_BUSY) {
		ret = -EBUSY;
		goto retained;
	}
	if (hw->globals_owned) {
		control = fe_read(fe, RTL_L2_FDB_CONTROL);
		if (control == ~0U) {
			ret = -EIO;
			goto retained;
		}
		if ((control & FE_SW_FDB_INIT) ||
		    !(control & RTL_L2_FDB_LEARN_DISABLE)) {
			ret = -EBUSY;
			goto retained;
		}
	}
	/* Retain every original until the complete rollback, including direct
 * globals and per-port limits, has passed readback. A failed suffix cannot
 * authorize a fresh prepare or free the already-restored prefix's owner. */
	ret = rtl_l2_journal_restore(&hw->journal, &io, hw->rows, hw->count,
				     READ_ONCE(hw->drained));
	if (ret)
		goto retained;
	for (i = 0; i < FE_LAN_PORTS; i++) {
		if (!(hw->limits_owned & BIT(i)))
			continue;
		ret = fe_switch_hw_limit_write(fe, i, hw->limits[i]);
		if (ret)
			goto retained;
	}
	if (hw->globals_owned) {
		for (i = 0; !ret && i < RTL_L2_FDB_FILTER_WORDS; i++)
			ret = fe_switch_hw_config_write(fe, RTL_L2_FDB_FILTER_WORD0 - i * 4,
							hw->filter[i], ~0U);
		if (!ret)
			ret = fe_switch_hw_config_write(fe, 0x1410, hw->learning, 0x7fU);
		if (!ret)
			ret = fe_switch_hw_config_write(fe, 0x1408, hw->learn_forward, BIT(29));
		if (!ret)
			ret = fe_switch_hw_config_write(fe, 0x140c, hw->learn_exception,
						0x7ffU | (0x7ffU << 16));
		if (!ret)
			ret = fe_switch_hw_config_write(fe, 0x1c04, hw->aging, 0x7ffffU);
		if (!ret)
			ret = fe_switch_hw_config_write(fe, 0xa1e0, hw->demux, 0x3ffU);
		if (!ret)
			ret = fe_switch_hw_config_write(fe, RTL_L2_FDB_CONTROL,
						 hw->control, FE_SW_FDB_OWNED_CONTROL);
		if (ret)
			goto retained;
	}
	/* Long indirect rollbacks must not release the owner if a connector
	 * changed after the initial closed-gate check. No selector is opened by
	 * restoration itself; only the generation-checked arm may do that. */
	if (!fe_switch_hw_rx_check(fe, 0, 0) || !fe_switch_hw_route_closed(fe)) {
		WRITE_ONCE(hw->rx_gate_verified, false);
		WRITE_ONCE(hw->drained, false);
		hw->reason = FE_SW_HW_ADMISSION;
		ret = -EIO;
		goto retained;
	}
	ret = rtl_l2_journal_release(&hw->journal, hw->rows, &hw->count);
	if (ret)
		goto retained;
	journal = hw->journal;
	memset(hw, 0, sizeof(*hw));
	hw->rows = rows;
	hw->journal = journal;
	WRITE_ONCE(hw->rx_gate_verified, true);
	hw->reason = reason;
	hw->observed = observed;
	/* RX stays CPU16. Only the core's epoch-checked arm may reopen a
	 * native/L3 route mask; restoring an old raw 25 selector is unsafe. */
	return 0;

retained:
	hw->journal.quarantined = 1;
	return ret;
}

static bool fe_switch_hw_arm(struct rtl_fe *fe, struct rtl_fe_switch_hw *hw,
			    unsigned int native, unsigned int route,
			    bool route_policy_allowed,
			    bool native_route_policy_allowed)
{
	unsigned int port, value;
	bool withdrawing = READ_ONCE(fe->pending_withdrawals);

	if (hw->journal.quarantined || hw->journal.restoring ||
	    (native | route) & ~FE_SW_LAN_MASK || (native & route) ||
	    (native && (!READ_ONCE(hw->prepared) || !READ_ONCE(hw->drained) ||
			!READ_ONCE(hw->port_policy_ready) ||
			hw->route_policy_allowed != native_route_policy_allowed ||
			(native_route_policy_allowed && !route_policy_allowed) ||
			native != hw->ports)) ||
	    (route && (!route_policy_allowed || !READ_ONCE(fe->enabled) ||
		       !READ_ONCE(fe->prepared))))
		return false;
	if (native && hw->isolated_mask &&
	    !rtl_l2_port_policy_mc_check(fe_read(fe, RTL_L2_POLICY_ARB_EXT))) {
		hw->reason = FE_SW_HW_ISOLATION;
		WRITE_ONCE(hw->port_policy_ready, false);
		fe_switch_hw_gate(fe, hw);
		return false;
	}
	/* Disabling routes in software is not proof that an uncertain cached
	 * action cannot still execute. Verify the CPU-only L3 gate BEFORE any
	 * native/RX selector opens, even after a failed disable set enabled=0.
	 * A verified gate preserves independent LAN switching while withdrawal
	 * retries continue. The FE mutex keeps this latch stable during arm.
	 */
	if (!route_policy_allowed) {
		/* A zero LAN route mask does not close the PON -> L3 connector.
		 * Keep both shared L3 selectors on their verified CPU-only profile,
		 * even when the L3 engine remains administratively enabled.
		 */
		fe_route_gate(fe);
		if (!fe_switch_hw_route_closed(fe)) {
			fe_switch_hw_gate(fe, hw);
			return false;
		}
	} else if (withdrawing && !fe_route_arm(fe)) {
		fe_switch_hw_gate(fe, hw);
		return false;
	}
	if (native) {
		/* Prepared, drained, static FDB replayed; learning is enabled only
		 * immediately before opening native ingress. No indirect MMIO. */
		if (fe_switch_hw_config_write(fe, 0x1c04, hw->requested_aging, 0x7ffffU) ||
		    fe_switch_hw_config_write(fe, RTL_L2_FDB_CONTROL,
					 hw->run_control, FE_SW_FDB_OWNED_CONTROL)) {
			hw->journal.quarantined = 1;
			WRITE_ONCE(hw->port_policy_ready, false);
			fe_switch_hw_gate(fe, hw);
			return false;
		}
	}
	for (port = 0; port < FE_LAN_PORTS; port++) {
		value = fe_read(fe, FE_LAN_RX_CTRL(port));
		if (value == ~0U)
			goto admission_failed;
		value = (value & ~FE_SW_RX_DEST_MASK) | FE_SW_RX_CPU;
		if (native & BIT(port))
			value &= ~FE_SW_RX_BYPASS;
		else if (route & BIT(port))
			value = (value & ~FE_SW_RX_DEST_MASK) | (25U << 16);
		fe_write(fe, FE_LAN_RX_CTRL(port), value);
	}
	if (!fe_switch_hw_rx_check(fe, native, route))
		goto admission_failed;
	if (route_policy_allowed && !withdrawing &&
	    READ_ONCE(fe->enabled) && READ_ONCE(fe->prepared)) {
		if (!fe_route_arm(fe)) {
			fe_switch_hw_gate(fe, hw);
			return false;
		}
	}
	WRITE_ONCE(hw->drained, false);
	/* This field records a closed-gate observation, never live native RX. */
	WRITE_ONCE(hw->rx_gate_verified, false);
	return true;

admission_failed:
	hw->reason = FE_SW_HW_ADMISSION;
	WRITE_ONCE(hw->port_policy_ready, false);
	fe_switch_hw_gate(fe, hw);
	return false;
}

#endif
