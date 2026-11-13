/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTL9617C_FE_SWITCH_HW_H
#define RTL9617C_FE_SWITCH_HW_H

#include <linux/delay.h>

#include "rtl9617c-l2-table.h"

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
};

struct fe_switch_hw_observed {
	unsigned int vlan_mode, hash_control, aging, packet_length;
	unsigned int tpid[4], rx_oversize_allow;
	unsigned int source_port, source_logical, learning_port, learning_profile;
};

struct rtl_fe_switch_hw {
	struct rtl_l2_snapshot rows[FE_SW_SNAPSHOTS];
	unsigned int count, ports, special_profile;
	unsigned int cf[FE_SW_CF_RULES], cf_count;
	unsigned int control, aging, requested_aging, learning;
	unsigned int learn_forward, learn_exception;
	unsigned int demux;
	unsigned int limits[FE_LAN_PORTS], limits_owned;
	unsigned int filter[RTL_L2_FDB_FILTER_WORDS];
	unsigned int run_control;
	enum fe_switch_hw_reason reason;
	struct fe_switch_hw_observed observed;
	bool globals_owned, prepared, drained;
};

static const char *fe_switch_hw_reason_name(const struct rtl_fe_switch_hw *hw)
{
	static const char * const names[] = {
		"ok", "requires-existing-svl", "priority-fdb-key", "tpid-profile",
		"cpu-egress-edit", "queue-baseline", "lan-source-map",
		"foreign-source-alias", "aging-timebase", "foreign-classifier",
		"foreign-learning", "special-profile-capacity", "mac-limit-io",
		"table-io", "shared-command-busy", "pipeline-drain-timeout",
		"native-mtu-baseline", "control-packet-classification",
	};

	return (unsigned int)hw->reason < ARRAY_SIZE(names) ? names[hw->reason] : "unknown";
}

/* No MAC TX disable: software forwarding must continue under a persistent
 * policy veto. Clearing a destination's TX enable is neither a proven GE
 * FIFO flush nor a safe way to restore the software fallback afterwards.
 */
static void fe_switch_hw_gate(struct rtl_fe *fe, struct rtl_fe_switch_hw *hw)
{
	unsigned int port, value;

	/* This also closes PON -> L3 -> LAN old-flow admission. LAN selectors
	 * alone cannot guard an ingress physically coming from the PON. */
	fe_route_gate(fe);
	for (port = 0; port < FE_LAN_PORTS; port++) {
		value = fe_read(fe, FE_LAN_RX_CTRL(port));
		value = (value & ~FE_SW_RX_DEST_MASK) | FE_SW_RX_CPU;
		fe_write(fe, FE_LAN_RX_CTRL(port), value);
	}
	/* Flush posted admission writes before the core publishes new policy. */
	fe_read(fe, FE_LAN_RX_CTRL(FE_LAN_PORTS - 1));
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
	if (!hw->globals_owned && !hw->count)
		return 0;
	if ((fe_read(fe, RTL_L2_FDB_ACCESS) |
	     fe_read(fe, RTL_L2_FDB_LIMIT_ACCESS)) & RTL_L2_ACCESS_BUSY) {
		hw->reason = FE_SW_HW_BUSY;
		return -EBUSY;
	}
	if (hw->globals_owned) {
		control = fe_read(fe, RTL_L2_FDB_CONTROL);
		fe_write(fe, RTL_L2_FDB_CONTROL,
			 control | RTL_L2_FDB_LEARN_DISABLE);
		fe_read(fe, RTL_L2_FDB_CONTROL);
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
				ret = rtl_l2_fdb_command_mode(&io);
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
	unsigned int i;

	for (i = 0; i < hw->count; i++)
		if (hw->rows[i].table == table && hw->rows[i].index == index)
			return &hw->rows[i];
	return NULL;
}

static int fe_switch_hw_snapshot(struct rtl_fe *fe, struct rtl_fe_switch_hw *hw,
				enum rtl_l2_table table, unsigned int index,
				struct rtl_l2_snapshot **snapshot)
{
	struct rtl_dq_io io = fe_io(fe);
	struct rtl_l2_snapshot *row;
	int ret;

	row = fe_switch_hw_snapshot_find(hw, table, index);
	if (!row) {
		if (hw->count == FE_SW_SNAPSHOTS)
			return -ENOSPC;
		row = &hw->rows[hw->count];
		ret = rtl_l2_snapshot_take(&io, row, table, index);
		if (ret)
			return ret;
		hw->count++;
	}
	*snapshot = row;
	return 0;
}

static int fe_switch_hw_replace(struct rtl_fe *fe, struct rtl_fe_switch_hw *hw,
			       enum rtl_l2_table table, unsigned int index,
			       const unsigned int *words)
{
	struct rtl_l2_snapshot *snapshot;
	struct rtl_dq_io io = fe_io(fe);
	int ret = fe_switch_hw_snapshot(fe, hw, table, index, &snapshot);

	if (ret)
		return ret;
	return rtl_l2_table_write(&io, table, index, words);
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
	struct rtl_dq_io io = fe_io(fe);
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
			ret = rtl_l2_table_write(&io, RTL_L2_TBL_CF_FIB, id, fib);
			if (!ret)
				ret = rtl_l2_table_write(&io, RTL_L2_TBL_CF_KEY, id, x);
			if (!ret)
				ret = rtl_l2_table_write(&io, RTL_L2_TBL_CF_KEY,
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
	 * does NOT. Recognise every configured TPID as C, and trap all tags.
	 * ILPB.sc_ind alone is only the PVID default, not a tagged-S override.
	 */
	rtl_l2_field_set(words, RTL_L2_ILPB_INNER_C_TPID_ENABLE, 1);
	rtl_l2_field_set(words, RTL_L2_ILPB_TOP_C_TPID_ENABLE, 1);
	rtl_l2_field_set(words, RTL_L2_ILPB_C_TPID_MATCH, 15);
	rtl_l2_field_set(words, RTL_L2_ILPB_OTHER_TPID_MATCH, 15);
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
	unsigned int port, type, stp, i, target = fe->enabled && fe->prepared ? 25 : 16;
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
		ret = rtl_l2_table_write(&io, RTL_L2_TBL_SPB,
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
		ret = rtl_l2_table_write(&io, RTL_L2_TBL_ILPB, port, words);
		if (ret)
			return ret;
		ret = fe_switch_hw_snapshot(fe, hw, RTL_L2_TBL_ELPB, port, &snapshot);
		if (ret)
			return ret;
		memcpy(words, snapshot->words, sizeof(words));
		fe_switch_hw_native_elpb(words);
		ret = rtl_l2_table_write(&io, RTL_L2_TBL_ELPB, port, words);
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
		ret = rtl_l2_port_limit_write(&io, port,
					     hw->limits[port] | RTL_L2_FDB_LIMIT_MAX);
		if (ret)
			return ret;
	}
	return 0;
}

static int fe_switch_hw_prepare(struct rtl_fe *fe, struct rtl_fe_switch_hw *hw,
			       unsigned int ports, unsigned long ageing,
			       bool snooping)
{
	struct rtl_dq_io io = fe_io(fe);
	unsigned int words[RTL_L2_TABLE_MAX_WORDS], filter[RTL_L2_FDB_FILTER_WORDS];
	unsigned int i, tpids = 0, field;
	int ret;

	(void)snooping; /* All multicast is trapped; Linux owns MDB/snooping. */
	hw->reason = FE_SW_HW_OK;
	if (!ports || (ports & ~FE_SW_LAN_MASK) || ageing > 0x7ffffUL)
		return -EINVAL;
	if (hw->globals_owned || hw->count || hw->prepared)
		return -EALREADY;
	fe_switch_hw_gate(fe, hw);
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
	if (!(hw->observed.vlan_mode & RTL_L2_VLAN_MODE_SVL)) {
		hw->reason = FE_SW_HW_VLAN_MODE;
		return -EOPNOTSUPP;
	}
	if (hw->observed.hash_control & RTL_L2_FDB_HASH_USE_PRIORITY) {
		hw->reason = FE_SW_HW_PRIORITY_KEY;
		return -EOPNOTSUPP;
	}
	hw->reason = FE_SW_HW_TPID;
	for (i = 0; i < 4; i++) {
		unsigned int tpid = hw->observed.tpid[i] & 0xffffU;

		if (tpid == 0x8100)
			tpids |= 1;
		if (tpid == 0x88a8)
			tpids |= 2;
	}
	if (tpids != 3)
		return -EOPNOTSUPP;
	/* SDK aal_ni_l2.h defines this min/max frame unit including FCS.
	 * Linux bridge MTU1500 permits 1518 Ethernet bytes (+4 FCS). An older
	 * global UNI jumbo threshold must not bypass Linux's egress limit.
	 * Read/validate only: external UNI ports may share this global setting.
	 */
	if (!(hw->observed.packet_length & 0x3fffU) ||
	    (hw->observed.packet_length & 0x3fffU) > 1522 ||
	    (hw->observed.rx_oversize_allow & ports)) {
		hw->reason = FE_SW_HW_MTU;
		return -EOPNOTSUPP;
	}
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
	if (hw->control & BIT(30))
		return -EBUSY; /* FDB info FIFO initialization is still active. */
	hw->aging = fe_read(fe, 0x1c04);
	hw->requested_aging = (hw->aging & ~0x7ffffU) | (unsigned int)ageing;
	hw->learning = fe_read(fe, 0x1410);
	hw->learn_forward = fe_read(fe, 0x1408);
	hw->learn_exception = fe_read(fe, 0x140c);
	hw->demux = fe_read(fe, 0xa1e0) & 0x3ffU;
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
	fe_write(fe, 0xa1e0, fe_read(fe, 0xa1e0) | 0x3ffU);
	hw->run_control = (hw->control & ~(RTL_L2_FDB_LEARN_MODE_MASK |
		RTL_L2_FDB_LEARN_DISABLE | RTL_L2_FDB_COLLISION_OVERWRITE |
		FE_SW_FDB_OVERFLOW_RECYCLE | BIT(2) | 0x7f8U | BIT(0))) |
		RTL_L2_FDB_CMD_MODE | RTL_L2_FDB_LEARN_HW | BIT(11) | 0x7f8U;
	if (ageing)
		hw->run_control |= BIT(0);
	/* Keep the original aging policy until the owner's complete SCAN has
	 * proved there is no foreign dynamic domain. arm applies the new time. */
	fe_write(fe, RTL_L2_FDB_CONTROL,
		 (hw->control | RTL_L2_FDB_CMD_MODE | RTL_L2_FDB_LEARN_DISABLE) &
		 ~(RTL_L2_FDB_COLLISION_OVERWRITE | FE_SW_FDB_OVERFLOW_RECYCLE));
	/* Learn valid untagged/unknown-EtherType frames, never invalid source
	 * addresses, loops or ingress-dropped traffic. Preserve reserved bits. */
	fe_write(fe, 0x1410, (hw->learning & ~0x7fU) | BIT(0) | BIT(2) | BIT(6));
	memcpy(filter, hw->filter, sizeof(filter));
	rtl_l2_fdb_scan_filter(filter);
	for (i = 0; i < RTL_L2_FDB_FILTER_WORDS; i++)
		fe_write(fe, RTL_L2_FDB_FILTER_WORD0 - i * 4, filter[i]);
	ret = fe_switch_hw_cf_claim(fe, hw);
	if (!ret)
		ret = fe_switch_hw_ports(fe, hw);
	if (!ret)
		ret = fe_switch_hw_limits(fe, hw);
	if (!ret) {
		/* SDK aal_fdb_init permits forwarding on a static-SA move. A
		 * Linux static destination FDB row is not source-port locking. */
		fe_write(fe, 0x1408, hw->learn_forward | BIT(29));
		/* A full/busy FDB bucket must fall back, not inherit reset DROP.
		 * SDK enum REDIRECT=1, CPU0 LDPID=16, COS=0. Keep all unspecified
		 * keep-old flags; their names alone do not prove edit semantics. */
		fe_write(fe, 0x140c,
			 (hw->learn_exception & ~(0x7ffU | (0x7ffU << 16))) |
			 16U | (1U << 9) | (16U << 16) | (1U << 25));
	}
	if (!ret)
		ret = fe_switch_hw_cf_install(fe, hw);
	if (ret)
		return ret;
	hw->reason = FE_SW_HW_OK;
	WRITE_ONCE(hw->prepared, true);
	return 0;
}

static int fe_switch_hw_restore(struct rtl_fe *fe, struct rtl_fe_switch_hw *hw)
{
	struct rtl_dq_io io = fe_io(fe);
	enum fe_switch_hw_reason reason = hw->reason;
	struct fe_switch_hw_observed observed = hw->observed;
	unsigned int i;
	int ret;

	/* Caller has first drained and deleted only its claimed FDB domain.
	 * SCAN filter remains ours until those deletes finish. */
	if (!hw->globals_owned && !hw->count) {
		WRITE_ONCE(hw->prepared, false);
		return 0;
	}
	if (!READ_ONCE(hw->drained))
		return -EBUSY;
	if ((fe_read(fe, RTL_L2_FDB_ACCESS) |
	     fe_read(fe, RTL_L2_FDB_LIMIT_ACCESS)) & RTL_L2_ACCESS_BUSY)
		return -EBUSY;
	for (i = 0; i < FE_LAN_PORTS; i++) {
		if (!(hw->limits_owned & BIT(i)))
			continue;
		ret = rtl_l2_port_limit_write(&io, i, hw->limits[i]);
		if (ret)
			return ret;
	}
	for (i = hw->count; i; i--) {
		ret = rtl_l2_snapshot_restore(&io, &hw->rows[i - 1]);
		if (ret)
			return ret;
	}
	if (hw->globals_owned) {
		for (i = 0; i < RTL_L2_FDB_FILTER_WORDS; i++)
			fe_write(fe, RTL_L2_FDB_FILTER_WORD0 - i * 4, hw->filter[i]);
		fe_write(fe, 0x1410, hw->learning);
		fe_write(fe, 0x1408, hw->learn_forward);
		fe_write(fe, 0x140c, hw->learn_exception);
		fe_write(fe, 0x1c04, hw->aging);
		fe_write(fe, 0xa1e0, (fe_read(fe, 0xa1e0) & ~0x3ffU) | hw->demux);
		fe_write(fe, RTL_L2_FDB_CONTROL, hw->control);
		fe_read(fe, RTL_L2_FDB_CONTROL);
	}
	memset(hw, 0, sizeof(*hw));
	hw->reason = reason;
	hw->observed = observed;
	/* RX stays CPU16. Only the core's epoch-checked arm may reopen a
	 * native/L3 route mask; restoring an old raw 25 selector is unsafe. */
	return 0;
}

static bool fe_switch_hw_arm(struct rtl_fe *fe, struct rtl_fe_switch_hw *hw,
			    unsigned int native, unsigned int route)
{
	unsigned int port, value;

	if ((native | route) & ~FE_SW_LAN_MASK || (native & route) ||
	    (native && (!READ_ONCE(hw->prepared) || !READ_ONCE(hw->drained) ||
			native != hw->ports)) ||
	    (route && (!READ_ONCE(fe->enabled) || !READ_ONCE(fe->prepared))))
		return false;
	if (native) {
		/* Prepared, drained, static FDB replayed; learning is enabled only
		 * immediately before opening native ingress. No indirect MMIO. */
		fe_write(fe, 0x1c04, hw->requested_aging);
		fe_write(fe, RTL_L2_FDB_CONTROL, hw->run_control);
		fe_read(fe, RTL_L2_FDB_CONTROL);
	}
	for (port = 0; port < FE_LAN_PORTS; port++) {
		value = fe_read(fe, FE_LAN_RX_CTRL(port));
		value = (value & ~FE_SW_RX_DEST_MASK) | FE_SW_RX_CPU;
		if (native & BIT(port))
			value &= ~FE_SW_RX_BYPASS;
		else if (route & BIT(port))
			value = (value & ~FE_SW_RX_DEST_MASK) | (25U << 16);
		fe_write(fe, FE_LAN_RX_CTRL(port), value);
	}
	fe_read(fe, FE_LAN_RX_CTRL(FE_LAN_PORTS - 1));
	if (READ_ONCE(fe->enabled) && READ_ONCE(fe->prepared)) {
		if (!fe_route_arm(fe)) {
			fe_switch_hw_gate(fe, hw);
			return false;
		}
	}
	WRITE_ONCE(hw->drained, false);
	return true;
}

#endif
