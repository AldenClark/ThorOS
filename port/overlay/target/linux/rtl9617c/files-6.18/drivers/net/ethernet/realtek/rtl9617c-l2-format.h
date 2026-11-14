/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_L2_FORMAT_H
#define RTL9617C_L2_FORMAT_H

#include <linux/errno.h>

/* Public GPL reference: ca-network-drivers 8b4f4882, aal-77c; silicon
 * rtl8277c_registers.h from GPL-for-GP3000 5090fbcb. These are wire formats,
 * not a policy allowing arbitrary ports, VLANs or shared resources. Arrays
 * use hardware DATA word numbering: words[0] is DATA0, regardless of MMIO
 * address order. No C bitfields, host byte-order dependency, or allocation.
 */
#define RTL_L2_TABLE_MAX_WORDS 5
#define RTL_L2_LOGICAL_PORTS 64
#define RTL_L2_VLAN_IDS 4096
#define RTL_L2_VLAN_FIB_ENTRIES 128
#define RTL_L2_MC_FIB_ENTRIES 64
#define RTL_L2_MC_VECTOR_ENTRIES 256
#define RTL_L2_SPB_PROFILES 8
#define RTL_L2_SPB_PACKET_TYPES 32
#define RTL_L2_SPECIAL_PRIORITIES 31
#define RTL_L2_CF_ENTRIES 512
#define RTL_L2_FDB_MAIN_ENTRIES 4096
#define RTL_L2_FDB_OVERFLOW_ENTRIES 32
#define RTL_L2_FDB_ENTRIES (RTL_L2_FDB_MAIN_ENTRIES + RTL_L2_FDB_OVERFLOW_ENTRIES)
#define RTL_L2_FDB_WORDS 4

#define RTL_L2_ACCESS_BUSY 0x80000000U
#define RTL_L2_ACCESS_WRITE 0x40000000U
#define RTL_L2_FDB_CONTROL 0x1c00U
#define RTL_L2_FDB_ACCESS 0x1ca0U
#define RTL_L2_FDB_DATA0 0x1cb0U
#define RTL_L2_FDB_RETURN 0x1c2cU
#define RTL_L2_FDB_FILTER_WORD0 0x1c28U
#define RTL_L2_FDB_FILTER_WORDS 5
#define RTL_L2_FDB_CMD_MODE 0x80000000U
#define RTL_L2_FDB_LEARN_DISABLE (1U << 22)
#define RTL_L2_FDB_LEARN_MODE_MASK (3U << 23)
#define RTL_L2_FDB_LEARN_HW (1U << 23)
#define RTL_L2_FDB_COLLISION_OVERWRITE (1U << 25)
#define RTL_L2_PP_TPID_S 0x1108U
#define RTL_L2_PP_TPID_C 0x110cU
#define RTL_L2_PP_TPID_OTHER 0x1110U
#define RTL_L2_PP_TPID_USER 0x1114U
#define RTL_L2_DSCP_KEEP_RECEIVED 0U
#define RTL_L2_PRIORITY_KEEP_RECEIVED 0U
#define RTL_L2_VLAN_MODE_CONTROL 0x1414U
#define RTL_L2_VLAN_MODE_SVL 1U
#define RTL_L2_FDB_HASH_CONTROL 0x1400U
#define RTL_L2_FDB_HASH_USE_PRIORITY (1U << 6)
#define RTL_L2_FDB_LIMIT_ACCESS 0x1cb4U
#define RTL_L2_FDB_LIMIT_DATA 0x1cb8U
#define RTL_L2_FDB_LIMIT_SELECT (1U << 6)
#define RTL_L2_FDB_LIMIT_MAX 0x1fffU
#define RTL_L2_RESERVED_GROUP_MAC_LOW 0x1178U
#define RTL_L2_RESERVED_GROUP_MAC_HIGH 0x117cU
#define RTL_L2_RESERVED_GROUP_MASK_LOW 0x1180U
#define RTL_L2_RESERVED_GROUP_MASK_HIGH 0x1184U
#define RTL_L2_RESERVED_GROUP_MAC_LOW_DEFAULT 0xc2000000U
#define RTL_L2_RESERVED_GROUP_MAC_HIGH_DEFAULT 0x0180U
#define RTL_L2_RESERVED_GROUP_MASK_LOW_DEFAULT 0xfffffff0U
#define RTL_L2_RESERVED_GROUP_MASK_HIGH_DEFAULT 0xffffU
#define RTL_L2_SPECIAL_IEEE_RESERVED_GROUP 5U
#define RTL_L2_SPECIAL_NORMAL 0U

enum rtl_l2_table {
	RTL_L2_TBL_ILPB,
	RTL_L2_TBL_ELPB,
	RTL_L2_TBL_SPB,
	RTL_L2_TBL_DFT_FWD,
	RTL_L2_TBL_MEMBERSHIP_ID,
	RTL_L2_TBL_PORT_MEMBERSHIP,
	RTL_L2_TBL_VLAN_LAN_INDEX,
	RTL_L2_TBL_VLAN_FIB,
	RTL_L2_TBL_MC_FIB,
	RTL_L2_TBL_MC_VECTOR,
	RTL_L2_TBL_REDIR_LDPID,
	RTL_L2_TBL_REDIR_DROP,
	RTL_L2_TBL_CF_KEY,
	RTL_L2_TBL_CF_FIB,
	RTL_L2_TBL_IPPB,
	RTL_L2_TBL_SPECIAL_PRIORITY,
	RTL_L2_TBL_COUNT,
};

struct rtl_l2_table_layout {
	unsigned int access, data0, entries, words;
};

static inline int rtl_l2_table_layout(enum rtl_l2_table table,
				    struct rtl_l2_table_layout *layout)
{
	static const struct rtl_l2_table_layout layouts[RTL_L2_TBL_COUNT] = {
		[RTL_L2_TBL_ILPB] = { 0x11e4, 0x11f8, 64, 5 },
		[RTL_L2_TBL_ELPB] = { 0x1420, 0x1428, 64, 2 },
		[RTL_L2_TBL_SPB] = { 0x130c, 0x1310, 256, 1 },
		[RTL_L2_TBL_DFT_FWD] = { 0x1564, 0x1568, 256, 1 },
		[RTL_L2_TBL_MEMBERSHIP_ID] = { 0x156c, 0x1570, 64, 1 },
		[RTL_L2_TBL_PORT_MEMBERSHIP] = { 0x1574, 0x157c, 64, 2 },
		[RTL_L2_TBL_VLAN_LAN_INDEX] = { 0x1a20, 0x1a24, 4096, 1 },
		[RTL_L2_TBL_VLAN_FIB] = { 0x1a0c, 0x1a14, 128, 2 },
		[RTL_L2_TBL_MC_FIB] = { 0x1634, 0x1640, 64, 3 },
		[RTL_L2_TBL_MC_VECTOR] = { 0xaa64, 0xaa6c, 256, 2 },
		[RTL_L2_TBL_REDIR_LDPID] = { 0x1614, 0x1618, 64, 1 },
		[RTL_L2_TBL_REDIR_DROP] = { 0x161c, 0x1620, 32, 1 },
		[RTL_L2_TBL_CF_KEY] = { 0x1e04, 0x1e10, 1024, 3 },
		[RTL_L2_TBL_CF_FIB] = { 0x1e14, 0x1e20, 512, 3 },
		[RTL_L2_TBL_IPPB] = { 0x11dc, 0x11e0, 64, 1 },
		/* SDK aal_l2_specpkt_pri_get only admits priorities 0..30,
		 * although the access address field can represent index31. */
		[RTL_L2_TBL_SPECIAL_PRIORITY] = { 0x1204, 0x1208, RTL_L2_SPECIAL_PRIORITIES, 1 },
	};

	if (!layout || (unsigned int)table >= RTL_L2_TBL_COUNT)
		return -EINVAL;
	*layout = layouts[table];
	return 0;
}

enum rtl_l2_stp {
	RTL_L2_STP_DROP,
	RTL_L2_STP_LEARN_NO_FORWARD,
	RTL_L2_STP_FORWARD_NO_LEARN,
	RTL_L2_STP_FORWARD_AND_LEARN,
};

enum rtl_l2_flood_type {
	RTL_L2_FLOOD_BROADCAST,
	RTL_L2_FLOOD_UNKNOWN_UNICAST,
	RTL_L2_FLOOD_UNKNOWN_L2_MULTICAST,
	RTL_L2_FLOOD_UNKNOWN_L3_MULTICAST,
};

enum rtl_l2_cf_packet_type {
	RTL_L2_CF_UNICAST,
	RTL_L2_CF_BROADCAST,
	RTL_L2_CF_MULTICAST,
	RTL_L2_CF_UNKNOWN_UNICAST,
	RTL_L2_CF_UNKNOWN_MULTICAST,
};

/* Only verified fields are exposed. Helpers preserve every other bit from
 * the caller's actual snapshot. A field's table must match the row supplied.
 * ILPB has a 4-bit selector but SPB has only eight physical 32-entry banks;
 * rtl_l2_field_set() rejects the otherwise representable selectors 8..15.
 */
#define RTL_L2_FIELDS(X) \
	X(ILPB_DEFAULT_PREMARK, ILPB, 0, 0, 1) \
	X(ILPB_COLOR_SOURCE, ILPB, 0, 1, 2) \
	X(ILPB_INGRESS_FILTER, ILPB, 0, 3, 1) \
	X(ILPB_DEFAULT_COS, ILPB, 0, 4, 3) \
	X(ILPB_COS_MARK, ILPB, 0, 7, 3) \
	X(ILPB_COS_MODE, ILPB, 0, 10, 3) \
	X(ILPB_DEFAULT_DSCP, ILPB, 0, 13, 6) \
	X(ILPB_DSCP_MARK, ILPB, 0, 19, 4) \
	X(ILPB_DSCP_MODE, ILPB, 0, 23, 2) \
	X(ILPB_DSCP_MARKDOWN, ILPB, 0, 25, 1) \
	X(ILPB_DEFAULT_PRIORITY, ILPB, 0, 26, 3) \
	X(ILPB_INNER_PRIORITY_MODE, ILPB, 0, 29, 2) \
	X(ILPB_PRIORITY_MARK_LOW, ILPB, 0, 31, 1) \
	X(ILPB_STP, ILPB, 2, 0, 2) \
	X(ILPB_OTHER_TPID_MATCH, ILPB, 2, 2, 4) \
	X(ILPB_INNER_C_TPID_ENABLE, ILPB, 2, 6, 1) \
	X(ILPB_INNER_S_TPID_ENABLE, ILPB, 2, 7, 1) \
	X(ILPB_TOP_C_TPID_ENABLE, ILPB, 2, 8, 1) \
	X(ILPB_TOP_S_TPID_ENABLE, ILPB, 2, 9, 1) \
	X(ILPB_C_TPID_MATCH, ILPB, 2, 10, 4) \
	X(ILPB_S_TPID_MATCH, ILPB, 2, 14, 4) \
	X(ILPB_DROP_DOUBLE_TAG, ILPB, 2, 18, 1) \
	X(ILPB_DROP_PRIORITY_TAG, ILPB, 2, 19, 1) \
	X(ILPB_DROP_UNTAGGED, ILPB, 2, 20, 1) \
	X(ILPB_DROP_C_TAG, ILPB, 2, 21, 1) \
	X(ILPB_DROP_S_TAG, ILPB, 2, 22, 1) \
	X(ILPB_DROP_SINGLE_TAG, ILPB, 2, 23, 1) \
	X(ILPB_NON_INNER_TAG_COMMAND, ILPB, 2, 24, 1) \
	X(ILPB_INNER_VLAN_COMMAND, ILPB, 2, 25, 2) \
	X(ILPB_INNER_VID_SELECT, ILPB, 2, 27, 2) \
	X(ILPB_UNTAG_COMMAND, ILPB, 2, 29, 1) \
	X(ILPB_TOP_VLAN_COMMAND, ILPB, 2, 30, 2) \
	X(ILPB_PRIORITY_MARK_HIGH, ILPB, 1, 0, 3) \
	X(ILPB_CHANGE_PRIORITY_ON_POP, ILPB, 1, 3, 1) \
	X(ILPB_TOP_PRIORITY_MODE, ILPB, 1, 4, 2) \
	X(ILPB_FLOW_ID_SELECT, ILPB, 1, 6, 3) \
	X(ILPB_CLASSIFIER_LENGTH, ILPB, 1, 9, 6) \
	X(ILPB_CLASSIFIER_START, ILPB, 1, 15, 8) \
	X(ILPB_CLASSIFIER_ENABLE, ILPB, 1, 23, 1) \
	X(ILPB_SPECIAL_PROFILE, ILPB, 1, 24, 4) \
	X(ILPB_DA_SA_SWAP, ILPB, 1, 28, 1) \
	X(ILPB_LOOP_ENABLE, ILPB, 1, 29, 1) \
	X(ILPB_SA_MOVE_DISABLE_FORWARD, ILPB, 1, 30, 1) \
	X(ILPB_STATION_MOVE_ENABLE, ILPB, 1, 31, 1) \
	X(ILPB_VLAN_COMMAND_SELECT, ILPB, 3, 0, 2) \
	X(ILPB_SC_IND, ILPB, 3, 2, 1) \
	X(ILPB_DEFAULT_VID, ILPB, 3, 3, 12) \
	X(ILPB_SA_MISS_FORWARD, ILPB, 3, 20, 1) \
	X(ILPB_SA_LIMIT_DROP, ILPB, 3, 21, 1) \
	X(ILPB_WAN, ILPB, 4, 10, 1) \
	X(ILPB_CPU_PORT, ILPB, 4, 11, 1) \
	X(ELPB_VLAN_AWARE, ELPB, 0, 0, 1) \
	X(ELPB_STP_FORWARD, ELPB, 0, 1, 1) \
	X(ELPB_VLAN_LOOKUP, ELPB, 0, 2, 1) \
	X(ELPB_WAN, ELPB, 0, 3, 1) \
	X(ELPB_CLASSIFIER_LENGTH, ELPB, 0, 4, 6) \
	X(ELPB_CLASSIFIER_START, ELPB, 0, 10, 8) \
	X(ELPB_CLASSIFIER_ENABLE, ELPB, 0, 18, 1) \
	X(ELPB_CLASSIFIER_FLOW_SELECT, ELPB, 0, 19, 1) \
	X(ELPB_CLASSIFIER_COS_SELECT, ELPB, 0, 20, 1) \
	X(ELPB_DSCP_MARK, ELPB, 0, 21, 4) \
	X(ELPB_DSCP_MODE, ELPB, 0, 25, 2) \
	X(ELPB_DSCP_CONTROL, ELPB, 0, 27, 1) \
	X(ELPB_DSCP_MARKDOWN, ELPB, 0, 28, 1) \
	X(ELPB_INNER_PRIORITY_MODE, ELPB, 0, 29, 2) \
	X(ELPB_PRIORITY_MARK_LOW, ELPB, 0, 31, 1) \
	X(ELPB_PRIORITY_MARK_HIGH, ELPB, 1, 0, 3) \
	X(ELPB_CHANGE_PRIORITY_ON_POP, ELPB, 1, 3, 1) \
	X(ELPB_TOP_PRIORITY_MODE, ELPB, 1, 4, 2) \
	X(ELPB_PRIORITY_CONTROL, ELPB, 1, 6, 1) \
	X(ELPB_USE_TX_VLAN_ACL, ELPB, 1, 7, 1) \
	X(SPB_NO_EDIT, SPB, 0, 0, 1) \
	X(SPB_KEEP_TIMESTAMP, SPB, 0, 1, 1) \
	X(SPB_BYPASS_SA_CHECK, SPB, 0, 2, 1) \
	X(SPB_LIMIT_FORWARD_PERMIT, SPB, 0, 3, 1) \
	X(SPB_LEARN_DISABLE, SPB, 0, 4, 1) \
	X(SPB_GROUP_ENABLE, SPB, 0, 5, 1) \
	X(SPB_FLOW_ID, SPB, 0, 6, 12) \
	X(SPB_FLOW_ENABLE, SPB, 0, 18, 1) \
	X(SPB_RATE_LIMIT_BYPASS, SPB, 0, 19, 1) \
	X(SPB_COS, SPB, 0, 20, 3) \
	X(SPB_DESTINATION, SPB, 0, 23, 6) \
	X(SPB_SPECIAL_FORWARD, SPB, 0, 29, 1) \
	X(SPB_NO_DROP, SPB, 0, 30, 1) \
	X(SPB_COLLISION_FORWARD_PERMIT, SPB, 0, 31, 1) \
	X(DFT_DENY, DFT_FWD, 0, 0, 1) \
	X(DFT_GROUP, DFT_FWD, 0, 1, 10) \
	X(DFT_REDIRECT, DFT_FWD, 0, 11, 1) \
	X(DFT_GROUP_VALID, DFT_FWD, 0, 12, 1) \
	X(MEMBERSHIP_CHECK_ID, MEMBERSHIP_ID, 0, 0, 4) \
	X(VLAN_INDEX_VALID, VLAN_LAN_INDEX, 0, 0, 1) \
	X(VLAN_INDEX_FIB, VLAN_LAN_INDEX, 0, 1, 7) \
	X(VLAN_FIB_UNTAG, VLAN_FIB, 0, 0, 16) \
	X(VLAN_FIB_MEMBERS, VLAN_FIB, 0, 16, 16) \
	X(VLAN_FIB_GROUP, VLAN_FIB, 1, 0, 10) \
	X(MC_C_VLAN_COMMAND, MC_FIB, 0, 0, 2) \
	X(MC_C_VID, MC_FIB, 0, 2, 12) \
	X(MC_C_TPID_COMMAND, MC_FIB, 0, 14, 1) \
	X(MC_C_TPID_SELECT, MC_FIB, 0, 15, 1) \
	X(MC_C_PRIORITY_COMMAND, MC_FIB, 0, 16, 2) \
	X(MC_C_PRIORITY, MC_FIB, 0, 18, 3) \
	X(MC_C_DEI_COMMAND, MC_FIB, 0, 21, 1) \
	X(MC_C_DEI, MC_FIB, 0, 22, 1) \
	X(MC_POLICER_ID, MC_FIB, 0, 23, 9) \
	X(MC_S_VLAN_COMMAND, MC_FIB, 1, 0, 2) \
	X(MC_S_VID, MC_FIB, 1, 2, 12) \
	X(MC_S_TPID_COMMAND, MC_FIB, 1, 14, 1) \
	X(MC_S_TPID_SELECT, MC_FIB, 1, 15, 2) \
	X(MC_S_PRIORITY_COMMAND, MC_FIB, 1, 17, 2) \
	X(MC_S_PRIORITY, MC_FIB, 1, 19, 3) \
	X(MC_S_DEI_COMMAND, MC_FIB, 1, 22, 1) \
	X(MC_S_DEI, MC_FIB, 1, 23, 1) \
	X(MC_DESTINATION, MC_FIB, 1, 24, 6) \
	X(MC_COS_COMMAND, MC_FIB, 1, 30, 1) \
	X(MC_WAN_DESTINATION, MC_FIB, 1, 31, 1) \
	X(MC_PERMIT_SOURCE_PORT, MC_FIB, 2, 0, 1) \
	X(MC_SOURCE_MAC_COMMAND, MC_FIB, 2, 1, 1) \
	X(MC_SOURCE_MAC_SELECT, MC_FIB, 2, 2, 3) \
	X(MC_COS, MC_FIB, 2, 5, 3) \
	X(MC_TTL_ZERO_CONTROL, MC_FIB, 2, 8, 2) \
	X(MC_TTL_DECREMENT, MC_FIB, 2, 10, 1) \
	X(MC_KEEP_ORIGINAL_SOURCE_PORT, MC_FIB, 2, 11, 1) \
	X(REDIR_COS_VALID, REDIR_LDPID, 0, 0, 1) \
	X(REDIR_COS, REDIR_LDPID, 0, 1, 3) \
	X(REDIR_DESTINATION, REDIR_LDPID, 0, 4, 6) \
	X(REDIR_ENABLE, REDIR_LDPID, 0, 10, 1) \
	X(REDIR_WAN, REDIR_LDPID, 0, 11, 1) \
	X(IPPB_SOURCE, IPPB, 0, 0, 6) \
	X(SPECIAL_PRIORITY_TYPE, SPECIAL_PRIORITY, 0, 0, 5)

enum rtl_l2_field {
#define RTL_L2_FIELD_ENUM(name, table, word, shift, width) RTL_L2_##name,
	RTL_L2_FIELDS(RTL_L2_FIELD_ENUM)
#undef RTL_L2_FIELD_ENUM
	RTL_L2_FIELD_COUNT,
};

struct rtl_l2_field_layout {
	unsigned char table, word, shift, width;
};

static const struct rtl_l2_field_layout rtl_l2_fields[RTL_L2_FIELD_COUNT] = {
#define RTL_L2_FIELD_LAYOUT(name, table, word, shift, width) \
	[RTL_L2_##name] = { RTL_L2_TBL_##table, word, shift, width },
	RTL_L2_FIELDS(RTL_L2_FIELD_LAYOUT)
#undef RTL_L2_FIELD_LAYOUT
};

static inline int rtl_l2_field_set(unsigned int *words, enum rtl_l2_field field,
				   unsigned int value)
{
	const struct rtl_l2_field_layout *layout;
	unsigned int mask;

	if (!words || (unsigned int)field >= RTL_L2_FIELD_COUNT)
		return -EINVAL;
	layout = &rtl_l2_fields[field];
	mask = (1U << layout->width) - 1U;
	if (value > mask ||
	    (field == RTL_L2_ILPB_SPECIAL_PROFILE && value >= RTL_L2_SPB_PROFILES))
		return -EINVAL;
	words[layout->word] = (words[layout->word] & ~(mask << layout->shift)) |
		(value << layout->shift);
	return 0;
}

static inline int rtl_l2_field_get(const unsigned int *words,
				   enum rtl_l2_field field, unsigned int *value)
{
	const struct rtl_l2_field_layout *layout;

	if (!words || !value || (unsigned int)field >= RTL_L2_FIELD_COUNT)
		return -EINVAL;
	layout = &rtl_l2_fields[field];
	*value = (words[layout->word] >> layout->shift) &
		((1U << layout->width) - 1U);
	return 0;
}

/* A vector bit selects one MC_FIB recipe, NOT a physical port. In contrast,
 * PORT_MEMBERSHIP bitmap bits are logical destination ports. Both are stored
 * as DATA0 low 32 bits / DATA1 high 32 bits; the helpers only encode bits.
 */
static inline void rtl_l2_bitmap_encode(unsigned int words[2],
					unsigned long long bitmap)
{
	words[0] = (unsigned int)bitmap;
	words[1] = (unsigned int)(bitmap >> 32);
}

static inline unsigned long long rtl_l2_bitmap_decode(const unsigned int words[2])
{
	return words[0] | ((unsigned long long)words[1] << 32);
}

/* aal_mcast.h explicitly defines the COS command as active-low. */
#define RTL_L2_MC_COS_REPLACE 0U
#define RTL_L2_MC_COS_KEEP 1U

/* PONCLE key encoding from aal_l2_classification.c __aal_l2_cf_key_write.
 * Each logical rule uses X at index and Y at index + 512. The TCAM valid
 * bit is copied explicitly, not complemented as a ternary match bit.
 * Tag recognition still depends on the separately owned PP TPID profile.
 * Two rules are needed for (C-tag OR S-tag); one rule cannot express OR.
 */
static inline int rtl_l2_cf_tag_key(unsigned int x[3], unsigned int y[3],
				     unsigned int source, unsigned int stag)
{
	unsigned int care, data, bit;

	if (!x || !y || source >= RTL_L2_LOGICAL_PORTS || stag > 1)
		return -EINVAL;
	bit = stag ? 12 : 13;
	care = (63U << 6) | (1U << bit);
	data = (source << 6) | (1U << bit);
	x[0] = ~care | ~data;
	y[0] = ~care | data;
	x[1] = y[1] = ~0U;
	x[2] = y[2] = ~0U;
	return 0;
}

/* PONCLE packet type is not the same enumeration as the DFT_FWD index.
 * Exact matching deliberately avoids merging types whose upper bits differ.
 */
static inline int rtl_l2_cf_pkt_type_key(unsigned int x[3], unsigned int y[3],
					  unsigned int source, unsigned int type)
{
	unsigned int care, data;

	if (!x || !y || source >= RTL_L2_LOGICAL_PORTS ||
	    type > RTL_L2_CF_UNKNOWN_MULTICAST)
		return -EINVAL;
	care = (63U << 6) | (7U << 16);
	data = (source << 6) | (type << 16);
	x[0] = ~care | ~data;
	y[0] = ~care | data;
	x[1] = y[1] = ~0U;
	x[2] = y[2] = ~0U;
	return 0;
}

/* A transparent PONCLE redirect is one CPU packet, not a mirrored copy.
 * It does not override any earlier pipeline edit; the owner must preserve
 * tags in ILPB/ELPB/SPB as well. COS is left unchanged (cf_cos_act = 0).
 */
static inline int rtl_l2_cf_destination(unsigned int words[3],
					unsigned int destination)
{
	if (!words || destination >= RTL_L2_LOGICAL_PORTS)
		return -EINVAL;
	words[0] = 0;
	words[1] = (3U << 5) | (destination << 8);
	words[2] = 0;
	return 0;
}

enum rtl_l2_fdb_command {
	RTL_L2_FDB_SCAN = 1,
	RTL_L2_FDB_READ = 4,
	RTL_L2_FDB_APPEND = 0x45,
	RTL_L2_FDB_DELETE = 0x85,
};

#define RTL_L2_FDB_STATUS_HIT_OVER_LIMIT 4U
#define RTL_L2_FDB_STATUS_HIT 5U
#define RTL_L2_FDB_STATUS_FULL 10U
#define RTL_L2_FDB_STATUS_LIMIT 11U
#define RTL_L2_FDB_STATUS_MISS 15U

/* SCAN uses persistent CPU_CMD_WORD0..4 comparison state. The owner must
 * snapshot these direct registers, wait for idle, and hold the shared FDB
 * lock before programming them. This applies the SDK full-valid-entry scan
 * filter (lpid 0..63, all other fields masked) to that snapshot, preserving
 * reserved bits and all ignored comparisons. It must not be changed while
 * a timed-out command may still complete. It is not a whole-table flush.
 */
static inline void rtl_l2_fdb_scan_filter(unsigned int words[RTL_L2_FDB_FILTER_WORDS])
{
	words[0] &= ~63U;
	words[1] |= 63U;
	words[4] = (words[4] & ~0x7fffU) | 0x7ffeU;
}

struct rtl_l2_fdb_entry {
	unsigned char mac[6];
	unsigned short key_vid, learned_vid, destination;
	unsigned char key_sc, key_dot1p, learned_sc, is_static;
	unsigned char sa_permit, da_permit, multicast, age;
	unsigned char valid, temporary, in_refresh, in_station_move, untagged;
};

static inline int rtl_l2_fdb_encode(unsigned int words[RTL_L2_FDB_WORDS],
				    const struct rtl_l2_fdb_entry *entry)
{
	unsigned int data0;

	if (!words || !entry || entry->key_vid >= RTL_L2_VLAN_IDS ||
	    entry->learned_vid >= RTL_L2_VLAN_IDS || entry->key_sc > 1 ||
	    entry->learned_sc > 1 || entry->key_dot1p > 7 || entry->is_static > 1 ||
	    entry->sa_permit > 1 || entry->da_permit > 1 || entry->multicast > 1 ||
	    entry->valid > 1 || entry->temporary > 1 || entry->in_refresh > 1 ||
	    entry->in_station_move > 1 || entry->untagged > 1 ||
	    entry->destination >= (entry->multicast ? 1024U : RTL_L2_LOGICAL_PORTS))
		return -EINVAL;
	data0 = entry->destination | ((unsigned int)entry->multicast << 10) |
		((unsigned int)entry->age << 11) | ((unsigned int)entry->is_static << 19) |
		((unsigned int)entry->da_permit << 20) | ((unsigned int)entry->sa_permit << 21) |
		((unsigned int)entry->learned_sc << 22) |
		((unsigned int)(entry->learned_vid & 511) << 23);
	/* UC DATA0 low10 bits are not a group ID: use the SDK aal_fdb_data0_t
 	 * overlay. For MC, bit9 belongs to the group ID, not entry_valid. */
	if (!entry->multicast)
		data0 |= ((unsigned int)entry->valid << 9) |
			((unsigned int)entry->temporary << 8) |
			((unsigned int)entry->in_station_move << 7) |
			((unsigned int)entry->in_refresh << 6);
	words[0] = data0;
	words[1] = (entry->learned_vid >> 9) | ((unsigned int)entry->key_dot1p << 3) |
		((unsigned int)entry->key_sc << 6) | ((unsigned int)entry->key_vid << 7) |
		((unsigned int)entry->mac[5] << 19) |
		((unsigned int)(entry->mac[4] & 31) << 27);
	words[2] = (entry->mac[4] >> 5) | ((unsigned int)entry->mac[3] << 3) |
		((unsigned int)entry->mac[2] << 11) | ((unsigned int)entry->mac[1] << 19) |
		((unsigned int)(entry->mac[0] & 31) << 27);
	words[3] = (entry->mac[0] >> 5) | ((unsigned int)entry->untagged << 3);
	return 0;
}

static inline void rtl_l2_fdb_decode(const unsigned int words[RTL_L2_FDB_WORDS],
				     struct rtl_l2_fdb_entry *entry)
{
	entry->mac[0] = ((words[3] & 7U) << 5) | (words[2] >> 27);
	entry->mac[1] = words[2] >> 19;
	entry->mac[2] = words[2] >> 11;
	entry->mac[3] = words[2] >> 3;
	entry->mac[4] = ((words[2] & 7U) << 5) | (words[1] >> 27);
	entry->mac[5] = words[1] >> 19;
	entry->key_vid = (words[1] >> 7) & 4095U;
	entry->key_sc = (words[1] >> 6) & 1U;
	entry->key_dot1p = (words[1] >> 3) & 7U;
	entry->learned_vid = ((words[1] & 7U) << 9) | (words[0] >> 23);
	entry->learned_sc = (words[0] >> 22) & 1U;
	entry->is_static = (words[0] >> 19) & 1U;
	entry->sa_permit = (words[0] >> 21) & 1U;
	entry->da_permit = (words[0] >> 20) & 1U;
	entry->multicast = (words[0] >> 10) & 1U;
	entry->age = (words[0] >> 11) & 255U;
	entry->destination = words[0] & (entry->multicast ? 1023U : 63U);
	entry->valid = entry->multicast ? 1U : ((words[0] >> 9) & 1U);
	entry->temporary = entry->multicast ? 0U : ((words[0] >> 8) & 1U);
	entry->in_station_move = entry->multicast ? 0U : ((words[0] >> 7) & 1U);
	entry->in_refresh = entry->multicast ? 0U : ((words[0] >> 6) & 1U);
	entry->untagged = (words[3] >> 3) & 1U;
}

#endif
