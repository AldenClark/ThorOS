/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_MDB_OFFLOAD_H
#define RTL9617C_MDB_OFFLOAD_H

#include "rtl9617c-fe-pipeline.h"

/* Exact IP multicast uses the classifier FULL_KEY, not the routing CRC or
 * the L2 CF's MAC key. Contract: pinned aal-77c/include/aal_l3_cls.h and
 * aal_l3_cls.c (__l3_cls_fib_idx_get/aal_l3_cls_add), SDK 8b4f4882ff0e.
 * Each profile has 128 key rows. A full key consumes two 352-bit rows and
 * two standard 224-bit result rows; the second result row selects format0.
 *
 * The FE owner serializes ALL CLS/CAM writers and gates ingress before
 * init/install/withdraw. It must own both default profiles, exclude foreign
 * result groups, preserve the actual/original LAN LSPID and arrange that a
 * miss reaches the CPU. This header never takes over a nonempty classifier.
 * Bridge policy/querier/time invariance is checked by the snapshot consumer,
 * not inferred from an IP address here. Control protocols remain software.
 *
 * An indirect timeout is not cancellation and clearing keys is not an L3
 * packet drain. After any VALID publication attempt, that key/FIB slot and
 * its MCE dependencies remain immutable until a real hardware reset. No
 * policy churn can recycle an index still carried by an in-flight packet.
 */
#define RTL_MDB_TCAM_SLOTS 62U
#define RTL_MDB_PROFILE_GUARDS 2U
#define RTL_MDB_KEY_WORDS 22U
#define RTL_MDB_FIB_WORDS 14U
#define RTL_MDB_KEY_VALID (15U << 27)

struct rtl_mdb_rule {
	/* Numeric address words in network order, most significant word first.
	 * IPv4 occupies word0 and requires word1..3 == 0 (not IPv4-mapped IPv6).
	 */
	unsigned int destination[4], source[4];
	unsigned short vid, group;
	unsigned char ipv6, source_specific, ingress, protocol;
};

struct rtl_mdb_dependency {
	void *context;
	/* Pins the immutable MCE vector, every action and the CPU-copy token.
	 * Failure must retain any uncertain partial ownership. No unpin is
	 * performed here: the caller revokes token admission after withdrawal.
	 */
	int (*publish)(void *context, unsigned int group);
};

struct rtl_mdb_tcam_slot {
	struct rtl_mdb_rule rule;
	unsigned int key_saved[RTL_MDB_KEY_WORDS];
	unsigned int fib_saved[RTL_MDB_FIB_WORDS];
	unsigned char claimed, dirty, exposed, active;
};

struct rtl_mdb_profile_guard {
	unsigned int key_saved[RTL_MDB_KEY_WORDS];
	unsigned int fib_saved[RTL_MDB_FIB_WORDS];
	unsigned char dirty, exposed, active;
};

struct rtl_mdb_tcam {
	struct rtl_mdb_tcam_slot slot[RTL_MDB_TCAM_SLOTS];
	/* Physical FULL_KEY slots62/63 belong to the FE lifetime, independent
	 * of any bridge policy epoch or multicast vector. They prevent an MC
	 * Ethernet packet with a unicast IP tuple from falling into route Hash.
	 */
	struct rtl_mdb_profile_guard guard[RTL_MDB_PROFILE_GUARDS];
	struct rtl_fe_cam_protocol ether[2];
	unsigned char ether_id[2];
	unsigned short used, active;
	unsigned char initialized, prepared, poisoned, exposed;
	unsigned char guards_ready, guard_exposed;
};

static inline int rtl_mdb_words_equal(const unsigned int *a,
	const unsigned int *b, unsigned int count)
{
	unsigned int i;
	for (i = 0; i < count; i++)
		if (a[i] != b[i])
			return 0;
	return 1;
}

static inline void rtl_mdb_words_copy(unsigned int *to,
	const unsigned int *from, unsigned int count)
{
	unsigned int i;
	for (i = 0; i < count; i++)
		to[i] = from[i];
}

static inline int rtl_mdb_rule_valid(const struct rtl_mdb_rule *rule)
{
	unsigned int d, s;
	if (!rule || rule->ipv6 > 1 || rule->source_specific > 1 ||
	    rule->ingress >= 5 || !rule->group || rule->group >= 256)
		return -EINVAL;
	/* Tagged MCE packet-editor/ELPB ordering is a separate contract. */
	if (rule->vid || (rule->protocol != 6 && rule->protocol != 17))
		return -EOPNOTSUPP;
	d = rule->destination[0];
	s = rule->source[0] | rule->source[1] |
	    rule->source[2] | rule->source[3];
	if (rule->source_specific != !!s)
		return -EINVAL;
	if (rule->ipv6) {
		if ((d >> 24) != 255 ||
		    (rule->source_specific && (rule->source[0] >> 24) == 255))
			return -EINVAL;
		/* Linux always floods link-local all-nodes, independent of MDB. */
		if (d == 0xff020000U && !rule->destination[1] &&
		    !rule->destination[2] && rule->destination[3] == 1)
			return -EOPNOTSUPP;
	} else {
		if ((d >> 28) != 14 || rule->destination[1] ||
		    rule->destination[2] || rule->destination[3] ||
		    rule->source[1] || rule->source[2] || rule->source[3] ||
		    (rule->source_specific && (rule->source[0] >> 28) >= 14))
			return -EINVAL;
		if ((d & 0xffffff00U) == 0xe0000000U)
			return -EOPNOTSUPP;
	}
	return 0;
}

/* Output is unchanged on rejection. Masks are inverse except the IP prefix
 * length fields; IPv6 uses 128 and IPv4 32. The long-key continuation has
 * no independent VALID/type/control bits (the SDK only publishes row0).
 */
static inline int rtl_mdb_rule_build(const struct rtl_mdb_rule *rule,
	unsigned int ether_id, unsigned int key[RTL_MDB_KEY_WORDS],
	unsigned int fib[RTL_MDB_FIB_WORDS])
{
	unsigned int k[RTL_MDB_KEY_WORDS], f[RTL_MDB_FIB_WORDS], i, prefix;
	int ret = rtl_mdb_rule_valid(rule);
	if (ret)
		return ret;
	if (!ether_id || ether_id > 63 || !key || !fib)
		return -EINVAL;
	for (i = 0; i < RTL_MDB_KEY_WORDS; i++)
		k[i] = ~0U;
	for (i = 0; i < RTL_MDB_FIB_WORDS; i++)
		f[i] = 0;
	prefix = rule->ipv6 ? 128 : 32;
	rtl_fe_bits_set(k, 46, 1, 0); /* L4 valid */
	rtl_fe_bits_set(k, 47, 1, 1);
	rtl_fe_bits_set(k, 48, 1, 0); /* no parser checksum error */
	rtl_fe_bits_set(k, 49, 1, 0);
	rtl_fe_bits_set(k, 53, 1, 0); /* no fragment/options */
	rtl_fe_bits_set(k, 54, 1, 0);
	rtl_fe_bits_set(k, 55, 1, 0);
	rtl_fe_bits_set(k, 56, 1, 0);
	rtl_fe_bits_set(k, 59, 1, 0); /* IP DA multicast */
	rtl_fe_bits_set(k, 60, 1, 1);
	rtl_fe_bits_set(k, 61, 9, prefix);
	rtl_fe_bits_set(k, 198, 9, rule->source_specific ? prefix : 0);
	for (i = 0; i < 4; i++) {
		unsigned int index = rule->ipv6 ? 3 - i : i;
		rtl_fe_bits_set(k, 70 + i * 32, 32, rule->destination[index]);
		rtl_fe_bits_set(k, 207 + i * 32, 32, rule->source[index]);
	}
	rtl_fe_bits_set(k, 335, 17, 0); /* address/control/reserved */
	rtl_fe_bits_set(k, 344, 3, 6); /* CL_FULL_KEY, result type0 */
	rtl_fe_bits_set(k, 347, 4, 1); /* VALID, written LAST */
	rtl_fe_bits_set(k, 352, 1, 0); /* exact IP protocol */
	rtl_fe_bits_set(k, 353, 8, rule->protocol);
	rtl_fe_bits_set(k, 371, 1, 0); /* exact version + valid IP */
	rtl_fe_bits_set(k, 372, 1, rule->ipv6);
	rtl_fe_bits_set(k, 373, 1, 0);
	rtl_fe_bits_set(k, 374, 1, 1);
	rtl_fe_bits_set(k, 446, 1, 0); /* exact zero VLAN count */
	rtl_fe_bits_set(k, 447, 2, 0);
	rtl_fe_bits_set(k, 459, 1, 0); /* exclude PPPoE/other outer EtherTypes */
	rtl_fe_bits_set(k, 460, 6, ether_id);
	rtl_fe_bits_set(k, 517, 1, 0); /* IP multicast Ethernet DA */
	rtl_fe_bits_set(k, 518, 1, 1);
	rtl_fe_bits_set(k, 519, 1, 0);
	rtl_fe_bits_set(k, 520, 1, 1);
	rtl_fe_bits_set(k, 521, 1, 0);
	rtl_fe_bits_set(k, 522, 1, 0);
	rtl_fe_bits_set(k, 621, 1, 0); /* original ingress excludes PON/CPU */
	rtl_fe_bits_set(k, 622, 6, rule->ingress);
	rtl_fe_bits_set(k, 628, 1, 0);
	rtl_fe_bits_set(k, 629, 6, rule->ingress);
	rtl_fe_bits_set(k, 635, 22, 0);
	rtl_fe_bits_set(k, 657, 32, 0);
	rtl_fe_bits_set(k, 689, 15, 0);
	/* The standard mode0 original-packet recipe does not decrement TTL or
	 * rewrite MAC/VLAN/PPPoE. Replace only its destination with an MCE ID.
	 */
	rtl_fe_classify_cpu_original(f);
	rtl_fe_bits_set(f, 158, 10, rule->group);
	rtl_fe_bits_set(f, 168, 1, 1);
	rtl_mdb_words_copy(key, k, RTL_MDB_KEY_WORDS);
	rtl_mdb_words_copy(fib, f, RTL_MDB_FIB_WORDS);
	return 0;
}

static inline unsigned int rtl_mdb_fib_index(unsigned int slot)
{
	return (slot << 3) | 4U;
}

/* Disjoint type0 CPU guards, not higher-priority catchalls:
 * A: MAC_MC=1, MAC_BC=0, IP_DA_MC=0; B: MAC_BC=1.
 * Exact MDB has MAC_MC=1, MAC_BC=0, IP_DA_MC=1. All other guard
 * selectors are wildcard, including source, VLAN, EtherType and protocol.
 * Ordinary routed IP rules separately reject multicast IP endpoints.
 */
static inline int rtl_mdb_guard_build(unsigned int which,
	unsigned int key[RTL_MDB_KEY_WORDS], unsigned int fib[RTL_MDB_FIB_WORDS])
{
	unsigned int i;
	if (which >= RTL_MDB_PROFILE_GUARDS || !key || !fib)
		return -EINVAL;
	for (i = 0; i < RTL_MDB_KEY_WORDS; i++)
		key[i] = ~0U;
	for (i = 0; i < RTL_MDB_FIB_WORDS; i++)
		fib[i] = 0;
	/* Prefix masks are lengths, unlike the inverse one-bit masks. */
	rtl_fe_bits_set(key, 61, 9, 0);
	rtl_fe_bits_set(key, 198, 9, 0);
	for (i = 0; i < 4; i++) {
		rtl_fe_bits_set(key, 70 + i * 32, 32, 0);
		rtl_fe_bits_set(key, 207 + i * 32, 32, 0);
	}
	if (!which) {
		rtl_fe_bits_set(key, 59, 1, 0);
		rtl_fe_bits_set(key, 60, 1, 0);
		rtl_fe_bits_set(key, 519, 1, 0);
		rtl_fe_bits_set(key, 520, 1, 1);
	}
	rtl_fe_bits_set(key, 521, 1, 0);
	rtl_fe_bits_set(key, 522, 1, !!which);
	rtl_fe_bits_set(key, 335, 17, 0);
	rtl_fe_bits_set(key, 344, 3, 6);
	rtl_fe_bits_set(key, 347, 4, 1);
	rtl_fe_bits_set(key, 635, 22, 0);
	rtl_fe_bits_set(key, 657, 32, 0);
	rtl_fe_bits_set(key, 689, 15, 0);
	rtl_fe_classify_cpu_original(fib);
	return 0;
}

static inline int rtl_mdb_row_read(const struct rtl_dq_io *io,
	unsigned int access, unsigned int data, unsigned int index,
	unsigned int *words, unsigned int count)
{
	unsigned int i;
	int ret = rtl_fe_window_idle(io, access);
	if (ret)
		return ret;
	ret = io->indirect(io->context, access, 0x80000000U | index);
	if (ret)
		return ret;
	for (i = 0; i < count; i++)
		words[i] = io->read(io->context, data - i * 4);
	return 0;
}

static inline int rtl_mdb_row_write(const struct rtl_dq_io *io,
	unsigned int access, unsigned int data, unsigned int index,
	const unsigned int *words, unsigned int count)
{
	unsigned int i, check[11];
	int ret = rtl_fe_window_idle(io, access);
	if (ret)
		return ret;
	for (i = 0; i < count; i++)
		io->write(io->context, data - i * 4, words[i]);
	ret = io->indirect(io->context, access, 0xc0000000U | index);
	if (ret)
		return ret;
	ret = rtl_mdb_row_read(io, access, data, index, check, count);
	if (ret)
		return ret;
	return rtl_mdb_words_equal(words, check, count) ? 0 : -EIO;
}

/* Snapshot ALL key formats/profiles before claiming any row. Inactive FIB
 * bytes are not assumed zero and are restored in full on pre-publication
 * rollback. A failed init retains its CAM binding/snapshots for restore.
 */
static inline int rtl_mdb_tcam_init(const struct rtl_dq_io *io,
	struct rtl_mdb_tcam *tcam)
{
	unsigned int i, side, words[11], protocol[2] = {0x0800, 0x86dd};
	int ret;
	if (!rtl_l2_io_valid(io) || !tcam)
		return -EINVAL;
	if (tcam->initialized || tcam->prepared || tcam->poisoned ||
	    tcam->used || tcam->exposed || tcam->guards_ready || tcam->guard_exposed)
		return -EBUSY;
	for (i = 0; i < 256; i++) {
		ret = rtl_mdb_row_read(io, 0x3380, 0x33ac, i, words, 11);
		if (ret)
			return ret;
		if (words[10] & RTL_MDB_KEY_VALID)
			return -EBUSY;
		if (i < RTL_MDB_TCAM_SLOTS * 2)
			rtl_mdb_words_copy(tcam->slot[i / 2].key_saved +
				(i % 2) * 11, words, 11);
		else if (i < (RTL_MDB_TCAM_SLOTS + RTL_MDB_PROFILE_GUARDS) * 2)
			rtl_mdb_words_copy(tcam->guard[i / 2 - RTL_MDB_TCAM_SLOTS].key_saved +
				(i % 2) * 11, words, 11);
	}
	for (i = 0; i < RTL_MDB_TCAM_SLOTS; i++) {
		for (side = 0; side < 2; side++) {
			ret = rtl_mdb_row_read(io, 0x33b0, 0x33cc,
				rtl_mdb_fib_index(i) + side,
				tcam->slot[i].fib_saved + side * 7, 7);
			if (ret)
				return ret;
		}
	}
	for (i = 0; i < RTL_MDB_PROFILE_GUARDS; i++) {
		for (side = 0; side < 2; side++) {
			ret = rtl_mdb_row_read(io, 0x33b0, 0x33cc,
				rtl_mdb_fib_index(RTL_MDB_TCAM_SLOTS + i) + side,
				tcam->guard[i].fib_saved + side * 7, 7);
			if (ret)
				return ret;
		}
	}
	tcam->prepared = 1;
	for (i = 0; i < 2; i++) {
		ret = rtl_fe_window_idle(io, 0x3200);
		if (ret)
			goto fail;
		ret = rtl_fe_cam_protocol_get(io, &tcam->ether[i], 2, protocol[i]);
		if (ret < 0)
			goto fail;
		tcam->ether_id[i] = ret;
		ret = rtl_mdb_row_read(io, 0x3200, 0x3214,
			(2U << 16) | tcam->ether[i].index, words, 5);
		if (ret)
			goto fail;
		if (!(words[0] & (1U << 16)) || (words[0] & 65535U) != protocol[i]) {
			ret = -EIO;
			goto fail;
		}
	}
	tcam->initialized = 1;
	return 0;
fail:
	tcam->poisoned = 1;
	return ret;
}

/* Install before clearing the global my-MAC-failure CLS bypass. No MCE
 * lease is needed for the fixed original-packet CPU16 destination. Once a
 * VALID command is attempted, guards and their FIB rows are immutable for
 * the entire FE lifetime; ordinary MDB withdrawal must leave them intact.
 */
static inline int rtl_mdb_profile_prepare(const struct rtl_dq_io *io,
	struct rtl_mdb_tcam *tcam)
{
	unsigned int i, side, key[RTL_MDB_KEY_WORDS], fib[RTL_MDB_FIB_WORDS], words[11];
	int ret;
	if (!rtl_l2_io_valid(io) || !tcam || !tcam->initialized)
		return -EINVAL;
	if (tcam->poisoned || tcam->guards_ready || tcam->guard_exposed)
		return -EBUSY;
	for (i = 0; i < RTL_MDB_PROFILE_GUARDS; i++) {
		struct rtl_mdb_profile_guard *guard = &tcam->guard[i];
		unsigned int slot = RTL_MDB_TCAM_SLOTS + i;
		for (side = 0; side < 2; side++) {
			ret = rtl_mdb_row_read(io, 0x3380, 0x33ac, slot * 2 + side, words, 11);
			if (ret)
				goto fail;
			if (!rtl_mdb_words_equal(words, guard->key_saved + side * 11, 11)) {
				ret = -EBUSY;
				goto fail;
			}
			ret = rtl_mdb_row_read(io, 0x33b0, 0x33cc, rtl_mdb_fib_index(slot) + side, words, 7);
			if (ret)
				goto fail;
			if (!rtl_mdb_words_equal(words, guard->fib_saved + side * 7, 7)) {
				ret = -EBUSY;
				goto fail;
			}
		}
		rtl_mdb_guard_build(i, key, fib);
		guard->dirty = 1;
		for (side = 0; side < 2; side++) {
			ret = rtl_mdb_row_write(io, 0x3380, 0x33ac, slot * 2 + side,
				guard->key_saved + side * 11, 11);
			if (ret)
				goto fail;
		}
		ret = rtl_mdb_row_write(io, 0x33b0, 0x33cc, rtl_mdb_fib_index(slot) + 1, fib + 7, 7);
		if (ret)
			goto fail;
		ret = rtl_mdb_row_write(io, 0x33b0, 0x33cc, rtl_mdb_fib_index(slot), fib, 7);
		if (ret)
			goto fail;
		ret = rtl_mdb_row_write(io, 0x3380, 0x33ac, slot * 2 + 1, key + 11, 11);
		if (ret)
			goto fail;
		guard->exposed = tcam->guard_exposed = 1;
		ret = rtl_mdb_row_write(io, 0x3380, 0x33ac, slot * 2, key, 11);
		if (ret)
			goto fail;
		guard->active = 1;
	}
	tcam->guards_ready = 1;
	return 0;
fail:
	tcam->poisoned = 1;
	return ret;
}

/* Warm base validation: exact MDB was withdrawn before this call. Check
 * both complete guard keys/results and reject every other valid key in
 * BOTH profiles (all result groups/formats), not merely our own slots.
 */
static inline int rtl_mdb_profile_check(const struct rtl_dq_io *io,
	const struct rtl_mdb_tcam *tcam)
{
	unsigned int i, side, key[RTL_MDB_KEY_WORDS], fib[RTL_MDB_FIB_WORDS], words[11];
	int ret;
	if (!rtl_l2_io_valid(io) || !tcam || !tcam->guards_ready ||
	    !tcam->guard_exposed || tcam->poisoned || tcam->active)
		return -EBUSY;
	for (i = 0; i < 256; i++) {
		ret = rtl_mdb_row_read(io, 0x3380, 0x33ac, i, words, 11);
		if (ret)
			return ret;
		if (i >= RTL_MDB_TCAM_SLOTS * 2 &&
		    i < (RTL_MDB_TCAM_SLOTS + RTL_MDB_PROFILE_GUARDS) * 2) {
			unsigned int which = i / 2 - RTL_MDB_TCAM_SLOTS;
			if (!tcam->guard[which].active)
				return -EBUSY;
			rtl_mdb_guard_build(which, key, fib);
			if (!rtl_mdb_words_equal(words, key + (i % 2) * 11, 11))
				return -EIO;
		} else if (words[10] & RTL_MDB_KEY_VALID) {
			return -EBUSY;
		}
	}
	for (i = 0; i < RTL_MDB_PROFILE_GUARDS; i++) {
		rtl_mdb_guard_build(i, key, fib);
		for (side = 0; side < 2; side++) {
			ret = rtl_mdb_row_read(io, 0x33b0, 0x33cc,
				rtl_mdb_fib_index(RTL_MDB_TCAM_SLOTS + i) + side, words, 7);
			if (ret)
				return ret;
			if (!rtl_mdb_words_equal(words, fib + side * 7, 7))
				return -EIO;
		}
	}
	return 0;
}

/* No reliance on undocumented tie-breaking between equal-priority keys.
 * The bridge consumer folds equivalent ASM/SSM policies or keeps the
 * wildcard on CPU while emitting disjoint exact sources. Any accidental
 * overlap in its final hardware plan is still rejected here.
 */
static inline int rtl_mdb_rules_overlap(const struct rtl_mdb_rule *a,
	const struct rtl_mdb_rule *b)
{
	if (a->ipv6 != b->ipv6 || a->ingress != b->ingress ||
	    a->protocol != b->protocol || a->vid != b->vid ||
	    !rtl_mdb_words_equal(a->destination, b->destination, 4))
		return 0;
	return !a->source_specific || !b->source_specific ||
		rtl_mdb_words_equal(a->source, b->source, 4);
}

static inline int rtl_mdb_slot_check_saved(const struct rtl_dq_io *io,
	struct rtl_mdb_tcam *tcam, unsigned int index)
{
	struct rtl_mdb_tcam_slot *slot = &tcam->slot[index];
	unsigned int side, words[11];
	int ret;
	for (side = 0; side < 2; side++) {
		ret = rtl_mdb_row_read(io, 0x3380, 0x33ac, index * 2 + side,
			words, 11);
		if (ret)
			return ret;
		if (!rtl_mdb_words_equal(words, slot->key_saved + side * 11, 11))
			return -EBUSY;
		ret = rtl_mdb_row_read(io, 0x33b0, 0x33cc,
			rtl_mdb_fib_index(index) + side, words, 7);
		if (ret)
			return ret;
		if (!rtl_mdb_words_equal(words, slot->fib_saved + side * 7, 7))
			return -EBUSY;
	}
	return 0;
}

static inline int rtl_mdb_tcam_install(const struct rtl_dq_io *io,
	struct rtl_mdb_tcam *tcam, const struct rtl_mdb_rule *rule,
	const struct rtl_mdb_dependency *dependency, unsigned int *result)
{
	struct rtl_mdb_tcam_slot *slot;
	unsigned int key[RTL_MDB_KEY_WORDS], fib[RTL_MDB_FIB_WORDS], i, index;
	int ret;
	if (!rtl_l2_io_valid(io) || !tcam || !dependency ||
	    !dependency->publish || !result)
		return -EINVAL;
	ret = rtl_mdb_rule_valid(rule);
	if (ret)
		return ret;
	if (!tcam->initialized || tcam->poisoned)
		return -EBUSY;
	if (tcam->used == RTL_MDB_TCAM_SLOTS)
		return -ENOSPC;
	for (i = 0; i < tcam->used; i++)
		if (tcam->slot[i].active && rtl_mdb_rules_overlap(rule, &tcam->slot[i].rule))
			return -EEXIST;
	ret = rtl_mdb_rule_build(rule, tcam->ether_id[rule->ipv6], key, fib);
	if (ret)
		return ret;
	index = tcam->used;
	ret = rtl_mdb_slot_check_saved(io, tcam, index);
	if (ret) {
		tcam->poisoned = 1;
		return ret;
	}
	slot = &tcam->slot[index];
	slot->rule = *rule;
	slot->claimed = 1;
	tcam->used++;
	/* The callback may pin its graph partially even on failure. Retain this
	 * slot and require explicit recovery instead of assuming cancellation.
	 */
	ret = dependency->publish(dependency->context, rule->group);
	if (ret)
		goto fail;
	slot->dirty = 1;
	/* Explicitly clear/verify both roots before any FIB overwrite. */
	for (i = 0; i < 2; i++) {
		ret = rtl_mdb_row_write(io, 0x3380, 0x33ac, index * 2 + i,
			slot->key_saved + i * 11, 11);
		if (ret)
			goto fail;
	}
	/* Format first, data second, long-key continuation third, VALID last. */
	ret = rtl_mdb_row_write(io, 0x33b0, 0x33cc,
		rtl_mdb_fib_index(index) + 1, fib + 7, 7);
	if (ret)
		goto fail;
	ret = rtl_mdb_row_write(io, 0x33b0, 0x33cc,
		rtl_mdb_fib_index(index), fib, 7);
	if (ret)
		goto fail;
	ret = rtl_mdb_row_write(io, 0x3380, 0x33ac, index * 2 + 1, key + 11, 11);
	if (ret)
		goto fail;
	/* Record exposure BEFORE submitting: even a timed-out command can win. */
	slot->exposed = 1;
	tcam->exposed = 1;
	ret = rtl_mdb_row_write(io, 0x3380, 0x33ac, index * 2, key, 11);
	if (ret)
		goto fail;
	slot->active = 1;
	tcam->active++;
	*result = index;
	return 0;
fail:
	tcam->poisoned = 1;
	return ret;
}

/* A pending operation may have left either the saved or intended row. A
 * third image means foreign modification/corruption: retain ownership and
 * the ingress gate rather than overwriting someone else's classifier.
 */
static inline int rtl_mdb_key_clear(const struct rtl_dq_io *io,
	unsigned int index, const unsigned int *saved, const unsigned int *expected)
{
	unsigned int words[11], e[11];
	int ret = rtl_mdb_row_read(io, 0x3380, 0x33ac, index, words, 11);
	if (ret)
		return ret;
	rtl_mdb_words_copy(e, expected, 11);
	e[10] &= ~RTL_MDB_KEY_VALID;
	if (!rtl_mdb_words_equal(words, saved, 11) &&
	    !rtl_mdb_words_equal(words, expected, 11) &&
	    !rtl_mdb_words_equal(words, e, 11))
		return -EIO;
	words[10] &= ~RTL_MDB_KEY_VALID;
	return rtl_mdb_row_write(io, 0x3380, 0x33ac, index, words, 11);
}

/* Caller closes ingress first. Success means no owned key remains valid;
 * only then may CPU-copy token admission be revoked. The immutable result
 * rows and dependency leases are deliberately retained after withdrawal.
 */
static inline int rtl_mdb_tcam_withdraw(const struct rtl_dq_io *io,
	struct rtl_mdb_tcam *tcam)
{
	unsigned int i, side, key[RTL_MDB_KEY_WORDS], fib[RTL_MDB_FIB_WORDS];
	int ret;
	if (!rtl_l2_io_valid(io) || !tcam)
		return -EINVAL;
	for (i = 0; i < tcam->used; i++) {
		struct rtl_mdb_tcam_slot *slot = &tcam->slot[i];
		if (!slot->dirty)
			continue;
		ret = rtl_mdb_rule_build(&slot->rule, tcam->ether_id[slot->rule.ipv6], key, fib);
		if (ret)
			goto fail;
		for (side = 0; side < 2; side++) {
			ret = rtl_mdb_key_clear(io, i * 2 + side,
				slot->key_saved + side * 11, key + side * 11);
			if (ret)
				goto fail;
		}
		if (slot->active) {
			slot->active = 0;
			tcam->active--;
		}
	}
	return 0;
fail:
	tcam->poisoned = 1;
	return ret;
}

/* Restore is only a never-exposed rollback, NOT packet retirement. It can
 * be retried after a timed-out command completes; DATA is never touched
 * while its ACCESS still owns the shared window. All original bytes,
 * including the adjacent format row, are restored and read back.
 */
static inline int rtl_mdb_tcam_restore(const struct rtl_dq_io *io,
	struct rtl_mdb_tcam *tcam)
{
	unsigned int i, side, words[11], key[RTL_MDB_KEY_WORDS], fib[RTL_MDB_FIB_WORDS];
	int ret;
	if (!rtl_l2_io_valid(io) || !tcam)
		return -EINVAL;
	if (tcam->exposed || tcam->active || tcam->guard_exposed)
		return -EBUSY;
	ret = rtl_mdb_tcam_withdraw(io, tcam);
	if (ret)
		return ret;
	for (i = 0; i < RTL_MDB_PROFILE_GUARDS; i++) {
		struct rtl_mdb_profile_guard *guard = &tcam->guard[i];
		unsigned int slot = RTL_MDB_TCAM_SLOTS + i;
		if (!guard->dirty)
			continue;
		rtl_mdb_guard_build(i, key, fib);
		for (side = 0; side < 2; side++) {
			ret = rtl_mdb_key_clear(io, slot * 2 + side,
				guard->key_saved + side * 11, key + side * 11);
			if (ret)
				goto fail;
			ret = rtl_mdb_row_read(io, 0x33b0, 0x33cc,
				rtl_mdb_fib_index(slot) + side, words, 7);
			if (ret)
				goto fail;
			if (!rtl_mdb_words_equal(words, guard->fib_saved + side * 7, 7) &&
			    !rtl_mdb_words_equal(words, fib + side * 7, 7)) {
				ret = -EIO;
				goto fail;
			}
		}
		for (side = 0; side < 2; side++) {
			ret = rtl_mdb_row_write(io, 0x33b0, 0x33cc,
				rtl_mdb_fib_index(slot) + side, guard->fib_saved + side * 7, 7);
			if (ret)
				goto fail;
			ret = rtl_mdb_row_write(io, 0x3380, 0x33ac,
				slot * 2 + side, guard->key_saved + side * 11, 11);
			if (ret)
				goto fail;
		}
		guard->dirty = 0;
	}
	for (i = 0; i < tcam->used; i++) {
		struct rtl_mdb_tcam_slot *slot = &tcam->slot[i];
		if (!slot->dirty)
			continue;
		ret = rtl_mdb_rule_build(&slot->rule, tcam->ether_id[slot->rule.ipv6], key, fib);
		if (ret)
			goto fail;
		for (side = 0; side < 2; side++) {
			ret = rtl_mdb_row_read(io, 0x33b0, 0x33cc,
				rtl_mdb_fib_index(i) + side, words, 7);
			if (ret)
				goto fail;
			if (!rtl_mdb_words_equal(words, slot->fib_saved + side * 7, 7) &&
			    !rtl_mdb_words_equal(words, fib + side * 7, 7)) {
				ret = -EIO;
				goto fail;
			}
		}
		for (side = 0; side < 2; side++) {
			ret = rtl_mdb_row_write(io, 0x33b0, 0x33cc,
				rtl_mdb_fib_index(i) + side, slot->fib_saved + side * 7, 7);
			if (ret)
				goto fail;
		}
		for (side = 0; side < 2; side++) {
			ret = rtl_mdb_row_write(io, 0x3380, 0x33ac,
				i * 2 + side, slot->key_saved + side * 11, 11);
			if (ret)
				goto fail;
		}
		slot->dirty = 0;
	}
	for (i = 0; i < 2; i++) {
		unsigned int expected[5] = {(1U << 16) | (i ? 0x86ddU : 0x0800U), 0, 0, 0, 0};
		if (!tcam->ether[i].created)
			continue;
		ret = rtl_mdb_row_read(io, 0x3200, 0x3214,
			(2U << 16) | tcam->ether[i].index, words, 5);
		if (ret)
			goto fail;
		if (!rtl_mdb_words_equal(words, tcam->ether[i].saved, 5) &&
		    !rtl_mdb_words_equal(words, expected, 5)) {
			ret = -EIO;
			goto fail;
		}
		ret = rtl_mdb_row_write(io, 0x3200, 0x3214,
			(2U << 16) | tcam->ether[i].index, tcam->ether[i].saved, 5);
		if (ret)
			goto fail;
		tcam->ether[i].created = 0;
	}
	/* Reusing a completely rolled back, never-exposed owner is safe. */
	for (i = 0; i < tcam->used; i++)
		tcam->slot[i].claimed = 0;
	tcam->used = 0;
	tcam->initialized = 0;
	tcam->prepared = 0;
	tcam->poisoned = 0;
	tcam->guards_ready = 0;
	return 0;
fail:
	tcam->poisoned = 1;
	return ret;
}

#endif
