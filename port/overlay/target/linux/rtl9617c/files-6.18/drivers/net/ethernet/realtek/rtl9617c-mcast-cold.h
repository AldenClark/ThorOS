/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTL9617C_MCAST_COLD_H
#define RTL9617C_MCAST_COLD_H

#include "rtl9617c-mcast-state.h"

#define RTL_MCAST_CONTROL 0xaa60U
#define RTL_MCAST_COPY_LSPID_TO_POL (1U << 17)
#define RTL_MCAST_BUFFER_FLUSH (1U << 18)
#define RTL_MCAST_NI_SOURCE 0xa1c0U
#define RTL_MCAST_ELPB_RELOOKUP (1U << 3)

static inline int rtl_mcast_foreign_group(unsigned int foreign[8],
					unsigned int group)
{
	/* DFT/VLAN/FDB encode 10 bits but MCE has only 256 physical vectors.
	 * High bits are not an invitation to alias two owners modulo 256.
	 */
	if (group >= RTL_L2_MC_VECTOR_ENTRIES)
		return -EOPNOTSUPP;
	rtl_l2_owner_set(foreign, group);
	return 0;
}

static inline int rtl_mcast_cold_fdb(struct rtl_mcast_state *state,
		const struct rtl_dq_io *io, unsigned int foreign[8])
{
	unsigned int saved[RTL_L2_FDB_FILTER_WORDS], filter[RTL_L2_FDB_FILTER_WORDS];
	struct rtl_l2_fdb_result result;
	struct rtl_l2_fdb_entry entry;
	unsigned int i, reg, start = 0, control;
	int ret, restore = 0;

	ret = rtl_l2_fdb_mode_control(io, &control);
	if (ret)
		return ret;
	if (!(control & RTL_L2_FDB_CMD_MODE))
		return -EOPNOTSUPP;
	for (i = 0; i < RTL_L2_FDB_FILTER_WORDS; i++) {
		saved[i] = filter[i] = io->read(io->context, RTL_L2_FDB_FILTER_WORD0 - i * 4);
		state->saved_fdb_filter[i] = saved[i];
	}
	/* Own before the first write. A late command retains the snapshot in
	 * the FE-lifetime object; a stack unwind must not destroy its owner. */
	state->fdb_filter_owned = 1;
	rtl_l2_fdb_scan_filter(filter);
	for (i = 0; i < RTL_L2_FDB_FILTER_WORDS; i++) {
		reg = RTL_L2_FDB_FILTER_WORD0 - i * 4;
		io->write(io->context, reg, filter[i]);
		if (io->read(io->context, reg) != filter[i]) {
			ret = -EIO;
			goto out;
		}
	}
	while (start < RTL_L2_FDB_ENTRIES) {
		ret = rtl_l2_fdb_scan(io, start, &result);
		state->cold_reads++;
		if (ret <= 0)
			break;
		start = result.index + 1;
		rtl_l2_fdb_decode(result.words, &entry);
		if (entry.multicast) {
			ret = rtl_mcast_foreign_group(foreign, entry.destination);
			if (ret)
				break;
		} else if (entry.destination == RTL_MCAST_SOURCE) {
			ret = -EOPNOTSUPP;
			break;
		}
		ret = 0;
	}
out:
	/* An unfinished command owns its persistent comparison filter. */
	if (rtl_l2_fdb_mode_control(io, &control))
		return ret ? ret : -EBUSY;
	for (i = 0; i < RTL_L2_FDB_FILTER_WORDS; i++) {
		reg = RTL_L2_FDB_FILTER_WORD0 - i * 4;
		io->write(io->context, reg, saved[i]);
		if (io->read(io->context, reg) != saved[i])
			restore = -EIO;
	}
	if (!restore)
		state->fdb_filter_owned = 0;
	return restore ? restore : ret;
}

/* Actual cold-only root enumeration, not a free-space heuristic. The FE
 * owner MUST separately fence CPU injection and prove no inherited L3
 * hash/classifier/DDR producer before calling this function. LAN/PON MAC
 * admission is still closed and no runtime owner has been published.
 * Unknown indirect group producers refuse this optional feature; they are
 * never rewritten just to create free vectors. No timeout is a drain.
 */
static inline int rtl_mcast_cold_prepare(struct rtl_mcast_state *state,
		struct rtl_l2_owner *owner, const struct rtl_dq_io *io)
{
	unsigned int foreign[8] = { 1U }, words[5], x[3], y[3];
	unsigned int index, group, value, control, mode, ni, source, nonempty = 0;
	int ret;

	if (!state || !owner || !rtl_l2_io_valid(io) || owner->sealed ||
	    state->contract_ready)
		return -EINVAL;
	mode = io->read(io->context, RTL_L2_VLAN_MODE_CONTROL);
	control = io->read(io->context, RTL_MCAST_CONTROL);
	ni = io->read(io->context, RTL_MCAST_NI_SOURCE);
	if (mode == ~0U || control == ~0U || ni == ~0U)
		return -EIO;
	if ((mode & RTL_MCAST_ELPB_RELOOKUP) ||
	    (control & RTL_MCAST_BUFFER_FLUSH) ||
	    (ni & 63U) != RTL_MCAST_SOURCE || !(ni & (1U << 7)) ||
	    (ni & 0xff00U))
		return -EOPNOTSUPP;
	for (index = 0; index < RTL_L2_LOGICAL_PORTS * 4; index++) {
		ret = rtl_l2_table_read(io, RTL_L2_TBL_DFT_FWD, index, words);
		if (ret)
			return ret;
		state->cold_reads++;
		if ((words[0] & 1U) || !(words[0] & (1U << 12)))
			continue;
		group = (words[0] >> 1) & 1023U;
		if (words[0] & (1U << 11)) {
			if (group == RTL_MCAST_SOURCE)
				return -EOPNOTSUPP;
			continue;
		}
		ret = rtl_mcast_foreign_group(foreign, group);
		if (ret)
			return ret;
	}
	/* LAN and both WAN VID maps share every row in this one bank. Read
	 * all rows, including currently unindexed rows, conservatively. */
	for (index = 0; index < RTL_L2_VLAN_FIB_ENTRIES; index++) {
		ret = rtl_l2_table_read(io, RTL_L2_TBL_VLAN_FIB, index, words);
		if (ret)
			return ret;
		state->cold_reads++;
		ret = rtl_mcast_foreign_group(foreign, words[1] & 1023U);
		if (ret)
			return ret;
	}
	ret = rtl_mcast_cold_fdb(state, io, foreign);
	if (ret)
		return ret;
	for (index = 0; index < RTL_L2_CF_ENTRIES; index++) {
		ret = rtl_l2_table_read(io, RTL_L2_TBL_CF_KEY, index, x);
		if (!ret)
			ret = rtl_l2_table_read(io, RTL_L2_TBL_CF_KEY,
						index + RTL_L2_CF_ENTRIES, y);
		if (ret)
			return ret;
		state->cold_reads += 2;
		if ((x[2] ^ y[2]) & (1U << 16))
			return -EOPNOTSUPP;
		if (!(x[2] & (1U << 16)))
			continue;
		ret = rtl_l2_table_read(io, RTL_L2_TBL_CF_FIB, index, words);
		if (ret)
			return ret;
		state->cold_reads++;
		/* grpid/flowid assignments are context-dependent metadata,
		 * not the direct 8-bit forward_act=MCGID contract. */
		if (words[0] & ((1U << 23) | (1U << 24)))
			return -EOPNOTSUPP;
		value = (words[1] >> 5) & 7U;
		group = (words[1] >> 8) & 255U;
		if (value == 4) {
			ret = rtl_mcast_foreign_group(foreign, group);
			if (ret)
				return ret;
		} else if (value > 4 || (value == 3 && group == RTL_MCAST_SOURCE)) {
			return -EOPNOTSUPP;
		}
	}
	for (index = 0; index < RTL_L2_SPB_PROFILES * RTL_L2_SPB_PACKET_TYPES; index++) {
		ret = rtl_l2_table_read(io, RTL_L2_TBL_SPB, index, words);
		if (ret)
			return ret;
		state->cold_reads++;
		if ((words[0] & (1U << 5)) ||
		    ((words[0] & (1U << 29)) &&
		     ((words[0] >> 23) & 63U) == RTL_MCAST_SOURCE))
			return -EOPNOTSUPP;
	}
	for (index = 0; index < RTL_L2_LOGICAL_PORTS; index++) {
		ret = rtl_l2_table_read(io, RTL_L2_TBL_REDIR_LDPID, index, words);
		if (ret)
			return ret;
		state->cold_reads++;
		if ((words[0] & (1U << 10)) &&
		    ((words[0] >> 4) & 63U) == RTL_MCAST_SOURCE)
			return -EOPNOTSUPP;
		ret = rtl_l2_table_read(io, RTL_L2_TBL_IPPB, index, words);
		if (ret)
			return ret;
		state->cold_reads++;
		if (index != RTL_MCAST_SOURCE && (words[0] & 63U) == RTL_MCAST_SOURCE)
			return -EOPNOTSUPP;
	}
	/* A queued old CPU copy can outlive removal of its producer root.
	 * With the old cp_lspid_to_pol_id setting, it may carry LSPID instead
	 * of the explicit action POL. Reserve the complete 6-bit source range
	 * AND each old action's upper-three-bit class. This covers full
	 * zero-extension, low-six-bit overwrite and action-POL-last ordering
	 * without asserting an undocumented overwrite width. Never recycle
	 * these boot tokens; complete coverage means ordinary CPU fallback.
	 */
	for (source = 0; source < 64; source++)
		rtl_l2_owner_set(state->forbidden_token, source);
	for (index = 0; index < RTL_L2_MC_FIB_ENTRIES; index++) {
		ret = rtl_l2_table_read(io, RTL_L2_TBL_MC_FIB, index, words);
		if (ret)
			return ret;
		state->cold_reads++;
		value = (words[0] >> 23) & ~63U;
		for (source = 0; source < 64; source++)
			rtl_l2_owner_set(state->forbidden_token, value | source);
	}
	for (index = 1; index < RTL_L2_MC_VECTOR_ENTRIES; index++) {
		if (!rtl_l2_owner_has(foreign, index))
			continue;
		ret = rtl_l2_table_read(io, RTL_L2_TBL_MC_VECTOR, index, words);
		if (ret)
			return ret;
		state->cold_reads++;
		nonempty |= words[0] | words[1];
	}
	/* The default cp_lspid_to_pol_id_en=1 would overwrite our immutable
	 * token. Clear it only with exclusive MCE producer ownership. A
	 * foreign active root may rely on that setting and vetoes the change.
	 */
	if ((control & RTL_MCAST_COPY_LSPID_TO_POL) && nonempty)
		return -EOPNOTSUPP;
	ret = rtl_l2_owner_mc_cold_scan(owner, io, foreign);
	if (ret)
		return ret;
	value = control & ~RTL_MCAST_COPY_LSPID_TO_POL;
	if (value != control) {
		state->saved_mce_control = control;
		state->mce_control_owned = 1;
		io->write(io->context, RTL_MCAST_CONTROL, value);
	}
	if (io->read(io->context, RTL_MCAST_CONTROL) != value) {
		owner->ready_mask &= ~RTL_L2_OWNER_MC_READY;
		owner->mc_error = -EIO;
		return rtl_l2_owner_fault(owner, -EIO);
	}
	state->contract_ready = 1;
	return 0;
}

#endif
