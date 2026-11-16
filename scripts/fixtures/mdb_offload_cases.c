/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Host transport only: every key/action/ownership operation is production. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mdb_sdk.h"
#include "rtl9617c-mdb-offload.h"

struct model {
	unsigned int key[256][11], fib[1040][7], cam[63][5];
	unsigned int registers[0x3400 / 4];
	unsigned int commands, writes, table_writes, pins, valid_writes;
	unsigned int fail_at, failure_mode, corrupt_at;
	unsigned int pending_access, pending_command;
	int pin_error;
};
static struct model m, original;
static struct rtl_mdb_tcam t;
static unsigned long assertions, fault_cases;

static unsigned int get(const unsigned int *w, unsigned int bit, unsigned int width)
{
	uint64_t value = w[bit / 32];
	if ((bit % 32) + width > 32)
		value |= (uint64_t)w[bit / 32 + 1] << 32;
	return (value >> (bit % 32)) & (width == 32 ? UINT32_MAX : ((1ULL << width) - 1));
}

static unsigned int model_read(void *context, unsigned int reg)
{
	struct model *s = context;
	assert(reg < sizeof(s->registers));
	return s->registers[reg / 4];
}

static unsigned int window_for_data(unsigned int reg)
{
	if (reg >= 0x3384 && reg <= 0x33ac)
		return 0x3380;
	if (reg >= 0x33b4 && reg <= 0x33cc)
		return 0x33b0;
	if (reg >= 0x3204 && reg <= 0x3214)
		return 0x3200;
	assert(0);
	return 0;
}

static void model_write(void *context, unsigned int reg, unsigned int value)
{
	struct model *s = context;
	unsigned int access = window_for_data(reg);
	assert(!(s->registers[access / 4] & 0x80000000U));
	assert(s->pending_access != access);
	s->writes++;
	s->registers[reg / 4] = value;
}

static void complete(struct model *s, unsigned int access, unsigned int command)
{
	unsigned int *row, count, data, index, i;
	if (access == 0x3380) {
		index = command & 255;
		row = s->key[index]; count = 11; data = 0x33ac;
	} else if (access == 0x33b0) {
		index = command & 2047;
		assert(index < 1040);
		row = s->fib[index]; count = 7; data = 0x33cc;
	} else {
		assert(access == 0x3200 && ((command >> 16) & 255) == 2);
		index = command & 63;
		assert(index < 63);
		row = s->cam[index]; count = 5; data = 0x3214;
	}
	if (command & 0x40000000U) {
		s->table_writes++;
		if (access == 0x3380 && (s->registers[0x3384 / 4] & RTL_MDB_KEY_VALID)) {
			unsigned int f = ((index >> 1) << 3) | 4U;
			/* Semantic publication oracle independent of the production
			 * index helper: dependencies, both FIB rows and continuation
			 * must already be complete when a key first becomes visible.
			 */
			assert(!(index & 1));
			if (index / 2 >= RTL_MDB_TCAM_SLOTS) {
				assert(get(s->fib[f], 168, 1) == 0);
				assert(get(s->fib[f], 158, 10) == 16);
				assert(get(s->fib[f], 183, 1) == 1);
				assert(get(s->fib[f], 204, 4) == 15);
			} else {
				assert(s->pins);
				assert(get(s->fib[f], 168, 1) == 1);
				assert(get(s->fib[f], 158, 10) > 0 && get(s->fib[f], 158, 10) < 256);
				assert(get(s->key[index + 1], 0, 1) == 0);
				assert(get(s->key[index + 1], 107, 1) == 0);
			}
			for (i = 0; i < 7; i++)
				assert(s->fib[f + 1][i] == 0);
			assert(!(s->key[index + 1][10] & RTL_MDB_KEY_VALID));
			s->valid_writes++;
		}
		for (i = 0; i < count; i++)
			row[i] = s->registers[(data - i * 4) / 4];
	} else {
		for (i = 0; i < count; i++)
			s->registers[(data - i * 4) / 4] = row[i];
		if (s->corrupt_at == s->commands)
			s->registers[data / 4] ^= 1;
	}
	s->registers[access / 4] = 0;
}

static int model_indirect(void *context, unsigned int access, unsigned int command)
{
	struct model *s = context;
	assert(!(s->registers[access / 4] & 0x80000000U));
	assert(s->pending_access != access);
	s->commands++;
	if (s->commands == s->fail_at) {
		if (s->failure_mode == 1) {
			s->pending_access = access;
			s->pending_command = command;
			s->registers[access / 4] = command;
		} else if (s->failure_mode == 2) {
			complete(s, access, command);
		}
		return -ETIMEDOUT;
	}
	complete(s, access, command);
	return 0;
}

static void finish_pending(struct model *s)
{
	if (s->pending_access) {
		complete(s, s->pending_access, s->pending_command);
		s->pending_access = 0;
	}
}

static int pin(void *context, unsigned int group)
{
	struct model *s = context;
	assert(group > 0 && group < 256);
	s->pins++;
	return s->pin_error;
}

static const struct rtl_dq_io io = { &m, model_read, model_write, model_indirect };
static const struct rtl_mdb_dependency dep = { &m, pin };

static void reset(unsigned int existing_cam)
{
	unsigned int row, word;
	memset(&m, 0, sizeof(m));
	memset(&t, 0, sizeof(t));
	for (row = 0; row < 256; row++) {
		for (word = 0; word < 11; word++)
			m.key[row][word] = 0x80c12340U ^ (row * 0x1731) ^ (word * 0x120001);
		m.key[row][10] &= ~RTL_MDB_KEY_VALID;
	}
	for (row = 0; row < 1040; row++)
		for (word = 0; word < 7; word++)
			m.fib[row][word] = 0x4d905300U ^ (row * 0x810b) ^ (word * 0x301015);
	for (row = 0; row < 63; row++) {
		for (word = 0; word < 5; word++)
			m.cam[row][word] = 0x132447a0U ^ (row * 0x1703) ^ (word * 0x1123);
		m.cam[row][0] &= ~(1U << 16);
	}
	if (existing_cam) {
		memset(m.cam[7], 0, sizeof(m.cam[7]));
		memset(m.cam[13], 0, sizeof(m.cam[13]));
		m.cam[7][0] = 0x10800;
		m.cam[13][0] = 0x186dd;
	}
	original = m;
}

static struct rtl_mdb_rule rule(unsigned int v6, unsigned int source)
{
	struct rtl_mdb_rule r = { .destination = {0xef010203, 0, 0, 0},
		.group = 17, .ipv6 = v6, .source_specific = source,
		.ingress = 3, .protocol = 17 };
	if (v6) {
		r.destination[0] = 0xff3e0000;
		r.destination[1] = 0xabc90123;
		r.destination[2] = 0x1bbd7432;
		r.destination[3] = 0x00a401b9;
		if (source) {
			r.source[0] = 0x20010db8;
			r.source[1] = 0xa9823635;
			r.source[2] = 0x874db9a1;
			r.source[3] = 0x0acb7d19;
		}
	} else if (source) {
		r.source[0] = 0xc0000207;
	}
	return r;
}

#ifdef MDB_HAVE_SDK
static void sdk_parity(const struct rtl_mdb_rule *r, unsigned int ether,
	const unsigned int key[22], const unsigned int fib[14])
{
	cl_full_key_t k;
	cls_fib_mod_0_t f;
	unsigned char expected[56] = {0};
	unsigned int p = r->ipv6 ? 128 : 32;
	assert(sizeof(k) == 88);
	memset(&k, 255, sizeof(k));
	k.msk_l4_vld = 0; k.l4_vld = 1;
	k.msk_l3_chksum_err = 0; k.l3_chksum_err = 0;
	k.msk_ip_fragment = 0; k.ip_fragment = 0;
	k.msk_ip_options = 0; k.ip_options = 0;
	k.msk_ip_da_mc = 0; k.ip_da_mc = 1;
	k.msk_ip_da_l = p & 127; k.msk_ip_da_h = p >> 7;
	k.msk_ip_sa_l = r->source_specific ? (p & 127) : 0;
	k.msk_ip_sa_h = r->source_specific ? (p >> 7) : 0;
	k.ip_da_0 = r->destination[r->ipv6 ? 3 : 0];
	k.ip_da_1 = r->destination[r->ipv6 ? 2 : 1];
	k.ip_da_2 = r->destination[r->ipv6 ? 1 : 2];
	k.ip_da_3 = r->destination[r->ipv6 ? 0 : 3];
	k.ip_sa_0 = r->source[r->ipv6 ? 3 : 0];
	k.ip_sa_1 = r->source[r->ipv6 ? 2 : 1];
	k.ip_sa_2 = r->source[r->ipv6 ? 1 : 2];
	k.ip_sa_3 = r->source[r->ipv6 ? 0 : 3];
	k.ip_addr_ctrl = 0;
	k.cls_entry_mode = 0; k.cls_pri = 0; k.cls_rslt_type = 0;
	k.cls_key_type = 6; k.cls_key_valid = 1; k.rsv4 = 0;
	k.msk_ip_protocol = 0; k.ip_protocol = r->protocol;
	k.msk_ip_ver = 0; k.ip_ver = r->ipv6; k.msk_ip_vld = 0; k.ip_vld = 1;
	k.msk_vlan_cnt = 0; k.vlan_cnt = 0;
	k.msk_ethertype_enc = 0; k.ethertype_enc = ether;
	k.msk_mac_da_ip_mc = 0; k.mac_da_ip_mc = 1;
	k.msk_mac_da_mc = 0; k.mac_da_mc = 1;
	k.msk_mac_da_bc = 0; k.mac_da_bc = 0;
	k.msk_o_lspid = 0; k.o_lspid = r->ingress;
	k.msk_lspid = 0; k.lspid = r->ingress;
	k.rsv4_2 = 0; k.rsv4_3 = 0;
	k.cls_entry_mode_1 = 0; k.cls_pri_1 = 0; k.cls_rslt_type_1 = 0;
	k.cls_key_type_1 = 0; k.cls_key_valid_1 = 0; k.rsv4_1 = 0;
	assert(!memcmp(&k, key, sizeof(k)));
	memset(&f, 0, sizeof(f));
	f.dpid_vld = 1; f.dpid_pri = 1; f.permit = 1;
	f.mcgid = r->group; f.mc = 1;
	f.keep_orig_pkt_vld = 1; f.keep_orig_pkt = 1;
	f.t2_ctrl_vld = 1; f.t2_ctrl = 15;
	memcpy(expected, &f, sizeof(f));
	assert(!memcmp(expected, fib, sizeof(expected)));
}
#else
static void sdk_parity(const struct rtl_mdb_rule *r, unsigned int e,
	const unsigned int *key, const unsigned int *fib)
{
	(void)r; (void)e; (void)key; (void)fib;
}
#endif

static void formats(void)
{
	unsigned int key[22], fib[14], v6, source, ingress, ether, proto, group, i;
	for (v6 = 0; v6 < 2; v6++)
	for (source = 0; source < 2; source++)
	for (ingress = 0; ingress < 5; ingress++)
	for (ether = 1; ether < 64; ether += 31)
	for (proto = 0; proto < 2; proto++)
	for (group = 1; group < 256; group += 127) {
		struct rtl_mdb_rule r = rule(v6, source);
		r.ingress = ingress; r.protocol = proto ? 17 : 6; r.group = group;
		assert(!rtl_mdb_rule_build(&r, ether, key, fib));
		assert(get(key, 61, 9) == (v6 ? 128 : 32));
		assert(get(key, 198, 9) == (source ? (v6 ? 128 : 32) : 0));
		for (i = 0; i < 4; i++) {
			assert(get(key, 70 + 32 * i, 32) == r.destination[v6 ? 3 - i : i]);
			assert(get(key, 207 + 32 * i, 32) == r.source[v6 ? 3 - i : i]);
		}
		assert(get(key, 622, 6) == ingress && get(key, 629, 6) == ingress);
		assert(get(key, 446, 3) == 0 && get(key, 459, 1) == 0);
		assert(get(key, 460, 6) == ether && get(key, 353, 8) == r.protocol);
		assert(get(key, 344, 3) == 6 && get(key, 347, 4) == 1);
		assert(get(key, 699, 4) == 0);
		assert(get(fib, 158, 10) == group && get(fib, 168, 1) == 1);
		assert(get(fib, 203, 5) == 31 && get(fib, 182, 2) == 3);
		assert(get(fib, 0, 32) == 0 && get(fib, 208, 1) == 0);
		for (i = 7; i < 14; i++) assert(fib[i] == 0);
		sdk_parity(&r, ether, key, fib);
		assertions++;
	}
	/* Distinct IP groups with the same Ethernet multicast mapping are NOT
	 * aliases in the full key; all 128 IPv6 source/destination bits matter.
	 */
	for (v6 = 0; v6 < 2; v6++) {
		struct rtl_mdb_rule r = rule(v6, 1), b;
		unsigned int k2[22], f2[14];
		assert(!rtl_mdb_rule_build(&r, 8, key, fib));
		b = r; b.destination[0] ^= v6 ? 0x00010000 : 0x00800000;
		assert(!rtl_mdb_rule_build(&b, 8, k2, f2));
		assert(memcmp(key, k2, sizeof(key)));
		b = r; b.source[v6 ? 2 : 0] ^= 1;
		assert(!rtl_mdb_rule_build(&b, 8, k2, f2));
		assert(memcmp(key, k2, sizeof(key)));
	}
	for (i = 0; i < 18; i++) {
		struct rtl_mdb_rule r = rule(i >= 10, 0);
		unsigned int before[22], fbefore[14];
		ether = 1;
		switch (i) {
		case 0: r.vid = 1; break;
		case 1: r.vid = 4095; break;
		case 2: r.protocol = 2; break;
		case 3: r.protocol = 58; break;
		case 4: r.ingress = 7; break;
		case 5: r.group = 256; break;
		case 6: r.group = 0; break;
		case 7: r.destination[0] = 0xe00000fb; break;
		case 8: r.destination[1] = 1; break;
		case 9: r.source[0] = 1; break;
		case 10: r.destination[0] = 0x20010db8; break;
		case 11: r.source_specific = 1; break;
		case 12: r.source_specific = 1; r.source[0] = 0xff010000; break;
		case 13: r.ipv6 = 2; break;
		case 14: ether = 0; break;
		case 15: ether = 64; break;
		case 16: r.source_specific = 2; break;
		case 17: r.destination[0] = 0xff020000; r.destination[1] = 0;
			r.destination[2] = 0; r.destination[3] = 1; break;
		}
		memset(key, 0xa5, sizeof(key)); memcpy(before, key, sizeof(key));
		memset(fib, 0x5a, sizeof(fib)); memcpy(fbefore, fib, sizeof(fib));
		assert(rtl_mdb_rule_build(&r, ether, key, fib) < 0);
		assert(!memcmp(key, before, sizeof(key)) && !memcmp(fib, fbefore, sizeof(fib)));
		assertions++;
	}
}

static void assert_restored(void)
{
	assert(!memcmp(m.key, original.key, sizeof(m.key)));
	assert(!memcmp(m.fib, original.fib, sizeof(m.fib)));
	assert(!memcmp(m.cam, original.cam, sizeof(m.cam)));
}

static void lifecycle(void)
{
	unsigned int i, mode, slot, before, rows;
	struct rtl_mdb_rule r = rule(0, 0);
	for (mode = 0; mode < 2; mode++) {
		reset(mode);
		assert(!rtl_mdb_tcam_init(&io, &t));
		assert(t.initialized && !t.poisoned && !t.exposed);
		assert(t.ether_id[0] == (mode ? 8 : 1));
		assert(t.ether_id[1] == (mode ? 14 : 2));
		assert(!rtl_mdb_tcam_restore(&io, &t));
		assert_restored();
	}
	reset(1);
	assert(!rtl_mdb_tcam_init(&io, &t));
	assert(!rtl_mdb_tcam_install(&io, &t, &r, &dep, &slot));
	assert(slot == 0 && t.active == 1 && t.used == 1 && t.exposed && m.valid_writes == 1);
	before = m.table_writes;
	slot = 999;
	assert(rtl_mdb_tcam_install(&io, &t, &r, &dep, &slot) == -EEXIST);
	assert(slot == 999 && m.table_writes == before);
	r = rule(0, 1);
	assert(rtl_mdb_tcam_install(&io, &t, &r, &dep, &slot) == -EEXIST);
	assert(!rtl_mdb_tcam_withdraw(&io, &t));
	assert(t.used == 1 && t.active == 0 && t.exposed);
	before = m.writes;
	assert(rtl_mdb_tcam_restore(&io, &t) == -EBUSY);
	assert(before == m.writes);
	assert(!rtl_mdb_tcam_install(&io, &t, &r, &dep, &slot));
	assert(slot == 1); /* never overwrite the retired slot0 action */
	for (i = 2; i < RTL_MDB_TCAM_SLOTS; i++) {
		r.source[0]++;
		assert(!rtl_mdb_tcam_install(&io, &t, &r, &dep, &slot));
		assert(slot == i);
	}
	rows = m.table_writes;
	r.source[0]++;
	assert(rtl_mdb_tcam_install(&io, &t, &r, &dep, &slot) == -ENOSPC);
	assert(m.table_writes == rows);
	assert(!rtl_mdb_tcam_withdraw(&io, &t));
	assert(!t.active && t.used == RTL_MDB_TCAM_SLOTS);
	for (i = 0; i < 256; i++) assert(!(m.key[i][10] & RTL_MDB_KEY_VALID));
	assertions += 70;
	/* Foreign valid keys in ANY format or profile forbid takeover. */
	for (i = 0; i < 256; i++) {
		reset(0);
		m.key[i][10] |= 1U << (27 + (i % 4));
		assert(rtl_mdb_tcam_init(&io, &t) == -EBUSY);
		assert(!m.writes && !m.table_writes && !t.prepared);
		assertions++;
	}
	/* Fresh stale/foreign key or FIB after snapshot cannot be overwritten. */
	for (mode = 0; mode < 2; mode++) {
		reset(1);
		assert(!rtl_mdb_tcam_init(&io, &t));
		if (mode) m.fib[4][3] ^= 1; else m.key[1][4] ^= 1;
		before = m.writes;
		assert(rtl_mdb_tcam_install(&io, &t, &r, &dep, &slot) == -EBUSY);
		assert(before == m.writes && t.poisoned && !t.used);
	}
	/* A matching payload with a foreign VALID subkey is not our key. */
	reset(1); assert(!rtl_mdb_tcam_init(&io, &t));
	assert(!rtl_mdb_tcam_install(&io, &t, &r, &dep, &slot));
	m.key[0][10] ^= 3U << 27;
	before = m.writes;
	assert(rtl_mdb_tcam_withdraw(&io, &t) == -EIO);
	assert(before == m.writes && t.poisoned);
}

static void fault_matrix(void)
{
	unsigned int init_commands, install_commands, withdraw_commands, restore_commands;
	unsigned int i, mode, slot, start, before;
	struct rtl_mdb_rule r = rule(1, 1);
	reset(0); assert(!rtl_mdb_tcam_init(&io, &t));
	init_commands = m.commands;
	start = m.commands;
	assert(!rtl_mdb_tcam_install(&io, &t, &r, &dep, &slot));
	install_commands = m.commands - start;
	start = m.commands;
	assert(!rtl_mdb_tcam_withdraw(&io, &t));
	withdraw_commands = m.commands - start;
	/* Fail the readback of the continuation, immediately before VALID.
	 * Both FIB rows and the second key row were already changed, so this
	 * exercises a meaningful full-byte rollback rather than an empty one.
	 */
	reset(0); assert(!rtl_mdb_tcam_init(&io, &t));
	m.fail_at = m.commands + install_commands - 2;
	assert(rtl_mdb_tcam_install(&io, &t, &r, &dep, &slot) < 0);
	assert(t.used == 1 && t.slot[0].dirty && !t.exposed);
	m.fail_at = 0; start = m.commands;
	assert(!rtl_mdb_tcam_restore(&io, &t));
	restore_commands = m.commands - start;
	assert_restored();
	for (mode = 0; mode < 3; mode++) {
		for (i = 1; i <= init_commands; i++) {
			reset(0); m.fail_at = i; m.failure_mode = mode;
			assert(rtl_mdb_tcam_init(&io, &t) < 0);
			assert(!t.initialized && !t.used && !t.exposed);
			m.fail_at = 0;
			finish_pending(&m);
			assert(!rtl_mdb_tcam_restore(&io, &t));
			assert_restored();
			fault_cases++;
		}
		for (i = 1; i <= install_commands; i++) {
			reset(0); assert(!rtl_mdb_tcam_init(&io, &t));
			m.fail_at = m.commands + i; m.failure_mode = mode; slot = 999;
			assert(rtl_mdb_tcam_install(&io, &t, &r, &dep, &slot) < 0);
			assert(slot == 999 && t.poisoned && !t.active);
			m.fail_at = 0;
			/* A quarantined owner must never start another installation. */
			before = m.writes;
			assert(rtl_mdb_tcam_install(&io, &t, &r, &dep, &slot) == -EBUSY);
			assert(m.writes == before);
			if (m.pending_access == 0x3380) {
				before = m.writes;
				assert(rtl_mdb_tcam_withdraw(&io, &t) == -EBUSY || !t.used);
				assert(m.writes == before);
			}
			finish_pending(&m);
			assert(!rtl_mdb_tcam_withdraw(&io, &t));
			if (t.exposed) {
				assert(rtl_mdb_tcam_restore(&io, &t) == -EBUSY);
				assert(!(m.key[0][10] & RTL_MDB_KEY_VALID));
			} else {
				assert(!rtl_mdb_tcam_restore(&io, &t));
				assert_restored();
			}
			fault_cases++;
		}
		for (i = 1; i <= withdraw_commands; i++) {
			unsigned int fib_before[14];
			reset(0); assert(!rtl_mdb_tcam_init(&io, &t));
			assert(!rtl_mdb_tcam_install(&io, &t, &r, &dep, &slot));
			memcpy(fib_before, m.fib[4], sizeof(fib_before));
			m.fail_at = m.commands + i; m.failure_mode = mode;
			assert(rtl_mdb_tcam_withdraw(&io, &t) < 0);
			assert(t.poisoned && t.used == 1 && t.exposed);
			m.fail_at = 0;
			if (m.pending_access) {
				before = m.writes;
				assert(rtl_mdb_tcam_withdraw(&io, &t) == -EBUSY);
				assert(m.writes == before);
			}
			finish_pending(&m);
			assert(!rtl_mdb_tcam_withdraw(&io, &t));
			assert(!t.active && !(m.key[0][10] & RTL_MDB_KEY_VALID));
			assert(!(m.key[1][10] & RTL_MDB_KEY_VALID));
			assert(!memcmp(fib_before, m.fib[4], sizeof(fib_before)));
			assert(rtl_mdb_tcam_restore(&io, &t) == -EBUSY);
			fault_cases++;
		}
		for (i = 1; i <= restore_commands; i++) {
			reset(0); assert(!rtl_mdb_tcam_init(&io, &t));
			m.fail_at = m.commands + install_commands - 2;
			assert(rtl_mdb_tcam_install(&io, &t, &r, &dep, &slot) < 0);
			assert(t.used == 1 && t.slot[0].dirty && !t.exposed);
			m.fail_at = m.commands + i; m.failure_mode = mode;
			assert(rtl_mdb_tcam_restore(&io, &t) < 0);
			assert(t.poisoned && !t.exposed && t.used == 1);
			m.fail_at = 0;
			if (m.pending_access)
				assert(rtl_mdb_tcam_restore(&io, &t) == -EBUSY);
			finish_pending(&m);
			assert(!rtl_mdb_tcam_restore(&io, &t));
			assert_restored();
			fault_cases++;
		}
	}
	/* Failed dependency publication cannot publish a key or touch its FIB. */
	reset(1); assert(!rtl_mdb_tcam_init(&io, &t));
	m.pin_error = -EIO; before = m.writes; slot = 999;
	assert(rtl_mdb_tcam_install(&io, &t, &r, &dep, &slot) == -EIO);
	assert(!m.valid_writes && m.writes == before && t.poisoned && slot == 999);
	assert(!rtl_mdb_tcam_restore(&io, &t)); assert_restored();
	/* Corrupt readback must quarantine, not authorize ingress. */
	for (i = 1; i <= install_commands; i++) {
		reset(1); assert(!rtl_mdb_tcam_init(&io, &t));
		m.corrupt_at = m.commands + i;
		slot = 999;
		if (rtl_mdb_tcam_install(&io, &t, &r, &dep, &slot)) {
			assert(t.poisoned && slot == 999);
			m.corrupt_at = 0;
			assert(!rtl_mdb_tcam_withdraw(&io, &t));
		}
		fault_cases++;
	}
	printf("MDB command matrix: init=%u, install=%u, withdraw=%u, restore=%u, fault cases=%lu\n",
	       init_commands, install_commands, withdraw_commands, restore_commands, fault_cases);
}

static bool guard_matches(const unsigned int key[22], unsigned int mc,
	unsigned int bc, unsigned int ip_mc)
{
	return (get(key, 519, 1) || get(key, 520, 1) == mc) &&
		(get(key, 521, 1) || get(key, 522, 1) == bc) &&
		(get(key, 59, 1) || get(key, 60, 1) == ip_mc);
}

static void guard_formats(void)
{
	unsigned int k[2][22], f[2][14];
	for (unsigned int which = 0; which < 2; which++) {
		assert(!rtl_mdb_guard_build(which, k[which], f[which]));
		assert(get(k[which], 61, 9) == 0 && get(k[which], 198, 9) == 0);
		const unsigned int wildcard[] = {46, 48, 53, 55, 352, 371, 373, 446, 459, 517, 621, 628};
		for (unsigned int i = 0; i < sizeof(wildcard) / sizeof(wildcard[0]); i++)
			assert(get(k[which], wildcard[i], 1) == 1);
#ifdef MDB_HAVE_SDK
		cl_full_key_t expected;
		cls_fib_mod_0_t result;
		unsigned char bytes[56] = {0};
		memset(&expected, 255, sizeof(expected));
		expected.msk_ip_da_l = expected.msk_ip_da_h = 0;
		expected.msk_ip_sa_l = expected.msk_ip_sa_h = 0;
		expected.ip_da_0 = expected.ip_da_1 = expected.ip_da_2 = expected.ip_da_3 = 0;
		expected.ip_sa_0 = expected.ip_sa_1 = expected.ip_sa_2 = expected.ip_sa_3 = 0;
		if (!which) {
			expected.msk_ip_da_mc = 0; expected.ip_da_mc = 0;
			expected.msk_mac_da_mc = 0; expected.mac_da_mc = 1;
		}
		expected.msk_mac_da_bc = 0; expected.mac_da_bc = which;
		expected.ip_addr_ctrl = 0; expected.cls_entry_mode = 0; expected.cls_pri = 0;
		expected.cls_rslt_type = 0; expected.cls_key_type = 6; expected.cls_key_valid = 1;
		expected.rsv4 = expected.rsv4_2 = expected.rsv4_3 = 0;
		expected.cls_entry_mode_1 = expected.cls_pri_1 = expected.cls_rslt_type_1 = 0;
		expected.cls_key_type_1 = expected.cls_key_valid_1 = expected.rsv4_1 = 0;
		assert(!memcmp(&expected, k[which], sizeof(expected)));
		memset(&result, 0, sizeof(result));
		result.dpid_vld = result.dpid_pri = result.permit = 1;
		result.mcgid = 16; result.keep_orig_pkt_vld = result.keep_orig_pkt = 1;
		result.t2_ctrl_vld = 1; result.t2_ctrl = 15;
		memcpy(bytes, &result, sizeof(result));
		assert(!memcmp(bytes, f[which], sizeof(bytes)));
#endif
	}
	for (unsigned int mc = 0; mc < 2; mc++)
	for (unsigned int bc = 0; bc < 2; bc++)
	for (unsigned int ipmc = 0; ipmc < 2; ipmc++) {
		bool a = guard_matches(k[0], mc, bc, ipmc), b = guard_matches(k[1], mc, bc, ipmc);
		bool mdb = mc && !bc && ipmc;
		assert(a == (mc && !bc && !ipmc));
		assert(b == !!bc && !(a && b) && !(mdb && (a || b)));
		assertions++;
	}
	assert(rtl_mdb_guard_build(2, k[0], f[0]) == -EINVAL);
}

static void guard_lifecycle(void)
{
	unsigned int start, commands, before;
	reset(1); assert(!rtl_mdb_tcam_init(&io, &t));
	start = m.commands;
	assert(!rtl_mdb_profile_prepare(&io, &t));
	commands = m.commands - start;
	assert(t.guards_ready && t.guard_exposed && !t.exposed && !t.used && !t.active);
	assert(!rtl_mdb_profile_check(&io, &t));
	assert(!rtl_mdb_tcam_withdraw(&io, &t));
	assert(!rtl_mdb_profile_check(&io, &t));
	before = m.writes;
	assert(rtl_mdb_tcam_restore(&io, &t) == -EBUSY && before == m.writes);
	for (unsigned int i = 0; i < 256; i++) {
		if (i >= 124 && i <= 127) continue;
		unsigned int saved = m.key[i][10]; m.key[i][10] |= RTL_MDB_KEY_VALID;
		assert(rtl_mdb_profile_check(&io, &t) == -EBUSY);
		m.key[i][10] = saved; assertions++;
	}
	for (unsigned int which = 0; which < 2; which++) {
		for (unsigned int word = 0; word < 22; word++) {
			unsigned int row = 124 + which * 2 + word / 11;
			m.key[row][word % 11] ^= 1;
			assert(rtl_mdb_profile_check(&io, &t) == -EIO);
			m.key[row][word % 11] ^= 1; assertions++;
		}
		for (unsigned int word = 0; word < 14; word++) {
			unsigned int row = ((62 + which) << 3 | 4) + word / 7;
			m.fib[row][word % 7] ^= 1;
			assert(rtl_mdb_profile_check(&io, &t) == -EIO);
			m.fib[row][word % 7] ^= 1; assertions++;
		}
	}
	for (unsigned int mode = 0; mode < 3; mode++) {
		for (unsigned int fault = 1; fault <= commands; fault++) {
			reset(1); assert(!rtl_mdb_tcam_init(&io, &t));
			m.fail_at = m.commands + fault; m.failure_mode = mode;
			assert(rtl_mdb_profile_prepare(&io, &t) < 0);
			finish_pending(&m);
			assert(!t.used && !t.active && !t.exposed && t.poisoned);
			if (t.guard_exposed) {
				assert(rtl_mdb_tcam_restore(&io, &t) == -EBUSY);
				assert(rtl_mdb_profile_prepare(&io, &t) == -EBUSY);
			} else {
				assert(!rtl_mdb_tcam_restore(&io, &t)); assert_restored();
			}
			fault_cases++;
		}
	}
}

int main(void)
{
	formats();
	lifecycle();
	fault_matrix();
	guard_formats();
	guard_lifecycle();
	printf("Exact MDB production key/action/lifecycle: %lu cases, %lu total fault cases PASS", assertions, fault_cases);
#ifdef MDB_HAVE_SDK
	printf(" (pinned SDK FULL_KEY + mode0 byte parity)");
#endif
	puts("");
	return 0;
}
