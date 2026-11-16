/* SPDX-License-Identifier: GPL-2.0-only */
/* Only kernel objects, bounded snapshot input and MMIO are emulated. */
#include <arpa/inet.h>
#include <assert.h>
#define __maybe_unused __attribute__((unused))
#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

typedef uint8_t u8;
typedef uint16_t u16, __be16;
typedef uint32_t u32, __be32;
typedef uint64_t u64;
#define CONFIG_BRIDGE 1
#define CONFIG_NET_SWITCHDEV 1
#define CONFIG_BRIDGE_IGMP_SNOOPING 1
#define CONFIG_RTL9617C_SWITCH_GUARD 1
#define IS_REACHABLE(x) (x)
#define IS_ENABLED(x) (x)
#define BIT(x) (1UL << (x))
#define GENMASK(h, l) ((~0UL >> (sizeof(unsigned long) * 8 - 1 - (h))) & (~0UL << (l)))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define READ_ONCE(x) (x)
#define smp_load_acquire(x) (*(x))
#define lockdep_assert_held(x) ((void)(x))
#define ASSERT_RTNL() ((void)0)
#define GFP_KERNEL 0
#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define IFF_PROMISC 0x100
#define BR_STATE_FORWARDING 3
#define MDB_RTR_TYPE_TEMP_QUERY 1
#define MDB_RTR_TYPE_PERM 2
#define MDB_RTR_TYPE_TEMP 3
#ifndef FE_MDB_FOCUSED
#define FE_MDB_FOCUSED 0
#endif
#define BR_BPDU_GUARD BIT(1)
#define BR_ROOT_BLOCK BIT(2)
#define BR_MULTICAST_FAST_LEAVE BIT(3)
#define BR_ADMIN_COST BIT(4)
#define BR_LEARNING BIT(5)
#define BR_FLOOD BIT(6)
#define BR_PROMISC BIT(7)
#define BR_LEARNING_SYNC BIT(9)
#define BR_MCAST_FLOOD BIT(11)
#define BR_MULTICAST_TO_UNICAST BIT(12)
#define BR_BCAST_FLOOD BIT(14)
#define BR_ISOLATED BIT(16)
#define BR_BPDU_FILTER BIT(24)
#define FE_LAN_PORTS 5
#define FE_LAN_RX_CTRL(port) (0xa5f8 + 0x90 * (port))
#define FE_SW_RX_DEST_MASK (0x3fU << 16)
#define FE_SW_RX_BYPASS BIT(28)
#define FE_SW_RX_CPU (FE_SW_RX_BYPASS | (16U << 16))
#define be32_to_cpu(x) ntohl(x)

static unsigned allocations, frees, allocation_failure;
static void *kvzalloc(size_t bytes, int flags)
{
	(void)flags;
	allocations++;
	return allocations == allocation_failure ? NULL : calloc(1, bytes);
}
static void kvfree(void *ptr) { if (ptr) frees++; free(ptr); }
static int scnprintf(char *buffer, size_t bytes, const char *format, ...)
{
	va_list args;
	int length;
	va_start(args, format);
	length = vsnprintf(buffer, bytes, format, args);
	va_end(args);
	return !bytes ? 0 : (size_t)length < bytes ? length : (int)bytes - 1;
}

struct net { unsigned id; };
struct list_head { unsigned unused; };
struct net_device {
	struct net *net;
	struct net_bridge *br;
	struct net_device *master, *lower[6];
	unsigned long flags, port_flags;
	unsigned state, lower_count;
	int ifindex;
	bool running, carrier, bridge, eligible, vlan;
};
#define netdev_for_each_lower_dev(dev, lowerdev, iter) \
	for ((iter) = (void *)(uintptr_t)0; (uintptr_t)(iter) < (dev)->lower_count && \
	     (((lowerdev) = (dev)->lower[(uintptr_t)(iter)]), true); \
	     (iter) = (void *)((uintptr_t)(iter) + 1))
static struct net *dev_net(const struct net_device *dev) { return dev->net; }
static bool netif_running(const struct net_device *dev) { return dev->running; }
static bool netif_carrier_ok(const struct net_device *dev) { return dev->carrier; }
static bool netif_is_bridge_master(const struct net_device *dev) { return dev->bridge; }
static struct net_device *netdev_master_upper_dev_get(const struct net_device *dev) { return dev->master; }
static bool br_rtl9617c_l2_eligible(const struct net_device *dev) { return dev->eligible; }
static bool br_rtl9617c_l2_port_eligible(const struct net_device *dev) { return dev->eligible; }
static bool br_vlan_enabled(const struct net_device *dev) { return dev->vlan; }
static bool br_port_flag_is_set(const struct net_device *dev, unsigned long flag) { return !!(dev->port_flags & flag); }
static unsigned br_port_get_stp_state(const struct net_device *dev) { return dev->state; }

struct br_ip {
	union { __be32 ip4;
#if CONFIG_IPV6
		struct in6_addr ip6;
#endif
	} src;
	union { __be32 ip4;
#if CONFIG_IPV6
		struct in6_addr ip6;
#endif
		unsigned char mac_addr[ETH_ALEN];
	} dst;
	__be16 proto;
	u16 vid;
};
struct rtl9617c_switch_guard {
	struct net *net;
	u64 identity, generation;
	bool registered, armed, blocked;
};
static bool rtl9617c_switch_guard_blocked(struct rtl9617c_switch_guard *g) { return g->blocked; }
static u64 rtl9617c_switch_guard_generation(struct rtl9617c_switch_guard *g) { return g->generation; }

#include <linux/rtl9617c-mdb.h>
#include "rtl9617c-mdb-offload.h"
#include "rtl9617c-mcast-cold.h"

struct rtl_fe_mdb;
struct rtl_fe_port { struct net_device *netdev; unsigned source, destination; bool retired; };
struct rtl_fe_switch_hw { bool prepared; unsigned ports; };
struct rtl_fe_bridge {
	struct rtl9617c_switch_guard guard;
	struct rtl_fe_switch_hw hw;
	struct net_device *ports[5], *master;
	bool stopping, vlan_domain, route_policy_allowed, native_route_policy_allowed;
};
struct rtl_fe_mcast { struct rtl_mcast_state state; };
struct rtl_fe {
	struct rtl_fe_bridge *bridge;
	struct rtl_fe_mcast *mcast;
	struct rtl_fe_mdb *mdb;
	struct rtl_l2_owner *l2_owner;
	struct rtl_fe_port ports[5];
	int lock;
	bool native_mdb_profile, enabled, prepared, base_ready, base_failed;
	bool engine_ready, shutting_down, route_admitted, route_gate_ready;
	bool route_gate_verified, dma_exposed;
	unsigned pending_withdrawals;
};

struct model {
	unsigned key[256][11], fib[2048][7], cam[63][5];
	unsigned mc_fib[64][3], mc_vector[256][2];
	unsigned registers[0x10000 / 4];
	unsigned commands, writes, reads, table_writes, valid_writes;
	unsigned fail_at, failure_mode, corrupt_at, change_epoch_at_valid;
	unsigned pending_access, pending_command, exhaust_after_valid;
};
static struct model m;
static struct rtl_fe fe;
static struct rtl_fe_bridge bridge;
static struct rtl_fe_mcast mcast;
static struct rtl_l2_owner owner;
static struct rtl_l2_snapshot owner_rows[RTL_L2_OWNER_ROWS];
static unsigned short owner_index[16384];
static struct net network, foreign_network;
static struct net_device master, ports[5], foreign;
static unsigned long flags[5];
static struct br_rtl9617c_mdb_snapshot snapshot;
static struct br_rtl9617c_mdb_record records[300];
static unsigned record_count, snapshot_calls;
static int snapshot_error;
static unsigned long cases, faults;

static unsigned get(const unsigned *words, unsigned bit, unsigned width)
{
	uint64_t value = words[bit / 32];
	if ((bit % 32) + width > 32)
		value |= (uint64_t)words[bit / 32 + 1] << 32;
	return (value >> (bit % 32)) & (width == 32 ? UINT32_MAX : ((1ULL << width) - 1));
}

static unsigned window_for_data(unsigned reg)
{
	if (reg >= 0x3384 && reg <= 0x33ac) return 0x3380;
	if (reg >= 0x33b4 && reg <= 0x33cc) return 0x33b0;
	if (reg >= 0x3204 && reg <= 0x3214) return 0x3200;
	if (reg >= 0x1638 && reg <= 0x1640) return 0x1634;
	if (reg >= 0xaa68 && reg <= 0xaa6c) return 0xaa64;
	return 0;
}
static unsigned model_read(void *context, unsigned reg)
{
	struct model *s = context;
	unsigned access = window_for_data(reg);
	assert(reg < sizeof(s->registers));
	if (access) assert(!(s->registers[access / 4] & 0x80000000U));
	s->reads++;
	return s->registers[reg / 4];
}
static void model_write(void *context, unsigned reg, unsigned value)
{
	struct model *s = context;
	unsigned access = window_for_data(reg);
	assert(access && !(s->registers[access / 4] & 0x80000000U));
	assert(s->pending_access != access);
	s->writes++;
	s->registers[reg / 4] = value;
}
static void complete(struct model *s, unsigned access, unsigned command)
{
	unsigned *row, count, data, index, i;
	if (access == 0x3380) {
		index = command & 255;
		row = s->key[index]; count = 11; data = 0x33ac;
	} else if (access == 0x33b0) {
		index = command & 2047;
		row = s->fib[index]; count = 7; data = 0x33cc;
	} else if (access == 0x3200) {
		assert(((command >> 16) & 255) == 2);
		index = command & 63; assert(index < 63);
		row = s->cam[index]; count = 5; data = 0x3214;
	} else if (access == 0x1634) {
		index = command & 63;
		row = s->mc_fib[index]; count = 3; data = 0x1640;
	} else {
		assert(access == 0xaa64);
		index = command & 255;
		row = s->mc_vector[index]; count = 2; data = 0xaa6c;
	}
	if (command & 0x40000000U) {
		s->table_writes++;
		if (access == 0x3380 && (s->registers[0x3384 / 4] & RTL_MDB_KEY_VALID)) {
			unsigned f = ((index >> 1) << 3) | 4;
			unsigned group = get(s->fib[f], 158, 10);
			struct rtl_mcast_vector *v;
			struct rtl_mcast_token *token;
			if (index / 2 >= RTL_MDB_TCAM_SLOTS) {
				assert(!(index & 1) && group == 16 && !get(s->fib[f], 168, 1));
				assert(get(s->fib[f], 183, 1) && get(s->fib[f], 204, 4) == 15);
				for (i = 0; i < 7; i++) assert(!s->fib[f + 1][i]);
				assert(!(s->key[index + 1][10] & RTL_MDB_KEY_VALID));
				goto copy_row;
			}
			assert(!(index & 1) && group && group < 256);
			v = &mcast.state.vector[group];
			assert(v->active && v->published && owner.active[RTL_L2_SHARED_MC_VECTOR][group]);
			token = &mcast.state.token[v->token];
			assert(token->allocated && token->published);
			assert(token->owner == bridge.guard.identity && token->generation == bridge.guard.generation);
			assert(!(v->egress & BIT(token->ingress)));
			assert(get(s->fib[f], 168, 1) == 1);
			assert(get(s->fib[f], 182, 1) && get(s->fib[f], 183, 1));
			for (i = 0; i < 7; i++) assert(s->fib[f + 1][i] == 0);
			assert(get(s->key[index + 1], 0, 1) == 0);
			assert(get(s->key[index + 1], 107, 1) == 0);
			assert(!(s->key[index + 1][10] & RTL_MDB_KEY_VALID));
			s->valid_writes++;
		}
copy_row:
		for (i = 0; i < count; i++) row[i] = s->registers[(data - i * 4) / 4];
	} else {
		for (i = 0; i < count; i++) s->registers[(data - i * 4) / 4] = row[i];
		if (s->corrupt_at == s->commands) s->registers[data / 4] ^= 1;
	}
	s->registers[access / 4] = 0;
	if (s->change_epoch_at_valid && s->valid_writes == s->change_epoch_at_valid) {
		bridge.guard.generation++;
		s->change_epoch_at_valid = 0;
	}
	if (s->exhaust_after_valid && s->valid_writes == s->exhaust_after_valid) {
		for (i = 0; i < 8; i++) owner.ledger.bank[RTL_L2_SHARED_MC_VECTOR].foreign[i] = ~0U;
		s->exhaust_after_valid = 0;
	}
}
static int model_indirect(void *context, unsigned access, unsigned command)
{
	struct model *s = context;
	assert(!(s->registers[access / 4] & 0x80000000U));
	assert(s->pending_access != access);
	s->commands++;
	if (s->commands == s->fail_at) {
		if (s->failure_mode == 1) {
			s->pending_access = access; s->pending_command = command;
			s->registers[access / 4] = command;
		} else if (s->failure_mode == 2) complete(s, access, command);
		return -ETIMEDOUT;
	}
	complete(s, access, command);
	return 0;
}
static void finish_pending(void)
{
	if (m.pending_access) {
		complete(&m, m.pending_access, m.pending_command);
		m.pending_access = 0;
	}
}
static struct rtl_dq_io fe_io(struct rtl_fe *unused)
{
	(void)unused;
	return (struct rtl_dq_io){ &m, model_read, model_write, model_indirect };
}
static unsigned fe_read(struct rtl_fe *unused, unsigned reg) { (void)unused; return model_read(&m, reg); }
static struct rtl_fe_port *fe_port(struct rtl_fe *context, struct net_device *dev)
{
	for (unsigned i = 0; i < 5; i++)
		if (!context->ports[i].retired && context->ports[i].netdev == dev) return &context->ports[i];
	return NULL;
}

#include "fe_mdb_host_helpers.h"
#include "rtl9617c-fe-mdb.h"

#ifdef FE_MDB_REAL_SNAPSHOT
#include "fe_mdb_real_snapshot.h"
#endif

int br_rtl9617c_mdb_snapshot(const struct net_device *dev, u16 vid,
	struct rtl9617c_switch_guard *guard, unsigned budget,
	struct br_rtl9617c_mdb_snapshot *out, br_rtl9617c_mdb_emit_t emit, void *priv)
{
	assert(dev == &master && !vid && guard == &bridge.guard && budget == FE_MDB_WORK_BUDGET);
	snapshot_calls++;
#ifdef FE_MDB_REAL_SNAPSHOT
	if (real_snapshot_enabled)
		return fe_test_real_snapshot(dev, vid, guard, budget, out, emit, priv);
#endif
	*out = snapshot;
	for (unsigned i = 0; i < record_count; i++) {
		int ret = emit(priv, &records[i]);
		if (ret) { memset(out, 0, sizeof(*out)); return ret; }
	}
	if (snapshot_error) memset(out, 0, sizeof(*out));
	return snapshot_error;
}

static void reset_without_profile(void)
{
#ifdef FE_MDB_REAL_SNAPSHOT
	real_snapshot_enabled = false;
#endif
	/* Test process reset models a fresh device. Production fe_mdb_free is
	 * separately tested to retain once-exposed state; never use this as a
	 * runtime retirement recipe. */
	free(fe.mdb);
	memset(&fe, 0, sizeof(fe)); memset(&m, 0, sizeof(m));
	memset(&bridge, 0, sizeof(bridge)); memset(&mcast, 0, sizeof(mcast));
	memset(&owner, 0, sizeof(owner)); memset(owner_rows, 0, sizeof(owner_rows));
	memset(owner_index, 0, sizeof(owner_index));
	memset(&master, 0, sizeof(master)); memset(ports, 0, sizeof(ports));
	memset(&foreign, 0, sizeof(foreign)); memset(&snapshot, 0, sizeof(snapshot));
	memset(records, 0, sizeof(records)); record_count = snapshot_calls = 0;
	snapshot_error = 0; allocations = frees = allocation_failure = 0;
	master.net = &network; master.running = master.bridge = master.eligible = true;
	master.ifindex = 20; master.lower_count = 5;
	bridge.master = &master; bridge.route_policy_allowed = true;
	bridge.native_route_policy_allowed = true;
	bridge.hw.prepared = true; bridge.hw.ports = 31;
	bridge.guard = (struct rtl9617c_switch_guard){ .net = &network, .identity = 7,
		.generation = 19, .registered = true };
	fe.bridge = &bridge; fe.mcast = &mcast; fe.l2_owner = &owner;
	fe.native_mdb_profile = fe.enabled = fe.prepared = fe.base_ready = fe.engine_ready = true;
	fe.route_gate_ready = fe.route_gate_verified = true;
	for (unsigned i = 0; i < 5; i++) {
		ports[i] = (struct net_device){ .net = &network, .master = &master,
			.port_flags = BR_LEARNING | BR_FLOOD | BR_MCAST_FLOOD | BR_BCAST_FLOOD,
			.state = BR_STATE_FORWARDING, .ifindex = 2 + (int)i,
			.running = true, .carrier = true, .eligible = true };
		flags[i] = ports[i].port_flags; bridge.ports[i] = &ports[i];
		master.lower[i] = &ports[i];
		fe.ports[i] = (struct rtl_fe_port){ .netdev = &ports[i], .source = i, .destination = i };
		m.registers[FE_LAN_RX_CTRL(i) / 4] = FE_SW_RX_CPU;
	}
	m.registers[0x3400 / 4] = BIT(2) | BIT(3) | BIT(19);
	m.registers[0x3404 / 4] = 7 | (25 << 8) | (1 << 14) | (24 << 16) | (2 << 22) | (3 << 24);
	for (unsigned i = 0; i < 2; i++) {
		unsigned lpb[3]; rtl_fe_ingress_lpb(lpb, i ? 7 : 0, 16); rtl_fe_bits_set(lpb, 42, 4, 1);
		for (unsigned w = 0; w < 3; w++) m.registers[(0x3414 + i * 12 + w * 4) / 4] = lpb[w];
		for (unsigned t = 0; t < 4; t++) rtl_fe_classifier_default(m.fib[fe_classifier_default_index(i, t, 0)], i, t, 1);
	}
	const unsigned exceptions[] = {0x3248, 0x324c, 0x3314, 0x3318};
	for (unsigned i = 0; i < ARRAY_SIZE(exceptions); i++) m.registers[exceptions[i] / 4] = 0xfffffa10;
	m.registers[RTL_MCAST_NI_SOURCE / 4] = RTL_MCAST_SOURCE | BIT(7);
	m.registers[RTL_L2_VLAN_MODE_CONTROL / 4] = 1;
	struct rtl_dq_io io = fe_io(&fe);
	unsigned foreign_vectors[8] = {0};
	assert(!rtl_l2_owner_init(&owner, owner_rows, owner_index, rtl_l2_journal_index_count(), 5));
	assert(!rtl_l2_owner_mc_cold_scan(&owner, &io, foreign_vectors));
	rtl_l2_owner_seal(&owner);
	/* Explicit synthetic contract: host row emptiness does NOT establish
	 * real inherited producer/drain ownership, which currently blocks HW. */
	mcast.state.contract_ready = 1;
	snapshot.master = &master; snapshot.generation = bridge.guard.generation;
	snapshot.snooping = snapshot.context_enabled = snapshot.running = true;
	snapshot.ip4 = (struct br_rtl9617c_mdb_family){ .supported = true, .version = 3,
		.own_querier = true, .querier_present = true };
	snapshot.ip6 = (struct br_rtl9617c_mdb_family){ .supported = true, .version = 2,
		.own_querier = true, .querier_present = true };
	m.commands = m.reads = m.writes = m.table_writes = 0;
}

static void reset(void)
{
	reset_without_profile();
	/* Execute the real FE-lifetime guard prepare first, before the wrapper
	 * tests see an admitted native_mdb_profile. This is NOT a test-only
	 * assertion or hand-built ready latch. */
	assert(!fe_mdb_profile_prepare(&fe));
	assert(!fe_mdb_profile_check(&fe));
	m.commands = m.reads = m.writes = m.table_writes = 0;
	allocations = frees = 0;
}

static struct br_ip address(unsigned ipv6, unsigned group, unsigned source)
{
	struct br_ip key = { .proto = htons(ipv6 ? ETH_P_IPV6 : ETH_P_IP) };
	if (ipv6) {
#if CONFIG_IPV6
		key.dst.ip6.s6_addr32[0] = htonl(0xff3e1234);
		key.dst.ip6.s6_addr32[1] = htonl(0x89abcdef);
		key.dst.ip6.s6_addr32[2] = htonl(0x76543210);
		key.dst.ip6.s6_addr32[3] = htonl(group);
		if (source) {
			key.src.ip6.s6_addr32[0] = htonl(0x20010db8);
			key.src.ip6.s6_addr32[1] = htonl(0x0198abcd);
			key.src.ip6.s6_addr32[2] = htonl(0xef762390);
			key.src.ip6.s6_addr32[3] = htonl(source);
		}
#else
		(void)group; (void)source;
#endif
	} else {
		key.dst.ip4 = htonl(0xef010000 | group);
		key.src.ip4 = source ? htonl(0xc0000200 | source) : 0;
	}
	return key;
}
static unsigned entry(unsigned ipv6, unsigned group, unsigned source, unsigned egress)
{
	unsigned id = ++record_count;
	records[id - 1] = (struct br_rtl9617c_mdb_record){ .id = id, .entry_id = id,
		.type = BR_RTL9617C_MDB_ENTRY, .key = address(ipv6, group, source),
		.entry.kind = source ? BR_RTL9617C_MDB_SOURCE_G : BR_RTL9617C_MDB_STAR_G };
	for (unsigned p = 0; p < 5; p++) {
		if (!(egress & BIT(p))) continue;
		unsigned next = ++record_count;
		records[next - 1] = (struct br_rtl9617c_mdb_record){ .id = next, .entry_id = id, .port_id = next,
			.type = BR_RTL9617C_MDB_PORT, .key = records[id - 1].key, .dev = &ports[p],
			.port = { .flags = flags[p], .state = BR_STATE_FORWARDING, .permanent = true, .forward = true } };
	}
	snapshot.record_count = record_count;
	return id;
}
static void router(unsigned ipv6, unsigned port)
{
	unsigned id = ++record_count;
	records[id - 1] = (struct br_rtl9617c_mdb_record){ .id = id,
		.type = BR_RTL9617C_MDB_ROUTER, .dev = &ports[port],
		.key = { .proto = htons(ipv6 ? ETH_P_IPV6 : ETH_P_IP) },
		.router = { .proto = htons(ipv6 ? ETH_P_IPV6 : ETH_P_IP), .type = MDB_RTR_TYPE_PERM } };
	snapshot.record_count = record_count;
}
static void source_record(unsigned entry_id, unsigned port_id)
{
	unsigned id = ++record_count;
	records[id - 1] = (struct br_rtl9617c_mdb_record){ .id = id,
		.type = BR_RTL9617C_MDB_SOURCE, .entry_id = entry_id, .port_id = port_id,
		.key = records[entry_id - 1].key, .dev = records[port_id - 1].dev,
		.source = { .user_added = true, .installed = true } };
	snapshot.record_count = record_count;
}
static int prepare(unsigned *steer)
{
	return fe_mdb_prepare(&fe, &bridge.guard, 19, &master, bridge.ports, flags, 31, steer);
}
static void no_keys(void)
{
	for (unsigned i = 0; i < 256; i++) {
		if (i >= 124 && i < 128) continue;
		assert(!(m.key[i][10] & RTL_MDB_KEY_VALID));
	}
}
static void reject(int expected, bool no_commands)
{
	unsigned steer = 0xdead;
	assert(prepare(&steer) == expected && steer == 0);
	assert(!m.table_writes && !m.writes);
	if (no_commands) assert(!m.commands);
	no_keys(); cases++;
}

static void cpu_only(unsigned expected)
{
	unsigned steer = 0xdead;

	assert(!prepare(&steer) && !steer);
	assert(!m.commands && !m.writes && !m.table_writes);
	assert(fe.mdb->cpu_entries == expected && fe.mdb->reason == FE_MDB_CPU_ONLY);
	assert(!fe.mdb->tcam.used && !fe.mdb->tcam.exposed);
	no_keys(); cases++;
}

static void good_matrix(void)
{
	for (unsigned ipv6 = 0; ipv6 <= CONFIG_IPV6; ipv6++) {
		for (unsigned ssm = 0; ssm < 2; ssm++) {
			for (unsigned mask = 1; mask < 32; mask++) {
				reset(); entry(ipv6, 7, ssm ? 9 : 0, mask);
				unsigned steer = 0, expected = 0;
				assert(!prepare(&steer));
				for (unsigned p = 0; p < 5; p++) if (mask & ~BIT(p)) expected |= BIT(p);
				assert(steer == expected && fe.mdb->steer_ports == expected);
				assert(fe.mdb->tcam.active == (unsigned)__builtin_popcount(expected) * 2);
				for (unsigned n = 0; n < fe.mdb->tcam.used; n++) {
					const struct rtl_mdb_rule *rule = &fe.mdb->tcam.slot[n].rule;
					struct rtl_mcast_vector *v = &mcast.state.vector[rule->group];
					struct rtl_mcast_token *t = &mcast.state.token[v->token];
					assert(rule->ipv6 == ipv6 && rule->source_specific == ssm);
					assert(v->egress == (mask & ~BIT(rule->ingress)));
					assert(t->ingress == rule->ingress && t->ingress_ifindex == ports[rule->ingress].ifindex);
					assert(t->master_ifindex == master.ifindex && t->generation == 19);
					assert(rule->protocol == (n & 1 ? IPPROTO_UDP : IPPROTO_TCP));
				}
				assert(!mcast.state.rx_active && !bridge.guard.armed);
				assert(!fe_mdb_withdraw(&fe)); no_keys();
				assert(fe_mdb_retained(&fe) && fe.mdb->tcam.exposed && !fe.mdb->tcam.active);
				struct rtl_fe_mdb *saved = fe.mdb;
				fe_mdb_free(&fe); assert(fe.mdb == saved);
				cases++;
			}
		}
	}
	reset(); entry(0, 17, 0, BIT(1)); records[1].port.forward = false; records[1].port.blocked = true;
	router(0, 2); router(1, 4);
	unsigned steer;
	assert(!prepare(&steer) && steer == (31U & ~BIT(2)));
	for (unsigned n = 0; n < fe.mdb->tcam.used; n++)
		assert(mcast.state.vector[fe.mdb->tcam.slot[n].rule.group].egress == BIT(2));
	cases++;
	reset(); entry(0, 17, 0, 0); assert(!prepare(&steer) && !steer && !m.commands && !m.writes);
	fe_mdb_free(&fe); assert(fe.mdb && fe.mdb->tcam.guard_exposed && !fe.mdb->tcam.exposed); cases++;
	reset(); entry(0, 17, 0, BIT(1)); snapshot.has_deadline = true;
	records[0].entry.host_joined = true; records[0].entry.timer.pending = true;
	assert(!prepare(&steer)); cases++; /* CPU retains local membership/timer decisions. */
	reset(); entry(0, 17, 0, BIT(1)); source_record(1, 2);
	assert(!prepare(&steer)); cases++;
}

static void cold_and_topology(void)
{
	reset(); entry(0, 1, 0, 2); mcast.state.contract_ready = 0; reject(-EOPNOTSUPP, true); assert(!m.reads);
	reset(); entry(0, 1, 0, 2); owner.ready_mask = 0; reject(-EOPNOTSUPP, true); assert(!m.reads);
	reset(); entry(0, 1, 0, 2); owner.ledger.quarantined = 1; reject(-EOPNOTSUPP, true);
	reset(); entry(0, 1, 0, 2); fe.native_mdb_profile = false; reject(-EOPNOTSUPP, true);
	reset(); entry(0, 1, 0, 2); bridge.native_route_policy_allowed = false; reject(-EOPNOTSUPP, true);
	reset(); entry(0, 1, 0, 2); bridge.vlan_domain = true; reject(-EOPNOTSUPP, true);
	reset(); entry(0, 1, 0, 2); master.vlan = true; reject(-EOPNOTSUPP, true);
	reset(); entry(0, 1, 0, 2); master.flags |= IFF_PROMISC; reject(-EOPNOTSUPP, true);
	reset(); entry(0, 1, 0, 2); ports[3].net = &foreign_network; reject(-EOPNOTSUPP, true);
	reset(); entry(0, 1, 0, 2); master.lower[5] = &foreign; master.lower_count = 6; reject(-EOPNOTSUPP, true);
	reset(); entry(0, 1, 0, 2); fe.ports[2].destination = 25; reject(-EOPNOTSUPP, true);
	reset(); entry(0, 1, 0, 2); ports[4].state = 0; reject(-EOPNOTSUPP, true);
	reset(); entry(0, 1, 0, 2); ports[1].port_flags |= BR_ISOLATED; flags[1] |= BR_ISOLATED; reject(-EOPNOTSUPP, true);
	reset(); entry(0, 1, 0, 2); flags[2] ^= BR_FLOOD; reject(-EAGAIN, true);
	reset(); entry(0, 1, 0, 2); bridge.guard.generation++; reject(-EAGAIN, true);
	reset(); entry(0, 1, 0, 2); bridge.guard.armed = true; reject(-EAGAIN, true);
	reset(); entry(0, 1, 0, 2); bridge.guard.blocked = true; reject(-EAGAIN, true);
	reset(); entry(0, 1, 0, 2); fe.route_admitted = true; reject(-EBUSY, true);
	reset(); entry(0, 1, 0, 2); mcast.state.rx_active = true; reject(-EBUSY, true);
	reset(); entry(0, 1, 0, 2); m.registers[FE_LAN_RX_CTRL(0) / 4] &= ~FE_SW_RX_BYPASS; reject(-EBUSY, true);
	reset(); entry(0, 1, 0, 2); m.registers[0x3418 / 4] &= ~(15U << 10); reject(-EBUSY, true);
}

static void policy_rejections(void)
{
	reset(); entry(0, 1, 0, 2); snapshot.ip4.own_querier = false; cpu_only(1);
	reset(); entry(0, 1, 0, 2); snapshot.ip4.querier_time_dependent = true; cpu_only(1);
	reset(); entry(0, 1, 0, 2); snapshot.ip4.query_delay.pending = true; cpu_only(1);
	reset(); entry(0, 1, 0, 2); snapshot.ip4.querier_present = false; cpu_only(1);
	reset(); entry(0, 1, 0, 2); snapshot.snooping = false; reject(-EOPNOTSUPP, true);
	reset(); entry(0, 1, 0, 2); snapshot.context_enabled = false; reject(-EOPNOTSUPP, true);
	reset(); entry(0, 1, 9, 2); snapshot.ip4.version = 2; cpu_only(1);
	reset(); entry(0, 1, 0, 2); records[1].port.mcast_to_unicast = true; cpu_only(1);
	reset(); entry(0, 1, 0, 2); router(0, 3); records[2].key.vid = 1; reject(-EINVAL, true);
	reset(); entry(0, 1, 0, 2); entry(0, 1, 9, 0); cpu_only(2);
	reset(); entry(0, 1, 9, 0); entry(0, 1, 0, 2); cpu_only(2);
	reset(); entry(0, 1, 9, 2); entry(0, 1, 9, 4); reject(-EINVAL, true);
	reset(); entry(0, 1, 0, 2); records[0].key.proto = 0; reject(-EINVAL, true);
	reset(); entry(0, 1, 0, 2); records[0].id = 9; reject(-EINVAL, true);
	reset(); entry(0, 1, 0, 2); records[1].entry_id = 2; reject(-EINVAL, true);
	reset(); entry(0, 1, 0, 2); records[1].port_id = 1; reject(-EINVAL, true);
	reset(); entry(0, 1, 0, 2); records[1].port.flags ^= BR_FLOOD; reject(-EAGAIN, true);
	reset(); entry(0, 1, 0, 2); records[1].port.state = 0; reject(-EAGAIN, true);
	reset(); entry(0, 1, 0, 2); snapshot.record_count++; reject(-EOPNOTSUPP, true);
	reset(); entry(0, 1, 0, 2); snapshot.generation++; reject(-EAGAIN, true);
	reset(); entry(0, 1, 0, 2); snapshot_error = -E2BIG; reject(-E2BIG, true);
	reset(); record_count = 257; reject(-ENOSPC, true);
#if !CONFIG_IPV6
	reset(); entry(1, 1, 0, 2); reject(-EINVAL, true);
#endif
}

/* Read the actual installed FULL_KEY/result rows, not the compiler's plan.
 * The query is an untagged, checksum-valid TCP/UDP multicast data packet.
 * Missing rules must remain CPU misses; no unspecified TCAM priority may
 * choose between overlapping wildcard/source-specific rows. */
static int lookup_lan(unsigned ipv6, unsigned group, unsigned source,
		      unsigned ingress, unsigned protocol)
{
	struct br_ip address_key = address(ipv6, group, source);
	struct rtl_mdb_rule query;
	int found = -1;

	assert(!fe_mdb_key(&address_key, &query));
	for (unsigned n = 0; n < RTL_MDB_TCAM_SLOTS; n++) {
		unsigned key[22], result[14], equal = 1;

		memcpy(key, m.key[n * 2], 11 * sizeof(unsigned));
		memcpy(key + 11, m.key[n * 2 + 1], 11 * sizeof(unsigned));
		if (!(key[10] & RTL_MDB_KEY_VALID)) continue;
		if (get(key, 372, 1) != ipv6 || get(key, 353, 8) != protocol ||
		    get(key, 622, 6) != ingress || get(key, 629, 6) != ingress) continue;
		assert(get(key, 61, 9) == (ipv6 ? 128U : 32U));
		for (unsigned word = 0; word < 4; word++) {
			unsigned index = ipv6 ? 3 - word : word;
			if (get(key, 70 + word * 32, 32) != query.destination[index]) equal = 0;
			if (get(key, 198, 9) && get(key, 207 + word * 32, 32) != query.source[index]) equal = 0;
		}
		if (!equal) continue;
		assert(found == -1); /* No hardware tie-break is part of the contract. */
		memcpy(result, m.fib[rtl_mdb_fib_index(n)], 7 * sizeof(unsigned));
		memcpy(result + 7, m.fib[rtl_mdb_fib_index(n) + 1], 7 * sizeof(unsigned));
		assert(get(result, 168, 1) == 1);
		unsigned vector = get(result, 158, 10);
		assert(vector && vector < 256 && mcast.state.vector[vector].active);
		found = (int)mcast.state.vector[vector].egress;
	}
	return found;
}

static void expect_lookup(unsigned ipv6, unsigned group, unsigned source, int lan_mask)
{
	for (unsigned p = 0; p < 5; p++) {
		int expected = lan_mask < 0 ? -1 : lan_mask & ~(int)BIT(p);
		if (!expected) expected = -1; /* CPU local delivery, no LAN target. */
		assert(lookup_lan(ipv6, group, source, p, IPPROTO_TCP) == expected);
		assert(lookup_lan(ipv6, group, source, p, IPPROTO_UDP) == expected);
	}
	cases++;
}

static void dynamic_and_coexistence(void)
{
	unsigned steer;

	for (unsigned ipv6 = 0; ipv6 <= CONFIG_IPV6; ipv6++) {
		for (unsigned pending = 0; pending < 2; pending++) {
			reset(); entry(ipv6, 1, 9, 2); source_record(1, 2); router(ipv6, 4);
			records[1].port.permanent = false; records[1].port.timer.pending = pending;
			records[2].source.user_added = false; records[2].source.timer.pending = !pending;
			records[3].router.type = MDB_RTR_TYPE_TEMP_QUERY;
			records[3].router.timer.pending = pending;
			(ipv6 ? &snapshot.ip6 : &snapshot.ip4)->local_router_time_dependent = true;
			assert(!prepare(&steer) && steer == 31);
			assert(fe.mdb->dynamic_rows == 3 && !fe.mdb->cpu_entries);
			expect_lookup(ipv6, 1, 9, 18); expect_lookup(ipv6, 1, 10, -1);
			/* A dequeued PG/source/router timer has not yet changed the
			 * materialized forwarding set. A changed writer epoch STILL
			 * revokes this generation; no new pre-CLS retirement is guessed. */
			assert(!fe_mdb_withdraw(&fe));
			bridge.guard.generation = snapshot.generation = 20;
			unsigned before = m.commands;
			assert(fe_mdb_prepare(&fe, &bridge.guard, 20, &master, bridge.ports,
				flags, 31, &steer) == -EOPNOTSUPP && !steer);
			assert(m.commands == before && fe.mdb->reason == FE_MDB_RETIRED_EPOCH);
			cases++;
		}
		for (unsigned reverse = 0; reverse < 2; reverse++) {
			reset();
			entry(ipv6, 1, reverse ? 9 : 0, 2);
			entry(ipv6, 1, reverse ? 0 : 9, 2);
			assert(!prepare(&steer) && fe.mdb->tcam.used == 8);
			assert(fe.mdb->folded_entries == 1 && !fe.mdb->cpu_entries);
			expect_lookup(ipv6, 1, 9, 2); expect_lookup(ipv6, 1, 10, 2);
		}
		reset(); entry(ipv6, 1, 0, 2); entry(ipv6, 1, 9, 4);
		assert(!prepare(&steer) && fe.mdb->cpu_entries == 1 && fe.mdb->overlap_cpu == 1);
		assert(fe.mdb->reason == FE_MDB_PARTIAL && !fe.mdb->folded_entries);
		expect_lookup(ipv6, 1, 9, 4); expect_lookup(ipv6, 1, 10, -1);
		reset(); entry(ipv6, 1, 0, 2); entry(ipv6, 1, 9, 0); entry(ipv6, 2, 0, 4);
		assert(!prepare(&steer) && fe.mdb->cpu_entries == 2 && fe.mdb->overlap_cpu == 1);
		expect_lookup(ipv6, 1, 9, -1); expect_lookup(ipv6, 1, 10, -1);
		expect_lookup(ipv6, 2, 9, 4);
		reset(); entry(ipv6, 1, 0, 2); entry(ipv6, 1, 9, 2);
		records[3].port.mcast_to_unicast = true;
		entry(ipv6, 2, 0, 4);
		assert(!prepare(&steer) && fe.mdb->cpu_entries == 2 && fe.mdb->overlap_cpu == 1);
		expect_lookup(ipv6, 1, 9, -1); expect_lookup(ipv6, 1, 10, -1);
		expect_lookup(ipv6, 2, 9, 4);
		/* Router membership wins over a blocked/empty exact PG just as
		 * br_multicast_flood does, making these two LAN masks equivalent. */
		reset(); entry(ipv6, 1, 0, 2); entry(ipv6, 1, 9, 2);
		records[3].port.forward = false; records[3].port.blocked = true;
		router(ipv6, 1);
		assert(!prepare(&steer) && fe.mdb->folded_entries == 1);
		expect_lookup(ipv6, 1, 9, 2); expect_lookup(ipv6, 1, 10, 2);
	}
	reset(); entry(0, 1, 0, 2); entry(0, 1, 9, 4); entry(0, 2, 0, 8);
	/* An unsupported source cannot be erased from wildcard shadowing. */
	records[2].key.src.ip4 = records[3].key.src.ip4 = htonl(0xef000009);
	assert(!prepare(&steer) && fe.mdb->cpu_entries == 2 && fe.mdb->overlap_cpu == 1);
	expect_lookup(0, 1, 10, -1); expect_lookup(0, 2, 10, 8);
	reset(); entry(0, 1, 0, 2); entry(0, 2, 0, 4);
	records[0].key.proto = records[1].key.proto = 0;
	records[0].entry.kind = BR_RTL9617C_MDB_L2;
	assert(!prepare(&steer) && fe.mdb->cpu_entries == 1);
	expect_lookup(0, 2, 10, 4);
#if CONFIG_IPV6
	reset(); entry(0, 1, 0, 2); entry(1, 1, 0, 4);
	snapshot.ip4.querier_time_dependent = true;
	assert(!prepare(&steer) && fe.mdb->cpu_entries == 1);
	expect_lookup(0, 1, 10, -1); expect_lookup(1, 1, 10, 4);
#endif
	reset();
	for (unsigned i = 0; i < 80; i++) entry(0, i + 1, 9, 0);
	entry(0, 81, 0, 2);
	assert(!prepare(&steer) && fe.mdb->cpu_entries == 80 && fe.mdb->tcam.used == 8);
	expect_lookup(0, 80, 9, -1); expect_lookup(0, 81, 9, 2);
	reset();
	for (unsigned i = 0; i < 6; i++) entry(0, i + 1, 0, 31);
	entry(0, 7, 0, 2); entry(0, 7, 9, 2);
	assert(!prepare(&steer) && fe.mdb->cpu_entries == 2 && fe.mdb->capacity_cpu == 2);
	assert(!fe.mdb->folded_entries && fe.mdb->tcam.used == 60);
	expect_lookup(0, 7, 9, -1); expect_lookup(0, 7, 10, -1);
}

static void register_rejections(void)
{
	/* Rebuild can occur without a fresh FE base check. The real wrapper
	 * must re-read every FE-lifetime guard byte, not trust ready flags. */
	for (unsigned guard = 0; guard < 2; guard++) {
		for (unsigned word = 0; word < 22; word++) {
			reset(); entry(0, 1, 0, 2);
			m.key[124 + guard * 2 + word / 11][word % 11] ^= 1;
			reject(-EIO, false);
		}
		for (unsigned word = 0; word < 14; word++) {
			reset(); entry(0, 1, 0, 2);
			m.fib[((62 + guard) * 8 | 4) + word / 7][word % 7] ^= 1;
			reject(-EIO, false);
		}
	}
	const unsigned registers[] = { 0x3400, 0x3404, 0x3414, 0x341c, 0x3420, 0x3428,
		0x3248, 0x324c, 0x3314, 0x3318 };
	for (unsigned i = 0; i < ARRAY_SIZE(registers); i++) {
		reset(); entry(0, 1, 0, 2); m.registers[registers[i] / 4] ^= 1;
		reject(-EOPNOTSUPP, false); assert(fe.mdb->bad_register == registers[i]);
	}
	reset(); entry(0, 1, 0, 2); m.registers[0x3400 / 4] |= BIT(20); reject(-EOPNOTSUPP, false);
	reset(); entry(0, 1, 0, 2); m.registers[0x3400 / 4] = ~0U; reject(-EIO, false);
	for (unsigned p = 0; p < 2; p++) for (unsigned t = 0; t < 4; t++) for (unsigned row = 0; row < 2; row++) {
		reset(); entry(0, 1, 0, 2);
		m.fib[fe_classifier_default_index(p, t, row)][0] ^= 1;
		reject(-EOPNOTSUPP, false); assert(fe.mdb->bad_register == 0x33cc);
	}
	reset(); entry(0, 1, 0, 2); m.key[255][10] = RTL_MDB_KEY_VALID;
	unsigned steer;
	assert(prepare(&steer) == -EBUSY && !steer && !m.table_writes);
	assert(m.key[255][10] == RTL_MDB_KEY_VALID); cases++;
}

static void capacity_and_rollback(void)
{
	unsigned steer;
	reset(); for (unsigned i = 0; i < 7; i++) entry(0, i + 1, 0, 31);
	assert(!prepare(&steer) && steer == 31 && fe.mdb->tcam.active == 60);
	assert(fe.mdb->cpu_entries == 1 && fe.mdb->capacity_cpu == 1);
	assert(fe.mdb->reason == FE_MDB_PARTIAL); cases++;
	reset(); for (unsigned i = 0; i < 7; i++) entry(0, i + 1, 0, i < 3 ? 31 : 2);
	assert(!prepare(&steer) && fe.mdb->tcam.used == 62 && fe.mdb->tcam.active == 62);
	assert(!fe_mdb_withdraw(&fe));
	unsigned before = m.commands;
	assert(!prepare(&steer) && !steer && m.commands == before);
	assert(fe.mdb->cpu_entries == 7 && fe.mdb->capacity_cpu == 7);
	assert(fe.mdb->reason == FE_MDB_CPU_ONLY); no_keys(); cases++;
	reset(); entry(0, 1, 9, 2); entry(0, 1, 10, 4);
	assert(!prepare(&steer)); assert(fe.mdb->tcam.active == 16); cases++;
	reset(); entry(0, 1, 0, 2); m.exhaust_after_valid = 2;
	assert(prepare(&steer) == -ENOSPC && !steer); no_keys();
	assert(fe.mdb->tcam.used == 2 && fe.mdb->tcam.exposed && !fe.mdb->tcam.active);
	assert(mcast.state.publications == 1); cases++;
	reset(); entry(0, 1, 0, 2); m.change_epoch_at_valid = 8;
	assert(prepare(&steer) == -EAGAIN && !steer); no_keys(); cases++;
	reset(); entry(0, 1, 0, 2); assert(!prepare(&steer));
	before = fe.mdb->tcam.used;
	assert(!fe_mdb_withdraw(&fe)); assert(!prepare(&steer));
	assert(fe.mdb->tcam.used == before * 2); cases++;
	assert(!fe_mdb_withdraw(&fe));
	before = m.commands;
	bridge.guard.generation = snapshot.generation = 20;
	assert(fe_mdb_prepare(&fe, &bridge.guard, 20, &master, bridge.ports, flags,
		31, &steer) == -EOPNOTSUPP && !steer);
	assert(fe.mdb->reason == FE_MDB_RETIRED_EPOCH && fe.mdb->generation == 19);
	assert(m.commands == before && fe_mdb_retained(&fe)); no_keys(); cases++;
	reset(); entry(0, 1, 0, 2); assert(!prepare(&steer));
	mcast.state.rx_active = 1; assert(fe_mdb_withdraw(&fe) == -EBUSY && fe.mdb->tcam.active);
	mcast.state.rx_active = 0; assert(!fe_mdb_withdraw(&fe)); cases++;
	reset_without_profile(); allocation_failure = 1;
	assert(fe_mdb_profile_prepare(&fe) == -ENOMEM && !m.reads); cases++;
	reset(); entry(0, 1, 0, 2); allocation_failure = 1;
	assert(prepare(&steer) == -ENOMEM && !steer && !m.commands); cases++;
	reset_without_profile(); m.fail_at = 1; m.failure_mode = 1;
	assert(fe_mdb_profile_prepare(&fe) < 0 && fe_mdb_retained(&fe) && fe.mdb->window_retained);
	struct rtl_fe_mdb *saved = fe.mdb;
	fe_mdb_free(&fe); assert(fe.mdb == saved);
	assert(fe_mdb_withdraw(&fe) < 0); finish_pending();
	assert(!fe_mdb_withdraw(&fe) && !fe_mdb_retained(&fe));
	fe_mdb_free(&fe); assert(!fe.mdb); cases++;
	/* A BUM DFT already references this exact vector. Optional MDB failure
	 * removes only its CLS producer; it must not decrement that aggregate
	 * MCE dependency while the DFT owner still needs it. */
	reset(); entry(0, 1, 0, 2);
	u16 bum;
	assert(!fe_mcast_group(&fe, &bridge.guard, 19, 0, &ports[0], &master, 0, 2, &bum));
	assert(!fe_mcast_publish(&fe, bum));
	m.exhaust_after_valid = 2;
	assert(prepare(&steer) == -ENOSPC && !steer); no_keys();
	assert(mcast.state.vector[bum].active && owner.active[RTL_L2_SHARED_MC_VECTOR][bum] == 1);
	cases++;
}

static void transaction_faults(void)
{
	unsigned steer;
	reset(); entry(0, 1, 0, 2); assert(!prepare(&steer));
	unsigned operations = m.commands;
	for (unsigned mode = 0; mode < 3; mode++) {
		for (unsigned fault = 1; fault <= operations; fault++) {
			reset(); entry(0, 1, 0, 2);
			m.fail_at = fault; m.failure_mode = mode;
			assert(prepare(&steer) < 0 && !steer);
			assert(!bridge.guard.armed && !mcast.state.rx_active);
			if (m.pending_access) {
				assert(fe_mdb_retained(&fe) || rtl_l2_owner_retained(&owner));
				finish_pending();
			}
			assert(!fe_mdb_withdraw(&fe)); no_keys();
			if (m.valid_writes) assert(fe.mdb->tcam.exposed && fe_mdb_retained(&fe));
			faults++;
		}
	}
}

static void profile_lifecycle(void)
{
	reset_without_profile();
	fe.enabled = fe.base_ready = fe.engine_ready = false;
	assert(!fe_mdb_profile_prepare(&fe) && !fe_mdb_profile_check(&fe));
	assert(fe.mdb->tcam.guards_ready && fe.mdb->tcam.guard_exposed);
	assert(!fe.mdb->generation && !fe.mdb->tcam.used && !fe.mdb->tcam.exposed);
	assert(fe_mdb_retained(&fe));
	struct rtl_fe_mdb *saved = fe.mdb;
	assert(!fe_mdb_withdraw(&fe)); fe_mdb_free(&fe); assert(fe.mdb == saved);
	assert(!fe_mdb_profile_check(&fe));
	cases++;
	reset_without_profile(); assert(!fe_mdb_profile_prepare(&fe));
	unsigned operations = m.commands;
	for (unsigned mode = 0; mode < 3; mode++) {
		for (unsigned fault = 1; fault <= operations; fault++) {
			reset_without_profile(); m.fail_at = fault; m.failure_mode = mode;
			assert(fe_mdb_profile_prepare(&fe) < 0);
			assert(!fe.mdb->tcam.used && !fe.mdb->tcam.exposed && !fe.mdb->generation);
			if (m.pending_access) {
				assert(fe_mdb_retained(&fe)); finish_pending();
			}
			assert(!fe_mdb_withdraw(&fe));
			if (fe.mdb->tcam.guard_exposed) {
				assert(fe_mdb_retained(&fe));
				saved = fe.mdb; fe_mdb_free(&fe); assert(saved == fe.mdb);
			} else {
				assert(!fe_mdb_retained(&fe)); fe_mdb_free(&fe); assert(!fe.mdb);
			}
			faults++;
		}
	}
	reset_without_profile(); m.key[255][10] = RTL_MDB_KEY_VALID;
	assert(fe_mdb_profile_prepare(&fe) == -EBUSY && !m.table_writes);
	assert(m.key[255][10] == RTL_MDB_KEY_VALID && !fe_mdb_retained(&fe)); cases++;
	reset_without_profile();
	for (unsigned i = 0; i < 63; i++) m.cam[i][0] = BIT(16) | (0x9000 + i);
	assert(fe_mdb_profile_prepare(&fe) == -ENOSPC && !fe_mdb_retained(&fe)); cases++;
}

#ifdef FE_MDB_REAL_SNAPSHOT
#include "fe_mdb_snapshot_cases.c"
#endif

int main(void)
{
	cold_and_topology(); policy_rejections(); dynamic_and_coexistence();
	capacity_and_rollback();
	if (!FE_MDB_FOCUSED) {
		good_matrix(); register_rejections(); transaction_faults(); profile_lifecycle();
	}
#ifdef FE_MDB_REAL_SNAPSHOT
	real_snapshot_cases();
#endif
	char stats[1024];
	assert(fe_mdb_stats(&fe, stats, sizeof(stats)) > 0 && strstr(stats, "mdb_state="));
	free(fe.mdb); fe.mdb = NULL;
	assert(fe_mdb_stats(&fe, stats, sizeof(stats)) > 0 && strstr(stats, "not-prepared"));
	printf("FE MDB actual wrapper + TCAM + MCE: %lu policy/lifecycle cases, %lu fault cases (IPv6=%u) PASS\n",
		cases, faults, CONFIG_IPV6);
	return 0;
}
