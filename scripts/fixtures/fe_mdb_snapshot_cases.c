/* End-to-end bridge objects -> actual bounded snapshot -> FE compiler ->
 * actual immutable MCE owner -> actual CLS key/FIB transaction. Hardware
 * transport and the already-owned cold contract remain explicit fixtures. */
static struct net_bridge snapshot_bridge;
static struct net_bridge_port snapshot_ports[5];
static struct net_bridge_mdb_entry snapshot_entries[8];
static struct net_bridge_port_group snapshot_groups[40];
static struct net_bridge_group_src snapshot_sources[8];
static struct net_bridge_mcast_port snapshot_routers[5];

static void snapshot_reset(void)
{
	static bool initialized;

	reset();
	if (initialized) assert(!pthread_mutex_destroy(&snapshot_bridge.multicast_lock));
	memset(&snapshot_bridge, 0, sizeof(snapshot_bridge));
	assert(!pthread_mutex_init(&snapshot_bridge.multicast_lock, NULL));
	initialized = true;
	memset(snapshot_entries, 0, sizeof(snapshot_entries));
	memset(snapshot_groups, 0, sizeof(snapshot_groups));
	memset(snapshot_sources, 0, sizeof(snapshot_sources));
	memset(snapshot_routers, 0, sizeof(snapshot_routers));
	master.br = &snapshot_bridge;
	snapshot_bridge.dev = &master;
	snapshot_bridge.options = BIT(BROPT_MULTICAST_ENABLED) | BIT(BROPT_HAS_IPV6_ADDR);
	snapshot_bridge.multicast_ctx = (struct net_bridge_mcast){
		.br = &snapshot_bridge, .multicast_querier = 1,
		.multicast_igmp_version = 3, .multicast_mld_version = 2,
	};
	for (unsigned p = 0; p < 5; p++)
		snapshot_ports[p] = (struct net_bridge_port){ .br = &snapshot_bridge,
			.dev = &ports[p], .flags = flags[p], .state = BR_STATE_FORWARDING };
	jiffies = 100;
	real_snapshot_enabled = true;
	assert(!snapshot_lock_depth && !snapshot_rcu_depth);
}

static void snapshot_entry(unsigned n, unsigned ipv6, unsigned group,
			   unsigned source, unsigned mask, bool pending)
{
	struct net_bridge_mdb_entry *entry = &snapshot_entries[n];

	entry->br = &snapshot_bridge;
	entry->addr = address(ipv6, group, source);
	hlist_add_head(&entry->mdb_node, &snapshot_bridge.mdb_list);
	for (unsigned p = 0; p < 5; p++) {
		struct net_bridge_port_group *pg = &snapshot_groups[n * 5 + p];

		if (!(mask & BIT(p))) continue;
		*pg = (struct net_bridge_port_group){
			.key = { .port = &snapshot_ports[p], .addr = entry->addr },
			.filter_mode = source ? MCAST_INCLUDE : MCAST_EXCLUDE,
			.timer = { .expires = pending ? 200 : 100, .pending = pending },
		};
		pg->next = entry->ports;
		entry->ports = pg;
	}
}

static void snapshot_source(unsigned n, unsigned pg, unsigned ipv6, bool pending)
{
	struct net_bridge_group_src *source = &snapshot_sources[n];

	*source = (struct net_bridge_group_src){ .pg = &snapshot_groups[pg],
		.addr = address(ipv6, 1, 9), .flags = BR_SGRP_F_INSTALLED,
		.timer = { .expires = pending ? 200 : 100, .pending = pending } };
	hlist_add_head(&source->node, &snapshot_groups[pg].src_list);
}

static void snapshot_router(unsigned ipv6, unsigned port, bool pending)
{
	struct net_bridge_mcast_port *router = &snapshot_routers[port];

	router->port = &snapshot_ports[port];
	router->multicast_router = MDB_RTR_TYPE_TEMP_QUERY;
#if CONFIG_IPV6
	if (ipv6) {
		router->ip6_mc_router_timer = (struct timer_list){ .expires = pending ? 200 : 100, .pending = pending };
		hlist_add_head(&router->ip6_rlist, &snapshot_bridge.multicast_ctx.ip6_mc_router_list);
		return;
	}
#else
	assert(!ipv6);
#endif
	router->ip4_mc_router_timer = (struct timer_list){ .expires = pending ? 200 : 100, .pending = pending };
	hlist_add_head(&router->ip4_rlist, &snapshot_bridge.multicast_ctx.ip4_mc_router_list);
}

static void real_snapshot_cases(void)
{
	unsigned steer;
	unsigned long before = cases;

	for (unsigned ipv6 = 0; ipv6 <= CONFIG_IPV6; ipv6++) {
		for (unsigned pending = 0; pending < 2; pending++) {
			snapshot_reset();
			snapshot_entry(0, ipv6, 1, 0, 2, pending);
			snapshot_source(0, 1, ipv6, pending);
			snapshot_entry(1, ipv6, 1, 9, 4, pending);
			snapshot_entry(2, ipv6, 2, 0, 8, pending);
			snapshot_router(ipv6, 4, pending);
			/* A dequeued timer (pending=false, expires==now) leaves PG
			 * flags/source materialization/router list unchanged until the
			 * fenced writer executes. The real snapshot must preserve it. */
			assert(!prepare(&steer) && steer == 31 && snapshot_calls == 1);
			assert(fe.mdb->dynamic_rows == 5 && fe.mdb->cpu_entries == 1);
			expect_lookup(ipv6, 1, 9, 20); expect_lookup(ipv6, 1, 10, -1);
			expect_lookup(ipv6, 2, 9, 24);
			assert(!snapshot_lock_depth && !snapshot_rcu_depth);
		}
		snapshot_reset();
		snapshot_entry(0, ipv6, 1, 0, 2, true);
		snapshot_entry(1, ipv6, 1, 9, 0, false);
		snapshot_entries[1].host_joined = true;
		snapshot_entry(2, ipv6, 2, 0, 4, true);
		assert(!prepare(&steer) && fe.mdb->cpu_entries == 2 && fe.mdb->overlap_cpu == 1);
		expect_lookup(ipv6, 1, 9, -1); expect_lookup(ipv6, 1, 10, -1);
		expect_lookup(ipv6, 2, 9, 4);
		snapshot_reset();
		snapshot_entry(0, ipv6, 1, 0, 2, true);
		snapshot_entry(1, ipv6, 1, 9, 6, true);
		snapshot_groups[6].flags = MDB_PG_FLAGS_STAR_EXCL;
		snapshot_groups[7].flags = MDB_PG_FLAGS_BLOCKED;
		snapshot_source(0, 1, ipv6, true);
		assert(!prepare(&steer) && fe.mdb->folded_entries == 1 && fe.mdb->tcam.used == 8);
		expect_lookup(ipv6, 1, 9, 2); expect_lookup(ipv6, 1, 10, 2);
		snapshot_reset();
		snapshot_entry(0, ipv6, 1, 0, 2, true);
		snapshot_groups[1].filter_mode = MCAST_INCLUDE;
		snapshot_entry(1, ipv6, 1, 9, 4, true);
		assert(!prepare(&steer) && fe.mdb->cpu_entries == 1);
		expect_lookup(ipv6, 1, 9, 4); expect_lookup(ipv6, 1, 10, -1);
	}
#if CONFIG_IPV6
	snapshot_reset();
	snapshot_entry(0, 0, 1, 0, 2, true);
	snapshot_entry(1, 1, 1, 0, 4, true);
	snapshot_bridge.multicast_ctx.ip4_other_query.delay_timer =
		(struct timer_list){ .pending = true, .expires = 200 };
	assert(!prepare(&steer) && fe.mdb->cpu_entries == 1);
	expect_lookup(0, 1, 9, -1); expect_lookup(1, 1, 9, 4);
#endif
	printf("FE MDB real bridge snapshot -> immutable MCE -> CLS: %lu directed packet-policy cases PASS\n", cases - before);
}
