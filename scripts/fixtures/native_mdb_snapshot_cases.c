/* Actual snapshot/guard functions have already been inserted above. */
static struct net_device portdev[4];
static struct net_bridge_port ports[4];
static struct net_bridge_mdb_entry entries[32];
static struct net_bridge_port_group groups[32];
static struct net_bridge_group_src sources[16];
static struct net_bridge_mcast_port routers[4];
static struct net_bridge_vlan vlan;
static struct br_rtl9617c_mdb_record records[256];
static struct br_rtl9617c_mdb_snapshot result;
static unsigned int emitted;
static int fail_at=-1, fail_code, add_error;
static bool expire_on_emit;
static atomic_int race_phase;
static int race_at=-1;
static bool race_complete;

static void setup(void)
{
	static bool lock_initialized;
	if (lock_initialized) assert(!pthread_mutex_destroy(&bridge.multicast_lock));
	memset(&bridge,0,sizeof(bridge));
	assert(!pthread_mutex_init(&bridge.multicast_lock,NULL)); lock_initialized=true;
	memset(&network,0,sizeof(network));
	network.rtl9617c_switch.generation=42;
	guard=(struct rtl9617c_switch_guard){.net=&network,.registered=true};
	master=(struct net_device){.net=&network,.br=&bridge,.ifindex=100,
		.master=true,.running=true,.flags=IFF_ALLMULTI};
	bridge.dev=&master;
	bridge.options=BIT(BROPT_MULTICAST_ENABLED)|BIT(BROPT_HAS_IPV6_ADDR);
	bridge.multicast_ctx=(struct net_bridge_mcast){.br=&bridge,
		.multicast_querier=1,.multicast_igmp_version=3,
		.multicast_mld_version=2,.multicast_router=MDB_RTR_TYPE_DISABLED,
		.multicast_membership_interval=1000};
	memset(entries,0,sizeof(entries));memset(groups,0,sizeof(groups));
	memset(sources,0,sizeof(sources));memset(routers,0,sizeof(routers));
	memset(&vlan,0,sizeof(vlan));memset(&result,0xa5,sizeof(result));
	for(unsigned int i=0;i<4;i++){
		portdev[i]=(struct net_device){.net=&network,.ifindex=(int)i+1,.running=true};
		ports[i]=(struct net_bridge_port){.dev=&portdev[i],.br=&bridge,.state=BR_STATE_FORWARDING};
	}
	jiffies=100;emitted=0;fail_at=-1;fail_code=-ENOSPC;expire_on_emit=false;
	quiesces=rebuilds=notifications=0;race_at=-1;race_complete=false;atomic_store(&race_phase,0);
	atomic_store(&hardware_open,true);add_error=0;
	assert(!rcu_depth && !mcast_depth && !gate_depth);
}

static struct br_ip ip4(u32 source,u32 destination,u16 vid)
{
	return (struct br_ip){.proto=htons(ETH_P_IP),.vid=vid,
		.src.ip4=htonl(source),.dst.ip4=htonl(destination)};
}

static void add_entry(unsigned int index,struct br_ip key,bool host)
{
	entries[index]=(struct net_bridge_mdb_entry){.br=&bridge,.addr=key,.host_joined=host};
	hlist_add_head(&entries[index].mdb_node,&bridge.mdb_list);
}
static void add_group(unsigned int index,unsigned int entry,unsigned int port,
		      unsigned int mode,unsigned int flags)
{
	groups[index]=(struct net_bridge_port_group){.key={.port=&ports[port],.addr=entries[entry].addr},
		.flags=flags,.filter_mode=mode,.rt_protocol=4};
	groups[index].eth_addr[5]=index+1;
	groups[index].next=entries[entry].ports;entries[entry].ports=&groups[index];
}
static void add_source(unsigned int index,unsigned int pg,struct br_ip key,u8 flags)
{
	sources[index]=(struct net_bridge_group_src){.pg=&groups[pg],.addr=key,.flags=flags};
	hlist_add_head(&sources[index].node,&groups[pg].src_list);
}
static bool header_empty(void)
{
	const struct br_rtl9617c_mdb_snapshot zero={};
	return !memcmp(&result,&zero,sizeof(zero));
}
static int collect(void *priv,const struct br_rtl9617c_mdb_record *record)
{
	assert(priv==&result && mcast_depth && rcu_depth && rtnl_held);
	/* Even while the final record is copied, no epoch/header is published. */
	assert(header_empty());
	if ((int)emitted==fail_at) return fail_code;
	if (emitted==256) return -ENOSPC;
	if ((int)emitted==race_at) {
		atomic_store_explicit(&race_phase,1,memory_order_release);
		/* Scheduling fault injection, NOT a permissible production callback. */
		while (atomic_load_explicit(&race_phase,memory_order_acquire)!=2) sched_yield();
	}
	if (expire_on_emit) jiffies=1000;
	records[emitted++]=*record;
	return 0;
}
static int snapshot(u16 vid,unsigned int budget)
{
	emitted=0;memset(&result,0xa5,sizeof(result));
	int ret=br_rtl9617c_mdb_snapshot(&master,vid,&guard,budget,&result,collect,&result);
	assert(!mcast_depth && !rcu_depth && !gate_depth);
	if(ret) assert(header_empty());
	else assert(result.record_count==emitted && result.master==&master &&
		result.generation==network.rtl9617c_switch.generation);
	cases++;return ret;
}
static struct br_rtl9617c_mdb_record *find_record(enum br_rtl9617c_mdb_record_type type,
					       const struct br_ip *key,const struct net_device *dev)
{
	for(unsigned int i=0;i<emitted;i++)
		if(records[i].type==type && (!key || !memcmp(&records[i].key,key,sizeof(*key))) &&
		   (!dev || records[i].dev==dev)) return &records[i];
	return NULL;
}
static void build_table(void)
{
	setup();
	add_entry(0,ip4(0,0xef010203,0),true);
	add_group(0,0,0,MCAST_INCLUDE,MDB_PG_FLAGS_PERMANENT);
	add_source(0,0,ip4(0x0a010101,0,0),BR_SGRP_F_INSTALLED|BR_SGRP_F_USER_ADDED);
	add_entry(1,ip4(0x0a010101,0xef010203,0),false);
	add_group(1,1,0,MCAST_INCLUDE,MDB_PG_FLAGS_PERMANENT|MDB_PG_FLAGS_BLOCKED);
	add_group(2,1,1,MCAST_EXCLUDE,MDB_PG_FLAGS_PERMANENT|MDB_PG_FLAGS_STAR_EXCL);
	/* Different complete IPv4 addresses alias to the same multicast MAC. */
	add_entry(2,ip4(0,0xef810203,0),false);
	add_group(3,2,1,MCAST_EXCLUDE,MDB_PG_FLAGS_PERMANENT);
	/* Empty exact entries must not silently become wildcard/unknown floods. */
	add_entry(3,ip4(0x0a010109,0xef010203,0),false);
	struct br_ip l2={};l2.dst.mac_addr[0]=1;l2.dst.mac_addr[5]=7;
	add_entry(4,l2,true);
#if CONFIG_IPV6
	struct br_ip v6={.proto=htons(ETH_P_IPV6)};
	v6.dst.ip6.s6_addr[0]=0xff;v6.dst.ip6.s6_addr[1]=0x3e;v6.dst.ip6.s6_addr[15]=5;
	add_entry(5,v6,false);add_group(4,5,2,MCAST_EXCLUDE,MDB_PG_FLAGS_PERMANENT);
	v6.dst.ip6.s6_addr[2]=0x17;v6.src.ip6.s6_addr[0]=0x20;v6.src.ip6.s6_addr[15]=9;
	add_entry(6,v6,true);add_group(5,6,3,MCAST_INCLUDE,MDB_PG_FLAGS_PERMANENT);
#endif
	routers[0]=(struct net_bridge_mcast_port){.port=&ports[0],.multicast_router=MDB_RTR_TYPE_PERM};
	hlist_add_head(&routers[0].ip4_rlist,&bridge.multicast_ctx.ip4_mc_router_list);
#if CONFIG_IPV6
	routers[1]=(struct net_bridge_mcast_port){.port=&ports[1],.multicast_router=MDB_RTR_TYPE_PERM};
	hlist_add_head(&routers[1].ip6_rlist,&bridge.multicast_ctx.ip6_mc_router_list);
#endif
}
static void exact_records(void)
{
	build_table();assert(!snapshot(0,128));
	assert(result.ip4.supported && result.ip4.version==3 && result.ip4.own_querier);
	assert(result.ip4.querier_present && !result.ip4.querier_time_dependent);
	assert(result.ip6.supported==!!CONFIG_IPV6 && result.snooping && result.running);
	assert(!result.has_deadline && result.master_flags==IFF_ALLMULTI);
	unsigned int expected=CONFIG_IPV6?16:11;assert(emitted==expected);
	for(unsigned int i=0;i<emitted;i++) {
		struct br_rtl9617c_mdb_record *r=&records[i];assert(r->id==i+1);
		if(r->type==BR_RTL9617C_MDB_ENTRY)assert(r->entry_id==r->id && !r->port_id);
		if(r->type==BR_RTL9617C_MDB_PORT)assert(r->port_id==r->id &&
			records[r->entry_id-1].type==BR_RTL9617C_MDB_ENTRY);
		if(r->type==BR_RTL9617C_MDB_SOURCE)assert(records[r->port_id-1].type==BR_RTL9617C_MDB_PORT &&
			records[r->port_id-1].entry_id==r->entry_id);
		cases++;
	}
	struct br_rtl9617c_mdb_record *r=find_record(BR_RTL9617C_MDB_ENTRY,&entries[0].addr,NULL);
	assert(r && r->entry.kind==BR_RTL9617C_MDB_STAR_G && r->entry.host_joined);
	r=find_record(BR_RTL9617C_MDB_ENTRY,&entries[3].addr,NULL);
	assert(r && r->entry.kind==BR_RTL9617C_MDB_SOURCE_G && !r->entry.host_joined);
	r=find_record(BR_RTL9617C_MDB_ENTRY,&entries[4].addr,NULL);
	assert(r && r->entry.kind==BR_RTL9617C_MDB_L2 && r->entry.host_joined);
	r=find_record(BR_RTL9617C_MDB_PORT,&entries[0].addr,&portdev[0]);
	assert(r && !r->port.forward && r->port.permanent && !r->port.blocked);
	r=find_record(BR_RTL9617C_MDB_PORT,&entries[1].addr,&portdev[0]);
	assert(r && !r->port.forward && r->port.blocked);
	r=find_record(BR_RTL9617C_MDB_PORT,&entries[1].addr,&portdev[1]);
	assert(r && r->port.forward && r->port.star_excl);
	r=find_record(BR_RTL9617C_MDB_SOURCE,&entries[0].addr,&portdev[0]);
	assert(r && r->source.user_added && r->source.installed &&
		!memcmp(&r->source.addr,&sources[0].addr,sizeof(struct br_ip)));
	r=find_record(BR_RTL9617C_MDB_ENTRY,&entries[2].addr,NULL);assert(r);
#if CONFIG_IPV6
	assert(find_record(BR_RTL9617C_MDB_ENTRY,&entries[5].addr,NULL));
	assert(find_record(BR_RTL9617C_MDB_ENTRY,&entries[6].addr,NULL));
	r=find_record(BR_RTL9617C_MDB_ROUTER,NULL,&portdev[1]);
	assert(r && r->router.proto==htons(ETH_P_IPV6));
#endif
	r=find_record(BR_RTL9617C_MDB_ROUTER,NULL,&portdev[0]);
	assert(r && r->router.proto==htons(ETH_P_IP) && r->router.type==MDB_RTR_TYPE_PERM);
	/* Router and blocked-PG rows both survive; the consumer must apply router precedence. */
	bridge.multicast_ctx.multicast_igmp_version=2;assert(!snapshot(0,128));
	r=find_record(BR_RTL9617C_MDB_PORT,&entries[0].addr,&portdev[0]);assert(r->port.forward);
	bridge.multicast_ctx.multicast_igmp_version=3;
	/* Duplicate hosts on one device and unicast-before-BLOCKED semantics. */
	ports[0].flags|=BR_MULTICAST_TO_UNICAST;
	add_group(7,1,0,MCAST_INCLUDE,MDB_PG_FLAGS_PERMANENT|MDB_PG_FLAGS_BLOCKED);
	assert(!snapshot(0,128));
	unsigned int duplicates=0;u32 last_id=0;unsigned char last_eth=0;
	for(unsigned int i=0;i<emitted;i++)if(records[i].type==BR_RTL9617C_MDB_PORT &&
		records[i].dev==&portdev[0] && !memcmp(&records[i].key,&entries[1].addr,sizeof(struct br_ip))){
		assert(records[i].port.forward && records[i].port.mcast_to_unicast && records[i].port.blocked);
		assert(records[i].id!=last_id && records[i].port.eth_addr[5]!=last_eth);
		last_id=records[i].id;last_eth=records[i].port.eth_addr[5];duplicates++;
	}
	assert(duplicates==2);
}
static void timer_contexts(void)
{
	for(unsigned int own=0;own<2;own++)for(unsigned int other=0;other<2;other++)
	for(unsigned int delay=0;delay<2;delay++)for(unsigned int kind=0;kind<4;kind++)
	for(unsigned int local=0;local<2;local++)for(unsigned int address=0;address<2;address++){
		setup();struct net_bridge_mcast *c=&bridge.multicast_ctx;
		c->multicast_querier=own;c->multicast_router=kind;
		if(!address)bridge.options&=~BIT(BROPT_HAS_IPV6_ADDR);
		c->ip4_other_query.timer=(struct timer_list){.pending=other,.expires=140};
		c->ip4_other_query.delay_timer=(struct timer_list){.pending=delay,.expires=150};
		c->ip4_mc_router_timer=(struct timer_list){.pending=local,.expires=160};
#if CONFIG_IPV6
		c->ip6_other_query=c->ip4_other_query;c->ip6_mc_router_timer=c->ip4_mc_router_timer;
#endif
		assert(!snapshot(0,1));
		assert(result.ip4.querier_present==__br_multicast_querier_exists(c,&c->ip4_other_query,false));
		assert(result.ip4.querier_time_dependent==(delay||(!own&&other)));
		struct sk_buff skb={.protocol=htons(ETH_P_IP)};
		assert(result.ip4.local_router==br_multicast_is_router(c,&skb));
		assert(result.ip4.local_router_time_dependent==(kind==MDB_RTR_TYPE_TEMP_QUERY&&local));
#if CONFIG_IPV6
		assert(result.ip6.querier_present==__br_multicast_querier_exists(c,&c->ip6_other_query,true));
		assert(result.ip6.own_querier==(own&&address));
		skb.protocol=htons(ETH_P_IPV6);assert(result.ip6.local_router==br_multicast_is_router(c,&skb));
#endif
	}
	build_table();entries[0].timer=(struct timer_list){.pending=true,.expires=130};
	groups[1].timer=(struct timer_list){.pending=true,.expires=120};
	sources[0].timer=(struct timer_list){.pending=true,.expires=110};
	assert(!snapshot(0,128) && result.earliest_deadline==110);
	/* Raw source lease expiry must not rewrite materialized PG BLOCKED. */
	sources[0].timer.pending=false;assert(!snapshot(0,128) && result.earliest_deadline==120);
	expire_on_emit=true;assert(snapshot(0,128)==-EAGAIN);
	setup();jiffies=ULONG_MAX-5;
	bridge.multicast_ctx.ip4_other_query.timer=(struct timer_list){.pending=true,.expires=3};
	bridge.multicast_ctx.ip4_other_query.delay_timer=(struct timer_list){.pending=true,.expires=ULONG_MAX-1};
	assert(!snapshot(0,1) && result.earliest_deadline==ULONG_MAX-1);
	jiffies=0;assert(snapshot(0,1)==-EAGAIN);
}
static void domains_and_limits(void)
{
	setup();assert(snapshot(4095,10)==-EINVAL);assert(snapshot(1,10)==-EINVAL);
	assert(snapshot(0,0)==-EINVAL);
	guard.net=&other_network;assert(snapshot(0,10)==-EXDEV);guard.net=&network;
	guard.registered=false;assert(snapshot(0,10)==-EAGAIN);guard.registered=true;
	network.rtl9617c_switch.active=1;assert(snapshot(0,10)==-EAGAIN);
	network.rtl9617c_switch.active=0;network.rtl9617c_switch.poisoned=true;
	assert(snapshot(0,10)==-EAGAIN);
	setup();
	for(unsigned int i=0;i<20;i++)add_entry(i,ip4(0,0xef010200+i,2),false);
	assert(snapshot(0,19)==-E2BIG);assert(!snapshot(0,20) && !emitted);
	setup();bridge.options|=BIT(BROPT_VLAN_ENABLED)|BIT(BROPT_MCAST_VLAN_SNOOPING_ENABLED);
	vlan.vid=10;vlan.priv_flags=BR_VLFLAG_MCAST_ENABLED|BR_VLFLAG_GLOBAL_MCAST_ENABLED;
	vlan.br_mcast_ctx=bridge.multicast_ctx;vlan.br_mcast_ctx.vlan=&vlan;
	vlan.br_mcast_ctx.multicast_igmp_version=2;bridge.vlan_group.vlan=&vlan;
	add_entry(0,ip4(0,0xef010203,10),true);add_entry(1,ip4(0,0xef010203,20),true);
	assert(!snapshot(10,10) && emitted==1 && result.vid==10 && result.ip4.version==2);
	assert(result.vlan_snooping && result.vlan_filtering && result.snooping && result.context_enabled);
	vlan.priv_flags=0;assert(!snapshot(10,10) && !result.snooping && !result.context_enabled);
	assert(snapshot(11,10)==-ENOENT);assert(snapshot(0,10)==-ENOENT);
}
static void all_or_nothing(void)
{
	build_table();assert(!snapshot(0,128));unsigned int total=emitted;
	const int errors[]={-ENOSPC,-ENOMEM,1};
	for(unsigned int e=0;e<3;e++)for(unsigned int i=0;i<total;i++){
		build_table();fail_at=i;fail_code=errors[e];
		assert(snapshot(0,128)==(errors[e]>0?-EINVAL:errors[e]));assert(emitted==i);
	}
	for(unsigned int i=1;i<total;i++){
		build_table();assert(snapshot(0,i)==-E2BIG);
	}
}

/* The real add wrapper dispatches into the real host-join implementation.
 * Table allocation/netlink parsing are outside this host fixture's claim. */
static int br_mdb_add_group(const struct br_mdb_config *cfg,struct netlink_ext_ack *ack)
{
	(void)ack;assert(mcast_depth && network.rtl9617c_switch.active && !atomic_load(&hardware_open));
	if(add_error)return add_error;
	struct net_bridge_mdb_entry *mp=br_mdb_ip_get(cfg->br,&cfg->group);assert(mp);
	br_multicast_host_join(&cfg->br->multicast_ctx,mp,true);return 0;
}

/* PRODUCTION_WRITERS are inserted here. */

static void writers(void)
{
	for(unsigned int i=0;i<4;i++){
		setup();add_entry(0,ip4(0x0a010101,0xef010203,0),false);
		struct br_mdb_entry entry={.ifindex=master.ifindex};
		struct br_mdb_config cfg={.br=&bridge,.entry=&entry,.group=entries[0].addr};
		const int errors[]={0,-ENOMEM,-ENOSPC,-EINVAL};add_error=errors[i];
		assert(__br_mdb_add(&cfg,NULL)==errors[i]);
		assert(network.rtl9617c_switch.generation==44 && !network.rtl9617c_switch.active);
		assert(quiesces==1 && rebuilds==1 && !atomic_load(&hardware_open));
		assert(entries[0].host_joined==!errors[i]);assert(!snapshot(0,10));
		if(!errors[i]){
			atomic_store(&hardware_open,true);assert(!__br_mdb_del(&cfg));
			assert(!entries[0].host_joined && !atomic_load(&hardware_open));
			assert(network.rtl9617c_switch.generation==46 && !network.rtl9617c_switch.active);
		}
	}
	setup();add_entry(0,ip4(0x0a010101,0xef010203,0),true);
	br_multicast_group_expired(&entries[0].timer);
	assert(!entries[0].host_joined && hlist_unhashed(&entries[0].mdb_node));
	assert(quiesces==1 && rebuilds==1 && !atomic_load(&hardware_open));assert(!snapshot(0,10)&&!emitted);
	setup();br_ip4_multicast_query_delay_expired(&bridge.multicast_ctx.ip4_other_query.delay_timer);
	assert(quiesces==1 && rebuilds==1 && network.rtl9617c_switch.generation==44);
#if CONFIG_IPV6
	br_ip6_multicast_query_delay_expired(&bridge.multicast_ctx.ip6_other_query.delay_timer);
	assert(quiesces==2 && rebuilds==2 && network.rtl9617c_switch.generation==46);
#endif
	setup();network.rtl9617c_switch.generation=UINT64_MAX;
	struct net *scope=rtl9617c_switch_policy_begin(&master);rtl9617c_switch_policy_end(scope);
	assert(network.rtl9617c_switch.poisoned && snapshot(0,10)==-EAGAIN);
}

static void query_noops(void)
{
	setup();struct net_bridge_mcast *c=&bridge.multicast_ctx;
	struct br_ip addr={};struct sk_buff packet={};
	spin_lock_bh(&bridge.multicast_lock);
	br_multicast_update_querier(c,&c->ip4_querier,0,&addr);
	assert(!quiesces && atomic_load(&hardware_open));
	br_multicast_update_querier(c,&c->ip4_querier,7,&addr);
	assert(quiesces==1 && rebuilds==1 && !atomic_load(&hardware_open));
	atomic_store(&hardware_open,true);
	br_multicast_update_querier(c,&c->ip4_querier,7,&addr);
	assert(quiesces==1 && atomic_load(&hardware_open));
	addr.proto=htons(ETH_P_IP);
	br_multicast_select_own_querier(c,&addr,&packet);
	assert(quiesces==1 && atomic_load(&hardware_open));
	packet.ip4.saddr=htonl(0x0a010101);
	br_multicast_select_own_querier(c,&addr,&packet);
	assert(quiesces==2 && !atomic_load(&hardware_open));
	atomic_store(&hardware_open,true);
	br_multicast_select_own_querier(c,&addr,&packet);
	assert(quiesces==2 && atomic_load(&hardware_open));
#if CONFIG_IPV6
	br_multicast_set_has_ipv6_addr(&bridge,true);
	assert(quiesces==2 && atomic_load(&hardware_open));
	br_multicast_set_has_ipv6_addr(&bridge,false);
	assert(quiesces==3 && !br_opt_get(&bridge,BROPT_HAS_IPV6_ADDR) && !atomic_load(&hardware_open));
	atomic_store(&hardware_open,true);br_multicast_set_has_ipv6_addr(&bridge,false);
	assert(quiesces==3 && atomic_load(&hardware_open));
	br_multicast_set_has_ipv6_addr(&bridge,true);
	assert(quiesces==4 && br_opt_get(&bridge,BROPT_HAS_IPV6_ADDR) && !atomic_load(&hardware_open));
	atomic_store(&hardware_open,true);addr.proto=htons(ETH_P_IPV6);
	br_multicast_select_own_querier(c,&addr,&packet);
	assert(quiesces==4 && atomic_load(&hardware_open));
	packet.ip6.saddr.s6_addr[0]=0xfe;packet.ip6.saddr.s6_addr[1]=0x80;
	br_multicast_select_own_querier(c,&addr,&packet);
	assert(quiesces==5 && !atomic_load(&hardware_open));
	atomic_store(&hardware_open,true);br_multicast_select_own_querier(c,&addr,&packet);
	assert(quiesces==5 && atomic_load(&hardware_open));
#endif
	spin_unlock_bh(&bridge.multicast_lock);
	assert(!network.rtl9617c_switch.active);
	cases+=CONFIG_IPV6?13:6;
}

static void *race_writer(void *unused)
{
	(void)unused;
	while(atomic_load_explicit(&race_phase,memory_order_acquire)!=1)sched_yield();
	if (race_complete) {
		/* The real delay callback can finish without multicast_lock. */
		br_ip4_multicast_query_delay_expired(&bridge.multicast_ctx.ip4_other_query.delay_timer);
		atomic_store_explicit(&race_phase,2,memory_order_release);
		return NULL;
	}
	struct net *scope=rtl9617c_switch_policy_begin(&master);
	atomic_store_explicit(&race_phase,2,memory_order_release);
	spin_lock_bh(&bridge.multicast_lock);
	br_multicast_host_leave(&entries[0],true);
	spin_unlock_bh(&bridge.multicast_lock);
	rtl9617c_switch_policy_end(scope);return NULL;
}
static void concurrent_writer(void)
{
	for(unsigned int iteration=0;iteration<32;iteration++)for(unsigned int point=0;point<2;point++)
	for(unsigned int complete=0;complete<2;complete++){
		setup();add_entry(0,ip4(0x0a010101,0xef010203,0),true);
		add_group(0,0,0,MCAST_INCLUDE,MDB_PG_FLAGS_PERMANENT);
		race_at=point;race_complete=complete;
		pthread_t worker;assert(!pthread_create(&worker,NULL,race_writer,NULL));
		assert(snapshot(0,10)==-EAGAIN);assert(!pthread_join(worker,NULL));
		assert(entries[0].host_joined==!!complete && !network.rtl9617c_switch.active);
		race_at=-1;assert(!snapshot(0,10));
		assert(find_record(BR_RTL9617C_MDB_ENTRY,&entries[0].addr,NULL)->entry.host_joined==!!complete);
	}
}
int main(void)
{
	exact_records();timer_contexts();domains_and_limits();all_or_nothing();writers();query_noops();concurrent_writer();
	printf("native MDB actual-source cases: %u ipv6=%u\n",cases,CONFIG_IPV6);
	return 0;
}
