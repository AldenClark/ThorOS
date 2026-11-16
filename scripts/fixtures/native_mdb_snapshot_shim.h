/* Host-only kernel substrate. Production snapshot/guard/bridge decisions are
 * inserted by test_native_mdb_snapshot.py, not reimplemented in this fixture.
 */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#undef htons
#undef htonl
#undef ntohl
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) __builtin_bswap16((uint16_t)(x))
#define htonl(x) __builtin_bswap32((uint32_t)(x))
#define ntohl(x) __builtin_bswap32((uint32_t)(x))
#else
#define htons(x) ((uint16_t)(x))
#define htonl(x) ((uint32_t)(x))
#define ntohl(x) ((uint32_t)(x))
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint16_t __be16;
typedef uint32_t __be32;
typedef uint16_t __u16;
#define IS_ENABLED(x) (x)
#define IS_REACHABLE(x) (x)
#define CONFIG_BRIDGE 1
#define CONFIG_BRIDGE_IGMP_SNOOPING 1
#define BIT(n) (1UL << (n))
#define HZ 250UL
#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define VLAN_VID_MASK 4095
#define U32_MAX UINT32_MAX
#define IFF_ALLMULTI 0x200U
#define IFF_PROMISC 0x100U
#define MCAST_EXCLUDE 0
#define MCAST_INCLUDE 1
#define BR_STATE_FORWARDING 3
#define RTM_NEWMDB 84
#define RTM_DELMDB 85
#define EXPORT_SYMBOL_GPL(x)
#define READ_ONCE(x) (x)
#define unlikely(x) (x)
#define WARN_ON_ONCE(x) (x)
#define fallthrough __attribute__((fallthrough))
#define __rcu
#define time_before(a,b) ((long)((a)-(b)) < 0)
#define time_after_eq(a,b) ((long)((a)-(b)) >= 0)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define timer_container_of(v,t,m) container_of(t,__typeof__(*(v)),m)
#define ether_addr_copy(d,s) memcpy(d,s,ETH_ALEN)
enum { MDB_RTR_TYPE_DISABLED, MDB_RTR_TYPE_TEMP_QUERY,
       MDB_RTR_TYPE_PERM, MDB_RTR_TYPE_TEMP };
enum { BROPT_VLAN_ENABLED, BROPT_MCAST_VLAN_SNOOPING_ENABLED,
       BROPT_MULTICAST_ENABLED, BROPT_HAS_IPV6_ADDR };
#define BR_VLFLAG_MCAST_ENABLED BIT(2)
#define BR_VLFLAG_GLOBAL_MCAST_ENABLED BIT(3)

struct hlist_node { struct hlist_node *next, **pprev; };
struct hlist_head { struct hlist_node *first; };
static void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	assert(!n->pprev);
	n->next=h->first; if (n->next) n->next->pprev=&n->next;
	h->first=n; n->pprev=&h->first;
}
static void hlist_del_init(struct hlist_node *n)
{
	if (!n->pprev) return;
	*n->pprev=n->next; if(n->next) n->next->pprev=n->pprev;
	n->next=NULL; n->pprev=NULL;
}
static bool hlist_unhashed(const struct hlist_node *n) { return !n->pprev; }
#define hlist_entry_safe(n,t,m) ((n)?container_of(n,t,m):NULL)
#define hlist_for_each_entry(p,h,m) \
	for ((p)=hlist_entry_safe((h)->first,__typeof__(*(p)),m); (p); \
	     (p)=hlist_entry_safe((p)->m.next,__typeof__(*(p)),m))

struct timer_list { unsigned long expires; bool pending; };
static bool timer_pending(const struct timer_list *t) { return t->pending; }
static unsigned long jiffies=100;
static void mod_timer(struct timer_list *t, unsigned long expires)
{
	t->expires=expires; t->pending=true;
}
static bool ipv4_is_zeronet(__be32 addr) { return !(ntohl(addr)&0xff000000U); }
static bool ipv6_addr_any(const struct in6_addr *addr)
{
	static const struct in6_addr zero;
	return !memcmp(addr,&zero,sizeof(zero));
}
static bool ipv6_addr_equal(const struct in6_addr *a,const struct in6_addr *b)
{
	return !memcmp(a,b,sizeof(*a));
}

struct net_bridge;
struct net { struct rtl9617c_switch_net PLACEHOLDER; };
/* NET_STATE is replaced with the actual guard state before compilation. */
struct net_device {
	struct net *net;
	struct net_bridge *br;
	unsigned int flags;
	int ifindex;
	bool master, running;
};
struct rtl9617c_switch_guard { struct net *net; bool registered; };
struct net_bridge_port {
	struct net_bridge *br;
	struct net_device *dev;
	unsigned long flags;
	u8 state;
};
struct net_bridge_port_group;
struct net_bridge_group_src {
	struct hlist_node node;
	struct br_ip addr;
	struct net_bridge_port_group *pg;
	u8 flags;
	struct timer_list timer;
};
struct net_bridge_port_group {
	struct net_bridge_port_group *next;
	struct { struct net_bridge_port *port; struct br_ip addr; } key;
	unsigned char eth_addr[ETH_ALEN];
	u8 flags, filter_mode, rt_protocol;
	struct hlist_head src_list;
	struct timer_list timer;
};
struct net_bridge_mdb_entry {
	struct net_bridge *br;
	struct net_bridge_port_group *ports;
	struct br_ip addr;
	bool host_joined;
	struct timer_list timer;
	struct hlist_node mdb_node;
};
struct bridge_mcast_other_query { struct timer_list timer, delay_timer; };
struct bridge_mcast_querier { struct br_ip addr; int port_ifidx, seq; };
struct net_bridge_vlan;
struct net_bridge_mcast {
	struct net_bridge *br;
	struct net_bridge_vlan *vlan;
	u8 multicast_router, multicast_querier;
	u8 multicast_igmp_version, multicast_mld_version;
	unsigned long multicast_membership_interval;
	struct hlist_head ip4_mc_router_list;
	struct timer_list ip4_mc_router_timer;
	struct bridge_mcast_other_query ip4_other_query;
	struct bridge_mcast_querier ip4_querier;
#if CONFIG_IPV6
	struct hlist_head ip6_mc_router_list;
	struct timer_list ip6_mc_router_timer;
	struct bridge_mcast_other_query ip6_other_query;
	struct bridge_mcast_querier ip6_querier;
#endif
};
struct net_bridge_mcast_port {
	struct net_bridge_port *port;
	u8 multicast_router;
	struct hlist_node ip4_rlist;
	struct timer_list ip4_mc_router_timer;
#if CONFIG_IPV6
	struct hlist_node ip6_rlist;
	struct timer_list ip6_mc_router_timer;
#endif
};
struct net_bridge_vlan {
	u16 vid;
	unsigned int priv_flags;
	struct net_bridge_mcast br_mcast_ctx;
};
struct net_bridge_vlan_group { struct net_bridge_vlan *vlan; };
struct net_bridge {
	struct net_device *dev;
	pthread_mutex_t multicast_lock;
	unsigned long options;
	struct net_bridge_mcast multicast_ctx;
	struct hlist_head mdb_list;
	struct net_bridge_vlan_group vlan_group;
};
struct sk_buff {
	__be16 protocol;
	struct { __be32 saddr; } ip4;
	struct { struct in6_addr saddr; } ip6;
};
#define ip_hdr(skb) (&(skb)->ip4)
#define ipv6_hdr(skb) (&(skb)->ip6)
struct netlink_ext_ack { int unused; };
struct br_mdb_entry { int ifindex; };
struct br_mdb_config {
	struct net_bridge *br;
	struct br_mdb_entry *entry;
	struct br_ip group;
};

static _Thread_local unsigned int rcu_depth, mcast_depth, gate_depth;
static bool rtnl_held=true;
static pthread_mutex_t rtl9617c_switch_lock=PTHREAD_MUTEX_INITIALIZER;
static unsigned int quiesces, rebuilds, notifications, cases;
static atomic_bool hardware_open;
static struct net_device master;
static struct net network, other_network;
static struct net_bridge bridge;
static struct rtl9617c_switch_guard guard;

static struct net *dev_net(const struct net_device *d) { return d->net; }
static struct net_bridge *netdev_priv(const struct net_device *d) { return d->br; }
static bool netif_is_bridge_master(const struct net_device *d) { return d->master; }
static bool netif_running(const struct net_device *d) { return d->running; }
static bool br_opt_get(const struct net_bridge *b, unsigned int option)
{
	return !!(b->options & BIT(option));
}
static void br_opt_toggle(struct net_bridge *b,unsigned int option,bool value)
{
	assert(mcast_depth && network.rtl9617c_switch.active && !atomic_load(&hardware_open));
	if(value)b->options|=BIT(option);else b->options&=~BIT(option);
}
static void write_seqcount_begin(int *seq)
{
	assert(mcast_depth && network.rtl9617c_switch.active && !atomic_load(&hardware_open));
	assert(!(*seq&1));++*seq;
}
static void write_seqcount_end(int *seq) { assert(*seq&1);++*seq; }
static struct net_bridge_vlan_group *br_vlan_group(struct net_bridge *b)
{
	assert(rtnl_held); return &b->vlan_group;
}
static struct net_bridge_vlan *br_vlan_find(struct net_bridge_vlan_group *vg,u16 vid)
{
	return vg->vlan && vg->vlan->vid==vid ? vg->vlan : NULL;
}
#define ASSERT_RTNL() assert(rtnl_held)
#define rcu_read_lock() (++rcu_depth)
#define rcu_read_unlock() do { assert(rcu_depth); --rcu_depth; } while(0)
#define spin_lock_bh(p) do { assert(!mcast_depth); assert(!pthread_mutex_lock(p)); ++mcast_depth; } while(0)
#define spin_unlock_bh(p) do { assert(mcast_depth==1); --mcast_depth; assert(!pthread_mutex_unlock(p)); } while(0)
#define spin_lock(p) spin_lock_bh(p)
#define spin_unlock(p) spin_unlock_bh(p)
#define spin_lock_irqsave(p,f) do { (f)=0; assert(!pthread_mutex_lock(p)); ++gate_depth; } while(0)
#define spin_unlock_irqrestore(p,f) do { (void)(f); assert(gate_depth==1); --gate_depth; assert(!pthread_mutex_unlock(p)); } while(0)
#define mlock_dereference(p,b) (assert(mcast_depth), (p))

static bool rtl9617c_switch_related(struct net *net,struct net_device *dev)
{
	assert(gate_depth && rcu_depth);
	return guard.registered && guard.net==net && dev==&master;
}
static void rtl9617c_switch_quiesce(struct net *net)
{
	assert(gate_depth && net==&network); ++quiesces;
	atomic_store(&hardware_open,false);
}
static void rtl9617c_switch_rebuild(struct net *net)
{
	assert(gate_depth && net==&network); ++rebuilds;
	assert(!atomic_load(&hardware_open));
}

/* PRODUCTION_GUARD is inserted here. */

static void policy_cleanup(struct net **net) { rtl9617c_switch_policy_end(*net); }
#define CLASS(name,var) struct net *var __attribute__((cleanup(policy_cleanup))) = rtl9617c_switch_policy_begin
static struct net_bridge_mdb_entry *br_mdb_ip_get(struct net_bridge *br,const struct br_ip *key)
{
	struct net_bridge_mdb_entry *mp;
	assert(mcast_depth);
	hlist_for_each_entry(mp,&br->mdb_list,mdb_node)
		if (!memcmp(&mp->addr,key,sizeof(*key))) return mp;
	return NULL;
}
static void br_mdb_notify(struct net_device *dev,struct net_bridge_mdb_entry *mp,
			  struct net_bridge_port_group *pg,int event)
{
	(void)mp;(void)pg;(void)event;
	assert(dev==&master && mcast_depth && network.rtl9617c_switch.active);
	assert(!atomic_load(&hardware_open)); ++notifications;
}
static void br_multicast_star_g_host_state(struct net_bridge_mdb_entry *mp)
{
	(void)mp; /* Host mutation tests intentionally use S,G, not this dispatch. */
	assert(false);
}
static void br_multicast_del_mdb_entry(struct net_bridge_mdb_entry *mp)
{
	assert(mcast_depth && network.rtl9617c_switch.active);
	assert(!atomic_load(&hardware_open)); hlist_del_init(&mp->mdb_node);
}
static void br_multicast_del_pg(struct net_bridge_mdb_entry *mp,
			       struct net_bridge_port_group *pg,
			       struct net_bridge_port_group **pp)
{
	(void)mp;(void)pg;(void)pp;
	assert(false); /* Non-host user deletions are covered by writer-scope audit. */
}
