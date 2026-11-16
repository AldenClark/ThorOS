/* Host substrate ONLY. The snapshot implementation and bridge predicates
 * below are read from the real prepared kernel by test_fe_mdb.py. */
#include <stddef.h>
#include <pthread.h>
#undef htons
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) __builtin_bswap16((uint16_t)(x))
#else
#define htons(x) ((uint16_t)(x))
#endif
#define VLAN_VID_MASK 4095
#define U32_MAX UINT32_MAX
#define MCAST_EXCLUDE 0
#define MCAST_INCLUDE 1
#define EXPORT_SYMBOL_GPL(x)
#define time_before(a, b) ((long)((a) - (b)) < 0)
#define time_after_eq(a, b) ((long)((a) - (b)) >= 0)
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define ether_addr_copy(d, s) memcpy(d, s, ETH_ALEN)
#define BR_VLFLAG_MCAST_ENABLED BIT(2)
#define BR_VLFLAG_GLOBAL_MCAST_ENABLED BIT(3)
enum { BROPT_VLAN_ENABLED, BROPT_MCAST_VLAN_SNOOPING_ENABLED,
       BROPT_MULTICAST_ENABLED, BROPT_HAS_IPV6_ADDR };
struct net_bridge;
struct net_bridge_vlan;
struct net_bridge_port_group;
/* SNAPSHOT_TYPES */
static bool real_snapshot_enabled;
static unsigned long jiffies;
static unsigned int snapshot_lock_depth, snapshot_rcu_depth;
static inline bool timer_pending(const struct timer_list *timer) { return timer->pending; }
static inline bool ipv4_is_zeronet(__be32 address) { return !(ntohl(address) & 0xff000000U); }
static inline bool ipv6_addr_any(const struct in6_addr *address)
{
	const struct in6_addr zero = {};
	return !memcmp(address, &zero, sizeof(zero));
}
static inline void hlist_add_head(struct hlist_node *node, struct hlist_head *head)
{
	assert(!node->pprev);
	node->next = head->first;
	if (node->next) node->next->pprev = &node->next;
	head->first = node; node->pprev = &head->first;
}
#define hlist_entry_safe(n, t, m) ((n) ? container_of(n, t, m) : NULL)
#define hlist_for_each_entry(p, h, m) \
	for ((p) = hlist_entry_safe((h)->first, __typeof__(*(p)), m); (p); \
	     (p) = hlist_entry_safe((p)->m.next, __typeof__(*(p)), m))
static inline struct net_bridge *netdev_priv(const struct net_device *dev) { return dev->br; }
static inline bool br_opt_get(const struct net_bridge *br, unsigned option) { return !!(br->options & BIT(option)); }
static inline struct net_bridge_vlan_group *br_vlan_group(struct net_bridge *br) { return &br->vlan_group; }
static inline struct net_bridge_vlan *br_vlan_find(struct net_bridge_vlan_group *group, u16 vid)
{
	return group->vlan && group->vlan->vid == vid ? group->vlan : NULL;
}
#define rcu_read_lock() (++snapshot_rcu_depth)
#define rcu_read_unlock() do { assert(snapshot_rcu_depth); --snapshot_rcu_depth; } while (0)
#define spin_lock_bh(lock) do { assert(!snapshot_lock_depth); assert(!pthread_mutex_lock(lock)); ++snapshot_lock_depth; } while (0)
#define spin_unlock_bh(lock) do { assert(snapshot_lock_depth == 1); --snapshot_lock_depth; assert(!pthread_mutex_unlock(lock)); } while (0)
#define mlock_dereference(p, b) (assert(snapshot_lock_depth), (p))
