/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_RTL9617C_SWITCH_H
#define _LINUX_RTL9617C_SWITCH_H

#include <linux/cleanup.h>
#include <linux/errno.h>
#include <linux/kconfig.h>
#include <linux/list.h>
#include <linux/types.h>

struct net;
struct net_device;

/* Control-plane state only; never consulted on the packet fast path. */
struct rtl9617c_switch_net {
	u64 generation;
	unsigned int active;
	unsigned int nf_blockers;
	unsigned int tcx_blockers;
	unsigned int xdp_blockers;
	bool poisoned;
};

/* All callbacks run with the core gate spinlock held and IRQs disabled.
 * quiesce/arm may only perform bounded direct MMIO and readback.  rebuild
 * may only queue work.  No callback may acquire RTNL, a mutex or this API.
 * Quiesce stops NEW hardware admission; it does not claim to drain TX FIFOs.
 */
struct rtl9617c_switch_guard_ops {
	void (*quiesce)(void *priv);
	void (*rebuild)(void *priv);
	bool (*arm)(void *priv);
};

struct rtl9617c_switch_guard {
	struct list_head list;
	struct net *net;
	const struct rtl9617c_switch_guard_ops *ops;
	void *priv;
	bool registered;
};

#if IS_REACHABLE(CONFIG_BRIDGE) && IS_ENABLED(CONFIG_NET_SWITCHDEV)
/* RTNL held.  Only eligibility; table/port/VLAN hardware programming remains
 * the driver's responsibility.  BUM/control frames must stay on the CPU.
 */
bool br_rtl9617c_l2_eligible(const struct net_device *master);
bool br_rtl9617c_l2_port_eligible(const struct net_device *port);
#else
static inline bool br_rtl9617c_l2_eligible(const struct net_device *master)
{
	return false;
}
static inline bool br_rtl9617c_l2_port_eligible(const struct net_device *port)
{
	return false;
}
#endif

#if IS_REACHABLE(CONFIG_BRIDGE)
/* Delete only a still-owned dynamic HW-learned VID-0 entry.  Unlike a broad
 * DEL_TO_BRIDGE event this must never remove a newer user/static/local row.
 */
bool br_rtl9617c_fdb_forget(const struct net_device *port,
			    const unsigned char *addr);
int br_rtl9617c_fdb_learn(const struct net_device *port,
			 const unsigned char *addr,
			 struct rtl9617c_switch_guard *guard, u64 generation);
#else
static inline bool br_rtl9617c_fdb_forget(const struct net_device *port,
				       const unsigned char *addr)
{
	return false;
}
static inline int br_rtl9617c_fdb_learn(const struct net_device *port,
				      const unsigned char *addr,
				      struct rtl9617c_switch_guard *guard,
				      u64 generation)
{
	return -EOPNOTSUPP;
}
#endif

#if IS_ENABLED(CONFIG_RTL9617C_SWITCH_GUARD)
int rtl9617c_switch_guard_register(struct rtl9617c_switch_guard *guard,
				 struct net *net,
				 const struct rtl9617c_switch_guard_ops *ops,
				 void *priv);
void rtl9617c_switch_guard_unregister(struct rtl9617c_switch_guard *guard);
u64 rtl9617c_switch_guard_generation(struct rtl9617c_switch_guard *guard);
bool rtl9617c_switch_guard_blocked(struct rtl9617c_switch_guard *guard);
bool rtl9617c_switch_guard_try_arm(struct rtl9617c_switch_guard *guard,
				 u64 generation);
void rtl9617c_switch_guard_invalidate(struct rtl9617c_switch_guard *guard);
/* Worker-only, with its configuration mutex held: closes without advancing
 * the epoch or queuing itself.  The worker must still finish via try_arm.
 */
void rtl9617c_switch_guard_quiesce(struct rtl9617c_switch_guard *guard);
/* Call with the bridge hash lock already held, never in reverse order.
 * publish may only update the locked FDB (GFP_ATOMIC allocation is allowed).
 * Notifications and any nested guard calls must happen AFTER this returns.
 */
int rtl9617c_switch_guard_publish(struct rtl9617c_switch_guard *guard,
				u64 generation, int (*publish)(void *), void *context);

/* BEGIN must precede publication; END follows the complete mutation, even
 * on an error/rollback path.  Nested and concurrent changes are supported.
 * NULL is a no-op, for hardware-originated FDB feedback (not new policy).
 */
struct net *rtl9617c_switch_policy_begin(struct net_device *dev);
void rtl9617c_switch_policy_end(struct net *net);
void rtl9617c_switch_nf_block(struct net *net);
void rtl9617c_switch_nf_unblock(struct net *net);
void rtl9617c_switch_tcx_change(struct net_device *dev, bool old, bool new);
void rtl9617c_switch_xdp_change(struct net_device *dev, bool old, bool new);
struct net *rtl9617c_switch_move_begin(struct net_device *dev, struct net *net);
bool rtl9617c_switch_device_has_policy(const struct net_device *dev);
#else
static inline struct net *rtl9617c_switch_policy_begin(struct net_device *dev)
{
	return NULL;
}
static inline int
rtl9617c_switch_guard_publish(struct rtl9617c_switch_guard *guard,
			     u64 generation, int (*publish)(void *), void *context)
{
	return -EOPNOTSUPP;
}
static inline void rtl9617c_switch_policy_end(struct net *net) { }
static inline void rtl9617c_switch_nf_block(struct net *net) { }
static inline void rtl9617c_switch_nf_unblock(struct net *net) { }
static inline void rtl9617c_switch_tcx_change(struct net_device *dev,
					    bool old, bool new) { }
static inline void rtl9617c_switch_xdp_change(struct net_device *dev,
					    bool old, bool new) { }
static inline struct net *rtl9617c_switch_move_begin(struct net_device *dev,
						  struct net *net)
{
	return NULL;
}
#endif

/* A scope keeps worker rearming disabled across all return/error paths.
 * Save the namespace, not the possibly detached/freed bridge port object.
 */
DEFINE_CLASS(rtl9617c_switch_policy, struct net *,
	     rtl9617c_switch_policy_end(_T),
	     rtl9617c_switch_policy_begin(dev), struct net_device *dev);

#endif
