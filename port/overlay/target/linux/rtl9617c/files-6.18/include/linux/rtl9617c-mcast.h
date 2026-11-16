/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_RTL9617C_MCAST_H
#define _LINUX_RTL9617C_MCAST_H

#include <linux/kconfig.h>
#include <linux/skbuff.h>
#include <linux/types.h>

struct net_device;

/* A verified MCE CPU copy is NOT a generic switchdev forwarding mark.
 * The hardware has already emitted its complete native-port egress set.
 * Preserve bridge ingress, VLAN-self and local-receive policy, but never
 * reflood the copy under a later bridge topology.  All identities below
 * are scalar: neither a queued skb nor an skb clone retains a driver or
 * net_device pointer after device/namespace teardown.
 *
 * owner is a boot-lifetime, never-reused guard identity.  generation is
 * the exact pre-publication policy epoch of the immutable MCE recipe, not
 * the current generation sampled when the packet happens to reach NAPI.
 */
struct rtl9617c_mcast_copy {
	u64 owner;
	u64 generation;
	int ingress_ifindex;
	int master_ifindex;
	u16 vid;
	u16 token;
};

#if IS_ENABLED(CONFIG_RTL9617C_SWITCH_GUARD)
bool rtl9617c_mcast_copy_valid(const struct sk_buff *skb,
			     const struct net_device *ingress,
			     const struct net_device *master);

static inline bool rtl9617c_mcast_copy_present(const struct sk_buff *skb)
{
	return skb_ext_exist(skb, SKB_EXT_RTL9617C_MCAST);
}

static inline void rtl9617c_mcast_copy_clear(struct sk_buff *skb)
{
	skb_ext_del(skb, SKB_EXT_RTL9617C_MCAST);
}
#else
static inline bool rtl9617c_mcast_copy_valid(const struct sk_buff *skb,
					   const struct net_device *ingress,
					   const struct net_device *master)
{
	return false;
}

static inline bool rtl9617c_mcast_copy_present(const struct sk_buff *skb)
{
	return false;
}

static inline void rtl9617c_mcast_copy_clear(struct sk_buff *skb) { }
#endif
#endif
