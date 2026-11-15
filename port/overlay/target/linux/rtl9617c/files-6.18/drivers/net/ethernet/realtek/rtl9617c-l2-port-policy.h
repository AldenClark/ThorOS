/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTL9617C_L2_PORT_POLICY_H
#define RTL9617C_L2_PORT_POLICY_H

#include "rtl9617c-l2-format.h"

/* RTL8277C aal_port.c: aal_port_mmshp_check_set() addresses a row by
 * logical SOURCE and its bitmap selects logical DESTINATIONS. This is
 * different from the 16-bit VLAN membership-ID map and from MC vectors.
 * Only the five native LAN sources are owned by this policy compiler.
 */
#define RTL_L2_POLICY_LAN_MASK 0x1fU
#define RTL_L2_POLICY_CPU 16U
#define RTL_L2_POLICY_LOCAL_L3 25U
#define RTL_L2_POLICY_ARB_EXT 0x160cU
#define RTL_L2_POLICY_MC_MEMBERSHIP_CHECK (1U << 0)
#define RTL_L2_POLICY_REDIRECT_ENABLE (1U << 10)

struct rtl_l2_port_policy {
	unsigned int stp;
	unsigned int members[2];
};

static inline int
rtl_l2_port_policy_build(unsigned int native, unsigned int learning,
			 unsigned int isolated, unsigned int source,
			 unsigned int local_target,
			 struct rtl_l2_port_policy *policy)
{
	struct rtl_l2_port_policy next;
	unsigned int destinations;

	if (!policy || !native || (native & ~RTL_L2_POLICY_LAN_MASK) ||
	    ((learning | isolated) & ~native) || source >= 5 ||
	    !(native & (1U << source)) ||
	    (local_target != RTL_L2_POLICY_CPU &&
	     local_target != RTL_L2_POLICY_LOCAL_L3))
		return -EINVAL;

	next.stp = learning & (1U << source) ?
		RTL_L2_STP_FORWARD_AND_LEARN : RTL_L2_STP_FORWARD_NO_LEARN;
	destinations = native & ~(1U << source);
	/* Linux BR_ISOLATED blocks only isolated -> isolated forwarding.
	 * Isolated -> ordinary and ordinary -> isolated remain permitted.
	 * Local delivery and software forwarding must remain reachable.
	 */
	if (isolated & (1U << source))
		destinations &= ~isolated;
	next.members[0] = destinations | (1U << RTL_L2_POLICY_CPU) |
		(1U << local_target);
	next.members[1] = 0;
	*policy = next;
	return 0;
}

static inline int rtl_l2_port_policy_mc_check(unsigned int arb_ext)
{
	/* A failed/all-ones MMIO read must not look like an enabled checker. */
	return arb_ext != ~0U &&
		(arb_ext & RTL_L2_POLICY_MC_MEMBERSHIP_CHECK);
}

#endif
