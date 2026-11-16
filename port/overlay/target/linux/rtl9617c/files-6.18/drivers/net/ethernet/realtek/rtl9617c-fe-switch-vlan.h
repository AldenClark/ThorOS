/* SPDX-License-Identifier: GPL-2.0-only */
/* RTNL/FE-mutex control-plane extension for the cold-owned IVL backend.
 * Included after the common topology snapshot. This is consumed by the
 * production worker; it does not authorize an unprogrammed VLAN plan. */
#ifndef RTL9617C_FE_SWITCH_VLAN_H
#define RTL9617C_FE_SWITCH_VLAN_H

static enum fe_switch_reason
fe_switch_vlan_snapshot(struct rtl_fe_bridge *sw, struct fe_switch_plan *plan,
			 enum fe_switch_reason legacy)
{
	struct fe_switch_plan check = *plan;
	struct bridge_vlan_info info;
	struct rtl_l2_vlan_spec spec;
	struct net_device *master, *dev;
	unsigned int port, vid, slot;
	bool useful = false;
	int ret;

	sw->vlan_domain = false;
	sw->master_count = 0;
	memset(sw->masters, 0, sizeof(sw->masters));
	memset(&sw->vlans, 0, sizeof(sw->vlans));
	if (!fe_native_l2_ivl(sw->fe))
		return legacy;
	/* The legacy untagged backend depends on the cold SVL namespace. An
	 * immutable IVL boot choice must never silently run it in a new mode. */
	if (!plan->vlan_filtering)
		return FE_SWITCH_VLAN_UNSUPPORTED;
	check.vlan_filtering = false;
	check.multi_bridge = false;
	legacy = fe_switch_plan_validate(&check);
	if (legacy != FE_SWITCH_OK)
		return legacy;

	/* Include every member in bridge identity and VLAN conflict checks,
	 * not only the currently forwarding subset. A down port may carry a
	 * sticky FDB destination which still needs CPU-only key protection. */
	for (port = 0; port < FE_LAN_PORTS; port++) {
		dev = sw->ports[port];
		if (!dev)
			continue;
		master = netdev_master_upper_dev_get(dev);
		if (!master || !netif_is_bridge_master(master))
			continue;
		if (!br_vlan_enabled(master) ||
		    !br_rtl9617c_l2_vlan_port_eligible(dev))
			return FE_SWITCH_VLAN_UNSUPPORTED;
		for (slot = 0; slot < sw->master_count; slot++)
			if (sw->masters[slot] == master)
				break;
		if (slot == sw->master_count) {
			if (slot == FE_LAN_PORTS)
				return FE_SWITCH_MULTI_BRIDGE;
			sw->masters[sw->master_count++] = master;
		}
		for (vid = 1; vid < RTL_L2_VLAN_IDS - 1; vid++) {
			ret = br_vlan_get_info(dev, vid, &info);
			if (ret == -ENOENT)
				continue;
			if (ret || info.vid != vid ||
			    (info.flags & (BRIDGE_VLAN_INFO_PVID |
					   BRIDGE_VLAN_INFO_UNTAGGED)))
				return FE_SWITCH_VLAN_UNSUPPORTED;
			memset(&spec, 0, sizeof(spec));
			spec.vid = vid;
			spec.bridge = slot + 1;
			spec.members = BIT(port);
			if ((plan->ports & BIT(port)) &&
			    plan->state[port] == BR_STATE_FORWARDING) {
				spec.forwarding = BIT(port);
				if (plan->flags[port] & BR_LEARNING)
					spec.learning = BIT(port);
			}
			if (plan->flags[port] & BR_ISOLATED)
				spec.isolated = BIT(port);
			ret = rtl_l2_vlan_plan_add(&sw->vlans, &spec);
			if (ret)
				return ret == -EADDRINUSE ? FE_SWITCH_MULTI_BRIDGE :
					FE_SWITCH_VLAN_UNSUPPORTED;
		}
	}
	for (slot = 0; slot < sw->vlans.count; slot++)
		if (hweight32(sw->vlans.vlans[slot].forwarding) >= 2)
			useful = true;
	if (!useful)
		return FE_SWITCH_NO_BRIDGE;
	sw->vlan_domain = true;
	return FE_SWITCH_OK;
}

/* All native bridges share one ASIC ageing register. A topology change on
 * only one bridge is not permission to shorten every other bridge's timer. */
static int fe_switch_age_ticks(struct rtl_fe_bridge *sw, unsigned long *ticks)
{
	unsigned long next;
	unsigned int i;
	int ret;

	if (!sw->vlan_domain)
		return br_rtl9617c_fdb_hold_time(sw->master, ticks);
	if (!sw->master_count)
		return -ENODEV;
	for (i = 0; i < sw->master_count; i++) {
		ret = br_rtl9617c_fdb_hold_time(sw->masters[i], &next);
		if (ret)
			return ret;
		if (i && next != *ticks)
			return -EOPNOTSUPP;
		*ticks = next;
	}
	return 0;
}

static bool fe_switch_vlan_replay_member(struct rtl_fe_bridge *sw,
			 const struct switchdev_notifier_fdb_info *info, int port)
{
	const struct rtl_l2_vlan_spec *vlan = fe_switch_vlan_find(sw, info->vid);
	struct net_device *master;

	if (!vlan)
		return false;
	master = fe_switch_bridge_for_vid(sw, info->vid);
	if (!master)
		return false;
	if (port >= 0)
		return (vlan->members & BIT(port)) &&
		       netdev_master_upper_dev_get(sw->ports[port]) == master;
	return info->is_local && info->info.dev == master;
}

#endif
