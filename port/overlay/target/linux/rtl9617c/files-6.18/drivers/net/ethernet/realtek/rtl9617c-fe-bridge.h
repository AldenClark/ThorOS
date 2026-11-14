/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Autonomous MAC/VLAN bridge learning is not a policy authorization.
 *
 * One frame reaching NF_BR_POST_ROUTING proves only that this frame was
 * accepted. A MAC/EtherType rule also matches different IP addresses, TCP/UDP
 * ports, connection states and future policy changes, bypassing bridge
 * netfilter and tc without any explicit flow-add decision.
 *
 * Keep ordinary Linux bridge forwarding. Only the flower callbacks admitted
 * by the nftables flowtable backend may create hardware rules. Do not register
 * wire/bridge packet hooks, allocate skb extensions, or run an observation
 * workqueue here. Reintroducing L2 offload requires an explicit policy compiler
 * and matching invalidation contract, not a user-controlled bypass switch.
 *
 * These no-allocation compatibility entry points keep FE lifecycle/status
 * callers stable while the unsafe learner is removed.
 */
static struct rtl_fe_bridge *fe_bridge_start(struct rtl_fe *fe)
{
 (void)fe;
 return NULL;
}

static void fe_bridge_stop(struct rtl_fe_bridge *bridge)
{
 (void)bridge;
}

static ssize_t fe_bridge_stats(struct rtl_fe_bridge *bridge, char *buffer, size_t bytes)
{
 (void)bridge;
 return scnprintf(buffer,bytes,
  "bridge_autolearn=0 bridge_policy=explicit_flowtable_only "
  "bridge_pending=0 bridge_queued=0 bridge_coalesced=0 bridge_overflow=0 "
  "bridge_work=0 bridge_maintenance=0\n");
}
