// SPDX-License-Identifier: GPL-2.0-only
/* Synchronous pre-publication admission gate for the RTL9617C switch.
 *
 * The bridge remains policy owner.  The switch driver rebuilds its tables
 * in process context, then atomically compares the snapshot generation and
 * opens admission.  A configuration BEGIN closes admission before Linux
 * makes a new decision visible.  END never opens admission itself.
 *
 * Lock order: RTNL -> driver configuration mutex -> gate lock, or
 * nf_hook_mutex -> gate lock, or bridge spinlock -> gate lock.  In particular,
 * no gate callback acquires any of these outer locks.  Epoch/veto state is
 * per namespace and exists before a driver registers, so late probe cannot
 * miss an already installed firewall, TCX or XDP policy.
 */
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/netdevice.h>
#include <linux/rtl9617c-switch.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <net/net_namespace.h>
#include <net/sch_generic.h>

static DEFINE_SPINLOCK(rtl9617c_switch_lock);
static LIST_HEAD(rtl9617c_switch_guards);

static bool rtl9617c_switch_net_blocked(const struct rtl9617c_switch_net *state)
{
	return state->poisoned || state->active || state->nf_blockers ||
	       state->tcx_blockers || state->xdp_blockers;
}

static void rtl9617c_switch_quiesce(struct net *net)
{
	struct rtl9617c_switch_guard *guard;

	list_for_each_entry(guard, &rtl9617c_switch_guards, list)
		if (guard->net == net)
			guard->ops->quiesce(guard->priv);
}

static void rtl9617c_switch_rebuild(struct net *net)
{
	struct rtl9617c_switch_guard *guard;

	list_for_each_entry(guard, &rtl9617c_switch_guards, list)
		if (guard->net == net)
			guard->ops->rebuild(guard->priv);
}

static void rtl9617c_switch_advance(struct net *net)
{
	if (unlikely(++net->rtl9617c_switch.generation == 0))
		net->rtl9617c_switch.poisoned = true;
}

int rtl9617c_switch_guard_register(struct rtl9617c_switch_guard *guard,
				 struct net *net,
				 const struct rtl9617c_switch_guard_ops *ops,
				 void *priv)
{
	unsigned long flags;

	if (!net || !ops || !ops->quiesce || !ops->rebuild || !ops->arm)
		return -EINVAL;

	spin_lock_irqsave(&rtl9617c_switch_lock, flags);
	if (guard->registered) {
		spin_unlock_irqrestore(&rtl9617c_switch_lock, flags);
		return -EBUSY;
	}
	guard->net = get_net(net);
	guard->ops = ops;
	guard->priv = priv;
	guard->registered = true;
	list_add_tail(&guard->list, &rtl9617c_switch_guards);
	ops->quiesce(priv);
	ops->rebuild(priv);
	spin_unlock_irqrestore(&rtl9617c_switch_lock, flags);
	return 0;
}
EXPORT_SYMBOL_GPL(rtl9617c_switch_guard_register);

void rtl9617c_switch_guard_unregister(struct rtl9617c_switch_guard *guard)
{
	struct net *net = NULL;
	unsigned long flags;

	spin_lock_irqsave(&rtl9617c_switch_lock, flags);
	if (guard->registered) {
		guard->ops->quiesce(guard->priv);
		list_del_init(&guard->list);
		guard->registered = false;
		net = guard->net;
		guard->net = NULL;
	}
	spin_unlock_irqrestore(&rtl9617c_switch_lock, flags);
	if (net)
		put_net(net);
}
EXPORT_SYMBOL_GPL(rtl9617c_switch_guard_unregister);

u64 rtl9617c_switch_guard_generation(struct rtl9617c_switch_guard *guard)
{
	unsigned long flags;
	u64 generation = 0;

	spin_lock_irqsave(&rtl9617c_switch_lock, flags);
	if (guard->registered)
		generation = guard->net->rtl9617c_switch.generation;
	spin_unlock_irqrestore(&rtl9617c_switch_lock, flags);
	return generation;
}
EXPORT_SYMBOL_GPL(rtl9617c_switch_guard_generation);

bool rtl9617c_switch_guard_blocked(struct rtl9617c_switch_guard *guard)
{
	unsigned long flags;
	bool blocked = true;

	spin_lock_irqsave(&rtl9617c_switch_lock, flags);
	if (guard->registered)
		blocked = rtl9617c_switch_net_blocked(&guard->net->rtl9617c_switch);
	spin_unlock_irqrestore(&rtl9617c_switch_lock, flags);
	return blocked;
}
EXPORT_SYMBOL_GPL(rtl9617c_switch_guard_blocked);

bool rtl9617c_switch_guard_try_arm(struct rtl9617c_switch_guard *guard,
				 u64 generation)
{
	struct rtl9617c_switch_net *state;
	unsigned long flags;
	bool armed = false;

	spin_lock_irqsave(&rtl9617c_switch_lock, flags);
	if (!guard->registered)
		goto out;
	state = &guard->net->rtl9617c_switch;
	if (rtl9617c_switch_net_blocked(state) || state->generation != generation)
		goto out;
	armed = guard->ops->arm(guard->priv);
	if (!armed)
		guard->ops->quiesce(guard->priv);
out:
	spin_unlock_irqrestore(&rtl9617c_switch_lock, flags);
	return armed;
}
EXPORT_SYMBOL_GPL(rtl9617c_switch_guard_try_arm);

void rtl9617c_switch_guard_invalidate(struct rtl9617c_switch_guard *guard)
{
	unsigned long flags;

	spin_lock_irqsave(&rtl9617c_switch_lock, flags);
	if (guard->registered) {
		rtl9617c_switch_advance(guard->net);
		rtl9617c_switch_quiesce(guard->net);
		rtl9617c_switch_rebuild(guard->net);
	}
	spin_unlock_irqrestore(&rtl9617c_switch_lock, flags);
}
EXPORT_SYMBOL_GPL(rtl9617c_switch_guard_invalidate);

void rtl9617c_switch_guard_quiesce(struct rtl9617c_switch_guard *guard)
{
	unsigned long flags;

	spin_lock_irqsave(&rtl9617c_switch_lock, flags);
	if (guard->registered)
		guard->ops->quiesce(guard->priv);
	spin_unlock_irqrestore(&rtl9617c_switch_lock, flags);
}
EXPORT_SYMBOL_GPL(rtl9617c_switch_guard_quiesce);

int rtl9617c_switch_guard_publish(struct rtl9617c_switch_guard *guard,
				u64 generation, int (*publish)(void *), void *context)
{
	struct rtl9617c_switch_net *state;
	unsigned long flags;
	int ret = -EAGAIN;

	spin_lock_irqsave(&rtl9617c_switch_lock, flags);
	if (!guard->registered)
		goto out;
	state = &guard->net->rtl9617c_switch;
	if (!rtl9617c_switch_net_blocked(state) && state->generation == generation)
		ret = publish(context);
out:
	spin_unlock_irqrestore(&rtl9617c_switch_lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(rtl9617c_switch_guard_publish);

struct net *rtl9617c_switch_policy_begin(struct net_device *dev)
{
	struct net *net;
	unsigned long flags;

	if (!dev)
		return NULL;
	net = dev_net(dev);
	spin_lock_irqsave(&rtl9617c_switch_lock, flags);
	if (unlikely(++net->rtl9617c_switch.active == 0))
		net->rtl9617c_switch.poisoned = true;
	rtl9617c_switch_advance(net);
	rtl9617c_switch_quiesce(net);
	spin_unlock_irqrestore(&rtl9617c_switch_lock, flags);
	return net;
}
EXPORT_SYMBOL_GPL(rtl9617c_switch_policy_begin);

void rtl9617c_switch_policy_end(struct net *net)
{
	unsigned long flags;

	if (!net)
		return;
	spin_lock_irqsave(&rtl9617c_switch_lock, flags);
	if (WARN_ON_ONCE(!net->rtl9617c_switch.active)) {
		net->rtl9617c_switch.poisoned = true;
		rtl9617c_switch_quiesce(net);
	} else {
		net->rtl9617c_switch.active--;
	}
	rtl9617c_switch_advance(net);
	rtl9617c_switch_rebuild(net);
	spin_unlock_irqrestore(&rtl9617c_switch_lock, flags);
}
EXPORT_SYMBOL_GPL(rtl9617c_switch_policy_end);

/* Called before hook publication / after a successful real hook removal.
 * nf_hook_mutex serializes the hook lifetime, the gate lock serializes arm.
 */
void rtl9617c_switch_nf_block(struct net *net)
{
	unsigned long flags;

	spin_lock_irqsave(&rtl9617c_switch_lock, flags);
	if (unlikely(++net->rtl9617c_switch.nf_blockers == 0))
		net->rtl9617c_switch.poisoned = true;
	rtl9617c_switch_advance(net);
	rtl9617c_switch_quiesce(net);
	rtl9617c_switch_rebuild(net);
	spin_unlock_irqrestore(&rtl9617c_switch_lock, flags);
}
EXPORT_SYMBOL_GPL(rtl9617c_switch_nf_block);

void rtl9617c_switch_nf_unblock(struct net *net)
{
	unsigned long flags;

	spin_lock_irqsave(&rtl9617c_switch_lock, flags);
	if (WARN_ON_ONCE(!net->rtl9617c_switch.nf_blockers)) {
		net->rtl9617c_switch.poisoned = true;
		rtl9617c_switch_quiesce(net);
	} else {
		net->rtl9617c_switch.nf_blockers--;
	}
	rtl9617c_switch_advance(net);
	rtl9617c_switch_rebuild(net);
	spin_unlock_irqrestore(&rtl9617c_switch_lock, flags);
}
EXPORT_SYMBOL_GPL(rtl9617c_switch_nf_unblock);

static void rtl9617c_switch_veto_change(struct net_device *dev,
				      unsigned int *count, bool old, bool new)
{
	struct net *net = dev_net(dev);
	unsigned long flags;

	if (old == new)
		return;
	spin_lock_irqsave(&rtl9617c_switch_lock, flags);
	if (new) {
		if (unlikely(++*count == 0))
			net->rtl9617c_switch.poisoned = true;
	} else if (WARN_ON_ONCE(!*count)) {
		net->rtl9617c_switch.poisoned = true;
	} else {
		--*count;
	}
	rtl9617c_switch_advance(net);
	rtl9617c_switch_quiesce(net);
	rtl9617c_switch_rebuild(net);
	spin_unlock_irqrestore(&rtl9617c_switch_lock, flags);
}

void rtl9617c_switch_tcx_change(struct net_device *dev, bool old, bool new)
{
	rtl9617c_switch_veto_change(dev, &dev_net(dev)->rtl9617c_switch.tcx_blockers,
				   old, new);
}
EXPORT_SYMBOL_GPL(rtl9617c_switch_tcx_change);

void rtl9617c_switch_xdp_change(struct net_device *dev, bool old, bool new)
{
	rtl9617c_switch_veto_change(dev, &dev_net(dev)->rtl9617c_switch.xdp_blockers,
				   old, new);
}
EXPORT_SYMBOL_GPL(rtl9617c_switch_xdp_change);

/* TCX/XDP attachments survive a netns move, unlike a removed netfilter hook.
 * Transfer their vetoes before dev_net_set(), with both namespaces active.
 * The caller ends both scopes after publishing the new namespace.
 */
struct net *rtl9617c_switch_move_begin(struct net_device *dev, struct net *net)
{
	struct net *old = dev_net(dev);
	unsigned int tcx = 0, xdp = dev_xdp_prog_count(dev);
	unsigned long flags;

	ASSERT_RTNL();
#ifdef CONFIG_NET_XGRESS
	tcx = !!rcu_access_pointer(dev->tcx_ingress) +
	      !!rcu_access_pointer(dev->tcx_egress);
#endif
	spin_lock_irqsave(&rtl9617c_switch_lock, flags);
	if (unlikely(++old->rtl9617c_switch.active == 0))
		old->rtl9617c_switch.poisoned = true;
	if (unlikely(++net->rtl9617c_switch.active == 0))
		net->rtl9617c_switch.poisoned = true;
	if (WARN_ON_ONCE(old->rtl9617c_switch.tcx_blockers < tcx ||
			 old->rtl9617c_switch.xdp_blockers < xdp)) {
		old->rtl9617c_switch.poisoned = true;
		net->rtl9617c_switch.poisoned = true;
	} else {
		old->rtl9617c_switch.tcx_blockers -= tcx;
		old->rtl9617c_switch.xdp_blockers -= xdp;
		net->rtl9617c_switch.tcx_blockers += tcx;
		net->rtl9617c_switch.xdp_blockers += xdp;
		if (net->rtl9617c_switch.tcx_blockers < tcx ||
		    net->rtl9617c_switch.xdp_blockers < xdp)
			net->rtl9617c_switch.poisoned = true;
	}
	rtl9617c_switch_advance(old);
	rtl9617c_switch_advance(net);
	rtl9617c_switch_quiesce(old);
	rtl9617c_switch_quiesce(net);
	spin_unlock_irqrestore(&rtl9617c_switch_lock, flags);
	return old;
}
EXPORT_SYMBOL_GPL(rtl9617c_switch_move_begin);

static bool rtl9617c_switch_qdisc_has_policy(const struct Qdisc *qdisc)
{
	const char *id = qdisc->ops->id;

	if (qdisc->handle || (qdisc->flags & TCQ_F_SW_POLICY))
		return true;
	/* Only unconfigured, ordinary default queues are transparent here.
	 * In particular a custom default cake/htb/tbf must not bypass shaping.
	 */
	return strcmp(id, "noop") && strcmp(id, "noqueue") &&
	       strcmp(id, "mq") && strcmp(id, "pfifo_fast") &&
	       strcmp(id, "fq_codel") && strcmp(id, "fq");
}

/* Called under RTNL during the worker snapshot.  Automatic default qdiscs
 * have handle 0; an explicitly configured/changed qdisc is software policy.
 * TCX and XDP are persistent namespace vetoes as well, not mere snapshots.
 */
bool rtl9617c_switch_device_has_policy(const struct net_device *dev)
{
	struct Qdisc *qdisc;
	unsigned int i;

	ASSERT_RTNL();
	qdisc = rtnl_dereference(dev->qdisc);
	if (rtl9617c_switch_qdisc_has_policy(qdisc))
		return true;
	for (i = 0; i < dev->num_tx_queues; i++) {
		qdisc = rtnl_dereference(netdev_get_tx_queue(dev, i)->qdisc_sleeping);
		if (rtl9617c_switch_qdisc_has_policy(qdisc))
			return true;
	}
	return false;
}
EXPORT_SYMBOL_GPL(rtl9617c_switch_device_has_policy);
