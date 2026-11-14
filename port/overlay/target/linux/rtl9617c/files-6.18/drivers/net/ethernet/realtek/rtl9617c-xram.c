// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RTL9617C management XRAM Ethernet path, ported to Linux netdev/NAPI/phylib.
 * Packet format and sequences: Realtek Semiconductor Corp. 2022, GPL-2.0+,
 * GPL-for-GP3000 5090fbcb6ba743dd7b1314811ef557bad0460147,
 * bootloader/u-boot-2022.10/board/realtek_10G_PON/common/eth_ni.c.
 * This first LAN path retains the PHY setup performed by the stock bootloader.
 */
#include <linux/bitfield.h>
#include <linux/completion.h>
#include <linux/crc32.h>
#include <linux/delay.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>
#include <linux/phy.h>
#include <linux/phy/phy.h>
#include <linux/platform_device.h>
#include <linux/rcupdate.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/unaligned.h>
#include <linux/tyfza1-led.h>
#include <linux/workqueue.h>
#include <net/gro.h>

#include "rtl9617c-xram-format.h"
#include "rtl9617c-dma.h"
#include "rtl9617c-qm.h"
#include "rtl9617c-ni.h"
#include "rtl9617c-fe.h"
#include "rtl9617c-mib.h"

#define GLB_STATIC 0xa01c
#define PORT_TO_CPU GENMASK(3, 0)
#define MAC_ADDR0 0xa024
#define MAC_ADDR1 0xa028
#define PORT_STATIC 0xa5c0
#define PORT_GLB 0xa5c4
#define PORT_RX 0xa5c8
#define PORT_TX 0xa5d4
#define PORT_STRIDE 0x90
#define RX_ADDR 0xaa20
#define TX_ADDR 0xaa24
#define XRAM_CFG 0xaa28
#define RX_READ 0xaa2c
#define RX_WRITE 0xaa30
#define TX_WRITE 0xaa44
#define TX_READ 0xaa48
#define POINTER_MASK GENMASK(9, 0)
#define CPU_DISABLE (BIT(0) | BIT(9))
#define RX_PROMISC GENMASK(15, 14)
#define XR_OWN BIT(31)
#define PKT_SIZE GENMASK(13, 0)
#define PKT_VALID BIT(19)
#define PKT_ERRORS (GENMASK(23, 20) | BIT(25) | BIT(26))

struct rtl_xram;

/* There is no verified complete NI/QM/AXI drain predicate in the public
 * RTL8277C SDK. A physical engine which has seen our DMA addresses cannot be
 * rebound to a new allocation after unbind. Built-in lifetime plus this
 * aperture claim also covers forced platform removal, not just sysfs unbind.
 * Unexposed probe failures release the claim and remain retryable. */
struct rtl_ni_owner {
	struct list_head list;
	resource_size_t start, end;
	struct device *device;
	bool exposed;
};

static LIST_HEAD(rtl_ni_owners);
static DEFINE_MUTEX(rtl_ni_owners_lock);

static struct rtl_ni_owner *rtl_ni_owner_claim(struct device *dev,
					    const struct resource *resource)
{
	struct rtl_ni_owner *owner, *entry;

	if (!resource)
		return ERR_PTR(-EINVAL);
	owner = kzalloc(sizeof(*owner), GFP_KERNEL);
	if (!owner)
		return ERR_PTR(-ENOMEM);
	owner->start = resource->start;
	owner->end = resource->end;
	owner->device = get_device(dev);
	mutex_lock(&rtl_ni_owners_lock);
	list_for_each_entry(entry, &rtl_ni_owners, list) {
		if (entry->start <= owner->end && owner->start <= entry->end) {
			mutex_unlock(&rtl_ni_owners_lock);
			put_device(owner->device);
			kfree(owner);
			return ERR_PTR(-EBUSY);
		}
	}
	list_add_tail(&owner->list, &rtl_ni_owners);
	mutex_unlock(&rtl_ni_owners_lock);
	return owner;
}

static void rtl_ni_owner_expose(struct rtl_ni_owner *owner)
{
	/* The owning instance is serialized by RTNL. This bit is monotonic and
	 * the claim remains on the global list even after the instance is gone. */
	WRITE_ONCE(owner->exposed, true);
}

static void rtl_ni_owner_release(struct rtl_ni_owner *owner)
{
	if (!owner || READ_ONCE(owner->exposed))
		return;
	mutex_lock(&rtl_ni_owners_lock);
	list_del(&owner->list);
	mutex_unlock(&rtl_ni_owners_lock);
	put_device(owner->device);
	kfree(owner);
}

struct rtl_lan {
	struct rtl_xram *shared;
	unsigned int port;
};

/* Raw MAC counters from one complete pre-existing PM sample, not the
 * wrap-extended OAM totals. No reset-generation hardware contract is known;
 * users must reject deltas after a counter decrease, failed/stale sample or
 * changed device/boot identity. The interaction between the SDK's global
 * cnt_op_mode=2 and explicit ACCESS READ_ONLY is not a verified silicon
 * contract: a successful raw sample does not establish cumulative semantics.
 * These are all-path MAC counters, not L2 hits.
 */
struct rtl_lan_mib_evidence {
	u64 seq, attempts, begin_ns, end_ns, attempt_begin_ns, attempt_end_ns;
	u64 rx_bytes, tx_bytes;
	u32 rx_uc, rx_mc, rx_bc, tx_uc, tx_mc, tx_bc;
	u32 config_begin, config_end;
	int error;
	bool valid;
};

struct rtl_xram {
	/* Primary netdev embeds the shared engine;other LANs only carry this
	 * initial per-port member and use the same NI/DMA/QM owner. */
	struct rtl_lan lan;
	struct net_device *netdev;
	struct net_device *ports[5];
	unsigned int registered_ports;
	struct work_struct lan4_work;
	struct completion lan4_ready;
	struct device *lan4_parent;
	struct device_node *lan4_phy;
	void __iomem *ni;
	void __iomem *xram;
	struct phy *sgmii;
	unsigned int sgmii_speed;
	struct tyfza1_led phy_led;
	bool phy_led_registered;
	bool native_groups_created;
	struct napi_struct napi;
	struct hrtimer timer;
	u32 idle_poll_ms;
	u64 timer_fast_ticks, timer_idle_ticks;
	spinlock_t tx_lock;
	spinlock_t rx_lock;
	struct mutex mib_lock;
	struct delayed_work mib_work;
	unsigned long long mib_total[5][RTL_NI_MIB_COUNTERS];
	struct rtl_lan_mib_evidence mib_evidence[5];
	bool rx_active;
	u32 port;
	bool tx_pending;
	unsigned int tx_length;
	u8 tx_buffer[2048];
	bool dma_tx;
	struct rtl_dma_tx dma;
	bool qm_rx;
	struct rtl_qm_rx qm;
	int rx_irq;
	bool irq_requested;
	unsigned int engine_users;
	struct rtl_fe *fe;
	struct rtl_ni_owner *owner;
	bool base_ready;
	bool dma_exposed;
	bool engine_poisoned;
	bool host_active;
	bool pon_gate_valid;
	u32 pon_gate_requested;
	bool removing;
};

static struct rtl_xram *rtl_shared(struct net_device *dev)
{
	return ((struct rtl_lan *)netdev_priv(dev))->shared;
}

static unsigned int rtl_mib_read(void *context, unsigned int reg)
{
	struct rtl_xram *priv = context;

	return readl(priv->ni + reg);
}

static void rtl_mib_write(void *context, unsigned int reg, unsigned int value)
{
	struct rtl_xram *priv = context;

	writel(value, priv->ni + reg);
}

static int rtl_mib_indirect(void *context, unsigned int reg, unsigned int command)
{
	struct rtl_xram *priv = context;
	u32 status;
	int ret;

	/* A previous timeout is not cancellation. Leave a late transaction's
	 * ACCESS command intact until it is actually idle, including retries by
	 * the next background/OAM reader under the same MIB owner mutex. */
	ret = readl_poll_timeout(priv->ni + reg, status,
				 !(status & BIT(31)), 1, 100000);
	if (ret)
		return ret;
	writel(command, priv->ni + reg);
	return readl_poll_timeout(priv->ni + reg, status, !(status & BIT(31)), 1, 100000);
}

int rtl9617c_ni_pm_read(struct device *dev, unsigned int port, unsigned long long counters[37])
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));
	const struct rtl_dq_io io = {priv, rtl_mib_read, rtl_mib_write, rtl_mib_indirect};
	unsigned long long raw[RTL_NI_MIB_COUNTERS];
	struct rtl_lan_mib_evidence *sample;
	u32 config_begin = 0, config_end = 0;
	int ret;

	if (port >= ARRAY_SIZE(priv->mib_total) || !counters)
		return -EINVAL;
	mutex_lock(&priv->mib_lock);
	sample = &priv->mib_evidence[port];
	sample->attempts++;
	sample->attempt_begin_ns = ktime_get_boottime_ns();
	if (READ_ONCE(priv->removing)) {
		ret = -ENODEV;
	} else {
		/* Keep config evidence without altering the shared counter mode.
		 * aal_ni_l2.c requests ACCESS op_code=0 for read_clear=false;
		 * preserve that command, not a claim about silicon clear behavior. */
		config_begin = readl(priv->ni + GLB_STATIC);
		ret = rtl_ni_mib_read(&io, port, raw);
		config_end = readl(priv->ni + GLB_STATIC);
	}
	sample->attempt_end_ns = ktime_get_boottime_ns();
	sample->error = ret;
	if (!ret) {
		sample->rx_bytes = raw[25];
		sample->tx_bytes = raw[51];
		sample->rx_uc = raw[0];
		sample->rx_mc = raw[1];
		sample->rx_bc = raw[2];
		sample->tx_uc = raw[26];
		sample->tx_mc = raw[27];
		sample->tx_bc = raw[28];
		sample->config_begin = config_begin;
		sample->config_end = config_end;
		sample->begin_ns = sample->attempt_begin_ns;
		sample->end_ns = sample->attempt_end_ns;
		sample->seq++;
		sample->valid = true;
		rtl_ni_mib_pm(priv->mib_total[port], raw, counters);
	}
	mutex_unlock(&priv->mib_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_pm_read);

static void rtl_mib_work(struct work_struct *work)
{
	struct rtl_xram *priv = container_of(to_delayed_work(work), struct rtl_xram, mib_work);
	unsigned long long counters[37];
	unsigned int port;

	/* Extend narrow counters independently of OAM/PM enable and client reads. */
	for (port = 0; port < ARRAY_SIZE(priv->ports); port++) {
		int ret;

		if (!(READ_ONCE(priv->registered_ports) & BIT(port)))
			continue;
		ret = rtl9617c_ni_pm_read(priv->netdev->dev.parent, port, counters);

		if (ret)
			dev_err_ratelimited(priv->netdev->dev.parent, "NI port%u MIB read failed: %d\n", port, ret);
	}
	schedule_delayed_work(&priv->mib_work, HZ);
}

int rtl9617c_ni_fe_add_port(struct device *dev,struct net_device *netdev,unsigned int llid)
{
 struct rtl_xram *priv=netdev_priv(dev_get_drvdata(dev));
 return rtl_fe_add_port(priv->fe,netdev,7,32+llid,llid);
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_fe_add_port);
int rtl9617c_ni_itu_paths(struct device *dev, struct net_device *netdev, const struct rtl_itu_paths *paths)
{
 struct rtl_xram *priv=netdev_priv(dev_get_drvdata(dev));
 return rtl_fe_set_itu_paths(priv->fe,netdev,paths);
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_itu_paths);
void rtl9617c_ni_fe_remove_port(struct device *dev,struct net_device *netdev)
{
 struct rtl_xram *priv=netdev_priv(dev_get_drvdata(dev));
 rtl_fe_remove_port(priv->fe,netdev);
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_fe_remove_port);
int rtl9617c_ni_fe_setup_tc(struct device *dev,struct net_device *netdev,
 enum tc_setup_type type,void *data)
{
 struct rtl_xram *priv=netdev_priv(dev_get_drvdata(dev));
 return rtl_fe_setup_tc(priv->fe,netdev,type,data);
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_fe_setup_tc);
int rtl9617c_ni_fe_enable(struct device *dev)
{
 struct rtl_xram *priv=netdev_priv(dev_get_drvdata(dev));
 return rtl_fe_enable(priv->fe);
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_fe_enable);
int rtl9617c_ni_fe_cpu_path(struct device *dev)
{
 struct rtl_xram *priv=netdev_priv(dev_get_drvdata(dev));
 /* Snapshot shared scheduler state only after the first NI/QM start. */
 if(!READ_ONCE(priv->engine_users))return -EAGAIN;
 return rtl_fe_cpu_path(priv->fe);
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_fe_cpu_path);
int rtl9617c_ni_fe_disable(struct device *dev)
{
 struct rtl_xram *priv=netdev_priv(dev_get_drvdata(dev));
 return rtl_fe_disable(priv->fe);
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_fe_disable);
ssize_t rtl9617c_ni_fe_state(struct device *dev,char *buffer)
{
 struct rtl_xram *priv=netdev_priv(dev_get_drvdata(dev));
 return rtl_fe_state(priv->fe,buffer);
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_fe_state);

int rtl9617c_ni_report_configure(struct device *dev, unsigned int low, unsigned int high)
{
	struct net_device *netdev = dev_get_drvdata(dev);
	struct rtl_xram *priv;

	if (!netdev)
		return -EPROBE_DEFER;
	priv = netdev_priv(netdev);
	writel((high << 14) | low, priv->ni + 0x96d4);
	return 0;
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_report_configure);

u32 rtl9617c_ni_report_state(struct device *dev)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));
	return readl(priv->ni + 0x96d4);
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_report_state);

/* Original aal_l3_tm_es_ni_port_ena_set: PON ports8..23 use bits0..15. */
u32 rtl9617c_ni_pon_gate(struct device *dev, u32 enabled)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));
	unsigned long flags;
	u32 saved, control;

	spin_lock_irqsave(&priv->tx_lock, flags);
	control = readl(priv->ni + 0x610c);
	saved = priv->pon_gate_valid ? priv->pon_gate_requested : control & 0xffffU;
	priv->pon_gate_requested = enabled & 0xffffU;
	priv->pon_gate_valid = true;
	/* Remember recovery's desired gate while host RX is inactive, but do
	 * not let a delayed restore reopen it after close or NI quarantine. */
	if (!priv->host_active || priv->engine_poisoned || priv->removing)
		enabled = 0;
	writel((control & ~0xffffU) | (enabled & 0xffffU), priv->ni + 0x610c);
	readl(priv->ni + 0x610c);
	spin_unlock_irqrestore(&priv->tx_lock, flags);
	return saved;
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_pon_gate);

/* Caller holds tx_lock. Gate publication is separate from queue ownership;
 * keep the requested PON mask across host close/open, without resetting QM. */
static void rtl_pon_host_gate(struct rtl_xram *priv, bool active)
{
	u32 control, enabled = 0;

	if (!priv->qm_rx)
		return;
	control = readl(priv->ni + 0x610c);
	if (!priv->pon_gate_valid) {
		priv->pon_gate_requested = control & 0xffffU;
		priv->pon_gate_valid = true;
	}
	if (active && priv->host_active && !priv->engine_poisoned && !priv->removing)
		enabled = priv->pon_gate_requested;
	writel((control & ~0xffffU) | enabled, priv->ni + 0x610c);
	readl(priv->ni + 0x610c);
}

static unsigned int rtl_pointer(struct rtl_xram *priv, unsigned int reg)
{
	return readl(priv->ni + reg) & POINTER_MASK;
}

static void rtl_update(struct rtl_xram *priv, unsigned int reg, u32 mask, u32 value)
{
	writel((readl(priv->ni + reg) & ~mask) | value, priv->ni + reg);
}

static void rtl_mac_address(struct rtl_xram *priv)
{
	const u8 *mac = priv->netdev->dev_addr;

	writel(get_unaligned_be32(mac), priv->ni + MAC_ADDR0);
	rtl_update(priv, MAC_ADDR1, 0xff, mac[4]);
	rtl_update(priv, PORT_STATIC + priv->port * PORT_STRIDE,
		   GENMASK(31, 24), (u32)mac[5] << 24);
}

static void rtl_adjust_link(struct net_device *dev)
{
	struct rtl_lan *lan = netdev_priv(dev);
	struct phy_device *phy = dev->phydev;

	if (phy->link) {
		/* Port4's SGMII PCS requires GMII even at 10/100 Mbps. */
		rtl_update(lan->shared, PORT_STATIC + lan->port * PORT_STRIDE,
			   GENMASK(3, 0),
			   lan->port == 4 || phy->speed >= SPEED_1000 ? 0 : 1);
		rtl_update(lan->shared, PORT_GLB + lan->port * PORT_STRIDE,
			   BIT(0) | BIT(1), (phy->speed == SPEED_10 ? BIT(0) : 0) |
			   (phy->duplex == DUPLEX_HALF ? BIT(1) : 0));
		if (lan->port == 4 && lan->shared->sgmii_speed != phy->speed) {
			int ret = phy_set_speed(lan->shared->sgmii, phy->speed);

			if (ret) {
				netdev_err(dev, "S3 speed %d failed: %d\n", phy->speed, ret);
				phy_error(phy);
				return;
			}
			lan->shared->sgmii_speed = phy->speed;
		}
	}
	phy_print_status(dev->phydev);
}

static void rtl_rx_mode(struct net_device *dev)
{
	struct rtl_xram *priv = rtl_shared(dev);
	bool accept_all = (dev->flags & (IFF_PROMISC | IFF_ALLMULTI)) ||
			  !netdev_mc_empty(dev);

	if (priv->qm_rx)
		return;
	/* Taurus's management filter uses mode 1 for promiscuous receive. */
	rtl_update(priv, XRAM_CFG, RX_PROMISC, FIELD_PREP(RX_PROMISC, accept_all));
}

static int rtl_poll(struct napi_struct *napi, int budget)
{
	struct rtl_xram *priv = container_of(napi, struct rtl_xram, napi);
	struct net_device *dev = priv->netdev;
	int packets = 0;

	if (priv->qm_rx) {
		unsigned long flags;

		packets = rtl_qm_rx_poll(&priv->qm, napi, budget);
		/* Completion can deliver GRO packets; keep IRQs enabled for the stack. */
		if (packets < budget && napi_complete_done(napi, packets)) {
			spin_lock_irqsave(&priv->rx_lock, flags);
			if (priv->rx_active)
				rtl_update(priv, 0x6110, 0xff, 0xff);
			spin_unlock_irqrestore(&priv->rx_lock, flags);
		}
		return packets;
	}

	while (packets < budget) {
		unsigned int rd = rtl_pointer(priv, RX_READ);
		unsigned int wr = rtl_pointer(priv, RX_WRITE);
		unsigned int offset, next, size, copied;
		struct sk_buff *skb;
		u32 header, status;

		if (rd == wr)
			break;
		header = readl(priv->xram + rd * 8 + 4);
		if (header & XR_OWN)
			break;
		next = header & POINTER_MASK;
		if (next >= RTL_XRAM_RX_END || next == rd) {
			dev->stats.rx_errors++;
			writel(wr, priv->ni + RX_READ);
			break;
		}
		offset = rtl_xram_word_next(rd * 8 + 4, 0, RTL_XRAM_RX_END * 8);
		status = readl(priv->xram + offset);
		size = FIELD_GET(PKT_SIZE, status);
		packets++;
		if (!(status & PKT_VALID) || (status & PKT_ERRORS) ||
		    size < ETH_HLEN + ETH_FCS_LEN || size > 1522) {
			dev->stats.rx_errors++;
			writel(next, priv->ni + RX_READ);
			continue;
		}
		size -= ETH_FCS_LEN;
		skb = napi_alloc_skb(napi, size);
		if (!skb) {
			dev->stats.rx_dropped++;
			writel(next, priv->ni + RX_READ);
			continue;
		}
		offset = rtl_xram_word_next(offset, 0, RTL_XRAM_RX_END * 8);
		offset = rtl_xram_word_next(offset, 0, RTL_XRAM_RX_END * 8);
		for (copied = 0; copied < size; copied += 4) {
			__le32 word = cpu_to_le32(readl(priv->xram + offset));

			memcpy(skb_put(skb, min(4U, size - copied)), &word,
			       min(4U, size - copied));
			offset = rtl_xram_word_next(offset, 0, RTL_XRAM_RX_END * 8);
		}
		writel(next, priv->ni + RX_READ);
		skb->protocol = eth_type_trans(skb, dev);
		dev->stats.rx_packets++;
		dev->stats.rx_bytes += size;
		napi_gro_receive(napi, skb);
	}
	if (packets < budget)
		napi_complete_done(napi, packets);
	return packets;
}

static enum hrtimer_restart rtl_timer(struct hrtimer *timer)
{
	struct rtl_xram *priv = container_of(timer, struct rtl_xram, timer);
	unsigned int interval = READ_ONCE(priv->idle_poll_ms);

	if (!priv->qm_rx || READ_ONCE(priv->qm.refill.pending)) {
		napi_schedule(&priv->napi);
		interval = 1;
	}
	spin_lock(&priv->tx_lock);
	if (priv->dma_tx) {
		struct rtl9617c_ni_endpoint *endpoint;
		bool wake;

		rtl_dma_tx_complete(&priv->dma, priv->netdev);
		wake = priv->dma.wake_pending && rtl_dma_tx_available(&priv->dma);
		if (wake) {
			unsigned int port;

			priv->dma.wake_pending = false;
			rcu_read_lock();
			endpoint = rcu_dereference(priv->qm.pon);
			if (endpoint)
				endpoint->wake(endpoint);
			rcu_read_unlock();
			for (port = 0; port < ARRAY_SIZE(priv->ports); port++)
				if (priv->ports[port] && netif_running(priv->ports[port]) &&
				    netif_queue_stopped(priv->ports[port]))
					netif_wake_queue(priv->ports[port]);
		}
		/* Software read intentionally trails two prefetched descriptors. Use
		 * the hardware cursor to detect activity, not tx->read != tx->write. */
		if (priv->dma.hardware_read != priv->dma.write || priv->dma.wake_pending)
			interval = 1;
	} else if (priv->tx_pending && rtl_pointer(priv, TX_READ) == rtl_pointer(priv, TX_WRITE)) {
		priv->tx_pending = false;
		priv->netdev->stats.tx_packets++;
		priv->netdev->stats.tx_bytes += priv->tx_length;
		netif_wake_queue(priv->netdev);
	}
	if (priv->tx_pending)
		interval = 1;
	spin_unlock(&priv->tx_lock);
	if (interval == 1)
		priv->timer_fast_ticks++;
	else
		priv->timer_idle_ticks++;
	hrtimer_forward_now(timer, ms_to_ktime(interval));
	return HRTIMER_RESTART;
}

static irqreturn_t rtl_rx_irq(int irq, void *data)
{
	struct rtl_xram *priv = data;

	rtl_update(priv, 0x6110, 0xff, 0);
	napi_schedule_irqoff(&priv->napi);
	return IRQ_HANDLED;
}

static netdev_tx_t rtl_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct rtl_lan *lan = netdev_priv(dev);
	struct rtl_xram *priv = lan->shared;
	unsigned int pointer, offset, wire, i;
	unsigned long flags;
	u32 crc;

	if (skb->len < ETH_HLEN || skb->len > 1522) {
		dev->stats.tx_dropped++;
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}
	spin_lock_irqsave(&priv->tx_lock, flags);
	if (unlikely(!priv->host_active || priv->removing || priv->engine_poisoned)) {
		dev->stats.tx_dropped++;
		spin_unlock_irqrestore(&priv->tx_lock, flags);
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}
	if (priv->dma_tx) {
		const struct rtl9617c_ni_frame frame = {
			.header_high = BIT(13),
			.header_low = (16 << 9) | (lan->port << 3) | BIT(29),
		};
		netdev_tx_t result = rtl_dma_tx_frame(&priv->dma, skb, dev, &frame);

		spin_unlock_irqrestore(&priv->tx_lock, flags);
		return result;
	}
	pointer = rtl_pointer(priv, TX_WRITE);
	if (priv->tx_pending || rtl_pointer(priv, TX_READ) != pointer) {
		netif_stop_queue(dev);
		spin_unlock_irqrestore(&priv->tx_lock, flags);
		return NETDEV_TX_BUSY;
	}
	wire = rtl_xram_wire_length(skb->len);
	memset(priv->tx_buffer, 0, ALIGN(8 + wire, 4));
	skb_copy_bits(skb, 0, priv->tx_buffer + 8, skb->len);
	crc = crc32_le(~0, priv->tx_buffer + 8, wire - 4) ^ ~0;
	put_unaligned_le32(crc, priv->tx_buffer + 8 + wire - 4);
	offset = pointer * 8 + 4;
	writel(rtl_xram_tx_header(rtl_xram_tx_next(pointer, wire), wire),
	       priv->xram + offset);
	offset = rtl_xram_word_next(offset, RTL_XRAM_TX_START * 8, RTL_XRAM_TX_END * 8);
	for (i = 0; i < wire + 8; i += 4) {
		writel(get_unaligned_le32(priv->tx_buffer + i), priv->xram + offset);
		offset = rtl_xram_word_next(offset, RTL_XRAM_TX_START * 8, RTL_XRAM_TX_END * 8);
	}
	priv->tx_pending = true;
	priv->tx_length = skb->len;
	netif_stop_queue(dev);
	wmb();
	writel(rtl_xram_tx_next(pointer, wire), priv->ni + TX_WRITE);
	spin_unlock_irqrestore(&priv->tx_lock, flags);
	dev_consume_skb_any(skb);
	return NETDEV_TX_OK;
}

static void rtl_engine_poison(struct rtl_xram *priv)
{
	unsigned long flags;

	/* Serialize the shared PON gate with recovery's rtl9617c_ni_pon_gate(). */
	spin_lock_irqsave(&priv->tx_lock, flags);
	WRITE_ONCE(priv->engine_poisoned, true);
	/* Do not reset/reassign BIDs, descriptors or in-flight DMA addresses.
	 * These gates stop new admission, not previously accepted transactions. */
	if (priv->dma_exposed) {
		if (priv->qm_rx)
			rtl_qm_rx_stop(&priv->qm);
		if (priv->dma_tx)
			rtl_dma_tx_quiesce(&priv->dma);
	}
	spin_unlock_irqrestore(&priv->tx_lock, flags);
}

static int rtl_engine_prepare(struct rtl_xram *priv)
{
	struct net_device *dev = priv->netdev;
	unsigned long flags;
	unsigned int port;
	u32 config;
	int ret;

	/* This routine is called once for this physical owner. In particular,
	 * never TQM-reset, memset a ring, or push all BIDs again on ndo_open. */
	if (priv->dma_tx || priv->qm_rx) {
		priv->dma_exposed = true;
		rtl_ni_owner_expose(priv->owner);
	}
	if (priv->qm_rx) {
		/* Cold defaults may not overwrite an explicit PON recovery mask.
		 * Keep its egress closed throughout sleeping QM/FE initialization;
		 * only the final host publication may enable the requested ports. */
		spin_lock_irqsave(&priv->tx_lock, flags);
		if (!priv->pon_gate_valid) {
			priv->pon_gate_requested = 0xffffU;
			priv->pon_gate_valid = true;
		}
		rtl_pon_host_gate(priv, false);
		spin_unlock_irqrestore(&priv->tx_lock, flags);
	}
	if (priv->dma_tx) {
		/* The bootloader's XRAM path leaves the normal LAN scheduler off. */
		/* Original aal_l2_qm_init: EQ1 has4K64-byte pages, with29 pages
		 * reserved per port so one full frame survives shared-pool pressure. */
		writel(BIT(31) | (4U << 16) | (29U << 20), priv->ni + 0x2208);
		rtl_update(priv, 0x2218, GENMASK(14, 0), 29);
		writel(0x08008021, priv->ni + 0x2210);
		/* Port15 uses scheduler instance14. Leaving it stopped
		 * holds VOQ120..127 buffers until every LAN/PON data path runs out. */
		rtl_update(priv, 0x2304 + 12 * 14, 0xff, 0xff);
		rtl_update(priv, 0x2300, BIT(31) | BIT(15), BIT(31) | BIT(15));
		for (port = 0; port < ARRAY_SIZE(priv->ports); port++)
			if (priv->ports[port]) {
				rtl_update(priv, 0x2300, BIT(31) | BIT(port), BIT(31) | BIT(port));
				rtl_update(priv, 0x2304 + 12 * port, 0xff, 0xff);
			}
		ret = rtl_dma_tx_start(&priv->dma);
		if (ret)
			return ret;
	}
	if (priv->qm_rx) {
		ret = rtl_qm_rx_start(&priv->qm, priv->port);
		if (ret)
			return ret;
		for (port = 0; port < ARRAY_SIZE(priv->ports); port++)
			if (priv->ports[port])
				rtl_update(priv, 0xa5f8 + PORT_STRIDE * port,
					   BIT(28) | GENMASK(21, 16) | BIT(31), BIT(28) | (16 << 16));
	}

	rtl_update(priv, GLB_STATIC, PORT_TO_CPU, priv->dma_tx ? 0xf : priv->port);
	rtl_mac_address(priv);
	writel((RTL_XRAM_RX_END - 1) << 16, priv->ni + RX_ADDR);
	writel((RTL_XRAM_TX_END - 1) << 16 | RTL_XRAM_TX_START, priv->ni + TX_ADDR);
	config = readl(priv->ni + XRAM_CFG) & ~RX_PROMISC;
	writel(config | CPU_DISABLE, priv->ni + XRAM_CFG);
	udelay(100);
	writel(priv->qm_rx ? config | CPU_DISABLE : config & ~CPU_DISABLE,
	       priv->ni + XRAM_CFG);
	rtl_rx_mode(dev);
	priv->tx_pending = false;
	priv->base_ready = true;
	return 0;
}

static int rtl_engine_start(struct rtl_xram *priv)
{
	unsigned long flags;
	int ret;

	if (priv->removing)
		return -ENODEV;
	if (priv->engine_poisoned)
		return -EIO;
	/* FE owns its installed CPU profile for the same device lifetime. Gate
	 * flows before first setup, but never restore a boot-time profile while
	 * the PON classifier can still send packets to that profile. */
	ret = rtl_fe_engine_suspend(priv->fe);
	if (ret)
		return ret;
	if (!priv->base_ready) {
		ret = rtl_engine_prepare(priv);
		if (ret)
			goto poison;
		spin_lock_irqsave(&priv->tx_lock, flags);
		rtl_pon_host_gate(priv, false);
		spin_unlock_irqrestore(&priv->tx_lock, flags);
	}
	ret = rtl_fe_engine_resume(priv->fe);
	if (ret) {
		/* NI is complete. FE owns whether its failure is retryable or a
		 * permanent base quarantine; never destroy this queue allocation
		 * just because a flow-table transaction was temporarily busy. */
		netdev_err(priv->netdev, "FE resume failed: %d; NI base retained, next open retries FE\n", ret);
		return ret;
	}
	napi_enable(&priv->napi);
	spin_lock_irqsave(&priv->tx_lock, flags);
	WRITE_ONCE(priv->host_active, true);
	rtl_pon_host_gate(priv, true);
	spin_unlock_irqrestore(&priv->tx_lock, flags);
	if (priv->qm_rx) {
		spin_lock_irqsave(&priv->rx_lock, flags);
		priv->rx_active = true;
		rtl_update(priv, 0x6110, 0xff, 0xff);
		spin_unlock_irqrestore(&priv->rx_lock, flags);
	}
	/* A retained EPP can already contain packets when IRQs are rearmed.
	 * Poll explicitly instead of depending on a new interrupt edge. */
	napi_schedule(&priv->napi);
	hrtimer_start(&priv->timer, ms_to_ktime(1), HRTIMER_MODE_REL);
	return 0;

poison:
	rtl_engine_poison(priv);
	netdev_err(priv->netdev, "NI initialization failed: %d; DMA owner retained, reboot required\n", ret);
	return ret;
}

static void rtl_engine_stop(struct rtl_xram *priv)
{
	unsigned long flags;
	int ret;

	if (!priv->host_active)
		return;
	spin_lock_irqsave(&priv->tx_lock, flags);
	WRITE_ONCE(priv->host_active, false);
	rtl_pon_host_gate(priv, false);
	spin_unlock_irqrestore(&priv->tx_lock, flags);
	/* Retire routing authorization, not the lifetime CPU/NI/QM allocation.
	 * CPU-profile PON arrivals can still be in flight when the last user
	 * closes; their queues and DMA buffers remain valid while host RX sleeps. */
	ret = rtl_fe_engine_suspend(priv->fe);
	if (ret)
		netdev_err(priv->netdev, "FE suspend failed: %d; NI base retained, next open retries FE\n", ret);
	hrtimer_cancel(&priv->timer);
	if (priv->qm_rx) {
		spin_lock_irqsave(&priv->rx_lock, flags);
		priv->rx_active = false;
		rtl_update(priv, 0x6110, 0xff, 0);
		spin_unlock_irqrestore(&priv->rx_lock, flags);
		synchronize_irq(priv->rx_irq);
	}
	napi_disable(&priv->napi);
	if (priv->qm_rx) {
		/* Completion releases NAPI ownership before the final rearm check.
		 * Wait for the BH-disabled poll tail; this is not a hardware drain. */
		synchronize_net();
	}
}

static int rtl_engine_get(struct rtl_xram *priv)
{
	int ret;

	/* Both netdev open/stop paths are serialized by RTNL. */
	if (priv->removing)
		return -ENODEV;
	if (priv->engine_poisoned)
		return -EIO;
	if (priv->engine_users) {
		priv->engine_users++;
		return 0;
	}
	/* QM ingress and schedulers only cover ports published before the first start. */
	wait_for_completion(&priv->lan4_ready);
	ret = rtl_engine_start(priv);
	if (!ret)
		priv->engine_users = 1;
	return ret;
}

static void rtl_engine_put(struct rtl_xram *priv)
{
	if (WARN_ON_ONCE(!priv->engine_users))
		return;
	if (!--priv->engine_users)
		rtl_engine_stop(priv);
}

static int rtl_open(struct net_device *dev)
{
	struct rtl_lan *lan = netdev_priv(dev);
	struct rtl_xram *priv = lan->shared;
	int ret = rtl_engine_get(priv);

	if (ret)
		return ret;
	/* Stock aal_set_active_port releases this port's interface and RX/TX resets. */
	rtl_update(priv, 0xa008, BIT(lan->port) | BIT(lan->port + 6) | BIT(lan->port + 12), 0);
	rtl_update(priv, PORT_STATIC + lan->port * PORT_STRIDE,
		   GENMASK(31, 24), (u32)dev->dev_addr[5] << 24);
	rtl_update(priv, PORT_RX + lan->port * PORT_STRIDE, BIT(0), BIT(0));
	rtl_update(priv, PORT_TX + lan->port * PORT_STRIDE, BIT(0), BIT(0));
	phy_start(dev->phydev);
	netif_start_queue(dev);
	return 0;
}

static int rtl_stop(struct net_device *dev)
{
	struct rtl_lan *lan = netdev_priv(dev);
	struct rtl_xram *priv = lan->shared;
	unsigned long flags;

	netif_stop_queue(dev);
	phy_stop(dev->phydev);
	rtl_fe_flush_port(priv->fe, dev);
	rtl_update(priv, PORT_RX + lan->port * PORT_STRIDE, BIT(0), 0);
	/* aal-77c/aal_port.c keeps TX enabled on disable to avoid a buffer hang.
	 * Admission is already gated; allow previously accepted frames to exit. */
	if (priv->dma_tx) {
		spin_lock_irqsave(&priv->tx_lock, flags);
		rtl_dma_tx_forget(&priv->dma, dev);
		spin_unlock_irqrestore(&priv->tx_lock, flags);
	}
	rtl_engine_put(priv);
	return 0;
}

int rtl9617c_ni_pon_attach(struct device *dev, struct rtl9617c_ni_endpoint *endpoint)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));

	if (!priv->qm_rx || !priv->dma_tx)
		return -EOPNOTSUPP;
	rcu_assign_pointer(priv->qm.pon, endpoint);
	return 0;
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_pon_attach);

void rtl9617c_ni_pon_detach(struct device *dev)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));

	rcu_assign_pointer(priv->qm.pon, NULL);
	synchronize_net();
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_pon_detach);

int rtl9617c_ni_open(struct device *dev)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));

	return rtl_engine_get(priv);
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_open);

void rtl9617c_ni_close(struct device *dev, struct net_device *owner)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));
	unsigned long flags;

	rtl_fe_flush_port(priv->fe,owner);
	spin_lock_irqsave(&priv->tx_lock, flags);
	rtl_dma_tx_forget(&priv->dma, owner);
	spin_unlock_irqrestore(&priv->tx_lock, flags);
	rtl_engine_put(priv);
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_close);

netdev_tx_t rtl9617c_ni_transmit(struct device *dev, struct net_device *owner,
			       struct sk_buff *skb, const struct rtl9617c_ni_frame *frame)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));
	unsigned long flags;
	netdev_tx_t result;

	spin_lock_irqsave(&priv->tx_lock, flags);
	if (unlikely(!priv->host_active || priv->removing || priv->engine_poisoned)) {
		owner->stats.tx_dropped++;
		spin_unlock_irqrestore(&priv->tx_lock, flags);
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}
	result = rtl_dma_tx_frame(&priv->dma, skb, owner, frame);
	spin_unlock_irqrestore(&priv->tx_lock, flags);
	return result;
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_transmit);

int rtl9617c_ni_oam_configure(struct device *dev)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));
	static const unsigned int index[] = {15, 0x8f, 0x4f, 0xcf};
	u32 status;
	unsigned int i;
	int ret;

	/* aal_port: NI7 ninth queue (LDPID15) enters the OAM physical port12. */
	for (i = 0; i < ARRAY_SIZE(index); i++) {
		writel(12, priv->ni + 0x1658);
		writel(BIT(31) | BIT(30) | index[i], priv->ni + 0x1654);
		ret = readl_poll_timeout(priv->ni + 0x1654, status, !(status & BIT(31)), 1, 100000);
		if (ret)
			return ret;
	}
	writel(0xff | (6 << 16), priv->ni + 0x2304 + 12 * 12);
	rtl_update(priv, 0x2300, BIT(12), BIT(12));
	return 0;
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_oam_configure);

static int rtl_setup_tc(struct net_device *netdev,enum tc_setup_type type,void *data)
{
 struct rtl_xram *priv=rtl_shared(netdev);
 return rtl_fe_setup_tc(priv->fe,netdev,type,data);
}

static int rtl_get_port_parent_id(struct net_device *netdev,
				  struct netdev_phys_item_id *ppid)
{
	return rtl_fe_get_port_parent_id(rtl_shared(netdev)->fe, ppid);
}

static const struct net_device_ops rtl_netdev_ops = {
 .ndo_setup_tc = rtl_setup_tc,
	.ndo_get_port_parent_id = rtl_get_port_parent_id,
	.ndo_open = rtl_open,
	.ndo_stop = rtl_stop,
	.ndo_start_xmit = rtl_xmit,
	.ndo_set_rx_mode = rtl_rx_mode,
	.ndo_set_mac_address = eth_mac_addr,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_eth_ioctl = phy_do_ioctl_running,
};

static const struct ethtool_ops rtl_ethtool_ops = {
	.get_link = ethtool_op_get_link,
	.get_link_ksettings = phy_ethtool_get_link_ksettings,
	.set_link_ksettings = phy_ethtool_set_link_ksettings,
	.nway_reset = phy_ethtool_nway_reset,
};

static int rtl_phy_led_output(struct tyfza1_led *led, unsigned int value)
{
	struct rtl_xram *priv = container_of(led, struct rtl_xram, phy_led);
	/* Original LED0: 0=off, 1=on, 2=PHY link/activity (LCR7 bits0/4). */
	return phy_modify_mmd(priv->ports[4]->phydev, MDIO_MMD_VEND2,
			      0xd044, 0x11, value == 2 ? 0x10 : value);
}

static void rtl_unregister_lan(struct rtl_xram *priv, unsigned int port)
{
	struct net_device *dev = priv->ports[port];
	unsigned long flags;

	if (!dev)
		return;
	if (port == 4 && priv->phy_led_registered) {
		tyfza1_led_unregister(&priv->phy_led);
		priv->phy_led_registered = false;
	}
	spin_lock_irqsave(&priv->tx_lock, flags);
	priv->ports[port] = NULL;
	spin_unlock_irqrestore(&priv->tx_lock, flags);
	rcu_assign_pointer(priv->qm.lan[port], NULL);
	if (priv->registered_ports & BIT(port))
		unregister_netdev(dev);
	/* Also cover an already-down device: a retained TX descriptor must
	 * never leave a completion owner pointing at a freed secondary netdev. */
	spin_lock_irqsave(&priv->tx_lock, flags);
	rtl_dma_tx_forget(&priv->dma, dev);
	spin_unlock_irqrestore(&priv->tx_lock, flags);
	rtl_fe_remove_port(priv->fe, dev);
	synchronize_net();
	if (dev->phydev)
		phy_disconnect(dev->phydev);
	if (dev != priv->netdev)
		free_netdev(dev);
	priv->registered_ports &= ~BIT(port);
}

static void rtl_sgmii_power_off(void *data)
{
	phy_power_off(data);
}

static unsigned int rtl_lan_number(unsigned int port)
{
	/* Enclosure LAN1 is NI3 on 4GE and NI4 on the 2.5G board. */
	return port == 4 ? 1 : 4 - port;
}

static int rtl_register_lan(struct rtl_xram *priv, struct device *parent,
			    unsigned int port, struct device_node *phy)
{
	struct phy_device *phydev;
	struct net_device *dev = NULL;
	struct rtl_lan *lan;
	bool sgmii_powered = false, registration_locked = false;
	u8 mac[ETH_ALEN];
	int ret;

	if (port == 4) {
		priv->sgmii = devm_phy_get(parent, "sgmii");
		if (IS_ERR(priv->sgmii)) {
			ret = PTR_ERR(priv->sgmii);
			goto put_phy;
		}
		ret = phy_power_on(priv->sgmii);
		if (ret)
			goto put_phy;
		ret = devm_add_action_or_reset(parent, rtl_sgmii_power_off, priv->sgmii);
		if (ret)
			goto put_phy;
		sgmii_powered = true;
	}
	dev = port == priv->port ? priv->netdev : alloc_etherdev(sizeof(*lan));
	if (!dev) {
		ret = -ENOMEM;
		goto put_phy;
	}
	priv->ports[port] = dev;
	SET_NETDEV_DEV(dev, parent);
	snprintf(dev->name, sizeof(dev->name), "lan%u", rtl_lan_number(port));
	lan = netdev_priv(dev);
	lan->shared = priv;
	lan->port = port;
	/* Stable NI hardware identity survives a userspace interface rename. */
	dev->dev_port = port;
	dev->netdev_ops = &rtl_netdev_ops;
	dev->ethtool_ops = &rtl_ethtool_ops;
	dev->max_mtu = ETH_DATA_LEN;
	/* One shared FDB/NI engine cannot isolate independently moved ports. */
	dev->netns_immutable = true;
	ether_addr_copy(mac, priv->netdev->dev_addr);
	mac[5] += port - priv->port;
	eth_hw_addr_set(dev, mac);
	phydev = of_phy_find_device(phy);
	if (!phydev) {
		ret = -ENODEV;
		goto put_phy;
	}
	ret = phy_connect_direct(dev, phydev, rtl_adjust_link,
		port == 4 ? PHY_INTERFACE_MODE_SGMII : PHY_INTERFACE_MODE_GMII);
	put_device(&phydev->mdio.dev);
	if (ret)
		goto put_phy;
	ret = rtl_fe_add_port(priv->fe, dev, port, port, 0);
	if (ret)
		goto put_phy;
	rcu_assign_pointer(priv->qm.lan[port], dev);
	/* Publish NI4 (2.5G LAN1) before taking RTNL for registration: an engine start
	 * waiting on lan4_ready under RTNL must not block this work. */
	if (port == 4) {
		complete_all(&priv->lan4_ready);
		rtnl_lock();
		registration_locked = true;
	}
	/* Synchronous ports are registered under rtl_register_lans()' RTNL. */
	ret = register_netdevice(dev);
	if (ret)
		goto put_phy;
	WRITE_ONCE(priv->registered_ports, priv->registered_ports | BIT(port));
	if (port == 4) {
		priv->phy_led.output = rtl_phy_led_output;
		priv->phy_led.requested = 2;
		priv->phy_led.cdev.name = "LED_8221B_P4_0";
		priv->phy_led.cdev.max_brightness = 2;
		ret = tyfza1_led_register(parent, &priv->phy_led, NULL);
		if (ret)
			dev_warn(parent, "LAN1 2.5G LED initialization failed: %d\n", ret);
		else
			priv->phy_led_registered = true;
	}
	dev_info(parent, "%s: LAN port %u %s, PHY %08x, MAC %pM\n",
		 dev->name, port, priv->qm_rx ? "native NI/DMA" : "management XRAM",
		 dev->phydev->phy_id, dev->dev_addr);
	of_node_put(phy);
	if (registration_locked)
		rtnl_unlock();
	return 0;

put_phy:
	of_node_put(phy);
	if (dev)
		rtl_unregister_lan(priv, port);
	if (sgmii_powered)
		devm_release_action(parent, rtl_sgmii_power_off, priv->sgmii);
	if (registration_locked)
		rtnl_unlock();
	return ret;
}

static void rtl_lan4_work(struct work_struct *work)
{
	struct rtl_xram *priv = container_of(work, struct rtl_xram, lan4_work);
	int ret = rtl_register_lan(priv, priv->lan4_parent, 4, priv->lan4_phy);

	if (ret)
		dev_err(priv->lan4_parent, "LAN1 initialization failed: %d; other ports retained\n", ret);
	complete_all(&priv->lan4_ready);
}

static void rtl_register_lans(struct rtl_xram *priv, struct device *parent)
{
	struct device_node *phy;
	unsigned int port;
	int ret;

	/* Do not expose an openable port until all synchronous ports are
	 * published and NI4 work is queued (or its completion is signalled). */
	rtnl_lock();
	for (port = 0; port < ARRAY_SIZE(priv->ports); port++) {
		phy = of_parse_phandle(parent->of_node,
			port == priv->port ? "phy-handle" : "realtek,lan-phys",
			port == priv->port ? 0 : port);
		if (!phy)
			continue;
		if (port == 4) {
			/* Like the OEM rtk_rtl8221b_device_init_thread, set up
			 * the external RTL8221B off the boot path: its HiSGMII
			 * force-down poll can take the full 100 x 100ms. */
			priv->lan4_parent = parent;
			priv->lan4_phy = phy;
			INIT_WORK(&priv->lan4_work, rtl_lan4_work);
			schedule_work(&priv->lan4_work);
			continue;
		}
		ret = rtl_register_lan(priv, parent, port, phy);
		if (ret)
			dev_err(parent, "LAN%u initialization failed: %d; other ports retained\n",
				rtl_lan_number(port), ret);
	}
	if (!priv->lan4_phy)
		complete_all(&priv->lan4_ready);
	rtnl_unlock();
}

static ssize_t xram_state_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = dev_get_drvdata(dev);
	struct rtl_xram *priv = netdev_priv(netdev);

	return sysfs_emit(buf, "port=%u cfg=%08x static=%08x rx=%u/%u tx=%u/%u pending=%u base_ready=%u dma_exposed=%u engine_poisoned=%u host_active=%u reboot_required=%u\n",
		priv->port, readl(priv->ni + XRAM_CFG), readl(priv->ni + GLB_STATIC),
		rtl_pointer(priv, RX_READ), rtl_pointer(priv, RX_WRITE),
		rtl_pointer(priv, TX_READ), rtl_pointer(priv, TX_WRITE), priv->tx_pending,
		READ_ONCE(priv->base_ready), READ_ONCE(priv->dma_exposed),
		READ_ONCE(priv->engine_poisoned), READ_ONCE(priv->host_active),
		READ_ONCE(priv->engine_poisoned));
}
static DEVICE_ATTR_RO(xram_state);

static ssize_t dma_state_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));

	return priv->dma_tx ? rtl_dma_tx_state(&priv->dma, buf) : sysfs_emit(buf, "XRAM TX\n");
}
static DEVICE_ATTR_RO(dma_state);

static ssize_t datapath_profile_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));

	return sysfs_emit(buf, "enabled=%u host_RX_poll_ns=%llu host_RX_polls=%llu\n",
		priv->qm.profile, priv->qm.host_poll_ns, priv->qm.host_polls);
}

static ssize_t datapath_profile_store(struct device *dev, struct device_attribute *attr,
	const char *buf, size_t count)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));
	bool enabled;
	int ret = kstrtobool(buf, &enabled);

	if (ret)
		return ret;
	WRITE_ONCE(priv->qm.profile, enabled);
	WRITE_ONCE(priv->dma.profile, enabled);
	return count;
}
static DEVICE_ATTR_RW(datapath_profile);

static ssize_t idle_poll_ms_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));

	return sysfs_emit(buf, "interval_ms=%u fast_ticks=%llu idle_ticks=%llu\n",
		READ_ONCE(priv->idle_poll_ms), READ_ONCE(priv->timer_fast_ticks),
		READ_ONCE(priv->timer_idle_ticks));
}

static ssize_t idle_poll_ms_store(struct device *dev, struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));
	unsigned int value;
	int ret = kstrtouint(buf, 0, &value);

	if (ret)
		return ret;
	if (value < 1 || value > 10)
		return -EINVAL;
	WRITE_ONCE(priv->idle_poll_ms, value);
	return count;
}
static DEVICE_ATTR_RW(idle_poll_ms);

static ssize_t pipeline_state_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));

	return sysfs_emit(buf, "l2tm_es=%08x l2tm_port0=%08x qm_eq=%08x ni_internal=%08x ni_nitx=%08x ni_qm=%08x rx_hdr=%08x/%08x/%08x rx_pkts=%u rx_out=%08x/%08x l2qm_free=%08x\n",
		readl(priv->ni + 0x2300), readl(priv->ni + 0x2304),
		readl(priv->ni + 0x2208), readl(priv->ni + 0xa1bc), readl(priv->ni + 0xa1f4),
		readl(priv->ni + 0xa120), readl(priv->ni + 0xa088),
		readl(priv->ni + 0xa08c), readl(priv->ni + 0xa090), readl(priv->ni + 0xa094),
		readl(priv->ni + 0xa10c), readl(priv->ni + 0xa110), readl(priv->ni + 0x2234));
}
static DEVICE_ATTR_RO(pipeline_state);

static ssize_t qm_state_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));

	return priv->qm_rx ? rtl_qm_rx_state(&priv->qm, buf) : sysfs_emit(buf, "XRAM RX\n");
}
static DEVICE_ATTR_RO(qm_state);

static ssize_t qm_voqs_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));

	return rtl_qm_rx_voq_state(&priv->qm, buf);
}
static DEVICE_ATTR_RO(qm_voqs);

static ssize_t rx_prefetch_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));

	return sysfs_emit(buf, "%u\n", READ_ONCE(priv->qm.rx_prefetch));
}

static ssize_t rx_prefetch_store(struct device *dev, struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));
	bool enabled;
	int ret = kstrtobool(buf, &enabled);

	if (ret)
		return ret;
	WRITE_ONCE(priv->qm.rx_prefetch, enabled);
	return count;
}
static DEVICE_ATTR_RW(rx_prefetch);

static ssize_t pppoe_rx_checksum_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));

	return sysfs_emit(buf, "%u\n", READ_ONCE(priv->qm.pppoe_rx_checksum));
}

static ssize_t pppoe_rx_checksum_store(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));
	bool enabled;
	int ret = kstrtobool(buf, &enabled);

	if (ret)
		return ret;
	/* Keep disabled unless good/bad real hardware captures prove that the
	 * checksum error flag applies to PPPoE-encapsulated IPv4 as well. */
	WRITE_ONCE(priv->qm.pppoe_rx_checksum, enabled);
	return count;
}
static DEVICE_ATTR_RW(pppoe_rx_checksum);

static ssize_t qm_trace_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));
	return rtl_qm_rx_trace(&priv->qm, buf);
}

static ssize_t qm_trace_store(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t count)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));
	priv->qm.trace_count = 0;
	return count;
}
static DEVICE_ATTR_RW(qm_trace);

static ssize_t qm_pool_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));
	return rtl_qm_rx_pool(&priv->qm, buf);
}
static DEVICE_ATTR_RO(qm_pool);

static ssize_t pon_deepq_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));

	return rtl_qm_deepq_state(&priv->qm, buf);
}
static DEVICE_ATTR_RO(pon_deepq);

static ssize_t qm_wait_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));
	unsigned int value = FIELD_GET(GENMASK(27, 26), readl(priv->ni + 0x6108));

	return sysfs_emit(buf, "%u\n", value);
}

/* Queue registers belong to the lifecycle owner. Raw diagnostic writes can
 * reset admission or race stop/resume without preserving BID ownership. */
static DEVICE_ATTR_RO(qm_wait);

static ssize_t qm_es_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));
	return sysfs_emit(buf, "%08x\n", readl(priv->ni + 0x6108));
}

static DEVICE_ATTR_RO(qm_es);

static ssize_t qm_buffer_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));
	return sysfs_emit(buf, "%08x\n", readl(priv->ni + 0x68b0));
}

static DEVICE_ATTR_RO(qm_buffer);

/* Diagnostic only: the epoch-checked FE/switch owner selects CPU/L2/L3 RX. */
static ssize_t rx_bypass_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));

	return sysfs_emit(buf, "%08x\n", readl(priv->ni + 0xa5f8 + PORT_STRIDE * priv->port));
}

static DEVICE_ATTR_RO(rx_bypass);

static ssize_t l2_switch_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));

	return sysfs_emit(buf, "%u\n", rtl_fe_switch_get(priv->fe));
}

static ssize_t l2_switch_store(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));
	bool enabled;
	int ret = kstrtobool(buf, &enabled);

	if (ret)
		return ret;
	/* Request the policy compiler; never open raw L2 ingress from sysfs.
	 * A true request may still safely fall back for unsupported topology. */
	ret = rtl_fe_switch_set(priv->fe, enabled);
	if (ret)
		return ret;
	return count;
}
static DEVICE_ATTR_RW(l2_switch);

static ssize_t l2_state_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));

	return rtl_fe_state(priv->fe, buf);
}
static DEVICE_ATTR_RO(l2_state);

static ssize_t l2_evidence_show(struct device *dev, struct device_attribute *attr,
			       char *buf)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));

	return rtl_fe_l2_evidence(priv->fe, buf);
}
static DEVICE_ATTR_RO(l2_evidence);

static ssize_t lan_mib_evidence_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(dev));
	struct rtl_lan_mib_evidence samples[5];
	int ifindices[5] = {0};
	u32 registered;
	unsigned int port;
	ssize_t length;

	/* Never issue MMIO, an indirect command or a new PM sample from this
	 * getter. A stalled background read must not block evidence collection.
	 * Formatting happens after the small cache copy releases the lock. */
	if (!rtnl_trylock())
		return -EAGAIN;
	if (!mutex_trylock(&priv->mib_lock)) {
		rtnl_unlock();
		return -EAGAIN;
	}
	memcpy(samples, priv->mib_evidence, sizeof(samples));
	registered = READ_ONCE(priv->registered_ports);
	for (port = 0; port < ARRAY_SIZE(samples); port++) {
		struct net_device *netdev = READ_ONCE(priv->ports[port]);

		/* RTNL prevents a registered netdev from being freed. Never
		 * dereference a not-yet-registered asynchronous probe candidate. */
		if ((registered & BIT(port)) && netdev)
			ifindices[port] = netdev->ifindex;
	}
	mutex_unlock(&priv->mib_lock);
	rtnl_unlock();
	length = sysfs_emit(buf,
		"schema=1 cached=1 clock=boottime raw=1 reset_tracking=0 "
		"counter_mode_verified=0 "
		"l2_attribution=0 atomic_hardware_snapshot=0 read_opcode=0 "
		"capture_ns=%llu registered_mask=%#x\n",
		ktime_get_boottime_ns(), registered);
	for (port = 0; port < ARRAY_SIZE(samples); port++) {
		const struct rtl_lan_mib_evidence *sample = &samples[port];

		length += sysfs_emit_at(buf, length,
			"port=%u ifindex=%d registered=%u valid=%u error=%d seq=%llu attempts=%llu "
			"begin_ns=%llu end_ns=%llu attempt_begin_ns=%llu attempt_end_ns=%llu "
			"rx_bytes=%llu tx_bytes=%llu rx_uc=%u rx_mc=%u rx_bc=%u "
			"tx_uc=%u tx_mc=%u tx_bc=%u config_begin=%#x config_end=%#x\n",
			port, ifindices[port], !!(registered & BIT(port)), sample->valid,
			sample->attempts ? sample->error : -ENODATA,
			sample->seq, sample->attempts, sample->begin_ns, sample->end_ns,
			sample->attempt_begin_ns, sample->attempt_end_ns,
			sample->rx_bytes, sample->tx_bytes, sample->rx_uc,
			sample->rx_mc, sample->rx_bc, sample->tx_uc, sample->tx_mc,
			sample->tx_bc, sample->config_begin, sample->config_end);
	}
	return length;
}
static DEVICE_ATTR_RO(lan_mib_evidence);

static struct attribute *rtl_native_attrs[] = {
	&dev_attr_xram_state.attr,
	&dev_attr_dma_state.attr,
	&dev_attr_datapath_profile.attr,
	&dev_attr_idle_poll_ms.attr,
	&dev_attr_pipeline_state.attr,
	&dev_attr_qm_state.attr,
	&dev_attr_qm_voqs.attr,
	&dev_attr_rx_prefetch.attr,
	&dev_attr_pppoe_rx_checksum.attr,
	&dev_attr_qm_trace.attr,
	&dev_attr_qm_pool.attr,
	&dev_attr_pon_deepq.attr,
	&dev_attr_qm_wait.attr,
	&dev_attr_qm_es.attr,
	&dev_attr_qm_buffer.attr,
	&dev_attr_rx_bypass.attr,
	&dev_attr_l2_switch.attr,
	&dev_attr_l2_state.attr,
	&dev_attr_l2_evidence.attr,
	&dev_attr_lan_mib_evidence.attr,
	NULL,
};
static umode_t rtl_native_visible(struct kobject *kobj, struct attribute *attr, int index)
{
	struct rtl_xram *priv = netdev_priv(dev_get_drvdata(kobj_to_dev(kobj)));

	if ((attr == &dev_attr_l2_switch.attr || attr == &dev_attr_l2_state.attr ||
	     attr == &dev_attr_l2_evidence.attr) &&
	    !priv->fe)
		return 0;
	if (!priv->qm_rx &&
	    (attr == &dev_attr_qm_pool.attr || attr == &dev_attr_qm_voqs.attr ||
	     attr == &dev_attr_rx_prefetch.attr || attr == &dev_attr_pppoe_rx_checksum.attr ||
	     attr == &dev_attr_pon_deepq.attr || attr == &dev_attr_qm_trace.attr ||
	     attr == &dev_attr_qm_wait.attr || attr == &dev_attr_qm_es.attr ||
	     attr == &dev_attr_qm_buffer.attr))
		return 0;
	return attr->mode;
}

static const struct attribute_group rtl_native_group = {
	.attrs = rtl_native_attrs,
	.is_visible = rtl_native_visible,
};

static const struct attribute_group *rtl_native_groups[] = {
	&rtl_native_group,
	NULL,
};

static bool rtl_ni_release_dma(struct rtl_xram *priv, struct device *dev)
{
	bool fe_released = rtl_fe_free(priv->fe);

	if (fe_released) {
		priv->fe = NULL;
		priv->qm.fe = NULL;
	}
	/* A never-opened interface may still have a bound flow callback. In that
	 * case FE deliberately keeps its private owner even without DMA exposure.
	 * Keep the physical claim and parent device as well; do not let another
	 * probe reuse the registers beneath that callback. */
	if (priv->dma_exposed || !fe_released) {
		rtl_ni_owner_expose(priv->owner);
		dev_err(dev, "NI teardown quarantined: DMA=%u FE_released=%u; buffers and physical owner retained, reboot required\n",
			priv->dma_exposed, fe_released);
		return false;
	}
	if (priv->qm_rx && priv->qm.memory)
		rtl_qm_rx_free(dev, &priv->qm);
	if (priv->dma_tx && priv->dma.memory)
		rtl_dma_tx_free(dev, &priv->dma);
	return true;
}

static int rtl_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct net_device *netdev;
	struct rtl_xram *priv;
	u8 mac[ETH_ALEN];
	u32 value;
	bool release_owner = true;
	int ret;

	netdev = alloc_etherdev(sizeof(*priv));
	if (!netdev)
		return -ENOMEM;
	SET_NETDEV_DEV(netdev, dev);
	priv = netdev_priv(netdev);
	priv->lan.shared = priv;
	priv->netdev = netdev;
	priv->idle_poll_ms = 4;
	priv->owner = rtl_ni_owner_claim(dev,
		platform_get_resource(pdev, IORESOURCE_MEM, 0));
	if (IS_ERR(priv->owner)) {
		ret = PTR_ERR(priv->owner);
		priv->owner = NULL;
		goto free_netdev;
	}
	priv->ni = devm_platform_ioremap_resource(pdev, 0);
	priv->xram = devm_platform_ioremap_resource(pdev, 1);
	if (IS_ERR(priv->ni) || IS_ERR(priv->xram)) {
		ret = IS_ERR(priv->ni) ? PTR_ERR(priv->ni) : PTR_ERR(priv->xram);
		goto free_netdev;
	}
	ret = of_property_read_u32(dev->of_node, "realtek,port", &priv->port);
	if (ret)
		goto free_netdev;
	priv->lan.port = priv->port;
	snprintf(netdev->name, sizeof(netdev->name), "lan%u", rtl_lan_number(priv->port));
	value = readl(priv->ni + MAC_ADDR0);
	put_unaligned_be32(value, mac);
	mac[4] = readl(priv->ni + MAC_ADDR1);
	mac[5] = readl(priv->ni + PORT_STATIC + priv->port * PORT_STRIDE) >> 24;
	eth_hw_addr_set(netdev, mac);
	netdev->netdev_ops = &rtl_netdev_ops;
	netdev->ethtool_ops = &rtl_ethtool_ops;
	netdev->max_mtu = ETH_DATA_LEN;
	spin_lock_init(&priv->tx_lock);
	spin_lock_init(&priv->rx_lock);
	mutex_init(&priv->mib_lock);
	init_completion(&priv->lan4_ready);
	INIT_DELAYED_WORK(&priv->mib_work, rtl_mib_work);
	netif_napi_add(netdev, &priv->napi, rtl_poll);
	hrtimer_setup(&priv->timer, rtl_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	priv->dma_tx = of_property_read_bool(dev->of_node, "realtek,dma-tx");
	if (priv->dma_tx) {
		priv->dma.registers = devm_platform_ioremap_resource(pdev, 2);
		if (IS_ERR(priv->dma.registers)) {
			ret = PTR_ERR(priv->dma.registers);
			goto del_napi;
		}
		priv->dma.axi_reorder = devm_platform_ioremap_resource_byname(pdev,
									      "dma-axi-reorder");
		if (IS_ERR(priv->dma.axi_reorder)) {
			ret = PTR_ERR(priv->dma.axi_reorder);
			goto del_napi;
		}
		priv->dma.port = priv->port;
		priv->dma.vp = 8;
		ret = rtl_dma_tx_alloc(dev, &priv->dma);
		if (ret)
			goto del_napi;
	}
	priv->qm_rx = of_property_read_bool(dev->of_node, "realtek,qm-rx");
	if (priv->qm_rx) {
		priv->qm.rx_prefetch = true;
		priv->qm.ni = priv->ni;
		priv->qm.axi_reorder = devm_platform_ioremap_resource(pdev, 3);
		if (IS_ERR(priv->qm.axi_reorder)) {
			ret = PTR_ERR(priv->qm.axi_reorder);
			goto free_dma;
		}
		priv->qm.block_reset = devm_platform_ioremap_resource(pdev, 4);
		if (IS_ERR(priv->qm.block_reset)) {
			ret = PTR_ERR(priv->qm.block_reset);
			goto free_dma;
		}
		ret = rtl_qm_rx_alloc(dev, &priv->qm);
		if (ret)
			goto free_dma;
		priv->rx_irq = platform_get_irq(pdev, 0);
		if (priv->rx_irq < 0) {
			ret = priv->rx_irq;
			goto free_dma;
		}
		rtl_update(priv, 0x6110, 0xff, 0);
		ret = request_irq(priv->rx_irq, rtl_rx_irq, 0, "rtl9617c-rx0", priv);
		if (ret)
			goto free_dma;
		priv->irq_requested = true;
	}
	if(priv->qm_rx) {
		priv->fe=rtl_fe_allocate(dev,priv->ni);
		if(IS_ERR(priv->fe)){ret=PTR_ERR(priv->fe);priv->fe=NULL;goto free_dma;}
		priv->qm.fe = priv->fe;
	}
	platform_set_drvdata(pdev, netdev);
	rtl_register_lans(priv, dev);
	ret = sysfs_create_groups(&dev->kobj, rtl_native_groups);
	if (ret)
		dev_warn(dev, "NI diagnostic attributes unavailable: %d\n", ret);
	else
		priv->native_groups_created = true;
	schedule_delayed_work(&priv->mib_work, HZ);
	return 0;

free_dma:
	if (priv->irq_requested)
		free_irq(priv->rx_irq, priv);
	release_owner = rtl_ni_release_dma(priv, dev);
del_napi:
	netif_napi_del(&priv->napi);
free_netdev:
	if (release_owner) {
		rtl_ni_owner_release(priv->owner);
		free_netdev(netdev);
	}
	return ret;
}

static void rtl_remove(struct platform_device *pdev)
{
	struct net_device *dev = platform_get_drvdata(pdev);
	struct rtl_xram *priv = netdev_priv(dev);
	unsigned long flags;
	unsigned int port;
	bool release_owner;

	if (priv->lan4_phy)
		flush_work(&priv->lan4_work);
	cancel_delayed_work_sync(&priv->mib_work);
	WRITE_ONCE(priv->removing, true);
	if (priv->native_groups_created)
		sysfs_remove_groups(&pdev->dev.kobj, rtl_native_groups);
	for (port = 0; port < ARRAY_SIZE(priv->ports); port++)
		rtl_unregister_lan(priv, port);
	/* Device links normally remove PON consumers first. Independently sever
	 * every software callback before devm MMIO mappings can disappear. */
	rtnl_lock();
	rcu_assign_pointer(priv->qm.pon, NULL);
	rtl_engine_stop(priv);
	priv->engine_users = 0;
	spin_lock_irqsave(&priv->tx_lock, flags);
	memset(priv->dma.owners, 0, sizeof(priv->dma.owners));
	spin_unlock_irqrestore(&priv->tx_lock, flags);
	rtl_engine_poison(priv);
	rtnl_unlock();
	synchronize_net();
	if (priv->irq_requested)
		free_irq(priv->rx_irq, priv);
	release_owner = rtl_ni_release_dma(priv, &pdev->dev);
	netif_napi_del(&priv->napi);
	platform_set_drvdata(pdev, NULL);
	if (release_owner) {
		rtl_ni_owner_release(priv->owner);
		free_netdev(dev);
	}
}

static const struct of_device_id rtl_match[] = {
	{ .compatible = "realtek,rtl9617c-xram-eth" }, { }
};
MODULE_DEVICE_TABLE(of, rtl_match);

static struct platform_driver rtl_driver = {
	.probe = rtl_probe,
	.remove = rtl_remove,
	.driver = { .name = "rtl9617c-xram", .of_match_table = rtl_match,
		    .suppress_bind_attrs = true },
};
module_platform_driver(rtl_driver);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RTL9617C management XRAM Ethernet");
