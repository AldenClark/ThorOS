/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_FE_H
#define RTL9617C_FE_H
#include <linux/device.h>
#include <linux/netdevice.h>

struct rtl_fe;
struct rtl_itu_paths;
int rtl_fe_set_itu_paths(struct rtl_fe *fe, struct net_device *dev, const struct rtl_itu_paths *paths);
struct rtl_fe *rtl_fe_allocate(struct device *device, void __iomem *registers);
/* false means a quarantined owner remains; NI must retain its DMA/provider. */
bool rtl_fe_free(struct rtl_fe *fe);
int rtl_fe_add_port(struct rtl_fe *fe, struct net_device *netdev,
                    unsigned int source, unsigned int destination, unsigned int llid);
void rtl_fe_remove_port(struct rtl_fe *fe, struct net_device *netdev);
bool rtl_fe_enabled(struct rtl_fe *fe);
int rtl_fe_flush_port(struct rtl_fe *fe, struct net_device *netdev);
int rtl_fe_setup_tc(struct rtl_fe *fe, struct net_device *netdev,
                    enum tc_setup_type type, void *data);
int rtl_fe_enable(struct rtl_fe *fe);
int rtl_fe_cpu_path(struct rtl_fe *fe);
int rtl_fe_disable(struct rtl_fe *fe);
int rtl_fe_engine_suspend(struct rtl_fe *fe);
int rtl_fe_engine_resume(struct rtl_fe *fe);
int rtl_fe_get_port_parent_id(struct rtl_fe *fe, struct netdev_phys_item_id *ppid);
int rtl_fe_switch_set(struct rtl_fe *fe, bool requested);
bool rtl_fe_switch_get(struct rtl_fe *fe);
void rtl_fe_switch_rx(struct rtl_fe *fe, struct sk_buff *skb,
                     unsigned int source, u32 header0, u32 header1);
ssize_t rtl_fe_state(struct rtl_fe *fe, char *buffer);
ssize_t rtl_fe_l2_evidence(struct rtl_fe *fe, char *buffer);
#endif
