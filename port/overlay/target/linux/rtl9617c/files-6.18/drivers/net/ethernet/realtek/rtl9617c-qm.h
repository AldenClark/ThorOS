/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_QM_H
#define RTL9617C_QM_H
#include <linux/dma-mapping.h>
#include <linux/netdevice.h>
#include <linux/rtl9617c-qm-layout.h>
#include "rtl9617c-ni.h"
#include "rtl9617c-qm-refill.h"
#include "rtl9617c-qm-deepq.h"

#define RTL_QM_RING_BYTES 1024
#define RTL_QM_COMMAND_BYTES 8
#define RTL_QM_VOQS 8
#define RTL_QM_BUFFERS_PER_EQ 256
#define RTL_QM_BUFFERS (2 * RTL_QM_BUFFERS_PER_EQ)
#define RTL_QM_MEMORY_BYTES (RTL_QM_RING_BYTES * RTL_QM_VOQS + RTL_QM_BUFFERS * RTL_QM_BUFFER_BYTES)

struct rtl_fe;

struct rtl_qm_rx {
	void __iomem *ni;
	void __iomem *axi_reorder;
	void __iomem *block_reset;
	void *memory;
	dma_addr_t memory_dma;
	struct device *device;
	void *ring_memory;
	dma_addr_t ring_dma;
	void *deepq_memory;
	dma_addr_t deepq_dma;
	bool deepq_configured;
	unsigned int read[RTL_QM_VOQS];
	u32 last_address;
	u32 last_size;
	u32 last_header[2];
	u32 trace[32][7];
	unsigned int trace_count;
	struct net_device __rcu *lan[5];
	/* Shared lifetime: allocated before LAN registration, freed after NAPI. */
	struct rtl_fe *fe;
	struct rtl_qm_refill refill;
	struct rtl9617c_ni_endpoint __rcu *pon;
	bool profile;
	u64 host_poll_ns, host_polls;
	u64 voq_packets[RTL_QM_VOQS];
	u64 poll_budget_hits;
	/* Valid L2 bytes delivered to the CPU, including allocation drops. */
	u64 cpu_packets, cpu_bytes;
	u64 ring_errors, buffer_errors;
	bool rx_prefetch;
	bool pppoe_rx_checksum;
};

int rtl_qm_rx_alloc(struct device *dev, struct rtl_qm_rx *rx);
int rtl_qm_rx_start(struct rtl_qm_rx *rx, unsigned int port);
void rtl_qm_rx_stop(struct rtl_qm_rx *rx);
void rtl_qm_rx_free(struct device *dev, struct rtl_qm_rx *rx);
int rtl_qm_rx_poll(struct rtl_qm_rx *rx, struct napi_struct *napi, int budget);
ssize_t rtl_qm_rx_state(struct rtl_qm_rx *rx, char *buf);
ssize_t rtl_qm_rx_voq_state(struct rtl_qm_rx *rx, char *buf);
ssize_t rtl_qm_rx_trace(struct rtl_qm_rx *rx, char *buf);
ssize_t rtl_qm_rx_pool(struct rtl_qm_rx *rx, char *buf);
ssize_t rtl_qm_deepq_state(struct rtl_qm_rx *rx, char *buf);
#endif
