/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_QM_RESOURCES_H
#define RTL9617C_QM_RESOURCES_H

/* RTL77C has 16 EQs and one 16K BID namespace, not 16K BIDs per EQ.
 * aal-77c/aal_l3qm.c checks this global limit and places DQ BIDs after
 * CPU BIDs. CFG1_EQ fields are 14 bits, EPP byte pointers are 24 bits,
 * EPP size is in 16-byte units and CFG2_EQ.refill_ths is eight bits.
 * Keep the resource plan together: growing a CPU pool must also move DQ
 * BIDs and grow the deferred-return queue, not create duplicate owners.
 */
#define RTL_QM_BID_LIMIT 16384
#define RTL_QM_EQ_LIMIT 16
#define RTL_QM_CPU_EQ_FIRST 4
#define RTL_QM_CPU_EQ_COUNT 2
#define RTL_QM_BUFFERS_PER_EQ 512
#define RTL_QM_BUFFERS (RTL_QM_CPU_EQ_COUNT * RTL_QM_BUFFERS_PER_EQ)
#define RTL_QM_CPU_BID_FIRST 0
#define RTL_QM_CPU_BID_END (RTL_QM_CPU_BID_FIRST + RTL_QM_BUFFERS)
#define RTL_QM_RESOURCE_BUFFER_BYTES 2048

/* The NAPI default is 64. Reserve one poll's buffers before the hardware
 * refill threshold, following aal_l3qm_init_empty_buffer_CPU(). There is
 * no change to NAPI weight, coalescing, headroom or supported packet size.
 */
#define RTL_QM_REFILL_RESERVE 64
#define RTL_QM_REFILL_THRESHOLD ((RTL_QM_BUFFERS_PER_EQ - RTL_QM_REFILL_RESERVE) / 8)
#define RTL_QM_REFILL_SIZE RTL_QM_BUFFERS_PER_EQ
#define RTL_QM_RING_BYTES 2048
#define RTL_QM_COMMAND_BYTES 8
#define RTL_QM_VOQS 8
#define RTL_QM_RING_COMMANDS (RTL_QM_RING_BYTES / RTL_QM_COMMAND_BYTES)
#define RTL_QM_RING_MEMORY_BYTES (RTL_QM_RING_BYTES * RTL_QM_VOQS)
#define RTL_QM_PAYLOAD_BYTES (RTL_QM_BUFFERS * RTL_QM_RESOURCE_BUFFER_BYTES)
/* EPPs have their own DMA allocation and base registers. Do not reserve a
 * second, unused copy before the payload: 2MiB plus even one page requires
 * a 4MiB allocation in dma-direct's non-CMA get_order() fallback. This is
 * unrelated to the required per-buffer header/headroom, which is unchanged.
 */
#define RTL_QM_PAYLOAD_OFFSET 0
#define RTL_QM_MEMORY_BYTES RTL_QM_PAYLOAD_BYTES

/* Native hardware-managed WAN private/shared DDR, not the fixed L2 SRAM.
 * CPU EQ4/5: BIDs 0..1023; WAN EQ1/2: BIDs 1024..3071.
 * Payload headroom is 2MiB CPU + 4MiB WAN (previously 1MiB + 2MiB).
 * LAN direct-L2 traffic does not enter these WAN deep queues.
 */
#define RTL_DQ_EQ_PRIVATE 1
#define RTL_DQ_EQ_SHARED 2
#define RTL_DQ_POOL_COUNT 2
#define RTL_DQ_BUFFERS 1024
#define RTL_DQ_BUFFER_BYTES RTL_QM_RESOURCE_BUFFER_BYTES
#define RTL_DQ_BID_FIRST RTL_QM_CPU_BID_END
#define RTL_DQ_BID_END (RTL_DQ_BID_FIRST + RTL_DQ_POOL_COUNT * RTL_DQ_BUFFERS)
#define RTL_DQ_MEMORY_BYTES (RTL_DQ_POOL_COUNT * RTL_DQ_BUFFERS * RTL_DQ_BUFFER_BYTES)

#if RTL_QM_CPU_EQ_COUNT != 2 || RTL_DQ_POOL_COUNT != 2
#error "Native CPU/DQ profile and refill ownership require two pools each"
#endif
#if RTL_QM_CPU_EQ_FIRST < 0 || RTL_QM_CPU_EQ_FIRST + RTL_QM_CPU_EQ_COUNT > RTL_QM_EQ_LIMIT || \
    RTL_DQ_EQ_PRIVATE < 0 || RTL_DQ_EQ_SHARED >= RTL_QM_EQ_LIMIT || \
    RTL_DQ_EQ_SHARED != RTL_DQ_EQ_PRIVATE + 1 || RTL_DQ_EQ_SHARED >= RTL_QM_CPU_EQ_FIRST
#error "CPU and DQ EQ ownership must be disjoint and encodable"
#endif
#if RTL_QM_BUFFERS_PER_EQ <= RTL_QM_REFILL_RESERVE || RTL_QM_BUFFERS_PER_EQ >= RTL_QM_BID_LIMIT || \
    RTL_DQ_BUFFERS <= 0 || RTL_DQ_BUFFERS >= RTL_QM_BID_LIMIT || \
    RTL_QM_CPU_BID_FIRST < 0 || RTL_DQ_BID_FIRST < RTL_QM_CPU_BID_END || \
    RTL_DQ_BID_END > RTL_QM_BID_LIMIT
#error "CPU/DQ BID ranges or counts exceed the shared RTL77C namespace"
#endif
#if RTL_QM_REFILL_THRESHOLD > 255 || RTL_QM_REFILL_SIZE < RTL_QM_BUFFERS_PER_EQ || \
    RTL_QM_BUFFERS_PER_EQ % 64
#error "CPU refill queue/threshold must cover its pool and fit CFG2_EQ"
#endif
#if RTL_QM_COMMAND_BYTES != 8 || RTL_QM_VOQS != 8 || RTL_QM_RING_BYTES < 64 || \
    (RTL_QM_RING_BYTES & (RTL_QM_RING_BYTES - 1)) || RTL_QM_RING_BYTES % 64 || \
    RTL_QM_RING_BYTES > 0x1000000 || RTL_QM_RING_BYTES / 16 > 0x1fffff || \
    RTL_QM_PAYLOAD_OFFSET % RTL_QM_RESOURCE_BUFFER_BYTES
#error "EPP rings must fit the hardware size/pointer fields and DMA alignment"
#endif
#if RTL_QM_RESOURCE_BUFFER_BYTES != 2048 || RTL_DQ_BUFFERS * 4 / 3 >= RTL_QM_BID_LIMIT
#error "QM buffer-size and DQ admission fields must remain encodable"
#endif
#if RTL_QM_PAYLOAD_OFFSET != 0 || RTL_QM_MEMORY_BYTES != RTL_QM_PAYLOAD_BYTES
#error "CPU payload starts at its own DMA base; EPP rings have a separate allocation"
#endif

/* Every native address command has 32 low address bits plus a separately
 * programmed CCI alias. Reject truncation, wrap and misalignment before
 * exposing any DMA address; a larger allocation cannot span that boundary.
 */
static inline int rtl_qm_dma_range_valid(unsigned long long address,
	unsigned int bytes, unsigned int alignment)
{
	return bytes && alignment && !(alignment & (alignment - 1)) &&
		!(address & (alignment - 1)) && address <= 0xffffffffULL &&
		bytes - 1 <= 0xffffffffULL - address;
}

#endif
