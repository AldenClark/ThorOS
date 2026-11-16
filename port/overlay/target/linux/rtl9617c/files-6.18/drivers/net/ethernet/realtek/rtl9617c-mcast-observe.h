/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTL9617C_MCAST_OBSERVE_H
#define RTL9617C_MCAST_OBSERVE_H

/* Passive evidence from already validated, CPU-owned HeaderA words only.
 *
 * ca-network-drivers@8b4f4882, aal-77c/include/aal_common.h HEADER_A_T:
 * word0 rx_pkt_type=12:11, mirror=14, pol_id=26:18;
 * word1 lspid=14:9, hdr_type=31:30. aal_port.h defines MC LSPID=0x1b.
 * hdr_type=3 overloads word0 bits30:0 with PTP metadata (cpu_flg remains bit31).
 * hdr_type=2 also overloads mcgid with L2 learning information. Therefore
 * neither a nonzero pol_id nor mcgid nor the MC source proves that hardware
 * forwarded the packet, its original ingress, or a bridge generation.
 *
 * One NAPI owner writes this state. No allocation, table/MMIO access, packet
 * payload/address retention or inferred offload_fwd_mark is permitted here.
 * The last raw HeaderA pair is one aligned word, read with READ_ONCE by the
 * ARM64 diagnostic consumer. It is NOT an atomic snapshot of the counters.
 * Keeping this hook before demux makes otherwise generic-dropped source27
 * candidates observable without inventing a replacement source device.
 */
struct rtl_mcast_observe {
	unsigned long long hdr_bum;
	unsigned long long source27;
	unsigned long long source27_cpu;
	unsigned long long source27_ptp;
	unsigned long long source27_pol_nonzero;
	unsigned long long source27_mirror;
	unsigned long long last_source27_header;
};

static inline void rtl_mcast_observe_rx(struct rtl_mcast_observe *observe,
				       unsigned int header0,
				       unsigned int header1,
				       unsigned int length)
{
	unsigned int format = header1 >> 30;
	unsigned int source = (header1 >> 9) & 63U;

	/* The production caller has already checked EPP ownership and framing.
	 * Retain a defensive minimum for isolated callers and host fault tests. */
	if (!observe || length < 14)
		return;
	if (format != 3 && ((header0 >> 11) & 3U))
		observe->hdr_bum++;
	if (source != 27)
		return;
	observe->source27++;
	observe->source27_cpu += format == 2;
	observe->source27_ptp += format == 3;
	if (format != 3) {
		observe->source27_pol_nonzero += !!((header0 >> 18) & 511U);
		observe->source27_mirror += !!(header0 & (1U << 14));
	}
	WRITE_ONCE(observe->last_source27_header,
		   ((unsigned long long)header0 << 32) | header1);
}

#endif
