/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_TM_EVIDENCE_H
#define RTL9617C_TM_EVIDENCE_H

/* NI-owned, explicitly requested TM/TE observations. No write/ACCESS callback
 * is provided: collecting evidence cannot change shaping, admission or the
 * shared ARB mapping. Reading a PM register CAN consume clear-on-read state.
 * The caller serializes all captures and cache readers with one owner mutex.
 *
 * Register reference: GPL-for-GP3000@5090fbcb6ba743dd7b1314811ef557bad0460147,
 * rtl8277c_registers.h. Behaviour reference: ca-network-drivers at
 * 8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0, aal-77c/aal_l2_tm.c.
 * L2TM GLB_CTRL.cntrcfg_clear_on_read controls BM counters. In contrast,
 * L2TE PM_CTRL.mem_auto_clr_on_read describes the indirect PM MEMORY, not a
 * proved mode for the direct TE drop registers. TE values remain RAW ONLY.
 */
#define RTL_TM_CAPTURE_MIN_NS 250000000ULL
#define RTL_TM_BM_COUNTERS 7U
#define RTL_TM_COUNTERS 11U

enum rtl_tm_config_index {
	RTL_TM_CLEAR_CONTROL, RTL_TM_BM_CONTROL, RTL_TM_BUFFER_CONFIG,
	RTL_TM_EQ_CONFIG, RTL_TM_PRIVATE_CONFIG, RTL_TM_ES_CONTROL,
	RTL_TM_ES_LAN0, RTL_TM_ES_LAN1, RTL_TM_ES_LAN2, RTL_TM_ES_LAN3,
	RTL_TM_ES_LAN4, RTL_TM_ES_L3WAN10, RTL_TM_ES_OAM12, RTL_TM_ES_L3LAN13,
	RTL_TM_TE_CONTROL, RTL_TM_FC_CONTROL, RTL_TM_TE_PM_CONTROL,
	RTL_TM_NI_INTERNAL, RTL_TM_NI_DEMUX0, RTL_TM_NI_DEMUX1,
	RTL_TM_NI_DEMUX2, RTL_TM_NI_DEMUX3, RTL_TM_NI_DEEP0, RTL_TM_NI_DEEP1,
	RTL_TM_NI_DEEP2, RTL_TM_NI_DEEP3, RTL_TM_LPB_MAP,
	RTL_TM_EQ_WEIGHT, RTL_TM_FE_BACKPRESSURE,
	RTL_TM_PRIVATE_PROFILE1, RTL_TM_PRIVATE_PROFILE2, RTL_TM_PRIVATE_PROFILE3,
	RTL_TM_PRIVATE_SELECT0, RTL_TM_PRIVATE_SELECT1,
	RTL_TM_CONFIGS
};

struct rtl_tm_register {
	const char *name;
	unsigned int offset;
};

static const struct rtl_tm_register rtl_tm_config_registers[] = {
	{"tm_clear_control", 0x2010}, {"bm_control", 0x2110},
	{"buffer_config", 0x2210}, {"eq_config", 0x2208},
	{"private_config", 0x2218}, {"es_control", 0x2300},
	{"es_lan0", 0x2304}, {"es_lan1", 0x2310}, {"es_lan2", 0x231c},
	{"es_lan3", 0x2328}, {"es_lan4", 0x2334},
	{"es_l3wan10", 0x237c}, {"es_oam12", 0x2394}, {"es_l3lan13", 0x23a0},
	{"te_control", 0x2404}, {"fc_control", 0x2908}, {"te_pm_control", 0x2f00},
	{"ni_internal", 0xa1bc}, {"ni_demux0", 0xa1e0}, {"ni_demux1", 0xa1dc},
	{"ni_demux2", 0xa1d8}, {"ni_demux3", 0xa1d4},
	{"ni_deep0", 0xa1f0}, {"ni_deep1", 0xa1ec},
	{"ni_deep2", 0xa1e8}, {"ni_deep3", 0xa1e4},
	{"lpb_map", 0x3404},
	/* Admission depends on the selected private profile, not just profile0.
	 * Inherited/externally changed selectors or pool weights must not leave
	 * apparently comparable BM samples in the same observed epoch. */
	{"eq_weight", 0x220c}, {"fe_backpressure", 0x2214},
	{"private_profile1", 0x221c}, {"private_profile2", 0x2220},
	{"private_profile3", 0x2224},
	{"private_select0", 0x2228}, {"private_select1", 0x222c},
};

static const struct rtl_tm_register rtl_tm_status_registers[] = {
	{"tm_init", 0x200c}, {"te_pm_init", 0x2f08}, {"fc_status", 0x2910},
	{"es_ready", 0x23d0}, {"es_pending0", 0x23d4}, {"es_pending1", 0x23d8},
	{"es_pending2", 0x23dc}, {"es_pending3", 0x23e0},
	{"es_ok0", 0x23e4}, {"es_ok1", 0x23e8}, {"es_ok2", 0x23ec},
	{"es_ok3", 0x23f0}, {"es_port_ok", 0x23f4}, {"es_arb", 0x23f8},
	{"buffer_free", 0x2234},
	/* aal_l2_qm's direct getters: raw instantaneous allocation/status, not
	 * packet/drop counters. No ACCESS selector and no PM clear-on-read bit
	 * is involved. A sampled empty/private mask or CoS buffer use does not
	 * identify the source of the global BM drop counter. */
	{"private_empty_ports", 0x2230}, {"eq_free", 0x2260},
	{"cos0_bufcnt", 0x2238}, {"cos1_bufcnt", 0x223c},
	{"cos2_bufcnt", 0x2240}, {"cos3_bufcnt", 0x2244},
	{"cos4_bufcnt", 0x2248}, {"cos5_bufcnt", 0x224c},
	{"cos6_bufcnt", 0x2250}, {"cos7_bufcnt", 0x2254},
};
#define RTL_TM_STATUSES (sizeof(rtl_tm_status_registers) / sizeof(rtl_tm_status_registers[0]))

static const struct rtl_tm_register rtl_tm_counter_registers[] = {
	{"bm_rx", 0x213c}, {"bm_tx", 0x2140}, {"bm_sb_drop", 0x2144},
	{"bm_hdr_drop", 0x2148}, {"bm_te_drop", 0x214c},
	{"bm_err_drop", 0x2150}, {"bm_nobuf_drop", 0x216c},
	{"te_pol_drop", 0x2f14}, {"te_tail_drop", 0x2f18},
	{"te_wred_y_drop", 0x2f1c}, {"te_wred_g_drop", 0x2f20},
};

enum rtl_tm_epoch_reason {
	RTL_TM_CONTINUOUS, RTL_TM_FIRST_SAMPLE, RTL_TM_CONFIG_CHANGED,
	RTL_TM_CONFIG_UNSTABLE, RTL_TM_DECREASE_OR_SATURATION,
	RTL_TM_OWNER_UNAVAILABLE, RTL_TM_CLOCK_CHANGED, RTL_TM_OWNER_CHANGED,
};

struct rtl_tm_evidence {
	unsigned long long seq, epoch, begin_ns, end_ns, owner_generation;
	unsigned long long observed[RTL_TM_BM_COUNTERS];
	unsigned int config[RTL_TM_CONFIGS], status[RTL_TM_STATUSES];
	unsigned int raw[RTL_TM_COUNTERS];
	unsigned int valid, delta_valid, epoch_reason;
};

struct rtl_tm_observe_io {
	void *context;
	unsigned int (*read)(void *context, unsigned int offset);
	unsigned long long (*clock)(void *context);
};

static inline void rtl_tm_evidence_invalidate(struct rtl_tm_evidence *state)
{
	unsigned int i;

	if (state->valid)
		state->epoch++;
	state->valid = state->delta_valid = 0;
	state->epoch_reason = RTL_TM_OWNER_UNAVAILABLE;
	for (i = 0; i < RTL_TM_BM_COUNTERS; i++)
		state->observed[i] = 0;
}

/* Return 1 for a new sample or 0 for a rate-limited cached sample. Every PM
 * register is read at most once per capture, even if configuration changes.
 * The initial read establishes the baseline and deliberately excludes all
 * boot-time/pre-owner traffic from observed[]. Config changes, unstable
 * reads, decreases (wrap OR reset) and saturation break the epoch; no huge
 * modulo delta is guessed. These are OBSERVED epochs, not proof that an
 * unobservable external reset/reader cannot have occurred between samples.
 */
static inline int rtl_tm_evidence_capture(const struct rtl_tm_observe_io *io,
					struct rtl_tm_evidence *state,
					unsigned long long owner_generation)
{
	struct rtl_tm_evidence next = {0};
	unsigned int i, reason = RTL_TM_CONTINUOUS, unstable = 0;
	unsigned int cleared;

	next.begin_ns = io->clock(io->context);
	if (state->seq && state->owner_generation == owner_generation &&
	    next.begin_ns >= state->end_ns &&
	    next.begin_ns - state->end_ns < RTL_TM_CAPTURE_MIN_NS)
		return 0;
	next.seq = state->seq + 1;
	next.epoch = state->epoch;
	next.owner_generation = owner_generation;
	for (i = 0; i < RTL_TM_CONFIGS; i++)
		next.config[i] = io->read(io->context, rtl_tm_config_registers[i].offset);
	for (i = 0; i < RTL_TM_STATUSES; i++)
		next.status[i] = io->read(io->context, rtl_tm_status_registers[i].offset);
	for (i = 0; i < RTL_TM_COUNTERS; i++)
		next.raw[i] = io->read(io->context, rtl_tm_counter_registers[i].offset);
	for (i = 0; i < RTL_TM_CONFIGS; i++)
		unstable |= next.config[i] !=
			io->read(io->context, rtl_tm_config_registers[i].offset);
	next.end_ns = io->clock(io->context);

	if (!state->valid)
		reason = RTL_TM_FIRST_SAMPLE;
	else if (state->owner_generation != owner_generation)
		reason = RTL_TM_OWNER_CHANGED;
	else if (next.begin_ns <= state->end_ns)
		reason = RTL_TM_CLOCK_CHANGED;
	else {
		for (i = 0; i < RTL_TM_CONFIGS; i++)
			if (state->config[i] != next.config[i])
				reason = RTL_TM_CONFIG_CHANGED;
		/* Exclude idle (bit30); observe only the hardware init flags. */
		if (((state->status[0] ^ next.status[0]) & 0x8000c000U) ||
		    ((state->status[1] ^ next.status[1]) & 15U))
			reason = RTL_TM_CONFIG_CHANGED;
	}
	next.valid = !unstable && next.end_ns >= next.begin_ns;
	if (!next.valid)
		reason = unstable ? RTL_TM_CONFIG_UNSTABLE : RTL_TM_CLOCK_CHANGED;
	cleared = next.config[RTL_TM_CLEAR_CONTROL] >> 31;
	if (!reason) {
		for (i = 0; i < RTL_TM_BM_COUNTERS; i++) {
			unsigned long long increment = next.raw[i];

			if (!cleared) {
				if (next.raw[i] < state->raw[i]) {
					reason = RTL_TM_DECREASE_OR_SATURATION;
					increment = 0;
				} else {
					increment -= state->raw[i];
				}
			}
			if (next.raw[i] == ~0U ||
			    increment > ~0ULL - state->observed[i])
				reason = RTL_TM_DECREASE_OR_SATURATION;
			next.observed[i] = state->observed[i] + increment;
		}
	}
	if (reason) {
		next.epoch++;
		for (i = 0; i < RTL_TM_BM_COUNTERS; i++)
			next.observed[i] = 0;
	}
	next.epoch_reason = reason;
	next.delta_valid = next.valid && !reason;
	*state = next;
	return 1;
}

#endif
