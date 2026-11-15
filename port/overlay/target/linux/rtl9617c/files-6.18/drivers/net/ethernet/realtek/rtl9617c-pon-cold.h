/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_PON_COLD_H
#define RTL9617C_PON_COLD_H

#ifdef __KERNEL__
#include <linux/delay.h>
#endif
#include "rtl9617c-qm-deepq.h"

/* Cold NI owner only, before ANY native LAN/PON user is published. The
 * adapter maps PON MAC offsets below 0xc000 and the three explicitly named
 * GLOBAL resources (low 32-bit SDK addresses), without owning an optical
 * driver, GPIO, BOSA or laser setting. GLOBAL words are NEVER written.
 * The NI probe is the sole native owner throughout this helper and the
 * subsequent fabric transaction; concurrent external firmware writers
 * are unsupported. Snapshot rechecks detect drift, not arbitrary bus races.
 *
 * Sources: pinned GPL aal-77c aal_pon.c:aal_pon_mac_enable_set,
 * aal_gpon.c:aal_gpon_active_set, aal_epon_mac.c:aal_epon_csr_reset /
 * aal_epon_mac_sw_reset_set, aal_xgpon.c:__glb_gpon_ctrl_init and
 * aal_psds.c:__psds_eth_csr_reset / aal_psds_out_of_reset.
 *
 * In particular, the SDK leaves EPON in reset in GPON modes. Do not access
 * every possible family, nor dispatch from the native PON default mode.
 * Reset/mux selection avoids held-reset MAC accesses; it is not a proof
 * that the APB bus or the board's clocks respond on real hardware. A LOS or
 * missing optical clock is not interpreted as a fabricated bus timeout.
 *
 * GPON en / XG mac_en are the SDK's receive-admission controls, not a
 * promise that protocol TX timing is unaffected. No dedicated TX, burst,
 * optical GPIO or global reset register is changed here.
 */
#define RTL_PON_COLD_RX_GATES(X) \
	X(EPON_1G, 0x088cU, 1U) \
	X(EPON_10G, 0x10b4U, 1U << 7) \
	X(GPON, 0x6114U, 1U << 1) \
	X(XGPON, 0x4004U, 3U)

#define RTL_PON_COLD_CONTROL 0xf4320094U
#define RTL_PON_COLD_EPON_CONTROL 0xf4320074U
#define RTL_PON_COLD_GPON_CONTROL 0xf432007cU
#define RTL_PON_COLD_EPON_MODE (1U << 0)
/* Despite its name, SDK pdc_reset=0 asserts reset; 1 releases it. */
#define RTL_PON_COLD_PDC_RELEASED (1U << 9)
#define RTL_PON_COLD_EPON_RELEASED (1U << 0)
#define RTL_PON_COLD_EPON_1G_RELEASED (1U << 2)
#define RTL_PON_COLD_EPON_10G_RELEASED (1U << 3)
#define RTL_PON_COLD_ACTIVE_ETH_RELEASED (1U << 9)
#define RTL_PON_COLD_EPON_ETHERNET_MODE (1U << 18)
#define RTL_PON_COLD_ANI_RELEASED (1U << 0)
#define RTL_PON_COLD_GPON_RELEASED (1U << 1)
#define RTL_PON_COLD_XGPON_RELEASED (1U << 2)

#define RTL_PON_COLD_PDC_FIFO_STATUS 0x9010U
#define RTL_PON_COLD_PDC_FIFO_DEPTH 31U
#define RTL_PON_COLD_FIFO_POLLS 1000U
#define RTL_PON_COLD_FIFO_STABLE 3U

enum rtl_pon_cold_gate_id {
#define RTL_PON_COLD_GATE_ID(name, reg, mask) RTL_PON_COLD_GATE_##name,
	RTL_PON_COLD_RX_GATES(RTL_PON_COLD_GATE_ID)
#undef RTL_PON_COLD_GATE_ID
	RTL_PON_COLD_GATE_COUNT,
};

enum rtl_pon_cold_stage {
	RTL_PON_COLD_NONE,
	RTL_PON_COLD_GLOBAL,
	RTL_PON_COLD_SELECT,
	RTL_PON_COLD_GATE,
	RTL_PON_COLD_READBACK,
	RTL_PON_COLD_FIFO,
	RTL_PON_COLD_VERIFY,
	RTL_PON_COLD_READY,
};

struct rtl_pon_cold_state {
	unsigned int control, epon_control, gpon_control;
	unsigned int gated_mask, fifo_status, fifo_polls;
	unsigned int refused_register, refused_value;
	int error;
	unsigned char pdc_active, stage, ready;
};

static const struct {
	unsigned int reg, mask;
} rtl_pon_cold_gates[] = {
#define RTL_PON_COLD_GATE_ENTRY(name, reg, mask) { reg, mask },
	RTL_PON_COLD_RX_GATES(RTL_PON_COLD_GATE_ENTRY)
#undef RTL_PON_COLD_GATE_ENTRY
};

static inline int rtl_pon_cold_error(struct rtl_pon_cold_state *state,
				    int error, unsigned int reg,
				    unsigned int value)
{
	state->error = error;
	state->refused_register = reg;
	state->refused_value = value;
	state->ready = 0;
	return error;
}

static inline int rtl_pon_cold_globals_match(const struct rtl_dq_io *io,
					    struct rtl_pon_cold_state *state)
{
	unsigned int value;

#define RTL_PON_COLD_VERIFY_GLOBAL(reg, member) do { \
	value = io->read(io->context, reg); \
	if (value != state->member) \
		return rtl_pon_cold_error(state, -EAGAIN, reg, value); \
} while (0)
	RTL_PON_COLD_VERIFY_GLOBAL(RTL_PON_COLD_CONTROL, control);
	RTL_PON_COLD_VERIFY_GLOBAL(RTL_PON_COLD_EPON_CONTROL, epon_control);
	RTL_PON_COLD_VERIFY_GLOBAL(RTL_PON_COLD_GPON_CONTROL, gpon_control);
#undef RTL_PON_COLD_VERIFY_GLOBAL
	return 0;
}

/* Recheck after the NI's own cold fabric transaction, before publication.
 * A changed mux/reset word is NOT permission to touch the newly selected
 * MAC. Reject first. The caller must quarantine any ambiguous shared write.
 */
static inline int rtl_pon_cold_verify(const struct rtl_dq_io *io,
				     struct rtl_pon_cold_state *state)
{
	unsigned int i, value;
	int ret;

	if (!io || !io->read || !state)
		return -EINVAL;
	if (!state->ready)
		return state->error ? state->error : -EAGAIN;
	state->stage = RTL_PON_COLD_VERIFY;
	ret = rtl_pon_cold_globals_match(io, state);
	if (ret)
		return ret;
	for (i = 0; i < RTL_PON_COLD_GATE_COUNT; i++) {
		if (!(state->gated_mask & (1U << i)))
			continue;
		value = io->read(io->context, rtl_pon_cold_gates[i].reg);
		if (value & rtl_pon_cold_gates[i].mask)
			return rtl_pon_cold_error(state, -EIO,
						  rtl_pon_cold_gates[i].reg, value);
	}
	if (state->pdc_active) {
		value = io->read(io->context, RTL_PON_COLD_PDC_FIFO_STATUS);
		state->fifo_status = value;
		state->fifo_polls++;
		if (value & RTL_PON_COLD_PDC_FIFO_DEPTH)
			return rtl_pon_cold_error(state, -EBUSY,
						  RTL_PON_COLD_PDC_FIFO_STATUS, value);
	}
	state->stage = RTL_PON_COLD_READY;
	state->error = 0;
	return 0;
}

static inline int rtl_pon_cold_quiesce(const struct rtl_dq_io *io,
				      struct rtl_pon_cold_state *state)
{
	unsigned int i, value, children, stable = 0;
	int ret;

	if (!io || !io->read || !io->write || !state)
		return -EINVAL;
	*state = (struct rtl_pon_cold_state){ 0 };
	state->stage = RTL_PON_COLD_GLOBAL;
	state->control = io->read(io->context, RTL_PON_COLD_CONTROL);
	state->epon_control = io->read(io->context, RTL_PON_COLD_EPON_CONTROL);
	state->gpon_control = io->read(io->context, RTL_PON_COLD_GPON_CONTROL);
	/* All-ones is not an admissible mode/reset snapshot. Do not turn a
	 * missing register window into permission for broad MAC accesses. */
	if (state->control == ~0U)
		return rtl_pon_cold_error(state, -EIO, RTL_PON_COLD_CONTROL,
					  state->control);
	if (state->epon_control == ~0U)
		return rtl_pon_cold_error(state, -EIO, RTL_PON_COLD_EPON_CONTROL,
					  state->epon_control);
	if (state->gpon_control == ~0U)
		return rtl_pon_cold_error(state, -EIO, RTL_PON_COLD_GPON_CONTROL,
					  state->gpon_control);
	/* Reject a torn initial reset/mux snapshot before any MAC access. Do
	 * not resample and reinterpret it as a different selected family. */
	ret = rtl_pon_cold_globals_match(io, state);
	if (ret)
		return ret;
	state->pdc_active = !!(state->control & RTL_PON_COLD_PDC_RELEASED);
	if (!state->pdc_active) {
		/* PDC is already held in reset: do not read its FIFO or any MAC.
		 * NI must still perform its OWN local drain; this is not a DDR
		 * retirement or a proof about work already accepted by NI. */
		state->ready = 1;
		return rtl_pon_cold_verify(io, state);
	}
	state->stage = RTL_PON_COLD_SELECT;
	if (state->control & RTL_PON_COLD_EPON_MODE) {
		/* Active Ethernet can have epon_ethernet_mode=0: the SDK writes
		 * 0x30200, enabling its separate block while EPON stays reset. */
		if (state->epon_control & (RTL_PON_COLD_ACTIVE_ETH_RELEASED |
					   RTL_PON_COLD_EPON_ETHERNET_MODE))
			return rtl_pon_cold_error(state, -EOPNOTSUPP,
				RTL_PON_COLD_EPON_CONTROL, state->epon_control);
		children = state->epon_control & (RTL_PON_COLD_EPON_1G_RELEASED |
						  RTL_PON_COLD_EPON_10G_RELEASED);
		if (children && !(state->epon_control & RTL_PON_COLD_EPON_RELEASED))
			return rtl_pon_cold_error(state, -EOPNOTSUPP,
				RTL_PON_COLD_EPON_CONTROL, state->epon_control);
		if (children & RTL_PON_COLD_EPON_1G_RELEASED)
			state->gated_mask |= 1U << RTL_PON_COLD_GATE_EPON_1G;
		if (children & RTL_PON_COLD_EPON_10G_RELEASED)
			state->gated_mask |= 1U << RTL_PON_COLD_GATE_EPON_10G;
	} else {
		children = state->gpon_control & (RTL_PON_COLD_GPON_RELEASED |
						  RTL_PON_COLD_XGPON_RELEASED);
		if (children && !(state->gpon_control & RTL_PON_COLD_ANI_RELEASED))
			return rtl_pon_cold_error(state, -EOPNOTSUPP,
				RTL_PON_COLD_GPON_CONTROL, state->gpon_control);
		if (children & RTL_PON_COLD_GPON_RELEASED)
			state->gated_mask |= 1U << RTL_PON_COLD_GATE_GPON;
		if (children & RTL_PON_COLD_XGPON_RELEASED)
			state->gated_mask |= 1U << RTL_PON_COLD_GATE_XGPON;
	}
	/* Gate every RELEASED MAC in the selected family. This also handles
	 * SDK's temporary GPON+XG release and EPON's simultaneous 1G/10G
	 * release, without touching the unused, held-reset opposite family. */
	state->stage = RTL_PON_COLD_GATE;
	for (i = 0; i < RTL_PON_COLD_GATE_COUNT; i++) {
		if (!(state->gated_mask & (1U << i)))
			continue;
		value = io->read(io->context, rtl_pon_cold_gates[i].reg);
		if (value == ~0U)
			return rtl_pon_cold_error(state, -EIO,
						  rtl_pon_cold_gates[i].reg, value);
		if (value & rtl_pon_cold_gates[i].mask)
			io->write(io->context, rtl_pon_cold_gates[i].reg,
				  value & ~rtl_pon_cold_gates[i].mask);
	}
	state->stage = RTL_PON_COLD_READBACK;
	for (i = 0; i < RTL_PON_COLD_GATE_COUNT; i++) {
		if (!(state->gated_mask & (1U << i)))
			continue;
		value = io->read(io->context, rtl_pon_cold_gates[i].reg);
		if (value & rtl_pon_cold_gates[i].mask)
			return rtl_pon_cold_error(state, -EIO,
						  rtl_pon_cold_gates[i].reg, value);
	}
	state->stage = RTL_PON_COLD_FIFO;
	for (i = 0; i < RTL_PON_COLD_FIFO_POLLS; i++) {
		value = io->read(io->context, RTL_PON_COLD_PDC_FIFO_STATUS);
		state->fifo_status = value;
		state->fifo_polls++;
		if (value & RTL_PON_COLD_PDC_FIFO_DEPTH)
			stable = 0;
		else if (++stable == RTL_PON_COLD_FIFO_STABLE)
			break;
		usleep_range(100, 200);
	}
	if (i == RTL_PON_COLD_FIFO_POLLS)
		return rtl_pon_cold_error(state, -ETIMEDOUT,
			RTL_PON_COLD_PDC_FIFO_STATUS, state->fifo_status);
	/* No restore: normal PON mode initialization owns explicit reopen.
	 * Stable PDC occupancy is only a local FIFO check, NOT NI/DDR drain. */
	state->ready = 1;
	return rtl_pon_cold_verify(io, state);
}

#endif
