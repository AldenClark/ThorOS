/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_FRAME_H
#define RTL9617C_FRAME_H

/* Supported physical UNI envelope: MTU1500 and at most two VLAN headers.
 * SDK aal_ni_l2.h defines UNI min/max in bytes including FCS. GE has one
 * fixed MRU, unlike XGE's tag-aware AUTO mode. This is a bounded hardware
 * MRU policy, not a byte-exact copy of the software bridge egress test.
 * All recognised tagged native ingress is redirected to the CPU.
 */
#define RTL_NI_FRAME_MTU 1500U
#define RTL_NI_FRAME_MAX_TAGS 2U
#define RTL_NI_FRAME_BYTES (14U + RTL_NI_FRAME_MTU + 4U * RTL_NI_FRAME_MAX_TAGS)
#define RTL_NI_FRAME_WIRE_BYTES (RTL_NI_FRAME_BYTES + 4U)

#endif
