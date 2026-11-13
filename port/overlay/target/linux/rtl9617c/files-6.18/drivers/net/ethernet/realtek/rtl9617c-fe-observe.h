/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_FE_OBSERVE_H
#define RTL9617C_FE_OBSERVE_H

/* Rule admission telemetry, not packet hit/miss counters. All writers hold
 * fe->lock. Keep this independent of MMIO so rejected rules remain observable
 * even when a hardware table is busy or a PON mapping is unsupported. */
enum rtl_fe_reject_reason {
 FE_REJECT_UNSPECIFIED,
 FE_REJECT_KEYS,
 FE_REJECT_META,
 FE_REJECT_CONTROL,
 FE_REJECT_PROTOCOL,
 FE_REJECT_VLAN,
 FE_REJECT_ACTION,
 FE_REJECT_NAT,
 FE_REJECT_PORT,
 FE_REJECT_PON,
 FE_REJECT_COUNT,
};

struct rtl_fe_observe {
 unsigned long long replace_requests, parse_rejected, install_failed;
 unsigned long long reason[FE_REJECT_COUNT];
 unsigned long long install_unavailable, install_duplicate, install_collision;
 unsigned long long install_no_space, install_no_memory, install_io, install_other;
};

static inline void rtl_fe_observe_parse(struct rtl_fe_observe *observe,
 unsigned int reason)
{
 observe->parse_rejected++;
 if(reason>=FE_REJECT_COUNT)reason=FE_REJECT_UNSPECIFIED;
 observe->reason[reason]++;
}

static inline void rtl_fe_observe_install(struct rtl_fe_observe *observe,int error)
{
 if(!error)return;
 observe->install_failed++;
 switch(error) {
 case -EAGAIN:case -ENODEV:observe->install_unavailable++;break;
 case -EEXIST:observe->install_duplicate++;break;
 /* fe_install rejects a live bucket/CRC collision with EOPNOTSUPP. */
 case -EOPNOTSUPP:observe->install_collision++;break;
 case -ENOSPC:observe->install_no_space++;break;
 case -ENOMEM:observe->install_no_memory++;break;
 case -EBUSY:case -ETIMEDOUT:case -EIO:observe->install_io++;break;
 default:observe->install_other++;break;
 }
}
#endif
