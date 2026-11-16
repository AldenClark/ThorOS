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
 /* A flow block calls several ports. A rule for a different ingress is
  * not evidence that this ingress's metadata format is unsupported. */
 FE_REJECT_OTHER_INGRESS,
 FE_REJECT_COUNT,
};

/* The failing operation, not just errno, identifies an admission refusal.
 * EOPNOTSUPP is used by format, FDB-domain and collision guards alike. */
enum rtl_fe_install_stage {
 FE_INSTALL_NONE,
 FE_INSTALL_PORT,
 FE_INSTALL_FORMAT,
 FE_INSTALL_UNICAST,
 FE_INSTALL_ENGINE,
 FE_INSTALL_POLICY,
 FE_INSTALL_LINK,
 FE_INSTALL_COOKIE,
 FE_INSTALL_HASH_COLLISION,
 FE_INSTALL_HASH_CAPACITY,
 FE_INSTALL_ALLOCATE,
 FE_INSTALL_SOURCE_MAC,
 FE_INSTALL_DESTINATION_MAC,
 FE_INSTALL_INTERFACE,
 FE_INSTALL_MTU,
 FE_INSTALL_COUNTER,
 FE_INSTALL_PUBLISH,
 FE_INSTALL_STAGE_COUNT,
};

static inline const char *rtl_fe_install_stage_name(unsigned int stage)
{
 static const char *const names[]={
  "none","port","format","unicast","engine","policy","link","cookie",
  "hash_collision","hash_capacity","allocate","source_mac","destination_mac",
  "interface","mtu","counter","publish",
 };

 return stage<FE_INSTALL_STAGE_COUNT?names[stage]:"invalid";
}

struct rtl_fe_observe {
 unsigned long long replace_requests, parse_rejected, install_failed, install_succeeded;
 unsigned long long reason[FE_REJECT_COUNT];
 unsigned long long install_unavailable, install_duplicate, install_collision;
 unsigned long long install_unsupported, install_no_space, install_no_memory, install_io, install_other;
 unsigned long long stage_failed[FE_INSTALL_STAGE_COUNT];
 unsigned long long last_failure_request;
 unsigned int stage, last_failure_stage;
 int last_failure_error, rollback_error, last_rollback_error;
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
 unsigned int stage=observe->stage;

 if(!error){observe->install_succeeded++;return;}
 if(stage>=FE_INSTALL_STAGE_COUNT)stage=FE_INSTALL_NONE;
 observe->install_failed++;
 observe->stage_failed[stage]++;
 observe->last_failure_stage=stage;
 observe->last_failure_error=error;
 observe->last_failure_request=observe->replace_requests;
 observe->last_rollback_error=observe->rollback_error;
 switch(error) {
 case -EAGAIN:case -ENODEV:observe->install_unavailable++;break;
 case -EEXIST:observe->install_duplicate++;break;
 case -EOPNOTSUPP:
  if(stage==FE_INSTALL_HASH_COLLISION)observe->install_collision++;
  else observe->install_unsupported++;
  break;
 case -ENOSPC:observe->install_no_space++;break;
 case -ENOMEM:observe->install_no_memory++;break;
 case -EBUSY:case -ETIMEDOUT:case -EIO:observe->install_io++;break;
 default:observe->install_other++;break;
 }
}
#endif
