/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_FE_CACHE_SNAPSHOT_H
#define RTL9617C_FE_CACHE_SNAPSHOT_H
#include "rtl9617c-fe-table.h"

/* Diagnostic only: the owner holds fe->lock and supplies a read-opcode-only,
 * deadline-bounded io->indirect callback. No production cache commands. */
enum rtl_fe_cache_observation {
 RTL_FE_CACHE_LAYOUT_UNSUPPORTED,
 RTL_FE_CACHE_IO_INCOMPLETE,
 RTL_FE_CACHE_KEY_CHANGED,
 RTL_FE_CACHE_FIB_CHANGED,
 RTL_FE_CACHE_CHECK_ACTION_ONLY,
 RTL_FE_CACHE_SET_MISS,
 RTL_FE_CACHE_EQUAL,
 RTL_FE_CACHE_DIFFERENT,
};
struct rtl_fe_cache_expected {
 unsigned int hash_index,crc32;
 unsigned short crc16;
 unsigned int action[7];
};
struct rtl_fe_cache_snapshot {
 enum rtl_fe_cache_observation observation;
 int error;
 unsigned int complete,scanned,cache_index,location,age,check_actions;
 unsigned int word_mask,diff[7];
};

/* SDK aal_hash_cache_hash_index_get: 2K full-entry cache has64 sets,
 * each with32 ways, selected by CRC16[15:10]. CACHE_HASH_DATA1 contains
 * CRC16[12:0], slot[17:13], location[18], priority[20:19], age[22:21].
 * Age/priority may change autonomously; neither is part of identity.
 * loc1 is Check_Action (SDK aal_hash_cache_aqm_static_entry_add), and
 * cannot be compared to the normal DDR action. Age0 is not an empty test. */
static inline int rtl_fe_cache_identity(const unsigned int a[7],
 const unsigned int b[7])
{
 return a[0]==b[0] && !((a[1]^b[1])&0x7ffffU);
}

static inline void rtl_fe_cache_snapshot(const struct rtl_dq_io *io,
 const struct rtl_fe_cache_expected *expected,struct rtl_fe_cache_snapshot *out)
{
 unsigned int before[7],middle[7],after[7],fib[7],again[7];
 unsigned int base,way,i,config;
 int ret;

 *out=(struct rtl_fe_cache_snapshot){.observation=RTL_FE_CACHE_LAYOUT_UNSUPPORTED,
  .cache_index=RTL_FE_CACHE_ENTRIES};
 /* ct_size4=2K, ca_width3, full internal224-bit action SRAM. */
 config=io->read(io->context,0x38a0);
 if((config&(7U|(7U<<8)|(3U<<16)))!=(4U|(3U<<8)|(1U<<16))) {
  out->error=-EOPNOTSUPP;
  return;
 }
 base=((unsigned int)expected->crc16>>10)<<5;
 for(way=0;way<32;way++) {
  out->scanned=way+1;
  ret=rtl_fe_cache_read(io,base+way,0,before);
  if(ret)goto incomplete;
  if(before[0]!=expected->crc32 || (before[1]&0x1fffU)!=(expected->crc16&0x1fffU) ||
     ((before[1]>>13)&31U)!=(expected->hash_index&31U))continue;
  out->cache_index=base+way;
  out->location=(before[1]>>18)&1U;
  out->age=(before[1]>>21)&3U;
  if(out->location) {
   out->check_actions++;
   continue;
  }
  ret=rtl_fe_cache_read(io,base+way,1,fib);
  if(ret)goto incomplete;
  ret=rtl_fe_cache_read(io,base+way,0,middle);
  if(ret)goto incomplete;
  if(!rtl_fe_cache_identity(before,middle)) {
   out->observation=RTL_FE_CACHE_KEY_CHANGED;
   return;
  }
  ret=rtl_fe_cache_read(io,base+way,1,again);
  if(ret)goto incomplete;
  ret=rtl_fe_cache_read(io,base+way,0,after);
  if(ret)goto incomplete;
  if(!rtl_fe_cache_identity(before,after)) {
   out->observation=RTL_FE_CACHE_KEY_CHANGED;
   return;
  }
  for(i=0;i<7;i++)if(fib[i]!=again[i]) {
   out->observation=RTL_FE_CACHE_FIB_CHANGED;
   return;
  }
  out->age=(after[1]>>21)&3U;
  for(i=0;i<7;i++) {
   out->diff[i]=fib[i]^expected->action[i];
   if(out->diff[i])out->word_mask|=1U<<i;
  }
  out->complete=1;
  out->observation=out->word_mask?RTL_FE_CACHE_DIFFERENT:RTL_FE_CACHE_EQUAL;
  return;
 }
 out->complete=1;
 out->observation=out->check_actions?RTL_FE_CACHE_CHECK_ACTION_ONLY:RTL_FE_CACHE_SET_MISS;
 return;
incomplete:
 out->error=ret;
 out->observation=RTL_FE_CACHE_IO_INCOMPLETE;
}
#endif
