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
 RTL_FE_CACHE_IDENTITY_AMBIGUOUS,
};
struct rtl_fe_cache_expected {
 unsigned int hash_index,crc32;
 unsigned short crc16;
 unsigned int action[RTL_FE_NAPTV6_ACTION_WORDS];
};
struct rtl_fe_cache_snapshot {
 enum rtl_fe_cache_observation observation;
 int error;
 unsigned int complete,scanned,cache_index,location,age,check_actions;
 unsigned int word_mask,action_bits,diff[RTL_FE_NAPTV6_ACTION_WORDS];
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

/* aal_hash.c::__hash_cache_action_internalSram_hw_entry_get reads the
 * second 224-bit half at addr[10]=1, not at the adjacent cache index. */
static inline int rtl_fe_cache_action_read(const struct rtl_dq_io *io,
 unsigned int index,unsigned int half,unsigned int words[14])
{
 int ret=rtl_fe_cache_read(io,index,1,words);

 if(!ret && half)ret=rtl_fe_cache_read(io,index|(1U<<10),1,words+7);
 return ret;
}

static inline void rtl_fe_cache_snapshot(const struct rtl_dq_io *io,
 const struct rtl_fe_cache_expected *expected,struct rtl_fe_cache_snapshot *out)
{
 unsigned int before[7],middle[7],after[7],fib[14],again[14];
 unsigned int base,way,i,config,half,ways,words,mask;
 int ret;

 *out=(struct rtl_fe_cache_snapshot){.observation=RTL_FE_CACHE_LAYOUT_UNSUPPORTED,
  .cache_index=RTL_FE_CACHE_ENTRIES};
 /* Both geometries are fixed at cold prepare, never inferred from a flow.
  * The SDK's half-mode CRC set helper uses a suspicious 0x7fffffff mask
  * on a 16-bit CRC. Do not turn that into a guessed silicon hash formula:
  * diagnostics scan all 1024 documented cache rows under the same deadline.
  * A half-mode candidate does not prove target identity: CACHE_HASH_DATA1
  * stores only CRC16[12:0]. Without the verified set formula, the missing
  * upper bits can name another current or retired main-table owner. Even
  * one stable matching candidate must not be reported as target equality.
  * The forwarding path still uses the native CRC/slot invalidate command. */
 config=io->read(io->context,0x38a0);
 mask=7U|(7U<<8)|(3U<<16);
 if((config&mask)==(rtl_fe_cache_config(0)&mask))half=0;
 else if((config&mask)==(rtl_fe_cache_config(1)&mask))half=1;
 else {
  out->error=-EOPNOTSUPP;
  return;
 }
 base=half?0:((unsigned int)expected->crc16>>10)<<5;
 ways=half?RTL_FE_NAPTV6_CACHE_ENTRIES:32;
 words=half?11:7;
 out->action_bits=half?RTL_FE_NAPTV6_ACTION_BITS:224;
 for(way=0;way<ways;way++) {
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
  ret=rtl_fe_cache_action_read(io,base+way,half,fib);
  if(ret)goto incomplete;
  ret=rtl_fe_cache_read(io,base+way,0,middle);
  if(ret)goto incomplete;
  if(!rtl_fe_cache_identity(before,middle)) {
   out->observation=RTL_FE_CACHE_KEY_CHANGED;
   return;
  }
  ret=rtl_fe_cache_action_read(io,base+way,half,again);
  if(ret)goto incomplete;
  ret=rtl_fe_cache_read(io,base+way,0,after);
  if(ret)goto incomplete;
  if(!rtl_fe_cache_identity(before,after)) {
   out->observation=RTL_FE_CACHE_KEY_CHANGED;
   return;
  }
  for(i=0;i<words;i++) {
   mask=half && i==10?1U:~0U;
   if((fib[i]^again[i])&mask) {
    out->observation=RTL_FE_CACHE_FIB_CHANGED;
    return;
   }
  }
  out->age=(after[1]>>21)&3U;
  for(i=0;i<words;i++) {
   mask=half && i==10?1U:~0U;
   out->diff[i]=(fib[i]^expected->action[i])&mask;
   if(out->diff[i])out->word_mask|=1U<<i;
  }
  if(half) {
   out->observation=RTL_FE_CACHE_IDENTITY_AMBIGUOUS;
   return;
  }
  out->complete=1;
  out->observation=out->word_mask?RTL_FE_CACHE_DIFFERENT:RTL_FE_CACHE_EQUAL;
  return;
 }
 if(half && out->check_actions) {
  out->observation=RTL_FE_CACHE_IDENTITY_AMBIGUOUS;
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
