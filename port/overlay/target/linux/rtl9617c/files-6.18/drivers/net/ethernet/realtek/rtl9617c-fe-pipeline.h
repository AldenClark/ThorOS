/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_FE_PIPELINE_H
#define RTL9617C_FE_PIPELINE_H
#include "rtl9617c-fe-table.h"

struct rtl_fe_cam_protocol {
 unsigned int saved[5];
 unsigned char bank,index;
 unsigned char created;
};

/* Factory aal_cam_init installs EtherType8864 and PPP21/57. Parser keys use
 * the actual CAM index plus one, independently of the packet editor's values. */
static inline int rtl_fe_cam_protocol_get(const struct rtl_dq_io *io,
 struct rtl_fe_cam_protocol *binding,unsigned int bank,unsigned int protocol)
{
 unsigned int count=bank==2?63:15,index,word,words[5],free_index=count;
 unsigned int width=bank==2?5:3;
 int ret;

 binding->bank=bank;binding->created=0;
 for(index=0;index<count;index++) {
  ret=io->indirect(io->context,0x3200,0x80000000U|(bank<<16)|index);
  if(ret)return ret;
  for(word=0;word<width;word++)words[word]=io->read(io->context,0x3214-word*4);
  if(words[0]&(1U<<16)) {
   if((words[0]&65535)==protocol){binding->index=index;return index+1;}
  } else if(free_index==count) {
   free_index=index;
   for(word=0;word<width;word++)binding->saved[word]=words[word];
  }
 }
 if(free_index==count)return -ENOSPC;
 ret=rtl_fe_window_idle(io,0x3200);
 if(ret)return ret;
 binding->index=free_index;binding->created=1;
 for(word=0;word<width;word++)io->write(io->context,0x3214-word*4,word?0:protocol|(1U<<16));
 ret=io->indirect(io->context,0x3200,0xc0000000U|(bank<<16)|free_index);
 if(ret)return ret;
 return free_index+1;
}

static inline int rtl_fe_cam_protocol_put(const struct rtl_dq_io *io,struct rtl_fe_cam_protocol *binding)
{
 unsigned int word;
 int ret;

 if(!binding->created)return 0;
 ret=rtl_fe_window_idle(io,0x3200);
 if(ret)return ret;
 for(word=0;word<(binding->bank==2?5U:3U);word++)io->write(io->context,0x3214-word*4,binding->saved[word]);
 ret=io->indirect(io->context,0x3200,0xc0000000U|(binding->bank<<16)|binding->index);
 if(!ret)binding->created=0;
 return ret;
}

/* Classifier mode0 selects the Hash profile and supplies CPU16 on a miss.
 * A hit may replace its destination. Source can be kept or set explicitly.
 * Format from aal_l3_cls.h. */
static inline void rtl_fe_classify_hash(unsigned int words[7],unsigned int profile,unsigned int source)
{
 unsigned int i;
 for(i=0;i<7;i++)words[i]=0;
 rtl_fe_bits_set(words,203,1,1); /* t2_ctrl_vld */
 rtl_fe_bits_set(words,204,4,profile); /* t2_ctrl */
 rtl_fe_bits_set(words,186,1,1); /* stage2_ctrl_vld */
 rtl_fe_bits_set(words,187,1,0); /* stage2_ctrl */
 /* CLS supplies the CPU destination; a Hash hit may replace it. */
 rtl_fe_bits_set(words,154,1,1); /* dpid_vld */
 rtl_fe_bits_set(words,155,1,1); /* dpid_pri */
 rtl_fe_bits_set(words,156,1,1); /* permit */
 rtl_fe_bits_set(words,158,10,16); /* CPU0, matching the native RX pool. */
 rtl_fe_bits_set(words,208,1,1); /* lspid_vld */
 rtl_fe_bits_set(words,209,6,source); /* lspid */
}

/* Pre-programmed CPU gate profile. The vendor bypass_l3fe recipe uses
 * keep_orig_pkt plus T2_CTRL_BYPASS=15, not a raw PDC/NI redirect: the latter
 * still reaches the packet editor and may reconstruct a PPP control frame.
 * Native RX uses CPU0 without the vendor deep-Q bit. Preserve original LSPID
 * so a PON packet remains source7 and LAN packets keep their physical port.
 * Caller must also own/program the adjacent standard-FIB format row to mode0
 * and exclude competing classifier keys/default result groups before use.
 */
static inline void rtl_fe_classify_cpu_original(unsigned int words[7])
{
 unsigned int i;

 for(i=0;i<7;i++)words[i]=0;
 rtl_fe_bits_set(words,154,1,1); /* dpid_vld */
 rtl_fe_bits_set(words,155,1,1); /* dpid_pri */
 rtl_fe_bits_set(words,156,1,1); /* permit */
 rtl_fe_bits_set(words,158,10,16); /* CPU0 */
 rtl_fe_bits_set(words,182,1,1); /* keep_orig_pkt_vld */
 rtl_fe_bits_set(words,183,1,1); /* keep_orig_pkt */
 rtl_fe_bits_set(words,203,1,1); /* t2_ctrl_vld */
 rtl_fe_bits_set(words,204,4,15); /* T2_CTRL_BYPASS */
}

/* Each of the two CLS profiles owns 128 key rows, all in this one window.
 * No mutation: a foreign full/short/flow key makes default-only ownership
 * unsafe. Check all four valid flags, including the second half of long keys.
 * 0 = both profiles empty, -EBUSY = foreign key/window, other errors propagate.
 */
static inline int rtl_fe_classifier_keys_empty(const struct rtl_dq_io *io)
{
 unsigned int i;
 int ret;

 for(i=0;i<256;i++) {
  ret=rtl_fe_window_idle(io,0x3380);
  if(ret)return ret;
  ret=io->indirect(io->context,0x3380,0x80000000U|i);
  if(ret)return ret;
  if(io->read(io->context,0x3384)&(15U<<27))return -EBUSY;
 }
 return 0;
}

/* LPB profile used by the internal LAN-to-L3 connector. No VLAN/packet
 * rewriting occurs here; classifier and flow actions decide forwarding. */
static inline void rtl_fe_ingress_lpb(unsigned int words[3],unsigned int source,unsigned int destination)
{
 unsigned int i;
 for(i=0;i<3;i++)words[i]=0;
 rtl_fe_bits_set(words,24,14,1700); /* mru_len */
 rtl_fe_bits_set(words,38,4,15); /* t5_ctrl */
 rtl_fe_bits_set(words,42,4,0); /* t1_ctrl */
 rtl_fe_bits_set(words,68,6,destination); /* default_ldpid */
 rtl_fe_bits_set(words,88,6,source); /* lspid */
}
static inline int rtl_fe_classifier_read(const struct rtl_dq_io *io,unsigned int index,unsigned int words[7])
{
 unsigned int i;
 int ret=io->indirect(io->context,0x33b0,0x80000000U|index);
 if(ret)return ret;
 for(i=0;i<7;i++)words[i]=io->read(io->context,0x33cc-i*4);
 return 0;
}
static inline int rtl_fe_classifier_write(const struct rtl_dq_io *io,unsigned int index,const unsigned int words[7])
{
 unsigned int i;
 int ret=rtl_fe_window_idle(io,0x33b0);
 if(ret)return ret;
 for(i=0;i<7;i++)io->write(io->context,0x33cc-i*4,words[i]);
 return io->indirect(io->context,0x33b0,0xc0000000U|index);
}

static inline int rtl_fe_source_mac_read(const struct rtl_dq_io *io,unsigned int index,unsigned int words[5])
{
 unsigned int i;
 int ret=io->indirect(io->context,0x3200,0x80030000U|index);
 if(ret)return ret;
 for(i=0;i<5;i++)words[i]=io->read(io->context,0x3214-i*4);
 return 0;
}
static inline int rtl_fe_source_mac_write(const struct rtl_dq_io *io,unsigned int index,const unsigned int words[5])
{
 unsigned int i;
 int ret=rtl_fe_window_idle(io,0x3200);
 if(ret)return ret;
 for(i=0;i<5;i++)io->write(io->context,0x3214-i*4,words[i]);
 return io->indirect(io->context,0x3200,0xc0030000U|index);
}
/* TX interface MIB is224 bits:bytes64,UC32,non-UC32,drop-bytes64,
 * drop-packets32. This driver uses its allocated EIF index (0..31) as
 * the counter selector; counter address width is not EIF table capacity. */
static inline int rtl_fe_tx_counter_read(const struct rtl_dq_io *io,
 unsigned int index,unsigned int words[7])
{
 unsigned int i;
 int ret=io->indirect(io->context,0x35c8,0x80000000U|index);

 if(ret)return ret;
 for(i=0;i<7;i++)words[i]=io->read(io->context,0x35e4-i*4);
 return 0;
}
/* L3 uses an FDB address as a DA-rewrite reference, not as an L2 lookup.
 * The RTL8277C FC driver's path action calls this a 4096+32-entry FDB index;
 * VID/PCP rewriting is a separate action. Keep these references outside the
 * Linux bridge's learning namespace, otherwise a routed flow pins a bridge
 * row's output port and its last release restores stale bridge state.
 *
 * VID4095 is exclusively internal: every packet-side L2 lookup must exclude
 * it (including PVID/classifier/EVTO remaps). Linux configuration validation
 * alone is not sufficient. The L2 owner must exclude the WHOLE VID domain
 * from learning notifications, ageing reconciliation and per-bridge flushes,
 * and use the same lock as L3 for the shared FDB command window. Global IVL
 * mode must not change while rows are referenced. See the evidence document;
 * a host format test is not a physical forwarding/ASIC-errata validation.
 */
#define RTL_FE_FDB_PIN_VID 4095U
#define RTL_FE_FDB_PIN_SCIND 1U
#define RTL_FE_FDB_PIN_DOT1P 0U
#define RTL_FE_FDB_PIN_PORT 16U

static inline int rtl_fe_fdb_is_pin_domain(const unsigned int words[4])
{
 /* Protect unexpected SC/PCP/type values too: they may be an uncertain write. */
 return ((words[1]>>7)&4095U)==RTL_FE_FDB_PIN_VID;
}

static inline int rtl_fe_fdb_is_pin(const unsigned int words[4])
{
 unsigned int type_mask=63U|(1U<<7)|(1U<<8)|(1U<<9)|(1U<<10)|
  (1U<<19)|(1U<<20)|(1U<<21);
 unsigned int type=RTL_FE_FDB_PIN_PORT|(1U<<9)|(1U<<19)|(1U<<20)|(1U<<21);

 return rtl_fe_fdb_is_pin_domain(words) &&
  ((words[1]>>6)&1U)==RTL_FE_FDB_PIN_SCIND &&
  ((words[1]>>3)&7U)==RTL_FE_FDB_PIN_DOT1P &&
  (words[0]&type_mask)==type;
}

/* FDB MAC begins at bit51; CMD_RETURN bits4..16 supply the DA index. */
static inline void rtl_fe_fdb_key(unsigned int words[4],const unsigned char mac[6])
{
 unsigned int i;
 for(i=0;i<4;i++)words[i]=0;
 for(i=0;i<6;i++)rtl_fe_bits_set(words,51+(5-i)*8,8,mac[i]);
 rtl_fe_bits_set(words,39,12,RTL_FE_FDB_PIN_VID);
 rtl_fe_bits_set(words,38,1,RTL_FE_FDB_PIN_SCIND);
 rtl_fe_bits_set(words,35,3,RTL_FE_FDB_PIN_DOT1P);
 /* CPU is a defensive destination only, never the domain-isolation guard. */
 words[0]=RTL_FE_FDB_PIN_PORT|(1U<<9)|(255U<<11)|(1U<<19)|(1U<<20)|(1U<<21);
}
static inline int rtl_fe_fdb_command(const struct rtl_dq_io *io,unsigned int command,unsigned int words[4],unsigned int *result)
{
 unsigned int i,control;
 int ret=rtl_fe_window_idle(io,0x1ca0);
 if(ret)return ret;
 /* The MAC-limit window leases the same cpu_opt_mode in indirect mode.
  * A late limit command remains active after its owner drops the mutex;
  * neither the mode nor FDB DATA may be changed until both windows idle. */
 ret=rtl_fe_window_idle(io,0x1cb4);
 if(ret)return ret;
 control=io->read(io->context,0x1c00);
 io->write(io->context,0x1c00,control|0x80000000U);
 for(i=0;i<4;i++)io->write(io->context,0x1cb0-i*4,words[i]);
 io->write(io->context,0x1c2c,0);
 ret=io->indirect(io->context,0x1ca0,0x80000000U|command);
 if(ret)return ret;
 /* A timeout is not cancellation: switching cpu_opt_mode while the FDB
  * command is still running changes the interpretation of its shared window.
  * The fabric owner retains the original mode across a failed transaction;
  * this stateless helper must not guess it during a later retry. */
 ret=rtl_fe_window_idle(io,0x1ca0);
 if(ret)return ret;
 ret=rtl_fe_window_idle(io,0x1cb4);
 if(ret)return ret;
 io->write(io->context,0x1c00,control);
 *result=io->read(io->context,0x1c2c);
 for(i=0;i<4;i++)words[i]=io->read(io->context,0x1cb0-i*4);
 return 0;
}
#endif
