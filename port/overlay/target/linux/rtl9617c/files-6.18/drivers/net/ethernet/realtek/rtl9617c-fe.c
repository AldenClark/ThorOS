// SPDX-License-Identifier: GPL-2.0-or-later
/* Native Linux flowtable backend for the Taurus main Hash/packet editor. */
#include <linux/bitmap.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <linux/dma-mapping.h>
#include <linux/etherdevice.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/ip.h>
#include <linux/if_vlan.h>
#include <linux/if_bridge.h>
#include <linux/ipv6.h>
#include <linux/ppp_defs.h>
#include <linux/list.h>
#include <linux/ktime.h>
#include <linux/uaccess.h>
#include <linux/rbtree.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/tc_act/tc_csum.h>
#include <linux/unaligned.h>
#include <linux/workqueue.h>
#include <net/flow_offload.h>
#include <net/pkt_cls.h>
#include "rtl9617c-fe.h"
#include "rtl9617c-fe-pipeline.h"
#include "rtl9617c-fe-cache-snapshot.h"
#include "rtl9617c-fe-observe.h"
#include "rtl9617c-l2-evidence.h"
#include "rtl9617c-fabric.h"
#include "rtl9617c-pon-path.h"
#include <linux/rtl9617c-bridge.h>

struct rtl_fe_bridge;
static struct rtl_fe_bridge *fe_bridge_start(struct rtl_fe *fe);
static int fe_bridge_stop(struct rtl_fe_bridge *bridge);
static ssize_t fe_bridge_stats(struct rtl_fe_bridge *bridge, char *buffer, size_t bytes);
static int fe_switch_quiesce_locked(struct rtl_fe *fe);
static void fe_switch_reconcile_locked(struct rtl_fe *fe);
static int fe_switch_request_locked(struct rtl_fe *fe, bool requested);
static bool fe_switch_requested(struct rtl_fe *fe);
static bool fe_switch_flow_allowed(struct rtl_fe *fe);

#define FE_INTERFACES 32
#define FE_COUNTERS 32
#define FE_SOURCE_MACS 15
#define FE_LAN_PORTS 5
#define FE_LAN_RX_CTRL(port) (0xa5f8+0x90*(port))

enum rtl_fe_mode {
 RTL_FE_MODE_OFF,
 RTL_FE_MODE_CPU,
 RTL_FE_MODE_HARDWARE,
};

struct rtl_fe_port {
 struct list_head list;
 struct rtl_fe *fe;
 struct net_device *netdev;
 unsigned int source, destination, llid, bindings;
 bool retired;
};
struct rtl_fe_mac {
 unsigned int users, saved[5];
 bool ready;
 u8 address[ETH_ALEN];
};
struct rtl_fe_interface {
 unsigned int users, saved, source_mac, pppoe;
 bool counted, ready;
};
struct rtl_fe_mtu {
 unsigned int users, size, saved;
};
struct rtl_fe_flow {
 struct list_head list, retry;
 struct rb_node cookie_node;
 unsigned long cookie, lastused;
 struct rtl_fe_port *input, *output;
 unsigned int hash_index, counter, source_mac, destination_index;
 unsigned int pppoe, mtu_index;
 unsigned int ingress_session;
 unsigned int ingress_pol;
 u8 ip_source[16],ip_destination[16],protocol;
 u8 ethernet_source[ETH_ALEN];
 u16 ethernet_protocol;
 u16 source_port,destination_port;
 bool ipv6, bridge;
 bool learned;
 unsigned int bridge_index;
 unsigned int bridge_ingress, bridge_egress;
 u8 bridge_tags;
 struct {u16 tci,protocol;} bridge_tag[2];
 u16 bridge_vid;
 u16 bridge_ppp_protocol;
 unsigned int destination_saved[4];
 u16 crc16;
 u32 crc32;
 unsigned char ethernet_bytes;
 bool destination_created, destination_ready;
 bool mtu_owned;
 bool published, source_owned, destination_owned, interface_owned, counted, installed, deleting;
 u8 destination[ETH_ALEN];
 u64 bytes;
 u32 packets;
};
static const unsigned int fe_registers[] = {
 0x3834,0x3838,0x383c,0x3840,0x3844,0x3848,0x384c,0x3850,
 0x3854,0x3858,0x385c,0x38a0,0x38b8,0x38bc,0x38c4,0x3924,0x3724,
 0x3400,0x3404,0x3414,0x3418,0x341c,0x3420,0x3424,0x3428,
 0x3700,0x3704,0x3708,0x370c,0x3710,0x3714,0x3718,0x371c,0x3720,0x3860,0x394c,0x3950,0x3954,0x3958,0x395c,
 0x2300,0x2394,0x23a0,0xa1e0,
 0x3278,0x327c,0x3280,
 0x3500,0x3504,0x351c,
 0x3940,0x3944,0x3948,0x3c80,
 0x3508,0x30cc,0x30a4,0x3218,
};
/* aal-77c/include/aal_l3_cls.h cls_fib_mod_0_t and
 * l3_cls_fib_tbl_entry_t: mode0 occupies only the first row's payload.
 * The second row supplies fib_format_sel, not another zero payload. */
static const unsigned int fe_cls_mode0_mask[2][7] = {
 {0xffffcfffU,0xcfffffffU,0xffffffffU,0xfffffffbU,
  0xffffffffU,0xecffffffU,0x03ffffffU},
 {0,0,0,0,0,0,0x03800000U},
};
struct rtl_fe {
 struct device *device;
 struct dentry *debug;
 void __iomem *registers;
 struct mutex lock;
 /* Atomic policy publication cannot wait for the sleeping table owner. */
 spinlock_t route_lock;
 struct delayed_work cleanup_work;
 struct list_head ports, flows, blocks, retries;
 struct rb_root cookies;
 void *memory;
 dma_addr_t dma;
 bool enabled, prepared, cpu_path, lan_redirected;
 /* NI stop/start must not confuse requested policy with live ASIC state. */
 bool engine_ready, shutting_down;
 bool route_gate_ready, route_admitted, dma_exposed;
 /* prepared owns the pre-write snapshot; base_ready is only published
  * after every base table/profile has been installed. An exposed partial
  * setup is not a reusable CPU path and is quarantined until reboot. */
 bool base_ready, base_failed;
 enum rtl_fe_mode desired_mode;
 unsigned int fdb_cmd_mode_saved;
 unsigned int cache_target;
 unsigned int pp_rejected_register, pp_rejected_value;
 unsigned int base_rejected_register, base_rejected_value;
 int error;
 u64 installs, deletes, misses;
 struct rtl_fe_observe observe;
 unsigned int saved[ARRAY_SIZE(fe_registers)], mask_saved[8];
 unsigned int bridge_mask_saved[3][8];
 struct rtl_fe_cam_protocol protocol_cam[3];
 unsigned char ppp_protocol_ids[2];
 unsigned int lan_saved[FE_LAN_PORTS];
 unsigned int classifier_saved[2][4][2][7], map_saved[2][4];
 struct rtl_fe_mac source_macs[FE_SOURCE_MACS];
 struct rtl_fe_interface interfaces[FE_INTERFACES];
 struct rtl_fe_mtu mtus[16];
 struct rtl_itu_paths *itu_paths;
 struct net_device *itu_netdev;
 struct rtl_fe_bridge *bridge;
 struct rtl_fabric fabric;
 DECLARE_BITMAP(hashes,RTL_FE_HASH_ENTRIES);
 DECLARE_BITMAP(counters,FE_INTERFACES);
};
static unsigned int fe_read(void *context,unsigned int address)
{
 struct rtl_fe *fe=context;
 return readl(fe->registers+address);
}
static void fe_write(void *context,unsigned int address,unsigned int value)
{
 struct rtl_fe *fe=context;
 writel(value,fe->registers+address);
}
static int fe_access(void *context,unsigned int address,unsigned int value)
{
 struct rtl_fe *fe=context;
 u32 status, busy=(address==0x38b0 || address==0x393c || address==0x38e0)?1:BIT(31);
 int ret;

 /* A timed-out command can still complete later. Do not overwrite its
  * ACCESS register. DATA-window writers must also check before staging. */
 ret=readl_poll_timeout(fe->registers+address,status,!(status&busy),1,100000);
 if(ret)return ret;
 writel(value,fe->registers+address);
 return readl_poll_timeout(fe->registers+address,status,!(status&busy),1,100000);
}
static struct rtl_dq_io fe_io(struct rtl_fe *fe)
{
 return (struct rtl_dq_io){fe,fe_read,fe_write,fe_access};
}

int rtl_fe_fabric_cold_prepare(struct rtl_fe *fe)
{
 struct rtl_dq_io io;
 int ret;

 if(!fe)return -EOPNOTSUPP;
 io=fe_io(fe);
 mutex_lock(&fe->lock);
 if(fe->engine_ready || fe->prepared || fe->dma_exposed || fe->shutting_down) {
  ret=-EBUSY;
  goto out;
 }
 ret=rtl_fabric_cold_prepare(&io,&fe->fabric);
 /* A verified preflight refusal preserves the old software/routing
  * baseline. Ambiguous writes and failed cleanup never publish NI users.
  */
 if(ret && fe->fabric.refusal && !fe->fabric.poisoned)ret=1;
out:
 mutex_unlock(&fe->lock);
 return ret;
}

/* LPB1 (LAN connector) and LPB2 (PON connector) select one of two owned
 * classifier profiles. Profile1 has the SDK keep-original CPU action for
 * EVERY default result type; profile0 alone may enter the routing hash.
 * The real TCAM is verified empty before either profile is claimed. This
 * direct selector, unlike a raw PDC bypass, preserves PPPoE control packets
 * and stops old WAN->LAN hash hits as well as new LAN admission.
 *
 * Lock order: core policy guard -> route_lock. Never take the core guard or
 * fe->lock while holding route_lock. No indirect command or delay here.
 */
static bool fe_route_select_locked(struct rtl_fe *fe, unsigned int profile)
{
 unsigned int i, address, value;
 bool selected=true;

 for(i=0;i<2;i++) {
  address=0x3418+i*12;
  value=fe_read(fe,address);
  fe_write(fe,address,(value&~(15U<<10))|(profile<<10));
 }
 for(i=0;i<2;i++)
  if(((fe_read(fe,0x3418+i*12)>>10)&15)!=profile)selected=false;
 return selected;
}

static void fe_route_gate(struct rtl_fe *fe)
{
 unsigned long flags;

 spin_lock_irqsave(&fe->route_lock,flags);
 if(fe->route_gate_ready)fe_route_select_locked(fe,1);
 WRITE_ONCE(fe->route_admitted,false);
 spin_unlock_irqrestore(&fe->route_lock,flags);
}

/* Called only by the generation-checked fabric owner, never by prepare. */
static bool fe_route_arm(struct rtl_fe *fe)
{
 unsigned long flags;
 bool admitted=false, safe=true;

 spin_lock_irqsave(&fe->route_lock,flags);
 if(!fe->enabled) {
  if(fe->route_gate_ready)safe=fe_route_select_locked(fe,1);
 } else if(fe->prepared && fe->route_gate_ready &&
           fe->engine_ready && !fe->shutting_down) {
  admitted=fe_route_select_locked(fe,0);
  if(!admitted)fe_route_select_locked(fe,1);
  safe=admitted;
 } else safe=false;
 WRITE_ONCE(fe->route_admitted,admitted);
 spin_unlock_irqrestore(&fe->route_lock,flags);
 return safe;
}

static unsigned int fe_classifier_default_index(unsigned int profile,
                                               unsigned int result,
                                               unsigned int row)
{
 return (1024U|(profile<<2)|((result&1U)<<1)|((result&2U)<<3))+row;
}
static struct rtl_fe_port *fe_port(struct rtl_fe *fe,struct net_device *netdev)
{
 struct rtl_fe_port *port;
 list_for_each_entry(port,&fe->ports,list)
  if(!port->retired && port->netdev==netdev)return port;
 return NULL;
}
/* All cookie and retry-list operations are serialized by fe->lock. */
static struct rtl_fe_flow *fe_flow(struct rtl_fe *fe,unsigned long cookie)
{
 struct rb_node *node=fe->cookies.rb_node;

 while(node) {
  struct rtl_fe_flow *flow=rb_entry(node,struct rtl_fe_flow,cookie_node);
  if(cookie<flow->cookie)node=node->rb_left;
  else if(cookie>flow->cookie)node=node->rb_right;
  else return flow;
 }
 return NULL;
}
static void fe_index_flow(struct rtl_fe *fe,struct rtl_fe_flow *flow)
{
 struct rb_node **link=&fe->cookies.rb_node,*parent=NULL;

 while(*link) {
  struct rtl_fe_flow *other=rb_entry(*link,struct rtl_fe_flow,cookie_node);
  parent=*link;
  if(flow->cookie<other->cookie)link=&parent->rb_left;
  else link=&parent->rb_right;
 }
 rb_link_node(&flow->cookie_node,parent,link);
 rb_insert_color(&flow->cookie_node,&fe->cookies);
}
static void fe_collect_ports(struct rtl_fe *fe)
{
 struct rtl_fe_port *port,*next;
 struct rtl_fe_flow *flow;

 list_for_each_entry_safe(port,next,&fe->ports,list) {
  bool owned=false;
  if(!port->retired || port->bindings)continue;
  list_for_each_entry(flow,&fe->flows,list)
   if(flow->input==port || flow->output==port){owned=true;break;}
  if(!owned){list_del(&port->list);kfree(port);}
 }
}

/* PON normal business entry changes are made by the PON control transaction,
 * outside this backend. No flow callback acquires the PON state/RTNL locks. */
static int fe_prepare(struct rtl_fe *fe)
{
 struct rtl_dq_io io=fe_io(fe);
 unsigned int mask[8],cls[7],zero[7]={0},lpb[3],i,side,type,row;
 unsigned long flags;
 int ret;

 /* Parser/DDoS exceptions may bypass LPB and its CPU classifier profile.
  * Do not take ownership unless every override is already keep-original
  * CPU/drop with all route/edit stages bypassed. This is a readonly probe:
  * an unsupported boot/PON policy remains untouched and uses software. */
 fe->pp_rejected_register=0;
 fe->pp_rejected_value=0;
 ret=rtl_fe_pp_exceptions_check(&io,&fe->pp_rejected_register,
                               &fe->pp_rejected_value);
 if(ret)return ret;
 /* Neither a foreign valid TCAM key nor its result action may defeat the
  * CPU default used by our atomic gate. Do not clear somebody else's ACL. */
 ret=rtl_fe_classifier_keys_empty(&io);
 if(ret)return ret;
 for(i=0;i<ARRAY_SIZE(fe_registers);i++)fe->saved[i]=fe_read(fe,fe_registers[i]);
 for(i=0;i<FE_LAN_PORTS;i++)fe->lan_saved[i]=fe_read(fe,FE_LAN_RX_CTRL(i));
 ret=rtl_fe_mask_read(&io,63,fe->mask_saved);
 if(ret)return ret;
 for(i=0;i<3;i++) {
  ret=rtl_fe_mask_read(&io,61-2*i,fe->bridge_mask_saved[i]);
  if(ret)return ret;
 }
 /* SDK defaults are standard TWO-row FIBs, with four result types per
  * profile. The second row contains fib_format_sel: stale data there can
  * reinterpret an otherwise correct first row. Save every owned row. */
 for(i=0;i<2;i++) {
  for(type=0;type<4;type++)for(row=0;row<2;row++) {
   ret=rtl_fe_classifier_read(&io,fe_classifier_default_index(i,type,row),
                              fe->classifier_saved[i][type][row]);
   if(ret)return ret;
  }
  for(side=0;side<4;side++) {
   ret=fe_access(fe,0x1654,BIT(31)|(24+i)|(side<<6));
   if(ret)return ret;
   fe->map_saved[i][side]=fe_read(fe,0x1658);
  }
 }
 fe->prepared=true;
 /* Original aal_l3fe_l4_chksum: EPP checksum status requires this engine. */
 /* SDK L3FE checksum engines: explicitly enable IPv4 and L4 checking.
  * Invalid parser classes still miss the exact routing hash templates. */
 fe_write(fe,0x3218,fe_read(fe,0x3218)|BIT(15)|BIT(16));
 /* Keep GEM rewriting disabled until its classifier/default chain is ready. */
 fe_write(fe,0x351c,fe_read(fe,0x351c)&~BIT(10));
 /* Command-window idle is not a proof that all late AXI DMA has drained.
  * Record exposure before publishing the first hardware-visible address. */
 fe->dma_exposed=true;
 rtl_fe_dma_tables(&io,lower_32_bits(fe->dma),(upper_32_bits(fe->dma)&255)|2);
 ret=fe_access(fe,0x393c,1);
 if(ret)return ret;
 rtl_fe_ipv6_mask(mask);
 /* Keep LLID/POL_ID and LSPID in the key; orig_lspid/profile are ignored.
  * Full128 address prefixes also cover IPv4, which the parser clamps to32.
  * TCP FIN/SYN/RST continue on the kernel control path. */
 mask[6]|=BIT(23)|BIT(26);
 mask[0]&=~(BIT(1)|BIT(2)|BIT(3));
 mask[3]&=~BIT(4); /* mask.vlan_cnt bit100, key.vlan_cnt bits464..465 */
 /* Match VID/TPID on both tags, independently of PCP/DEI. */
 mask[2]&=~(BIT(30)|BIT(31)); /* inner VID/TPID bits94..95 */
 mask[3]&=~(BIT(2)|BIT(3));  /* top VID/TPID bits98..99 */
 mask[2]&=~(BIT(25)|BIT(27)); /* PPPoE session/type bits89/91 */
 ret=rtl_fe_mask_write(&io,63,mask);
 if(ret)return ret;
 rtl_fe_bridge_mask(mask);
 ret=rtl_fe_mask_write(&io,61,mask);
 if(ret)return ret;
 rtl_fe_bridge_mask(mask);
 rtl_fe_bits_set(mask,92,2,0); /* Exact learned inner DEI/PCP. */
 rtl_fe_bits_set(mask,96,2,0); /* Exact learned outer DEI/PCP. */
 ret=rtl_fe_mask_write(&io,59,mask);
 if(ret)return ret;
 rtl_fe_bits_set(mask,135,8,255); /* Wired PPPoE data retains no VIF selector. */
 rtl_fe_bits_set(mask,88,1,0); /* Match the CAM protocol encoding; LCP misses. */
 ret=rtl_fe_mask_write(&io,57,mask);
 if(ret)return ret;
 fe_write(fe,0x3500,0x11); /* Session version/type1, code0. */
 fe_write(fe,0x3504,PPP_IP|PPP_IPV6<<16);
 fe_write(fe,0x30a4,fe_read(fe,0x30a4)|BIT(31)); /* PON stream from HeaderA into HeaderI. */
 fe_write(fe,0x351c,(fe_read(fe,0x351c)&~(0x3fU<<4|0x3fU<<16|7U<<24))|BIT(31)|BIT(12)|32U<<4|16U<<16);
 /* TX MIB differences use unsigned wrap, including the32-bit packet count. */
 fe_write(fe,0x3508,fe_read(fe,0x3508)|0x1f00);
 /* Linux must generate TTL/Hop-Limit errors from the original ingress
  * packet; override an accelerated WAN action's deep-Q flag as well. */
 fe_write(fe,0x30cc,(fe_read(fe,0x30cc)&~0xfffU)|0xf21);
 /* Use the SAME action in all result groups; they are not assumed to be
  * mutually exclusive packet classes. Normal profile0 keeps actual LSPID
  * (LAN0..4 / PON7); profile1 skips T2 and sends the original frame to CPU. */
 for(i=0;i<2;i++) {
  if(i)rtl_fe_classify_cpu_original(cls);
  else {rtl_fe_classify_hash(cls,0,0);rtl_fe_bits_set(cls,208,1,0);}
  for(type=0;type<4;type++) {
   ret=rtl_fe_classifier_write(&io,fe_classifier_default_index(i,type,1),zero);
   if(!ret)ret=rtl_fe_classifier_write(&io,fe_classifier_default_index(i,type,0),cls);
   if(ret)return ret;
  }
 }
 for(i=0;i<2;i++) {
  rtl_fe_ingress_lpb(lpb,i?7:0,16);
  rtl_fe_bits_set(lpb,42,4,1); /* CPU gate until generation-checked arm. */
  spin_lock_irqsave(&fe->route_lock,flags);
  for(side=0;side<3;side++)fe_write(fe,0x3414+i*12+side*4,lpb[side]);
  spin_unlock_irqrestore(&fe->route_lock,flags);
  for(side=0;side<4;side++) {
   ret=rtl_fe_window_idle(&io,0x1654);
   if(ret)return ret;
   fe_write(fe,0x1658,i?12:13);
   ret=fe_access(fe,0x1654,BIT(31)|BIT(30)|(i?24:25)|(side<<6));
   if(ret)return ret;
  }
 }
 spin_lock_irqsave(&fe->route_lock,flags);
 fe->route_gate_ready=true;
 ret=fe_route_select_locked(fe,1)?0:-EIO;
 fe->route_admitted=false;
 spin_unlock_irqrestore(&fe->route_lock,flags);
 if(ret)return ret;
 fe_write(fe,0x3400,(fe_read(fe,0x3400)&~(BIT(0)|BIT(10)))|BIT(3)|BIT(2)|BIT(19));
 fe_write(fe,0x3404,7|(25<<8)|(1<<14)|(24<<16)|(2<<22)|(3<<24));
 fe_write(fe,0x2300,fe_read(fe,0x2300)|BIT(12)|BIT(13));
 fe_write(fe,0x2304+12*12,0xff|(6<<16));
 fe_write(fe,0x2304+13*12,0xff|(6<<16));
 for(i=0;i<5;i++)fe_write(fe,0x394c+i*4,0);
 fe_write(fe,0x3724,RTL_FE_ACTION_GROUPS|(3U<<25));
 fe_write(fe,0x3704,63); /* IP/IPv6 five-tuple. */
 fe_write(fe,0x3708,61|BIT(8)); /* Transparent Ethernet. */
 fe_write(fe,0x370c,59|(2U<<8)); /* Learned bridge with explicit VLAN tags. */
 fe_write(fe,0x3710,57|(3U<<8)); /* Wired PPPoE data. */
 fe_write(fe,0x3700,4);
 fe_write(fe,0x3860,0x020d0000);
 fe_write(fe,0x3278,0x88a88100);
 fe_write(fe,0x327c,0x92009100);
 fe_write(fe,0x3280,0x77); /* Original parser TPID defaults. */
 for(i=0;i<3;i++) {
  ret=rtl_fe_cam_protocol_get(&io,&fe->protocol_cam[i],i?8:2,
   i==0?ETH_P_PPP_SES:i==1?PPP_IP:PPP_IPV6);
  if(ret<0)return ret;
  if(i)fe->ppp_protocol_ids[i-1]=ret;
 }
 /* The Linux rule already selected the physical LAN output. A second
  * L2 lookup would override it with the indexed DA entry's forwarding port.
  * NI demux3 enters L2TM directly; only LAN0..4's selectors change. */
 fe_write(fe,0xa1e0,fe_read(fe,0xa1e0)|0x3ff);
 rtl_fe_cache_start(&io);
 fe_write(fe,0x351c,fe_read(fe,0x351c)|BIT(10));
 fe->base_ready=true;
 return 0;
}
static int fe_restore(struct rtl_fe *fe)
{
 struct rtl_dq_io io=fe_io(fe);
 unsigned int i,side,type,row;
 unsigned long flags;
 int ret;

 if(!fe->prepared)return 0;
 fe_route_gate(fe);
 /* A PDC source may still name connector24 after the last Linux NI user
  * closes. Neither an idle table command nor cache invalidation proves
  * that the full L3/AXI pipeline has drained. Never restore the old LPB,
  * classifier or DMA bases after publication, even during device remove. */
 if(fe->dma_exposed)return -EBUSY;
 fe_write(fe,0x351c,fe_read(fe,0x351c)&~BIT(10));
 fe_write(fe,0x38c4,0);
 ret=fe_access(fe,0x393c,1);
 if(ret)return ret;
 /* All driver route owners have already been deleted and the cache is
  * now invalidated. Retire the atomic selector before restoring its FIBs;
  * it must not select a partially restored/foreign classifier profile.
  * LAN admission remains CPU-only throughout this ownership handoff. */
 spin_lock_irqsave(&fe->route_lock,flags);
 fe->route_gate_ready=false;
 fe->route_admitted=false;
 spin_unlock_irqrestore(&fe->route_lock,flags);
 for(i=0;i<3;i++) {
  ret=rtl_fe_cam_protocol_put(&io,&fe->protocol_cam[i]);
  if(ret)return ret;
 }
 for(i=0;i<2;i++) {
  for(side=0;side<4;side++) {
   ret=rtl_fe_window_idle(&io,0x1654);
   if(ret)return ret;
   fe_write(fe,0x1658,fe->map_saved[i][side]);
   ret=fe_access(fe,0x1654,BIT(31)|BIT(30)|(24+i)|(side<<6));
   if(ret)return ret;
  }
  for(type=0;type<4;type++)for(row=0;row<2;row++) {
   ret=rtl_fe_classifier_write(&io,fe_classifier_default_index(i,type,row),
                               fe->classifier_saved[i][type][row]);
   if(ret)return ret;
  }
 }
 ret=rtl_fe_mask_write(&io,63,fe->mask_saved);
 if(ret)return ret;
 for(i=0;i<3;i++) {
  ret=rtl_fe_mask_write(&io,61-2*i,fe->bridge_mask_saved[i]);
  if(ret)return ret;
 }
 for(i=0;i<ARRAY_SIZE(fe_registers);i++)fe_write(fe,fe_registers[i],fe->saved[i]);
 fe_read(fe,0x383c);
 fe->base_ready=false;
 fe->prepared=false;
 return 0;
}
static int fe_source_get(struct rtl_fe *fe,const u8 *address,unsigned int *index)
{
 struct rtl_dq_io io=fe_io(fe);
 unsigned int i,words[5]={};
 int ret;

 for(i=0;i<FE_SOURCE_MACS;i++)
  if(fe->source_macs[i].users && ether_addr_equal(address,fe->source_macs[i].address)) {
   if(!fe->source_macs[i].ready)return -EBUSY;
   fe->source_macs[i].users++;
   *index=i;
   return 0;
  }
 for(i=0;i<FE_SOURCE_MACS;i++)if(!fe->source_macs[i].users)break;
 if(i==FE_SOURCE_MACS)return -ENOSPC;
 ret=rtl_fe_source_mac_read(&io,i,fe->source_macs[i].saved);
 if(ret)return ret;
 for(unsigned int byte=0;byte<ETH_ALEN;byte++)rtl_fe_bits_set(words,(5-byte)*8,8,address[byte]);
 words[1]|=BIT(16);
 /* A timed-out write may have reached the CAM. Give rollback ownership of
  * the saved row before issuing it, so a failed restore stays on retries. */
 ether_addr_copy(fe->source_macs[i].address,address);
 fe->source_macs[i].users=1;
 fe->source_macs[i].ready=false;
 *index=i;
 ret=rtl_fe_source_mac_write(&io,i,words);
 if(ret)return ret;
 fe->source_macs[i].ready=true;
 return 0;
}
static int fe_source_put(struct rtl_fe *fe,unsigned int index)
{
 struct rtl_dq_io io=fe_io(fe);
 int ret;

 if(index>=FE_SOURCE_MACS || !fe->source_macs[index].users)return -EINVAL;
 if(fe->source_macs[index].users>1){fe->source_macs[index].users--;return 0;}
 fe->source_macs[index].ready=false;
 ret=rtl_fe_source_mac_write(&io,index,fe->source_macs[index].saved);
 if(!ret)fe->source_macs[index].users=0;
 return ret;
}
/* RTL9617C EGRESS_L3_IF_TBL_ACCESS has a5-bit address, hence32 rows.
 * SDK aal-77c/include/aal_l3_if.h FE_L3E_IF_TBL_ENTRY_MAX, commit
 * 8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0. Do not alias live rows32..63.
 * Wait for a previous operation before touching its shared data window. */
static int fe_interface_transfer(struct rtl_fe *fe,unsigned int index,
 unsigned int *value,bool write)
{
 unsigned int status;
 int ret;

 if(index>=FE_INTERFACES)return -ERANGE;
 ret=readl_poll_timeout(fe->registers+0x3000,status,!(status&BIT(31)),1,100000);
 if(ret)return ret;
 if(write)fe_write(fe,0x3004,*value);
 ret=fe_access(fe,0x3000,BIT(31)|(write?BIT(30):0)|index);
 if(!ret && !write)*value=fe_read(fe,0x3004);
 return ret;
}
/* L3 output interfaces select a source MAC; they are not flow-table slots.
 * All32 rows have independent MIBs.
 * Counted flows own one interface MIB. Further flows share its MAC selection
 * with their action counter bit clear, so they cannot pollute that flow MIB. */
static int fe_interface_get(struct rtl_fe *fe,struct rtl_fe_flow *flow)
{
 struct rtl_fe_interface *interface;
 unsigned int index=find_first_zero_bit(fe->counters,FE_INTERFACES),i;
 int ret;

 if(index==FE_INTERFACES) {
  for(i=0;i<FE_INTERFACES;i++)
   if(fe->interfaces[i].users && fe->interfaces[i].ready &&
      fe->interfaces[i].source_mac==flow->source_mac &&
      fe->interfaces[i].pppoe==flow->pppoe &&
      (!fe->interfaces[i].counted || index==FE_INTERFACES)) {
    index=i;
    if(!fe->interfaces[i].counted)break;
   }
  if(index==FE_INTERFACES)return -ENOSPC;
 }
 interface=&fe->interfaces[index];
 if(!interface->users) {
  ret=fe_interface_transfer(fe,index,&interface->saved,false);
  if(ret)return ret;
  interface->ready=false;
  interface->source_mac=flow->source_mac;
  interface->pppoe=flow->pppoe;
  __set_bit(index,fe->counters);
 }
 flow->counter=index;
 flow->counted=index<FE_COUNTERS && !interface->counted;
 interface->counted|=flow->counted;
 interface->users++;
 flow->interface_owned=true;
 if(interface->users==1) {
  /* Exclude Ethernet padding from the PPPoE payload length (SDK EIF bit23). */
  unsigned int value=BIT(23)|BIT(18)|((flow->source_mac+1)<<19)|flow->pppoe;
  ret=fe_interface_transfer(fe,index,&value,true);
  if(!ret)interface->ready=true;
  return ret;
 }
 return 0;
}
static int fe_interface_put(struct rtl_fe *fe,struct rtl_fe_flow *flow)
{
 struct rtl_fe_interface *interface;
 int ret;

 if(flow->counter>=FE_INTERFACES)return -ERANGE;
 interface=&fe->interfaces[flow->counter];
 if(interface->users==1) {
  interface->ready=false;
  ret=fe_interface_transfer(fe,flow->counter,&interface->saved,true);
  if(ret)return ret;
  __clear_bit(flow->counter,fe->counters);
 }
 interface->users--;
 if(flow->counted)interface->counted=false;
 return 0;
}
static int fe_mtu_get(struct rtl_fe *fe,struct rtl_fe_flow *flow,unsigned int size)
{
 unsigned int i,index=16,address,shift,value;
 struct rtl_fe_mtu *mtu;

 for(i=0;i<16;i++) {
  if(fe->mtus[i].users && fe->mtus[i].size==size){index=i;break;}
  if(!fe->mtus[i].users && index==16)index=i;
 }
 if(index==16)return -ENOSPC;
 mtu=&fe->mtus[index];
 if(!mtu->users) {
  address=0x3520+(index/2)*4;shift=(index%2)*16;
  value=fe_read(fe,address);
  mtu->saved=(value>>shift)&0x3fff;
  mtu->size=size;
  fe_write(fe,address,(value&~(0x3fffU<<shift))|size<<shift);
 }
 mtu->users++;
 flow->mtu_index=index;flow->mtu_owned=true;
 return 0;
}
static void fe_mtu_put(struct rtl_fe *fe,struct rtl_fe_flow *flow)
{
 unsigned int index=flow->mtu_index,address=0x3520+(index/2)*4,shift=(index%2)*16;
 struct rtl_fe_mtu *mtu=&fe->mtus[index];

 if(!--mtu->users)
  fe_write(fe,address,(fe_read(fe,address)&~(0x3fffU<<shift))|mtu->saved<<shift);
 flow->mtu_owned=false;
}
static int fe_destination_get(struct rtl_fe *fe,struct rtl_fe_flow *flow,const u8 *address)
{
 struct rtl_dq_io io=fe_io(fe);
 struct rtl_fe_flow *other;
 unsigned int words[4],result;
 int ret;

 ether_addr_copy(flow->destination,address);
 list_for_each_entry(other,&fe->flows,list)
  if(other!=flow && other->destination_owned && ether_addr_equal(other->destination,address)) {
   if(!other->destination_ready || other->deleting)return -EBUSY;
   flow->destination_index=other->destination_index;
   memcpy(flow->destination_saved,other->destination_saved,sizeof(flow->destination_saved));
   flow->destination_created=other->destination_created;
   flow->destination_owned=true;
   flow->destination_ready=true;
   return 0;
  }
 rtl_fe_fdb_key(words,address);
 ret=rtl_fe_fdb_command(&io,4,words,&result);
 if(ret)return ret;
 /* The SDK CMD_RETURN status is distinct from ACCESS completion. Only
  * HIT and MISS establish whether an original row exists. */
 if((result&15)!=5 && (result&15)!=15)return -EIO;
 /* The private VID/SC key is not permission to overwrite a foreign or
  * indeterminate row. A real L2 forwarding entry must never be pinned here. */
 if((result&15)==5 && !rtl_fe_fdb_is_pin(words))return -EADDRINUSE;
 flow->destination_created=(result&15)==15;
 if(!flow->destination_created)memcpy(flow->destination_saved,words,sizeof(words));
 /* APPEND updates an existing key in place. Pin its MAC/permissions until
  * the last Linux flow releases it, then restore its original contents. */
 if(flow->destination_created)rtl_fe_fdb_key(words,address);
 else words[0]|=BIT(9)|BIT(19)|BIT(20)|BIT(21);
 /* APPEND can change the table before its completion poll times out.
  * Retain the original row/key for rollback before issuing the command. */
 flow->destination_owned=true;
 flow->destination_ready=false;
 ret=rtl_fe_fdb_command(&io,0x45,words,&result);
 if(ret)return ret;
 if((result&15)==10)return -ENOSPC;
 /* 4 is the SDK's successful append with a port-limit warning. Status 11
  * may have updated a row but is not success; retain rollback ownership. */
 if((result&15)!=5 && (result&15)!=4)return -EIO;
 rtl_fe_fdb_key(words,address);
 ret=rtl_fe_fdb_command(&io,4,words,&result);
 if(ret)return ret;
 if((result&15)!=5 || !rtl_fe_fdb_is_pin(words) ||
    ((result>>4)&0x1fff)>=4128)return -EIO;
 flow->destination_index=(result>>4)&0x1fff;
 flow->destination_ready=true;
 return 0;
}
static int fe_destination_put(struct rtl_fe *fe,struct rtl_fe_flow *flow)
{
 struct rtl_dq_io io=fe_io(fe);
 struct rtl_fe_flow *other;
 unsigned int words[4],result;
 int ret;

 flow->destination_ready=false;
 list_for_each_entry(other,&fe->flows,list)
  if(other!=flow && other->destination_owned && ether_addr_equal(other->destination,flow->destination))return 0;
 if(flow->destination_created) {
  rtl_fe_fdb_key(words,flow->destination);
  ret=rtl_fe_fdb_command(&io,0x85,words,&result);
  if(ret)return ret;
  /* Deletion is idempotent only for the documented HIT/MISS results. */
  return (result&15)==5 || (result&15)==15?0:-EIO;
 }
 memcpy(words,flow->destination_saved,sizeof(words));
 ret=rtl_fe_fdb_command(&io,0x45,words,&result);
 if(ret)return ret;
 if((result&15)==10)return -ENOSPC;
 return (result&15)==5 || (result&15)==4?0:-EIO;
}

struct rtl_fe_rule {
 struct rtl_fe_ipv4_key key;
 struct rtl_fe_ipv6_key key6;
 bool ipv6, bridge;
 bool vlan_exact;
 u16 ingress_tci[2];
 u8 ppp_protocol_slot;
 unsigned short ethernet_protocol;
 unsigned int pppoe_session, egress_pppoe, mtu;
 bool pppoe_input;
 struct rtl_fe_ipv4_action action;
 struct rtl_fe_port *input,*output;
 struct rtl_fe_vlan vlan[2];
 unsigned char vlan_count,ethernet_bytes;
 u8 source[ETH_ALEN],destination[ETH_ALEN];
 unsigned int reject_reason;
};
static int fe_vlan_tpid(__be16 protocol)
{
 switch(ntohs(protocol)) {
 case ETH_P_8021Q:return 1;
 case ETH_P_8021AD:return 2;
 default:return -EOPNOTSUPP;
 }
}
static int fe_vlan_match(const struct flow_match_vlan *match,struct rtl_fe_vlan *vlan)
{
 int tpid;

 if(match->mask->vlan_id!=VLAN_VID_MASK || match->mask->vlan_tpid!=htons(0xffff) ||
    match->mask->vlan_priority || match->mask->vlan_dei ||
    match->mask->vlan_eth_type)return -EOPNOTSUPP;
 tpid=fe_vlan_tpid(match->key->vlan_tpid);
 if(tpid<0)return tpid;
 *vlan=(struct rtl_fe_vlan){.vid=match->key->vlan_id,.tpid=tpid};
 return 0;
}
#include "rtl9617c-fe-vlan.h"

static int fe_parse_bridge(struct rtl_fe_port *port,struct flow_rule *rule,struct rtl_fe_rule *data)
{
 struct flow_match_eth_addrs ethernet;
 struct flow_match_basic basic;
 struct flow_match_vlan vlan;
 struct flow_action_entry *act;
 struct net_device *output=NULL;
 bool known[2]={false,false},changed=false;
 unsigned int count,key;
 int i,ret;

 data->reject_reason=FE_REJECT_KEYS;
 for(key=0;key<FLOW_DISSECTOR_KEY_MAX;key++) {
  if(!flow_rule_match_key(rule,key))continue;
  switch(key) {
  case FLOW_DISSECTOR_KEY_BASIC:case FLOW_DISSECTOR_KEY_ETH_ADDRS:
  case FLOW_DISSECTOR_KEY_META:case FLOW_DISSECTOR_KEY_CONTROL:
  case FLOW_DISSECTOR_KEY_VLAN:case FLOW_DISSECTOR_KEY_CVLAN:
  case FLOW_DISSECTOR_KEY_PPPOE:break;
  default:return -EOPNOTSUPP;
  }
 }
 if(!flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_BASIC))return -EOPNOTSUPP;
 data->reject_reason=FE_REJECT_PROTOCOL;
 flow_rule_match_basic(rule,&basic);
 if(basic.mask->n_proto!=htons(0xffff) || basic.mask->ip_proto)return -EOPNOTSUPP;
 if(flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_CONTROL)) {
  struct flow_match_control control;
  data->reject_reason=FE_REJECT_CONTROL;
  flow_rule_match_control(rule,&control);
  if(control.mask->thoff || control.mask->addr_type || control.mask->flags)return -EOPNOTSUPP;
 }
 if(flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_META)) {
  struct flow_match_meta meta;
  data->reject_reason=FE_REJECT_META;
  flow_rule_match_meta(rule,&meta);
  if(meta.mask->ingress_iftype || meta.mask->l2_miss || (meta.mask->ingress_ifindex &&
     (meta.mask->ingress_ifindex!=-1 || meta.key->ingress_ifindex!=port->netdev->ifindex)))
   return -EOPNOTSUPP;
 }
 flow_rule_match_eth_addrs(rule,&ethernet);
 data->reject_reason=FE_REJECT_KEYS;
 for(i=0;i<ETH_ALEN;i++)
  if(ethernet.mask->src[i]!=255 || ethernet.mask->dst[i]!=255)return -EOPNOTSUPP;
 if(!is_valid_ether_addr(ethernet.key->src) || !is_valid_ether_addr(ethernet.key->dst))return -EINVAL;
 data->bridge=true;data->input=port;
 data->ethernet_protocol=ntohs(basic.key->n_proto);
 data->key=(struct rtl_fe_ipv4_key){.ingress=port->source,.llid=port->llid,
  .mask=61};
 ether_addr_copy(data->source,ethernet.key->src);
 ether_addr_copy(data->destination,ethernet.key->dst);
 data->reject_reason=FE_REJECT_PROTOCOL;
 if(data->ethernet_protocol==ETH_P_PPP_SES) {
  struct flow_match_pppoe pppoe;
  if(!flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_PPPOE))return -EOPNOTSUPP;
  flow_rule_match_pppoe(rule,&pppoe);
  if(pppoe.mask->session_id!=htons(0xffff) || pppoe.mask->ppp_proto ||
     (pppoe.mask->type && (pppoe.mask->type!=htons(0xffff) ||
     pppoe.key->type!=htons(ETH_P_PPP_SES))))return -EOPNOTSUPP;
  data->pppoe_input=true;data->pppoe_session=ntohs(pppoe.key->session_id);
 } else if(flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_PPPOE))return -EOPNOTSUPP;
 data->reject_reason=FE_REJECT_VLAN;
 if(flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_VLAN)) {
  flow_rule_match_vlan(rule,&vlan);
  ret=fe_vlan_match(&vlan,&data->vlan[data->vlan_count++]);
  if(ret)return ret;
 }
 if(flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_CVLAN)) {
  if(!data->vlan_count)return -EOPNOTSUPP;
  flow_rule_match_cvlan(rule,&vlan);
  ret=fe_vlan_match(&vlan,&data->vlan[data->vlan_count++]);
  if(ret)return ret;
 }
 count=data->vlan_count;
 memcpy(data->action.vlan,data->vlan,sizeof(data->vlan));
 data->reject_reason=FE_REJECT_ACTION;
 flow_action_for_each(i,act,&rule->action) {
  switch(act->id) {
  case FLOW_ACTION_REDIRECT:
   if(output || i!=(int)rule->action.num_entries-1)return -EOPNOTSUPP;
   output=act->dev;break;
  case FLOW_ACTION_VLAN_POP:
   if(!count)return -EOPNOTSUPP;
   data->action.vlan[0]=data->action.vlan[1];known[0]=known[1];
   count--;changed=true;break;
  case FLOW_ACTION_VLAN_PUSH:
   if(count==2 || act->vlan.vid>VLAN_VID_MASK || act->vlan.prio>7)return -EOPNOTSUPP;
   ret=fe_vlan_tpid(act->vlan.proto);
   if(ret<0)return ret;
   data->action.vlan[1]=data->action.vlan[0];known[1]=known[0];
   data->action.vlan[0]=(struct rtl_fe_vlan){.vid=act->vlan.vid,.tpid=ret,.priority=act->vlan.prio};
   known[0]=true;count++;changed=true;break;
  default:return -EOPNOTSUPP;
  }
 }
 if(changed)for(i=0;i<count;i++)if(!known[i])return -EOPNOTSUPP;
 data->reject_reason=FE_REJECT_PORT;
 data->output=fe_port(port->fe,output);
 if(!data->output || data->input==data->output)return -EOPNOTSUPP;
 data->action.bridge=1;
 data->action.destination=data->output->destination;
 data->action.deep_queue=data->output->destination>=32;
 data->action.check_mask=data->key.mask;
 data->action.vlan_count=count;data->action.vlan_set=changed;
 data->ethernet_bytes=ETH_HLEN+VLAN_HLEN*count+(data->pppoe_input?8:0);
 return 0;
}

static int fe_parse(struct rtl_fe_port *port,struct flow_cls_offload *cls,struct rtl_fe_rule *data)
{
 struct flow_rule *rule=flow_cls_offload_flow_rule(cls);
 struct flow_match_meta meta;
 struct flow_match_basic basic;
 struct flow_match_pppoe pppoe;
 struct flow_match_ipv4_addrs addresses;
 struct flow_match_ipv6_addrs addresses6;
 struct flow_match_ports ports;
 struct flow_match_vlan vlan_match;
 struct flow_action_entry *act;
 struct net_device *output=NULL;
 u8 ethernet[ETH_HLEN]={},ethernet_known[ETH_ALEN*2]={};
 __be32 new_source,new_destination;
 __be16 new_sport,new_dport;
 bool source_changed,destination_changed;
 struct rtl_fe_vlan output_vlan[2];
 bool vlan_known[2]={false,false},vlan_changed=false;
 unsigned int output_vlan_count,key;
 int i,ret;
 __be16 protocol;

 if(flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
  ret=fe_parse_bridge(port,rule,data);
  if(ret)return ret;
  goto itu_paths;
 }
 /* Never silently drop match predicates. In particular, an IP TOS/TTL,
  * tunnel, connection-state or arbitrary TCP flag restriction cannot be
  * widened into this fixed five-tuple hardware template. */
 data->reject_reason=FE_REJECT_KEYS;
 for(key=0;key<FLOW_DISSECTOR_KEY_MAX;key++) {
  if(!flow_rule_match_key(rule,key))continue;
  switch(key) {
  case FLOW_DISSECTOR_KEY_META:case FLOW_DISSECTOR_KEY_CONTROL:
  case FLOW_DISSECTOR_KEY_BASIC:case FLOW_DISSECTOR_KEY_IPV4_ADDRS:
  case FLOW_DISSECTOR_KEY_IPV6_ADDRS:case FLOW_DISSECTOR_KEY_PORTS:
  case FLOW_DISSECTOR_KEY_VLAN:case FLOW_DISSECTOR_KEY_CVLAN:
  case FLOW_DISSECTOR_KEY_PPPOE:case FLOW_DISSECTOR_KEY_TCP:break;
  default:return -EOPNOTSUPP;
  }
 }
 if(!flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_META) ||
    !flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_BASIC) ||
    (!flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_IPV4_ADDRS) &&
     !flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_IPV6_ADDRS)) ||
    !flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_PORTS))return -EOPNOTSUPP;
 flow_rule_match_meta(rule,&meta);
 data->reject_reason=FE_REJECT_META;
 if(meta.mask->ingress_ifindex!=-1 || meta.mask->ingress_iftype || meta.mask->l2_miss ||
    meta.key->ingress_ifindex!=port->netdev->ifindex)return -EOPNOTSUPP;
 data->reject_reason=FE_REJECT_PROTOCOL;
 flow_rule_match_basic(rule,&basic);
 protocol=basic.key->n_proto;
 if(protocol==htons(ETH_P_PPP_SES)) {
  if(!flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_PPPOE))return -EOPNOTSUPP;
  flow_rule_match_pppoe(rule,&pppoe);
  if(pppoe.mask->session_id!=htons(0xffff) || pppoe.mask->ppp_proto!=htons(0xffff) ||
     pppoe.mask->type!=htons(0xffff) || pppoe.key->type!=htons(ETH_P_PPP_SES))return -EOPNOTSUPP;
  if(pppoe.key->ppp_proto==htons(PPP_IP))protocol=htons(ETH_P_IP);
  else if(pppoe.key->ppp_proto==htons(PPP_IPV6))protocol=htons(ETH_P_IPV6);
  else return -EOPNOTSUPP;
  data->pppoe_input=true;data->pppoe_session=ntohs(pppoe.key->session_id);
 } else if(flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_PPPOE))return -EOPNOTSUPP;
 data->ipv6=protocol==htons(ETH_P_IPV6);
 if((protocol!=htons(ETH_P_IP) && !data->ipv6) || basic.mask->n_proto!=htons(0xffff) ||
    basic.mask->ip_proto!=255 || (basic.key->ip_proto!=IPPROTO_TCP && basic.key->ip_proto!=IPPROTO_UDP))
  return -EOPNOTSUPP;
 if(flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_IPV4_ADDRS)==data->ipv6 ||
    flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_IPV6_ADDRS)!=data->ipv6)return -EOPNOTSUPP;
 data->reject_reason=FE_REJECT_CONTROL;
 if(flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_CONTROL)) {
  struct flow_match_control control;
  flow_rule_match_control(rule,&control);
  if(control.mask->thoff || control.mask->flags ||
     control.mask->addr_type!=0xffff || control.key->addr_type!=
     (data->ipv6?FLOW_DISSECTOR_KEY_IPV6_ADDRS:FLOW_DISSECTOR_KEY_IPV4_ADDRS))return -EOPNOTSUPP;
 }
 if(flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_TCP)) {
  struct flow_match_tcp tcp;
  flow_rule_match_tcp(rule,&tcp);
  /* ASIC mask retains FIN/SYN/RST (bits0..2) as zero. It ignores all
   * other TCP flags: accept only predicates implied by that template. */
  if(basic.key->ip_proto!=IPPROTO_TCP || tcp.key->flags ||
     (ntohs(tcp.mask->flags)&~7U))return -EOPNOTSUPP;
 }
 data->reject_reason=FE_REJECT_VLAN;
 data->vlan_count=0;
 if(flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_VLAN)) {
  flow_rule_match_vlan(rule,&vlan_match);
  ret=fe_vlan_match(&vlan_match,&data->vlan[data->vlan_count++]);
  if(ret)return ret;
 }
 if(flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_CVLAN)) {
  if(!data->vlan_count)return -EOPNOTSUPP;
  flow_rule_match_cvlan(rule,&vlan_match);
  ret=fe_vlan_match(&vlan_match,&data->vlan[data->vlan_count++]);
  if(ret)return ret;
 }
 output_vlan_count=data->vlan_count;
 memcpy(output_vlan,data->vlan,sizeof(output_vlan));
 data->reject_reason=FE_REJECT_KEYS;
 flow_rule_match_ports(rule,&ports);
 if(ports.mask->src!=htons(0xffff) || ports.mask->dst!=htons(0xffff))return -EOPNOTSUPP;
 data->input=port;
 data->key=(struct rtl_fe_ipv4_key){
  .source_port=ntohs(ports.key->src),.destination_port=ntohs(ports.key->dst),
  .protocol=basic.key->ip_proto,.ingress=port->source,.llid=port->llid,.mask=63};
 if(data->ipv6) {
  if(!flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_IPV6_ADDRS))return -EOPNOTSUPP;
  flow_rule_match_ipv6_addrs(rule,&addresses6);
  data->key6=(struct rtl_fe_ipv6_key){.source_port=data->key.source_port,
   .destination_port=data->key.destination_port,.protocol=data->key.protocol,
   .ingress=data->key.ingress,.llid=data->key.llid,.mask=data->key.mask};
  for(i=0;i<4;i++) {
   if(addresses6.mask->src.s6_addr32[i]!=htonl(~0U) ||
      addresses6.mask->dst.s6_addr32[i]!=htonl(~0U))return -EOPNOTSUPP;
   data->key6.source[i]=ntohl(addresses6.key->src.s6_addr32[i]);
   data->key6.destination[i]=ntohl(addresses6.key->dst.s6_addr32[i]);
  }
  new_source=new_destination=0;
 } else {
  if(!flow_rule_match_key(rule,FLOW_DISSECTOR_KEY_IPV4_ADDRS))return -EOPNOTSUPP;
  flow_rule_match_ipv4_addrs(rule,&addresses);
  if(addresses.mask->src!=htonl(~0U) || addresses.mask->dst!=htonl(~0U))return -EOPNOTSUPP;
  data->key.source=ntohl(addresses.key->src);data->key.destination=ntohl(addresses.key->dst);
  new_source=addresses.key->src;new_destination=addresses.key->dst;
 }
 new_sport=ports.key->src;new_dport=ports.key->dst;
 data->reject_reason=FE_REJECT_ACTION;
 flow_action_for_each(i,act,&rule->action) {
  unsigned int offset=act->mangle.offset;
  u32 value;

  switch(act->id) {
  case FLOW_ACTION_PPPOE_PUSH:
   if(data->egress_pppoe || !act->pppoe.sid || !act->pppoe.mtu ||
      act->pppoe.mtu>0x3fff)return -EOPNOTSUPP;
   data->egress_pppoe=3U|((unsigned int)act->pppoe.sid<<2);
   data->mtu=act->pppoe.mtu;
   break;
  case FLOW_ACTION_VLAN_POP:
   if(!output_vlan_count)return -EOPNOTSUPP;
   output_vlan[0]=output_vlan[1];vlan_known[0]=vlan_known[1];
   output_vlan_count--;vlan_changed=true;
   break;
  case FLOW_ACTION_VLAN_PUSH:
   if(output_vlan_count==2 || act->vlan.vid>VLAN_VID_MASK || act->vlan.prio>7)
    return -EOPNOTSUPP;
   ret=fe_vlan_tpid(act->vlan.proto);
   if(ret<0)return ret;
   output_vlan[1]=output_vlan[0];vlan_known[1]=vlan_known[0];
   output_vlan[0]=(struct rtl_fe_vlan){.vid=act->vlan.vid,.tpid=ret,.priority=act->vlan.prio};
   vlan_known[0]=true;output_vlan_count++;vlan_changed=true;
   break;
  case FLOW_ACTION_REDIRECT:
   if(output || i!=(int)rule->action.num_entries-1)return -EOPNOTSUPP;
   output=act->dev;break;
  case FLOW_ACTION_CSUM:
   /* The packet editor supports the checksums implied by this IPv4
    * TCP/UDP template, not arbitrary tc checksum-repair requests. */
   if(data->ipv6 || act->csum_flags&~(TCA_CSUM_UPDATE_FLAG_IPV4HDR|
      (basic.key->ip_proto==IPPROTO_TCP?TCA_CSUM_UPDATE_FLAG_TCP:TCA_CSUM_UPDATE_FLAG_UDP)))
    return -EOPNOTSUPP;
   break;
  case FLOW_ACTION_MANGLE:
   if(act->mangle.htype==FLOW_ACT_MANGLE_HDR_TYPE_ETH) {
    if(offset>sizeof(ethernet_known)-sizeof(value))return -EOPNOTSUPP;
    value=get_unaligned((u32 *)(ethernet+offset));
    put_unaligned((value&act->mangle.mask)|act->mangle.val,(u32 *)(ethernet+offset));
    value=get_unaligned((u32 *)(ethernet_known+offset));
    put_unaligned(value|~act->mangle.mask,(u32 *)(ethernet_known+offset));
   } else if(act->mangle.htype==FLOW_ACT_MANGLE_HDR_TYPE_IP4) {
    if(data->ipv6)return -EOPNOTSUPP;
    if(act->mangle.mask)return -EOPNOTSUPP;
    if(offset==offsetof(struct iphdr,saddr))memcpy(&new_source,&act->mangle.val,4);
    else if(offset==offsetof(struct iphdr,daddr))memcpy(&new_destination,&act->mangle.val,4);
    else return -EOPNOTSUPP;
   } else if(act->mangle.htype==FLOW_ACT_MANGLE_HDR_TYPE_TCP || act->mangle.htype==FLOW_ACT_MANGLE_HDR_TYPE_UDP) {
    __be16 pair[2]={new_sport,new_dport};
    if((act->mangle.htype==FLOW_ACT_MANGLE_HDR_TYPE_TCP)!=(basic.key->ip_proto==IPPROTO_TCP))
     return -EOPNOTSUPP;
    if(offset)return -EOPNOTSUPP;
    memcpy(&value,pair,4);
    value=(value&act->mangle.mask)|act->mangle.val;
    memcpy(pair,&value,4);
    new_sport=pair[0];new_dport=pair[1];
    if(data->ipv6 && (new_sport!=ports.key->src || new_dport!=ports.key->dst))return -EOPNOTSUPP;
   } else return -EOPNOTSUPP;
   break;
  default:return -EOPNOTSUPP;
  }
 }
 for(i=0;i<ETH_ALEN*2;i++)
  if(ethernet_known[i]!=255)return -EOPNOTSUPP;
 data->reject_reason=FE_REJECT_PORT;
 data->output=fe_port(port->fe,output);
 if(!data->output || data->input==data->output)return -EOPNOTSUPP;
 ether_addr_copy(data->destination,ethernet);
 ether_addr_copy(data->source,ethernet+ETH_ALEN);
 if(!is_valid_ether_addr(data->source) || !is_valid_ether_addr(data->destination))return -EINVAL;
 source_changed=!data->ipv6 && (new_source!=addresses.key->src || new_sport!=ports.key->src);
 destination_changed=!data->ipv6 && (new_destination!=addresses.key->dst || new_dport!=ports.key->dst);
 data->reject_reason=FE_REJECT_NAT;
 if(source_changed && destination_changed)return -EOPNOTSUPP;
 /* A remaining input tag has unknown PCP/DEI. Leave it untouched, or let
  * Linux perform a partial-stack edit; a new tag is fully specified. */
 data->reject_reason=FE_REJECT_VLAN;
 if(vlan_changed)
  for(i=0;i<output_vlan_count;i++)if(!vlan_known[i])return -EOPNOTSUPP;
 data->action=(struct rtl_fe_ipv4_action){.destination=data->output->destination,.check_mask=63,
  .deep_queue=data->output->destination>=32,.translate=source_changed||destination_changed,
  .translate_destination=destination_changed,.address=ntohl(destination_changed?new_destination:new_source),
  .port=ntohs(destination_changed?new_dport:new_sport)};
 data->action.vlan_set=vlan_changed;
 data->action.pppoe_pop=data->pppoe_input && !data->egress_pppoe;
 data->action.vlan_count=output_vlan_count;
 memcpy(data->action.vlan,output_vlan,sizeof(output_vlan));
 data->ethernet_bytes=ETH_HLEN+VLAN_HLEN*output_vlan_count+(data->egress_pppoe?8:0);
itu_paths:
 data->reject_reason=FE_REJECT_PON;
 if(port->fe->itu_paths) {
  bool mapped=port->fe->itu_paths->profile_count!=0;
  for(i=0;!mapped && i<(int)port->fe->itu_paths->count;i++)mapped=port->fe->itu_paths->path[i].unmarked_mode!=0;
  if(mapped)return fe_itu_rule(data);
 }
 if(port->netdev==port->fe->itu_netdev) {
  const struct rtl_itu_path *path=rtl_itu_path_downstream(port->fe->itu_paths,
   data->vlan_count?data->vlan[0].vid:65535,255);
  if(!path)return -EOPNOTSUPP;
  data->key.llid=path->index;data->key6.llid=path->index;
 }
 if(data->output->netdev==port->fe->itu_netdev) {
  const struct rtl_itu_path *path=rtl_itu_path_flow(port->fe->itu_paths,
   data->action.vlan_count?data->action.vlan[0].vid:65535);
  if(!path)return -EOPNOTSUPP;
  data->action.destination=32+path->tcont;
  data->action.deep_queue=1;
  data->action.cos=path->queue;
  data->action.gem_set=1;data->action.gem_index=path->index;
 }
 return 0;
}

static int fe_delete(struct rtl_fe *fe,struct rtl_fe_flow *flow)
{
 struct rtl_dq_io io=fe_io(fe);
 int ret;

 flow->deleting=true;
 if(flow->published) {
  ret=rtl_fe_main_age(&io,flow->hash_index,0);
  if(ret)goto retry;
 }
 /* G3_hash 3.3.2 requires clearing the DDR key before invalidating cache.
  * SDK aal_hash_delete, ca-network-drivers commit
  * 8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0, lines3302..3305. */
 ((__le32 *)fe->memory)[flow->hash_index]=0;
 dma_wmb();
 if(flow->published) {
  ret=rtl_fe_cache_command(&io,flow->hash_index,flow->crc16,1);
  if(ret)goto retry;
  flow->published=false;
 }
 if(flow->destination_owned) {
  ret=fe_destination_put(fe,flow);
  if(ret)goto retry;
  flow->destination_owned=false;
 }
 /* The EIF still names the source CAM until its restore succeeds. */
 if(flow->interface_owned) {
  ret=fe_interface_put(fe,flow);
  if(ret)goto retry;
  flow->interface_owned=false;
 }
 if(flow->source_owned) {
  ret=fe_source_put(fe,flow->source_mac);
  if(ret)goto retry;
  flow->source_owned=false;
 }
 if(flow->mtu_owned)fe_mtu_put(fe,flow);
 __clear_bit(flow->hash_index,fe->hashes);
 rb_erase(&flow->cookie_node,&fe->cookies);
 list_del(&flow->retry);
 list_del(&flow->list);
 if(flow->installed)fe->deletes++;
 kfree(flow);
 return 0;
retry:
 /* Keep the cookie reserved until every hardware owner is released. */
 if(list_empty(&flow->retry))list_add_tail(&flow->retry,&fe->retries);
 if(!fe->shutting_down)mod_delayed_work(system_wq,&fe->cleanup_work,HZ);
 return ret;
}
static void fe_cleanup_work(struct work_struct *work)
{
 struct rtl_fe *fe=container_of(to_delayed_work(work),struct rtl_fe,cleanup_work);
 struct rtl_fe_flow *flow,*next;

 mutex_lock(&fe->lock);
 if(fe->shutting_down)goto unlock;
 list_for_each_entry_safe(flow,next,&fe->retries,retry)
  fe_delete(fe,flow);
 fe_collect_ports(fe);
unlock:
 mutex_unlock(&fe->lock);
}

/* A synchronous L2 policy gate also invalidates old route actions before
 * LAN is readmitted. The Linux flowtable can still provide its software
 * path; a cached hardware action from an older bridge generation is not
 * authority to bypass the new topology, VLAN, STP or filtering decision. */
static int __maybe_unused fe_switch_flush_routes_locked(struct rtl_fe *fe)
{
 struct rtl_fe_flow *flow,*next;
 int ret;

 list_for_each_entry_safe(flow,next,&fe->flows,list) {
  ret=fe_delete(fe,flow);
  if(ret){fe->error=ret;return ret;}
 }
 fe_collect_ports(fe);
 return 0;
}

static int fe_install(struct rtl_fe_port *port,struct rtl_fe_rule data,unsigned long cookie)
{
 struct rtl_fe *fe=port->fe;
 struct rtl_dq_io io=fe_io(fe);
 struct rtl_fe_flow *flow;
 unsigned int words[23],action[8],crc32,index,start,counters[7],i;
 u16 crc16;
 int ret;

 if(port->retired || fe->shutting_down)return -ENODEV;
 if(!fe->engine_ready || !fe->enabled || !fe_switch_flow_allowed(fe) ||
    !netif_running(data.input->netdev) || !netif_running(data.output->netdev) ||
    !netif_carrier_ok(data.input->netdev) || !netif_carrier_ok(data.output->netdev))return -EAGAIN;
 if(fe_flow(fe,cookie))return -EEXIST;
 if(data.bridge)rtl_fe_bridge_key(words,data.source,data.destination,data.ethernet_protocol,
  data.key.ingress,data.key.llid,data.key.mask);
 else if(data.ipv6)rtl_fe_ipv6_key(words,&data.key6);
 else rtl_fe_ipv4_key(words,&data.key);
 rtl_fe_vlan_key(words,data.vlan,data.vlan_count);
 if(data.vlan_exact)for(i=0;i<data.vlan_count;i++) {
  rtl_fe_bits_set(words,i?426:445,1,!!(data.ingress_tci[i]&VLAN_CFI_MASK));
  rtl_fe_bits_set(words,i?427:446,3,data.ingress_tci[i]>>VLAN_PRIO_SHIFT);
 }
 rtl_fe_key_set(words,RTL_FE_KEY_PPPOE_SESSION_ID,data.pppoe_session);
 rtl_fe_key_set(words,RTL_FE_KEY_PPPOE_TYPE,data.pppoe_input?2:0);
 if(data.vlan_exact && data.pppoe_input)rtl_fe_bits_set(words,400,4,data.ppp_protocol_slot);
 rtl_fe_key_set(words,RTL_FE_KEY_ORIG_LSPID,0);
 rtl_fe_key_set(words,RTL_FE_KEY_CTRL_SET_ID,0);
 rtl_fe_key_set(words,RTL_FE_KEY_TABLE_ID,0);
 rtl_fe_key_crc(words,&crc32,&crc16);
 start=rtl_fe_hash_bucket(crc16);
 /* Hardware compares only CRC32 within the 32-slot bucket. Inspect the
  * occupied DDR keys instead of walking every flow on each installation.
  * The retry list also covers an uncertain cache invalidation: deletion
  * clears DDR first, but a failed cache command can leave the old key live. */
 for(index=start;index<start+32;index++)
  if(test_bit(index,fe->hashes) &&
     le32_to_cpu(((__le32 *)fe->memory)[index])==crc32)return -EOPNOTSUPP;
 list_for_each_entry(flow,&fe->retries,retry)
  if(flow->published && flow->hash_index/32==start/32 &&
     flow->crc32==crc32)return -EOPNOTSUPP;
 /* RTL9617C cache-age0 erratum: invalidating CRC16[12:0]=0/slot0
  * can select an empty cache row instead of this flow. Keep slot0 free.
  * SDK aal_hash.c (__hash_tbl_entry_add), ca-network-drivers commit
  * 8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0, lines3777..3783. */
 for(index=start+(!(crc16&0x1fff));index<start+32;index++)
  if(!test_bit(index,fe->hashes))break;
 if(index==start+32)return -ENOSPC;
 flow=kzalloc(sizeof(*flow),GFP_KERNEL);
 if(!flow)return -ENOMEM;
 flow->cookie=cookie;
 flow->hash_index=index;flow->crc16=crc16;flow->crc32=crc32;
 INIT_LIST_HEAD(&flow->retry);
 flow->input=data.input;flow->output=data.output;flow->lastused=jiffies;
 flow->ethernet_bytes=data.ethernet_bytes;
 flow->pppoe=data.egress_pppoe;
 flow->ingress_session=data.pppoe_session;
 flow->ingress_pol=data.key.llid;
 flow->ethernet_protocol=data.ethernet_protocol;
 ether_addr_copy(flow->ethernet_source,data.source);
 flow->protocol=data.key.protocol;flow->ipv6=data.ipv6;
 flow->bridge=data.bridge;
 flow->source_port=data.key.source_port;flow->destination_port=data.key.destination_port;
 for(i=0;i<(data.ipv6?4:1);i++) {
  put_unaligned_be32(data.ipv6?data.key6.source[i]:data.key.source,flow->ip_source+i*4);
  put_unaligned_be32(data.ipv6?data.key6.destination[i]:data.key.destination,flow->ip_destination+i*4);
 }
 __set_bit(index,fe->hashes);
 list_add_tail(&flow->list,&fe->flows);
 fe_index_flow(fe,flow);
 if(!data.bridge) {
  flow->source_mac=FE_SOURCE_MACS;
  ret=fe_source_get(fe,data.source,&flow->source_mac);
  flow->source_owned=flow->source_mac!=FE_SOURCE_MACS;
  if(ret)goto rollback;
  ret=fe_destination_get(fe,flow,data.destination);
  if(ret)goto rollback;
  ret=fe_interface_get(fe,flow);
  if(ret)goto rollback;
 } else ether_addr_copy(flow->destination,data.destination);
 if(data.mtu) {
  ret=fe_mtu_get(fe,flow,data.mtu);
  if(ret)goto rollback;
  data.action.mtu_set=1;data.action.mtu_index=flow->mtu_index;
 }
 if(flow->counted) {
  ret=rtl_fe_tx_counter_read(&io,flow->counter,counters);
  if(ret)goto rollback;
  flow->bytes=(u64)counters[1]<<32|counters[0];flow->packets=counters[2]+counters[3];
 }
 data.action.mac_da_index=flow->destination_index;
 data.action.egress_interface=flow->counter;
 rtl_fe_ipv4_action(action,&data.action);
 rtl_fe_action_set(action,RTL_FE_L3_IF_COUNTER_EN,flow->counted);
 ((__le32 *)fe->memory)[index]=cpu_to_le32(crc32);
 memcpy(fe->memory+RTL_FE_ACTION_OFFSET+index*RTL_FE_ACTION_BYTES,action,sizeof(action));
 dma_wmb();
 flow->published=true;
 ret=rtl_fe_main_age(&io,index,1); /* FC idle/valid; hardware hit raises age. */
 if(ret)goto rollback;
 flow->installed=true;
 fe->installs++;
 return 0;
rollback:
 /* Keep an incomplete release attached to its owners for the next callback. */
 if(fe_delete(fe,flow))fe->error=ret;
 return ret;
}
static int fe_replace(struct rtl_fe_port *port,struct flow_cls_offload *cls)
{
 struct rtl_fe_rule data={};
 struct rtl_fe_observe *observe=&port->fe->observe;
 int ret;

 observe->replace_requests++;
 ret=fe_parse(port,cls,&data);
 if(ret) {
  rtl_fe_observe_parse(observe,data.reject_reason);
  return ret;
 }
 ret=fe_install(port,data,cls->cookie);
 rtl_fe_observe_install(observe,ret);
 return ret;
}
static int fe_stats(struct rtl_fe *fe,struct rtl_fe_flow *flow,struct flow_cls_offload *cls)
{
 struct rtl_dq_io io=fe_io(fe);
 unsigned int words[7],age;
 u64 bytes;
 u64 byte_delta;
 u32 packets;
 u32 packet_delta;
 int ret;

 if(!flow->published)return -ENOENT;
 ret=rtl_fe_main_age_read(&io,flow->hash_index,&age);
 if(ret)return ret;
 if(age>1) {
  ret=rtl_fe_main_age(&io,flow->hash_index,1);
  if(ret)return ret;
  flow->lastused=jiffies;
 }
 if(!flow->counted) {
  flow_stats_update(&cls->stats,0,0,0,flow->lastused,FLOW_ACTION_HW_STATS_DELAYED);
  return 0;
 }
 ret=rtl_fe_tx_counter_read(&io,flow->counter,words);
 if(ret)return ret;
 bytes=(u64)words[1]<<32|words[0];packets=words[2]+words[3];
 if(bytes!=flow->bytes || packets!=flow->packets)flow->lastused=jiffies;
 byte_delta=bytes-flow->bytes;packet_delta=packets-flow->packets;
 /* The PE MIB measures the output frame, including its VLAN headers. */
 flow_stats_update(&cls->stats,byte_delta-(u64)packet_delta*flow->ethernet_bytes,packet_delta,0,
                   flow->lastused,FLOW_ACTION_HW_STATS_DELAYED);
 flow->bytes=bytes;flow->packets=packets;
 return 0;
}
static int fe_block_callback(enum tc_setup_type type,void *data,void *private)
{
 struct rtl_fe_port *port=private;
 struct rtl_fe *fe=port->fe;
 struct flow_cls_offload *cls=data;
 struct rtl_fe_flow *flow,*next;
 int ret;

 if(type!=TC_SETUP_CLSFLOWER || cls->common.chain_index)return -EOPNOTSUPP;
 mutex_lock(&fe->lock);
 if(fe->shutting_down){ret=-ENODEV;goto unlock;}
 list_for_each_entry_safe(flow,next,&fe->retries,retry) {
  ret=fe_delete(fe,flow);
  if(ret)goto unlock;
 }
 flow=fe_flow(fe,cls->cookie);
 switch(cls->command) {
 case FLOW_CLS_REPLACE:
  ret=port->retired?-ENODEV:fe_replace(port,cls);
  break;
 case FLOW_CLS_DESTROY:
  ret=flow && flow->input==port?fe_delete(fe,flow):-ENOENT;
  break;
 case FLOW_CLS_STATS:
  ret=port->retired?-ENODEV:
      flow && flow->input==port?fe_stats(fe,flow,cls):-ENOENT;
  break;
 default:ret=-EOPNOTSUPP;
 }
 fe_collect_ports(fe);
unlock:
 /* Legacy rejected reports failed admission, including unsupported rules;
  * it is not a packet-miss counter, nor a count of stats/destroy callbacks. */
 if(ret && cls->command==FLOW_CLS_REPLACE && ret!=-EEXIST)fe->misses++;
 mutex_unlock(&fe->lock);
 return ret;
}
static void fe_block_release(void *private)
{
 struct rtl_fe_port *port=private;
 struct rtl_fe *fe=port->fe;

 mutex_lock(&fe->lock);
 port->bindings--;
 fe_collect_ports(fe);
 mutex_unlock(&fe->lock);
}
int rtl_fe_setup_tc(struct rtl_fe *fe,struct net_device *netdev,enum tc_setup_type type,void *data)
{
 struct rtl_fe_port *port,*candidate;
 struct flow_block_offload *block=data;
 struct flow_block_cb *callback;
 int ret;

 /* This backend implements exact, policy-authorized nft flowtable rules.
  * Bare clsact flower has priorities/chains and policy invalidation semantics
  * that the fixed hash templates cannot implement safely. */
 if(!fe || type!=TC_SETUP_FT)return -EOPNOTSUPP;
 if(block->binder_type!=FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)return -EOPNOTSUPP;
 mutex_lock(&fe->lock);
 /* UNBIND must remain available to release a quarantined callback owner;
  * new binds and all hardware callbacks are rejected after shutdown. */
 if(fe->shutting_down && block->command!=FLOW_BLOCK_UNBIND){ret=-ENODEV;goto unlock;}
 if(block->command==FLOW_BLOCK_UNBIND) {
  /* A retired callback can outlive free_netdev, and a new netdev may reuse
   * the same address. Resolve its block/private identity, not whichever
   * active port now happens to have that netdev pointer. */
  port=NULL;callback=NULL;
  list_for_each_entry(candidate,&fe->ports,list)
   if(candidate->netdev==netdev) {
    callback=flow_block_cb_lookup(block->block,fe_block_callback,candidate);
    if(callback){port=candidate;break;}
   }
  if(!callback){ret=-ENOENT;goto unlock;}
 } else {
  port=fe_port(fe,netdev);
  if(!port){ret=-ENODEV;goto unlock;}
  callback=flow_block_cb_lookup(block->block,fe_block_callback,port);
 }
 block->driver_block_list=&fe->blocks;
 switch(block->command) {
 case FLOW_BLOCK_BIND:
  /* fw4 probes a second flowtable while the active one remains bound. */
  if(callback){flow_block_cb_incref(callback);ret=0;break;}
  callback=flow_block_cb_alloc(fe_block_callback,port,port,fe_block_release);
  if(IS_ERR(callback)){ret=PTR_ERR(callback);break;}
  flow_block_cb_incref(callback);
  flow_block_cb_add(callback,block);
  list_add_tail(&callback->driver_list,&fe->blocks);
  port->bindings++;
  ret=0;
  break;
 case FLOW_BLOCK_UNBIND:
  if(!callback){ret=-ENOENT;break;}
  if(!flow_block_cb_decref(callback)) {
   flow_block_cb_remove(callback,block);
   list_del(&callback->driver_list);
  }
  ret=0;
  break;
 default:ret=-EOPNOTSUPP;break;
 }
unlock:
 mutex_unlock(&fe->lock);
 return ret;
}

static int fe_counters_show(struct seq_file *file,void *unused)
{
 struct rtl_fe *fe=file->private;
 struct rtl_dq_io io=fe_io(fe);
 struct rtl_fe_flow *flow;
 unsigned int words[7],age,interface,destination;
 const __le32 *action;
 int ret;

 mutex_lock(&fe->lock);
 if(fe->shutting_down){mutex_unlock(&fe->lock);return -ENODEV;}
 seq_puts(file,"hash input output pol_id dpid ingress_sid egress_sid age protocol source destination counter bytes packets drop_bytes drop_packets egress_word\n");
 list_for_each_entry(flow,&fe->flows,list) {
  if(!flow->published)continue;
  /* A failed hardware withdrawal may outlive unregister/free_netdev.
   * Retired ports retain pointer identity for UNBIND, not a netdev owner. */
  if(flow->input->retired || flow->output->retired)continue;
  ret=rtl_fe_main_age_read(&io,flow->hash_index,&age);
  interface=0;
  if(!ret && flow->interface_owned)ret=fe_interface_transfer(fe,flow->counter,&interface,false);
  if(ret){seq_printf(file,"%u error=%d\n",flow->hash_index,ret);continue;}
  action=fe->memory+RTL_FE_ACTION_OFFSET+flow->hash_index*RTL_FE_ACTION_BYTES;
  destination=le32_to_cpu(action[0])>>8&1023;
  if((le32_to_cpu(action[0])&BIT(18)) && (le32_to_cpu(action[3])&BIT(6)))
   destination=32+((le32_to_cpu(action[3])>>10)&31);
  seq_printf(file,"%u %s %s %u %u %u %u %u ",flow->hash_index,
             flow->input->netdev->name,flow->output->netdev->name,
             flow->ingress_pol,destination,flow->ingress_session,flow->pppoe>>2,age);
  if(flow->bridge)
   seq_printf(file,"%04x %pM %pM ",flow->ethernet_protocol,
              flow->ethernet_source,flow->destination);
  else if(flow->ipv6)
   seq_printf(file,"%u [%pI6c]:%u [%pI6c]:%u ",flow->protocol,
              flow->ip_source,flow->source_port,flow->ip_destination,flow->destination_port);
  else
   seq_printf(file,"%u %pI4:%u %pI4:%u ",flow->protocol,
              flow->ip_source,flow->source_port,flow->ip_destination,flow->destination_port);
  if(!flow->interface_owned) {
   seq_puts(file,"- - - - - -\n");
   continue;
  }
  if(!flow->counted) {
   seq_printf(file,"- - - - - %08x\n",interface);
   continue;
  }
  ret=rtl_fe_tx_counter_read(&io,flow->counter,words);
  if(ret){seq_printf(file,"error=%d\n",ret);continue;}
  seq_printf(file,"%u %llu %u %llu %u %08x\n",flow->counter,
             (u64)words[1]<<32|words[0],words[2]+words[3],
             (u64)words[5]<<32|words[4],words[6],interface);
 }
 mutex_unlock(&fe->lock);
 return 0;
}
DEFINE_SHOW_ATTRIBUTE(fe_counters);


/* Opt-in diagnostics; never scheduled or called by packet/flow callbacks. */
struct fe_cache_read_context {
 struct rtl_fe *fe;
 u64 deadline;
};

/* Both idle precheck and completion wait are at most1ms, constrained by the
 * remaining50ms soft budget. No second request follows any access failure. */
static int fe_cache_read_access(void *context,unsigned int address,unsigned int value)
{
 struct fe_cache_read_context *ctx=context;
 u64 now;
 unsigned int timeout;
 u32 status;
 int ret;

 if(address!=0x38e4 || !(value&BIT(31)) || (value&~(BIT(31)|0xfffU)))
  return -EINVAL;
 now=ktime_get_ns();
 if(now>=ctx->deadline || ctx->deadline-now<1000)return -ETIMEDOUT;
 timeout=min_t(u64,1000,(ctx->deadline-now)/1000);
 ret=readl_poll_timeout(ctx->fe->registers+address,status,!(status&BIT(31)),1,timeout);
 if(ret)return ret;
 now=ktime_get_ns();
 if(now>=ctx->deadline || ctx->deadline-now<1000)return -ETIMEDOUT;
 timeout=min_t(u64,1000,(ctx->deadline-now)/1000);
 writel(value,ctx->fe->registers+address);
 return readl_poll_timeout(ctx->fe->registers+address,status,!(status&BIT(31)),1,timeout);
}
static unsigned int fe_cache_read_reg(void *context,unsigned int address)
{
 struct fe_cache_read_context *ctx=context;
 return fe_read(ctx->fe,address);
}

static ssize_t fe_cache_target_write(struct file *file,const char __user *buffer,
 size_t count,loff_t *position)
{
 struct rtl_fe *fe=file->private_data;
 unsigned int target;
 int ret=kstrtouint_from_user(buffer,count,0,&target);

 if(ret)return ret;
 /* 65536 disables queries;0..65535 select an active main-hash index. */
 if(target>RTL_FE_HASH_ENTRIES)return -ERANGE;
 if(!mutex_trylock(&fe->lock))return -EBUSY;
 if(fe->shutting_down){mutex_unlock(&fe->lock);return -ENODEV;}
 fe->cache_target=target;
 mutex_unlock(&fe->lock);
 return count;
}
static const struct file_operations fe_cache_target_fops={
 .owner=THIS_MODULE,.open=simple_open,.write=fe_cache_target_write,
};

static int fe_cache_snapshot_show(struct seq_file *file,void *unused)
{
 static const char *const observations[]={
  "layout_unsupported","io_incomplete","key_changed","fib_changed",
  "check_action_only","not_in_expected_set","observed_equal","observed_different",
 };
 struct rtl_fe *fe=file->private;
 struct rtl_fe_flow *flow;
 struct rtl_fe_cache_expected expected={};
 struct rtl_fe_cache_snapshot result;
 struct fe_cache_read_context context={.fe=fe};
 const struct rtl_dq_io io={.context=&context,.read=fe_cache_read_reg,
  .indirect=fe_cache_read_access};
 char input[IFNAMSIZ],output[IFNAMSIZ];
 unsigned int i,protocol=0,source_port=0,destination_port=0;
 const __le32 *action;
 const char *status="target_inactive";

 if(!mutex_trylock(&fe->lock)) {
  seq_puts(file,"status=busy complete=0\n");
  return 0;
 }
 if(fe->shutting_down){status="backend_shutdown";goto no_query;}
 if(fe->cache_target==RTL_FE_HASH_ENTRIES) {
  status="disabled";
  goto no_query;
 }
 if(!fe->prepared) {
  status="backend_unprepared";
  goto no_query;
 }
 list_for_each_entry(flow,&fe->flows,list)
  if(flow->hash_index==fe->cache_target && flow->published && !flow->deleting &&
     !flow->input->retired && !flow->output->retired) {
   expected.hash_index=flow->hash_index;
   expected.crc16=flow->crc16;
   expected.crc32=le32_to_cpu(((__le32 *)fe->memory)[flow->hash_index]);
   action=fe->memory+RTL_FE_ACTION_OFFSET+flow->hash_index*RTL_FE_ACTION_BYTES;
   for(i=0;i<7;i++)expected.action[i]=le32_to_cpu(action[i]);
   strscpy(input,flow->input->netdev->name,sizeof(input));
   strscpy(output,flow->output->netdev->name,sizeof(output));
   protocol=flow->protocol;source_port=flow->source_port;destination_port=flow->destination_port;
   context.deadline=ktime_get_ns()+50ULL*1000*1000;
   rtl_fe_cache_snapshot(&io,&expected,&result);
   mutex_unlock(&fe->lock);
   /* KEY/FIB bracketing observes stability, not hardware atomicity: cache
    * replacement/ABA remains possible. Raw addresses/actions never leave. */
   seq_printf(file,"status=%s complete=%u error=%d hash=%u input=%s output=%s proto=%u sport=%u dport=%u crc32=%08x crc16=%04x scanned=%u cache=%u loc=%u age=%u check_actions=%u word_mask=%02x",
    observations[result.observation],result.complete,result.error,expected.hash_index,
    input,output,protocol,source_port,destination_port,expected.crc32,expected.crc16,
    result.scanned,result.cache_index,result.location,result.age,result.check_actions,result.word_mask);
   for(i=0;i<7;i++)seq_printf(file," diff%u=%08x",i,result.diff[i]);
   seq_putc(file,'\n');
   return 0;
  }
no_query:
 mutex_unlock(&fe->lock);
 seq_printf(file,"status=%s complete=0\n",status);
 return 0;
}
DEFINE_SHOW_ATTRIBUTE(fe_cache_snapshot);

struct rtl_fe *rtl_fe_allocate(struct device *device,void __iomem *registers)
{
 void __iomem *reo=devm_platform_ioremap_resource_byname(to_platform_device(device),"l3fe-axi-reorder");
 struct rtl_fe *fe;
 unsigned int *defaults,i;

 if(IS_ERR(reo))return ERR_CAST(reo);
 fe=kzalloc(sizeof(*fe),GFP_KERNEL);
 if(!fe)return ERR_PTR(-ENOMEM);
 fe->device=device;fe->registers=registers;
 /* The shared fabric owns the command-mode bit across timeouts. A timed-out
  * FDB operation must not have its mode changed while ACCESS is busy. */
 fe->fdb_cmd_mode_saved=fe_read(fe,0x1c00)&BIT(31);
 mutex_init(&fe->lock);
 spin_lock_init(&fe->route_lock);
 INIT_DELAYED_WORK(&fe->cleanup_work,fe_cleanup_work);
 INIT_LIST_HEAD(&fe->ports);INIT_LIST_HEAD(&fe->flows);INIT_LIST_HEAD(&fe->blocks);
 INIT_LIST_HEAD(&fe->retries);
 fe->cookies=RB_ROOT;
 fe->cache_target=RTL_FE_HASH_ENTRIES;
 fe->memory=dma_alloc_coherent(device,RTL_FE_MEMORY_BYTES,&fe->dma,GFP_KERNEL);
 if(!fe->memory){kfree(fe);return ERR_PTR(-ENOMEM);}
 defaults=fe->memory+RTL_FE_DEFAULT_OFFSET;
 for(i=0;i<32;i++)rtl_fe_cpu_miss(defaults+i*4);
 dma_wmb();
 fe->debug=debugfs_create_dir("rtl9617c-fe",NULL);
 debugfs_create_file("flows",0400,fe->debug,fe,&fe_counters_fops);
 debugfs_create_file("cache_target",0200,fe->debug,fe,&fe_cache_target_fops);
 debugfs_create_file("cache_snapshot",0400,fe->debug,fe,&fe_cache_snapshot_fops);
 fe->bridge=fe_bridge_start(fe);
 if(IS_ERR(fe->bridge)) {
  int ret=PTR_ERR(fe->bridge);
  debugfs_remove_recursive(fe->debug);
  dma_free_coherent(fe->device,RTL_FE_MEMORY_BYTES,fe->memory,fe->dma);
  kfree(fe);
  return ERR_PTR(ret);
 }
 /* aal_l3fe_axi_reo_init: Hash uses instance1. ID15 avoids the stock
  * main-Hash hang; default actions must remain in DMA memory as well. */
 writel(15,reo+0x80);
 writel(BIT(31)|8,reo+0x84);
 writel(BIT(28),reo+0x88);
 writel(BIT(28),reo+0x8c);
 writel(BIT(31)|9,reo+0x90);
 readl(reo+0x90);
 return fe;
}
int rtl_fe_add_port(struct rtl_fe *fe,struct net_device *netdev,unsigned int source,
                    unsigned int destination,unsigned int llid)
{
 struct rtl_fe_port *port;

 if(!fe)return 0;
 port=kzalloc(sizeof(*port),GFP_KERNEL);
 if(!port)return -ENOMEM;
 port->fe=fe;port->netdev=netdev;port->source=source;port->destination=destination;port->llid=llid;
 mutex_lock(&fe->lock);
 if(fe->shutting_down){mutex_unlock(&fe->lock);kfree(port);return -ENODEV;}
 list_add_tail(&port->list,&fe->ports);
 netdev->hw_features|=NETIF_F_HW_TC;
 netdev->features|=NETIF_F_HW_TC;
 fe_switch_reconcile_locked(fe);
 mutex_unlock(&fe->lock);
 return 0;
}
bool rtl_fe_enabled(struct rtl_fe *fe)
{
 return fe && !READ_ONCE(fe->shutting_down) && READ_ONCE(fe->engine_ready) && READ_ONCE(fe->enabled);
}

/* A stable physical switch ID shared by all of its LAN netdevs. Use the
 * MMIO resource address, not a kernel pointer or a possibly duplicate MAC. */
int rtl_fe_get_port_parent_id(struct rtl_fe *fe, struct netdev_phys_item_id *ppid)
{
 struct resource *resource;

 if(!fe || READ_ONCE(fe->shutting_down))return -EOPNOTSUPP;
 resource=platform_get_resource(to_platform_device(fe->device),IORESOURCE_MEM,0);
 if(!resource)return -ENODEV;
 ppid->id_len=sizeof(u64);
 put_unaligned_be64(resource->start,ppid->id);
 return 0;
}

/* This is a request to the policy compiler, not a raw bypass-register knob.
 * Success does not claim native L2 is active: status reports the admission
 * result and any unsupported policy or hardware precondition separately. */
int rtl_fe_switch_set(struct rtl_fe *fe, bool requested)
{
 int ret;

 if(!fe)return -EOPNOTSUPP;
 mutex_lock(&fe->lock);
 ret=fe->shutting_down?-ENODEV:fe_switch_request_locked(fe,requested);
 mutex_unlock(&fe->lock);
 return ret;
}

bool rtl_fe_switch_get(struct rtl_fe *fe)
{
 bool requested;

 if(!fe)return false;
 mutex_lock(&fe->lock);
 requested=!fe->shutting_down && fe_switch_requested(fe);
 mutex_unlock(&fe->lock);
 return requested;
}

void rtl_fe_remove_port(struct rtl_fe *fe,struct net_device *netdev)
{
 struct rtl_fe_port *port;
 struct rtl_fe_flow *flow,*next;

 if(!fe)return;
 mutex_lock(&fe->lock);
 if(!fe->shutting_down) {
  int ret=fe_switch_quiesce_locked(fe);
  if(ret)fe->error=ret;
 }
 port=fe_port(fe,netdev);
 if(port) {
  port->retired=true;
  if(!fe->shutting_down)list_for_each_entry_safe(flow,next,&fe->flows,list)
   if(flow->input==port || flow->output==port) {
    int ret=fe_delete(fe,flow);
    if(ret)fe->error=ret;
   }
  fe_collect_ports(fe);
 }
 fe_switch_reconcile_locked(fe);
 mutex_unlock(&fe->lock);
}
int rtl_fe_flush_port(struct rtl_fe *fe,struct net_device *netdev)
{
 struct rtl_fe_port *port;
 struct rtl_fe_flow *flow,*next;
 int ret=0;

 if(!fe)return 0;
 mutex_lock(&fe->lock);
 if(fe->shutting_down){mutex_unlock(&fe->lock);return -ENODEV;}
 ret=fe_switch_quiesce_locked(fe);
 if(ret){fe->error=ret;mutex_unlock(&fe->lock);return ret;}
 port=fe_port(fe,netdev);
 list_for_each_entry_safe(flow,next,&fe->flows,list)
  if(flow->input==port || flow->output==port) {
   ret=fe_delete(fe,flow);
   if(ret){fe->error=ret;break;}
  }
 fe_switch_reconcile_locked(fe);
 mutex_unlock(&fe->lock);
 return ret;
}
int rtl_fe_set_itu_paths(struct rtl_fe *fe,struct net_device *netdev,const struct rtl_itu_paths *paths)
{
 struct rtl_itu_paths *copy=paths?kvmalloc(rtl_itu_paths_bytes(paths),GFP_KERNEL):NULL;
 struct rtl_fe_flow *flow,*next;
 struct rtl_fe_port *port;
 int ret=0;

 if(paths && !copy)return -ENOMEM;
 if(copy)memcpy(copy,paths,rtl_itu_paths_bytes(paths));
 mutex_lock(&fe->lock);
 if(fe->shutting_down){ret=-ENODEV;goto unlock;}
 port=fe_port(fe,netdev);
 list_for_each_entry_safe(flow,next,&fe->flows,list)
  if(flow->input==port || flow->output==port) {
   ret=fe_delete(fe,flow);
   if(ret)goto unlock;
  }
 kvfree(fe->itu_paths);
 fe->itu_paths=copy;copy=NULL;
 fe->itu_netdev=paths?netdev:NULL;
unlock:
 mutex_unlock(&fe->lock);
 kvfree(copy);
 return ret;
}
static void fe_lan_restore_locked(struct rtl_fe *fe)
{
 unsigned int i;

 if(!fe->lan_redirected)return;
 /* A saved RX selector is never authority to reopen native L2 or L3 after
  * a policy gate. Only the generation-checked switch guard may do that. */
 for(i=0;i<FE_LAN_PORTS;i++)
  fe_write(fe,FE_LAN_RX_CTRL(i),
   (fe->lan_saved[i]&~(63U<<16))|BIT(28)|(16U<<16));
 fe->lan_redirected=false;
}

static bool fe_base_match(struct rtl_fe *fe,unsigned int reg,
                          unsigned int mask,unsigned int expected)
{
 unsigned int value=fe_read(fe,reg);

 if((value&mask)==(expected&mask))return true;
 fe->base_rejected_register=reg;
 fe->base_rejected_value=value;
 return false;
}

/* Warm NI reopen does not reset or repopulate the shared QM any more.
 * Verify the retained connector contract instead of writing a fresh base
 * over potentially in-flight packets. Only defined bits are compared in
 * shared/register words (RTL8277C generated register definitions and the
 * SDK's LPB/CLS layouts). This is a configuration check,
 * NOT a complete L3/AXI drain or per-flow retirement proof. */
static int fe_base_check_locked(struct rtl_fe *fe)
{
 struct rtl_dq_io io=fe_io(fe);
 static const unsigned int high[]={0x3838,0x3840,0x384c,0x3858};
 static const unsigned int low[]={0x383c,0x3844,0x3850,0x385c};
 static const unsigned int offset[]={0,RTL_FE_ACTION_OFFSET,
  RTL_FE_OVERFLOW_OFFSET,RTL_FE_DEFAULT_OFFSET};
 unsigned int expected[7],actual[7],lpb[3],i,side,type,row,word;
 unsigned int address_high=(upper_32_bits(fe->dma)&255)|2;
 int ret;

 if(!fe->prepared || !fe->base_ready || fe->base_failed ||
    !fe->route_gate_ready)return -EIO;
 fe->base_rejected_register=0;
 fe->base_rejected_value=0;
 ret=rtl_fe_pp_exceptions_check(&io,&fe->pp_rejected_register,
                               &fe->pp_rejected_value);
 if(ret)return ret;
 /* Both connectors must already select the keep-original CPU profile. */
 for(i=0;i<2;i++) {
  rtl_fe_ingress_lpb(lpb,i?7:0,16);
  rtl_fe_bits_set(lpb,42,4,1);
  for(word=0;word<3;word++)
   if(!fe_base_match(fe,0x3414+i*12+word*4,word==2?0x3fffffffU:~0U,lpb[word]))return -EIO;
 }
 for(i=0;i<ARRAY_SIZE(high);i++)
  if(!fe_base_match(fe,high[i],255,address_high) ||
     !fe_base_match(fe,low[i],~127U,lower_32_bits(fe->dma)+offset[i]))return -EIO;
 if(!fe_base_match(fe,0x3848,7,4) || !fe_base_match(fe,0x3854,7,1) ||
    !fe_base_match(fe,0x38c4,0xfc000000U,0xa0000000U) ||
    !fe_base_match(fe,0x2300,BIT(12)|BIT(13),BIT(12)|BIT(13)) ||
    !fe_base_match(fe,0x2394,0x00ff00ffU,0x000600ffU) ||
    !fe_base_match(fe,0x23a0,0x00ff00ffU,0x000600ffU) ||
    !fe_base_match(fe,0xa1e0,0x3ff,0x3ff) ||
    !fe_base_match(fe,0x3400,BIT(0)|BIT(2)|BIT(3)|BIT(10)|BIT(19),
                   BIT(2)|BIT(3)|BIT(19)) ||
    !fe_base_match(fe,0x3404,0x03ffffffU,7U|(25U<<8)|(1U<<14)|(24U<<16)|(2U<<22)|(3U<<24)) ||
    !fe_base_match(fe,0x30a4,BIT(31),BIT(31)) ||
    !fe_base_match(fe,0x351c,BIT(31)|BIT(12)|BIT(10)|(63U<<4)|
                   (63U<<16)|(7U<<24),BIT(31)|BIT(12)|BIT(10)|(32U<<4)|(16U<<16)))
  return -EIO;
 ret=rtl_fe_classifier_keys_empty(&io);
 if(ret)return ret;
 for(i=0;i<2;i++) {
  for(side=0;side<4;side++) {
   ret=fe_access(fe,0x1654,BIT(31)|(24+i)|(side<<6));
   if(ret)return ret;
   if(!fe_base_match(fe,0x1658,15,i?13:12))return -EIO;
  }
  for(type=0;type<4;type++)for(row=0;row<2;row++) {
   memset(expected,0,sizeof(expected));
   if(!row) {
    if(i)rtl_fe_classify_cpu_original(expected);
    else {rtl_fe_classify_hash(expected,0,0);rtl_fe_bits_set(expected,208,1,0);}
   }
   ret=rtl_fe_classifier_read(&io,fe_classifier_default_index(i,type,row),actual);
   if(ret)return ret;
   for(word=0;word<ARRAY_SIZE(expected);word++) {
    unsigned int mask=fe_cls_mode0_mask[row][word];

    if((actual[word]&mask)!=(expected[word]&mask)) {
     fe->base_rejected_register=0x33cc-word*4;
     fe->base_rejected_value=actual[word];
     return -EIO;
    }
   }
  }
 }
 return 0;
}

static void fe_base_quarantine_locked(struct rtl_fe *fe)
{
 /* Do not restore, recycle, or retry a half-programmed base. Existing
  * async users already reject shutting_down; final free unregisters them
  * before NI's devm mappings disappear. Unbind/release remain software-only. */
 fe->base_failed=true;
 fe->engine_ready=false;
 fe->shutting_down=true;
 fe->enabled=false;
 fe->cpu_path=false;
 fe_route_gate(fe);
 fe_lan_restore_locked(fe);
}

static int fe_base_require_locked(struct rtl_fe *fe)
{
 int ret;

 if(fe->base_failed)return -EIO;
 if(fe->fabric.poisoned)return -EIO;
 if(fe->fabric.ready) {
  struct rtl_dq_io io=fe_io(fe);
  ret=rtl_fabric_check(&io,&fe->fabric);
  if(ret) {
   fe_base_quarantine_locked(fe);
   return ret;
  }
 }
 if(!fe->prepared) {
  ret=fe_prepare(fe);
  if(ret) {
   /* Read-only preflight/snapshot failures acquired no base or DMA owner. */
   if(fe->prepared || fe->dma_exposed)fe_base_quarantine_locked(fe);
   return ret;
  }
 }
 ret=fe_base_check_locked(fe);
 if(ret)fe_base_quarantine_locked(fe);
 return ret;
}

static int fe_disable_locked(struct rtl_fe *fe)
{
 struct rtl_fe_flow *flow,*next;
 int ret;

 /* Publish no-admission even if a later L2/table withdrawal must retry. */
 fe->enabled=false;
 fe->cpu_path=false;
 fe_route_gate(fe);
 ret=fe_switch_quiesce_locked(fe);
 if(ret)return ret;
 fe_lan_restore_locked(fe);
 if(fe->base_failed)return -EIO;
 if(fe->prepared) {
  if(!fe->base_ready || !fe->route_gate_ready ||
     !fe_base_match(fe,0x3418,15U<<10,1U<<10) ||
     !fe_base_match(fe,0x3424,15U<<10,1U<<10)) {
   fe_base_quarantine_locked(fe);
   return -EIO;
  }
  list_for_each_entry_safe(flow,next,&fe->flows,list) {
   ret=fe_delete(fe,flow);
   if(ret)return ret;
  }
  /* Retire the SDK's individual route owners, not the permanent base.
   * The original-packet CPU profile must remain valid while any PDC entry
   * or previously accepted packet can still name an L3 connector. */
  if(!fe->dma_exposed)ret=fe_restore(fe);
 }
 fe_collect_ports(fe);
 return ret;
}
static int fe_enable_locked(struct rtl_fe *fe)
{
 unsigned int i;
 int ret;

 if(fe->enabled)return 0;
 ret=fe_disable_locked(fe);
 if(ret)return ret;
 ret=fe_base_require_locked(fe);
 if(ret)return ret;
 /* The DMA tables, miss actions and port maps exist before admitting LAN. */
 /* A CPU-only trap does not own LAN admission. Snapshot the current NI
  * baseline only when admitting LAN, including after an engine restart. */
 for(i=0;i<FE_LAN_PORTS;i++)fe->lan_saved[i]=fe_read(fe,FE_LAN_RX_CTRL(i));
 fe->lan_redirected=true;
 /* Reconcile queues the single fabric owner. It admits route25/native L2
  * under the policy gate lock, never racing a newly published firewall or
  * bridge change with an unconditional RX selector write from this path. */
 fe->enabled=true;
 fe->cpu_path=false;
 return 0;
}
/* ITU CPU delivery still traverses the packet editor. A raw PDC bypass
 * does not apply the keep_orig_pkt miss action and can rebuild LCP as
 * PPP IPv4. Keep the classifier/miss tables, but admit no hardware flows. */
static int fe_cpu_path_locked(struct rtl_fe *fe)
{
 int ret;

 if(fe->cpu_path)return 0;
 ret=fe_disable_locked(fe);
 if(ret)return ret;
 ret=fe_base_require_locked(fe);
 if(ret)return ret;
 fe->cpu_path=true;
 return 0;
}

int rtl_fe_enable(struct rtl_fe *fe)
{
 int ret;

 if(!fe)return -EOPNOTSUPP;
 mutex_lock(&fe->lock);
 if(fe->shutting_down)ret=-ENODEV;
 else if(!fe->engine_ready)ret=-EAGAIN;
 else {
  ret=fe_enable_locked(fe);
  if(!ret)fe->desired_mode=RTL_FE_MODE_HARDWARE;
 }
 fe->error=ret;
 fe_switch_reconcile_locked(fe);
 mutex_unlock(&fe->lock);
 return ret;
}

int rtl_fe_cpu_path(struct rtl_fe *fe)
{
 int ret;

 if(!fe)return -EOPNOTSUPP;
 mutex_lock(&fe->lock);
 if(fe->shutting_down)ret=-ENODEV;
 else if(!fe->engine_ready)ret=-EAGAIN;
 else {
  ret=fe_cpu_path_locked(fe);
  if(!ret)fe->desired_mode=RTL_FE_MODE_CPU;
 }
 fe->error=ret;
 fe_switch_reconcile_locked(fe);
 mutex_unlock(&fe->lock);
 return ret;
}

int rtl_fe_disable(struct rtl_fe *fe)
{
 int ret;

 if(!fe)return 0;
 mutex_lock(&fe->lock);
 ret=fe->shutting_down?-ENODEV:fe_disable_locked(fe);
 if(!ret)fe->desired_mode=RTL_FE_MODE_OFF;
 fe->error=ret;
 fe_switch_reconcile_locked(fe);
 mutex_unlock(&fe->lock);
 return ret;
}

/* Called under RTNL, outside NI spinlocks. Never acquire a PON lock here:
 * an OMCI ndo_stop can already hold pon->lock while releasing its NI user.
 * Stopping the host user is not PON withdrawal. Keep the original-packet
 * CPU profile and every exposed base allocation for the device lifetime. */
int rtl_fe_engine_suspend(struct rtl_fe *fe)
{
 int ret;

 if(!fe)return 0;
 mutex_lock(&fe->lock);
 fe->engine_ready=false;
 ret=fe->shutting_down?-ENODEV:fe_disable_locked(fe);
 fe->error=ret;
 mutex_unlock(&fe->lock);
 return ret;
}

/* NI/QM/DMA reuse their established queues on a warm open. No fresh base
 * snapshot, MEM_INI or DMA pointer publication is permitted here. Validate
 * the retained CPU connectors before reporting a successful NI open; only
 * the generation-checked fabric owner can admit the requested route mode. */
int rtl_fe_engine_resume(struct rtl_fe *fe)
{
 int ret=0;

 if(!fe)return 0;
 mutex_lock(&fe->lock);
 if(fe->shutting_down){ret=-ENODEV;goto unlock;}
 if(!list_empty(&fe->flows)){ret=-EBUSY;goto unlock;}
 if(fe->prepared) {
  ret=fe_base_require_locked(fe);
  if(ret)goto unlock;
 }
 if(fe->desired_mode==RTL_FE_MODE_HARDWARE)ret=fe_enable_locked(fe);
 else if(fe->desired_mode==RTL_FE_MODE_CPU)ret=fe_cpu_path_locked(fe);
 if(ret) {
  /* A failed mode transition never discards the permanent base owner. */
  fe_route_gate(fe);
  fe->enabled=false;
  fe->cpu_path=false;
 } else fe->engine_ready=true;
unlock:
 if(ret)fe->engine_ready=false;
 fe->error=ret;
 fe_switch_reconcile_locked(fe);
 mutex_unlock(&fe->lock);
 return ret;
}

bool rtl_fe_free(struct rtl_fe *fe)
{
 struct rtl_fe_port *port,*next;
 struct rtl_fe_flow *flow,*flow_next;
 bool bound=false;
 int ret, switch_ret;

 if(!fe)return true;
 mutex_lock(&fe->lock);
 fe->shutting_down=true;
 fe->engine_ready=false;
 fe->desired_mode=RTL_FE_MODE_OFF;
 mutex_unlock(&fe->lock);
 switch_ret=fe_bridge_stop(fe->bridge);
 if(!switch_ret)fe->bridge=NULL;
 debugfs_remove_recursive(fe->debug);
 cancel_delayed_work_sync(&fe->cleanup_work);
 mutex_lock(&fe->lock);
 ret=fe_disable_locked(fe);
 if(!ret)ret=switch_ret;
 list_for_each_entry(port,&fe->ports,list)if(port->bindings)bound=true;
 /* This check precedes ALL ownership handoff, including the shared FDB
  * command-mode lease. An exposed/partial base may still be referenced by
  * a PON packet; do not restore a boot owner just because software is idle. */
 if(!ret && (fe->dma_exposed || fe->prepared || fe->base_failed || fe->fabric.poisoned))ret=-EBUSY;
 if(!ret && !bound && list_empty(&fe->blocks) && list_empty(&fe->flows)) {
  struct rtl_dq_io io=fe_io(fe);
  ret=rtl_fe_window_idle(&io,0x1ca0);
  if(!ret)ret=rtl_fe_window_idle(&io,0x1cb4);
  if(!ret) {
   fe_write(fe,0x1c00,(fe_read(fe,0x1c00)&~BIT(31))|fe->fdb_cmd_mode_saved);
   fe_read(fe,0x1c00);
  }
 }
 fe->error=ret;
 /* Failure can leave Hash/Cache DMA using this memory. A removed callback
  * can also still own its private port until its release runs. Without a
  * proven hardware drain and zero callback references, leaking a quarantined
  * owner until reboot is safer than DMA/use-after-free. No work or callbacks
  * may perform MMIO once shutting_down is set. */
 if(ret || bound || !list_empty(&fe->blocks) || !list_empty(&fe->flows)) {
  mutex_unlock(&fe->lock);
  dev_err(fe->device,"FE teardown quarantined: error=%d callbacks=%u; DMA memory retained, reboot required\n",ret,bound);
  return false;
 }
 mutex_unlock(&fe->lock);
 list_for_each_entry_safe(flow,flow_next,&fe->flows,list){list_del(&flow->list);kfree(flow);}
 list_for_each_entry_safe(port,next,&fe->ports,list){list_del(&port->list);kfree(port);}
 dma_free_coherent(fe->device,RTL_FE_MEMORY_BYTES,fe->memory,fe->dma);
 kvfree(fe->itu_paths);
 kfree(fe);
 return true;
}
ssize_t rtl_fe_l2_evidence(struct rtl_fe *fe, char *buffer)
{
 static const char * const names[] = {
#define RTL_L2_EVIDENCE_NAME(name, offset, label) label,
  RTL_L2_EVIDENCE_REGISTERS(RTL_L2_EVIDENCE_NAME)
#undef RTL_L2_EVIDENCE_NAME
 };
 struct rtl_l2_evidence sample;
 struct rtl_dq_io io;
 unsigned long flags;
 unsigned int i;
 ssize_t length;
 u64 begin, end;

 if(!fe)return sysfs_emit(buffer,"schema=1 available=0 reason=no_fe\n");
 /* A diagnostic must not wait behind a slow FDB/FE transaction. Sysfs
  * removal drains readers before the NI devm register mapping is removed. */
 if(!mutex_trylock(&fe->lock))return -EBUSY;
 if(!fe->engine_ready || fe->shutting_down) {
  mutex_unlock(&fe->lock);
  return sysfs_emit(buffer,"schema=1 available=0 reason=engine_down\n");
 }
 io=(struct rtl_dq_io){ .context=fe, .read=fe_read };
 begin=ktime_get_ns();
 /* Same lock order as the configuration owner; only 17 direct reads,
  * no loops waiting for hardware and no selector/table command writes. */
 spin_lock_irqsave(&fe->route_lock,flags);
 rtl_l2_evidence_read(&io,&sample);
 spin_unlock_irqrestore(&fe->route_lock,flags);
 end=ktime_get_ns();
 mutex_unlock(&fe->lock);
 length=sysfs_emit(buffer,"schema=1 available=1 clock=monotonic begin_ns=%llu end_ns=%llu "
  "mmio_writes=0 atomic_snapshot=0 forwarding_proven=0 retirement_proven=0\n",
  begin,end);
 for(i=0;i<RTL_L2_EVIDENCE_REG_COUNT;i++)
  length+=scnprintf(buffer+length,PAGE_SIZE-length,"%s=0x%08x\n",
                    names[i],sample.words[i]);
 length+=scnprintf(buffer+length,PAGE_SIZE-length,
  "mce_copy_lspid_to_pol=%u mce_flush_requested=%u "
  "arb_keep_original_lspid=%u arb_mc_membership_check=%u\n",
  sample.mce_copy_lspid_to_pol,sample.mce_flush_requested,
  sample.arb_keep_original_lspid,sample.arb_mc_membership_check);
 /* Report baseline incompatibility even without two live bridge ports.
  * These two decoded checks are not an aggregate eligibility verdict. */
 length+=scnprintf(buffer+length,PAGE_SIZE-length,
  "native_l2_svl_compatible=%u native_l2_priority_key_compatible=%u "
  "native_l2_prerequisites_complete=0\n",
  sample.native_l2_svl_compatible,sample.native_l2_priority_key_compatible);
 for(i=0;i<RTL_L2_EVIDENCE_LAN_PORTS;i++)
  length+=scnprintf(buffer+length,PAGE_SIZE-length,
   "hw_port=%u rx_control=0x%08x bypass=%u bypass_destination=%u\n",
   i,sample.lan_rx[i],(sample.lan_rx[i]>>28)&1U,
   (sample.lan_rx[i]>>16)&63U);
 return length;
}

ssize_t rtl_fe_state(struct rtl_fe *fe,char *buffer)
{
 ssize_t length;
 struct rtl_fe_flow *flow;
 unsigned int flows=0,counted=0,bridged=0,learned=0;
 unsigned int lan_cpu=0,lan_route=0,lan_l2=0,i;

 if(!fe)return sysfs_emit(buffer,"available=0\n");
 mutex_lock(&fe->lock);
 list_for_each_entry(flow,&fe->flows,list)if(flow->published) {
  flows++;
  counted+=flow->counted;
  bridged+=flow->bridge;learned+=flow->learned;
 }
 if(fe->engine_ready && !fe->shutting_down)for(i=0;i<FE_LAN_PORTS;i++) {
  unsigned int control=fe_read(fe,FE_LAN_RX_CTRL(i));
  if(!(control&BIT(28)))lan_l2|=BIT(i);
  else if(((control>>16)&63)==16)lan_cpu|=BIT(i);
  else if(((control>>16)&63)==25)lan_route|=BIT(i);
 }
 length=sysfs_emit(buffer,"available=1 enabled=%u prepared=%u error=%d flows=%u hash_entries=%u counter_slots=%u counted_flows=%u activity_flows=%u installs=%llu deletes=%llu rejected=%llu bridge_rules=%u learned_bridge_rules=%u cpu_path=%u\n",
  fe->enabled,fe->prepared,fe->error,flows,RTL_FE_HASH_ENTRIES,
  FE_COUNTERS,counted,flows-counted,fe->installs,fe->deletes,fe->misses,bridged,learned,fe->cpu_path);
 length+=scnprintf(buffer+length,PAGE_SIZE-length,
  "engine_ready=%u requested_mode=%u shutting_down=%u\n",
  fe->engine_ready,fe->desired_mode,fe->shutting_down);
 length+=scnprintf(buffer+length,PAGE_SIZE-length,
  "route_gate_ready=%u route_admitted=%u dma_exposed=%u\n",
  READ_ONCE(fe->route_gate_ready),READ_ONCE(fe->route_admitted),fe->dma_exposed);
 length+=scnprintf(buffer+length,PAGE_SIZE-length,
  "base_ready=%u base_failed=%u base_lifetime_owner=%u full_l3_drain_verified=0 "
  "base_rejected_register=0x%x base_rejected_value=0x%x\n",
  fe->base_ready,fe->base_failed,fe->dma_exposed,
  fe->base_rejected_register,fe->base_rejected_value);
 length+=scnprintf(buffer+length,PAGE_SIZE-length,
  "pp_rejected_register=0x%x pp_rejected_value=0x%x\n",
  fe->pp_rejected_register,fe->pp_rejected_value);
 length+=scnprintf(buffer+length,PAGE_SIZE-length,
  "fabric_ready=%u fabric_poisoned=%u fabric_changed=%u fabric_refusal=%u fabric_error=%d "
  "fabric_vlan_mode=0x%x fabric_uni_frame=0x%x fabric_storage=0x%x fabric_native_mtu_compatible=%u "
  "fabric_rejected_register=0x%x fabric_rejected_value=0x%x\n",
  fe->fabric.ready,fe->fabric.poisoned,fe->fabric.changed,fe->fabric.refusal,fe->fabric.error,
  fe->fabric.vlan_mode,fe->fabric.packet_length,fe->fabric.storage_length,
  rtl_fabric_native_mtu_compatible(&fe->fabric),
  fe->fabric.rejected_register,fe->fabric.rejected_value);
 length+=scnprintf(buffer+length,PAGE_SIZE-length,
  "fdb_pin_vid=%u fdb_pin_sc=%u fdb_pin_port=%u\n",
  RTL_FE_FDB_PIN_VID,RTL_FE_FDB_PIN_SCIND,RTL_FE_FDB_PIN_PORT);
 length+=scnprintf(buffer+length,PAGE_SIZE-length,
  "lan_admission_valid=%u lan_cpu_mask=%u lan_route_mask=%u lan_native_l2_mask=%u\n",
  fe->engine_ready && !fe->shutting_down,lan_cpu,lan_route,lan_l2);
 length+=scnprintf(buffer+length,PAGE_SIZE-length,
  "admission_requests=%llu parse_rejected=%llu install_failed=%llu reject_unspecified=%llu reject_keys=%llu reject_meta=%llu reject_control=%llu reject_protocol=%llu reject_vlan=%llu reject_action=%llu reject_nat=%llu reject_port=%llu reject_pon=%llu\n",
  fe->observe.replace_requests,fe->observe.parse_rejected,fe->observe.install_failed,
  fe->observe.reason[FE_REJECT_UNSPECIFIED],fe->observe.reason[FE_REJECT_KEYS],
  fe->observe.reason[FE_REJECT_META],fe->observe.reason[FE_REJECT_CONTROL],
  fe->observe.reason[FE_REJECT_PROTOCOL],fe->observe.reason[FE_REJECT_VLAN],
  fe->observe.reason[FE_REJECT_ACTION],fe->observe.reason[FE_REJECT_NAT],
  fe->observe.reason[FE_REJECT_PORT],fe->observe.reason[FE_REJECT_PON]);
 length+=scnprintf(buffer+length,PAGE_SIZE-length,
  "install_unavailable=%llu install_duplicate=%llu install_collision=%llu install_no_space=%llu install_no_memory=%llu install_io=%llu install_other=%llu\n",
  fe->observe.install_unavailable,fe->observe.install_duplicate,fe->observe.install_collision,
  fe->observe.install_no_space,fe->observe.install_no_memory,fe->observe.install_io,
  fe->observe.install_other);
 mutex_unlock(&fe->lock);
 length+=fe_bridge_stats(fe->bridge,buffer+length,PAGE_SIZE-length);
 return length;
}

#include "rtl9617c-fe-switch.h"
