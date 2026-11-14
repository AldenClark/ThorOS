#!/usr/bin/env python3
"""Exercise the production QM/switch hook with raw, independent HeaderA bytes.

The pinned 77C SDK defines original LSPID in HeaderA[46:41], CPU-header
presence in bit 31 of its first host-order word, and type in bits 31:30 of
its second word. None of those fields is an already-forwarded indication.
This checks transport/integration, not ASIC forwarding or learning policy.
"""
import ast
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
drivers = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
source = (drivers / 'rtl9617c-qm.c').read_text()
xram = (drivers / 'rtl9617c-xram.c').read_text()
tree = ast.parse((root / 'scripts/fixtures/qm_cached_epp_model.py').read_text())
common = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == 'common' for t in n.targets))


def body(text, name):
    start = text.index(name + '(')
    start = text.rfind('\n', 0, start) + 1
    end = text.index('{', start) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


common = common.replace('struct sk_buff {', 'struct sk_buff {bool offload_fwd_mark;')
start, end = common.index('static u32 readl('), common.index('static bool rtl_rx_checksum_valid(')
common = common[:start] + r'''
static unsigned hardware_write,retired,pushed,hook_calls,lan_calls,pon_calls;
static unsigned wanted_source;
static u32 wanted_h0,wanted_h1;
static struct net_device *wanted_input;
static struct rtl_fe *wanted_fe;
static u32 readl(void *reg) {
 unsigned off=(u8 *)reg-(u8 *)active->ni;
 if(off==0x3218)return 0;
 assert(off>=EPP_WRITE && off<EPP_WRITE+32 && !(off&3));
 return off==EPP_WRITE?hardware_write:0;
}
static void writel(u32 value,void *reg) {
 assert((u8 *)reg-(u8 *)active->ni==EPP_READ && value==8);retired++;
}
static void dma_sync_single_for_cpu(void *dev,dma_addr_t addr,unsigned bytes,int dir) {
 (void)addr;assert(dev==active->device && (bytes==64 || bytes==2048) && dir==DMA_FROM_DEVICE);
}
static int rtl_qm_try_push(void *ctx,unsigned addr,unsigned eq) {
 assert(ctx==active && retired && addr==active->memory_dma+8192 && eq==4);pushed++;return 0;
}
''' + common[end:]
common = common.replace(body(common, 'rtl_fe_switch_rx'), r'''
static void rtl_fe_switch_rx(struct rtl_fe *fe,struct sk_buff *skb,unsigned source,u32 h0,u32 h1) {
 assert(fe==wanted_fe && source==wanted_source && source<5);
 assert(h0==wanted_h0 && h1==wanted_h1 && retired && pushed==0);
 assert(skb->len==64 && skb->data==skb->storage && !skb->protocol);
 assert(!skb->offload_fwd_mark);hook_calls++;
}
''')
common = common.replace(body(common, 'eth_type_trans'), r'''
static unsigned eth_type_trans(struct sk_buff *skb,struct net_device *dev) {
 assert(hook_calls==1 && dev==wanted_input);skb->dev=dev;
 skb->data+=14;skb->len-=14;return ETH_P_IP;
}
''')
common = common.replace(body(common, 'napi_gro_receive'), r'''
static void napi_gro_receive(struct napi_struct *napi,struct sk_buff *skb) {
 (void)napi;u8 expected[64];packet_bytes(23,expected);
 assert(skb->dev==wanted_input && skb->len==50 && !memcmp(skb->data,expected+14,50));
 assert(!skb->offload_fwd_mark && hook_calls==1);lan_calls++;free(skb);
}
''')
common = common.replace(body(common, 'pon_receive'), r'''
static void pon_receive(struct rtl9617c_ni_endpoint *ep,struct napi_struct *napi,
                       struct sk_buff *skb,unsigned metadata) {
 (void)ep;(void)napi;u8 expected[64];packet_bytes(23,expected);
 assert(!hook_calls && metadata==(wanted_source|(5U<<8)));
 assert(skb->len==64 && !memcmp(skb->data,expected,64));pon_calls++;free(skb);
}
''')
poll = source[source.index('static void rtl_qm_rx_retire('):
              source.index('\nssize_t rtl_qm_rx_voq_state(')]
test = common + poll + r'''
static void setup(struct rtl_qm_rx *rx,struct net_device *owner,struct net_device ports[5],
                  struct rtl_fe *fe,unsigned source,unsigned cpu,unsigned type,
                  unsigned packet_type,unsigned mirror) {
 *rx=(struct rtl_qm_rx){.memory_dma=0x4000000,.ring_dma=0x6000000,.device=owner,.fe=fe};
 rx->memory=calloc(1,RTL_QM_MEMORY_BYTES);rx->ring_memory=calloc(1,8192);rx->ni=calloc(1,65536);
 memset(owner,0,sizeof(*owner));memset(ports,0,5*sizeof(*ports));
 for(unsigned i=0;i<5;i++){ports[i].running=true;rx->lan[i]=&ports[i];}
 active=rx;wanted_source=source;wanted_input=source<5?&ports[source]:0;wanted_fe=fe;
 wanted_h0=(cpu<<31)|(5U<<18)|(mirror<<14)|(packet_type<<11);
 wanted_h1=(type<<30)|((64+cpu*8)<<15)|(source<<9)|(16<<3)|7;
 unsigned off=8192,header=8+cpu*8;
 put(__builtin_bswap32(wanted_h0),rx->memory+off+RTL_QM_HEADROOM);
 put(__builtin_bswap32(wanted_h1),rx->memory+off+RTL_QM_HEADROOM+4);
 packet_bytes(23,rx->memory+off+RTL_QM_HEADROOM+header);
 put((rx->memory_dma+off)|0x54,rx->ring_memory);put(0,rx->ring_memory+4);
 hardware_write=8;retired=pushed=hook_calls=lan_calls=pon_calls=0;
}
static void cleanup(struct rtl_qm_rx *rx) {free(rx->memory);free(rx->ring_memory);free(rx->ni);}
int main(void) {
 struct rtl_qm_rx rx;struct net_device owner,ports[5];struct rtl_fe fe={0};
 struct napi_struct napi={.dev=&owner};unsigned cases=0;
 for(unsigned p=0;p<5;p++)for(unsigned cpu=0;cpu<2;cpu++)
  for(unsigned type=0;type<4;type++)for(unsigned packet=0;packet<4;packet++)
   for(unsigned mirror=0;mirror<2;mirror++) {
    setup(&rx,&owner,ports,&fe,p,cpu,type,packet,mirror);
    assert(rtl_qm_rx_poll(&rx,&napi,64)==1);
    assert(hook_calls==1 && lan_calls==1 && !pon_calls && retired==1 && pushed==1);
    assert(ports[p].stats.rx_packets==1 && ports[p].stats.rx_bytes==64);
    cleanup(&rx);cases++;
   }
 /* Unregistered/down LAN ports must not enter the switch learning callback. */
 for(unsigned p=0;p<5;p++)for(unsigned missing=0;missing<2;missing++) {
  setup(&rx,&owner,ports,&fe,p,1,2,3,1);
  if(missing)rx.lan[p]=0;else ports[p].running=false;
  assert(rtl_qm_rx_poll(&rx,&napi,64)==1 && !hook_calls && !lan_calls);
  assert(owner.stats.rx_dropped==1 && retired==1 && pushed==1);
  cleanup(&rx);cases++;
 }
 const unsigned other_sources[]={5,6,7,31,32,63};
 struct rtl9617c_ni_endpoint endpoint={.receive=pon_receive};
 for(unsigned i=0;i<ARRAY_SIZE(other_sources);i++) {
  unsigned p=other_sources[i];setup(&rx,&owner,ports,&fe,p,1,2,3,1);rx.pon=&endpoint;
  assert(rtl_qm_rx_poll(&rx,&napi,64)==1 && !hook_calls && !lan_calls);
  assert(pon_calls==(p==7 || p>=32));
  assert(owner.stats.rx_dropped==(p!=7 && p<32));
  cleanup(&rx);cases++;
 }
 /* FE-less native mode still passes valid bytes/metadata to its no-op API. */
 setup(&rx,&owner,ports,0,4,0,0,0,0);
 assert(rtl_qm_rx_poll(&rx,&napi,64)==1 && hook_calls==1 && lan_calls==1);
 cleanup(&rx);cases++;
 printf("QM switch integration: %u production-poll HeaderA/source/lifetime cases passed; no inferred forward mark\n",cases);
}
'''

parent_test = r'''
#include <assert.h>
#include <errno.h>
#include <string.h>
struct netdev_phys_item_id {unsigned char id[32],id_len;};
struct rtl_fe {struct netdev_phys_item_id parent;};
struct rtl_xram {struct rtl_fe *fe;};
struct net_device {struct rtl_xram *shared;};
static struct rtl_xram *rtl_shared(struct net_device *dev) {return dev->shared;}
static int rtl_fe_get_port_parent_id(struct rtl_fe *fe,struct netdev_phys_item_id *id) {
 if(!fe)return -EOPNOTSUPP;*id=fe->parent;return 0;
}
''' + body(xram, 'rtl_get_port_parent_id') + r'''
int main(void) {
 struct rtl_fe chip1={.parent={{1,2,3,4},4}},chip2={.parent={{1,2,3,5},4}};
 struct rtl_xram shared1={&chip1},shared2={&chip2},legacy={0};
 struct net_device ports[5],other={&shared2},unsupported={&legacy};
 struct netdev_phys_item_id id1,id2;
 for(unsigned i=0;i<5;i++) {
  ports[i].shared=&shared1;assert(!rtl_get_port_parent_id(&ports[i],&id1));
  assert(id1.id_len==4 && !memcmp(id1.id,chip1.parent.id,4));
 }
 assert(!rtl_get_port_parent_id(&other,&id2) && memcmp(id1.id,id2.id,4));
 assert(rtl_get_port_parent_id(&unsupported,&id2)==-EOPNOTSUPP);
 assert(!memcmp(id2.id,chip2.parent.id,4));
}
'''
assert '.ndo_get_port_parent_id = rtl_get_port_parent_id' in xram
assert 'dev->netns_immutable = true;' in body(xram, 'rtl_register_lan')
assert 'NETIF_F_NETNS_LOCAL' not in xram
assert 'priv->qm.fe = priv->fe;' in body(xram, 'rtl_probe')
assert 'rx_bypass_store(' not in xram
assert 'DEVICE_ATTR_RO(rx_bypass)' in xram
assert '&dev_attr_l2_switch.attr' in xram
assert 'attr == &dev_attr_l2_switch.attr && !priv->fe' in body(xram, 'rtl_native_visible')
sysfs_test = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
struct rtl_fe {bool requested;};
struct rtl_xram {struct rtl_fe *fe;};
struct device {struct rtl_xram *private;};
struct device_attribute {int dummy;};
static unsigned writes;static int failure;
static struct rtl_xram *dev_get_drvdata(struct device *dev){return dev->private;}
static struct rtl_xram *netdev_priv(struct rtl_xram *priv){return priv;}
static int kstrtobool(const char *text,bool *value){
 if(!strcmp(text,"1")){*value=true;return 0;}
 if(!strcmp(text,"0")){*value=false;return 0;}return -EINVAL;
}
static bool rtl_fe_switch_get(struct rtl_fe *fe){return fe&&fe->requested;}
static int rtl_fe_switch_set(struct rtl_fe *fe,bool value){
 if(!fe)return -EOPNOTSUPP;if(failure)return failure;
 writes++;fe->requested=value;return 0;
}
static ssize_t sysfs_emit(char *buf,const char *format,...){
 va_list ap;va_start(ap,format);int ret=vsprintf(buf,format,ap);va_end(ap);return ret;
}
''' + body(xram, 'l2_switch_show') + body(xram, 'l2_switch_store') + r'''
int main(void){
 struct rtl_fe fe={0};struct rtl_xram priv={&fe};struct device dev={&priv};char buf[16];
 assert(l2_switch_show(&dev,0,buf)==2&&!strcmp(buf,"0\n"));
 assert(l2_switch_store(&dev,0,"invalid",7)==-EINVAL&&!writes);
 assert(l2_switch_store(&dev,0,"1",1)==1&&writes==1&&fe.requested);
 assert(l2_switch_show(&dev,0,buf)==2&&!strcmp(buf,"1\n"));
 failure=-EBUSY;assert(l2_switch_store(&dev,0,"0",1)==-EBUSY&&writes==1&&fe.requested);
 failure=0;assert(l2_switch_store(&dev,0,"0",1)==1&&writes==2&&!fe.requested);
 priv.fe=0;assert(l2_switch_store(&dev,0,"1",1)==-EOPNOTSUPP&&writes==2);
 assert(l2_switch_show(&dev,0,buf)==2&&!strcmp(buf,"0\n"));
}
'''
with tempfile.TemporaryDirectory(prefix='qm-switch-') as directory:
    directory = Path(directory)
    for name, contents in (('rx', test), ('parent', parent_test), ('sysfs', sysfs_test)):
        cfile, binary = directory / (name + '.c'), directory / name
        cfile.write_text(contents)
        subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-function', '-Wno-unused-variable', '-Wno-unused-parameter',
                        '-Wno-misleading-indentation',
                        '-fsanitize=address,undefined', '-I', str(drivers), '-I',
                        str(root / 'port/overlay/target/linux/rtl9617c/files-6.18/include/linux'),
                        str(cfile), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
