#!/usr/bin/env python3
"""Check management-frame sizes and XRAM ring wrap against hardware formats."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

HEADER = Path(__file__).resolve().parents[1] / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c-xram-format.h'


def function(source, name):
    match = re.search(r'^static [\w *]+\b' + name + r'\([^;{}]*\)\s*\{', source, re.M)
    assert match, name
    end = source.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


class XramFormat(unittest.TestCase):
    def test_packet_sizes_and_wrap(self):
        code = r'''
#include <assert.h>
#include "rtl9617c-xram-format.h"
int main(void) {
    /* Ethernet minimum, exact FCS length, and tagged MTU. */
    assert(rtl_xram_wire_length(42) == 64);
    assert(rtl_xram_wire_length(60) == 64);
    assert(rtl_xram_wire_length(61) == 65);
    assert(rtl_xram_wire_length(1514) == 1518);
    assert(rtl_xram_wire_length(1518) == 1522);
    assert(rtl_xram_wire_length(1522) == 1526);
    /* One 8-byte XR header plus one 8-byte Header A, then frame+FCS. */
    assert(rtl_xram_tx_next(0x300, 64) == 0x30a);
    assert(rtl_xram_tx_next(0x3fc, 64) == 0x306);
    assert(rtl_xram_tx_next(0x300, 1520) == 0x3c0);
    assert(rtl_xram_tx_next(0x3ff, 1520) == 0x3bf);
    /* On the actual board: bits 11:10 are ignored; bit 12 changes tail length. */
    assert(rtl_xram_tx_header(0x30f, 102) == 0x8000630fU);
    assert(rtl_xram_tx_header(0x3c0, 1518) == 0x800063c0U);
    assert(rtl_xram_tx_header(0x30a, 64) == 0x8000030aU);
    assert(rtl_xram_word_next(0x17fc, 0, 0x1800) == 0);
    assert(rtl_xram_word_next(0x1ffc, 0x1800, 0x2000) == 0x1800);
    for (unsigned pointer = 0x300; pointer < 0x400; pointer++) {
        unsigned next = rtl_xram_tx_next(pointer, 1528);
        assert(next >= 0x300 && next < 0x400);
        assert(((next - pointer) & 0xff) == 193);
    }
}
'''
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'xram-format-test.c'
            binary = Path(temp) / 'xram-format-test'
            source.write_text(code)
            subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=undefined',
                            '-I', str(HEADER.parent), str(source), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True)

    def test_production_rx_bytes_limits_and_wrap(self):
        source = (HEADER.parent / 'rtl9617c-xram.c').read_text()
        poll = function(source, 'rtl_poll')
        tx = function(source, 'rtl_xmit')
        # Execute the actual first admission block; the DMA/ring transmit
        # implementations remain covered by their dedicated suites.
        tx_bound = tx[tx.index('\tif (skb->len < ETH_HLEN'):tx.index('\tspin_lock_irqsave(')]
        qm = (HEADER.parent / 'rtl9617c-qm.c').read_text()
        # Execute the existing validated length/copy block independently of
        # EPP ownership. QM is a different RX path, not subject to rtl_poll's
        # legacy XRAM branch limit. Do not add a new coarse bound to QM.
        qm_copy = qm[qm.index('\t\t\theader = 8 +'):qm.index('\t\t\tif (checksum_enabled &&')]
        common = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "rtl9617c-xram-format.h"
#include "rtl9617c-qm-layout.h"
typedef uint32_t u32;typedef uint32_t __le32;
#define ETH_HLEN 14
#define ETH_FCS_LEN 4
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define FIELD_GET(mask,value) (((value)&(mask))>>__builtin_ctz(mask))
#define READ_ONCE(x) (x)
#define cpu_to_le32(x) (x)
#define min(a,b) ((a)<(b)?(a):(b))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define RX_READ 0xaa2c
#define RX_WRITE 0xaa30
#define POINTER_MASK GENMASK(9,0)
#define XR_OWN BIT(31)
#define PKT_SIZE GENMASK(13,0)
#define PKT_VALID BIT(19)
#define PKT_ERRORS (GENMASK(23,20)|BIT(25)|BIT(26))
#define NETDEV_TX_OK 0
#define L1_CACHE_BYTES 64
struct sk_buff {unsigned len,protocol;unsigned char storage[2048],*data;};
struct net_device {struct {unsigned rx_errors,rx_dropped,rx_packets,rx_bytes,tx_dropped;} stats;};
struct napi_struct {int unused;};
struct rtl_qm_rx {unsigned cpu_packets,cpu_bytes;bool rx_prefetch;unsigned char *memory;};
struct rtl_xram {struct napi_struct napi;struct net_device *netdev;bool qm_rx,rx_active;int rx_lock;struct rtl_qm_rx qm;unsigned char *ni,*xram;};
static unsigned expected_length,delivered,completions;
static unsigned char expected[2048];
static u32 readl(void *reg){u32 value;memcpy(&value,reg,4);return value;}
static void writel(u32 value,void *reg){memcpy(reg,&value,4);}
static unsigned rtl_pointer(struct rtl_xram *priv,unsigned reg){return readl(priv->ni+reg)&POINTER_MASK;}
static int rtl_qm_rx_poll(struct rtl_qm_rx *rx,struct napi_struct *napi,int budget){(void)rx;(void)napi;(void)budget;assert(false);return 0;}
#define spin_lock_irqsave(p,f) ((void)(p),(f)=0)
#define spin_unlock_irqrestore(p,f) ((void)(p),(void)(f))
static void rtl_update(struct rtl_xram *priv,unsigned reg,unsigned mask,unsigned value){(void)priv;(void)reg;(void)mask;(void)value;assert(false);}
static bool napi_complete_done(struct napi_struct *napi,int packets){(void)napi;(void)packets;completions++;return true;}
static struct sk_buff *napi_alloc_skb(struct napi_struct *napi,unsigned size){
 (void)napi;assert(size<=2048);struct sk_buff *skb=calloc(1,sizeof(*skb));assert(skb);skb->data=skb->storage;return skb;
}
static void *skb_put(struct sk_buff *skb,unsigned count){assert(skb->len+count<=2048);void *data=skb->data+skb->len;skb->len+=count;return data;}
static unsigned eth_type_trans(struct sk_buff *skb,struct net_device *dev){
 (void)dev;assert(skb->len==expected_length && !memcmp(skb->data,expected,expected_length));
 skb->data+=ETH_HLEN;skb->len-=ETH_HLEN;return 0x800;
}
static void napi_gro_receive(struct napi_struct *napi,struct sk_buff *skb){
 (void)napi;assert(skb->len==expected_length-ETH_HLEN && !memcmp(skb->data,expected+ETH_HLEN,skb->len));delivered++;free(skb);
}
static void dev_kfree_skb_any(struct sk_buff *skb){(void)skb;}
static void prefetch(void *data){(void)data;}
'''
        unit = common + poll + '\nstatic int transmit_admission(struct sk_buff *skb,struct net_device *dev){\n' + tx_bound + '\nreturn 1;\n}\n'
        unit += r'''
static struct sk_buff *qm_copy(struct rtl_qm_rx *rx,struct net_device *dev,struct napi_struct *napi,
 unsigned h0,unsigned h1,unsigned command,unsigned offset){
 unsigned header,length;struct sk_buff *skb;
''' + qm_copy + r'''
 return skb;
consume:
 return NULL;
}
int main(void){
 unsigned cases=0;
 struct net_device dev={0};struct rtl_xram priv={.netdev=&dev};
 priv.ni=calloc(1,0xab00);priv.xram=calloc(1,RTL_XRAM_RX_END*8);assert(priv.ni&&priv.xram);
 const unsigned frames[]={1518,1522,1526,1527};
 const unsigned starts[]={0,1,0x280,0x2fe,0x2ff};
 for(unsigned f=0;f<4;f++)for(unsigned s=0;s<5;s++){
  unsigned wire=frames[f],rd=starts[s];
  unsigned next=(rd+2+(wire+7)/8)%RTL_XRAM_RX_END;
  memset(priv.xram,0,RTL_XRAM_RX_END*8);memset(&dev,0,sizeof(dev));
  writel(rd,priv.ni+RX_READ);writel(next,priv.ni+RX_WRITE);
  writel(next,priv.xram+rd*8+4);
  unsigned offset=rtl_xram_word_next(rd*8+4,0,RTL_XRAM_RX_END*8);
  writel(PKT_VALID|wire,priv.xram+offset);
  offset=rtl_xram_word_next(offset,0,RTL_XRAM_RX_END*8);
  offset=rtl_xram_word_next(offset,0,RTL_XRAM_RX_END*8);
  expected_length=wire-ETH_FCS_LEN;delivered=completions=0;
  for(unsigned i=0;i<wire;i++)expected[i]=(unsigned char)(i*37+f*13+s);
  for(unsigned i=0;i<wire;i+=4){
   unsigned char word[4]={0};memcpy(word,expected+i,min(4U,wire-i));
   u32 value;memcpy(&value,word,4);writel(value,priv.xram+offset);
   offset=rtl_xram_word_next(offset,0,RTL_XRAM_RX_END*8);
  }
  assert(rtl_poll(&priv.napi,1)==1 && rtl_pointer(&priv,RX_READ)==next);
  if(wire<=1526){assert(delivered==1 && dev.stats.rx_packets==1 && dev.stats.rx_bytes==wire-4 && !dev.stats.rx_errors);}
  else assert(!delivered && dev.stats.rx_errors==1 && !dev.stats.rx_packets);
  assert(!completions);cases++;
 }
 for(unsigned length=1521;length<=1523;length++){
  struct sk_buff skb={.len=length};memset(&dev,0,sizeof(dev));
  assert(transmit_admission(&skb,&dev)==(length<=1522));
  assert(dev.stats.tx_dropped==(length>1522));cases++;
 }
 free(priv.ni);free(priv.xram);
 /* Existing QM buffer geometry accepts a full 1522-byte no-FCS frame,
  * both ordinary HeaderA and the optional eight-byte extra header. */
 struct rtl_qm_rx rx={.memory=calloc(1,2048),.rx_prefetch=true};assert(rx.memory);
 for(unsigned extra=0;extra<2;extra++){
  const unsigned header=8+extra*8,length=1522;
  for(unsigned i=0;i<length;i++)expected[i]=(unsigned char)(i*19+extra);
  memcpy(rx.memory+RTL_QM_HEADROOM+header,expected,length);memset(&dev,0,sizeof(dev));
  struct sk_buff *skb=qm_copy(&rx,&dev,&priv.napi,extra?BIT(31):0,(length+extra*8)<<15,BIT(4)|BIT(6),0);
  assert(skb && skb->len==1522 && !memcmp(skb->data,expected,length) && !dev.stats.rx_errors);
  assert(length<=RTL_QM_DATA_BYTES-header);free(skb);cases++;
 }
 assert(rx.cpu_packets==2 && rx.cpu_bytes==3044);free(rx.memory);
 printf("XRAM: %u production RX byte-copy/wrap, TX-bound and existing QM double-tag-capacity cases passed\n",cases);
}
'''
        old = unit.replace('size > RTL_NI_FRAME_WIRE_BYTES', 'size > 1522', 1)
        self.assertNotEqual(old, unit)
        # files-6.18 contains the driver and the independent QM layout header.
        include_linux = next(parent for parent in HEADER.parents if parent.name == 'files-6.18') / 'include/linux'
        with tempfile.TemporaryDirectory(prefix='xram-rx-boundary-') as temp:
            temp = Path(temp)
            for name, text, passed in (('production',unit,True),('old_1522_rx',old,False)):
                cfile,binary=temp/(name+'.c'),temp/name
                cfile.write_text(text)
                subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-O1','-g',
                                '-fsanitize=address,undefined','-I',str(HEADER.parent),'-I',str(include_linux),
                                str(cfile),'-o',str(binary)],check=True)
                result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=10)
                if passed:
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                    print(result.stdout,end='')
                else:
                    self.assertNotEqual(result.returncode,0)
                    self.assertIn('Assertion',result.stderr)
                    self.assertIn('delivered==1',result.stderr)
                    print('old_1522_rx: rejected by actual packet-delivery assertion')


if __name__ == '__main__':
    unittest.main()
