#!/usr/bin/env python3
"""Execute the production legacy XRAM xmit path with short skb-copy failures.

MMIO is modeled and copy failure is injected like a malformed/incomplete skb.
The production TYFZA1 DT uses DMA TX; this legacy-path correctness test is not
evidence for the reported hardware-offload throughput issue.
"""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
driver = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--mutants', action='store_true')
args = parser.parse_args()
source = (driver / 'rtl9617c-xram.c').read_text()


def function(name):
    match = re.search(r'(?m)^static [\w *]+\b' + name + r'\([^;{}]*\)\s*\{', source)
    assert match, name
    end = source.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end] + '\n'


fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rtl9617c-xram-format.h"
typedef uint32_t u32;
typedef int netdev_tx_t;
#define NETDEV_TX_OK 0
#define NETDEV_TX_BUSY 1
#define ETH_HLEN 14
#define BIT(n) (1U<<(n))
#define ALIGN(n,a) (((n)+(a)-1)&~((a)-1))
#define TX_WRITE 0xaa44
#define TX_READ 0xaa48
#define POINTER_MASK 0x3ffU
#define unlikely(x) (x)
struct rtl_xram;
struct rtl_lan {struct rtl_xram *shared;unsigned port;};
struct net_device {struct rtl_lan priv;bool stopped;struct {unsigned tx_dropped,tx_packets,tx_bytes;}stats;};
struct sk_buff {unsigned len;bool fail,freed,consumed;unsigned partial;unsigned char data[1600];};
struct rtl9617c_ni_frame {u32 header_high,header_low;};
struct rtl_xram {
 bool host_active,removing,engine_poisoned,dma_tx,tx_pending;
 int tx_lock,dma;unsigned tx_length;unsigned char tx_buffer[2048],*xram,*ni;
};
static unsigned copies,crc_calls,mmio_writes,publications,frees,consumes,barriers,kicks,dma_calls;
static struct rtl_xram *active;
static void *netdev_priv(struct net_device *d){return &d->priv;}
#define spin_lock_irqsave(p,f) do{(f)=0;assert(!*(p));*(p)=1;}while(0)
#define spin_unlock_irqrestore(p,f) do{(void)(f);assert(*(p));*(p)=0;}while(0)
static u32 readl(void *p){u32 n;memcpy(&n,p,4);return n;}
static void writel(u32 n,void *p) {
 assert(active->tx_lock);
 if(p==active->ni+TX_WRITE){assert(barriers==1);publications++;}
 else assert((unsigned char *)p>=active->xram+RTL_XRAM_TX_START*8 &&
             (unsigned char *)p<=active->xram+RTL_XRAM_TX_END*8-4);
 memcpy(p,&n,4);mmio_writes++;
}
static u32 get_unaligned_le32(void *p){return readl(p);}
static void put_unaligned_le32(u32 n,void *p){memcpy(p,&n,4);}
static void wmb(void){assert(active->tx_lock);barriers++;}
static void netif_stop_queue(struct net_device *d){d->stopped=true;}
static void dev_kfree_skb_any(struct sk_buff *s){assert(!s->freed);s->freed=true;frees++;}
static void dev_consume_skb_any(struct sk_buff *s){assert(!s->freed);s->freed=s->consumed=true;consumes++;}
static int skb_copy_bits(struct sk_buff *s,unsigned offset,void *p,unsigned bytes) {
 assert(offset+bytes<=s->len);copies++;
 if(s->fail){assert(s->partial<=bytes);memcpy(p,s->data+offset,s->partial);return -1;}
 memcpy(p,s->data+offset,bytes);return 0;
}
static u32 crc32_le(u32 crc,const unsigned char *p,unsigned bytes) {
 crc_calls++;
 while(bytes--){crc^=*p++;for(unsigned b=0;b<8;b++)crc=(crc>>1)^((crc&1)?0xedb88320U:0);}
 return crc;
}
static int rtl_dma_tx_frame(int *dma,struct sk_buff *s,struct net_device *d,const struct rtl9617c_ni_frame *f) {
 (void)dma;assert(active->tx_lock && f->header_high==BIT(13));dma_calls++;
 if(s->fail)return NETDEV_TX_BUSY;
 netif_stop_queue(d);dev_consume_skb_any(s);return NETDEV_TX_OK;
}
static void rtl_tx_timer_kick_locked(struct rtl_xram *p){assert(p->tx_lock);kicks++;}
'''

tests = r'''
static void setup(struct rtl_xram *p,struct net_device *d,unsigned pointer) {
 memset(p,0,sizeof(*p));memset(d,0,sizeof(*d));d->priv.shared=p;
 p->host_active=true;p->tx_length=987;
 p->xram=malloc(RTL_XRAM_TX_END*8);p->ni=calloc(1,65536);assert(p->xram && p->ni);
 memset(p->xram,0xa5,RTL_XRAM_TX_END*8);memset(p->tx_buffer,0xa7,sizeof(p->tx_buffer));
 put_unaligned_le32(pointer,p->ni+TX_READ);put_unaligned_le32(pointer,p->ni+TX_WRITE);
 copies=crc_calls=mmio_writes=publications=frees=consumes=barriers=kicks=dma_calls=0;active=p;
}
static void cleanup(struct rtl_xram *p){assert(!p->tx_lock);free(p->xram);free(p->ni);}
int main(void) {
 const unsigned lengths[]={14,42,60,61,1514,1522};
 const unsigned pointers[]={RTL_XRAM_TX_START,RTL_XRAM_TX_END-1};
 unsigned cases=0;
 for(unsigned ptr=0;ptr<2;ptr++)for(unsigned len=0;len<6;len++)for(unsigned fail=0;fail<4;fail++) {
  struct rtl_xram p;struct net_device d;setup(&p,&d,pointers[ptr]);
  struct sk_buff s={.len=lengths[len],.fail=fail!=0};
  s.partial=fail==2?5:fail==3?s.len-1:0;
  for(unsigned i=0;i<s.len;i++)s.data[i]=(i*29+7)&255;
  assert(rtl_xmit(&s,&d)==NETDEV_TX_OK && s.freed && copies==1 && !dma_calls);
  assert(!d.stats.tx_packets && !d.stats.tx_bytes);
  if(fail) {
   assert(d.stats.tx_dropped==1 && frees==1 && !consumes && !s.consumed);
   assert(!p.tx_pending && p.tx_length==987 && !d.stopped);
   assert(!mmio_writes && !publications && !barriers && !crc_calls);
   assert(rtl_pointer(&p,TX_WRITE)==pointers[ptr]);
   for(unsigned i=0;i<RTL_XRAM_TX_END*8;i++)assert(p.xram[i]==0xa5);
  } else {
   unsigned wire=rtl_xram_wire_length(s.len),next=rtl_xram_tx_next(pointers[ptr],wire);
   assert(!d.stats.tx_dropped && !frees && consumes==1 && s.consumed);
   assert(p.tx_pending && p.tx_length==s.len && d.stopped);
   assert(publications==1 && barriers==1 && crc_calls==1 && rtl_pointer(&p,TX_WRITE)==next);
   assert(readl(p.xram+pointers[ptr]*8+4)==rtl_xram_tx_header(next,wire));
   unsigned offset=rtl_xram_word_next(pointers[ptr]*8+4,RTL_XRAM_TX_START*8,RTL_XRAM_TX_END*8);
   for(unsigned i=0;i<wire+8;i+=4){
    assert(readl(p.xram+offset)==get_unaligned_le32(p.tx_buffer+i));
    offset=rtl_xram_word_next(offset,RTL_XRAM_TX_START*8,RTL_XRAM_TX_END*8);
   }
   assert(!memcmp(p.tx_buffer+8,s.data,s.len));
   for(unsigned i=s.len;i<wire-4;i++)assert(!p.tx_buffer[8+i]);
  }
  cleanup(&p);cases++;
 }
 for(unsigned busy=0;busy<2;busy++) {
  struct rtl_xram p;struct net_device d;setup(&p,&d,RTL_XRAM_TX_START);
  struct sk_buff s={.len=64,.fail=true,.partial=5};
  if(busy)p.tx_pending=true;else put_unaligned_le32(RTL_XRAM_TX_START+1,p.ni+TX_READ);
  assert(rtl_xmit(&s,&d)==NETDEV_TX_BUSY && !s.freed && d.stopped);
  assert(!copies && !frees && !consumes && !mmio_writes && !d.stats.tx_dropped);
  cleanup(&p);cases++;
 }
 for(unsigned state=0;state<3;state++) {
  struct rtl_xram p;struct net_device d;setup(&p,&d,RTL_XRAM_TX_START);
  struct sk_buff s={.len=64};
  if(!state)p.host_active=false;else if(state==1)p.removing=true;else p.engine_poisoned=true;
  assert(rtl_xmit(&s,&d)==NETDEV_TX_OK && s.freed && d.stats.tx_dropped==1);
  assert(frees==1 && !consumes && !copies && !mmio_writes);
  cleanup(&p);cases++;
 }
 for(unsigned busy=0;busy<2;busy++) {
  struct rtl_xram p;struct net_device d;setup(&p,&d,RTL_XRAM_TX_START);p.dma_tx=true;
  struct sk_buff s={.len=64,.fail=busy!=0};
  assert(rtl_xmit(&s,&d)==(busy?NETDEV_TX_BUSY:NETDEV_TX_OK));
  assert(dma_calls==1 && !mmio_writes && !copies && !frees && kicks==busy && s.freed==!busy);
  cleanup(&p);cases++;
 }
 printf("Legacy XRAM TX: %u production-xmit cases passed; partial-copy failures publish nothing and free once, BUSY keeps skb, normal wrap/padding and DMA dispatch preserved\n",cases);
}
'''


def run(label, tx, directory, expect_pass):
    source, executable = directory / (label + '.c'), directory / label
    source.write_text(fixture + function('rtl_pointer') + tx + tests)
    subprocess.run(['cc', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-I', str(driver),
                    str(source), '-o', str(executable)], check=True)
    result = subprocess.run([str(executable)], capture_output=True, text=True)
    if expect_pass:
        assert result.returncode == 0, result.stdout + result.stderr
        print(result.stdout, end='')
    else:
        assert result.returncode != 0 and 'Assertion' in result.stderr, result.stdout + result.stderr
        print('Old unchecked skb copy rejected by executable TX publication/drop/ownership oracle')


with tempfile.TemporaryDirectory(prefix='xram-tx-copy-', dir=root / 'artifacts') as work:
    directory = Path(work)
    tx = function('rtl_xmit')
    run('fixed', tx, directory, True)
    if args.mutants:
        begin = tx.index('\tif (skb_copy_bits(skb, 0, priv->tx_buffer + 8, skb->len)) {')
        end = tx.index('\n\tcrc = crc32_le(', begin)
        old = tx[:begin] + '\tskb_copy_bits(skb, 0, priv->tx_buffer + 8, skb->len);' + tx[end:]
        run('unchecked-copy', old, directory, False)
