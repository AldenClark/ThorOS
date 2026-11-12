#!/usr/bin/env python3
"""Exercise production DMA TX header/padding, overflow, completion and BUSY paths.

This is a native host model of skb and MMIO, not a DMA-coherency test on RTL9617C.
"""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
driver = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
source = (driver / 'rtl9617c-dma.c').read_text()


def function(name):
    match = re.search(r'^.*\b' + name + r'\([^;]*?\)\s*\{', source, re.M)
    assert match, name
    end = source.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end] + '\n'


model = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int netdev_tx_t;
#define NETDEV_TX_OK 0
#define NETDEV_TX_BUSY 1
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define unlikely(x) (x)
#define max(a,b) ((a)>(b)?(a):(b))
#define cpu_to_le32(x) (x)
#define dma_wmb() ((void)0)
#define __iomem
#define RTL_DMA_COUNT 64
#define RTL_DMA_BUFFER_SIZE 2048
#define RTL_DMA_DEPTH 6
struct rtl_dma_descriptor {u32 address,control;};
struct net_device {bool stopped;struct {u64 tx_packets,tx_bytes,tx_dropped;}stats;};
struct sk_buff {const u8 *data;unsigned len;bool freed,failed;};
struct rtl9617c_ni_frame {u32 header_high,header_low;const u8 *prefix;unsigned prefix_length;bool raw_payload;};
struct rtl_dma_tx {bool profile;void *registers,*axi_reorder,*descriptors_unused;
 struct rtl_dma_descriptor *descriptors;u32 memory_dma;void *memory;
 unsigned read,write,lengths[64];struct net_device *owners[64];
 unsigned port,vp;u32 completion_checks,invalid_frames,queue_busy;bool wake_pending;unsigned hardware_read;};
static unsigned mmio_reads,mmio_writes,copies;
static u32 readl(void *p){u32 v;memcpy(&v,p,4);mmio_reads++;return v;}
static void writel(u32 v,void *p){memcpy(p,&v,4);mmio_writes++;}
static void put_unaligned_le32(u32 v,void *p){memcpy(p,&v,4);}
static u32 get32(const void *p){u32 v;memcpy(&v,p,4);return v;}
static bool netif_queue_stopped(struct net_device *d){return d->stopped;}
static void netif_stop_queue(struct net_device *d){d->stopped=true;}
static void netif_wake_queue(struct net_device *d){d->stopped=false;}
static void dev_kfree_skb_any(struct sk_buff *s){assert(!s->freed);s->freed=true;}
static void dev_consume_skb_any(struct sk_buff *s){dev_kfree_skb_any(s);}
static int skb_copy_bits(struct sk_buff *s,unsigned offset,void *p,unsigned n){
 copies++;if(s->failed)return -1;
 assert(offset+n<=s->len);memcpy(p,s->data+offset,n);return 0;
}
#define VP_BASE 0x100
#define VP_STRIDE 0xa0
#define VP_WRITE 0x18
#define VP_READ 0x1c
#define MEMORY_BYTES (RTL_DMA_COUNT*(sizeof(struct rtl_dma_descriptor)+RTL_DMA_BUFFER_SIZE))
'''
functions = ''.join(function(name) for name in ('rtl_dma_vp', 'rtl_dma_tx_complete', 'rtl_dma_tx_frame'))
available = r'''
static inline bool rtl_dma_tx_available(struct rtl_dma_tx *tx) {
 return ((tx->read-tx->write-1)&(RTL_DMA_COUNT-1))>2;
}
'''
tests = r'''
int main(void) {
 struct rtl_dma_tx tx={.memory_dma=0x04000000,.port=0,.vp=8};
 struct net_device dev={};
 u8 *memory=malloc(MEMORY_BYTES+128),*regs=calloc(1,4096),bytes[2300]={};
 assert(memory&&regs);
 memset(memory,0xa5,MEMORY_BYTES+128);tx.memory=memory;tx.registers=regs;tx.descriptors=tx.memory;
 u8 *slot=memory+RTL_DMA_COUNT*sizeof(struct rtl_dma_descriptor);
 for(unsigned i=0;i<sizeof(bytes);i++)bytes[i]=(i*7+1)&255;
 struct sk_buff skb={.data=bytes,.len=40};
 struct rtl9617c_ni_frame frame={.header_high=BIT(13),.header_low=(16<<9)|BIT(29)};
 assert(rtl_dma_tx_frame(&tx,&skb,&dev,&frame)==NETDEV_TX_OK&&skb.freed);
 assert(tx.write==1&&mmio_reads==0&&copies==1);
 assert(get32(slot+4)==60&&!memcmp(slot+16,bytes,40));
 for(unsigned i=56;i<76;i++)assert(slot[i]==0);
 assert(slot[76]==0xa5); /* No eager zeroing of the next buffer's tail. */
 assert(get32(&tx.descriptors[0].control)==(0x61000002U|(76U<<8)));
 /* An explicitly raw packet doesn't get padded or have old bytes exposed. */
 skb=(struct sk_buff){.data=bytes,.len=40};frame.raw_payload=true;
 assert(rtl_dma_tx_frame(&tx,&skb,&dev,&frame)==NETDEV_TX_OK&&skb.freed);
 u8 *raw=slot+RTL_DMA_BUFFER_SIZE;
 assert(get32(raw+4)==40&&!memcmp(raw+16,bytes,40)&&raw[56]==0xa5);
 /* Small PON prefix is copied before the skb, within the same DMA slot. */
 u8 prefix[12];memset(prefix,0x6d,sizeof(prefix));
 skb=(struct sk_buff){.data=bytes,.len=70};frame.raw_payload=false;
 frame.prefix=prefix;frame.prefix_length=12;
 assert(rtl_dma_tx_frame(&tx,&skb,&dev,&frame)==NETDEV_TX_OK&&skb.freed);
 u8 *prefixed=slot+2*RTL_DMA_BUFFER_SIZE;
 assert(!memcmp(prefixed+16,prefix,12)&&!memcmp(prefixed+28,bytes,70));
 unsigned before=tx.write;
 skb=(struct sk_buff){.data=bytes,.len=2033};frame.prefix_length=0;
 assert(rtl_dma_tx_frame(&tx,&skb,&dev,&frame)==NETDEV_TX_OK&&skb.freed);
 assert(tx.write==before&&tx.invalid_frames==1&&dev.stats.tx_dropped==1);
 skb=(struct sk_buff){.data=bytes,.len=100};frame.prefix_length=2033;
 assert(rtl_dma_tx_frame(&tx,&skb,&dev,&frame)==NETDEV_TX_OK&&skb.freed);
 assert(tx.write==before&&tx.invalid_frames==2);
 frame.prefix_length=1;frame.prefix=NULL;
 skb=(struct sk_buff){.data=bytes,.len=100};
 assert(rtl_dma_tx_frame(&tx,&skb,&dev,&frame)==NETDEV_TX_OK&&skb.freed);
 assert(tx.write==before&&tx.invalid_frames==3);
 frame.prefix_length=0;
 skb=(struct sk_buff){.data=bytes,.len=100,.failed=true};
 assert(rtl_dma_tx_frame(&tx,&skb,&dev,&frame)==NETDEV_TX_OK&&skb.freed);
 assert(tx.write==before&&tx.invalid_frames==4);
 for(unsigned i=MEMORY_BYTES;i<MEMORY_BYTES+128;i++)assert(memory[i]==0xa5);
 /* No MMIO read per short packet: reclaim only near ring exhaustion. */
 for(unsigned i=0;i<58;i++){
  skb=(struct sk_buff){.data=bytes,.len=100};
  assert(rtl_dma_tx_frame(&tx,&skb,&dev,&frame)==NETDEV_TX_OK&&skb.freed);
 }
 assert(mmio_reads==0&&tx.write==61);
 /* Hardware hasn't advanced: full ring must give BUSY without consuming skb. */
 skb=(struct sk_buff){.data=bytes,.len=100};
 assert(rtl_dma_tx_frame(&tx,&skb,&dev,&frame)==NETDEV_TX_BUSY);
 assert(!skb.freed&&dev.stopped&&tx.wake_pending&&tx.queue_busy==1&&mmio_reads==1);
 u32 hw=tx.write;writel(hw,rtl_dma_vp(&tx)+VP_READ);
 rtl_dma_tx_complete(&tx,&dev);
 assert(!dev.stopped && tx.hardware_read==hw && tx.read==hw-2);
 assert(dev.stats.tx_packets==hw-2 && dev.stats.tx_bytes>0);
 assert(!memcmp(slot+16,bytes,40)); /* Descriptor head not overwritten. */
 printf("Native DMA TX: bounds, PON prefix, zero tail, copy errors, ring BUSY/wake and batched MMIO checks passed (%u polls / %u frames)\n",mmio_reads,hw);
 free(memory);free(regs);
}
'''

with tempfile.TemporaryDirectory(prefix='dma-tx-', dir=root / 'artifacts') as path:
    file = Path(path) / 'test.c'
    executable = Path(path) / 'test'
    file.write_text(model + available + functions + tests)
    subprocess.run(['cc', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                    str(file), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
