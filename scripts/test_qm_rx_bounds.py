#!/usr/bin/env python3
"""Fault-inject native QM EPP pointers and EQ ownership before DMA sync/refill.

The independent wire constraints are the pinned RTL9617C SDK's 8-byte
CPU_EPP_FIFO_CMD_64BIT_T (ni-drv-77c/ca_ni_rx.h) and byte-offset pointers
(aal-77c/aal_l3qm.c). The native setup assigns 256 buffers to each of EQ4/5.
This is a host fault-injection test, not a hardware coherency/throughput test.
"""
from pathlib import Path
import argparse
import ast
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
drivers = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', type=Path)
args = parser.parse_args()
source = (args.source or drivers / 'rtl9617c-qm.c').read_text()
tree = ast.parse((root / 'scripts/fixtures/qm_cached_epp_model.py').read_text())
model = next(ast.literal_eval(n.value) for n in tree.body
             if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'common'
                                                for t in n.targets))
start = model.index('static u32 readl(')
end = model.index('static bool rtl_rx_checksum_valid', start)
model = model[:start] + r'''
static unsigned write_pointer[8],ring_syncs,payload_syncs,retired,pushes,returned_eq;
static unsigned returned_address;
static u32 readl(void *p) {
 unsigned r=(u8 *)p-(u8 *)active->ni;
 if(r==0x3218)return 0;
 assert(r>=EPP_WRITE && r<EPP_WRITE+32 && !(r&3));
 return write_pointer[(r-EPP_WRITE)/4];
}
static void writel(u32 v,void *p) {
 unsigned r=(u8 *)p-(u8 *)active->ni;
 assert(r>=EPP_READ && r<EPP_READ+32 && !(r&3));
 assert(v<1024 && !(v&7));retired++;
}
static void dma_sync_single_for_cpu(void *d,dma_addr_t a,unsigned n,int direction) {
 assert(d==active->device && direction==DMA_FROM_DEVICE);
 if(a>=active->ring_dma && a<active->ring_dma+8192) {
  unsigned off=a-active->ring_dma;
  /* A published interval belongs to one 1024-byte VOQ, not the whole allocation. */
  assert(n && !(off%64) && !(n%64) && off%1024+n<=1024);
  ring_syncs++;
 } else {
  assert(n==2048 && a>=active->memory_dma+8192 &&
         a<=active->memory_dma+RTL_QM_MEMORY_BYTES-2048 && !(a%2048));
  payload_syncs++;
 }
}
static int rtl_qm_try_push(void *context,unsigned address,unsigned eq) {
 struct rtl_qm_rx *rx=context;
 unsigned off=address-rx->memory_dma-8192;
 assert(retired && !(off%2048) && off<512*2048 && eq==4+off/(256*2048));
 pushes++;returned_eq=eq;returned_address=address;return 0;
}
''' + model[end:]
start = model.index('static void received(')
end = model.index('static void napi_gro_receive(', start)
model = model[:start] + r'''
static void received(struct sk_buff *s) {
 u8 expected[64];unsigned id=get_unaligned_be32(s->data+28);
 packet_bytes(id,expected);assert(s->len==50 && !memcmp(s->data,expected+14,50));
 delivered++;free(s);
}
''' + model[end:]

start = source.index('static void rtl_qm_rx_retire(')
end = source.index('\nssize_t rtl_qm_rx_state(', start)
cases = r'''
static void setup(struct rtl_qm_rx *rx,struct net_device *owner,struct net_device *input) {
 *rx=(struct rtl_qm_rx){.memory_dma=0x4000000,.ring_dma=0x6000000,.device=owner};
 memset(owner,0,sizeof(*owner));memset(input,0,sizeof(*input));input->running=true;
 rx->lan[0]=input;rx->memory=calloc(1,RTL_QM_MEMORY_BYTES);
 rx->ring_memory=calloc(1,8192);rx->ni=calloc(1,65536);active=rx;
 memset(write_pointer,0,sizeof(write_pointer));ring_syncs=payload_syncs=retired=pushes=delivered=0;
 returned_eq=returned_address=0;
}
static void cleanup(struct rtl_qm_rx *rx) {
 free(rx->memory);free(rx->ring_memory);free(rx->ni);
}
static void command(struct rtl_qm_rx *rx,unsigned voq,unsigned rd,unsigned address,unsigned eq,unsigned id) {
 void *entry=rx->ring_memory+voq*1024+rd;
 put(address|eq|BIT(4)|BIT(6),entry);put(0,entry+4);
 rx->read[voq]=rd;write_pointer[voq]=(rd+8)%1024;
 unsigned off=address-rx->memory_dma;
 if(off>=8192 && off<=RTL_QM_MEMORY_BYTES-2048) {
  put(0,rx->memory+off+RTL_QM_HEADROOM);
  put(__builtin_bswap32(64U<<15),rx->memory+off+RTL_QM_HEADROOM+4);
  packet_bytes(id,rx->memory+off+RTL_QM_HEADROOM+8);
 }
}
int main(void) {
 struct rtl_qm_rx rx;struct net_device owner,input;struct napi_struct napi={.dev=&owner};
 const unsigned bad[]={1,7,1024,1025,2048,0xffffff};unsigned cases=0;
 for(unsigned which=0;which<2;which++)for(unsigned q=0;q<8;q++)for(unsigned i=0;i<6;i++) {
  setup(&rx,&owner,&input);
  if(which)rx.read[q]=bad[i];else write_pointer[q]=bad[i];
  assert(rtl_qm_rx_poll(&rx,&napi,64)==0);
  assert(rx.ring_errors==1 && owner.stats.rx_errors==1 && !ring_syncs &&
         !payload_syncs && !retired && !pushes && !delivered);
  assert((which?rx.read[q]:write_pointer[q])==bad[i]);
  cleanup(&rx);cases++;
 }
 /* Every boundary of both independent CPU pools, including VOQ/ring wrap. */
 const unsigned ids[]={0,255,256,511};
 for(unsigned q=0;q<8;q++)for(unsigned i=0;i<4;i++)for(unsigned wrap=0;wrap<2;wrap++) {
  setup(&rx,&owner,&input);unsigned address=rx.memory_dma+8192+ids[i]*2048;
  command(&rx,q,wrap?1016:0,address,4+ids[i]/256,ids[i]);
  assert(rtl_qm_rx_poll(&rx,&napi,64)==1);
  assert(ring_syncs==1 && payload_syncs==1 && retired==1 && pushes==1 && delivered==1);
  assert(returned_address==address && returned_eq==4+ids[i]/256);
  assert(rx.cpu_packets==1 && rx.cpu_bytes==64 && !rx.ring_errors && !rx.buffer_errors);
  cleanup(&rx);cases++;
 }
 /* Address range alone is insufficient: an EQ4 buffer may not be returned to EQ5. */
 for(unsigned i=0;i<4;i++)for(unsigned eq=0;eq<16;eq++) {
  if(eq==4+ids[i]/256)continue;
  setup(&rx,&owner,&input);
  command(&rx,0,0,rx.memory_dma+8192+ids[i]*2048,eq,ids[i]);
  assert(rtl_qm_rx_poll(&rx,&napi,64)==1);
  assert(rx.buffer_errors==1 && owner.stats.rx_errors==1 && retired==1 &&
         !payload_syncs && !pushes && !delivered && !rx.cpu_packets && !rx.cpu_bytes);
  cleanup(&rx);cases++;
 }
 const unsigned off[]={0,8192-2048,8192+128,RTL_QM_MEMORY_BYTES,0xfffff800U};
 for(unsigned i=0;i<5;i++) {
  setup(&rx,&owner,&input);command(&rx,0,0,rx.memory_dma+off[i],4,0);
  assert(rtl_qm_rx_poll(&rx,&napi,64)==1);
  assert(rx.buffer_errors==1 && retired==1 && !payload_syncs && !pushes && !delivered);
  cleanup(&rx);cases++;
 }
 /* A faulty high-priority pointer does not strand a healthy lower VOQ. */
 setup(&rx,&owner,&input);write_pointer[7]=0xffffff;
 command(&rx,0,0,rx.memory_dma+8192,4,0);
 assert(rtl_qm_rx_poll(&rx,&napi,64)==1);
 assert(rx.ring_errors==1 && owner.stats.rx_errors==1 && delivered==1 && pushes==1);
 cleanup(&rx);cases++;
 puts("QM ownership: malformed 24-bit/unaligned pointers cannot sync or retire; per-EQ buffer partitions checked; valid boundaries and CPU byte counters passed");
 printf("%u production-poll fault/boundary cases passed\n",cases);
}
'''
with tempfile.TemporaryDirectory(prefix='qm-rx-bounds-', dir=root / 'artifacts') as temp:
    c, exe = Path(temp) / 'test.c', Path(temp) / 'test'
    c.write_text(model + source[start:end] + cases)
    subprocess.run(['cc', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-Wno-unused-function', '-Wno-unused-variable', '-Wno-misleading-indentation',
                    '-fsanitize=address,undefined', '-I', str(drivers), '-I',
                    str(root / 'port/overlay/target/linux/rtl9617c/files-6.18/include/linux'),
                    str(c), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
