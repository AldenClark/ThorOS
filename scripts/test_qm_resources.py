#!/usr/bin/env python3
"""Exercise the shared CPU/DQ resource plan and actual DMA allocation/unwind.

RTL77C has one 16384-entry BID namespace. Its public silicon declarations
give 14-bit EQ counts/starts, 24-bit EPP pointers and 21-bit ring sizes in
16-byte units; test_qm_sdk_registers.py independently decodes the production
writes against that pinned header. These host tests cover allocation faults,
address truncation/wrap, all pool boundaries and mutation controls. They do
not establish ASIC occupancy, DMA timing or throughput.
"""
import argparse
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'


def function(source, name):
    match = re.search(r'^.*\b' + name + r'\([^;]*?\)\s*\{', source, re.M)
    assert match, name
    end = source.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end] + '\n'


MODEL = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "rtl9617c-qm-deepq.h"
#include "rtl9617c-qm-layout.h"
typedef uint64_t dma_addr_t;
#define L1_CACHE_BYTES 64
#define DMA_FROM_DEVICE 2
#define GFP_KERNEL 0
#define EQ_ID RTL_QM_CPU_EQ_FIRST
struct device {unsigned unused;};
struct rtl_qm_rx {
 struct device *device;void *memory,*ring_memory,*deepq_memory;
 dma_addr_t memory_dma,ring_dma,deepq_dma;
};
static struct device device;
static unsigned char token[3];
static bool live[3];
static unsigned calls,frees,fail_slot;
static dma_addr_t addresses[3];
/* Independent allocation sizes: the payload is exactly 2MiB, not 2MiB plus
 * a duplicate EPP prefix (which forces a 4MiB get_order() fallback). The
 * EPP allocation remains independent, followed by 4MiB WAN DDR payload. */
static const unsigned sizes[]={2*1024*1024,16*1024,4*1024*1024};
static const unsigned alignments[]={2048,64,2048};
static void *allocate(struct device *dev,unsigned bytes,dma_addr_t *address,
                      int flags,bool coherent,int direction) {
 unsigned i=calls++;assert(i<3 && dev==&device && bytes==sizes[i] && flags==GFP_KERNEL);
 assert(coherent==(i==2) && (coherent || direction==DMA_FROM_DEVICE));
 if(i==fail_slot)return NULL;
 assert(!live[i]);live[i]=true;*address=addresses[i];return token+i;
}
static void release(struct device *dev,unsigned bytes,void *memory,
                    dma_addr_t address,bool coherent,int direction) {
 unsigned i=(unsigned char *)memory-token;
 assert(i<3 && live[i] && dev==&device && bytes==sizes[i] && address==addresses[i]);
 assert(coherent==(i==2) && (coherent || direction==DMA_FROM_DEVICE));
 /* Free in reverse allocation order, never release an unallocated pool. */
 for(unsigned j=i+1;j<3;j++)assert(!live[j]);
 live[i]=false;frees++;
}
static void *dma_alloc_noncoherent(struct device *d,unsigned n,dma_addr_t *a,int dir,int flags) {
 return allocate(d,n,a,flags,false,dir);
}
static void *dma_alloc_coherent(struct device *d,unsigned n,dma_addr_t *a,int flags) {
 return allocate(d,n,a,flags,true,0);
}
static void dma_free_noncoherent(struct device *d,unsigned n,void *p,dma_addr_t a,int dir) {
 release(d,n,p,a,false,dir);
}
static void dma_free_coherent(struct device *d,unsigned n,void *p,dma_addr_t a) {
 release(d,n,p,a,true,0);
}
static unsigned push_calls,push_fail;
static int rtl_qm_push(struct rtl_qm_rx *rx,unsigned address,unsigned eq) {
 unsigned index=push_calls++;
 assert(index<1024 && address==rx->memory_dma+index*2048U && eq==4+index/512);
 assert(address>=rx->memory_dma && address+2047ULL<rx->memory_dma+2*1024*1024);
 return index==push_fail?-ETIMEDOUT:0;
}
struct mmio {
 unsigned regs[65536/4],reads,writes,commands,fail_at;
 unsigned credits[32],voq[256];
};
static unsigned read_reg(void *context,unsigned reg) {
 struct mmio *m=context;assert(reg<65536 && !(reg&3));m->reads++;return m->regs[reg/4];
}
static void write_reg(void *context,unsigned reg,unsigned value) {
 struct mmio *m=context;assert(reg<65536 && !(reg&3));m->writes++;m->regs[reg/4]=value;
}
static int indirect(void *context,unsigned reg,unsigned value) {
 struct mmio *m=context;assert(!(m->regs[reg/4]&0x80000000U));
 assert((value&0xc0000000U)==0xc0000000U);m->commands++;
 if(m->fail_at && m->commands==m->fail_at) {
  m->regs[reg/4]=value;return -ETIMEDOUT;
 }
 if(reg==0x95a8)m->credits[value&31]=m->regs[0x95ac/4];
 else if(reg==0x95c0)m->voq[value&255]=m->regs[0x95c4/4];
 else assert(reg==0x95b0);
 m->regs[reg/4]=value&~0x80000000U;return 0;
}
'''

CASES = r'''
static void reset(struct rtl_qm_rx *rx) {
 memset(rx,0,sizeof(*rx));memset(live,0,sizeof(live));calls=frees=0;fail_slot=~0U;
 addresses[0]=0x04000000;addresses[1]=0x06000000;addresses[2]=0x12000000;
}
static void no_live(void) {for(unsigned i=0;i<3;i++)assert(!live[i]);}
static void check_dq(struct mmio *m,unsigned address) {
 assert(!(m->regs[0x610c/4]&0xffff));
 /* Raw field positions are independent of the resource macros. */
 for(unsigned pool=0;pool<2;pool++) {
  unsigned base=(0x61e8+(pool+1)*20)/4;
  assert(m->regs[base]==(address+pool*1024*2048U+1));
  assert(m->regs[base+1]==(1024U<<16)+(1024+pool*1024));
  assert(m->regs[base+2]==5 && m->regs[base+3]==0x61008060 && m->regs[base+4]==2);
 }
 assert(m->regs[0x612c/4]==0x21 && m->regs[0x958c/4]==(682U|(1364U<<16)));
 for(unsigned p=16;p<32;p++) {
  assert(m->regs[(0x6148+p*4)/4]==1);
  assert(m->credits[p]==0x44004400U);
  for(unsigned q=p*8;q<p*8+8;q++)assert(m->voq[q]==3);
 }
}
int main(void) {
 struct rtl_qm_rx rx;unsigned cases=0;
 assert(RTL_QM_BUFFERS_PER_EQ==512 && RTL_QM_BUFFERS==1024 && RTL_QM_REFILL_SIZE==512);
 assert(RTL_QM_REFILL_THRESHOLD==56 && RTL_QM_RING_BYTES==2048 && RTL_QM_RING_COMMANDS==256);
 assert(RTL_QM_PAYLOAD_BYTES==2*1024*1024 && RTL_DQ_MEMORY_BYTES==4*1024*1024);
 assert(RTL_QM_PAYLOAD_OFFSET==0 && RTL_QM_MEMORY_BYTES==2*1024*1024);
 assert(RTL_QM_BUFFER_BYTES==RTL_QM_RESOURCE_BUFFER_BYTES && RTL_QM_BUFFER_BYTES==2048);
 assert(RTL_QM_CPU_BID_FIRST==0 && RTL_QM_CPU_BID_END==1024);
 assert(RTL_DQ_BID_FIRST==1024 && RTL_DQ_BID_END==3072 && RTL_QM_BID_LIMIT==16384);
 reset(&rx);assert(!rtl_qm_rx_alloc(&device,&rx) && calls==3 && !frees);
 push_calls=0;push_fail=~0U;
 assert(!populate_cpu_buffers(&rx) && push_calls==1024);
 rtl_qm_rx_free(&device,&rx);assert(frees==3);no_live();cases++;
 /* The actual startup PUSH loop uses the payload base, not ring storage,
  * and stops at every first/last boundary of both independently owned EQs. */
 const unsigned failed_push[]={0,511,512,1023};
 for(unsigned i=0;i<sizeof(failed_push)/sizeof(*failed_push);i++) {
  reset(&rx);assert(!rtl_qm_rx_alloc(&device,&rx));
  push_calls=0;push_fail=failed_push[i];
  assert(populate_cpu_buffers(&rx)==-ETIMEDOUT && push_calls==push_fail+1);
  /* The isolated loop does not release DMA; the full NI owner retains an
   * exposed failed startup. This fixture explicitly releases its model. */
  assert(!frees && live[0] && live[1] && live[2]);
  rtl_qm_rx_free(&device,&rx);no_live();cases++;
 }
 for(unsigned failure=0;failure<3;failure++) {
  reset(&rx);fail_slot=failure;
  assert(rtl_qm_rx_alloc(&device,&rx)==-ENOMEM);
  assert(calls==failure+1 && frees==failure && !rx.memory && !rx.ring_memory && !rx.deepq_memory);
  no_live();cases++;
 }
 const unsigned long long bad[]={1,127,0xffffffffULL,0x100000000ULL,0xfffffffffffff800ULL};
 for(unsigned slot=0;slot<3;slot++) {
  for(unsigned j=0;j<sizeof(bad)/sizeof(*bad);j++) {
   reset(&rx);addresses[slot]=bad[j];
   assert(rtl_qm_rx_alloc(&device,&rx)==-ERANGE && calls==slot+1 && frees==slot+1);
   assert(!rx.memory && !rx.ring_memory && !rx.deepq_memory);no_live();cases++;
  }
  /* A range ending exactly at 4GiB is encodable; one aligned step later
   * must not wrap low 32-bit commands into a different owner's memory. */
  reset(&rx);addresses[slot]=0x100000000ULL-sizes[slot];
  assert(!rtl_qm_rx_alloc(&device,&rx));
  push_calls=0;push_fail=~0U;
  assert(!populate_cpu_buffers(&rx) && push_calls==1024);
  rtl_qm_rx_free(&device,&rx);no_live();cases++;
  reset(&rx);addresses[slot]=0x100000000ULL-sizes[slot]+alignments[slot];
  assert(rtl_qm_rx_alloc(&device,&rx)==-ERANGE && calls==slot+1 && frees==slot+1);
  no_live();cases++;
 }
 assert(!rtl_qm_dma_range_valid(0,0,128) && !rtl_qm_dma_range_valid(0,128,0));
 assert(!rtl_qm_dma_range_valid(0,128,3) && rtl_qm_dma_range_valid(0,128,128));
 /* Validate all 32-bit DQ boundary encodings before any hardware writes. */
 const unsigned invalid_dq[]={1,127,128,2047,0xffc00800U,0xfffff800U,0xffffffffU};
 for(unsigned i=0;i<sizeof(invalid_dq)/sizeof(*invalid_dq);i++) {
  struct mmio m={0};struct rtl_dq_io io={&m,read_reg,write_reg,indirect};
  assert(rtl_qm_deepq_prepare(&io,invalid_dq[i])==-ERANGE);
  assert(!m.reads && !m.writes && !m.commands);cases++;
 }
 const unsigned valid_dq[]={0,2048,0x12000000U,0xffc00000U};
 unsigned total_commands=0;
 for(unsigned i=0;i<sizeof(valid_dq)/sizeof(*valid_dq);i++) {
  struct mmio m={0};struct rtl_dq_io io={&m,read_reg,write_reg,indirect};
  m.regs[0x610c/4]=~0U;
  assert(!rtl_qm_deepq_prepare(&io,valid_dq[i]));check_dq(&m,valid_dq[i]);
  total_commands=m.commands;cases++;
 }
 /* Admission remains closed at every indirect failure of the larger plan. */
 assert(total_commands==145);
 for(unsigned fail=1;fail<=total_commands;fail++) {
  struct mmio m={.fail_at=fail};struct rtl_dq_io io={&m,read_reg,write_reg,indirect};
  m.regs[0x610c/4]=~0U;
  assert(rtl_qm_deepq_prepare(&io,0x12000000)==-ETIMEDOUT);
  assert(m.commands==fail && !(m.regs[0x610c/4]&0xffff));cases++;
 }
 printf("QM resources: %u allocation/address/DQ-fault cases; 3072 disjoint BIDs, 6MiB payload, 256 commands/VOQ and exact unwind passed\n",cases);
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    source = (DRIVER / 'rtl9617c-qm.c').read_text()
    production = ''.join(function(source, n) for n in ('rtl_qm_rx_alloc', 'rtl_qm_rx_free'))
    push_start = source.index('\tfor (i = 0; i < RTL_QM_BUFFERS; i++)')
    push_end = source.index('\tret = rtl_qm_cpu_credits(rx);', push_start)
    production += ('static int populate_cpu_buffers(struct rtl_qm_rx *rx) { unsigned i; int ret;\n'
                   + source[push_start:push_end] + 'return 0;}\n')
    headers = {name: (DRIVER / name).read_text() for name in (
        'rtl9617c-qm-resources.h', 'rtl9617c-qm-deepq.h')}
    layout = ROOT / 'port/overlay/target/linux/rtl9617c/files-6.18/include/linux/rtl9617c-qm-layout.h'
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = dict(os.environ)
    env.setdefault('ASAN_OPTIONS', 'detect_leaks=0:halt_on_error=1')
    env.setdefault('UBSAN_OPTIONS', 'halt_on_error=1')
    with tempfile.TemporaryDirectory(prefix='qm-resources-', dir=ROOT / 'artifacts') as temp:
        work = Path(temp)
        (work / layout.name).write_text(layout.read_text())

        def run(name, overrides=None, changed_production=None, rejection=None):
            for header, contents in (headers | (overrides or {})).items():
                (work / header).write_text(contents)
            c, exe = work / 'test.c', work / 'test'
            c.write_text(MODEL + (changed_production or production) + CASES)
            built = subprocess.run(['cc', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=address,undefined', '-I', str(work),
                                    str(c), '-o', str(exe)], capture_output=True, text=True)
            if rejection == 'compile':
                assert built.returncode and '#error' in built.stderr, (name, built.stderr)
                print(f'PASS: resource invariant rejected {name}')
                return
            assert built.returncode == 0, (name, built.stderr)
            result = subprocess.run([str(exe)], capture_output=True, text=True, env=env)
            if rejection == 'assert':
                assert result.returncode and ('Assertion' in result.stderr or 'Assertion' in result.stdout), (name, result.stdout, result.stderr)
                print(f'PASS: assertion killed {name}')
            else:
                assert result.returncode == 0, (name, result.stdout, result.stderr)
                print(result.stdout, end='')

        run('production')
        if args.mutants:
            mutations = (
                ('overlapping CPU/DQ BIDs', '#define RTL_DQ_BID_FIRST RTL_QM_CPU_BID_END', '#define RTL_DQ_BID_FIRST 512', 'compile'),
                ('oversized DQ BID count', '#define RTL_DQ_BUFFERS 1024', '#define RTL_DQ_BUFFERS 16384', 'compile'),
                ('refill field overflow', '#define RTL_QM_BUFFERS_PER_EQ 512', '#define RTL_QM_BUFFERS_PER_EQ 2112', 'compile'),
                ('undersized deferred-return queue', '#define RTL_QM_REFILL_SIZE RTL_QM_BUFFERS_PER_EQ', '#define RTL_QM_REFILL_SIZE 256', 'compile'),
                ('non-power-of-two EPP ring', '#define RTL_QM_RING_BYTES 2048', '#define RTL_QM_RING_BYTES 1536', 'compile'),
                ('24-bit pointer overflow', '#define RTL_QM_RING_BYTES 2048', '#define RTL_QM_RING_BYTES 0x2000000', 'compile'),
                ('overlapping EQ ownership', '#define RTL_DQ_EQ_SHARED 2', '#define RTL_DQ_EQ_SHARED 4', 'compile'),
                ('duplicate unused EPP prefix', '#define RTL_QM_PAYLOAD_OFFSET 0', '#define RTL_QM_PAYLOAD_OFFSET RTL_QM_RING_MEMORY_BYTES', 'compile'),
                ('stale 24-unit refill threshold', '#define RTL_QM_REFILL_THRESHOLD ((RTL_QM_BUFFERS_PER_EQ - RTL_QM_REFILL_RESERVE) / 8)', '#define RTL_QM_REFILL_THRESHOLD 24', 'assert'),
                ('stale 128-command ring', '#define RTL_QM_RING_BYTES 2048', '#define RTL_QM_RING_BYTES 1024', 'assert'),
                ('DMA truncation/wrap accepted', 'return bytes && alignment', 'return 1 || (bytes && alignment', 'assert'),
            )
            key = 'rtl9617c-qm-resources.h'
            for name, before, after, rejection in mutations:
                assert before in headers[key], name
                changed = headers[key].replace(before, after, 1)
                if name == 'DMA truncation/wrap accepted':
                    changed = changed.replace('bytes - 1 <= 0xffffffffULL - address;', 'bytes - 1 <= 0xffffffffULL - address);')
                run(name, {key: changed}, rejection=rejection)
            key = 'rtl9617c-qm-deepq.h'
            before = '(RTL_DQ_BID_FIRST + pool * count)'
            assert before in headers[key]
            run('stale literal 512 DQ BID base', {key: headers[key].replace(before, '(512 + pool * count)', 1)}, rejection='assert')
            before = 'if (!rx->deepq_memory)\n\t\tgoto free_ring;'
            assert before in production
            run('missing unwind after DQ allocation failure', changed_production=production.replace(before, 'if (!rx->deepq_memory)\n\t\treturn -ENOMEM;', 1), rejection='assert')
            before = 'rx->memory_dma + RTL_QM_PAYLOAD_OFFSET +'
            assert before in production
            run('stale payload prefix in startup PUSH', changed_production=production.replace(before, 'rx->memory_dma + RTL_QM_RING_MEMORY_BYTES +', 1), rejection='assert')
            print(f'PASS: {len(mutations) + 3} resource-plan mutation controls')


if __name__ == '__main__':
    main()
