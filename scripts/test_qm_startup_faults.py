#!/usr/bin/env python3
"""Fault-inject every MMIO read in the actual cold QM startup and stop paths.

The host executes the real reset, EQ/DQ, credit, ingress and EPP setup functions.
The independent recorder does not emulate reset completion, DMA draining, or
silicon timing. It verifies that an all-ones read cannot produce a write, reset
unrelated PON/L3 blocks, retire an invalid EPP pointer, or free exposed memory.
Partial-publication quarantine is also covered by test_ni_owner_lifetime.py.
"""
import argparse
from pathlib import Path
import re
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'


def function(text, name):
    match = re.search(r'(?m)^(?:static\s+)?[\w *]+\b' + name + r'\([^;{}]*\)\s*\{', text)
    assert match, name
    end = text.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[match.start():end] + '\n'


SHIM = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
typedef uint64_t dma_addr_t;
#define __iomem
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define lower_32_bits(x) ((u32)(x))
#define rcu_access_pointer(p) (p)
#define DMA_FROM_DEVICE 2
#include "rtl9617c-qm-refill.h"
#include "rtl9617c-qm-deepq.h"
#include "rtl9617c-qm-layout.h"
#include "rtl9617c-l2qm.h"
struct rtl_qm_rx {
 void *ni,*axi_reorder,*block_reset,*ring_memory,*memory,*deepq_memory,*device;
 dma_addr_t ring_dma,memory_dma,deepq_dma;
 unsigned read[8],trace_count,next_voq;
 void *lan[5];bool deepq_configured;
 struct rtl_qm_refill refill;
};
static u32 regs[65536/4],axi[4096/4],reset_word;
static unsigned char rings[16*1024],payload_token,deepq_token,device_token;
static unsigned reads,writes,reset_writes,retire_writes,syncs,pushes;
static unsigned read_at[8192],fault_read,ignore_write,ignore_nth,ignored;
static unsigned reg_reads[65536/4],reg_writes[65536/4];
static bool fault_seen,stop_mode;
static const u32 foreign_reset=BIT(1)|BIT(3)|BIT(6)|BIT(9)|BIT(12)|BIT(19);
static const unsigned windows[]={
 0x66a4,0x1654,0x11dc,0x11e4,0x1b0c,0x1b44,0x1e04,0x1e14,
 0x1420,0x95a8,0x95b0,0x95c0,0x2db4
};
static unsigned reg_offset(void *p) {
 uintptr_t value=(uintptr_t)p,start=(uintptr_t)regs;
 assert(value>=start && value<start+sizeof(regs) && !(value&3));
 return value-start;
}
static u32 readl(void *p) {
 unsigned r=p==&reset_word?65536:reg_offset(p);
 assert(reads<ARRAY_SIZE(read_at));read_at[reads++]=r;
 if(r<65536)reg_reads[r/4]++;
 if(reads==fault_read){fault_seen=true;return ~0U;}
 return p==&reset_word?reset_word:regs[r/4];
}
static unsigned change_mask(unsigned r) {
 switch(r) {
 case 0x950c:case 0x6104:case 0x6108:return BIT(31);
 case 0x610c:case 0xa1dc:case 0xa1ec:return 0xffff;
 case 0x68f8:return 15;
 case 0x68b0:return 0xc8000000U;
 case 0x6000:return BIT(11)|BIT(13)|0xff;
 case 0x68f4:case 0x9004:return BIT(2);
 case 0x658c:return 0x1fffffff;
 case 0xa1bc:return 0xff;
 case 0x1404:case 0x95a0:return 3;
 case 0x2300:return BIT(8)|BIT(9);
 default:return ~0U;
 }
}
static void writel(u32 value,void *p) {
 /* Once a startup prerequisite failed, no further publication is safe.
  * Stop is best effort: a failed gate must not block other known gates. */
 assert(!fault_seen || stop_mode);
 writes++;
 if(p==&reset_word) {
  assert(((value^reset_word)&~BIT(5))==0);
  assert((value&~BIT(5))==foreign_reset);
  reset_word=value;reset_writes++;return;
 }
 uintptr_t address=(uintptr_t)p;
 if(address>=(uintptr_t)axi && address<(uintptr_t)axi+sizeof(axi)) {
  assert(!(address&3));*(u32 *)p=value;return;
 }
 unsigned r=reg_offset(p),mask=change_mask(r);
 reg_writes[r/4]++;
 if(r!=0x6108 || value!=0x8462ff01U)assert(!((value^regs[r/4])&~mask));
 if((r==0x6108 || r==0x6104) && (value&BIT(31)))assert(!(regs[0x610c/4]&0xffff));
 if(r==ignore_write && reg_writes[r/4]==ignore_nth){ignored++;return;}
 if(r==0x636c) {
  unsigned eq=value&15,index=pushes++;
  assert(index<1024 && eq==4+index/512);
  assert((value&~127U)==0x04000000U+index*2048U);
  assert(regs[(0x6328+eq*4)/4] && (regs[0x6368/4]&BIT(31)));
  regs[(0x6328+eq*4)/4]--;
 }
 if(r>=0x7100 && r<0x7120){assert(value<2048 && !(value&7));retire_writes++;}
 for(unsigned i=0;i<ARRAY_SIZE(windows);i++)if(r==windows[i]) {
  assert((value&0xc0000000U)==0xc0000000U);value&=~BIT(31);break;
 }
 regs[r/4]=value;
}
#define readl_poll_timeout(p,value,condition,delay,timeout) \
 ({ (value)=readl(p);(condition)?0:-ETIMEDOUT; })
#define readl_poll_timeout_atomic readl_poll_timeout
static void udelay(unsigned value){assert(value==1000);}
static void dma_sync_single_for_device(void *device,dma_addr_t address,unsigned n,int direction) {
 assert(device==&device_token && direction==DMA_FROM_DEVICE);
 assert(retire_writes==8 && !fault_seen);
 if(address==0x06000000U) {
  assert(n==sizeof(rings));for(unsigned i=0;i<n;i++)assert(!rings[i]);
 } else assert(address==0x04000000U && n==2*1024*1024);
 syncs++;
}
'''

CASES = r'''
static void setup(struct rtl_qm_rx *rx) {
 memset(regs,0,sizeof(regs));memset(axi,0,sizeof(axi));memset(rings,0xcc,sizeof(rings));
 memset(rx,0,sizeof(*rx));memset(reg_reads,0,sizeof(reg_reads));memset(reg_writes,0,sizeof(reg_writes));
 reads=writes=reset_writes=retire_writes=syncs=pushes=ignored=0;
 fault_read=ignore_write=ignore_nth=~0U;fault_seen=stop_mode=false;reset_word=foreign_reset;
 rx->ni=regs;rx->axi_reorder=axi;rx->block_reset=&reset_word;
 rx->memory=&payload_token;rx->deepq_memory=&deepq_token;rx->ring_memory=rings;rx->device=&device_token;
 rx->memory_dma=0x04000000;rx->ring_dma=0x06000000;rx->deepq_dma=0x12000000;
 rx->lan[0]=rx->lan[1]=rx->lan[2]=rx->lan[3]=rx->lan[4]=&device_token;
 rx->deepq_configured=true;rx->trace_count=99;rx->next_voq=99;
 regs[0x950c/4]=0x81b23456U;regs[0x6104/4]=0x84556677U;regs[0x6108/4]=0x862aff01U;
 regs[0x610c/4]=0xa5a5ffffU;regs[0x68f8/4]=0x12345003U;regs[0x68b0/4]=0xc855aa11U;
 regs[0x6000/4]=0x551f3312U;regs[0x68f4/4]=0xa5000100U;regs[0x658c/4]=0xc0000012U;
 regs[0xa1bc/4]=0xa5a534abU;regs[0xa1dc/4]=0x35a5ffffU;regs[0xa1ec/4]=0x55a5ffffU;
 regs[0x1404/4]=0x37550000U;regs[0x95a0/4]=0x5a551103U;regs[0x2300/4]=0x75442001U;
 regs[0x9004/4]=0x31554400U;regs[0x6850/4]=BIT(30);regs[0x6368/4]=BIT(31);
 regs[0x6338/4]=regs[0x633c/4]=512;
 for(unsigned q=0;q<8;q++){regs[(0x7000+q*4)/4]=(q*29+3)*8;regs[(0x7100+q*4)/4]=2040;}
}
static void owner_retained(struct rtl_qm_rx *rx) {
 assert(!rx->deepq_configured);
 assert(rx->memory==&payload_token && rx->deepq_memory==&deepq_token && rx->ring_memory==rings);
 assert(rx->memory_dma==0x04000000 && rx->ring_dma==0x06000000 && rx->deepq_dma==0x12000000);
 assert((reset_word&~BIT(5))==foreign_reset);
}
int main(void) {
 struct rtl_qm_rx rx;unsigned cases=0;
 setup(&rx);assert(!rtl_qm_rx_start(&rx,0));
 assert(rx.deepq_configured && reset_word==foreign_reset && reset_writes==2);
 assert(retire_writes==8 && syncs==2 && pushes==1024 && rx.next_voq==7 && !rx.trace_count);
 assert(!(regs[0x610c/4]&0xffff) && (regs[0x950c/4]&BIT(31)) && (regs[0x6104/4]&BIT(31)));
 unsigned success_reads=reads;assert(success_reads>2048 && success_reads<8192);cases++;
 /* Includes both reset reads; all startup RMWs; preflight/readback of
  * every EPP; all 1024 released-BID and FIFO checks; indirect staging
  * prerequisites/completions; DQ admission and final PUC gate readbacks. */
 for(unsigned fail=1;fail<=success_reads;fail++) {
  setup(&rx);fault_read=fail;
  assert(rtl_qm_rx_start(&rx,0)<0 && fault_seen);owner_retained(&rx);
  if(fail<=4)assert(reads==4 && !writes && !reset_writes && !syncs && !pushes);
  cases++;
 }
 /* Reject all pointer faults before retiring even one old queue. The
  * next warm reopen must never republish these partially exposed pools. */
 const unsigned bad_pointers[]={~0U,2048,7,0xffffff};
 for(unsigned q=0;q<8;q++)for(unsigned i=0;i<ARRAY_SIZE(bad_pointers);i++) {
  setup(&rx);regs[(0x7000+q*4)/4]=bad_pointers[i];
  assert(rtl_qm_rx_start(&rx,0)==-EIO && !retire_writes && !syncs && !pushes);
  owner_retained(&rx);cases++;
 }
 /* A discarded RDPTR write must fail before ring clear/cache ownership
  * transfer; checking only the last queue would miss the first seven. */
 for(unsigned q=0;q<8;q++) {
  setup(&rx);ignore_write=0x7100+q*4;ignore_nth=1;
  assert(rtl_qm_rx_start(&rx,0)==-EIO && ignored==1 && !syncs && !pushes);
  owner_retained(&rx);cases++;
 }
 setup(&rx);ignore_write=0x610c;ignore_nth=1;
 assert(rtl_qm_rx_start(&rx,0)==-EIO && ignored==1 && !retire_writes && !syncs && !pushes);
 owner_retained(&rx);cases++;
 /* Healthy stop closes only known gates; a failed read is skipped while
  * the other gates are still attempted. Neither outcome proves DMA drain. */
 const unsigned gates[]={0x950c,0x610c,0x6104,0x6108};
 for(unsigned fail=0;fail<=4;fail++) {
  setup(&rx);stop_mode=true;fault_read=fail?fail:~0U;
  rtl_qm_rx_stop(&rx);owner_retained(&rx);
  assert(reads==4 && writes==4-(fail!=0) && !reset_writes);
  for(unsigned i=0;i<4;i++) {
   unsigned mask=i==1?0xffffU:BIT(31);
   if(fail==i+1)assert(!reg_writes[gates[i]/4] && (regs[gates[i]/4]&mask));
   else assert(reg_writes[gates[i]/4]==1 && !(regs[gates[i]/4]&mask));
  }
  cases++;
 }
 printf("QM startup: %u cases; all %u actual MMIO reads fault-injected, foreign reset bits retained, invalid/unretired EPPs never published, failed owners retained\n",cases,success_reads);
}
'''


def run(production, name):
    with tempfile.TemporaryDirectory(prefix='qm-startup-fault-', dir=ROOT / 'artifacts') as temp:
        path = Path(temp)
        source, exe = path / 'test.c', path / 'test'
        source.write_text(SHIM + production + CASES)
        subprocess.run(['cc', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-parameter', '-fsanitize=address,undefined',
                        '-I', str(DRIVER),
                        '-I', str(ROOT / 'port/overlay/target/linux/rtl9617c/files-6.18/include/linux'),
                        str(source), '-o', str(exe)], check=True)
        result = subprocess.run([str(exe)], capture_output=True, text=True)
        if name == 'production':
            if result.returncode:
                raise SystemExit(result.stdout + result.stderr)
            print(result.stdout.strip())
        else:
            assert result.returncode and 'Assertion' in result.stderr, result
            print('QM startup mutation rejected:', name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    source = (DRIVER / 'rtl9617c-qm.c').read_text()
    constants = source[source.index('#define EQ_ID'):source.index('static int rtl_qm_rmw')]
    production = constants + ''.join(function(source, name) for name in (
        'rtl_qm_rmw', 'rtl_qm_window_idle', 'rtl_qm_indirect', 'rtl_qm_attribute',
        'rtl_qm_pon_destination_map', 'rtl_qm_push', 'rtl_qm_ingress',
        'rtl_dq_read', 'rtl_dq_write', 'rtl_dq_indirect', 'rtl_qm_axi_reorder',
        'rtl_qm_cpu_credits', 'rtl_qm_rx_start', 'rtl_qm_rx_stop'))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    run(production, 'production')
    if args.mutants:
        mutations = {
            'skip_first_read_preflight': ('if (cb == ~0U || rmu == ~0U || es == ~0U || reset == ~0U)', 'if (false)'),
            'reflect_failed_rmw': ('if (value == ~0U)', 'if (false)'),
            'mask_invalid_epp': ('if (value >= RTL_QM_RING_BYTES || (value & (RTL_QM_COMMAND_BYTES - 1)))', 'if (false)'),
            'ignore_epp_retirement_readback': ('if (value != rx->read[i])', 'if (false)'),
            'ignore_puc_gate_readback': ('if (value == ~0U || (value & 0xffffU))', 'if (false)'),
        }
        for name, (before, after) in mutations.items():
            assert before in production, (name, 'target drift')
            run(production.replace(before, after, 1), name)


if __name__ == '__main__':
    main()
