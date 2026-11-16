#!/usr/bin/env python3
"""Execute CPU EQ refill with real credit depletion and independent FIFO stalls."""
from pathlib import Path
import argparse
import resource
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
driver = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', type=Path)
parser.add_argument('--mutants', action='store_true')
args = parser.parse_args()
source = (args.source or driver / 'rtl9617c-qm.c').read_text()
start = source.index('static int rtl_qm_push(')
end = source.index('\nstatic int rtl_qm_ingress(', start)
model = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define EQ_ID 4
#define CPU_READY 0x6368
#define CPU_PUSH 0x636c
#include "rtl9617c-qm-refill.h"
struct rtl_qm_rx {void *ni;struct rtl_qm_refill refill;};
static u32 registers[0x10000/4],credit[2],reads[2],fifo_reads,pushed[2],stop_after,add_after,ready;
static bool bad_ready;
static u32 readl(void *p) {
 unsigned reg=(char *)p-(char *)registers;
 if(reg==0x6338||reg==0x633c){unsigned eq=(reg-0x6338)/4;reads[eq]++;return credit[eq];}
 assert(reg==CPU_READY);fifo_reads++;return bad_ready?~0U:(ready?BIT(31):0);
}
#define readl_poll_timeout_atomic(p,status,condition,interval,timeout) \
 ({ (status)=readl(p);(condition)?0:-ETIMEDOUT; })
static void writel(u32 value,void *p) {
 assert((char *)p-(char *)registers==CPU_PUSH);
 unsigned eq=(value&15)-4;assert(eq<2&&ready&&credit[eq]);
 assert((value&~127U)==0x4000000+eq*0x100000+pushed[eq]*2048);
 pushed[eq]++;credit[eq]--;
 if(pushed[0]+pushed[1]==add_after)credit[0]+=64;
 if(pushed[0]+pushed[1]==stop_after)ready=0;
}
"""
cases = r"""
static void setup(struct rtl_qm_rx *rx,unsigned n0,unsigned n1,unsigned c0,unsigned c1) {
 memset(rx,0,sizeof(*rx));rx->ni=registers;
 memset(reads,0,sizeof(reads));memset(pushed,0,sizeof(pushed));fifo_reads=0;
 credit[0]=c0;credit[1]=c1;ready=1;bad_ready=false;stop_after=add_after=~0U;
 for(unsigned e=0;e<2;e++)for(unsigned i=0;i<(e?n1:n0);i++)
  rtl_qm_refill_add(&rx->refill,(0x4000000+e*0x100000+i*2048)|(e+4));
}
int main(void) {
 struct rtl_qm_rx rx;unsigned count=0;
 for(unsigned c0=0;c0<=64;c0+=8)for(unsigned c1=0;c1<=64;c1+=8)
 for(unsigned stop=0;stop<=64;stop+=8){
  setup(&rx,64,64,c0,c1);stop_after=stop;if(!stop)ready=0;
  rtl_qm_refill_drain(&rx.refill,&rx,rtl_qm_try_push,64);
  assert(pushed[0]<=c0&&pushed[1]<=c1&&pushed[0]+pushed[1]<=64);
  assert(rx.refill.pending+rx.refill.returned==128);
  assert(rx.refill.eq_peak[0]==64 && rx.refill.eq_peak[1]==64);
  assert(rx.refill.eq_returned[0]==pushed[0] && rx.refill.eq_returned[1]==pushed[1]);
  assert(rx.refill.eq_retries[0]+rx.refill.eq_retries[1]==rx.refill.retries);
  assert(rx.refill.count[0]+pushed[0]==64&&rx.refill.count[1]+pushed[1]==64);
  /* Each later poll takes fresh credit; all retained suffixes drain once. */
  credit[0]=credit[1]=64;ready=1;stop_after=~0U;
  while(rx.refill.pending)rtl_qm_refill_drain(&rx.refill,&rx,rtl_qm_try_push,64);
  assert(pushed[0]==64&&pushed[1]==64&&rx.refill.returned==128);count++;
  assert(rx.refill.eq_returned[0]==64&&rx.refill.eq_returned[1]==64);
 }
 setup(&rx,64,0,64,0);rtl_qm_refill_drain(&rx.refill,&rx,rtl_qm_try_push,64);
 unsigned full_reads=reads[0];assert(pushed[0]==64&&fifo_reads==64);
 setup(&rx,64,0,8,0);add_after=8;rtl_qm_refill_drain(&rx.refill,&rx,rtl_qm_try_push,64);
 assert(pushed[0]==64&&reads[0]>=2); /* New credit is observed on exhaustion. */
 setup(&rx,2,0,64,0);rtl_qm_refill_drain(&rx.refill,&rx,rtl_qm_try_push,64);
 /* Unused cached allowance must not survive a later call. */
 rtl_qm_refill_add(&rx.refill,(0x4000000+2*2048)|4);credit[0]=0;
 unsigned before=reads[0];rtl_qm_refill_drain(&rx.refill,&rx,rtl_qm_try_push,64);
 assert(pushed[0]==2&&rx.refill.pending==1&&reads[0]==before+1);
 credit[0]=1;rtl_qm_refill_drain(&rx.refill,&rx,rtl_qm_try_push,64);assert(pushed[0]==3);
 setup(&rx,64,64,0,64);rtl_qm_refill_drain(&rx.refill,&rx,rtl_qm_try_push,64);
 assert(!pushed[0]&&pushed[1]==63&&rx.refill.count[0]==64);
 /* Both expanded pools may be entirely CPU-owned while PUSH is blocked.
  * Wrap at every queue head, then resume each full 512-entry pool exactly
  * once. This catches the old independent 256-slot software queue. */
 assert(RTL_QM_BUFFERS_PER_EQ==512 && RTL_QM_REFILL_SIZE>=512);
 for(unsigned head=0;head<512;head++) {
  setup(&rx,0,0,0,0);rx.refill.head[0]=head;rx.refill.head[1]=511-head;
  for(unsigned e=0;e<2;e++)for(unsigned i=0;i<512;i++)
   rtl_qm_refill_add(&rx.refill,(0x4000000+e*0x100000+i*2048)|(e+4));
  assert(rx.refill.pending==1024 && rx.refill.peak==1024);
  assert(rx.refill.eq_peak[0]==512 && rx.refill.eq_peak[1]==512);
  rtl_qm_refill_drain(&rx.refill,&rx,rtl_qm_try_push,64);
  assert(!pushed[0] && !pushed[1] && rx.refill.pending==1024);
  credit[0]=credit[1]=512;
  for(unsigned poll=0;rx.refill.pending && poll<32;poll++)
   rtl_qm_refill_drain(&rx.refill,&rx,rtl_qm_try_push,64);
  assert(!rx.refill.pending && rx.refill.returned==1024 && pushed[0]==512 && pushed[1]==512);
  assert(rx.refill.head[0]==head && rx.refill.head[1]==511-head);
  count++;
 }
 printf("%u dual-EQ credit/FIFO/resume cases; full64 EQ reads=%u, FIFO reads=64; cross-drain reset and EQ isolation passed\n",count,full_reads);
 assert(full_reads==1);
 /* All-ones and impossible released-BID counts must preserve ownership,
  * both during cold publication and within the live refill loop. The
  * independently healthy EQ still makes progress after an EQ4 fault. */
 const unsigned corrupt[]={~0U,513U,16383U};
 for(unsigned i=0;i<sizeof(corrupt)/sizeof(*corrupt);i++)for(unsigned eq=0;eq<2;eq++) {
  setup(&rx,0,0,0,0);credit[eq]=corrupt[i];
  assert(rtl_qm_push(&rx,0x4000000+eq*0x100000,eq+4)==-EIO);
  assert(!pushed[0] && !pushed[1] && !fifo_reads && rx.refill.eq_bad_credit[eq]==1);
  setup(&rx,1,1,1,1);credit[eq]=corrupt[i];
  rtl_qm_refill_drain(&rx.refill,&rx,rtl_qm_try_push,64);
  assert(rx.refill.count[eq]==1 && rx.refill.count[eq^1]==0);
  assert(rx.refill.pending==1 && !pushed[eq] && pushed[eq^1]==1);
  assert(rx.refill.eq_bad_credit[eq]==1 && rx.refill.eq_retries[eq]==1);
  credit[eq]=1;rtl_qm_refill_drain(&rx.refill,&rx,rtl_qm_try_push,64);
  assert(!rx.refill.pending && pushed[eq]==1 && pushed[eq^1]==1);
  count++;
 }
 setup(&rx,0,0,1,1);bad_ready=true;
 assert(rtl_qm_push(&rx,0x4000000,4)==-EIO && !pushed[0] && rx.refill.eq_bad_ready[0]==1);
 setup(&rx,1,1,1,1);bad_ready=true;
 rtl_qm_refill_drain(&rx.refill,&rx,rtl_qm_try_push,64);
 assert(rx.refill.pending==2 && !pushed[0] && !pushed[1]);
 assert(rx.refill.eq_bad_ready[0]==1 && rx.refill.eq_bad_ready[1]==1);
 bad_ready=false;rtl_qm_refill_drain(&rx.refill,&rx,rtl_qm_try_push,64);
 assert(!rx.refill.pending && pushed[0]==1 && pushed[1]==1);count++;
 /* Preserve legal non-count bits instead of requiring a magic whole word. */
 setup(&rx,0,0,0x40000001U,0);
 assert(!rtl_qm_push(&rx,0x4000000,4) && pushed[0]==1);
 setup(&rx,1,0,0x40000001U,0);rtl_qm_refill_drain(&rx.refill,&rx,rtl_qm_try_push,64);
 assert(!rx.refill.pending && pushed[0]==1 && !rx.refill.eq_bad_credit[0]);count++;
 setup(&rx,0,0,1,1);
 assert(rtl_qm_push(&rx,0x4000000,3)==-EINVAL && rtl_qm_push(&rx,0x4000000,6)==-EINVAL);
 assert(rtl_qm_try_push(&rx,0x4000000,3)==-EINVAL && rtl_qm_try_push(&rx,0x4000000,6)==-EINVAL);
 assert(!reads[0] && !reads[1] && !fifo_reads);count++;
 /* At high packet rates 32-bit totals wrap within a long-running capture.
  * Pending/peak stay bounded gauges; cumulative events must cross 2^32. */
 setup(&rx,1,0,1,0);rx.refill.returned=rx.refill.eq_returned[0]=0xffffffffULL;
 rx.refill.retries=rx.refill.eq_retries[0]=0xffffffffULL;ready=0;
 rtl_qm_refill_drain(&rx.refill,&rx,rtl_qm_try_push,64);
 assert(rx.refill.retries==0x100000000ULL && rx.refill.eq_retries[0]==0x100000000ULL);
 ready=1;rtl_qm_refill_drain(&rx.refill,&rx,rtl_qm_try_push,64);
 assert(rx.refill.returned==0x100000000ULL && rx.refill.eq_returned[0]==0x100000000ULL);
 count++;
 printf("QM refill faults: cold/live all-ones, over-capacity credits, invalid EQs, recovery, 64-bit totals PASS (%u total cases)\n",count);
}
"""


def run(production, name):
    with tempfile.TemporaryDirectory(prefix='qm-refill-credit-', dir=root / 'artifacts') as temp:
        c, exe = Path(temp) / 'test.c', Path(temp) / 'test'
        c.write_text(model + production + cases)
        subprocess.run(['cc', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-I', str(driver), str(c), '-o', str(exe)], check=True)
        result = subprocess.run([str(exe)], capture_output=True, text=True)
        if name == 'production':
            if result.returncode:
                raise SystemExit(result.stdout + result.stderr)
            print(result.stdout.strip())
        else:
            assert result.returncode and 'Assertion' in result.stderr, result
            print(f'QM refill mutation rejected: {name}')


resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
production = source[start:end]
run(production, 'production')
if args.mutants:
    mutations = {
        'accept_corrupt_credits': ('status == ~0U || (status & GENMASK(13, 0)) > RTL_QM_BUFFERS_PER_EQ',
                                  '(status & GENMASK(13, 0)) == 0'),
        'accept_all_ones_ready': ('if (status == ~0U)', 'if (status == 0)'),
    }
    for name, (before, after) in mutations.items():
        assert production.count(before) == 2, (name, 'target drift')
        run(production.replace(before, after), name)
