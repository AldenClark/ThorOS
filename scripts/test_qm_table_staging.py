#!/usr/bin/env python3
"""Fault-inject live ACCESS ownership into actual QM/DQ startup table writers.

The RTL77C generated register declarations define ACCESS[31]/rbw[30] and
shared DATA windows. A host timeout does not cancel that hardware command.
This tests safe retry ordering, not hardware completion timing. --revision
allows the same independent busy-window model to reject an older version.
"""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
drivers = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--revision')
args = parser.parse_args()


def read(name):
    if args.revision:
        path = (drivers / name).relative_to(root)
        return subprocess.check_output(['git', 'show', f'{args.revision}:{path}'], cwd=root, text=True)
    return (drivers / name).read_text()


def function(source, name):
    match = re.search(r'^.*\b' + name + r'\([^;]*?\)\s*\{', source, re.M)
    if not match:
        return ''  # Old revisions do not have the idle helper.
    start = match.start()
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


source = read('rtl9617c-qm.c')
production = ''.join(function(source, name) for name in (
    'rtl_qm_window_idle', 'rtl_qm_indirect', 'rtl_qm_attribute',
    'rtl_qm_pon_destination_map', 'rtl_qm_ingress', 'rtl_qm_cpu_credits',
    'rtl_dq_read', 'rtl_dq_write', 'rtl_dq_indirect'))
start = source.index('\t/* The vendor credit table marks counter MSBs valid')
end = source.index('\t/* Enable both CPU forwarding', start)
production += 'static int credits(struct rtl_qm_rx *rx) { void *ni=rx->ni;unsigned i;int ret;\n'
production += source[start:end] + '\nreturn 0;}\n'
fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define RTL_QM_BUFFERS_PER_EQ 256
#define RTL_QM_VOQS 8
#define EQ_ID 4
#include "rtl9617c-qm-deepq.h"
struct rtl_qm_rx {void *ni;};
static u32 regs[65536/4];
static unsigned held,writes[65536/4],requests[65536/4];
/* Register windows taken from the generated silicon header, not the driver. */
struct window {unsigned access,first,last;};
static const struct window windows[]={
 {0x66a4,0x66a8,0x66ac},{0x1654,0x1658,0x1658},
 {0x11dc,0x11e0,0x11e0},{0x11e4,0x11e8,0x11f8},
 {0x1b0c,0x1b10,0x1b40},{0x1b44,0x1b48,0x1b58},
 {0x1e04,0x1e08,0x1e10},{0x1e14,0x1e18,0x1e20},
 {0x1420,0x1424,0x1428},{0x95a8,0x95ac,0x95ac},
 {0x95b0,0x95b4,0x95bc},{0x95c0,0x95c4,0x95c4},
 {0x2db4,0x2db8,0x2db8}
};
static u32 readl(void *p) {return *(u32 *)p;}
static void writel(u32 v,void *p) {
 unsigned r=(char *)p-(char *)regs;
 assert(r<65536 && !(r&3));
 for(unsigned i=0;i<ARRAY_SIZE(windows);i++) {
  const struct window *w=windows+i;
  if(r>=w->first && r<=w->last)assert(!(regs[w->access/4]&BIT(31)));
  if(r==w->access) {
   assert(!(regs[r/4]&BIT(31)));requests[r/4]++;
   assert((v&(BIT(31)|BIT(30)))==(BIT(31)|BIT(30)));
   if(r!=held)v&=~BIT(31);
  }
 }
 writes[r/4]++;*(u32 *)p=v;
}
#define readl_poll_timeout(p,v,condition,delay,timeout) ({(v)=readl(p);(condition)?0:-ETIMEDOUT;})
'''
cases = r'''
static int call(struct rtl_qm_rx *rx,unsigned kind) {
 const struct rtl_dq_io io={rx,rtl_dq_read,rtl_dq_write,rtl_dq_indirect};
 switch(kind) {
 case 0:return rtl_qm_attribute(rx,48,0xa008060);
 case 1:return rtl_qm_pon_destination_map(rx);
 case 2:return rtl_qm_ingress(rx,3);
 case 3:return rtl_qm_cpu_credits(rx);
 case 4:return rtl_qm_deepq_prepare(&io,0x12000000);
 case 5:return credits(rx);
 default:assert(false);return -EINVAL;
 }
}
static void reset(void) {memset(regs,0,sizeof(regs));memset(writes,0,sizeof(writes));memset(requests,0,sizeof(requests));held=0;}
int main(void) {
 struct rtl_qm_rx rx={.ni=regs};
 const unsigned checks[][2]={
 {0,0x66a4},{1,0x1654},{2,0x1654},{2,0x11dc},{2,0x11e4},
 {2,0x1b0c},{2,0x1b44},{2,0x1e04},{2,0x1e14},{2,0x1420},
 {3,0x95a8},{3,0x95b0},{3,0x95c0},
 {4,0x95a8},{4,0x95b0},{4,0x95c0},{5,0x2db4}};
 for(unsigned kind=0;kind<6;kind++){reset();assert(call(&rx,kind)==0);}
 for(unsigned i=0;i<ARRAY_SIZE(checks);i++) {
  unsigned kind=checks[i][0],reg=checks[i][1];
  reset();regs[reg/4]=BIT(31)|BIT(30)|1;
  assert(call(&rx,kind)==-EBUSY && !writes[reg/4] && !requests[reg/4]);
  assert(regs[reg/4]==(BIT(31)|BIT(30)|1));
  reset();held=reg;
  assert(call(&rx,kind)==-ETIMEDOUT && requests[reg/4]==1 && (regs[reg/4]&BIT(31)));
  /* A host timeout did not relinquish hardware ownership. Retry must not stage. */
  assert(call(&rx,kind)==-EBUSY && requests[reg/4]==1);
  /* Only a real completion lets a subsequent initialization proceed. */
  held=0;regs[reg/4]&=~BIT(31);assert(call(&rx,kind)==0);
 }
 printf("QM staging: %zu writers/windows reject busy DATA/ACCESS overwrite; timeout/retry/actual completion and healthy startup passed\n",ARRAY_SIZE(checks));
}
'''
with tempfile.TemporaryDirectory(prefix='qm-staging-', dir=root / 'artifacts') as temp:
    path = Path(temp)
    (path / 'rtl9617c-qm-deepq.h').write_text(read('rtl9617c-qm-deepq.h'))
    c, exe = path / 'test.c', path / 'test'
    c.write_text(fixture + production + cases)
    subprocess.run(['cc', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-I', str(path), str(c), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
