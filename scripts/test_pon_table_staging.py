#!/usr/bin/env python3
"""Execute production PON table writers with a still-busy previous request.

The host MMIO model treats timeout as an outstanding hardware operation, not
as cancellation. This is an ownership/ordering regression, not silicon timing
or an optical throughput test. --revision runs the same oracle on older code.
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
    start = re.search(r'^.*\b' + name + r'\([^;]*?\)\s*\{', source, re.M).start()
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
typedef uint64_t u64;
#define BIT(n) (1U<<(n))
#define dev_err(...) ((void)0)
struct rtl9617c_pon {void *mac,*dev;};
static u32 regs[0x10000/4];
static unsigned int writes,requests,hold;
static u32 readl(const void *address){return *(const u32 *)address;}
static bool access_register(unsigned int offset){
 switch(offset){
 case 0x8000:case 0x8060:case 0x81c4:case 0x81ec:case 0x802c:
 case 0x80dc:case 0x80e8:case 0x612c:return true;
 default:return false;
 }
}
static void writel(u32 value,void *address){
 unsigned int offset=(unsigned char *)address-(unsigned char *)regs;
 writes++;
 if(access_register(offset)){
  requests++;
  if(offset!=hold)value&=~BIT(31);
 }
 *(u32 *)address=value;
}
#define readl_poll_timeout(p,v,condition,delay,timeout) ({(v)=readl(p);(condition)?0:-ETIMEDOUT;})
#include "rtl9617c-epon-sla.h"
'''

test = r'''
static void reset(void){memset(regs,0,sizeof(regs));writes=requests=hold=0;}
int main(void){
 struct rtl9617c_pon pon={.mac=regs};
 const struct rtl_dq_io io={&pon,rtl_puc_bp_read,rtl_puc_bp_write,rtl_puc_bp_access};
 const unsigned char weights[8]={1,1,2,3,0,0,0,0};
 /* Already-busy PVT must preserve all five staging words. */
 reset();regs[0x8000/4]=BIT(31)|1;regs[0x8014/4]=0x12345678;
 assert(rtl_puc_port(&pon,1,8,true)==-EBUSY);
 assert(!writes && !requests && regs[0x8014/4]==0x12345678);
 assert(rtl_itu_puc_tcont_weights(&io,1,255,weights)==-EBUSY && !writes);
 assert(rtl_puc_access(&pon,0x8000,2,false)==-EBUSY && !writes);
 /* A real submitted request times out, then a retry leaves its DATA alone. */
 reset();hold=0x8000;
 assert(rtl_puc_port(&pon,1,8,true)==-ETIMEDOUT);
 u32 pvt[5];memcpy(pvt,regs+0x8004/4,sizeof(pvt));unsigned int before=writes;
 assert(rtl_puc_port(&pon,2,4,true)==-EBUSY && writes==before);
 assert(!memcmp(pvt,regs+0x8004/4,sizeof(pvt)));
 regs[0x8000/4]&=~BIT(31);hold=0;
 assert(!rtl_puc_port(&pon,2,4,true));
 /* VSTBL busy must not partially publish the matching PVT policy. */
 reset();regs[0x8060/4]=BIT(31)|1;
 assert(rtl_itu_puc_schedule(&io,1,255,weights)==-EBUSY && !writes);
 regs[0x8060/4]=0;assert(!rtl_itu_puc_schedule(&io,1,255,weights));
 /* CIR/PIR staging words are separately owned by their access engines. */
 reset();regs[0x81c4/4]=BIT(31);regs[0x81cc/4]=0x11111111;regs[0x81c8/4]=0x22222222;
 assert(rtl_puc_token_buckets(&pon,255)==-EBUSY && !writes);
 assert(regs[0x81cc/4]==0x11111111 && regs[0x81c8/4]==0x22222222);
 reset();regs[0x81ec/4]=BIT(31);regs[0x81f4/4]=0x33333333;regs[0x81f0/4]=0x44444444;
 assert(rtl_puc_token_buckets(&pon,255)==-EBUSY);
 assert(regs[0x81f4/4]==0x33333333 && regs[0x81f0/4]==0x44444444);
 reset();assert(!rtl_puc_token_buckets(&pon,255) && requests==2);
 /* Flush may retain selector/drop state until its prior operation completes. */
 reset();regs[0x80dc/4]=BIT(31)|8;regs[0x80e0/4]=0x56781234;
 assert(rtl_epon_sla_flush(&io,1,8)==-EBUSY && !writes);
 assert(regs[0x80e0/4]==0x56781234);
 /* Read commands must not replace a pending ITU access command either. */
 reset();regs[0x612c/4]=BIT(31)|1024;
 assert(path_access(&pon,0x612c,BIT(31)|1025)==-EBUSY && !writes);
 regs[0x612c/4]=0;assert(!path_access(&pon,0x612c,BIT(31)|1025));
 puts("PON tables: PVT/VSTBL/CIR/PIR/flush/ITU busy staging and post-timeout retry ownership passed");
}
'''

puc = read('rtl9617c-pon-puc.c')
constants = '\n'.join(re.findall(r'^#define .*$', puc, re.M))
functions = ''.join(function(puc, name) for name in (
    'rtl_puc_access', 'rtl_puc_port', 'rtl_puc_token_buckets',
    'rtl_puc_bp_read', 'rtl_puc_bp_write', 'rtl_puc_bp_access'))
functions += function(read('rtl9617c-pon-path.c'), 'path_access')
with tempfile.TemporaryDirectory(prefix='pon-table-staging-') as directory:
    work = Path(directory)
    for name in ('rtl9617c-epon-sla.h', 'rtl9617c-pon-itu-puc.h',
                 'rtl9617c-pon-queue.h', 'rtl9617c-qm-deepq.h'):
        (work / name).write_text(read(name))
    cfile = work / 'test.c'
    binary = work / 'test'
    cfile.write_text(fixture + constants + '\n' + functions + test)
    subprocess.run(['cc', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    '-I', str(work), str(cfile), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
