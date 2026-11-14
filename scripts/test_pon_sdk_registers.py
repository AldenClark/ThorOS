#!/usr/bin/env python3
"""Decode production PON table writes using an independently supplied RTL77C SDK.

Run with --sdk-header /path/to/rtl8277c_registers.h. The reviewed reference is
jameywine/GPL-for-GP3000 5090fbcb (silicon header selected by the Taurus wrapper),
not the FPGA header. Vendor declarations are extracted at runtime: this test
does not substitute locally invented field layouts for the SDK. It verifies
register encoding, not actual silicon timing, scheduling or optical throughput.
"""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--sdk-header', type=Path, required=True)
args = parser.parse_args()
expected = 'ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0'
observed = hashlib.sha256(args.sdk_header.read_bytes()).hexdigest()
if observed != expected:
    raise SystemExit(f'SDK pin mismatch: {args.sdk_header.name}: {observed}; expected {expected}')
root = Path(__file__).resolve().parents[1]
drivers = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
sdk = args.sdk_header.read_text()


def declaration(name):
    end = sdk.index('} ' + name + ';') + len('} ' + name + ';')
    start = sdk.rfind('typedef volatile union {', 0, end)
    assert start >= 0
    return sdk[start:end] + '\n'


def function(source, name):
    start = re.search(r'^.*\b' + name + r'\([^;]*?\)\s*\{', source, re.M).start()
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


names = ['PDC_PDC_MAP_MEM_ACCESS_t', 'PDC_PDC_MAP_MEM_DATA0_t',
         'PDC_PDC_MAP_MEM_DATA1_t', 'PUC_PVTBL_ACCESS_t', 'PUC_VSTBL_ACCESS_t',
         'PUC_VOQ_TBC_MEM_ACCESS_t', 'PUC_VOQ_TBC_MEM_DATA0_t',
         'PUC_VOQ_TBC_MEM_DATA1_t', 'PUC_PIR_VOQ_TBC_MEM_ACCESS_t',
         'PUC_PIR_VOQ_TBC_MEM_DATA0_t', 'PUC_PIR_VOQ_TBC_MEM_DATA1_t']
names += [f'PUC_PVTBL_DATA{i}_t' for i in range(5)]
names += [f'PUC_VSTBL_DATA{i}_t' for i in range(5)]
declarations = ''.join(declaration(name) for name in names)
fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint32_t ca_uint32_t;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
struct rtl9617c_pon {void *mac;};
static u32 regs[0x10000/4],pdc[256][2],command[0x10000/4];
static u32 readl(const void *address){return *(const u32 *)address;}
static void writel(u32 value,void *address){
 unsigned int offset=(unsigned char *)address-(unsigned char *)regs;
 switch(offset){
 case 0x9020:
  if(value&BIT(30)){
   pdc[value&255][0]=regs[0x9028/4];pdc[value&255][1]=regs[0x9024/4];
  }
  /* fall through */
 case 0x8000:case 0x8060:case 0x81c4:case 0x81ec:
  command[offset/4]=value;value&=~BIT(31);break;
 }
 *(u32 *)address=value;
}
static void rtl_pon_update(void *p,u32 mask,u32 value){writel((readl(p)&~mask)|(value&mask),p);}
#define readl_poll_timeout(p,v,condition,delay,timeout) ({(v)=readl(p);(condition)?0:-ETIMEDOUT;})
#include "rtl9617c-pon-itu-puc.h"
'''
test = r'''
int main(void){
 struct rtl9617c_pon pon={.mac=regs};
 const struct rtl_dq_io io={&pon,rtl_puc_bp_read,rtl_puc_bp_write,rtl_puc_bp_access};
 assert(!rtl_pdc_itu_configure(&pon));
 for(unsigned int i=0;i<256;i++){
  PDC_PDC_MAP_MEM_DATA0_t a={.wrd=pdc[i][0]};
  PDC_PDC_MAP_MEM_DATA1_t b={.wrd=pdc[i][1]};
  assert(a.bf.lspid==7 && a.bf.ldpid==(i<8?16:24));
  assert(a.bf.fe_bypass==(i<8) && a.bf.cos==(i<8?6:0));
  assert(a.bf.no_drop==(i<8));
  assert(b.bf.pol_id==(i<8?i+128:i-8) && !b.bf.pol_en && !b.bf.deepq);
 }
 PDC_PDC_MAP_MEM_ACCESS_t pdc_access={.wrd=command[0x9020/4]};
 assert(pdc_access.bf.address==255 && pdc_access.bf.rbw && pdc_access.bf.access);
 /* SDK's split nine-bit queue fields must contain queue ID + validity. */
 const unsigned char weights[8]={1,3,5,7,9,11,13,15};
 for(unsigned int shift=0;shift<4;shift++){
  regs[0x8048/4]=shift;
  assert(!rtl_itu_puc_schedule(&io,31,0xa5,weights));
  PUC_PVTBL_DATA0_t a={.wrd=regs[0x8014/4]};
  PUC_PVTBL_DATA1_t b={.wrd=regs[0x8010/4]};
  PUC_PVTBL_DATA2_t c={.wrd=regs[0x800c/4]};
  PUC_PVTBL_DATA3_t d={.wrd=regs[0x8008/4]};
  PUC_PVTBL_DATA4_t e={.wrd=regs[0x8004/4]};
  unsigned int queues[8]={a.bf.voq0,a.bf.voq1,a.bf.voq2,
   a.bf.voq3|(b.bf.voq3<<5),b.bf.voq4,b.bf.voq5,b.bf.voq6,
   b.bf.voq7|(c.bf.voq7<<1)};
  unsigned int ratios[8]={c.bf.wrrratio0,c.bf.wrrratio1,
   d.bf.wrrratio2,d.bf.wrrratio3,d.bf.wrrratio4,d.bf.wrrratio5,
   e.bf.wrrratio6,e.bf.wrrratio7};
  for(unsigned int i=0;i<8;i++){
   assert(queues[i]==((248+i)|((0xa5U>>i&1U)<<8)));
   assert(ratios[i]==weights[i]);
  }
  assert(c.bf.entryvld && !c.bf.schmode && !e.bf.nxtptrvld);
  PUC_PVTBL_ACCESS_t pvt_access={.wrd=command[0x8000/4]};
  assert(pvt_access.bf.ADDR==31 && pvt_access.bf.rbw && pvt_access.bf.access);
  PUC_VSTBL_DATA0_t f={.wrd=regs[0x8074/4]};
  PUC_VSTBL_DATA1_t g={.wrd=regs[0x8070/4]};
  PUC_VSTBL_DATA2_t h={.wrd=regs[0x806c/4]};
  PUC_VSTBL_DATA3_t j={.wrd=regs[0x8068/4]};
  PUC_VSTBL_DATA4_t k={.wrd=regs[0x8064/4]};
  unsigned int credits[8]={f.bf.tbc0,f.bf.tbc1|(g.bf.tbc1<<12),g.bf.tbc2,
   g.bf.tbc3|(h.bf.tbc3<<4),h.bf.tbc4|(j.bf.tbc4<<16),j.bf.tbc5,
   j.bf.tbc6|(k.bf.tbc6<<8),k.bf.tbc7};
  for(unsigned int i=0;i<8;i++)assert(credits[i]==((unsigned int)weights[i]<<(7+shift)));
  PUC_VSTBL_ACCESS_t vst_access={.wrd=command[0x8060/4]};
  assert(vst_access.bf.ADDR==31 && vst_access.bf.rbw && vst_access.bf.access);
 }
 assert(!rtl_puc_token_buckets(&pon,255));
 PUC_VOQ_TBC_MEM_DATA0_t cir0={.wrd=regs[0x81cc/4]};
 PUC_VOQ_TBC_MEM_DATA1_t cir1={.wrd=regs[0x81c8/4]};
 PUC_PIR_VOQ_TBC_MEM_DATA0_t pir0={.wrd=regs[0x81f4/4]};
 PUC_PIR_VOQ_TBC_MEM_DATA1_t pir1={.wrd=regs[0x81f0/4]};
 assert(!cir0.bf.rate_k && !cir0.bf.rate_m && !cir0.bf.bs && !cir1.bf.bs);
 assert(cir1.bf.enb==2 && !cir1.bf.mode && !cir1.bf.tbc);
 assert(pir0.bf.rate_k==1023 && pir0.bf.rate_m==65535 && pir0.bf.bs==63);
 assert(pir1.bf.bs==63 && pir1.bf.enb==2 && !pir1.bf.mode && !pir1.bf.tbc);
 puts("RTL77C SDK oracle: production PDC 256 slots, PVT queue/weights, VSTBL credits, CIR/PIR fields match silicon declarations");
}
'''
puc = (drivers / 'rtl9617c-pon-puc.c').read_text()
pdc = (drivers / 'rtl9617c-pon-pdc.c').read_text()
constants = '\n'.join(re.findall(r'^#define .*$', puc + '\n' + pdc, re.M))
functions = ''.join(function(puc, name) for name in (
    'rtl_puc_access', 'rtl_puc_token_buckets',
    'rtl_puc_bp_read', 'rtl_puc_bp_write', 'rtl_puc_bp_access'))
functions += ''.join(function(pdc, name) for name in (
    'rtl_pdc_access', 'rtl_pdc_write', 'rtl_pdc_itu_configure'))
with tempfile.TemporaryDirectory(prefix='pon-sdk-registers-') as directory:
    work = Path(directory)
    cfile, binary = work / 'test.c', work / 'test'
    cfile.write_text(fixture + declarations + constants + '\n' + functions + test)
    subprocess.run(['cc', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    '-I', str(drivers), str(cfile), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
