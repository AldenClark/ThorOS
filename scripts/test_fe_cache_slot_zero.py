#!/usr/bin/env python3
"""Execute the production allocator against the RTL9617C cache-age0 erratum.

The independent admission oracle is the same-chip SDK's forbidden state;
MMIO/cache behavior is not simulated or claimed as hardware acceptance.
"""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
drivers = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--revision', help='Run against an older production allocator (same behavior oracle)')
args = parser.parse_args()
relative = str((drivers / 'rtl9617c-fe.c').relative_to(root))
def production_source(relative):
    return subprocess.check_output(['git', 'show', args.revision + ':' + relative], cwd=root, text=True) if args.revision else (root / relative).read_text()

source = production_source(relative)
# Keep the real slot-selection statements and full-bucket return, rather than
# duplicating the new algorithm in a host model. No new production API needed.
selection = re.search(r' for\(index=start\+.*?(?=\n flow=kzalloc\()', source, re.S)
if not selection:
    raise RuntimeError('production fe_install slot-selection boundary not found')
diag_source = production_source('tools/live-pon-diag/live_fe_memory.c')
diag_reject = re.search(r'if\((metadata\[0\]!=crc32 \|\| .*?)\)continue;', diag_source)
if not diag_reject:
    raise RuntimeError('production cache DMA metadata comparison not found')


model = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "rtl9617c-fe-table.h"
#define BITS_PER_LONG (sizeof(unsigned long)*8)
struct rtl_fe {unsigned long hashes[RTL_FE_HASH_ENTRIES/(sizeof(unsigned long)*8)];};
static int test_bit(unsigned int bit,const unsigned long *map){return !!(map[bit/BITS_PER_LONG]&(1UL<<(bit%BITS_PER_LONG)));}
static void occupy(struct rtl_fe *fe,unsigned int bit){fe->hashes[bit/BITS_PER_LONG]|=1UL<<(bit%BITS_PER_LONG);}
static int allocate(struct rtl_fe *fe,unsigned short crc16){
 unsigned int start=rtl_fe_hash_bucket(crc16),index;
'''
# SDK: jameywine/ca-network-drivers commit
# 8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0,
# ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c/aal_hash.c,
# __hash_tbl_entry_add_by_idx, lines3843..3851. cache_age0_hit is enabled
# by the production rtl_fe_dma_tables initializer, checked below.
oracle = '\n return (int)index;\n}\n' + (
    'static int diagnostic_rejects(unsigned int metadata[2],unsigned int crc32,unsigned short crc16){return '
    + diag_reject.group(1) + ';}\n') + r'''
/* Independent hardware constraint from the SDK, not an allocator. */
static int sdk_slot_admissible(unsigned int crc16,unsigned int idx,unsigned int start){
 if(!(crc16&0x1fff) && (idx==start))return -EINVAL;
 return 0;
}
static void check(struct rtl_fe *fe,unsigned short crc16,int actual){
 unsigned int start=crc16&0xffe0U;
 if(actual==-ENOSPC){
  for(unsigned int slot=0;slot<32;slot++)
   if(!test_bit(start+slot,fe->hashes))assert(sdk_slot_admissible(crc16,start+slot,start));
  return;
 }
 assert(actual>=0 && (unsigned int)actual>=start && (unsigned int)actual<start+32);
 assert(!test_bit((unsigned int)actual,fe->hashes));
 assert(!sdk_slot_admissible(crc16,(unsigned int)actual,start));
 /* Selection must not skip an earlier free slot accepted by the SDK. */
 for(unsigned int idx=start;idx<(unsigned int)actual;idx++)
  assert(test_bit(idx,fe->hashes) || sdk_slot_admissible(crc16,idx,start));
}
static void set_bucket(struct rtl_fe *fe,unsigned int start,uint32_t used){
 memset(fe->hashes,0xff,sizeof(fe->hashes));
 for(unsigned int slot=0;slot<32;slot++){
  unsigned int bit=start+slot;
  fe->hashes[bit/BITS_PER_LONG]&=~(1UL<<(bit%BITS_PER_LONG));
  if(used&(1U<<slot))occupy(fe,bit);
 }
}
static unsigned int registers[0x4000/4];
static unsigned int read_reg(void *ctx,unsigned int reg){(void)ctx;assert(reg<sizeof(registers));return registers[reg/4];}
static void write_reg(void *ctx,unsigned int reg,unsigned int value){(void)ctx;assert(reg<sizeof(registers));registers[reg/4]=value;}
static int indirect(void *ctx,unsigned int reg,unsigned int value){(void)ctx;(void)reg;(void)value;return 0;}
int main(void){
 struct rtl_fe fe={};
 unsigned int key[RTL_FE_KEY_WORDS],crc32;unsigned short crc16;
 struct rtl_fe_ipv4_key tuple={.source=0xc0000201U,.destination=0xc6336402U,
  .source_port=7640,.destination_port=443,.protocol=6,.ingress=3,.mask=63};
 rtl_fe_ipv4_key(key,&tuple);
 rtl_fe_key_set(key,RTL_FE_KEY_ORIG_LSPID,0);
 rtl_fe_key_set(key,RTL_FE_KEY_CTRL_SET_ID,0);
 rtl_fe_key_set(key,RTL_FE_KEY_TABLE_ID,0);
 rtl_fe_key_crc(key,&crc32,&crc16);
 assert(crc16==0xa000 && crc32==0x43b12e9bU);
 /* A normal TCP tuple reaches the forbidden key without injected CRC bytes. */
 int result=allocate(&fe,crc16);check(&fe,crc16,result);
 assert(result==0xa001);
 const struct rtl_dq_io io={NULL,read_reg,write_reg,indirect};
 rtl_fe_dma_tables(&io,0x03800000,2);
 assert(registers[0x38a0/4]&(1U<<18)); /* cache_age0_hit is actually enabled. */
 for(unsigned int crc=0;crc<=65535;crc++){
  unsigned int start=crc&0xffe0U;
  unsigned int metadata[2]={0x12345678U,(crc&0x1fffU)|(7U<<13)|(1U<<18)};
  assert(!diagnostic_rejects(metadata,0x12345678U,(unsigned short)crc));
  metadata[0]^=1;assert(diagnostic_rejects(metadata,0x12345678U,(unsigned short)crc));
  /* The command retains the CRC high bits used for cache set selection. */
  assert(!rtl_fe_cache_command(&io,start+1,(unsigned short)crc,1));
  assert(((registers[0x38ac/4]>>5)&0xffffU)==crc);
  assert((registers[0x38ac/4]&31)==1);
  /* All prefix occupancies test every boundary, including a full bucket. */
  for(unsigned int prefix=0;prefix<=32;prefix++){
   uint32_t used=prefix==32?UINT32_MAX:((1U<<prefix)-1);
   set_bucket(&fe,start,used);
   result=allocate(&fe,(unsigned short)crc);check(&fe,(unsigned short)crc,result);
  }
  /* Single holes include unsafe slot0, final slot31, and all interior holes. */
  for(unsigned int hole=0;hole<32;hole++){
   set_bucket(&fe,start,UINT32_MAX^(1U<<hole));
   result=allocate(&fe,(unsigned short)crc);check(&fe,(unsigned short)crc,result);
   if(hole==0 && !(crc&0x1fff))assert(result==-ENOSPC);
   else assert(result==(int)(start+hole));
  }
 }
 /* Explicit next-bucket boundary: a free following slot must not be used. */
 memset(fe.hashes,0xff,sizeof(fe.hashes));
 unsigned int start=0xa000;
 fe.hashes[(start+32)/BITS_PER_LONG]&=~(1UL<<((start+32)%BITS_PER_LONG));
 assert(allocate(&fe,0xa000)==-ENOSPC);
 puts("FE cache allocator: reachable TCP crc16=a000, all65536 CRCs/command fields/diagnostic comparisons,65 occupancy cases each, reserved slot0, full/last-slot/bucket boundaries passed");
}
'''
with tempfile.TemporaryDirectory(prefix='fe-cache-slot-zero-', dir=root / 'artifacts') as directory:
    cfile = Path(directory) / 'test.c'
    binary = Path(directory) / 'test'
    cfile.write_text(model + selection.group() + oracle)
    subprocess.run(['cc', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    '-I', str(drivers), str(cfile), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
