#!/usr/bin/env python3
"""Run the real per-route MTU pool against all 16 physical selectors.

The optional independent, pinned generated header verifies every selector's
register and halfword. This test models ownership, not packet execution or
the real ASIC's timing. test_fe_flow_parser checks route-MTU admission and
test_fe_hash_collision checks production install's packed action selector.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
RELATIVE = 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c-fe.c'
DRIVER = (ROOT / RELATIVE).parent
HEADER_SHA = 'ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0'


def function(source, name):
    start = re.search(r'^static (?:int|void) ' + name + r'\(', source, re.M).start()
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


def declaration(source, name):
    start = re.search(r'^#define ' + name + r'\s+0x', source, re.M).start()
    end = source.index('#endif /* !__ASSEMBLER__ */', start)
    return source[start:end] + '#endif /* !__ASSEMBLER__ */\n'


COMMON = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t ca_uint32_t;
struct rtl_fe_flow {unsigned int mtu_index;bool mtu_owned;};
struct rtl_fe {struct rtl_fe_mtu mtus[16];unsigned int reg[8],reads,writes;};
static unsigned int fe_read(struct rtl_fe *fe,unsigned int address)
{
 assert(address>=0x3520 && address<=0x353c && !(address&3));
 fe->reads++;return fe->reg[(address-0x3520)/4];
}
static void fe_write(struct rtl_fe *fe,unsigned int address,unsigned int value)
{
 assert(address>=0x3520 && address<=0x353c && !(address&3));
 fe->writes++;fe->reg[(address-0x3520)/4]=value;
}
static unsigned int original(unsigned int row)
{
 return 0xc000c000U|((1300U+row*2U)<<16)|(1400U+row);
}
static void init(struct rtl_fe *fe)
{
 memset(fe,0,sizeof(*fe));
 for(unsigned int row=0;row<8;row++)fe->reg[row]=original(row);
}
'''

TEST = r'''
static void capacity_and_restore(void)
{
 struct rtl_fe fe;init(&fe);struct rtl_fe_flow flows[17]={0};
 for(unsigned int i=0;i<16;i++) {
  assert(!fe_mtu_get(&fe,&flows[i],1200+i));
  assert(flows[i].mtu_owned && flows[i].mtu_index==i);
  check_slot(&fe,i,1200+i);
  assert((fe.reg[i/2]&0xc000c000U)==0xc000c000U);
 }
 unsigned int reads=fe.reads,writes=fe.writes;
 assert(fe_mtu_get(&fe,&flows[16],999)==-ENOSPC);
 assert(!flows[16].mtu_owned && fe.reads==reads && fe.writes==writes);
 /* Full pool still shares a matching selector without a register access. */
 assert(!fe_mtu_get(&fe,&flows[16],1215));
 assert(flows[16].mtu_index==15 && fe.mtus[15].users==2);
 assert(fe.reads==reads && fe.writes==writes);
 fe_mtu_put(&fe,&flows[15]);assert(!flows[15].mtu_owned);
 check_slot(&fe,15,1215);assert(fe.reads==reads && fe.writes==writes);
 /* Restoring one half must not clobber the still-owned neighbor. */
 for(unsigned int i=0;i<16;i+=2) {
  fe_mtu_put(&fe,&flows[i]);assert(!flows[i].mtu_owned);
  check_slot(&fe,i,original(i/2)&0x3fffU);
  check_slot(&fe,i+1,1201+i);
 }
 for(unsigned int i=1;i<15;i+=2)fe_mtu_put(&fe,&flows[i]);
 fe_mtu_put(&fe,&flows[16]);
 for(unsigned int i=0;i<8;i++)assert(fe.reg[i]==original(i));
 for(unsigned int i=0;i<16;i++)assert(!fe.mtus[i].users);
 /* Search a later matching row before taking an earlier free one. */
 memset(flows,0,sizeof(flows));
 assert(!fe_mtu_get(&fe,&flows[0],1500));
 assert(!fe_mtu_get(&fe,&flows[1],1492));
 fe_mtu_put(&fe,&flows[0]);reads=fe.reads;writes=fe.writes;
 assert(!fe_mtu_get(&fe,&flows[2],1492));
 assert(flows[2].mtu_index==1 && fe.mtus[1].users==2 && !fe.mtus[0].users);
 assert(fe.reads==reads && fe.writes==writes);
 fe_mtu_put(&fe,&flows[1]);fe_mtu_put(&fe,&flows[2]);
 for(unsigned int i=0;i<8;i++)assert(fe.reg[i]==original(i));
}
static void large_shared_pool(void)
{
 struct rtl_fe fe;init(&fe);struct rtl_fe_flow flows[4096]={0};
 for(unsigned int i=0;i<4096;i++) {
  assert(!fe_mtu_get(&fe,&flows[i],1400+i%4));
  assert(flows[i].mtu_index==i%4);
 }
 assert(fe.reads==4 && fe.writes==4);
 for(unsigned int i=0;i<4096;i+=2)fe_mtu_put(&fe,&flows[i]);
 check_slot(&fe,1,1401);check_slot(&fe,3,1403);
 for(unsigned int i=4096;i>0;i-=2)fe_mtu_put(&fe,&flows[i-1]);
 assert(fe.reads==8 && fe.writes==8);
 for(unsigned int i=0;i<8;i++)assert(fe.reg[i]==original(i));
}
static void bounds(void)
{
 struct rtl_fe fe;init(&fe);struct rtl_fe_flow f={0};
 unsigned int invalid[]={0,0x4000,0xffff,0xffffffffU};
 for(unsigned int i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++) {
  assert(fe_mtu_get(&fe,&f,invalid[i])==-EOPNOTSUPP);
  assert(!f.mtu_owned && !fe.reads && !fe.writes);
 }
 unsigned int valid[]={1,68,576,1280,1400,1492,1500,0x3fff};
 for(unsigned int i=0;i<sizeof(valid)/sizeof(valid[0]);i++) {
  assert(!fe_mtu_get(&fe,&f,valid[i]));check_slot(&fe,f.mtu_index,valid[i]);
  fe_mtu_put(&fe,&f);assert(!f.mtu_owned && fe.reg[0]==original(0));
 }
}
int main(void)
{
 capacity_and_restore();large_shared_pool();bounds();
 puts("MTU pool:16 selectors,17th distinct rejection,4096 shared owners/4 slots,"
      "halfword restoration,reserved bits,zero-MMIO sharing and14-bit bounds PASS");
 return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--registers', type=Path)
    parser.add_argument('--revision', help='Historical helper for a bounds negative control')
    args = parser.parse_args()
    native = (subprocess.check_output(['git', 'show', args.revision + ':' + RELATIVE],
              cwd=ROOT, text=True) if args.revision else (ROOT / RELATIVE).read_text())
    mtu = re.search(r'struct rtl_fe_mtu \{.*?\n\};', native, re.S).group()
    code = mtu + '\n' + COMMON
    if args.registers:
        data = args.registers.read_bytes()
        assert hashlib.sha256(data).hexdigest() == HEADER_SHA, 'incorrect SDK register input'
        header = data.decode()
        for pair in range(8):
            code += declaration(header, 'L3FE_PE_MTU_SIZE_' + str(pair))
        code += '\nstatic void check_slot(struct rtl_fe *fe,unsigned int i,unsigned int size) {\nswitch(i) {\n'
        for index in range(16):
            pair = index // 2
            name = 'L3FE_PE_MTU_SIZE_' + str(pair)
            code += (f'case {index}: {{ {name}_t value={{.wrd=fe->reg[{pair}]}};\n'
                     f'assert({name}-0xf4300000U==0x3520U+{pair}*4U);\n'
                     f'assert(value.bf.mtu_{index}==size);break;}}\n')
        code += 'default:assert(!"invalid selector");\n}}\n'
    else:
        # Fixed external layout, independently of the allocator's arithmetic.
        code += r'''
static void check_slot(struct rtl_fe *fe,unsigned int i,unsigned int size)
{
 assert(i<16);
 const unsigned int row[]={0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7};
 assert(((fe->reg[row[i]]>>(i%2?16:0))&0x3fffU)==size);
}
'''
    code += function(native, 'fe_mtu_get') + function(native, 'fe_mtu_put') + TEST
    with tempfile.TemporaryDirectory(prefix='fe-mtu-') as work:
        source, binary = Path(work) / 'test.c', Path(work) / 'test'
        source.write_text(code)
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        str(source), '-o', str(binary)], check=True)
        environment = dict(os.environ)
        environment.setdefault('ASAN_OPTIONS', 'detect_leaks=0')
        environment.setdefault('UBSAN_OPTIONS', 'halt_on_error=1')
        subprocess.run([str(binary)], check=True, env=environment)
    if args.registers:
        print('All16 selectors checked against the unmodified SHA256-pinned silicon header')


if __name__ == '__main__':
    main()
