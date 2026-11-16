#!/usr/bin/env python3
"""Exercise the real once-only ES repair, optionally against pinned SDK code.

The SDK flush command is executed only against an empty host register model;
production never issues that dropping command. No device access or timing claim.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
SDK_SHA = 'dc23170e0e3ff71aaa9a81b4d90b07de5d5c1a165a25912c117bd1eb59f433b4'
REGISTER_SHA = 'ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0'


def verified(path, digest):
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest, f'unpinned input: {path}'
    return data.decode()


def function(text, name):
    match = re.search(r'^.*\b' + name + r'\s*\([^;]*?\)\s*\{', text, re.M)
    assert match, name
    end = text.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[match.start():end] + '\n'


def declaration(text, name):
    begin = re.search(r'^#define ' + name + r'\s+0x', text, re.M).start()
    end = text.index('#endif /* !__ASSEMBLER__ */', begin)
    return text[begin:end] + '#endif /* !__ASSEMBLER__ */\n'


MODEL = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "rtl9617c-l2-es.h"
#define BIT(n) (1U << (n))
struct model {
 unsigned int reg[0x2400/4], original[0x2400/4], reads, writes;
 unsigned int selected, refuse_reg, corrupt, sdk;
};
static bool selected_reg(struct model *m, unsigned int reg) {
 for (unsigned p=0;p<16;p++)
  if ((m->selected&BIT(p)) && reg==0x2304U+12U*(p==15?14:p)) return true;
 return false;
}
static unsigned int read_reg(void *context, unsigned int reg) {
 struct model *m=context;
 assert(!(reg&3) && reg<sizeof(m->reg));
 if (!m->sdk) assert(selected_reg(m,reg));
 m->reads++;
 return m->reg[reg/4];
}
static void write_reg(void *context, unsigned int reg, unsigned int value) {
 struct model *m=context;
 assert(!(reg&3) && reg<sizeof(m->reg));
 if (!m->sdk) {
  assert(selected_reg(m,reg));
  assert(!(value&BIT(15))); /* Never issue a new destructive flush. */
 }
 m->writes++;
 if (reg==m->refuse_reg) value ^= m->corrupt;
 m->reg[reg/4]=value;
}
static struct rtl_dq_io io_for(struct model *m) {
 return (struct rtl_dq_io){m,read_reg,write_reg,NULL};
}
static uint32_t random_word(void) {
 static uint32_t seed=0x12345678U;
 seed^=seed<<13;seed^=seed>>17;seed^=seed<<5;
 return seed;
}
static void initialize(struct model *m, unsigned int selected) {
 memset(m,0,sizeof(*m));m->selected=selected;
 for(unsigned i=0;i<sizeof(m->reg)/sizeof(m->reg[0]);i++) m->reg[i]=random_word();
 for(unsigned p=0;p<16;p++)
  if(selected&BIT(p)) m->reg[(0x2304U+12U*(p==15?14:p))/4]|=BIT(15);
 memcpy(m->original,m->reg,sizeof(m->reg));
}
static void check_after(struct model *m) {
 for(unsigned i=0;i<sizeof(m->reg)/sizeof(m->reg[0]);i++) {
  unsigned expected=m->original[i];
  if(selected_reg(m,i*4)) expected=(expected&~BIT(15))|0xffU;
  assert(m->reg[i]==expected);
 }
}
static void native_test(void) {
 struct model m;
 unsigned long cases=0;
 for(unsigned mask=0;mask<32;mask++) for(unsigned sink=0;sink<2;sink++)
  for(unsigned trial=0;trial<64;trial++) {
   initialize(&m,mask|(sink?BIT(15):0));
   struct rtl_dq_io io=io_for(&m);
   assert(!rtl_l2_es_cold_prepare(&io,m.selected));check_after(&m);
   assert(m.writes==(unsigned)__builtin_popcount(m.selected));
   assert(m.reads==2*m.writes);cases++;
  }
 for(unsigned port=0;port<16;port++) if(0x801fU&BIT(port)) {
  unsigned reg=0x2304U+12U*(port==15?14:port);
  for(unsigned bit=0;bit<32;bit++) {
   initialize(&m,0x801fU);m.refuse_reg=reg;m.corrupt=BIT(bit);
   struct rtl_dq_io io=io_for(&m);
   assert(rtl_l2_es_cold_prepare(&io,m.selected)==-EIO);cases++;
  }
  initialize(&m,0x801fU);m.reg[reg/4]=~0U;
  struct rtl_dq_io io=io_for(&m);
  assert(rtl_l2_es_cold_prepare(&io,m.selected)==-EIO && !m.writes);cases++;
 }
 for(unsigned port=5;port<15;port++) {
  initialize(&m,BIT(port));struct rtl_dq_io io=io_for(&m);
  assert(rtl_l2_es_cold_prepare(&io,m.selected)==-EINVAL && !m.reads && !m.writes);cases++;
 }
 initialize(&m,0x10000U);struct rtl_dq_io io=io_for(&m);
 assert(rtl_l2_es_cold_prepare(&io,m.selected)==-EINVAL && !m.reads && !m.writes);
 cases++;
 initialize(&m,0x801fU);io=io_for(&m);
 assert(rtl_l2_es_cold_prepare(NULL,m.selected)==-EINVAL && !m.reads && !m.writes);cases++;
 io.read=NULL;
 assert(rtl_l2_es_cold_prepare(&io,m.selected)==-EINVAL && !m.reads && !m.writes);cases++;
 io=io_for(&m);io.write=NULL;
 assert(rtl_l2_es_cold_prepare(&io,m.selected)==-EINVAL && !m.reads && !m.writes);cases++;
 printf("L2 ES cold repair: %lu subset/dirty-state/readback/refusal cases passed\n",cases);
}
'''

SDK_MODEL = r'''
typedef uint32_t ca_uint32_t;
typedef unsigned ca_device_id_t;
typedef unsigned ca_port_id_t;
typedef int ca_status_t;
typedef bool ca_boolean_t;
#define CA_E_OK 0
#define CA_E_PARAM -1
#define TRUE true
#define FALSE false
#define CA_AAL_ES_MAX_PORT_ID 15
#define CA_AAL_ES_PORT_CHECK(x) do { if ((x)==14 || (x)>15) return CA_E_PARAM; } while(0)
static struct model *sdk_model;
#define CA_NE_REG_READ(reg) read_reg(sdk_model,(reg)-0xf4300000U)
#define CA_DEV_NE_REG_READ(device,reg) CA_NE_REG_READ(reg)
#define CA_NE_REG_WRITE(value,reg) write_reg(sdk_model,(reg)-0xf4300000U,(value))
#define CA_DEV_NE_REG_WRITE2(device,reg,value) CA_NE_REG_WRITE(value,reg)
'''

SDK_TEST = r'''
static void sdk_test(void) {
 struct model actual,expected;
 for(unsigned port=0;port<16;port++) if(0x801fU&BIT(port))
  for(unsigned queue=0;queue<8;queue++) for(unsigned trial=0;trial<64;trial++) {
   unsigned reg=0x2304U+12U*(port==15?14:port);
   initialize(&actual,BIT(port));
   L2TM_L2TM_ES_SCH_CFG0_t word={.wrd=actual.reg[reg/4]};
   word.bf.flush_en=1;word.bf.flush_voqid=queue;
   actual.reg[reg/4]=word.wrd;expected=actual;expected.sdk=1;sdk_model=&expected;
   /* SDK empty status avoids waiting/claiming any hardware drain. */
   unsigned status=(L2TM_L2TM_ES_VOQ_STS0-0xf4300000U)+(port/4)*4;
   actual.reg[status/4]=expected.reg[status/4]=0;
   for(unsigned q=0;q<8;q++) assert(!aal_l2_tm_es_voq_ena_set(0,port,q,TRUE));
   unsigned selected=~0U;
   assert(!aal_l2_tm_es_voq_flush_get(0,port,&selected) && selected==queue);
   assert(!aal_l2_tm_es_voq_flush_set(0,port,queue));
   struct rtl_dq_io io=io_for(&actual);
   assert(!rtl_l2_es_cold_prepare(&io,BIT(port)));
   assert(!memcmp(actual.reg,expected.reg,sizeof(actual.reg)));
   word.wrd=actual.reg[reg/4];
   assert(!word.bf.flush_en && word.bf.voq_en==0xff && word.bf.flush_voqid==queue);
  }
 puts("L2 ES SDK oracle: 3072 pinned enable/empty-flush/getter comparisons passed");
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk-root', type=Path)
    parser.add_argument('--registers', type=Path)
    args = parser.parse_args()
    assert bool(args.sdk_root) == bool(args.registers), 'provide both SDK and register inputs'
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    source = MODEL
    if args.sdk_root:
        sdk = verified(args.sdk_root / 'aal_l2_tm.c', SDK_SHA)
        registers = verified(args.registers, REGISTER_SHA)
        source += SDK_MODEL
        for name in ('L2TM_L2TM_ES_SCH_CFG0', 'L2TM_L2TM_ES_VOQ_STS0'):
            source += declaration(registers, name)
        for name in ('aal_l2_tm_es_voq_status_get', 'aal_l2_tm_es_voq_flush_set',
                     'aal_l2_tm_es_voq_flush_get', 'aal_l2_tm_es_voq_ena_set'):
            source += function(sdk, name)
        source += SDK_TEST
    source += 'int main(void) { native_test(); ' + ('sdk_test();' if args.sdk_root else '') + ' return 0; }\n'
    header = (DRIVER / 'rtl9617c-l2-es.h').read_text()
    mutants = {
        'keep_inherited_flush': header.replace('(saved[port] & ~0x8000U) | 0xffU', 'saved[port] | 0xffU'),
        'port15_wrong_instance': header.replace('(port == 15 ? 14 : port)', 'port'),
        'ignore_readback': header.replace('if (io->read(io->context, reg) != value)',
                                         'if (io->read(io->context, reg) != value && 0)'),
        'wipe_speed': header.replace('(saved[port] & ~0x8000U) | 0xffU',
                                     '(saved[port] & ~0xff8000U) | 0xffU'),
        'no_voq_enable': header.replace('(saved[port] & ~0x8000U) | 0xffU',
                                        '(saved[port] & ~0x8000U)'),
    }
    with tempfile.TemporaryDirectory(prefix='l2-es-cold-') as temporary:
        directory = Path(temporary)
        (directory / 'test.c').write_text(source)
        command = [os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                   '-Wno-unused-parameter', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                   '-I', str(DRIVER), str(directory / 'test.c'), '-o', str(directory / 'test')]
        environment = dict(os.environ)
        environment.setdefault('ASAN_OPTIONS', 'detect_leaks=0')
        environment.setdefault('UBSAN_OPTIONS', 'halt_on_error=1')
        subprocess.run(command, check=True)
        subprocess.run([str(directory / 'test')], check=True, env=environment)
        for name, content in mutants.items():
            assert content != header
            (directory / 'rtl9617c-l2-es.h').write_text(content)
            subprocess.run(command, check=True)
            result = subprocess.run([str(directory / 'test')], env=environment,
                                    capture_output=True, text=True)
            assert result.returncode != 0 and 'Assertion' in result.stderr, (name, result.stderr)
        print(f'L2 ES cold repair: {len(mutants)} broken-behaviour negative controls rejected')


if __name__ == '__main__':
    main()
