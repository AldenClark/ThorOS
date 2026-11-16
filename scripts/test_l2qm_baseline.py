#!/usr/bin/env python3
"""Execute native L2 SRAM setup, optionally against pinned public SDK sources.

The optional oracle compiles actual aal-77c init/setters/getters and generated
register declarations. No stock module, private device report or hardware is
needed. This checks admission encoding and failure handling, not ASIC timing,
buffer lifetime, live throughput, or the feasibility of a larger packet SRAM.
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
HEADER = DRIVER / 'rtl9617c-l2qm.h'
PINS = {
    'aal_l2_qm.c': '9ad3f7ee25f9c0d0cdf1714117ba8a58912bb72194732d395185567df51190c1',
    'include/aal_l2_qm.h': '67981b6666a647628d816084dbe59c1112863ef6684c770df121c3f2f572c270',
}
REGISTER_SHA = 'ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0'
STARTUP_SHA = 'be16d2768979e01ce28483c4f7e65e128d146eb1c4f46552ad127756f6b77cde'


def verified(path, digest):
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest, f'unpinned public source: {path}'
    return data.decode()


def function(text, name):
    start = re.search(r'^.*\b' + name + r'\s*\([^;]*?\)\s*\{', text, re.M)
    assert start, name
    end = text.index('{', start.start()) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start.start():end] + '\n'


def declaration(text, name):
    start = re.search(r'^#define ' + name + r'\s+0x', text, re.M)
    assert start, name
    end = text.index('#endif /* !__ASSEMBLER__ */', start.start())
    return text[start.start():end] + '#endif /* !__ASSEMBLER__ */\n'


MODEL = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "rtl9617c-l2qm.h"
struct model {
 unsigned reg[0x10000/4], reads, writes, ignored, mutate_after, fail_read;
};
static const unsigned baseline_regs[]={0x2208,0x2218,0x2228,0x222c,0x2210};
static unsigned read_reg(void *context,unsigned reg) {
 struct model *m=context;bool allowed=false;
 for(unsigned i=0;i<5;i++)allowed|=reg==baseline_regs[i];
 assert(allowed);m->reads++;
 if(m->fail_read && m->reads==m->fail_read)return ~0U;
 return m->reg[reg/4];
}
static void write_reg(void *context,unsigned reg,unsigned value) {
 struct model *m=context;bool allowed=false;
 for(unsigned i=0;i<5;i++)allowed|=reg==baseline_regs[i];
 assert(allowed);m->writes++;
 if(reg!=m->ignored)m->reg[reg/4]=value;
 if(m->mutate_after && m->writes==m->mutate_after)m->reg[0x2208/4]^=1;
}
static unsigned random_word(unsigned *seed) {
 *seed=*seed*1664525U+1013904223U;return *seed;
}
static void check_sdk(void);
'''

CASES = r'''
int main(void) {
 unsigned seed=0x3287b1;
 struct rtl_l2qm_io invalid={0};
 assert(rtl_l2qm_prepare(NULL)==-EINVAL);
 assert(rtl_l2qm_prepare(&invalid)==-EINVAL);
 invalid.read=read_reg;assert(rtl_l2qm_prepare(&invalid)==-EINVAL);
 assert(RTL_L2QM_CELLS==4096 && RTL_L2QM_CELL_BYTES==64);
 assert(RTL_L2QM_PRIVATE_CELLS==29 && RTL_L2QM_PORTS==16);
 assert(RTL_L2QM_RESERVED_CELLS==464 && RTL_L2QM_SHARED_CELLS==3632);
 assert(RTL_L2QM_SHARED_CELLS+RTL_L2QM_RESERVED_CELLS==RTL_L2QM_CELLS);
 assert(RTL_L2QM_PRIVATE_CELLS*RTL_L2QM_CELL_BYTES>=1536+8);
 assert(RTL_L2QM_NODROP_CELLS==33 && RTL_L2QM_NONCONGESTION_CELLS==2048);
 assert(RTL_L2QM_EQ_CONFIG==0x81d40000U);
 assert(RTL_L2QM_BUFFER_CONFIG==0x08008021U);
 assert(RTL_L2QM_PORT_FREE_CREDIT==0x8e308000U);
 /* Random inherited selectors include every port nibble, including 8..15.
  * All unrelated profile/selector reserved bits must survive verbatim. */
 for(unsigned n=0;n<10000;n++) {
  struct model m={0};struct rtl_l2qm_io io={&m,read_reg,write_reg};
  unsigned initial[5];
  for(unsigned i=0;i<5;i++) {
   initial[i]=random_word(&seed);if(initial[i]==~0U)initial[i]^=1;
   m.reg[baseline_regs[i]/4]=initial[i];
  }
  assert(!rtl_l2qm_prepare(&io));
  assert(m.writes==5 && m.reads==15);
  assert(m.reg[0x2208/4]==0x81d40000U && m.reg[0x2210/4]==0x08008021U);
  assert(m.reg[0x2218/4]==((initial[1]&~0x7fffU)|29));
  assert(m.reg[0x2228/4]==(initial[2]&0x88888888U));
  assert(m.reg[0x222c/4]==(initial[3]&0x88888888U));
  for(unsigned p=0;p<16;p++) {
   unsigned sel=m.reg[(p<8?0x2228:0x222c)/4]>>((p%8)*4)&7;
   assert(sel==0);
  }
 }
 /* Each all-ones register read refuses before the first baseline write. */
 for(unsigned i=0;i<5;i++) {
  struct model m={0};struct rtl_l2qm_io io={&m,read_reg,write_reg};
  m.reg[baseline_regs[i]/4]=~0U;
  assert(rtl_l2qm_prepare(&io)==-EIO && !m.writes);
 }
 /* Each ignored write must be caught, including both selector words. */
 for(unsigned i=0;i<5;i++) {
  struct model m={.ignored=baseline_regs[i]};
  struct rtl_l2qm_io io={&m,read_reg,write_reg};
  m.reg[0x2228/4]=0x76543210;m.reg[0x222c/4]=0x12345671;
  assert(rtl_l2qm_prepare(&io)==-EIO && m.writes==i+1);
 }
 /* Read faults at each immediate/final readback never report success. */
 for(unsigned i=6;i<=15;i++) {
  struct model m={.fail_read=i};struct rtl_l2qm_io io={&m,read_reg,write_reg};
  assert(rtl_l2qm_prepare(&io)==-EIO);
 }
 /* A later MMIO write clobbering the first word is caught by final audit. */
 for(unsigned n=2;n<=5;n++) {
  struct model m={.mutate_after=n};struct rtl_l2qm_io io={&m,read_reg,write_reg};
  assert(rtl_l2qm_prepare(&io)==-EIO);
 }
 check_sdk();
 puts("PASS: 10000 inherited L2QM baselines, sixteen-port reservations and fault paths");
 return 0;
}
'''


def sdk_oracle(registers, sdk_root, startup):
    register_text = verified(registers, REGISTER_SHA)
    sdk = {name: verified(sdk_root / name, pin) for name, pin in PINS.items()}
    startup_text = verified(startup, STARTUP_SHA)
    threshold = re.search(r'^INT\s+CFG_ID_L2TM_NON_CONGESTION_BUFF_THRESHOLD\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)\s*;',
                          startup_text, re.M)
    assert threshold and int(threshold[1], 0) == 2048
    definitions = ''.join(declaration(register_text, name) for name in (
        'L2TM_L2TM_QM_EQ_CFG', 'L2TM_L2TM_QM_GLOB_BUF_CFG',
        'L2TM_L2TM_QM_PORT_PRVT_PROFILE0', 'L2TM_L2TM_QM_PORT_PRVT_SELECT0',
        'L2TM_L2TM_QM_PORT_PRVT_SELECT1', 'L2TM_L2TE_CB_PORT_FREECNT_MEM_DATA'))
    functions = ''.join(function(sdk['aal_l2_qm.c'], name) for name in (
        'aal_l2_qm_eq_cfg_set', 'aal_l2_qm_buff_cfg_set',
        'aal_l2_qm_port_prvt_profile_set', 'aal_l2_qm_init',
        'aal_l2_qm_eq_cfg_get', 'aal_l2_qm_buff_cfg_get',
        'aal_l2_qm_port_prvt_sel_get', 'aal_l2_qm_port_prvt_profile_get'))
    return r'''
#define CA_IN
#define CA_OUT
#define CA_E_OK 0
#define CA_E_PARAM -1
#define CA_FALSE 0
#define CA_TRUE 1
#define FALSE 0
#define TRUE 1
#define CA_AAL_MAX_PORT_ID 15
typedef uint32_t ca_uint32_t;
typedef uint16_t ca_uint16_t;
typedef uint8_t ca_uint8_t;
typedef unsigned ca_device_id_t;
typedef unsigned ca_port_id_t;
typedef unsigned ca_boolean_t;
typedef int ca_status_t;
#include "sdk_qm.h"
''' + definitions + r'''
static struct model *sdk_model;
#define CA_DEV_NE_REG_READ(d,r) read_reg(sdk_model,(r)-0xf4300000U)
#define CA_DEV_NE_REG_WRITE2(d,r,v) write_reg(sdk_model,(r)-0xf4300000U,(v))
#define ca_printf(...) ((void)0)
#define CFG_ID_L2TM_NON_CONGESTION_BUFF_THRESHOLD 1
static int aal_scfg_read(unsigned key,unsigned size,ca_uint32_t *value) {
 assert(key==1 && size==4);
 *value=''' + str(int(threshold[1], 0)) + r''';return 0;
}
''' + functions + r'''
static void check_sdk(void) {
 unsigned seed=43;
 assert(CA_AAL_L2_QM_BUFF_NUMS==RTL_L2QM_CELLS);
 assert(CA_AAL_L2_QM_PORT_PRVT_BUFF_NUM==RTL_L2QM_PRIVATE_CELLS);
 assert(L2TM_L2TM_QM_EQ_CFG==0xf4302208U);
 assert(L2TM_L2TM_QM_GLOB_BUF_CFG==0xf4302210U);
 assert(L2TM_L2TM_QM_PORT_PRVT_PROFILE0==0xf4302218U);
 assert(L2TM_L2TM_QM_PORT_PRVT_SELECT0==0xf4302228U);
 assert(L2TM_L2TM_QM_PORT_PRVT_SELECT1==0xf430222cU);
 assert(L2TM_L2TE_CB_PORT_FREECNT_MEM_DATA==0xf4302db8U);
 for(unsigned n=0;n<256;n++) {
  struct model native={0},original={0};
  struct rtl_l2qm_io io={&native,read_reg,write_reg};
  for(unsigned i=0;i<5;i++) {
   unsigned word=random_word(&seed);if(word==~0U)word^=1;
   native.reg[baseline_regs[i]/4]=original.reg[baseline_regs[i]/4]=word;
  }
  assert(!rtl_l2qm_prepare(&io));
  sdk_model=&original;assert(!aal_l2_qm_init(0));
  /* Actual SDK init assumes reset selectors and leaves them untouched.
   * Compare its three programmed words, then independently decode the
   * native normalized selectors with SDK getters for all sixteen ports. */
  assert(original.reg[0x2208/4]==native.reg[0x2208/4]);
  assert(original.reg[0x2218/4]==native.reg[0x2218/4]);
  assert(original.reg[0x2210/4]==native.reg[0x2210/4]);
  sdk_model=&native;
  aal_l2_qm_eq_cfg_t eq0,eq1;aal_l2_qm_buff_cfg_t buffers;
  assert(!aal_l2_qm_eq_cfg_get(0,0,&eq0));
  assert(!aal_l2_qm_eq_cfg_get(0,1,&eq1));
  assert(!eq0.eq_ena && !eq0.buff_num && !eq0.prvt_buff_num);
  assert(eq1.eq_ena && eq1.buff_num==4 && eq1.prvt_buff_num==29);
  assert(!aal_l2_qm_buff_cfg_get(0,&buffers));
  assert(!buffers.fe_bp_ena && buffers.drop_ena && buffers.no_drop_threshold==33);
  assert(buffers.non_cong_threshold==2048);
  for(unsigned p=0;p<16;p++) {
   unsigned profile,cells;
   assert(!aal_l2_qm_port_prvt_sel_get(0,p,&profile) && profile==0);
   assert(!aal_l2_qm_port_prvt_profile_get(0,profile,&cells) && cells==29);
  }
  L2TM_L2TE_CB_PORT_FREECNT_MEM_DATA_t credits={.wrd=RTL_L2QM_PORT_FREE_CREDIT};
  assert(credits.bf.cnt0==0 && credits.bf.cnt0_msb==1);
  assert(credits.bf.cnt1==CA_AAL_L2_QM_BUFF_NUMS-16*CA_AAL_L2_QM_PORT_PRVT_BUFF_NUM);
  assert(credits.bf.cnt1_msb==1);
 }
 puts("PASS: pinned SDK actual init/getters, generated fields and 77c startup oracle");
}
''', sdk['include/aal_l2_qm.h']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--registers', type=Path)
    parser.add_argument('--sdk-root', type=Path)
    parser.add_argument('--startup', type=Path)
    parser.add_argument('--skip-mutants', action='store_true')
    args = parser.parse_args()
    supplied = [args.registers, args.sdk_root, args.startup]
    if any(supplied) and not all(supplied):
        parser.error('--registers, --sdk-root and --startup must be supplied together')
    oracle, sdk_header = ('static void check_sdk(void) {}\n', '')
    if all(supplied):
        oracle, sdk_header = sdk_oracle(*supplied)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    header = HEADER.read_text()
    mutations = {
        'selector8_15_not_normalized': ('expected[3] &= ~0x77777777U;', '(void)expected[3];'),
        'selector0_7_not_normalized': ('expected[2] &= ~0x77777777U;', '(void)expected[2];'),
        'wrong_selector_bank': ('0x222cU, 0x2210U', '0x2228U, 0x2210U'),
        'reserved_nibble_clobber': ('expected[2] &= ~0x77777777U;', 'expected[2] = 0;'),
        'unrelated_profile_clobber': ('(expected[1] & ~0x7fffU) | RTL_L2QM_PRIVATE_CELLS', 'RTL_L2QM_PRIVATE_CELLS'),
        'private_pool_underreservation': ('(RTL_L2QM_PRIVATE_CELLS << 20)', '((RTL_L2QM_PRIVATE_CELLS - 1) << 20)'),
        'unproved_sram_resize': ('#define RTL_L2QM_CELLS 4096U', '#define RTL_L2QM_CELLS 8192U'),
        'missing_immediate_readback': ('if (io->read(io->context, reg[i]) != expected[i])\n\t\t\treturn -EIO;',
                                       '(void)io->read(io->context, reg[i]);'),
        'missing_final_readback': ('for (i = 0; i < 5; i++)\n\t\tif (io->read(io->context, reg[i]) != expected[i])',
                                   'for (i = 5; i < 5; i++)\n\t\tif (io->read(io->context, reg[i]) != expected[i])'),
        'missed_all_ones': ('if (expected[i] == ~0U)', 'if (0)'),
    }
    env = os.environ.copy()
    env['ASAN_OPTIONS'] = 'detect_leaks=0'
    env['UBSAN_OPTIONS'] = 'halt_on_error=1'
    with tempfile.TemporaryDirectory(prefix='l2qm-baseline-') as temporary:
        work = Path(temporary)
        (work / 'sdk_qm.h').write_text(sdk_header)
        (work / 'ca_types.h').write_text('/* Fixture types precede SDK header. */\n')
        source = work / 'test.c'
        source.write_text(MODEL + oracle + CASES)

        def run(text, name, mutant=False):
            (work / HEADER.name).write_text(text)
            binary = work / name
            command = ['cc', '-std=gnu11', '-O1', '-g', '-fno-omit-frame-pointer',
                       '-fno-pie', '-no-pie', '-fsanitize=address,undefined',
                       '-I', str(work), str(source), '-o', str(binary)]
            subprocess.run(command, check=True, capture_output=True, text=True)
            result = subprocess.run([str(binary)], env=env, capture_output=True, text=True)
            if mutant:
                assert result.returncode != 0 and 'Assertion' in result.stderr, (name, result.stdout, result.stderr)
            else:
                assert result.returncode == 0, (result.stdout, result.stderr)
                print(result.stdout, end='')

        run(header, 'baseline')
        if not args.skip_mutants:
            for name, (before, after) in mutations.items():
                assert before in header, name
                run(header.replace(before, after, 1), name, True)
            print(f'PASS: {len(mutations)} assertion-killed L2QM mutation controls (ASan/UBSan)')
    if not all(supplied):
        print('NOTE: public SDK oracle not requested; synthetic tests do not prove silicon behavior')


if __name__ == '__main__':
    main()
