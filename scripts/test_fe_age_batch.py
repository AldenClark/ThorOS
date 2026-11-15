#!/usr/bin/env python3
"""Execute the production 32-slot FE activity transaction and a pinned SDK oracle.

The MMIO model checks transaction ownership and age-word preservation, not ASIC
timing. --sdk-root compiles the actual vendor row algorithm/bitfield union;
--mutants proves that the ownership, idle and failure assertions can fail.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
SDK_C_SHA = '679ca0a0a8588b3af5a3b04e0ce242636b6d723741a7ef8c5ed04b592035f3ea'
SDK_H_SHA = 'e9771a58e015ac5aa0e844be74e1b225daa8ebd90a63ffba60a35aeb3b6556c8'


def function(source, name):
    match = re.search(r'^(?:static )?(?:inline )?(?:int|void) ' + name + r'\(', source, re.M)
    if not match:
        raise RuntimeError('missing production/SDK function: ' + name)
    start = match.start()
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


COMMON = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "rtl9617c-fe-age.h"
struct model {
 unsigned int rows[RTL_FE_HASH_ENTRIES/32][4],data[4];
 unsigned int commands,data_reads,data_writes,fail_at,pending,access;
};
static struct model hw;
static unsigned int reg_word(unsigned int reg) {
 assert(reg>=0x392c && reg<=0x3938 && !(reg&3));return (0x3938-reg)/4;
}
static unsigned int read_reg(void *context,unsigned int reg) {
 struct model *m=context;
 if(reg==0x3928)return m->pending?m->pending:m->access;
 assert(!m->pending);m->data_reads++;return m->data[reg_word(reg)];
}
static void write_reg(void *context,unsigned int reg,unsigned int value) {
 struct model *m=context;assert(!m->pending);m->data_writes++;m->data[reg_word(reg)]=value;
}
static void finish(struct model *m,unsigned int value) {
 unsigned int row=value&0x7ff;
 assert((value&0xbffff800U)==0x80000000U);
 if(value&0x40000000U)memcpy(m->rows[row],m->data,sizeof(m->data));
 else memcpy(m->data,m->rows[row],sizeof(m->data));
 m->access=value&~0x80000000U;
}
static int indirect(void *context,unsigned int reg,unsigned int value) {
 struct model *m=context;assert(reg==0x3928);
 /* Matches fe_access(): an old command must retire before ACCESS changes. */
 if(m->pending)return -ETIMEDOUT;
 m->commands++;
 if(m->fail_at==m->commands){m->pending=value;return -ETIMEDOUT;}
 finish(m,value);return 0;
}
static struct rtl_dq_io io_for(struct model *m) {
 return (struct rtl_dq_io){m,read_reg,write_reg,indirect};
}
static void complete_late(struct model *m) {
 unsigned int command=m->pending;assert(command);m->pending=0;finish(m,command);
}
static unsigned int nibble(const unsigned int *words,unsigned int slot) {
 return (words[slot/8]>>((slot%8)*4))&15U;
}
static void put_nibble(unsigned int *words,unsigned int slot,unsigned int value) {
 unsigned int shift=(slot%8)*4;
 words[slot/8]=(words[slot/8]&~(15U<<shift))|(value<<shift);
}
static unsigned int random32(void) {
 static unsigned int state=0x83ac29e7U;
 state^=state<<13;state^=state>>17;state^=state<<5;return state;
}
'''

TEST = r'''
static void row_vectors(void) {
 struct rtl_dq_io io=io_for(&hw);
 for(unsigned int pass=0;pass<4096;pass++) {
  unsigned int first=(pass&2047U)*32,owned=random32()|1U,expected=0,before[4],after[4];
  memset(&hw,0,sizeof(hw));
  for(unsigned int w=0;w<4;w++)before[w]=hw.rows[first/32][w]=random32();
  memcpy(after,before,sizeof(after));
  for(unsigned int s=0;s<32;s++)if((owned&(1U<<s)) && nibble(before,s)>1) {
   expected|=1U<<s;put_nibble(after,s,1);
  }
  unsigned int probe=__builtin_ctz(expected?expected:owned),hits=0xdeadbeefU;
  assert(!rtl_fe_main_age_batch(&io,first,owned,probe,&hits));
  assert(hits==expected && !memcmp(hw.rows[first/32],after,sizeof(after)));
  assert(hw.commands==(expected?2U:1U));
  unsigned int reads=0,writes=0;
  for(unsigned int w=0;w<4;w++) {
   reads+=!!(owned&(255U<<(w*8)));writes+=!!(expected&(255U<<(w*8)));
  }
  assert(hw.data_reads==(expected?reads:1U) && hw.data_writes==writes);
 }
 /* Invalid, idle and busy words are not all-ones bus-failure sentinels. */
 for(unsigned int age=0;age<16;age++) {
  memset(&hw,0,sizeof(hw));
  for(unsigned int s=0;s<32;s++)put_nibble(hw.rows[2047],s,age);
  unsigned int hits=0xdeadbeefU;
  assert(!rtl_fe_main_age_batch(&io,65504,~0U,0,&hits));
  assert(hits==(age>1?~0U:0));
  for(unsigned int s=0;s<32;s++)assert(nibble(hw.rows[2047],s)==(age>1?1:age));
  assert(hw.commands==(age>1?2U:1U));
 }
}
static void invalid_inputs(void) {
 struct rtl_dq_io io=io_for(&hw),bad=io;unsigned int hits=0x12345678U;
 memset(&hw,0,sizeof(hw));
 assert(rtl_fe_main_age_batch(NULL,0,1,0,&hits)==-EINVAL);
 assert(rtl_fe_main_age_batch(&io,0,1,0,NULL)==-EINVAL);
 assert(rtl_fe_main_age_batch(&io,0,0,0,&hits)==-EINVAL);
 assert(rtl_fe_main_age_batch(&io,0,2,0,&hits)==-EINVAL);
 assert(rtl_fe_main_age_batch(&io,0,~0U,32,&hits)==-EINVAL);
 assert(rtl_fe_main_age_batch(&io,0,~0U,~0U,&hits)==-EINVAL);
 unsigned int indices[]={1,31,33,65535,65536,~0U};
 for(unsigned int i=0;i<sizeof(indices)/sizeof(*indices);i++)
  assert(rtl_fe_main_age_batch(&io,indices[i],1,0,&hits)==-EINVAL);
 bad.read=NULL;assert(rtl_fe_main_age_batch(&bad,0,1,0,&hits)==-EINVAL);
 bad=io;bad.write=NULL;assert(rtl_fe_main_age_batch(&bad,0,1,0,&hits)==-EINVAL);
 bad=io;bad.indirect=NULL;assert(rtl_fe_main_age_batch(&bad,0,1,0,&hits)==-EINVAL);
 assert(!hw.commands && !hw.data_reads && !hw.data_writes && hits==0x12345678U);
}
static void late_commands(void) {
 struct rtl_dq_io io=io_for(&hw);
 for(unsigned int fail=1;fail<=2;fail++) {
  memset(&hw,0,sizeof(hw));
  for(unsigned int w=0;w<4;w++)hw.rows[15][w]=0x76543210U;
  unsigned int hits=0x12345678U,words[4];hw.fail_at=fail;
  assert(rtl_fe_main_age_batch(&io,480,0xaaaaaaaaU,3,&hits)==-ETIMEDOUT);
  assert(hits==0x12345678U && hw.pending);
  unsigned int commands=hw.commands,reads=hw.data_reads,writes=hw.data_writes;
  memcpy(words,hw.data,sizeof(words));
  /* Retrying, even for another row, cannot change the timed-out DATA window. */
  assert(rtl_fe_main_age_batch(&io,512,~0U,0,&hits)==-ETIMEDOUT);
  assert(hits==0x12345678U && hw.commands==commands && hw.data_reads==reads && hw.data_writes==writes);
  assert(!memcmp(words,hw.data,sizeof(words)));
  complete_late(&hw);hw.fail_at=0;
  assert(!rtl_fe_main_age_batch(&io,480,0xaaaaaaaaU,3,&hits));
  assert(hits==(fail==1?0xa8a8a8a8U:0));
  for(unsigned int s=0;s<32;s++)assert(nibble(hw.rows[15],s)==((s&1U)?1U:s%8U));
 }
}
static void operation_budget(void) {
 struct rtl_dq_io io=io_for(&hw);unsigned int age,hits;
 memset(&hw,0,sizeof(hw));
 for(unsigned int w=0;w<4;w++)hw.rows[0][w]=0x66666666U;
 /* Previous production stats: READ, then read/modify/write for every hit. */
 for(unsigned int s=0;s<32;s++) {
  assert(!rtl_fe_main_age_read(&io,s,&age));assert(age==6);
  assert(!rtl_fe_main_age(&io,s,1));
 }
 assert(hw.commands==96);
 memset(&hw,0,sizeof(hw));
 for(unsigned int w=0;w<4;w++)hw.rows[0][w]=0x66666666U;
 assert(!rtl_fe_main_age_batch(&io,0,~0U,0,&hits));
 assert(hits==~0U && hw.commands==2);
 assert(hw.data_reads==4 && hw.data_writes==4);
}
static void sparse_and_idle_budget(void) {
 struct rtl_dq_io io=io_for(&hw);unsigned int before[4],hits;
 memset(&hw,0,sizeof(hw));
 /* Poison the old DATA window. READ must load every word of this row,
  * even though the sparse update reads/writes only one of those words. */
 for(unsigned int w=0;w<4;w++)hw.data[w]=~0U;
 hw.rows[0][0]=0x12345610U;hw.rows[0][1]=0x89abcdefU;
 hw.rows[0][2]=0xfedcba98U;hw.rows[0][3]=0x76543210U;
 memcpy(before,hw.rows[0],sizeof(before));
 assert(!rtl_fe_main_age_batch(&io,0,~0U,1,&hits));
 assert(!hits && hw.commands==1 && hw.data_reads==1 && !hw.data_writes);
 assert(!memcmp(before,hw.rows[0],sizeof(before))); /* Active neighbors untouched. */
 assert(!rtl_fe_main_age_batch(&io,0,1U<<31,31,&hits));
 assert(hits==(1U<<31) && hw.commands==3 && hw.data_reads==2 && hw.data_writes==1);
 put_nibble(before,31,1);assert(!memcmp(before,hw.rows[0],sizeof(before)));
}
'''

SDK_MODEL = r'''
typedef enum { AAL_TABLE_HASH_HASH_TBL, AAL_TABLE_HASH_OVERFLOW_TBL } aal_table_e;
typedef struct {unsigned int max_entry;} aal_table_t;
static aal_table_t hash_tbl_table={65536},overflow_tbl_table={64};
#define AAL_E_OK 0
#define AAL_E_OPNOTSUPP (-EOPNOTSUPP)
#define AAL_E_INVALID (-EINVAL)
#define AAL_E_OUTRANGE (-ERANGE)
#define AAL_E_ACCESSINCOMP (-ETIMEDOUT)
#define TABLE_TRY_TIMEOUT 10
#define L3FE_FE_L3E_HS_HASH_AGE_MEM_ACCESS 0x3928U
#define L3FE_FE_L3E_HS_HASH_AGE_MEM_DATA0 0x3938U
#define DBG(...) do{}while(0)
static struct model vendor;
static unsigned int sdk_read(unsigned int reg) {
 return read_reg(&vendor,reg);
}
static void sdk_write(unsigned int value,unsigned int reg) {
 if(reg==0x3928){assert(!indirect(&vendor,reg,value));return;}
 write_reg(&vendor,reg,value);
}
#define CA_NE_REG_READ(reg) sdk_read(reg)
#define CA_NE_REG_WRITE(value,reg) sdk_write(value,reg)
'''

SDK_TEST = r'''
static void sdk_vectors(void) {
 struct rtl_dq_io io=io_for(&hw);
 for(unsigned int row=0;row<2048;row++) {
  memset(&hw,0,sizeof(hw));memset(&vendor,0,sizeof(vendor));
  for(unsigned int w=0;w<4;w++)vendor.rows[row][w]=hw.rows[row][w]=random32();
  unsigned int actual=0,reference=0,probe=0;
  for(unsigned int i=0;i<32;i++)if(nibble(hw.rows[row],i)>1){probe=i;break;}
  assert(!rtl_fe_main_age_batch(&io,row*32,~0U,probe,&actual));
  assert(!aal_hash_traffic_status_get(AAL_TABLE_HASH_HASH_TBL,row*32,&reference));
  assert(actual==reference && !memcmp(hw.rows[row],vendor.rows[row],sizeof(hw.rows[row])));
 }
 puts("Pinned SDK aal_hash_traffic_status_get: 2048 real row/bitfield comparisons passed");
}
'''


def sdk_source(path):
    c_path = path / 'aal_hash.c'
    h_path = path / 'include/aal_hash.h'
    for file, expected in ((c_path, SDK_C_SHA), (h_path, SDK_H_SHA)):
        if hashlib.sha256(file.read_bytes()).hexdigest() != expected:
            raise RuntimeError('pinned SDK content mismatch: ' + str(file))
    header = h_path.read_text()
    enum = re.search(r'typedef enum \{\s*HASH_AGING_0.*?\} aal_hash_aging_e;', header, re.S).group()
    union = re.search(r'typedef volatile union \{\s*struct \{\s*uint32_t\s+slot_0 : 4;.*?aal_hash_age_t;', header, re.S).group()
    return enum + '\n' + union + '\n' + SDK_MODEL + function(c_path.read_text(), 'aal_hash_traffic_status_get') + SDK_TEST


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk-root', type=Path, help='Pinned aal-77c directory')
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    header = (DRIVER / 'rtl9617c-fe-age.h').read_text()
    sdk = sdk_source(args.sdk_root) if args.sdk_root else ''
    main_c = 'int main(void){row_vectors();invalid_inputs();late_commands();operation_budget();sparse_and_idle_budget();'
    if sdk:
        main_c += 'sdk_vectors();'
    main_c += 'puts("FE activity rows: 4096 ownership vectors, 16 ages, late completion and 96-to-2 transaction budget passed");return 0;}\n'
    with tempfile.TemporaryDirectory(prefix='fe-age-batch-', dir=ROOT / 'artifacts') as temporary:
        work = Path(temporary)
        (work / 'test.c').write_text(COMMON + TEST + sdk + main_c)
        # Local copy selects mutations; all transitively included production
        # headers, including the shared QM resource plan, come from DRIVER.
        def run(candidate, name):
            (work / 'rtl9617c-fe-age.h').write_text(candidate)
            binary = work / name
            command = [os.environ.get('CC', 'cc'), '-std=gnu11', '-g', '-Wall', '-Wextra', '-Werror',
                       '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer',
                       '-I', str(work), '-I', str(DRIVER), str(work / 'test.c'), '-o', str(binary)]
            # The unchanged vendor function spells 1<<31 with a signed literal.
            # Only this oracle run disables that legacy shift-base diagnostic;
            # the normal/mutation production run retains full UBSan coverage.
            if sdk:
                # The disabling option must follow -fsanitize=undefined.
                command.insert(command.index('-fno-omit-frame-pointer'), '-fno-sanitize=shift-base')
            subprocess.run(command, check=True)
            return subprocess.run([str(binary)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = run(header, 'baseline')
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        print(result.stdout, end='')
        if args.mutants:
            changes = {
                'unowned-slot': ('if (!(owned & (1U << i)))', 'if (0)'),
                'idle-is-active': ('age <= 1', 'age == 0'),
                'unaligned-row': ('(first & 31U) || !owned', '!owned'),
                'lost-write-error': ('if (ret)\n\t\t\treturn ret;', 'if (ret)\n\t\t\treturn 0;'),
                'wrong-word-order': ('0x3938 - i * 4', '0x392c + i * 4'),
                'idle-extra-data': ('*activity = 0;\n\t\treturn 0;', '*activity = 0;\n\t\t(void)io->read(io->context, 0x3938);\n\t\treturn 0;'),
                'write-unread-word': ('if (dirty & (1U << i))', 'if (1)'),
            }
            for name, (old, new) in changes.items():
                if old not in header:
                    raise RuntimeError('mutation anchor missing: ' + name)
                result = run(header.replace(old, new), name)
                if result.returncode == 0:
                    raise RuntimeError('fault escaped: ' + name)
            print('FE activity row regression assertions rejected all 7 behavioral mutations')


if __name__ == '__main__':
    main()
