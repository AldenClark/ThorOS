#!/usr/bin/env python3
"""Execute actual snapshot and MMIO read helper with scripted hardware observations."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
drivers = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
source = (drivers / 'rtl9617c-fe.c').read_text()
access = source[source.index('struct fe_cache_read_context {'):source.index('static unsigned int fe_cache_read_reg')]
fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "rtl9617c-fe-cache-snapshot.h"
static unsigned int keys[3][7],fibs[2][7],data[7],config;
static unsigned int requests,key_reads,fib_reads,match_way,fail_at,mode,base;
static unsigned int rd(void *p,unsigned int reg){
 (void)p;if(reg==0x38a0)return config;
 assert(reg>=0x38e8 && reg<=0x3900 && !(reg&3));return data[(0x3900-reg)/4];
}
static int req(void *p,unsigned int reg,unsigned int value){
 (void)p;assert(reg==0x38e4);assert((value&~0xfffU)==0x80000000U);
 unsigned int idx=value&2047U;assert(idx>=base && idx<base+32);
 requests++;if(requests==fail_at)return -ETIMEDOUT;
 memset(data,0,sizeof(data));
 if(idx!=base+match_way)return 0;
 if(value&(1U<<11)){assert(mode!=1);memcpy(data,fibs[fib_reads?1:0],sizeof(data));fib_reads++;}
 else {memcpy(data,keys[key_reads<3?key_reads:2],sizeof(data));key_reads++;}
 return 0;
}
static struct rtl_fe_cache_expected expected={.hash_index=0xaaa7,.crc32=0x12345678,.crc16=0xb3e1,
 .action={0x12345678,2,3,4,5,6,0xf0000000}};
static const struct rtl_dq_io io={.read=rd,.indirect=req};
static void reset(void){
 requests=key_reads=fib_reads=fail_at=mode=0;match_way=3;base=44*32;
 config=(4U|(3U<<8)|(1U<<16)|(1U<<18));
 for(unsigned int i=0;i<3;i++){
  memset(keys[i],0,sizeof(keys[i]));keys[i][0]=expected.crc32;
  keys[i][1]=0x13e1U|(7U<<13)|(i<<19); /* age0 remains a valid match. */
 }
 memcpy(fibs[0],expected.action,sizeof(fibs[0]));memcpy(fibs[1],fibs[0],sizeof(fibs[1]));
}
static void snapshot_cases(void){
 struct rtl_fe_cache_snapshot s;
 reset();rtl_fe_cache_snapshot(&io,&expected,&s);
 assert(s.complete && s.observation==RTL_FE_CACHE_EQUAL && !s.word_mask && s.scanned==4 && requests==8);
 reset();fibs[0][6]^=0x80000001;fibs[1][6]=fibs[0][6];rtl_fe_cache_snapshot(&io,&expected,&s);
 assert(s.complete && s.observation==RTL_FE_CACHE_DIFFERENT && s.word_mask==64 && s.diff[6]==0x80000001);
 for(unsigned int key=1;key<3;key++){
  reset();keys[key][1]^=1U<<13;rtl_fe_cache_snapshot(&io,&expected,&s);
  assert(!s.complete && s.observation==RTL_FE_CACHE_KEY_CHANGED && !s.word_mask);
 }
 reset();fibs[1][2]^=1;rtl_fe_cache_snapshot(&io,&expected,&s);
 assert(!s.complete && s.observation==RTL_FE_CACHE_FIB_CHANGED && !s.word_mask);
 reset();mode=1;keys[0][1]|=1U<<18;rtl_fe_cache_snapshot(&io,&expected,&s);
 assert(s.complete && s.observation==RTL_FE_CACHE_CHECK_ACTION_ONLY && !fib_reads && requests==32);
 reset();match_way=99;rtl_fe_cache_snapshot(&io,&expected,&s);
 assert(s.complete && s.observation==RTL_FE_CACHE_SET_MISS && requests==32 && s.scanned==32);
 reset();match_way=31;rtl_fe_cache_snapshot(&io,&expected,&s);
 assert(s.complete && s.observation==RTL_FE_CACHE_EQUAL && requests==36 && s.cache_index==base+31);
 for(unsigned int boundary=0;boundary<2;boundary++){
  reset();unsigned short saved=expected.crc16;
  expected.crc16=boundary?0xffff:0;base=boundary?2016:0;
  for(unsigned int k=0;k<3;k++)keys[k][1]=(expected.crc16&8191U)|(7U<<13);
  rtl_fe_cache_snapshot(&io,&expected,&s);assert(s.complete && s.observation==RTL_FE_CACHE_EQUAL);
  expected.crc16=saved;
 }
 for(unsigned int bit=0;bit<4;bit++){
  reset();config^=(unsigned int[]){1,1U<<8,1U<<16,1U<<17}[bit];rtl_fe_cache_snapshot(&io,&expected,&s);
  assert(!s.complete && s.observation==RTL_FE_CACHE_LAYOUT_UNSUPPORTED && !requests);
 }
 for(unsigned int failure=1;failure<=8;failure++){
  reset();fail_at=failure;rtl_fe_cache_snapshot(&io,&expected,&s);
  assert(!s.complete && s.error==-ETIMEDOUT && requests==failure && !s.word_mask);
 }
}
/* Execute the actual production read-op helper with fake MMIO/time at its
 * boundary. The poll records each requested timeout, and can fail pre/post. */
typedef uint64_t u64;typedef uint32_t u32;
#define BIT(x) (1U<<(x))
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
struct rtl_fe {unsigned char *registers;};
static unsigned char regs[0x4000];
static unsigned int polls,writes,poll_fail,timeout_max,last_value;
static u64 now_ns,advance;
static u64 ktime_get_ns(void){u64 n=now_ns;now_ns+=advance;return n;}
static int fake_poll(void *address,unsigned int timeout){
 assert(address==regs+0x38e4);assert(timeout && timeout<=1000);
 if(timeout>timeout_max)timeout_max=timeout;
 polls++;return polls==poll_fail?-ETIMEDOUT:0;
}
#define readl_poll_timeout(address,value,condition,delay,timeout) ((void)(value=0),fake_poll(address,timeout))
static void writel(unsigned int value,void *address){assert(address==regs+0x38e4);writes++;last_value=value;}
'''
checks = r'''
static void access_reset(void){polls=writes=poll_fail=timeout_max=last_value=0;now_ns=advance=0;}
static void access_cases(void){
 struct rtl_fe fe={.registers=regs};struct fe_cache_read_context ctx={.fe=&fe,.deadline=50000000};
 access_reset();assert(!fe_cache_read_access(&ctx,0x38e4,0x80000fff));assert(writes==1 && polls==2 && last_value==0x80000fff && timeout_max==1000);
 access_reset();poll_fail=1;assert(fe_cache_read_access(&ctx,0x38e4,0x80000000)==-ETIMEDOUT);assert(!writes && polls==1);
 access_reset();poll_fail=2;assert(fe_cache_read_access(&ctx,0x38e4,0x80000000)==-ETIMEDOUT);assert(writes==1 && polls==2);
 access_reset();now_ns=ctx.deadline;assert(fe_cache_read_access(&ctx,0x38e4,0x80000000)==-ETIMEDOUT);assert(!writes && !polls);
 access_reset();advance=ctx.deadline;assert(fe_cache_read_access(&ctx,0x38e4,0x80000000)==-ETIMEDOUT);assert(!writes && polls==1);
 access_reset();now_ns=ctx.deadline-2000;assert(!fe_cache_read_access(&ctx,0x38e4,0x80000000));assert(timeout_max==2);
 unsigned int invalid[]={0xc0000000,0x80001000,0,0x40000000};
 for(unsigned int i=0;i<4;i++){access_reset();assert(fe_cache_read_access(&ctx,0x38e4,invalid[i])==-EINVAL);assert(!writes && !polls);}
 access_reset();assert(fe_cache_read_access(&ctx,0x38b0,0x80000000)==-EINVAL);assert(!writes && !polls);
}
int main(void){snapshot_cases();access_cases();puts("FE cache snapshot production helper oracles PASS");return 0;}
'''
with tempfile.TemporaryDirectory(prefix='fe-cache-snapshot-') as temp:
    path = Path(temp)
    (path / 'oracle.c').write_text(fixture + access + checks)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                    '-I', str(drivers), str(path / 'oracle.c'), '-o', str(path / 'oracle')], check=True)
    subprocess.run([str(path / 'oracle')], check=True)
