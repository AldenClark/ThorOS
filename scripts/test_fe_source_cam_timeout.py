#!/usr/bin/env python3
"""Read-only frozen production extraction; expected failure proves lost CAM restore snapshot."""
from pathlib import Path
import subprocess, tempfile, re, json
here=Path(__file__).resolve().parent
source=here.parent/'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c-fe.c'
s=source.read_text();drivers=source.parent
assert 'flow->source_mac=FE_SOURCE_MACS;' in s
assert 'flow->source_owned=flow->source_mac!=FE_SOURCE_MACS;' in s
assert s.index('flow->source_owned=flow->source_mac!=FE_SOURCE_MACS;') < s.index('if(ret)goto rollback;', s.index('flow->source_mac=FE_SOURCE_MACS;'))

def function(name):
 start=re.search(r'^static int '+name+r'\(',s,re.M).start();end=s.index('{',start)+1;depth=1
 while depth:
  depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[start:end]
fixture=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "rtl9617c-fe-pipeline.h"
typedef unsigned char u8;
#define FE_SOURCE_MACS 15
#define ETH_ALEN 6
#define BIT(n) (1U<<(n))
struct rtl_fe_mac {unsigned int users,saved[5];bool ready;u8 address[6];};
struct rtl_fe {struct rtl_fe_mac source_macs[15];unsigned int window[5],cam[15][5];bool timeout_write;};
static bool ether_addr_equal(const u8 *a,const u8 *b){return !memcmp(a,b,6);}
static void ether_addr_copy(u8 *a,const u8 *b){memcpy(a,b,6);}
static unsigned int rd(void *p,unsigned int reg){struct rtl_fe *f=p;if(reg==0x3200)return 0;assert(reg>=0x3204 && reg<=0x3214);return f->window[(0x3214-reg)/4];}
static void wr(void *p,unsigned int reg,unsigned int value){struct rtl_fe *f=p;assert(reg>=0x3204 && reg<=0x3214);f->window[(0x3214-reg)/4]=value;}
static int req(void *p,unsigned int reg,unsigned int value){
 struct rtl_fe *f=p;assert(reg==0x3200 && ((value>>16)&15)==3);unsigned int index=value&15;assert(index<15);
 if(value&BIT(30)){
  /* A polling timeout does not roll back a hardware write. The requested
   * CAM state can have landed while software did not observe completion. */
  memcpy(f->cam[index],f->window,sizeof(f->window));
  if(f->timeout_write){f->timeout_write=false;return -ETIMEDOUT;}
 }else memcpy(f->window,f->cam[index],sizeof(f->window));
 return 0;
}
static struct rtl_dq_io fe_io(struct rtl_fe *f){return (struct rtl_dq_io){f,rd,wr,req};}
'''
test=r'''
int main(void){
 struct rtl_fe f={0};unsigned int original[5]={0x11223344,0x00010200,0,0,0};memcpy(f.cam[0],original,sizeof(original));
 const u8 a[6]={2,0,0,0,0,1},b[6]={2,0,0,0,0,2};unsigned int index=15;
 f.timeout_write=true;
 assert(fe_source_get(&f,a,&index)==-ETIMEDOUT);
 /* The caller uses index != FE_SOURCE_MACS to transfer ownership to its
  * rollback flow even though the write completion was not observed. */
 assert(index==0 && f.source_macs[0].users==1);
 assert(!f.source_macs[0].ready);
 /* An uncertain CAM write must not be shared by another acquisition. */
 unsigned int second=15;
 assert(fe_source_get(&f,a,&second)==-EBUSY && second==15);
 assert(f.source_macs[0].users==1);
 assert(memcmp(f.cam[0],original,sizeof(original)));
 assert(!fe_source_put(&f,index));
 assert(!f.source_macs[0].users && !memcmp(f.cam[0],original,sizeof(original)));
 assert(!fe_source_get(&f,b,&index) && index==0);
 assert(!fe_source_put(&f,index));
 assert(!memcmp(f.cam[0],original,sizeof(original)));
 return 0;
}
'''
with tempfile.TemporaryDirectory(dir=here,prefix='source-cam-') as d:
 p=Path(d);(p/'repro.c').write_text(fixture+function('fe_source_get')+function('fe_source_put')+test)
 subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-function','-fsanitize=address,undefined','-I'+str(drivers),str(p/'repro.c'),'-o',str(p/'repro')],check=True)
 subprocess.run([str(p/'repro')],check=True)
 print('PASS: timed-out source CAM acquisition preserves rollback ownership and original snapshot')
