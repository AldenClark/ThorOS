#!/usr/bin/env python3
"""A timed-out FDB APPEND retains its original row and cannot be shared."""
from pathlib import Path
import argparse
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
drivers = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--revision', help='Run the same fault oracle on older production code')
args = parser.parse_args()
relative = str((drivers / 'rtl9617c-fe.c').relative_to(root))
source = subprocess.check_output(['git', 'show', args.revision + ':' + relative], cwd=root, text=True) if args.revision else (drivers / 'rtl9617c-fe.c').read_text()

def function(name):
    start = re.search(r'^static int ' + name + r'\(', source, re.M).start()
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "rtl9617c-fe-pipeline.h"
typedef unsigned char u8;
#define BIT(n) (1U<<(n))
struct list_head {struct list_head *next,*prev;};
static void init(struct list_head *h){h->next=h->prev=h;}
static void add(struct list_head *n,struct list_head *h){n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;}
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_for_each_entry(p,h,m) for(struct list_head *c=(h)->next;c!=(h) && ((p)=container_of(c,__typeof__(*(p)),m));c=c->next)
struct rtl_fe_flow {
 struct list_head list;
 u8 destination[6];unsigned int destination_index,destination_saved[4];
 bool destination_created,destination_owned,destination_ready,deleting;
};
struct rtl_fe {
 struct list_head flows;
 unsigned int window[4],table[4],control,result,writes,commands;
 bool exists,timeout_append,limit_busy;
};
static bool ether_addr_equal(const u8 *a,const u8 *b){return !memcmp(a,b,6);}
static void ether_addr_copy(u8 *a,const u8 *b){memcpy(a,b,6);}
static unsigned int rd(void *p,unsigned int reg){
 struct rtl_fe *f=p;
 if(reg==0x1ca0)return 0;
 if(reg==0x1cb4)return f->limit_busy?BIT(31):0;
 if(reg==0x1c00)return f->control;
 if(reg==0x1c2c)return f->result;
 assert(reg>=0x1ca4 && reg<=0x1cb0);return f->window[(0x1cb0-reg)/4];
}
static void wr(void *p,unsigned int reg,unsigned int value){
 struct rtl_fe *f=p;
 f->writes++;
 if(reg==0x1c00){f->control=value;return;}
 if(reg==0x1c2c){f->result=value;return;}
 assert(reg>=0x1ca4 && reg<=0x1cb0);f->window[(0x1cb0-reg)/4]=value;
}
static int req(void *p,unsigned int reg,unsigned int value){
 struct rtl_fe *f=p;assert(reg==0x1ca0);
 f->commands++;
 switch(value&255){
 case 4:
  if(f->exists){memcpy(f->window,f->table,sizeof(f->window));f->result=(7<<4)|5;}
  else f->result=15;
  break;
 case 0x45:
  memcpy(f->table,f->window,sizeof(f->table));f->exists=true;f->result=(7<<4)|5;
  if(f->timeout_append){f->timeout_append=false;return -ETIMEDOUT;}
  break;
 case 0x85:f->exists=false;f->result=5;break;
 default:assert(false);
 }
 return 0;
}
static struct rtl_dq_io fe_io(struct rtl_fe *f){return (struct rtl_dq_io){f,rd,wr,req};}
'''
test = r'''
int main(void){
 const u8 mac[]={2,1,2,3,4,5};
 for(unsigned int existing=0;existing<2;existing++){
  struct rtl_fe f={0};struct rtl_fe_flow a={0},b={0};unsigned int original[4];
  init(&f.flows);add(&a.list,&f.flows);add(&b.list,&f.flows);
  rtl_fe_fdb_key(original,mac);
  /* A legitimate old private reference may have refreshed/changed ageing
   * state. Foreign dynamic or non-private rows must no longer be borrowed. */
  original[0]=(original[0]&~(255U<<11))|(37U<<11)|BIT(6);
  memcpy(f.table,original,sizeof(original));f.exists=existing;f.timeout_append=true;
  f.limit_busy=true;
  assert(fe_destination_get(&f,&a,mac)==-EBUSY);
  assert(!a.destination_owned && !f.writes && !f.commands);
  f.limit_busy=false;
  assert(fe_destination_get(&f,&a,mac)==-ETIMEDOUT);
  assert(a.destination_owned && !a.destination_ready);
  assert(a.destination_created==!existing);
  assert(fe_destination_get(&f,&b,mac)==-EBUSY && !b.destination_owned);
  /* A late MAC-limit command must also block rollback, without discarding
   * the destination's ownership or changing the shared mode/DATA windows. */
  f.limit_busy=true;unsigned int writes=f.writes,commands=f.commands;
  assert(fe_destination_put(&f,&a)==-EBUSY && a.destination_owned);
  assert(f.writes==writes && f.commands==commands && f.exists);
  f.limit_busy=false;
  assert(!fe_destination_put(&f,&a));a.destination_owned=false;
  assert(f.exists==existing);
  if(existing)assert(!memcmp(f.table,original,sizeof(original)));
  assert(!fe_destination_get(&f,&a,mac) && a.destination_ready);
  assert(!fe_destination_get(&f,&b,mac) && b.destination_ready);
  assert(a.destination_index==b.destination_index);
  assert(!fe_destination_put(&f,&a));a.destination_owned=false;
  assert(f.exists);
  assert(!fe_destination_put(&f,&b));b.destination_owned=false;
  assert(f.exists==existing);
  if(existing)assert(!memcmp(f.table,original,sizeof(original)));
 }
 puts("FDB: ambiguous APPEND retains rollback ownership; unready rows cannot be shared; existing/new last-owner restore passed");
}
'''
with tempfile.TemporaryDirectory(prefix='fe-fdb-') as tmp:
    path = Path(tmp)
    (path / 'test.c').write_text(fixture + function('fe_destination_get') + function('fe_destination_put') + test)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                    '-I' + str(drivers), str(path / 'test.c'), '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True)
