#!/usr/bin/env python3
"""Exercise FDB rollback and ready sharing across a pending hash withdrawal."""
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
indexed = 'struct rtl_fe_destination {' in source

def function(name):
    start = re.search(r'^static [^;{]*\b' + name + r'\(', source, re.M).start()
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "rtl9617c-fe-pipeline.h"
#include "rtl9617c_destination_tree.h"
typedef unsigned char u8;
#define ETH_ALEN 6
#define FE_DESTINATIONS (4096+32)
#define GFP_KERNEL 0
#define kzalloc(bytes,flags) calloc(1,bytes)
#define kfree(p) free(p)
#define BIT(n) (1U<<(n))
struct list_head {struct list_head *next,*prev;};
static void init(struct list_head *h){h->next=h->prev=h;}
static void add(struct list_head *n,struct list_head *h){n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;}
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_for_each_entry(p,h,m) for(struct list_head *c=(h)->next;c!=(h) && ((p)=container_of(c,__typeof__(*(p)),m));c=c->next)
struct rtl_fe_destination;
struct rtl_fe_flow {
 struct list_head list;
 u8 destination[6];unsigned int destination_index,destination_saved[4];
 bool destination_created,destination_owned,destination_ready,deleting;
 struct rtl_fe_destination *destination_owner;
 bool destination_live;
};
struct rtl_fe {
 struct list_head flows;
 struct rb_root destinations;
 unsigned int destination_count;
 unsigned int window[4],table[4],control,result,writes,commands;
 bool exists,timeout_append,limit_busy;
};
static inline bool ether_addr_equal(const u8 *a,const u8 *b){return !memcmp(a,b,6);}
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
static bool ready(struct rtl_fe_flow *flow){
#ifdef INDEXED_DESTINATIONS
 return flow->destination_owner && flow->destination_owner->ready;
#else
 return flow->destination_ready;
#endif
}
static bool created(struct rtl_fe_flow *flow){
#ifdef INDEXED_DESTINATIONS
 return flow->destination_owner->created;
#else
 return flow->destination_created;
#endif
}
static unsigned int *saved(struct rtl_fe_flow *flow){
#ifdef INDEXED_DESTINATIONS
 return flow->destination_owner->saved;
#else
 return flow->destination_saved;
#endif
}
static void retiring(struct rtl_fe_flow *flow){
 flow->deleting=true;
#ifdef INDEXED_DESTINATIONS
 fe_destination_retire(flow);
#endif
}
static void retiring_shared_owner(void){
 const u8 mac[]={2,1,2,3,4,5};
 const unsigned int order[6][3]={{0,1,2},{0,2,1},{1,0,2},{1,2,0},{2,0,1},{2,1,0}};
 for(unsigned int existing=0;existing<2;existing++)
 for(unsigned int retiring_first=0;retiring_first<2;retiring_first++)
 for(unsigned int permutation=0;permutation<6;permutation++) {
  struct rtl_fe f={0};struct rtl_fe_flow flows[3]={0};unsigned int original[4];
  init(&f.flows);add(&flows[0].list,&f.flows);add(&flows[1].list,&f.flows);add(&flows[2].list,&f.flows);
  rtl_fe_fdb_key(original,mac);original[0]=(original[0]&~(255U<<11))|(37U<<11)|BIT(6);
  memcpy(f.table,original,sizeof(original));f.exists=existing;
  assert(!fe_destination_get(&f,&flows[0],mac));
  assert(!fe_destination_get(&f,&flows[1],mac));
  /* fe_delete marks deleting before withdrawing hash age/cache. A timeout
   * there leaves this confirmed-ready FDB untouched. The second flow owns
   * the same row; list order must not veto new sharing through that owner. */
  retiring(&flows[retiring_first?0:1]);
  unsigned int writes=f.writes,commands=f.commands;
  assert(!fe_destination_get(&f,&flows[2],mac));
  assert(flows[2].destination_owned && ready(&flows[2]));
  assert(flows[2].destination_index==flows[0].destination_index);
  assert(created(&flows[2])==!existing);
  assert(f.writes==writes && f.commands==commands);
  if(existing)assert(!memcmp(saved(&flows[2]),original,sizeof(original)));
  /* Every release ordering keeps the row until the actual last owner.
   * Sharing does not detach the retiring flow's rollback reference. */
  for(unsigned int i=0;i<3;i++) {
   struct rtl_fe_flow *owner=&flows[order[permutation][i]];
   assert(!fe_destination_put(&f,owner));owner->destination_owned=false;
   assert(f.exists==(i==2?existing:true));
   assert(f.commands==commands+(i==2));
  }
  if(existing)assert(!memcmp(f.table,original,sizeof(original)));
  assert(!f.destination_count && RB_EMPTY_ROOT(&f.destinations));
 }
 /* No live owner: do not bypass a pending restore by starting a new
  * lookup/APPEND. A ready retiring row and an uncertain row both refuse. */
 for(unsigned int is_ready=0;is_ready<2;is_ready++) {
  struct rtl_fe f={0};struct rtl_fe_flow a={0},b={0};
  init(&f.flows);add(&a.list,&f.flows);add(&b.list,&f.flows);
  assert(!fe_destination_get(&f,&a,mac));
#ifdef INDEXED_DESTINATIONS
  a.destination_owner->ready=is_ready;
#else
  a.destination_ready=is_ready;
#endif
  retiring(&a);
  unsigned int writes=f.writes,commands=f.commands;
  assert(fe_destination_get(&f,&b,mac)==-EBUSY);
  assert(!b.destination_owned && f.writes==writes && f.commands==commands);
  assert(!fe_destination_put(&f,&a));
  assert(!f.destination_count && RB_EMPTY_ROOT(&f.destinations));
 }
}
int main(void){
 retiring_shared_owner();
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
  assert(a.destination_owned && !ready(&a));
  assert(created(&a)==!existing);
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
  assert(!fe_destination_get(&f,&a,mac) && ready(&a));
  assert(!fe_destination_get(&f,&b,mac) && ready(&b));
  assert(a.destination_index==b.destination_index);
  assert(!fe_destination_put(&f,&a));a.destination_owned=false;
  assert(f.exists);
  assert(!fe_destination_put(&f,&b));b.destination_owned=false;
  assert(f.exists==existing);
  if(existing)assert(!memcmp(f.table,original,sizeof(original)));
  assert(!f.destination_count && RB_EMPTY_ROOT(&f.destinations));
 }
 puts("FDB: 24 retiring/live sharing and release orders; ambiguous APPEND retains ownership; unready/only-retiring rows refused; last-owner restore passed");
}
'''
with tempfile.TemporaryDirectory(prefix='fe-fdb-') as tmp:
    path = Path(tmp)
    owner = re.search(r'struct rtl_fe_destination \{.*?\n\};', source, re.S)[0] if indexed else ''
    support = ''.join(function(n) for n in ('fe_destination_find', 'fe_destination_index', 'fe_destination_retire')) if indexed else ''
    fixture = fixture.replace('struct rtl_fe_destination;', owner or 'struct rtl_fe_destination;')
    (path / 'test.c').write_text(('#define INDEXED_DESTINATIONS 1\n' if indexed else '') + fixture + support + function('fe_destination_get') + function('fe_destination_put') + test)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                    '-I' + str(drivers), '-I' + str(root / 'scripts/fixtures'), str(path / 'test.c'), '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True)
