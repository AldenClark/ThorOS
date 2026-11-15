#!/usr/bin/env python3
"""Production MAC-pin owner index, Linux rbtree, scale and delayed-MMIO faults.

Requires a prepared Linux source tree for its actual tools/lib/rbtree.c.
--before runs the identical scale workload on the old full-flow-list code and
expects its traversal bound to fail. Counts are software operations, NOT ASIC
throughput, packet-buffer capacity, or a physical forwarding benchmark.
"""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--kernel', required=True, type=Path)
parser.add_argument('--before', action='store_true')
parser.add_argument('--baseline', default='HEAD')
parser.add_argument('--mutants', action='store_true')
args = parser.parse_args()
relative = 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c-fe.c'
driver = root / relative
native = subprocess.check_output(['git', 'show', args.baseline + ':' + relative],
                                cwd=root, text=True) if args.before else driver.read_text()
indexed = 'struct rtl_fe_destination {' in native
assert indexed != args.before, 'Baseline must use the full-flow-list destination implementation'


def function(name):
    start = re.search(r'^static [^;{]*\b' + name + r'\(', native, re.M).start()
    end = native.index('{', start) + 1
    depth = 1
    while depth:
        depth += (native[end] == '{') - (native[end] == '}')
        end += 1
    return native[start:end] + '\n'


common = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include "rtl9617c-fe-pipeline.h"
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define ETH_ALEN 6
#define FE_DESTINATIONS (4096+32)
#define GFP_KERNEL 0
#define BIT(n) (1U<<(n))
struct rtl_fe_port;
static unsigned long long visits, allocations, frees;
static bool fail_allocate;
static inline void *kzalloc(size_t bytes,int flags){
 (void)flags;
 if(fail_allocate){fail_allocate=false;return NULL;}
 void *result=calloc(1,bytes);if(result)allocations++;return result;
}
static inline void kfree(void *pointer){assert(pointer);frees++;free(pointer);}
static inline void ether_addr_copy(u8 *a,const u8 *b){memcpy(a,b,ETH_ALEN);}
static inline bool ether_addr_equal(const u8 *a,const u8 *b){return !memcmp(a,b,ETH_ALEN);}
/* Count actual production traversals; Linux's balancing is not replaced. */
#undef rb_entry
#define rb_entry(p,t,m) (++visits,container_of(p,t,m))
#undef list_for_each_entry
#define list_for_each_entry(p,h,m) for(p=list_first_entry(h,__typeof__(*p),m); \
 &p->m!=(h) && (++visits);p=list_next_entry(p,m))
struct row {bool exists;unsigned int words[4];};
struct rtl_fe {
 struct list_head flows;
 struct rb_root destinations;
 unsigned int destination_count;
 struct row table[FE_DESTINATIONS+1];
 unsigned int window[4],control,result,commands,writes;
 unsigned int timeout_at,pending_command,pending_words[4];
 bool busy;
};
static unsigned int field(const unsigned int words[4],unsigned int bit,unsigned int width){
 unsigned int result=0;
 for(unsigned int i=0;i<width;i++)result|=((words[(bit+i)/32]>>((bit+i)%32))&1U)<<i;
 return result;
}
static unsigned int model_id(const unsigned int words[4]){
 unsigned int id=field(words,51,24);assert(id<=FE_DESTINATIONS);return id;
}
static void model_complete(struct rtl_fe *fe,unsigned int command){
 struct row *row=&fe->table[model_id(fe->window)];
 unsigned int index=model_id(fe->window)%FE_DESTINATIONS;
 if(command==4){
  if(row->exists){memcpy(fe->window,row->words,sizeof(fe->window));fe->result=(index<<4)|5;}
  else fe->result=15;
 } else if(command==0x45){
  memcpy(row->words,fe->window,sizeof(row->words));row->exists=true;fe->result=(index<<4)|5;
 } else if(command==0x85){
  fe->result=row->exists?5:15;row->exists=false;
 } else assert(false);
}
static unsigned int read_register(void *context,unsigned int reg){
 struct rtl_fe *fe=context;
 if(reg==0x1ca0)return fe->busy?BIT(31):0;
 if(reg==0x1cb4)return 0;
 if(reg==0x1c00)return fe->control;
 if(reg==0x1c2c)return fe->result;
 assert(reg>=0x1ca4 && reg<=0x1cb0);return fe->window[(0x1cb0-reg)/4];
}
static void write_register(void *context,unsigned int reg,unsigned int value){
 struct rtl_fe *fe=context;assert(!fe->busy);fe->writes++;
 if(reg==0x1c00){fe->control=value;return;}
 if(reg==0x1c2c){fe->result=value;return;}
 assert(reg>=0x1ca4 && reg<=0x1cb0);fe->window[(0x1cb0-reg)/4]=value;
}
static int access_register(void *context,unsigned int reg,unsigned int value){
 struct rtl_fe *fe=context;assert(reg==0x1ca0 && !fe->busy);
 fe->commands++;
 if(fe->commands==fe->timeout_at){
  fe->busy=true;fe->pending_command=value&255;
  memcpy(fe->pending_words,fe->window,sizeof(fe->pending_words));return -ETIMEDOUT;
 }
 model_complete(fe,value&255);return 0;
}
static struct rtl_dq_io fe_io(struct rtl_fe *fe){
 return (struct rtl_dq_io){fe,read_register,write_register,access_register};
}
static inline void late_completion(struct rtl_fe *fe){
 assert(fe->busy);assert(!memcmp(fe->window,fe->pending_words,sizeof(fe->window)));
 fe->busy=false;model_complete(fe,fe->pending_command);
}
'''

tests = r'''
static void init_fe(struct rtl_fe *fe){memset(fe,0,sizeof(*fe));INIT_LIST_HEAD(&fe->flows);}
static void mac_for(unsigned int id,u8 mac[ETH_ALEN]){
 memcpy(mac,(u8[]){2,16,32,0,0,0},ETH_ALEN);
 mac[3]=id>>16;mac[4]=id>>8;mac[5]=id;
}
static int acquire(struct rtl_fe *fe,struct rtl_fe_flow *flow,unsigned int id){
 u8 mac[ETH_ALEN];mac_for(id,mac);return fe_destination_get(fe,flow,mac);
}
static void retire(struct rtl_fe_flow *flow){
 flow->deleting=true;
#ifdef INDEXED_DESTINATIONS
 fe_destination_retire(flow);
#endif
}
static void release(struct rtl_fe *fe,struct rtl_fe_flow *flow){
 retire(flow);assert(!fe_destination_put(fe,flow));flow->destination_owned=false;
 list_del(&flow->list);
}
static void scale(void){
 const unsigned int count=16384,unique=2048;
 struct rtl_fe *fe=calloc(1,sizeof(*fe));assert(fe);init_fe(fe);
 struct rtl_fe_flow *flows=calloc(count,sizeof(*flows));assert(flows);
 visits=0;
 for(unsigned int i=0;i<count;i++){
  list_add_tail(&flows[i].list,&fe->flows);assert(!acquire(fe,&flows[i],i%unique));
 }
 printf("destination scale: flows=%u distinct_macs=%u insert_node_visits=%llu commands=%u flow_bytes=%zu\n",
        count,unique,visits,fe->commands,sizeof(struct rtl_fe_flow));fflush(stdout);
 assert(visits<(unsigned long long)count*64);
 assert(fe->commands==unique*3);
#ifdef INDEXED_DESTINATIONS
 assert(fe->destination_count==unique);
 for(unsigned int i=0;i<unique;i++)assert(flows[i].destination_owner->users==count/unique);
#endif
 visits=0;
 /* A full permutation changes which flow releases each shared row last. */
 for(unsigned int i=0;i<count;i++)release(fe,&flows[(i*4051U)&(count-1)]);
 assert(list_empty(&fe->flows));assert(fe->commands==unique*4);
#ifdef INDEXED_DESTINATIONS
 assert(!fe->destination_count && RB_EMPTY_ROOT(&fe->destinations));
 assert(visits==0); /* put follows the owner pointer, never searches. */
#endif
 printf("destination scale: release_search_visits=%llu commands=%u\n",visits,fe->commands);
 assert(allocations==frees);free(flows);free(fe);
}
#ifdef INDEXED_DESTINATIONS
static void capacity(void){
 const unsigned int count=65536;
 struct rtl_fe *fe=calloc(1,sizeof(*fe));assert(fe);init_fe(fe);
 struct rtl_fe_flow *flows=calloc(count+1,sizeof(*flows));assert(flows);
 unsigned long long allocated=allocations;
 for(unsigned int i=0;i<count;i++){
  list_add_tail(&flows[i].list,&fe->flows);
  assert(!acquire(fe,&flows[i],i%FE_DESTINATIONS));
 }
 assert(fe->destination_count==FE_DESTINATIONS && allocations-allocated==FE_DESTINATIONS);
 assert(fe->commands==FE_DESTINATIONS*3);
 unsigned int commands=fe->commands,writes=fe->writes;
 assert(acquire(fe,&flows[count],FE_DESTINATIONS)==-ENOSPC);
 assert(!flows[count].destination_owned && fe->commands==commands && fe->writes==writes);
 /* Existing pins may still be shared when every physical row is owned. */
 assert(!acquire(fe,&flows[count],0));
 assert(fe->commands==commands && fe->writes==writes);
 assert(!fe_destination_put(fe,&flows[count]));
 for(unsigned int i=0;i<count;i++)release(fe,&flows[(i*4051U)&(count-1)]);
 assert(!fe->destination_count && RB_EMPTY_ROOT(&fe->destinations));
 assert(allocations==frees);
 printf("destination capacity: 65536 refs / 4128 pins, owner_bytes=%zu max_owner_bytes=%zu, no overcommit\n",
        sizeof(struct rtl_fe_destination),sizeof(struct rtl_fe_destination)*FE_DESTINATIONS);
 free(flows);free(fe);
}
static void faults(void){
 struct rtl_fe *fe=calloc(1,sizeof(*fe));assert(fe);
 struct rtl_fe_flow a={0},b={0},c={0};
 /* Every LOOKUP/APPEND/verification completion can be delayed. The actual
  * FDB helper must leave DATA untouched while ACCESS is still in flight. */
 for(unsigned int existing=0;existing<2;existing++)
 for(unsigned int phase=1;phase<=3;phase++){
  init_fe(fe);memset(&a,0,sizeof(a));memset(&b,0,sizeof(b));
  u8 mac[ETH_ALEN];mac_for(7,mac);unsigned int original[4];rtl_fe_fdb_key(original,mac);
  original[0]=(original[0]&~(255U<<11))|(37U<<11)|BIT(6);
  if(existing){fe->table[7].exists=true;memcpy(fe->table[7].words,original,sizeof(original));}
  fe->timeout_at=phase;
  assert(acquire(fe,&a,7)==-ETIMEDOUT && fe->busy);
  unsigned int commands=fe->commands,writes=fe->writes;
  assert(a.destination_owned==(phase>1));
  assert(fe->destination_count==(phase>1));
  assert(acquire(fe,&b,7)==-EBUSY && !b.destination_owned);
  assert(fe->commands==commands && fe->writes==writes);
  if(phase>1){
   struct rtl_fe_destination *owner=a.destination_owner;
   assert(!owner->ready && owner->users==1 && owner->live_users==1);
   retire(&a);retire(&a);assert(!owner->live_users && owner->users==1);
   assert(fe_destination_put(fe,&a)==-EBUSY && a.destination_owner==owner);
   assert(!owner->ready && !owner->live_users && owner->users==1);
   assert(fe->commands==commands && fe->writes==writes);
  }
  late_completion(fe);
  if(phase>1)assert(!fe_destination_put(fe,&a));
  assert(fe->table[7].exists==existing);
  if(existing)assert(!memcmp(fe->table[7].words,original,sizeof(original)));
  assert(!fe->destination_count && RB_EMPTY_ROOT(&fe->destinations));
  assert(allocations==frees);
 }
 /* Allocation failure has not modified the discovered row or gained an
  * owner; another flow can acquire it without waiting for cleanup. */
 init_fe(fe);memset(&a,0,sizeof(a));fail_allocate=true;
 assert(acquire(fe,&a,7)==-ENOMEM && fe->commands==1);
 assert(!a.destination_owned && !fe->destination_count && !fe->table[7].exists);
 assert(!acquire(fe,&a,7));assert(a.destination_owner->ready);
 unsigned int commands=fe->commands;
 assert(acquire(fe,&a,7)==-EALREADY && fe->commands==commands);
 assert(a.destination_owner->users==1 && a.destination_owner->live_users==1);
 assert(!fe_destination_put(fe,&a));
 assert(fe_destination_put(fe,&a)==-EINVAL);assert(allocations==frees);
 /* A pending hash withdrawal keeps its pin, but another live reference
  * authorizes zero-MMIO sharing. All-retiring refs no longer do. */
 init_fe(fe);memset(&a,0,sizeof(a));memset(&b,0,sizeof(b));memset(&c,0,sizeof(c));
 assert(!acquire(fe,&a,7) && !acquire(fe,&b,7));
 struct rtl_fe_destination *owner=a.destination_owner;
 retire(&a);retire(&a);assert(owner->users==2 && owner->live_users==1);
 commands=fe->commands;assert(!acquire(fe,&c,7) && fe->commands==commands);
 assert(c.destination_owner==owner && owner->users==3 && owner->live_users==2);
 assert(!fe_destination_put(fe,&c));assert(owner->users==2 && owner->live_users==1);
 retire(&b);assert(owner->users==2 && !owner->live_users);
 assert(acquire(fe,&c,7)==-EBUSY && fe->commands==commands);
 assert(!fe_destination_put(fe,&a));assert(owner->users==1 && !owner->live_users);
 assert(!fe_destination_put(fe,&b));assert(!fe->destination_count && allocations==frees);
 /* Last-owner DELETE or restore may complete after timeout. Keep the
  * indexed owner and original snapshot until a successful idempotent retry. */
 for(unsigned int existing=0;existing<2;existing++){
  init_fe(fe);memset(&a,0,sizeof(a));memset(&b,0,sizeof(b));
  u8 mac[ETH_ALEN];mac_for(7,mac);unsigned int original[4];rtl_fe_fdb_key(original,mac);
  original[0]=(original[0]&~(255U<<11))|(37U<<11)|BIT(6);
  if(existing){fe->table[7].exists=true;memcpy(fe->table[7].words,original,sizeof(original));}
  assert(!acquire(fe,&a,7));owner=a.destination_owner;fe->timeout_at=fe->commands+1;
  assert(fe_destination_put(fe,&a)==-ETIMEDOUT);
  assert(a.destination_owner==owner && a.destination_owned && !a.destination_live);
  assert(owner->users==1 && !owner->live_users && !owner->ready);
  commands=fe->commands;unsigned int writes=fe->writes;
  assert(acquire(fe,&b,7)==-EBUSY);
  assert(fe_destination_put(fe,&a)==-EBUSY && a.destination_owner==owner);
  assert(fe->commands==commands && fe->writes==writes && fe->destination_count==1);
  late_completion(fe);assert(!fe_destination_put(fe,&a));
  assert(!a.destination_owned && !a.destination_owner && !fe->destination_count);
  assert(fe->table[7].exists==existing);
  if(existing)assert(!memcmp(fe->table[7].words,original,sizeof(original)));
  assert(!acquire(fe,&b,7));assert(!fe_destination_put(fe,&b));
  assert(allocations==frees);
 }
 free(fe);
 puts("destination owner: allocation, delayed completion, shared/retiring refs, last restore, rollback quarantine and reuse passed");
}
#endif
int main(void){
 scale();
#ifdef INDEXED_DESTINATIONS
 capacity();faults();
#endif
 return 0;
}
'''

flow = re.search(r'struct rtl_fe_flow \{.*?\n\};', native, re.S)[0]
owner = re.search(r'struct rtl_fe_destination \{.*?\n\};', native, re.S)[0] if indexed else ''
support = ''.join(function(n) for n in ('fe_destination_find', 'fe_destination_index',
                                      'fe_destination_retire')) if indexed else ''
program = ('#define INDEXED_DESTINATIONS 1\n' if indexed else '') + common + owner + flow + support
program += function('fe_destination_get') + function('fe_destination_put') + tests
with tempfile.TemporaryDirectory(prefix='fe-destination-index-') as directory:
    work = Path(directory)
    src, binary = work / 'index.c', work / 'index'
    flags = ['cc', '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
             '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
             '-I' + str(args.kernel / 'tools/include'), '-I' + str(driver.parent)]
    tree = work / 'rbtree.o'
    # Linux's dummy augmentation callbacks intentionally ignore arguments;
    # retain strict warnings for the actual driver/harness translation unit.
    subprocess.run(flags + ['-Wno-unused-parameter', '-c',
                           str(args.kernel / 'tools/lib/rbtree.c'), '-o', str(tree)], check=True)
    src.write_text(program)
    subprocess.run(flags + [str(src), str(tree),
                           '-o', str(binary)], check=True)
    run = subprocess.run([str(binary)], text=True, capture_output=True)
    print(run.stdout, end='')
    if args.before:
        assert run.returncode and 'visits<' in run.stderr, run.stderr
        print('Original full-flow-list source fails the same traversal bound as expected')
    else:
        if run.returncode:
            print(run.stderr, end='')
        run.check_returncode()
    if args.mutants:
        assert indexed, '--mutants cannot be combined with --before'
        mutations = {
            'share_uncertain_writer': ('if(!owner->ready || !owner->live_users)',
                                       'if(!owner->live_users)'),
            'share_only_retiring': ('if(!owner->ready || !owner->live_users)',
                                    'if(!owner->ready)'),
            'retire_reference_twice': ('if(flow->destination_live)',
                                       'if(flow->destination_owned)'),
            'release_shared_row_early': ('if(owner->users==1)', 'if(owner->users>=1)'),
            'ignore_physical_capacity': ('if(fe->destination_count>=FE_DESTINATIONS)',
                                         'if(false)'),
            'forget_failed_last_release': ('if(ret)return ret;\n  /* Release is idempotent',
                                           'if(ret)ret=0;\n  /* Release is idempotent'),
        }
        for name, (before, after) in mutations.items():
            assert before in program, name
            mutant, executable = work / (name + '.c'), work / name
            mutant.write_text(program.replace(before, after, 1))
            subprocess.run(flags + [str(mutant), str(tree),
                                   '-o', str(executable)], check=True)
            rejected = subprocess.run([str(executable)], text=True, capture_output=True)
            assert rejected.returncode, f'{name} escaped the behavioral oracle'
            assert ('Assertion' in rejected.stderr or 'AddressSanitizer' in rejected.stderr or
                    'runtime error:' in rejected.stderr), rejected.stderr
            print('Rejected destination-owner mutant: ' + name)
