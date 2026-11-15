#!/usr/bin/env python3
"""Run real FE allocation: optional CPU index OOM cannot disable the data path.

All allocation failures before bridge publication and both indexed/unindexed
bridge-start failures must release their exact owners. No device is accessed.
"""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'

MODEL = r'''
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rtl9617c-fe-table.h"
#define __iomem
#define GFP_KERNEL 0
#define BIT(n) (1U<<(n))
#define ERR_PTR(err) ((void *)(intptr_t)(err))
#define ERR_CAST(p) ((void *)(p))
#define PTR_ERR(p) ((intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
struct device {int id;};
struct rtl_fe_flow;
struct list_head {struct list_head *next,*prev;};
struct rb_root {void *node;};
#define RB_ROOT ((struct rb_root){NULL})
struct rtl_fe {
 struct device *device;
 void *registers,*memory,*debug,*bridge;
 struct rtl_fe_flow **hash_owners;
 uintptr_t dma;
 unsigned int fdb_cmd_mode_saved,cache_target;
 int lock,route_lock;
 void (*cleanup_work)(void);
 struct list_head ports,flows,blocks,retries;
 struct rb_root cookies,destinations;
};
static bool fail_map,fail_owner,fail_dma,fail_index,fail_bridge;
static unsigned int allocations,releases,debug_created,debug_removed,reo_writes;
static unsigned int reo[64];
static int fe_counters_fops,fe_cache_target_fops,fe_cache_snapshot_fops;
static void *allocate(size_t count,size_t size,bool fail) {
 if(fail)return NULL;
 void *p=calloc(count,size);assert(p);allocations++;return p;
}
static void release(void *p) {if(p){releases++;free(p);}}
static void *kzalloc(size_t bytes,int flags) {(void)flags;return allocate(1,bytes,fail_owner);}
static void kfree(void *p) {release(p);}
static void *kvcalloc(size_t count,size_t bytes,int flags) {
 (void)flags;assert(count==RTL_FE_HASH_ENTRIES && bytes==sizeof(struct rtl_fe_flow *));
 return allocate(count,bytes,fail_index);
}
static void kvfree(void *p) {release(p);}
static void *dma_alloc_coherent(struct device *device,size_t bytes,uintptr_t *dma,int flags) {
 (void)flags;assert(device && bytes==RTL_FE_MEMORY_BYTES);*dma=0x10000000;
 return allocate(1,bytes,fail_dma);
}
static void dma_free_coherent(struct device *device,size_t bytes,void *p,uintptr_t dma) {
 assert(device && bytes==RTL_FE_MEMORY_BYTES && dma==0x10000000);release(p);
}
static void *to_platform_device(struct device *device) {return device;}
static void *devm_platform_ioremap_resource_byname(void *dev,const char *name) {
 assert(dev && !strcmp(name,"l3fe-axi-reorder"));return fail_map?ERR_PTR(-ENXIO):reo;
}
static void mutex_init(int *lock) {*lock=1;}
static void spin_lock_init(int *lock) {*lock=2;}
static void fe_cleanup_work(void) {}
#define INIT_DELAYED_WORK(work,fn) (*(work)=(fn))
static void INIT_LIST_HEAD(struct list_head *head) {head->next=head->prev=head;}
static unsigned int fe_read(struct rtl_fe *fe,unsigned int reg) {
 assert(fe->device && fe->registers && reg==0x1c00);return BIT(31)|0x12345678;
}
#define dma_wmb() ((void)0)
static void *debugfs_create_dir(const char *name,void *parent) {
 assert(!parent && !strcmp(name,"rtl9617c-fe"));debug_created++;return (void *)1;
}
static void debugfs_create_file(const char *name,unsigned int mode,void *dir,void *owner,void *fops) {
 assert(name && (mode==0400 || mode==0200) && dir==(void *)1 && owner && fops);debug_created++;
}
static void debugfs_remove_recursive(void *dir) {assert(dir==(void *)1);debug_removed++;}
static void *fe_bridge_start(struct rtl_fe *fe) {
 assert(fe->lock==1 && fe->route_lock==2 && fe->cleanup_work==fe_cleanup_work);
 assert(fe->ports.next==&fe->ports && fe->flows.next==&fe->flows);
 assert(fe->blocks.next==&fe->blocks && fe->retries.next==&fe->retries);
 assert(!fe->cookies.node && !fe->destinations.node);
 assert(fe->cache_target==RTL_FE_HASH_ENTRIES && fe->fdb_cmd_mode_saved==BIT(31));
 assert((fe->hash_owners==NULL)==fail_index);
 if(fe->hash_owners)for(unsigned int i=0;i<RTL_FE_HASH_ENTRIES;i++)assert(!fe->hash_owners[i]);
 return fail_bridge?ERR_PTR(-EIO):(void *)2;
}
static void writel(unsigned int value,void *address) {
 uintptr_t offset=(uintptr_t)address-(uintptr_t)reo;
 assert(offset>=0x80 && offset<=0x90 && !(offset&3));
 reo[offset/4]=value;reo_writes++;
}
static unsigned int readl(void *address) {return *(unsigned int *)address;}
'''

TEST = r'''
int main(void) {
 struct device device={1};unsigned int registers=0;
 /* Mapping failure, owner OOM, coherent DMA OOM, optional-index OOM and
  * bridge failure combinations. Success is released by the test; actual
  * teardown ordering/quarantine is covered by test_fe_teardown_quarantine. */
 for(unsigned int scenario=0;scenario<7;scenario++) {
  fail_map=scenario==0;fail_owner=scenario==1;fail_dma=scenario==2;
  fail_index=scenario==3 || scenario==5;fail_bridge=scenario==4 || scenario==5;
  allocations=releases=debug_created=debug_removed=reo_writes=0;
  struct rtl_fe *fe=rtl_fe_allocate(&device,&registers);
  if(scenario<3 || fail_bridge) {
   assert(IS_ERR(fe));
   assert(PTR_ERR(fe)==(fail_map?-ENXIO:fail_bridge?-EIO:-ENOMEM));
   assert(!reo_writes && allocations==releases);
   assert(debug_created==(fail_bridge?4U:0U) && debug_removed==(fail_bridge?1U:0U));
  } else {
   assert(!IS_ERR(fe));assert(reo_writes==5 && debug_created==4 && !debug_removed);
   assert((fe->hash_owners==NULL)==fail_index);
   assert(allocations==(fail_index?2U:3U));
   dma_free_coherent(fe->device,RTL_FE_MEMORY_BYTES,fe->memory,fe->dma);
   kvfree(fe->hash_owners);kfree(fe);
   assert(allocations==releases);
  }
 }
 puts("FE allocation: optional 512KiB index OOM preserves startup; mapping/owner/DMA/bridge failures release exact owners");
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    source = (DRIVER / 'rtl9617c-fe.c').read_text()
    start = source.index('struct rtl_fe *rtl_fe_allocate(')
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    allocation = source[start:end]
    with tempfile.TemporaryDirectory(prefix='fe-allocation-', dir=ROOT / 'artifacts') as temporary:
        work = Path(temporary)
        def run(candidate, name):
            file = work / (name + '.c')
            binary = work / name
            file.write_text(MODEL + candidate + TEST)
            subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-g', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-I', str(DRIVER), str(file), '-o', str(binary)], check=True)
            return subprocess.run([str(binary)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = run(allocation, 'baseline')
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        print(result.stdout, end='')
        if args.mutants:
            mutations = {
                'leak-on-bridge-failure': ('  kvfree(fe->hash_owners);', ''),
                'optional-index-becomes-required': (
                    ' defaults=fe->memory+RTL_FE_DEFAULT_OFFSET;',
                    ' if(!fe->hash_owners){dma_free_coherent(fe->device,RTL_FE_MEMORY_BYTES,fe->memory,fe->dma);kfree(fe);return ERR_PTR(-ENOMEM);}\n defaults=fe->memory+RTL_FE_DEFAULT_OFFSET;'),
            }
            for name, (old, new) in mutations.items():
                if old not in allocation:
                    raise RuntimeError('missing mutation anchor: ' + name)
                result = run(allocation.replace(old, new), name)
                if not result.returncode:
                    raise RuntimeError('fault escaped: ' + name)
            print('FE allocation regression assertions rejected both ownership/availability mutations')


if __name__ == '__main__':
    main()
