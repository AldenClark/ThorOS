#!/usr/bin/env python3
"""Run production FE teardown: failed hardware withdrawal must retain DMA owners."""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c-fe.c').read_text()
start = re.search(r'^void rtl_fe_free\(', source, re.M).start()
end = source.index('{', start) + 1
depth = 1
while depth:
    depth += (source[end] == '{') - (source[end] == '}')
    end += 1
production = source[start:end]

fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#define RTL_FE_MEMORY_BYTES 4096
enum rtl_fe_mode {RTL_FE_MODE_OFF,RTL_FE_MODE_CPU,RTL_FE_MODE_HARDWARE};
struct list_head {struct list_head *next,*prev;};
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_for_each_entry(p,h,m) for(struct list_head *c=(h)->next;c!=(h) && ((p)=container_of(c,__typeof__(*(p)),m));c=c->next)
#define list_for_each_entry_safe(p,n,h,m) for(struct list_head *c=(h)->next,*nc=c->next;c!=(h) && ((p)=container_of(c,__typeof__(*(p)),m),(n)=container_of(nc,__typeof__(*(n)),m),1);c=nc,nc=c->next)
static void init_list(struct list_head *h){h->next=h->prev=h;}
static bool list_empty(struct list_head *h){return h->next==h;}
static void list_add_tail(struct list_head *n,struct list_head *h){n->next=h;n->prev=h->prev;h->prev->next=n;h->prev=n;}
static void list_del(struct list_head *n){n->next->prev=n->prev;n->prev->next=n->next;}
struct rtl_fe_port {struct list_head list;unsigned int bindings;};
struct rtl_fe_flow {struct list_head list;};
struct rtl_fe {
 struct list_head ports,blocks,flows;
 bool shutting_down,engine_ready;
 enum rtl_fe_mode desired_mode;
 int lock,error,fail_disable;
 void *memory,*itu_paths,*device,*bridge,*debug;
 uintptr_t dma;
 unsigned int cleanup_work;
};
static struct rtl_fe *current;
static unsigned int frees,dma_frees,path_frees,warnings,cancelled,debug_removed;
static void mutex_lock(int *lock){assert(!*lock);*lock=1;}
static void mutex_unlock(int *lock){assert(*lock);*lock=0;}
static void fe_bridge_stop(void *bridge){assert(!bridge);}
static void debugfs_remove_recursive(void *debug){(void)debug;assert(current->shutting_down);debug_removed++;}
static void cancel_delayed_work_sync(unsigned int *work){(void)work;assert(current->shutting_down);cancelled++;}
static int fe_disable_locked(struct rtl_fe *fe){assert(fe->lock && fe->shutting_down && !fe->engine_ready);return fe->fail_disable;}
static void dev_err(void *device,const char *format,int error,unsigned int bound){
 (void)device;(void)format;(void)error;(void)bound;assert(current->shutting_down);warnings++;
}
static void kfree(void *pointer){frees++;free(pointer);}
static void kvfree(void *pointer){path_frees++;free(pointer);}
static void dma_free_coherent(void *device,unsigned int bytes,void *pointer,uintptr_t dma){
 (void)device;(void)dma;assert(bytes==RTL_FE_MEMORY_BYTES);assert(cancelled);dma_frees++;free(pointer);
}
static struct rtl_fe *make_owner(void){
 struct rtl_fe *fe=calloc(1,sizeof(*fe));assert(fe);
 init_list(&fe->ports);init_list(&fe->flows);init_list(&fe->blocks);
 fe->memory=malloc(RTL_FE_MEMORY_BYTES);fe->itu_paths=malloc(16);
 assert(fe->memory && fe->itu_paths);fe->engine_ready=true;fe->desired_mode=RTL_FE_MODE_HARDWARE;
 current=fe;frees=dma_frees=path_frees=warnings=cancelled=debug_removed=0;return fe;
}
'''
tests = r'''
int main(void){
 rtl_fe_free(NULL);
 struct rtl_fe *fe=make_owner();
 struct rtl_fe_port *port=calloc(1,sizeof(*port));assert(port);list_add_tail(&port->list,&fe->ports);
 rtl_fe_free(fe);
 assert(dma_frees==1 && path_frees==1 && frees==2 && !warnings && cancelled==1 && debug_removed==1);
 /* No unsafe cleanup succeeds merely because software ownership looks idle. */
 for(unsigned int fault=0;fault<4;fault++){
  fe=make_owner();port=calloc(1,sizeof(*port));assert(port);list_add_tail(&port->list,&fe->ports);
  struct rtl_fe_flow flow={};struct list_head block;
  if(fault==0)fe->fail_disable=-ETIMEDOUT;
  if(fault==1)port->bindings=1; /* release can run after driver-list unbind */
  if(fault==2)list_add_tail(&block,&fe->blocks);
  if(fault==3)list_add_tail(&flow.list,&fe->flows);
  rtl_fe_free(fe);
  assert(fe->shutting_down && !fe->engine_ready && fe->desired_mode==RTL_FE_MODE_OFF);
  assert(!dma_frees && !path_frees && !frees && warnings==1 && cancelled==1 && debug_removed==1);
  assert(fe->error==fe->fail_disable);
  /* Test-only deallocation of deliberately quarantined model objects. Real
   * hardware owners stay allocated until a reboot/drain can be proved. */
  free(port);free(fe->memory);free(fe->itu_paths);free(fe);
 }
 puts("FE teardown: success frees owners; timeout, callback references, driver blocks or residual flows quarantine DMA and private state");
}
'''
with tempfile.TemporaryDirectory(dir=root / 'artifacts', prefix='fe-quarantine-') as directory:
    path = Path(directory)
    (path / 'test.c').write_text(fixture + production + tests)
    subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                    str(path / 'test.c'), '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True)
