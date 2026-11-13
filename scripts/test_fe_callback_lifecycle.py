#!/usr/bin/env python3
"""Reproduce AP unregister with an outstanding flowtable callback reference."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c-fe.c').read_text()

def function(name):
    start = source.rfind('\n', 0, source.index(name + '(')) + 1
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'

common = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
struct list_head {struct list_head *next,*prev;};
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_for_each_entry(p,h,m) for(struct list_head *c=(h)->next;c!=(h) && ((p)=container_of(c,__typeof__(*(p)),m));c=c->next)
#define list_for_each_entry_safe(p,n,h,m) for(struct list_head *c=(h)->next,*nc=c->next;c!=(h) && ((p)=container_of(c,__typeof__(*(p)),m),(n)=container_of(nc,__typeof__(*(n)),m),1);c=nc,nc=c->next)
#define list_last_entry(h,t,m) container_of((h)->prev,t,m)
static void init(struct list_head *h){h->next=h->prev=h;}
static void list_add_tail(struct list_head *n,struct list_head *h){n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;}
static void list_del(struct list_head *n){n->prev->next=n->next;n->next->prev=n->prev;}
enum tc_setup_type {TC_SETUP_FT,TC_SETUP_BLOCK};
enum {FLOW_BLOCK_BIND,FLOW_BLOCK_UNBIND,FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS};
struct net_device {int id;};
struct rtl_fe;
struct rtl_fe_port {struct list_head list;struct rtl_fe *fe;struct net_device *netdev;unsigned int bindings;bool retired;};
struct rtl_fe_flow {struct list_head list;struct rtl_fe_port *input,*output;};
struct rtl_fe {struct list_head ports,flows,blocks;int lock;bool shutting_down;};
struct flow_block_cb {struct list_head list,driver_list;void *cb_priv;void (*release)(void *);unsigned int references;};
struct flow_block_offload {int binder_type,command;struct list_head cb_list;struct list_head *driver_block_list;struct flow_block_cb *bound;void *block;};
static unsigned int freed;
static void kfree(void *p){freed++;free(p);}
static void mutex_lock(int *p){assert(!*p);*p=1;}
static void mutex_unlock(int *p){assert(*p);*p=0;}
static int fe_block_callback(enum tc_setup_type t,void *d,void *p){(void)t;(void)d;return ((struct rtl_fe_port *)p)->fe->lock;}
#define IS_ERR(p) false
#define PTR_ERR(p) (-ENOMEM)
static struct flow_block_cb *flow_block_cb_lookup(void *pointer,void *callback,void *id){
 struct flow_block_offload *block=pointer;(void)callback;
 return block->bound && block->bound->cb_priv==id?block->bound:NULL;
}
static struct flow_block_cb *flow_block_cb_alloc(void *callback,void *id,void *priv,void (*release)(void *)){
 struct flow_block_cb *cb=calloc(1,sizeof(*cb));(void)callback;(void)id;assert(cb);
 cb->cb_priv=priv;cb->release=release;return cb;
}
static void flow_block_cb_incref(struct flow_block_cb *cb){cb->references++;}
static unsigned int flow_block_cb_decref(struct flow_block_cb *cb){return --cb->references;}
static void flow_block_cb_add(struct flow_block_cb *cb,struct flow_block_offload *block){
 block->bound=cb;list_add_tail(&cb->list,&block->cb_list);
}
static void flow_block_cb_remove(struct flow_block_cb *cb,struct flow_block_offload *block){(void)cb;(void)block;}

'''
test = r'''
int main(void){
 for(unsigned int i=0;i<2;i++){
  enum tc_setup_type type=i?TC_SETUP_BLOCK:TC_SETUP_FT;
  struct rtl_fe fe={};struct net_device dev={};
  init(&fe.ports);init(&fe.flows);init(&fe.blocks);
  struct rtl_fe_port *port=calloc(1,sizeof(*port));assert(port);
  port->fe=&fe;port->netdev=&dev;list_add_tail(&port->list,&fe.ports);
  struct flow_block_offload block={.binder_type=FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS};init(&block.cb_list);block.block=&block;
  if(type==TC_SETUP_BLOCK) {
   assert(rtl_fe_setup_tc(&fe,&dev,type,&block)==-EOPNOTSUPP);
   assert(!port->bindings && !block.bound);
   list_del(&port->list);free(port);continue;
  }
  assert(!rtl_fe_setup_tc(&fe,&dev,type,&block));assert(port->bindings==1 && block.bound->release);
  assert(!rtl_fe_setup_tc(&fe,&dev,type,&block));
  assert(port->bindings==1 && block.bound->references==2);
  port->retired=true;fe_collect_ports(&fe);
  assert(fe.ports.next==&port->list && !fe_block_callback(type,NULL,block.bound->cb_priv));
  block.command=FLOW_BLOCK_UNBIND;
  assert(!rtl_fe_setup_tc(&fe,&dev,type,&block));
  assert(block.bound->references==1 && fe.blocks.next==&block.bound->driver_list);
  assert(!rtl_fe_setup_tc(&fe,&dev,type,&block));fe_collect_ports(&fe);
  assert(port->bindings==1 && fe.ports.next==&port->list);
  block.bound->release(block.bound->cb_priv);free(block.bound);
  assert(fe.ports.next==&fe.ports && freed==i+1);
 }
 /* A pending old callback and a new active port can have the same netdev
  * pointer after allocator reuse, but they belong to different blocks. */
 struct rtl_fe fe={};struct net_device reused={};
 init(&fe.ports);init(&fe.flows);init(&fe.blocks);
 struct rtl_fe_port *old=calloc(1,sizeof(*old)),*fresh=calloc(1,sizeof(*fresh));assert(old && fresh);
 old->fe=fresh->fe=&fe;old->netdev=fresh->netdev=&reused;
 list_add_tail(&old->list,&fe.ports);
 struct flow_block_offload prior={.binder_type=FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS};
 struct flow_block_offload current={.binder_type=FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS};
 init(&prior.cb_list);init(&current.cb_list);prior.block=&prior;current.block=&current;
 assert(!rtl_fe_setup_tc(&fe,&reused,TC_SETUP_FT,&prior));
 old->retired=true;fe_collect_ports(&fe);
 list_add_tail(&fresh->list,&fe.ports);
 assert(!rtl_fe_setup_tc(&fe,&reused,TC_SETUP_FT,&current));
 assert(prior.bound->cb_priv==old && current.bound->cb_priv==fresh);
 prior.command=FLOW_BLOCK_UNBIND;
 assert(!rtl_fe_setup_tc(&fe,&reused,TC_SETUP_FT,&prior));
 assert(!prior.bound->references && current.bound->references==1);
 prior.bound->release(prior.bound->cb_priv);free(prior.bound);
 assert(fe.ports.next==&fresh->list && fresh->bindings==1);
 /* Shutdown rejects new binds, while a final UNBIND/release remains safe. */
 fe.shutting_down=true;
 assert(rtl_fe_setup_tc(&fe,&reused,TC_SETUP_FT,&current)==-ENODEV);
 assert(current.bound->references==1 && fresh->bindings==1);
 fresh->retired=true;current.command=FLOW_BLOCK_UNBIND;
 assert(!rtl_fe_setup_tc(&fe,&reused,TC_SETUP_FT,&current));
 current.bound->release(current.bound->cb_priv);free(current.bound);
 assert(fe.ports.next==&fe.ports && fe.blocks.next==&fe.blocks && freed==3);
 puts("FE callback lifetime: refcounted bind, retired/new pointer reuse and shutdown unbind passed; bare clsact rejected");
}
'''
with tempfile.TemporaryDirectory(prefix='fe-callback-', dir=root / 'artifacts') as directory:
    p = Path(directory)
    (p / 'test.c').write_text(common + ''.join(function(n) for n in
        ('fe_port', 'fe_collect_ports', 'fe_block_release', 'rtl_fe_setup_tc')) + test)
    subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                    str(p / 'test.c'), '-o', str(p / 'test')], check=True)
    subprocess.run([str(p / 'test')], check=True)
