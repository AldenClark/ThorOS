#!/usr/bin/env python3
"""Execute actual production fe_install on two independently derived colliding tuples."""
from pathlib import Path
import re, subprocess, tempfile
here=Path(__file__).resolve().parent
drivers=here.parent/'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
s=(drivers/'rtl9617c-fe.c').read_text()
def symbol(name):
 start=re.search(r'^static int '+name+r'\(',s,re.M).start();i=s.index('{',start)+1;depth=1
 while depth:depth+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[start:i]
flow=re.search(r'struct rtl_fe_flow \{.*?\n\};',s,re.S).group()
rule=re.search(r'struct rtl_fe_rule \{.*?\n\};',s,re.S).group()
fixture=r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include "rtl9617c-fe-pipeline.h"
typedef unsigned char u8;typedef unsigned short u16;typedef unsigned long long u64;typedef unsigned int u32;typedef unsigned int __le32;
#define BIT(n) (1U<<(n))
#define GFP_KERNEL 0
#define ETH_ALEN 6
#define FE_SOURCE_MACS 15
#define jiffies 1UL
#define VLAN_CFI_MASK 0x1000
#define VLAN_PRIO_SHIFT 13
#define kzalloc(n,f) calloc(1,n)
#define dma_wmb() ((void)0)
#define cpu_to_le32(v) (v)
struct list_head {struct list_head *next,*prev;};struct rb_node {int unused;};
static void INIT_LIST_HEAD(struct list_head *l){l->next=l->prev=l;}
static void list_add_tail(struct list_head *n,struct list_head *h){n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;}
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_for_each_entry(p,h,m) for(struct list_head *cursor=(h)->next;cursor!=(h) && ((p)=container_of(cursor,__typeof__(*(p)),m));cursor=cursor->next)
struct net_device {bool up;};
struct rtl_fe;
struct rtl_fe_port {struct rtl_fe *fe;struct net_device *netdev;bool retired;};
'''
fixture+=flow+rule+r'''
struct rtl_fe {bool enabled;int error;unsigned long installs;void *memory;struct list_head flows;unsigned long hashes[65536/64];};
static int netif_running(struct net_device *d){return d->up;}
static int netif_carrier_ok(struct net_device *d){return d->up;}
static struct rtl_fe_flow *fe_flow(struct rtl_fe *f,unsigned long c){(void)f;(void)c;return NULL;}
static bool test_bit(unsigned int n,unsigned long *b){return b[n/64]&(1UL<<(n%64));}
static void __set_bit(unsigned int n,unsigned long *b){b[n/64]|=1UL<<(n%64);}
static void fe_index_flow(struct rtl_fe *f,struct rtl_fe_flow *v){(void)f;(void)v;}
static void put_unaligned_be32(unsigned int v,u8 *p){p[0]=v>>24;p[1]=v>>16;p[2]=v>>8;p[3]=v;}
static void ether_addr_copy(u8 *p,const u8 *q){memcpy(p,q,6);}
static unsigned int rd(void *p,unsigned int r){(void)p;(void)r;return 0;}
static void wr(void *p,unsigned int r,unsigned int v){(void)p;(void)r;(void)v;}
static int access_ok(void *p,unsigned int r,unsigned int v){(void)p;(void)r;(void)v;return 0;}
static struct rtl_dq_io fe_io(struct rtl_fe *f){return (struct rtl_dq_io){f,rd,wr,access_ok};}
/* Successful unrelated owners are test doubles. The allocator, CRC, DDR
 * publication, action conversion and age publication below are production. */
static int fe_source_get(struct rtl_fe *f,const u8 *a,unsigned int *i){(void)f;(void)a;*i=0;return 0;}
static int fe_destination_get(struct rtl_fe *f,struct rtl_fe_flow *v,const u8 *a){(void)f;(void)a;v->destination_index=1;v->destination_owned=true;return 0;}
static int fe_interface_get(struct rtl_fe *f,struct rtl_fe_flow *v){(void)f;v->counter=1;v->interface_owned=true;return 0;}
static int fe_mtu_get(struct rtl_fe *f,struct rtl_fe_flow *v,unsigned int size){(void)f;(void)v;(void)size;return 0;}
static int fe_delete(struct rtl_fe *f,struct rtl_fe_flow *v){(void)f;(void)v;assert(!"unexpected rollback");return 0;}
'''
fixture+=symbol('fe_install')+r'''
int main(void){
 struct rtl_fe f={.enabled=true};INIT_LIST_HEAD(&f.flows);f.memory=calloc(1,RTL_FE_MEMORY_BYTES);assert(f.memory);
 struct net_device n={.up=true};struct rtl_fe_port p={.fe=&f,.netdev=&n},q=p;
 struct rtl_fe_rule a={.input=&p,.output=&q,.pppoe_input=true,.pppoe_session=1234,
  .key={.source=0x0a000001,.destination=0xc6336401,.source_port=10000,.destination_port=443,.protocol=6,.ingress=7,.llid=1,.mask=63},
  .action={.translate=1,.translate_destination=1,.address=0x0a000064,.destination=3,.check_mask=63}};
 struct rtl_fe_rule b=a;b.key.source=0x0ab82e30;b.key.destination=0xc63364cf;b.key.source_port=8894;b.action.address=0x0a0000c8;
 assert(!fe_install(&p,a,1));int ret=fe_install(&p,b,2);
 const unsigned int *ddr=f.memory;
 assert(ddr[16416]==0x07b0aa2b);
 assert(ret==-EEXIST && !ddr[16417]);
 free(container_of(f.flows.next,struct rtl_fe_flow,list));
 free(f.memory);
 return 0;
}
'''
with tempfile.TemporaryDirectory(dir=here,prefix='main-publish-') as d:
 p=Path(d);(p/'repro.c').write_text(fixture)
 subprocess.run(['cc','-std=c11','-Wno-unused-function','-fsanitize=address,undefined','-I'+str(drivers),str(p/'repro.c'),'-o',str(p/'repro')],check=True)
 r=subprocess.run([str(p/'repro')],capture_output=True,text=True)
 assert r.returncode==0, r.stdout+r.stderr
 print('PASS: same-bucket duplicate CRC32 is rejected before DDR publication')
