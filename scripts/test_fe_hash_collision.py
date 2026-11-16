#!/usr/bin/env python3
"""Execute actual production fe_install on two independently derived colliding tuples."""
from pathlib import Path
import argparse, re, subprocess, tempfile
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--mutants',action='store_true')
args=parser.parse_args()
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
static unsigned int allocations,mmio;
static void *test_alloc(size_t bytes){allocations++;return calloc(1,bytes);}
#define kzalloc(n,f) test_alloc(n)
#define dma_wmb() ((void)0)
#define cpu_to_le32(v) (v)
#define le32_to_cpu(v) (v)
struct list_head {struct list_head *next,*prev;};struct rb_node {int unused;};
static void INIT_LIST_HEAD(struct list_head *l){l->next=l->prev=l;}
static void list_add_tail(struct list_head *n,struct list_head *h){n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;}
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
static unsigned long traversed;
#define list_for_each_entry(p,h,m) for(struct list_head *cursor=(h)->next;cursor!=(h) && (++traversed,((p)=container_of(cursor,__typeof__(*(p)),m)));cursor=cursor->next)
struct net_device {bool up;};
struct rtl_fe;
struct rtl_fe_port {struct rtl_fe *fe;struct net_device *netdev;bool retired;};
'''
fixture+=flow+rule+r'''
struct rtl_fe {bool enabled,engine_ready,shutting_down,fabric_authorized,naptv6;const struct net_device *denied_port;int error;unsigned long installs;void *memory;struct rtl_fe_flow **hash_owners;struct list_head flows,retries;unsigned long hashes[65536/64];};
/* The actual epoch/identity policy is covered by the switch worker test.
 * Here the publisher must honor that policy BEFORE any allocation/MMIO. */
static bool fe_switch_flow_ports_allowed(struct rtl_fe *f,const struct net_device *input,const struct net_device *output)
{return f->fabric_authorized && input && output && input!=f->denied_port && output!=f->denied_port;}
static int netif_running(struct net_device *d){return d->up;}
static int netif_carrier_ok(struct net_device *d){return d->up;}
static struct rtl_fe_flow *fe_flow(struct rtl_fe *f,unsigned long c){(void)f;(void)c;return NULL;}
static bool test_bit(unsigned int n,unsigned long *b){return b[n/64]&(1UL<<(n%64));}
static void __set_bit(unsigned int n,unsigned long *b){b[n/64]|=1UL<<(n%64);}
static void fe_index_flow(struct rtl_fe *f,struct rtl_fe_flow *v){(void)f;(void)v;}
static void put_unaligned_be32(unsigned int v,u8 *p){p[0]=v>>24;p[1]=v>>16;p[2]=v>>8;p[3]=v;}
static void ether_addr_copy(u8 *p,const u8 *q){memcpy(p,q,6);}
static unsigned int rd(void *p,unsigned int r){(void)p;(void)r;mmio++;return 0;}
static void wr(void *p,unsigned int r,unsigned int v){(void)p;(void)r;(void)v;mmio++;}
static int access_ok(void *p,unsigned int r,unsigned int v){(void)p;(void)r;(void)v;mmio++;return 0;}
static struct rtl_dq_io fe_io(struct rtl_fe *f){return (struct rtl_dq_io){f,rd,wr,access_ok};}
/* Successful unrelated owners are test doubles. The allocator, CRC, DDR
 * publication, action conversion and age publication below are production. */
static int fe_source_get(struct rtl_fe *f,const u8 *a,unsigned int *i){(void)f;(void)a;*i=0;return 0;}
static int fe_destination_get(struct rtl_fe *f,struct rtl_fe_flow *v,const u8 *a){(void)f;(void)a;v->destination_index=1;v->destination_owned=true;return 0;}
static int fe_interface_get(struct rtl_fe *f,struct rtl_fe_flow *v){(void)f;v->counter=1;v->interface_owned=true;return 0;}
/* Actual MTU pool ownership is tested separately by test_fe_mtu. Select a
 * nonzero slot here so production install/packing cannot pass by default. */
static int fe_mtu_get(struct rtl_fe *f,struct rtl_fe_flow *v,unsigned int size){(void)f;assert(size==1400);v->mtu_owned=true;v->mtu_index=9;return 0;}
static int fe_delete(struct rtl_fe *f,struct rtl_fe_flow *v){(void)f;(void)v;assert(!"unexpected rollback");return 0;}
'''
fixture+=symbol('fe_install')+r'''
static unsigned int packed_bits(const unsigned int *words,unsigned int offset,unsigned int width)
{
 unsigned int result=0;
 for(unsigned int bit=0;bit<width;bit++)
  result|=((words[(offset+bit)/32]>>((offset+bit)%32))&1U)<<bit;
 return result;
}
static void naptv6_publication(void)
{
 struct rtl_fe f={.enabled=true,.engine_ready=true,.fabric_authorized=true};
 INIT_LIST_HEAD(&f.flows);INIT_LIST_HEAD(&f.retries);
 f.memory=calloc(1,RTL_FE_MEMORY_BYTES);assert(f.memory);
 f.hash_owners=calloc(RTL_FE_HASH_ENTRIES,sizeof(*f.hash_owners));assert(f.hash_owners);
 struct net_device n={.up=true},out={.up=true};
 struct rtl_fe_port p={.fe=&f,.netdev=&n},q={.fe=&f,.netdev=&out};
 struct rtl_fe_rule rule={.input=&p,.output=&q,.mtu=1400,.ipv6=true,
  .key={.protocol=17,.source_port=12345,.destination_port=443,.ingress=0,.mask=63},
  .key6={.source={0x20010db8,0x12345678,0xc0ffee12,0x87654321},
   .destination={0x20010db9,0xdeadbeef,0xaabbccdd,0x11223344},
   .protocol=17,.source_port=12345,.destination_port=443,.ingress=0,.mask=63},
  .action={.translate=1,.translate_ipv6=1,.translate_destination=1,
   .address6_high={0x20020db8,0x98765432,0xdeadb00f},.address=0xa1b2c3d4,
   .port=65535,.destination=3,.check_mask=63}};
 unsigned int old_allocations=allocations,old_mmio=mmio;
 assert(fe_install(&p,rule,300)==-EOPNOTSUPP); /* Immutable NORMAL profile. */
 f.naptv6=true;
 struct rtl_fe_rule bad=rule;bad.action.translate_ipv6=0;
 assert(fe_install(&p,bad,300)==-EOPNOTSUPP);
 bad=rule;bad.ipv6=false;
 assert(fe_install(&p,bad,300)==-EOPNOTSUPP);
 bad=rule;bad.action.translate=false;
 assert(fe_install(&p,bad,300)==-EOPNOTSUPP);
 for(unsigned int scope=0;scope<16;scope++) {
  bad=rule;bad.action.address6_high[0]=0xff000000U|(scope<<16);
  assert(fe_install(&p,bad,300)==-EOPNOTSUPP);
 }
 assert(allocations==old_allocations && mmio==old_mmio && !f.installs);
 for(unsigned int i=0;i<RTL_FE_MEMORY_BYTES/sizeof(unsigned int);i++)assert(!((unsigned int *)f.memory)[i]);
 assert(!fe_install(&p,rule,300));
 struct rtl_fe_flow *flow=container_of(f.flows.next,struct rtl_fe_flow,list);
 assert(f.hash_owners[flow->hash_index]==flow && flow->published && flow->installed);
 const unsigned int *action=(void *)((char *)f.memory+RTL_FE_ACTION_OFFSET+flow->hash_index*RTL_FE_ACTION_BYTES);
 assert(packed_bits(action,45,1) && packed_bits(action,46,1));
 assert(packed_bits(action,47,32)==rule.action.address);
 assert(packed_bits(action,79,1) && packed_bits(action,224,1));
 for(unsigned int i=0;i<3;i++)
  assert(packed_bits(action,225+32*i,32)==rule.action.address6_high[2-i]);
 assert(packed_bits(action,191,16)==65535);
 assert(packed_bits(action,207,1) && packed_bits(action,208,4)==9);
 assert(!(action[10]&~1U) && !action[11]);
 /* The full 48-byte slot is defined, and publication cannot scribble the
  * next hash's slot even though NORMAL callers still use 8-word buffers. */
 assert(RTL_FE_ACTION_BYTES==48);
 if(flow->hash_index+1<RTL_FE_HASH_ENTRIES)
  for(unsigned int i=0;i<RTL_FE_ACTION_BYTES/4;i++)assert(!action[12+i]);
 free(flow);free(f.hash_owners);free(f.memory);
}
int main(void){
 struct rtl_fe f={.enabled=true,.fabric_authorized=true};INIT_LIST_HEAD(&f.flows);INIT_LIST_HEAD(&f.retries);f.memory=calloc(1,RTL_FE_MEMORY_BYTES);assert(f.memory);
 f.hash_owners=calloc(RTL_FE_HASH_ENTRIES,sizeof(*f.hash_owners));assert(f.hash_owners);
 struct net_device n={.up=true},out={.up=true};struct rtl_fe_port p={.fe=&f,.netdev=&n},q={.fe=&f,.netdev=&out};
 struct rtl_fe_rule a={.input=&p,.output=&q,.mtu=1400,.pppoe_input=true,.pppoe_session=1234,
  .key={.source=0x0a000001,.destination=0xc6336401,.source_port=10000,.destination_port=443,.protocol=6,.ingress=7,.llid=1,.mask=63},
  .action={.translate=1,.translate_destination=1,.address=0x0a000064,.destination=3,.check_mask=63}};
 struct rtl_fe_rule b=a;b.key.source=0x0ab82e30;b.key.destination=0xc63364cf;b.key.source_port=8894;b.action.address=0x0a0000c8;
 /* A failed engine quiesce can leave enabled=true while ready=false.
  * Neither this state nor shutdown may publish or even touch MMIO/owners.
  * A policy gate must also block PON-originated callbacks (ingress=7),
  * although their PDC still points at the L3 engine and enabled stays true. */
 assert(fe_install(&p,a,1)==-EAGAIN);
 f.engine_ready=true;f.fabric_authorized=false;
 assert(fe_install(&p,a,1)==-EAGAIN);
 f.fabric_authorized=true;f.denied_port=&n;
 assert(fe_install(&p,a,1)==-EAGAIN);
 f.denied_port=&out;
 assert(fe_install(&p,a,1)==-EAGAIN);
 struct rtl_fe_rule same=a;same.output=&p;f.denied_port=&n;
 assert(fe_install(&p,same,1)==-EAGAIN);
 assert(!allocations && !mmio && !f.installs);
 f.denied_port=NULL;f.shutting_down=true;
 assert(fe_install(&p,a,1)==-ENODEV);
 f.shutting_down=false;p.retired=true;
 assert(fe_install(&p,a,1)==-ENODEV);p.retired=false;
 a.bridge=true;assert(fe_install(&p,a,1)==-EOPNOTSUPP);a.bridge=false;
 /* Even a caller bypassing fe_parse cannot publish multicast IP keys or
  * multicast NAT actions into the ordinary unicast hash namespace. */
 const unsigned int multicast4[]={0xe0000001U,0xef000001U,0xf0000001U,0xffffffffU};
 for(unsigned int side=0;side<2;side++)for(unsigned int ip=0;ip<4;ip++) {
  struct rtl_fe_rule bad=a;
  if(side)bad.key.destination=multicast4[ip];else bad.key.source=multicast4[ip];
  assert(fe_install(&p,bad,1)==-EOPNOTSUPP);
  bad=a;bad.action.address=multicast4[ip];bad.action.translate_destination=side;
  assert(fe_install(&p,bad,1)==-EOPNOTSUPP);
 }
 for(unsigned int side=0;side<2;side++)for(unsigned int scope=0;scope<16;scope++) {
  struct rtl_fe_rule bad=a;bad.ipv6=true;bad.action.translate=false;
  bad.key6.source[0]=bad.key6.destination[0]=0x20010db8U;
  if(side)bad.key6.destination[0]=0xff000000U|(scope<<16);
  else bad.key6.source[0]=0xff000000U|(scope<<16);
  assert(fe_install(&p,bad,1)==-EOPNOTSUPP);
 }
 assert(!allocations && !mmio && !f.installs && f.flows.next==&f.flows);
 for(unsigned int i=0;i<sizeof(f.hashes)/sizeof(f.hashes[0]);i++)assert(!f.hashes[i]);
 for(unsigned int i=0;i<RTL_FE_MEMORY_BYTES/sizeof(unsigned int);i++)assert(!((unsigned int *)f.memory)[i]);
 assert(!fe_install(&p,a,1));int ret=fe_install(&p,b,2);
 const unsigned int *ddr=f.memory;
 assert(ddr[16416]==0x07b0aa2b);
 const unsigned int *action=(void *)((char *)f.memory+RTL_FE_ACTION_OFFSET+16416*RTL_FE_ACTION_BYTES);
 assert((action[207/32]>>(207%32))&1);
 assert(((action[208/32]>>(208%32))&15)==9);
 assert(ret==-EOPNOTSUPP && !ddr[16417]);
 assert(!traversed); /* The ordinary insertion path must not scan all flows. */
 /* Once deletion has cleared the DDR key, a timed-out cache invalidation
  * may still retain it in hardware. Its retry owner must block reuse. */
 struct rtl_fe_flow *first=container_of(f.flows.next,struct rtl_fe_flow,list);
 assert(f.hash_owners[16416]==first && !f.hash_owners[16417]);
 ((unsigned int *)f.memory)[16416]=0;
 list_add_tail(&first->retry,&f.retries);
 assert(fe_install(&p,b,2)==-EOPNOTSUPP && !ddr[16417]);
 assert(f.retries.next==&first->retry && first->published);
 assert(traversed==1); /* Only the single unresolved cache owner was checked. */
 assert(f.hash_owners[16416]==first); /* A quarantined slot keeps its owner. */
 free(first);
 free(f.hash_owners);
 free(f.memory);
 naptv6_publication();
 return 0;
}
'''
with tempfile.TemporaryDirectory(dir=here,prefix='main-publish-') as d:
 p=Path(d)
 def run(source,mutant=None):
  (p/'repro.c').write_text(source)
  subprocess.run(['cc','-std=c11','-Wno-unused-function','-fsanitize=address,undefined','-I'+str(drivers),str(p/'repro.c'),'-o',str(p/'repro')],check=True)
  r=subprocess.run([str(p/'repro')],capture_output=True,text=True)
  if mutant:
   assert r.returncode and 'Assertion' in r.stderr,(mutant,r.stdout+r.stderr)
   print('PASS: actual publisher rejected '+mutant)
  else:
   assert r.returncode==0,r.stdout+r.stderr
 run(fixture)
 if args.mutants:
  body=symbol('fe_install')
  mutations={
   'NAPT6-in-normal-mode':(' || !fe->naptv6',''),
   'IPv6-action-loses-family-guard':('!data.ipv6 || ',''),
   'NAPT6-upper96-not-published':('action,sizeof(action));','action,32);'),
   'per-port-policy-not-checked':('!fe_switch_flow_ports_allowed(fe,data.input->netdev,data.output->netdev)','false'),
  }
  for name,(old,new) in mutations.items():
   assert body.count(old)==1,(name,'ambiguous mutation anchor')
   run(fixture.replace(body,body.replace(old,new,1),1),name)
 print('PASS: multicast/reserved route/NAT endpoints and offline/per-port/shutdown admission have zero allocation/MMIO/DDR writes; same-bucket collision and pending invalidation block publication; actual NAPT6 writes all 321 bits into its bounded 48-byte DDR slot')
