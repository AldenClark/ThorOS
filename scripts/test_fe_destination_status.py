#!/usr/bin/env python3
"""Decode SDK FDB semantic statuses, retaining uncertain destination ownership.

The transport stub completes every MMIO request successfully. The distinct
command status values come from aal-77c/include/aal_fdb.h at ca-network-drivers
8b4f4882ff0e237a1fa558fb0838e4b680bd6bd0, with APPEND success rules from
aal_fdb.c::__aal_fdb_entry_add_del. --revision runs the same oracle on older code.
"""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
relative = 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c-fe.c'
parser = argparse.ArgumentParser()
parser.add_argument('--revision')
args = parser.parse_args()
source = subprocess.check_output(['git', 'show', args.revision + ':' + relative], cwd=root, text=True) if args.revision else (root / relative).read_text()
indexed = 'struct rtl_fe_destination {' in source


def function(name):
    start = re.search(r'^static [^;{]*\b' + name + r'\(', source, re.M).start()
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


fixture = r'''
#include <stdbool.h>
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
#define list_for_each_entry(p,h,m) for(struct list_head *cursor=(h)->next;cursor!=(h) && ((p)=(void *)((char *)cursor-flow_link_offset));cursor=cursor->next)
struct rtl_fe_destination;
struct rtl_fe_flow {struct list_head list;bool destination_owned,destination_ready,destination_created,deleting;unsigned int destination_index,destination_saved[4];u8 destination[6];struct rtl_fe_destination *destination_owner;bool destination_live;};
#define flow_link_offset offsetof(struct rtl_fe_flow,list)
struct rtl_fe {struct list_head flows;struct rb_root destinations;unsigned int destination_count;};
static struct rtl_dq_io fe_io(struct rtl_fe *fe){return (struct rtl_dq_io){.context=fe};}
static void ether_addr_copy(u8 *a,const u8 *b){memcpy(a,b,6);}
static inline bool ether_addr_equal(const u8 *a,const u8 *b){return !memcmp(a,b,6);}
static unsigned int statuses[3],calls,commands[3],fail_call;
static unsigned int foreign_call,foreign_bit;
#define rtl_fe_fdb_command mock_fdb_command
static int mock_fdb_command(const struct rtl_dq_io *io,unsigned int command,unsigned int words[4],unsigned int *result){
 (void)io;unsigned int i=calls<3?calls:2;commands[i]=command;*result=statuses[i];
 if(!calls && (*result&15)==5)words[0]=(words[0]&~(255U<<11))|(37U<<11)|BIT(6);
 if(calls+1==foreign_call)words[foreign_bit/32]^=1U<<(foreign_bit%32);
 calls++;return calls==fail_call?-ETIMEDOUT:0;
}
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
/* Each semantic-status case has its own simulated device. Discard its
 * quarantined state between cases without pretending the failed MMIO was
 * successful. Release success/failure is exercised separately below. */
static void reset_case(struct rtl_fe *fe,struct rtl_fe_flow *flow){
#ifdef INDEXED_DESTINATIONS
 if(fe->destinations.rb_node)
  free(rb_entry(fe->destinations.rb_node,struct rtl_fe_destination,node));
#endif
 memset(fe,0,sizeof(*fe));fe->flows.next=fe->flows.prev=&fe->flows;
 memset(flow,0,sizeof(*flow));
}
static void prepare_owner(struct rtl_fe *fe,struct rtl_fe_flow *flow,const u8 *mac,
                          bool is_created,bool is_ready,bool live){
 flow->destination_owned=true;flow->destination_created=is_created;
 flow->destination_ready=is_ready;flow->deleting=!live;
 ether_addr_copy(flow->destination,mac);
#ifdef INDEXED_DESTINATIONS
 struct rtl_fe_destination *owner=calloc(1,sizeof(*owner));assert(owner);
 owner->users=1;owner->live_users=live;owner->ready=is_ready;owner->created=is_created;
 ether_addr_copy(owner->address,mac);fe_destination_index(fe,owner);
 flow->destination_owner=owner;flow->destination_live=live;
#else
 fe->flows.next=fe->flows.prev=&flow->list;flow->list.next=flow->list.prev=&fe->flows;
#endif
}
int main(void){
 struct rtl_fe fe={0};fe.flows.next=fe.flows.prev=&fe.flows;
 const u8 mac[6]={2,0,0,0,0,1};int failures=0,ret;struct rtl_fe_flow flow;
 unsigned int original[4];rtl_fe_fdb_key(original,mac);
 original[0]=(original[0]&~(255U<<11))|(37U<<11)|BIT(6);
 /* SDK: 0x5 HIT, 0xf MISS, 0xa append-full, 0xb MAC-limit. A successful
  * MMIO command is not the same as successfully installing/restoring a row. */
 for(unsigned int status=0;status<16;status++)if(status!=5 && status!=15){
  reset_case(&fe,&flow);statuses[0]=status;statuses[1]=statuses[2]=5;calls=0;
  ret=fe_destination_get(&fe,&flow,mac);
  if(ret>=0 || calls!=1 || flow.destination_owned){
   fprintf(stderr,"FAIL lookup status=%x: ret=%d calls=%u owned=%u\n",status,ret,calls,flow.destination_owned);failures++;
  }
 }
 for(unsigned int exists=0;exists<2;exists++)for(unsigned int status=0;status<16;status++){
  reset_case(&fe,&flow);statuses[0]=exists?5:15;statuses[1]=status;statuses[2]=5;calls=0;
  ret=fe_destination_get(&fe,&flow,mac);
  bool success=status==4 || status==5;
  if((!ret)!=success || !flow.destination_owned || ready(&flow)!=success ||
     created(&flow)==!!exists || calls!=(success?3U:2U)){
   fprintf(stderr,"FAIL append status=%x exists=%u: ret=%d calls=%u owned=%u ready=%u created=%u\n",
    status,exists,ret,calls,flow.destination_owned,ready(&flow),created(&flow));failures++;
  }
  if(exists && memcmp(saved(&flow),original,sizeof(original))){
   fprintf(stderr,"FAIL append status=%x lost original FDB snapshot\n",status);failures++;
  }
 }
 for(unsigned int created=0;created<2;created++)for(unsigned int status=0;status<16;status++){
  reset_case(&fe,&flow);prepare_owner(&fe,&flow,mac,created,true,true);
  statuses[0]=status;calls=0;
  ret=fe_destination_put(&fe,&flow);
  bool success=status==5 || status==(created?15:4);
  if((!ret)!=success || calls!=1 || commands[0]!=(created?0x85U:0x45U)){
   fprintf(stderr,"FAIL release created=%u status=%x: ret=%d calls=%u\n",created,status,ret,calls);failures++;
  }
 }
 /* Once APPEND is issued, a failed re-lookup cannot forget the row owner. */
 for(unsigned int status=0;status<16;status++)if(status!=5){
  reset_case(&fe,&flow);statuses[0]=15;statuses[1]=5;statuses[2]=status;calls=0;
  ret=fe_destination_get(&fe,&flow,mac);
  if(ret>=0 || !flow.destination_owned || ready(&flow) || !created(&flow)){
   fprintf(stderr,"FAIL post-append lookup status=%x loses ownership/readiness\n",status);failures++;
  }
 }
 for(unsigned int failed=1;failed<=3;failed++){
  reset_case(&fe,&flow);statuses[0]=statuses[1]=statuses[2]=5;calls=0;fail_call=failed;
  ret=fe_destination_get(&fe,&flow,mac);
  if(ret!=-ETIMEDOUT || flow.destination_owned!=(failed>1) || ready(&flow)){
   fprintf(stderr,"FAIL timeout phase=%u loses rollback ownership\n",failed);failures++;
  }
 }
 fail_call=0;
 /* A key hit is not permission to turn a foreign/malformed row into a
  * private pin. Reject before APPEND and before taking rollback ownership. */
 const unsigned int foreign_bits[]={0,4,7,8,9,10,19,20,21,35,38,39,50};
 for(unsigned int i=0;i<sizeof(foreign_bits)/sizeof(foreign_bits[0]);i++) {
  reset_case(&fe,&flow);statuses[0]=statuses[1]=statuses[2]=5;
  calls=0;foreign_call=1;foreign_bit=foreign_bits[i];
  ret=fe_destination_get(&fe,&flow,mac);
  if(ret!=-EADDRINUSE || calls!=1 || flow.destination_owned || ready(&flow)){
   fprintf(stderr,"FAIL foreign preexisting FDB bit=%u was adopted\n",foreign_bit);failures++;
  }
  reset_case(&fe,&flow);statuses[0]=15;calls=0;foreign_call=3;
  ret=fe_destination_get(&fe,&flow,mac);
  if(ret!=-EIO || calls!=3 || !flow.destination_owned || ready(&flow)){
   fprintf(stderr,"FAIL malformed post-APPEND bit=%u lost quarantine ownership\n",foreign_bit);failures++;
  }
 }
 foreign_call=0;
 const unsigned int indices[]={0,4095,4096,4127,4128,8191};
 for(unsigned int i=0;i<sizeof(indices)/sizeof(indices[0]);i++) {
  reset_case(&fe,&flow);statuses[0]=15;statuses[1]=5;
  statuses[2]=(indices[i]<<4)|5;calls=0;
  ret=fe_destination_get(&fe,&flow,mac);
  bool valid=indices[i]<4128;
  if((ret==0)!=valid || !flow.destination_owned || ready(&flow)!=valid ||
     (valid && flow.destination_index!=indices[i])){
   fprintf(stderr,"FAIL FDB physical index=%u ready/ownership mismatch\n",indices[i]);failures++;
  }
 }
 /* No new user may share an uncertain writer or a deleting destination. */
 struct rtl_fe_flow other={0};
 for(unsigned int deleting=0;deleting<2;deleting++){
  reset_case(&fe,&flow);memset(&other,0,sizeof(other));
  prepare_owner(&fe,&other,mac,true,deleting,!deleting);
  calls=0;ret=fe_destination_get(&fe,&flow,mac);
  if(ret!=-EBUSY || calls || flow.destination_owned){fprintf(stderr,"FAIL uncertain FDB shared\n");failures++;}
 }
 reset_case(&fe,&flow);
 if(!failures)puts("FDB semantic statuses: LOOKUP, APPEND hit/over-limit/full, DELETE miss, private-row types, 4128 physical rows, rollback ownership and sharing guards passed");
 return failures?1:0;
}
'''
with tempfile.TemporaryDirectory(prefix='fe-destination-status-') as directory:
    work = Path(directory)
    cfile, binary = work / 'test.c', work / 'test'
    owner = re.search(r'struct rtl_fe_destination \{.*?\n\};', source, re.S)[0] if indexed else ''
    support = ''.join(function(n) for n in ('fe_destination_find', 'fe_destination_index', 'fe_destination_retire')) if indexed else ''
    fixture = fixture.replace('struct rtl_fe_destination;', owner or 'struct rtl_fe_destination;')
    cfile.write_text(('#define INDEXED_DESTINATIONS 1\n' if indexed else '') + fixture + support + function('fe_destination_get') + function('fe_destination_put') + test)
    subprocess.run(['cc', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    '-I', str((root / relative).parent),
                    '-I', str(root / 'scripts/fixtures'),
                    str(cfile), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
