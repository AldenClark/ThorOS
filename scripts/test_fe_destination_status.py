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


def function(name):
    start = re.search(r'^static int ' + name + r'\(', source, re.M).start()
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
#include <string.h>
#include <errno.h>
typedef unsigned char u8;
#define ETH_ALEN 6
#define BIT(n) (1U<<(n))
struct list_head {struct list_head *next,*prev;};
#define list_for_each_entry(p,h,m) for(struct list_head *cursor=(h)->next;cursor!=(h) && ((p)=(void *)((char *)cursor-flow_link_offset));cursor=cursor->next)
struct rtl_fe_flow {struct list_head list;bool destination_owned,destination_ready,destination_created,deleting;unsigned int destination_index,destination_saved[4];u8 destination[6];};
static const size_t flow_link_offset=offsetof(struct rtl_fe_flow,list);
struct rtl_fe {struct list_head flows;};
struct rtl_dq_io {struct rtl_fe *context;};
static struct rtl_dq_io fe_io(struct rtl_fe *fe){return (struct rtl_dq_io){fe};}
static void ether_addr_copy(u8 *a,const u8 *b){memcpy(a,b,6);}
static bool ether_addr_equal(const u8 *a,const u8 *b){return !memcmp(a,b,6);}
static void rtl_fe_fdb_key(unsigned int words[4],const u8 mac[6]){memset(words,0,16);memcpy(words,mac,6);}
static unsigned int statuses[3],calls,commands[3],fail_call;
static int rtl_fe_fdb_command(const struct rtl_dq_io *io,unsigned int command,unsigned int words[4],unsigned int *result){
 (void)io;unsigned int i=calls<3?calls:2;commands[i]=command;*result=statuses[i];
 if(!calls && (*result&15)==5){words[0]=0x12345678;words[1]=0xabcdef01;}
 calls++;return calls==fail_call?-ETIMEDOUT:0;
}
'''
test = r'''
int main(void){
 struct rtl_fe fe={0};fe.flows.next=fe.flows.prev=&fe.flows;
 const u8 mac[6]={2,0,0,0,0,1};int failures=0,ret;struct rtl_fe_flow flow;
 /* SDK: 0x5 HIT, 0xf MISS, 0xa append-full, 0xb MAC-limit. A successful
  * MMIO command is not the same as successfully installing/restoring a row. */
 for(unsigned int status=0;status<16;status++)if(status!=5 && status!=15){
  memset(&flow,0,sizeof(flow));statuses[0]=status;statuses[1]=statuses[2]=5;calls=0;
  ret=fe_destination_get(&fe,&flow,mac);
  if(ret>=0 || calls!=1 || flow.destination_owned){
   fprintf(stderr,"FAIL lookup status=%x: ret=%d calls=%u owned=%u\n",status,ret,calls,flow.destination_owned);failures++;
  }
 }
 for(unsigned int exists=0;exists<2;exists++)for(unsigned int status=0;status<16;status++){
  memset(&flow,0,sizeof(flow));statuses[0]=exists?5:15;statuses[1]=status;statuses[2]=5;calls=0;
  ret=fe_destination_get(&fe,&flow,mac);
  bool success=status==4 || status==5;
  if((!ret)!=success || !flow.destination_owned || flow.destination_ready!=success ||
     flow.destination_created==!!exists || calls!=(success?3U:2U)){
   fprintf(stderr,"FAIL append status=%x exists=%u: ret=%d calls=%u owned=%u ready=%u created=%u\n",
    status,exists,ret,calls,flow.destination_owned,flow.destination_ready,flow.destination_created);failures++;
  }
  if(exists && (flow.destination_saved[0]!=0x12345678 || flow.destination_saved[1]!=0xabcdef01)){
   fprintf(stderr,"FAIL append status=%x lost original FDB snapshot\n",status);failures++;
  }
 }
 for(unsigned int created=0;created<2;created++)for(unsigned int status=0;status<16;status++){
  memset(&flow,0,sizeof(flow));flow.destination_owned=true;flow.destination_ready=true;
  flow.destination_created=created;statuses[0]=status;calls=0;
  ret=fe_destination_put(&fe,&flow);
  bool success=status==5 || status==(created?15:4);
  if((!ret)!=success || calls!=1 || commands[0]!=(created?0x85U:0x45U)){
   fprintf(stderr,"FAIL release created=%u status=%x: ret=%d calls=%u\n",created,status,ret,calls);failures++;
  }
 }
 /* Once APPEND is issued, a failed re-lookup cannot forget the row owner. */
 for(unsigned int status=0;status<16;status++)if(status!=5){
  memset(&flow,0,sizeof(flow));statuses[0]=15;statuses[1]=5;statuses[2]=status;calls=0;
  ret=fe_destination_get(&fe,&flow,mac);
  if(ret>=0 || !flow.destination_owned || flow.destination_ready || !flow.destination_created){
   fprintf(stderr,"FAIL post-append lookup status=%x loses ownership/readiness\n",status);failures++;
  }
 }
 for(unsigned int failed=1;failed<=3;failed++){
  memset(&flow,0,sizeof(flow));statuses[0]=statuses[1]=statuses[2]=5;calls=0;fail_call=failed;
  ret=fe_destination_get(&fe,&flow,mac);
  if(ret!=-ETIMEDOUT || flow.destination_owned!=(failed>1) || flow.destination_ready){
   fprintf(stderr,"FAIL timeout phase=%u loses rollback ownership\n",failed);failures++;
  }
 }
 fail_call=0;
 /* No new user may share an uncertain writer or a deleting destination. */
 struct rtl_fe_flow other={.destination_owned=true};memcpy(other.destination,mac,6);
 fe.flows.next=fe.flows.prev=&other.list;other.list.next=other.list.prev=&fe.flows;
 for(unsigned int deleting=0;deleting<2;deleting++){
  other.destination_ready=deleting;other.deleting=deleting;
  memset(&flow,0,sizeof(flow));calls=0;ret=fe_destination_get(&fe,&flow,mac);
  if(ret!=-EBUSY || calls || flow.destination_owned){fprintf(stderr,"FAIL uncertain FDB shared\n");failures++;}
 }
 if(!failures)puts("FDB semantic statuses: LOOKUP, APPEND hit/over-limit/full, DELETE miss, rollback ownership and sharing guards passed");
 return failures?1:0;
}
'''
with tempfile.TemporaryDirectory(prefix='fe-destination-status-') as directory:
    work = Path(directory)
    cfile, binary = work / 'test.c', work / 'test'
    cfile.write_text(fixture + function('fe_destination_get') + function('fe_destination_put') + test)
    subprocess.run(['cc', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    str(cfile), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
