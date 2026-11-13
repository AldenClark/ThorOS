#!/usr/bin/env python3
"""Execute the kernel's real directional offload and conntrack-marker semantics.

This is a compatibility test, not a request to make upstream installation
atomic: one accepted direction can set HW_OFFLOAD while the other uses the
software flowtable. Callback success alone is not a hardware hit counter.
"""
from pathlib import Path
import argparse
import re
import subprocess
import tempfile


def function(source, name):
    match = re.search(r'^.*\b' + name + r'\([^;]*?\)\s*\{', source, re.M)
    if not match:
        raise ValueError(f'missing function {name}')
    start = match.start()
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--kernel', type=Path, required=True, help='Prepared kernel tree')
args = parser.parse_args()
source = (args.kernel / 'net/netfilter/nf_flow_table_offload.c').read_text()
common = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint16_t __be16;
enum flow_offload_tuple_dir {FLOW_OFFLOAD_DIR_ORIGINAL,FLOW_OFFLOAD_DIR_REPLY,FLOW_OFFLOAD_DIR_MAX};
enum flow_cls_command {FLOW_CLS_REPLACE,FLOW_CLS_DESTROY,FLOW_CLS_STATS};
enum {NF_FLOW_HW,NF_FLOW_HW_BIDIRECTIONAL,NF_FLOW_HW_DEAD};
enum {IPS_OFFLOAD_BIT,IPS_HW_OFFLOAD_BIT};
#define ETH_P_ALL 3
#define TC_SETUP_CLSFLOWER 1
#define BIT(n) (1UL<<(n))
#define test_bit(n,p) (!!(*(p)&BIT(n)))
#define set_bit(n,p) (*(p)|=BIT(n))
#define clear_bit(n,p) (*(p)&=~BIT(n))
struct netlink_ext_ack {int unused;};
struct flow_stats {unsigned long lastused;};
struct flow_offload_tuple {unsigned dir;};
struct flow_offload_tuple_rhash {struct flow_offload_tuple tuple;};
struct nf_conn {unsigned long status;};
struct flow_offload {struct nf_conn *ct;unsigned long flags;struct flow_offload_tuple_rhash tuplehash[2];};
struct nf_flow_rule {void *rule;};
struct flow_cls_offload {
 struct {__be16 protocol;int prio;struct netlink_ext_ack *extack;} common;
 enum flow_cls_command command;unsigned long cookie;void *rule;struct flow_stats stats;
};
struct flow_block_cb {int (*cb)(int,void *,void *);void *cb_priv;struct flow_block_cb *next;};
struct list_head {struct flow_block_cb *first;};
struct nf_flowtable {int priority,flow_block_lock;struct {struct list_head cb_list;} flow_block;};
struct flow_offload_work {struct flow_offload *flow;struct nf_flowtable *flowtable;};
#define list_for_each_entry(pos,head,member) for(pos=(head)->first;pos;pos=pos->next)
static void down_read(int *lock){assert(!*lock);*lock=1;}
static void up_read(int *lock){assert(*lock);*lock=0;}
static int replies[2],allocated,destroyed,allocation_error,add_calls[2],del_calls[2];
static bool installed[2];
static struct nf_flow_rule rules[2];
static int callback(int type,void *data,void *priv){
 struct flow_cls_offload *cls=data;(void)priv;
 const struct flow_offload_tuple *tuple=(void *)cls->cookie;unsigned dir=tuple->dir;
 assert(type==TC_SETUP_CLSFLOWER && dir<2 && cls->common.prio==7);
 if(cls->command==FLOW_CLS_REPLACE){
  add_calls[dir]++;if(replies[dir]<0)return replies[dir];
  installed[dir]=true;return 0;
 }
 assert(cls->command==FLOW_CLS_DESTROY);del_calls[dir]++;installed[dir]=false;return 0;
}
static int nf_flow_offload_alloc(struct flow_offload_work *offload,struct nf_flow_rule *out[]){
 (void)offload;allocated++;if(allocation_error)return allocation_error;
 out[0]=&rules[0];out[1]=&rules[1];return 0;
}
static void nf_flow_offload_destroy(struct nf_flow_rule *out[]){
 assert(out[0]==&rules[0] && out[1]==&rules[1]);destroyed++;
}
'''
code = common
for name in ('nf_flow_offload_init', 'nf_flow_offload_tuple',
             'flow_offload_tuple_add', 'flow_offload_tuple_del',
             'flow_offload_rule_add', 'flow_offload_work_add', 'flow_offload_work_del'):
    code += function(source, name)
code += r'''
int main(void){
 struct flow_block_cb cb={.cb=callback};
 struct nf_flowtable ft={.priority=7,.flow_block={.cb_list={.first=&cb}}};
 for(unsigned bidir=0;bidir<2;bidir++)for(unsigned accepted=0;accepted<4;accepted++){
  struct nf_conn ct={.status=BIT(IPS_OFFLOAD_BIT)};
  struct flow_offload flow={.ct=&ct,.flags=BIT(NF_FLOW_HW)|(bidir?BIT(NF_FLOW_HW_BIDIRECTIONAL):0)};
  flow.tuplehash[1].tuple.dir=1;struct flow_offload_work work={&flow,&ft};
  replies[0]=accepted&1?0:-EOPNOTSUPP;replies[1]=accepted&2?0:-ENOSPC;
  allocated=destroyed=0;memset(add_calls,0,sizeof(add_calls));memset(del_calls,0,sizeof(del_calls));
  memset(installed,0,sizeof(installed));
  flow_offload_work_add(&work);
  bool any=(accepted&1)||(bidir&&(accepted&2));
  assert(test_bit(IPS_HW_OFFLOAD_BIT,&ct.status)==any);
  assert(test_bit(IPS_OFFLOAD_BIT,&ct.status)); /* software fallback survives rejection */
  assert(allocated==1 && destroyed==1 && add_calls[0]==1 && add_calls[1]==(int)bidir);
  assert(installed[0]==!!(accepted&1) && installed[1]==!!(bidir&&(accepted&2)));
  flow_offload_work_del(&work);
  assert(!test_bit(IPS_HW_OFFLOAD_BIT,&ct.status) && test_bit(NF_FLOW_HW_DEAD,&flow.flags));
  assert(!installed[0] && !installed[1] && del_calls[0]==1 && del_calls[1]==(int)bidir);
 }
 /* Allocation failure must not fabricate the hardware marker or remove SW. */
 struct nf_conn ct={.status=BIT(IPS_OFFLOAD_BIT)};struct flow_offload flow={.ct=&ct};
 struct flow_offload_work work={&flow,&ft};allocation_error=-ENOMEM;destroyed=0;
 flow_offload_work_add(&work);
 assert(ct.status==BIT(IPS_OFFLOAD_BIT) && !destroyed);
 /* No registered callback has the same fallback semantics as both rejections. */
 allocation_error=0;ft.flow_block.cb_list.first=NULL;flow.flags=BIT(NF_FLOW_HW_BIDIRECTIONAL);
 flow_offload_work_add(&work);assert(ct.status==BIT(IPS_OFFLOAD_BIT));
 puts("Kernel offload semantics: one/both/no accepted direction, paired deletion, allocation failure and SW fallback passed.");
}
'''
with tempfile.TemporaryDirectory(prefix='flowtable-directions-') as directory:
    work = Path(directory)
    c_file, binary = work / 'directions.c', work / 'directions'
    c_file.write_text(code)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', str(c_file), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
