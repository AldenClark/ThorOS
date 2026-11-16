#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute cached production L3/resource readers without any MMIO shim.

No register reader is linked: adding a hardware transaction to any reader
fails compilation. The fixture also proves bounded output and opaque flow IDs.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVERS = ROOT / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
source = (DRIVERS / 'rtl9617c-fe.c').read_text()
resource_kind = re.search(r'enum rtl_l2_shared_kind\s*\{[^}]+\};',
                          (DRIVERS / 'rtl9617c-l2-domain.h').read_text()).group(0)


def function(name):
    start = re.search(r'^ssize_t ' + name + r'\(', source, re.M).start()
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


MODEL = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include "rtl9617c-fe-observe.h"
#define PAGE_SIZE 4096
typedef unsigned long long u64;
static unsigned long jiffies=10000;
static unsigned int jiffies_to_msecs(unsigned long j) {return j*10;}
struct mutex {bool deny,held;};
static unsigned int locks,unlocks;
static struct mutex *active_lock;
static int mutex_trylock(struct mutex *m) {
 if(m->deny)return 0;assert(!m->held && !active_lock);m->held=true;
 active_lock=m;locks++;return 1;
}
static void mutex_unlock(struct mutex *m) {
 assert(m->held && active_lock==m);m->held=false;active_lock=NULL;unlocks++;
}
struct list_head {struct list_head *next,*prev;};
static void init_list(struct list_head *h) {h->next=h->prev=h;}
static void list_add_tail(struct list_head *n,struct list_head *h) {
 n->next=h;n->prev=h->prev;h->prev->next=n;h->prev=n;
}
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_for_each_entry(p,h,m) for(struct list_head *c=(h)->next;c!=(h) && ((p)=container_of(c,__typeof__(*(p)),m));c=c->next)
struct rtl_fe_port {unsigned int source;};
struct rtl_fe_flow {
 struct list_head list;
 struct rtl_fe_port *input,*output;
 u64 lease_id,observed_bytes,observed_packets;
 unsigned int hash_index,protocol,counter,observations,activity_hits;
 unsigned long observation_at;
 int observation_error;
 bool ipv6,installed,published,deleting,counted;
};
/* The enum is extracted verbatim, so adding a shared resource bank changes
 * the production loop and the fixture expectations together. */
RESOURCE_KIND
struct resource_ledger {bool quarantined;};
struct rtl_l2_owner {
 unsigned int sealed,ready_mask,count,scan_reads,publications,withdrawals,aborts,failures;
 int error;
 struct resource_ledger ledger;
 struct {bool quarantined;unsigned int capacity;} journal;
};
struct rtl_fe {
 struct mutex lock;struct list_head flows;struct rtl_fe_observe observe;u64 evidence_instance_ns;
 struct rtl_l2_owner *l2_owner;
};
static int scnprintf(char *b,size_t cap,const char *f,...) {
 va_list ap;va_start(ap,f);int n=vsnprintf(b,cap,f,ap);va_end(ap);
 assert(n>=0);return (size_t)n<cap?n:(cap?(int)cap-1:0);
}
static int sysfs_emit(char *b,const char *f,...) {
 va_list ap;va_start(ap,f);int n=vsnprintf(b,PAGE_SIZE,f,ap);va_end(ap);
 assert(n>=0 && n<PAGE_SIZE);return n;
}
static unsigned int resource_capacity_calls,resource_leased_calls,resource_available_calls;
static unsigned int resource_mce_calls,resource_mdb_calls;
static unsigned int rtl_l2_shared_capacity(enum rtl_l2_shared_kind kind) {
 assert(active_lock && active_lock->held && kind<RTL_L2_SHARED_COUNT);
 resource_capacity_calls++;return UINT_MAX-kind;
}
static unsigned int rtl_l2_shared_leased(const struct resource_ledger *ledger,
 enum rtl_l2_shared_kind kind) {
 assert(ledger && active_lock && active_lock->held && kind<RTL_L2_SHARED_COUNT);
 resource_leased_calls++;return UINT_MAX-kind-1;
}
static unsigned int rtl_l2_shared_available(const struct resource_ledger *ledger,
 enum rtl_l2_shared_kind kind) {
 assert(ledger && active_lock && active_lock->held && kind<RTL_L2_SHARED_COUNT);
 resource_available_calls++;return kind+1;
}
/* Real MCE/MDB format closure is proved by test_fe_diagnostic_budget.py;
 * these stubs verify the actual resource getter calls them under FE lock. */
static ssize_t fe_mcast_stats(struct rtl_fe *fe,char *buffer,size_t bytes) {
 assert(fe && active_lock==&fe->lock && fe->lock.held);resource_mce_calls++;
 return scnprintf(buffer,bytes,"fixture_mce_under_lock=1\n");
}
static ssize_t fe_mdb_stats(struct rtl_fe *fe,char *buffer,size_t bytes) {
 assert(fe && active_lock==&fe->lock && fe->lock.held);resource_mdb_calls++;
 return scnprintf(buffer,bytes,"fixture_mdb_under_lock=1\n");
}
'''

CASES = r'''
int main(void) {
 struct rtl_fe fe={.evidence_instance_ns=314159265};init_list(&fe.flows);
 char output[PAGE_SIZE+16];memset(output+PAGE_SIZE,0xa5,16);
 assert(rtl_fe_admission_state(NULL,output)>0 && strstr(output,"reason=no_fe"));
 assert(rtl_fe_flow_evidence(NULL,output)>0 && strstr(output,"reason=no_fe"));
 assert(rtl_fe_resource_state(NULL,output)>0 && strstr(output,"reason=no_fe"));
 fe.lock.deny=true;
 assert(rtl_fe_admission_state(&fe,output)>0 && strstr(output,"reason=busy retryable=1"));
 assert(rtl_fe_flow_evidence(&fe,output)>0 && strstr(output,"reason=busy retryable=1"));
 assert(rtl_fe_resource_state(&fe,output)>0 && strstr(output,"reason=busy retryable=1"));
 assert(!locks && !unlocks && !resource_mce_calls && !resource_mdb_calls);
 fe.lock.deny=false;
 assert(rtl_fe_resource_state(&fe,output)>0 && strstr(output,"l2_owner_unavailable=1"));
 assert(strstr(output,"mmio_reads=0 mmio_writes=0") && !active_lock);
 assert(resource_mce_calls==1 && resource_mdb_calls==1 && !resource_capacity_calls);
 struct rtl_l2_owner owner={.sealed=1,.ready_mask=UINT_MAX,.count=UINT_MAX,
  .scan_reads=UINT_MAX,.publications=UINT_MAX,.withdrawals=UINT_MAX,
  .aborts=UINT_MAX,.failures=UINT_MAX,.error=INT_MIN,
  .ledger={.quarantined=true},.journal={.quarantined=true,.capacity=UINT_MAX}};
 fe.l2_owner=&owner;
 assert(rtl_fe_resource_state(&fe,output)>0);
 assert(strstr(output,"l2_owner_error=-2147483648"));
 assert(strstr(output,"l2_owner_journal=4294967295/4294967295"));
 assert(resource_capacity_calls==RTL_L2_SHARED_COUNT);
 assert(resource_leased_calls==RTL_L2_SHARED_COUNT && resource_available_calls==RTL_L2_SHARED_COUNT);
 for(unsigned int kind=0;kind<RTL_L2_SHARED_COUNT;kind++) {
  char expected[192];
  snprintf(expected,sizeof(expected),
   "l2_bank_%u_capacity=%u l2_bank_%u_leased=%u l2_bank_%u_verified_available=%u\n",
   kind,UINT_MAX-kind,kind,UINT_MAX-kind-1,kind,kind+1);
  assert(strstr(output,expected));
 }
 assert(strstr(output,"fixture_mce_under_lock=1\nfixture_mdb_under_lock=1\n"));
 assert(resource_mce_calls==2 && resource_mdb_calls==2 && !active_lock);
 fe.observe.replace_requests=~0ULL;
 fe.observe.install_collision=3;fe.observe.install_unsupported=7;
 fe.observe.reason[FE_REJECT_OTHER_INGRESS]=11;
 for(unsigned i=0;i<FE_INSTALL_STAGE_COUNT;i++)fe.observe.stage_failed[i]=~0ULL;
 for(unsigned i=0;i<FE_FDB_MODE_REASON_COUNT;i++)fe.observe.fdb_mode_reason[i]=~0ULL;
 fe.observe.last_fdb_mode_reason=FE_FDB_MODE_CMD_DISABLED;
 fe.observe.last_fdb_mode_error=-EOPNOTSUPP;
 fe.observe.last_fdb_mode_sampled=1;
 fe.observe.last_fdb_mode_control=0x1ca00ff9U;
 fe.observe.last_failure_stage=FE_INSTALL_DESTINATION_MAC;
 fe.observe.last_failure_error=-EOPNOTSUPP;fe.observe.last_rollback_error=-ETIMEDOUT;
 assert(rtl_fe_admission_state(&fe,output)>0);
 assert(strstr(output,"requests=18446744073709551615"));
 assert(strstr(output,"install_collision=3 install_unsupported=7"));
 assert(strstr(output,"reject_other_ingress=11"));
 assert(strstr(output,"last_failure_stage=destination_mac last_failure_errno=-95 last_rollback_errno=-110"));
 assert(strstr(output,"fdb_mode_cmd_disabled=18446744073709551615"));
 assert(strstr(output,"fdb_mode_last_reason=cmd_disabled fdb_mode_last_error=-95 "));
 assert(strstr(output,"fdb_mode_last_control_sampled=1 fdb_mode_last_control=0x1ca00ff9"));
 assert(strstr(output,"stage_fdb_mode_failed=18446744073709551615"));
 assert(strstr(output,"stage_publish_failed=18446744073709551615"));
 assert(strstr(output,"mmio_reads=0 mmio_writes=0"));
 assert(rtl_fe_flow_evidence(&fe,output)>0 && strstr(output,"emitted=0 truncated=0"));
 assert(strstr(output,"instance_ns=314159265"));
 struct rtl_fe_port lan={.source=3},pon={.source=7};
 struct rtl_fe_flow rows[24]={0};
 rows[0]=(struct rtl_fe_flow){.lease_id=91,.hash_index=6,.input=&lan,.output=&pon,
  .protocol=6,.installed=true,.published=true,.counted=true,.counter=8,
  .observations=4,.observation_at=9900,.activity_hits=3,.observed_bytes=1000,.observed_packets=12};
 list_add_tail(&rows[0].list,&fe.flows);
 assert(rtl_fe_flow_evidence(&fe,output)>0);
 assert(strstr(output,"lease=91 hash=6 input_hw=3 output_hw=7"));
 assert(strstr(output,"samples=4 sample_age_ms=1000 sample_errno=0 age_hits=3 l3_bytes=1000 packets=12"));
 assert(strstr(output,"emitted=1 truncated=0"));
 rows[0].deleting=true;rows[0].observation_error=-ETIMEDOUT;
 assert(rtl_fe_flow_evidence(&fe,output)>0 && strstr(output,"deleting=1"));
 assert(strstr(output,"sample_errno=-110"));
 for(unsigned i=1;i<24;i++) {
  rows[i]=rows[0];rows[i].lease_id=~0ULL-i;
  rows[i].observed_bytes=rows[i].observed_packets=~0ULL;
  list_add_tail(&rows[i].list,&fe.flows);
 }
 ssize_t size=rtl_fe_flow_evidence(&fe,output);
 assert(size>0 && size<PAGE_SIZE && strstr(output,"truncated=1\n"));
 assert(!strstr(output,"cookie=") && !strstr(output,"source=") && !strstr(output,"destination="));
 for(unsigned i=0;i<16;i++)assert((unsigned char)output[PAGE_SIZE+i]==0xa5);
 assert(locks==unlocks && !fe.lock.held);
 puts("L3/resource evidence: actual cached getters/no MMIO, busy/no-FE, resource helpers under FE lock, complete banks, exact rejection stages, opaque lease identity, counter provenance and bounded partial reports passed");
}
'''

with tempfile.TemporaryDirectory(prefix='l3-evidence-') as temp:
    work = Path(temp)
    code = work / 'evidence.c'
    binary = work / 'evidence'
    code.write_text(MODEL.replace('RESOURCE_KIND', resource_kind) +
                    function('rtl_fe_admission_state') + function('rtl_fe_flow_evidence') +
                    function('rtl_fe_resource_state') + CASES)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-Wno-misleading-indentation', '-fsanitize=address,undefined',
                    '-I', str(DRIVERS), str(code), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

ni = (DRIVERS / 'rtl9617c-xram.c').read_text()
for name in ('l3_admission', 'l3_flows', 'l2_resources'):
    assert f'DEVICE_ATTR_RO({name})' in ni
    assert f'&dev_attr_{name}.attr,' in ni
