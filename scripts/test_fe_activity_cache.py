#!/usr/bin/env python3
"""Exercise the actual FE stats activity owner selection and positive-only cache.

Uses the same production MMIO helper as test_fe_age_batch, never a second cache
algorithm. Synthetic transaction counts are not a hardware throughput result.
"""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
from test_fe_age_batch import COMMON, DRIVER, ROOT, function


MODEL = r'''
#include <limits.h>
#define HZ 100UL
#define time_before(a,b) ((long)((a)-(b))<0)
static unsigned long jiffies;
struct rtl_fe_flow {
 unsigned int hash_index;
 unsigned long lastused;
 bool installed,published,deleting,activity_cached;
};
struct rtl_fe {struct rtl_fe_flow **hash_owners;};
static struct rtl_fe_flow *owners[RTL_FE_HASH_ENTRIES];
static struct rtl_fe_flow flows[32];
static struct rtl_fe fe;
static struct rtl_dq_io fe_io(struct rtl_fe *owner) {(void)owner;return io_for(&hw);}
static void init(unsigned int first) {
 memset(&hw,0,sizeof(hw));memset(owners,0,sizeof(owners));memset(flows,0,sizeof(flows));
 fe.hash_owners=owners;jiffies=1000;
 for(unsigned int i=0;i<32;i++) {
  flows[i]=(struct rtl_fe_flow){.hash_index=first+i,.lastused=50,.installed=true,.published=true};
  owners[first+i]=&flows[i];put_nibble(hw.rows[first/32],i,1);
 }
}
'''

TEST = r'''
static void active_budget(void) {
 init(65504);
 for(unsigned int i=0;i<32;i++)put_nibble(hw.rows[2047],i,6);
 for(unsigned int i=0;i<32;i++)assert(!fe_refresh_activity(&fe,&flows[i]));
 assert(hw.commands==2 && hw.data_reads==4 && hw.data_writes==4);
 for(unsigned int i=0;i<32;i++)assert(flows[i].activity_cached && flows[i].lastused==1000);
 jiffies=1050;
 for(unsigned int i=0;i<32;i++)assert(!fe_refresh_activity(&fe,&flows[i]));
 assert(hw.commands==2);
 for(unsigned int i=0;i<32;i++)assert(flows[i].lastused==1000);
 /* Expiry is exact, and a formerly active but now idle row has no new lease. */
 jiffies=1100;
 for(unsigned int i=0;i<32;i++)assert(!fe_refresh_activity(&fe,&flows[i]));
 assert(hw.commands==34);
 for(unsigned int i=0;i<32;i++)assert(flows[i].lastused==1000);
 jiffies=1150;
 assert(!fe_refresh_activity(&fe,&flows[0]));assert(hw.commands==35 && flows[0].lastused==1000);
}
static void idle_neighbor_becomes_active(void) {
 init(96);put_nibble(hw.rows[3],0,6);
 assert(!fe_refresh_activity(&fe,&flows[0]));assert(hw.commands==2);
 assert(flows[0].activity_cached && !flows[1].activity_cached && flows[1].lastused==50);
 /* The previous row sample must not hide a new hit near another flow's expiry. */
 put_nibble(hw.rows[3],1,2);
 assert(!fe_refresh_activity(&fe,&flows[1]));
 assert(hw.commands==4 && flows[1].lastused==1000 && flows[1].activity_cached);
 assert(!fe_refresh_activity(&fe,&flows[2]));assert(hw.commands==5 && flows[2].lastused==50);
 put_nibble(hw.rows[3],2,7);
 assert(!fe_refresh_activity(&fe,&flows[2]));assert(hw.commands==7 && flows[2].lastused==1000);
}
static void owner_selection(void) {
 init(320);
 for(unsigned int i=0;i<32;i++)put_nibble(hw.rows[10],i,6);
 owners[321]=NULL;flows[2].published=false;flows[3].installed=false;flows[4].deleting=true;
 assert(!fe_refresh_activity(&fe,&flows[0]));
 for(unsigned int i=0;i<32;i++) {
  bool excluded=i>=1 && i<=4;
  assert(nibble(hw.rows[10],i)==(excluded?6U:1U));
  assert(flows[i].lastused==(excluded?50UL:1000UL));
 }
 unsigned int commands=hw.commands;
 assert(fe_refresh_activity(&fe,&flows[1])==-EIO);
 assert(fe_refresh_activity(&fe,&flows[2])==-ENOENT);
 assert(fe_refresh_activity(&fe,&flows[3])==-ENOENT);
 assert(fe_refresh_activity(&fe,&flows[4])==-ENOENT);
 flows[5].hash_index=RTL_FE_HASH_ENTRIES;
 assert(fe_refresh_activity(&fe,&flows[5])==-EIO && hw.commands==commands);
}
static void recycle_owner(void) {
 init(160);put_nibble(hw.rows[5],0,6);
 assert(!fe_refresh_activity(&fe,&flows[0]));assert(flows[0].activity_cached);
 /* fe_delete clears the pointer before free; a new kzalloc'ed owner has no
  * cached observation even when the hardware slot and jiffies are identical. */
 owners[160]=NULL;
 struct rtl_fe_flow replacement={.hash_index=160,.lastused=999,.installed=true,.published=true};
 owners[160]=&replacement;put_nibble(hw.rows[5],0,2);
 assert(!fe_refresh_activity(&fe,&replacement));
 assert(hw.commands==4 && replacement.activity_cached && replacement.lastused==1000);
 assert(fe_refresh_activity(&fe,&flows[0])==-EIO);
}
static void failed_rows(void) {
 for(unsigned int fail=1;fail<=2;fail++) {
  init(480);for(unsigned int i=0;i<32;i++)put_nibble(hw.rows[15],i,6);
  hw.fail_at=fail;
  assert(fe_refresh_activity(&fe,&flows[0])==-ETIMEDOUT);
  for(unsigned int i=0;i<32;i++)assert(!flows[i].activity_cached && flows[i].lastused==50);
  assert(fe_refresh_activity(&fe,&flows[1])==-ETIMEDOUT);
  complete_late(&hw);hw.fail_at=0;
  assert(!fe_refresh_activity(&fe,&flows[0]));
  for(unsigned int i=0;i<32;i++)assert(flows[i].lastused==(fail==1?1000UL:50UL));
 }
}
static void no_index_fallback(void) {
 init(64);fe.hash_owners=NULL;put_nibble(hw.rows[2],0,6);
 assert(!fe_refresh_activity(&fe,&flows[0]));
 assert(hw.commands==3 && flows[0].lastused==1000 && !flows[0].activity_cached);
 assert(!fe_refresh_activity(&fe,&flows[1]));assert(hw.commands==4 && flows[1].lastused==50);
 put_nibble(hw.rows[2],1,6);hw.fail_at=7; /* read + read + failing write */
 assert(fe_refresh_activity(&fe,&flows[1])==-ETIMEDOUT && flows[1].lastused==50);
}
static void jiffies_wrap(void) {
 init(0);jiffies=ULONG_MAX-49UL;
 for(unsigned int i=0;i<32;i++)put_nibble(hw.rows[0],i,6);
 assert(!fe_refresh_activity(&fe,&flows[0]));assert(hw.commands==2);
 jiffies=49;assert(!fe_refresh_activity(&fe,&flows[1]));assert(hw.commands==2);
 assert(flows[1].lastused==ULONG_MAX-49UL);
 jiffies=50;assert(!fe_refresh_activity(&fe,&flows[1]));assert(hw.commands==3);
 assert(flows[1].lastused==ULONG_MAX-49UL);
 put_nibble(hw.rows[0],1,6);
 assert(!fe_refresh_activity(&fe,&flows[1]));assert(hw.commands==5 && flows[1].lastused==50);
}
int main(void) {
 active_budget();idle_neighbor_becomes_active();owner_selection();recycle_owner();
 failed_rows();no_index_fallback();jiffies_wrap();
 puts("FE activity owner/cache: dense row 96-to-2 commands; idle/new/retiring/reused slots, timeout, allocation fallback and jiffies wrap passed");
 return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    source = (DRIVER / 'rtl9617c-fe.c').read_text()
    refresh = function(source, 'fe_refresh_activity')
    with tempfile.TemporaryDirectory(prefix='fe-activity-cache-', dir=ROOT / 'artifacts') as temporary:
        work = Path(temporary)
        def run(candidate, name):
            file = work / (name + '.c')
            binary = work / name
            file.write_text(COMMON + MODEL + candidate + TEST)
            subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-g', '-Wall', '-Wextra',
                            '-Wno-unused-function', '-Werror', '-fsanitize=address,undefined',
                            '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-I', str(DRIVER), str(file), '-o', str(binary)], check=True)
            return subprocess.run([str(binary)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = run(refresh, 'baseline')
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        print(result.stdout, end='')
        if args.mutants:
            mutations = {
                'renew-without-hit': ('if(hits&(1U<<i))', 'if(owned&(1U<<i))'),
                'drop-lifetime-check': ('if(!flow->installed || !flow->published || flow->deleting)return -ENOENT;', ''),
                'select-retiring': ('owner->published && !owner->deleting', 'owner->published'),
                'select-unpublished': ('owner->installed && owner->published', 'owner->installed'),
                'select-uninstalled': ('owner->installed && owner->published', 'owner->published'),
                'slide-idle-time': ('time_before(now,flow->lastused+HZ))return 0;',
                                   'time_before(now,flow->lastused+HZ)){flow->lastused=now;return 0;}'),
                'cache-expiry-off-by-one': ('flow->lastused+HZ)', 'flow->lastused+HZ+1)'),
                'ignore-transaction-error': ('if(ret)return ret;\n for(i=0;i<32;i++)', 'if(ret)return 0;\n for(i=0;i<32;i++)'),
            }
            for name, (old, new) in mutations.items():
                if old not in refresh:
                    raise RuntimeError('missing mutation anchor: ' + name)
                result = run(refresh.replace(old, new), name)
                if not result.returncode:
                    raise RuntimeError('fault escaped: ' + name)
            print('FE activity owner/cache regression assertions rejected all 8 behavioral mutations')


if __name__ == '__main__':
    main()
