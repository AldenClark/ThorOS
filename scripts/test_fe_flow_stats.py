#!/usr/bin/env python3
"""Check production MIB-to-conntrack byte accounting and idle timestamps."""
from pathlib import Path
import re
import subprocess
import tempfile
from test_fe_age_batch import function

root=Path(__file__).resolve().parents[1]
source=(root/'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c-fe.c').read_text()
start=re.search(r'^static int fe_stats\(',source,re.M).start()
end=source.index('{',start)+1;depth=1
while depth:
    depth+=(source[end]=='{')-(source[end]=='}');end+=1
common=r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
typedef uint64_t u64;typedef uint32_t u32;
#define ETH_HLEN 14
#define FLOW_ACTION_HW_STATS_DELAYED 1
#define RTL_FE_HASH_ENTRIES 65536
#define HZ 100UL
#define time_before(a,b) ((long)((a)-(b))<0)
static unsigned long jiffies=100;
struct rtl_fe_flow;
struct rtl_fe {u64 bytes;u32 packets,non_uc;unsigned int age;struct rtl_fe_flow **hash_owners;};
struct rtl_fe_flow {bool published,counted,installed,deleting,activity_cached;unsigned int counter,hash_index,ethernet_bytes;u64 bytes,observed_bytes,observed_packets;u32 packets,observations,activity_hits;unsigned long lastused,observation_at;int observation_error;};
struct flow_cls_offload {struct {u64 bytes,packets;unsigned long lastused;} stats;};
struct rtl_dq_io {struct rtl_fe *fe;};
static struct rtl_dq_io fe_io(struct rtl_fe *fe){return (struct rtl_dq_io){fe};}
static int rtl_fe_main_age_read(struct rtl_dq_io *io,unsigned int index,unsigned int *age){(void)index;*age=io->fe->age;return 0;}
static int rtl_fe_main_age(struct rtl_dq_io *io,unsigned int index,unsigned int age){(void)index;io->fe->age=age;return 0;}
/* This MIB fixture deliberately exercises the no-index path. Actual row
 * ownership/caching uses production MMIO in test_fe_activity_cache. */
static int rtl_fe_main_age_batch(struct rtl_dq_io *io,unsigned int first,unsigned int owned,unsigned int probe,unsigned int *hits){
 (void)io;(void)first;(void)owned;(void)probe;(void)hits;assert(!"unexpected indexed path in MIB fixture");return -EOPNOTSUPP;
}
static int rtl_fe_tx_counter_read(struct rtl_dq_io *io,unsigned int counter,unsigned int *words){
 assert(counter==31);words[0]=io->fe->bytes;words[1]=io->fe->bytes>>32;words[2]=io->fe->packets;words[3]=io->fe->non_uc;return 0;
}
#define flow_stats_update(s,b,p,d,u,h) do{assert((d)==0 && (h)==1);(s)->bytes+=(b);(s)->packets+=(p);(s)->lastused=(u);}while(0)
'''
test=r'''
int main(void){
 struct rtl_fe fe={.bytes=5355,.packets=22,.age=1};
 struct rtl_fe_flow flow={.published=true,.counted=true,.activity_cached=true,.counter=31,.ethernet_bytes=14,.bytes=5000,.packets=17,.lastused=80};
 struct flow_cls_offload cls={};
 assert(!fe_stats(&fe,&flow,&cls));
 assert(cls.stats.packets==5 && cls.stats.bytes==285 && cls.stats.lastused==100);
 assert(flow.observations==1 && flow.observed_bytes==285 && flow.observed_packets==5);
 assert(flow.observation_at==100 && !flow.observation_error);
 assert(!flow.activity_cached); /* MIB activity must not slide the Hash row cache. */
 jiffies=120;assert(!fe_stats(&fe,&flow,&cls));
 assert(cls.stats.packets==5 && cls.stats.bytes==285 && cls.stats.lastused==100);
 assert(flow.observations==2 && flow.observed_bytes==285 && flow.observed_packets==5);
 flow.packets=UINT32_MAX-2;fe.packets=2;flow.bytes=6000;fe.bytes=6355;
 assert(!fe_stats(&fe,&flow,&cls));
 assert(cls.stats.packets==10 && cls.stats.bytes==570 && cls.stats.lastused==120);
 flow.counted=false;fe.age=6;jiffies=150;
 assert(!fe_stats(&fe,&flow,&cls));
 assert(fe.age==1 && cls.stats.lastused==150 && cls.stats.packets==10 && cls.stats.bytes==570);
 jiffies=180;assert(!fe_stats(&fe,&flow,&cls));
 assert(cls.stats.lastused==150); /* An idle shared interface must not renew this flow. */
 flow.counted=true;flow.ethernet_bytes=22;flow.packets=0;flow.bytes=0;fe.packets=5;fe.bytes=395;
 cls.stats.bytes=cls.stats.packets=0;
 assert(!fe_stats(&fe,&flow,&cls));
 assert(cls.stats.bytes==285 && cls.stats.packets==5); /* Output QinQ header excluded. */
 flow.ethernet_bytes=26;flow.packets=0;flow.bytes=0;fe.bytes=415;
 cls.stats.bytes=cls.stats.packets=0;
 assert(!fe_stats(&fe,&flow,&cls));
 assert(cls.stats.bytes==285 && cls.stats.packets==5); /* PPPoE plus one VLAN excluded. */
 /* MC1 GEM mapping uses the non-UC counter while the wire byte total stays shared. */
 flow.ethernet_bytes=26;flow.packets=0;flow.bytes=0;fe.packets=0;fe.non_uc=5;fe.bytes=415;
 cls.stats.bytes=cls.stats.packets=0;
 assert(!fe_stats(&fe,&flow,&cls));
 assert(cls.stats.bytes==285 && cls.stats.packets==5);
 /* Mixed classes and wrap in their combined 32-bit total preserve byte adjustment. */
 flow.packets=UINT32_MAX-2;flow.bytes=6000;fe.packets=UINT32_MAX;fe.non_uc=3;fe.bytes=6415;
 assert(!fe_stats(&fe,&flow,&cls));
 assert(cls.stats.bytes==570 && cls.stats.packets==10);
 /* A reset/decreasing byte total or a torn sample smaller than its L2
  * headers must not credit 2^64 bogus bytes to conntrack or the report. */
 u64 before_bytes=cls.stats.bytes,before_packets=cls.stats.packets;
 u64 observed=flow.observed_bytes;unsigned int samples=flow.observations;
 flow.bytes=5000;flow.packets=10;fe.bytes=20;fe.packets=11;fe.non_uc=0;
 assert(fe_stats(&fe,&flow,&cls)==-ERANGE && flow.observation_error==-ERANGE);
 assert(cls.stats.bytes==before_bytes && cls.stats.packets==before_packets);
 assert(flow.observed_bytes==observed && flow.observations==samples);
 assert(flow.bytes==20 && flow.packets==11);
 fe.bytes=21;fe.packets=12;
 assert(fe_stats(&fe,&flow,&cls)==-ERANGE);
 assert(cls.stats.bytes==before_bytes && cls.stats.packets==before_packets);
 fe.bytes=104;fe.packets=13;
 assert(!fe_stats(&fe,&flow,&cls) && !flow.observation_error);
 assert(cls.stats.bytes==before_bytes+57 && cls.stats.packets==before_packets+1);
 flow.published=false;assert(fe_stats(&fe,&flow,&cls)==-ENOENT);
 assert(flow.observation_error==-ENOENT);
 puts("Native FE stats:wire355 bytes/five packets ->IP285 bytes;idle lastused unchanged;packet counter wrap passed");
}
'''
with tempfile.TemporaryDirectory(dir=root/'artifacts',prefix='fe-stats-') as work:
    path=Path(work)/'stats.c';binary=Path(work)/'stats'
    path.write_text(common+function(source,'fe_refresh_activity')+source[start:end]+test)
    subprocess.run(['cc','-fsanitize=address,undefined','-g',str(path),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
