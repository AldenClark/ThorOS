#!/usr/bin/env python3
"""Execute real hardware-stats and software-refresh deadline ordering.

Extract unchanged functions from the prepared kernel. Deterministic CAS hooks
model a concurrent writer; a separate jiffies32 arithmetic fixture exercises
the kernel's 32-bit time_after ordering without claiming a 32-bit ABI build.
--before reverses patches 228 and 230 in a private source copy and reproduces
the original wrap, missing-activity, delayed-writer and force regressions.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--kernel", type=Path, required=True)
parser.add_argument("--before", action="store_true")
args = parser.parse_args()


def function(source, name):
    match = re.search(r"^.*\b" + re.escape(name) + r"\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    start = match.start()
    end = source.index("{", start) + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end] + "\n"


COMMON = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;typedef int32_t __s32;typedef uint64_t u64;typedef int64_t s64;
enum {NF_FLOW_HW_BIDIRECTIONAL,NF_FLOW_CLOSING};
enum {FLOW_OFFLOAD_DIR_ORIGINAL,FLOW_OFFLOAD_DIR_REPLY,FLOW_OFFLOAD_DIR_MAX};
#define NF_FLOWTABLE_COUNTER 1
#define BIT(n) (1UL<<(n))
#define test_bit(n,p) (!!(*(p)&BIT(n)))
#define likely(x) (x)
#define HZ 100U
#define nf_flowtable_time_stamp ((u32)jiffies)
#define READ_ONCE(v) (v)
#define WRITE_ONCE(v,n) delayed_write(&(v),(n))
#define max_t(t,a,b) ((t)(a)>(t)(b)?(t)(a):(t)(b))
#ifdef MODEL_JIFFIES32
#define time_after(a,b) ((__s32)((u32)(b)-(u32)(a))<0)
#else
#define time_after(a,b) ((long)((b)-(a))<0)
#endif
struct nf_conn {unsigned unused;};
struct flow_offload {struct nf_conn *ct;unsigned long flags;u32 timeout;};
struct nf_flowtable {unsigned flags;bool hardware;};
struct flow_offload_work {struct flow_offload *flow;struct nf_flowtable *flowtable;};
struct flow_stats {u64 bytes,pkts,lastused;};
static u64 jiffies;
static unsigned long duration=30*HZ;
static unsigned cases,cas_calls,cas_failures,hw_refreshes,stats_calls[2],acct_calls[2],bridge_calls[2];
static struct flow_stats samples[2];
static u64 bridge_samples[2],acct_bytes[2],acct_pkts[2];
static bool inject;
static u32 injected_deadline;
static u64 injected_now;
static bool try_cmpxchg(u32 *p,u32 *old,u32 updated){
 cas_calls++;
 if(inject){*p=injected_deadline;jiffies=injected_now;inject=false;}
 if(*p!=*old){*old=*p;cas_failures++;return false;}
 *p=updated;return true;
}
static void delayed_write(u32 *p,u32 updated){
 if(inject){*p=injected_deadline;jiffies=injected_now;inject=false;}
 *p=updated;
}
static unsigned long flow_offload_get_timeout(struct flow_offload *f){assert(f->ct);return duration;}
static bool nf_flowtable_hw_offload(struct nf_flowtable *t){return t->hardware;}
static void nf_flow_offload_add(struct nf_flowtable *t,struct flow_offload *f){assert(t->hardware && f->ct);hw_refreshes++;}
static void flow_offload_tuple_stats(struct flow_offload_work *w,unsigned dir,struct flow_stats *s){assert(w->flow->ct && dir<2);stats_calls[dir]++;*s=samples[dir];}
static void flow_offload_refresh_bridge(struct flow_offload *f,unsigned dir,u64 last){assert(f->ct && dir<2);bridge_calls[dir]++;bridge_samples[dir]=last;}
static void nf_ct_acct_add(struct nf_conn *ct,unsigned dir,u64 pkts,u64 bytes){assert(ct && dir<2);acct_calls[dir]++;acct_pkts[dir]+=pkts;acct_bytes[dir]+=bytes;}
'''

CASES = r'''
static struct nf_conn conn;
static struct flow_offload f;
static struct nf_flowtable table;
static struct flow_offload_work work;
static void reset(u64 now,u32 deadline){
 jiffies=now;duration=30*HZ;f=(struct flow_offload){.ct=&conn,.flags=BIT(NF_FLOW_HW_BIDIRECTIONAL),.timeout=deadline};
 table=(struct nf_flowtable){.flags=NF_FLOWTABLE_COUNTER,.hardware=true};
 work=(struct flow_offload_work){.flow=&f,.flowtable=&table};
 memset(samples,0,sizeof(samples));memset(stats_calls,0,sizeof(stats_calls));
 memset(acct_calls,0,sizeof(acct_calls));memset(bridge_calls,0,sizeof(bridge_calls));
 memset(acct_bytes,0,sizeof(acct_bytes));memset(acct_pkts,0,sizeof(acct_pkts));
 memset(bridge_samples,0,sizeof(bridge_samples));
 cas_calls=cas_failures=hw_refreshes=0;inject=false;injected_now=now;
}
static bool wrap_regression(void){
 /* A still-live post-wrap deadline must survive stale hardware activity.
  * It is eligible for STATS: delta1001 < 90% of the3000-tick timeout. */
 reset(UINT32_MAX-500U,500);samples[0].lastused=UINT32_MAX-4000U;
 flow_offload_work_stats(&work);cases++;return f.timeout!=500;
}
static bool empty_stats_regression(void){
 reset(UINT32_MAX+1ULL,10);flow_offload_work_stats(&work);cases++;
 return f.timeout!=10;
}
static bool delayed_packet_regression(void){
 reset(10000,10000);inject=true;injected_deadline=14000;
 flow_offload_refresh(&table,&f,false);cases++;return f.timeout!=14000;
}
static bool stale_packet_regression(void){
 reset(10000,14000);flow_offload_refresh(&table,&f,false);cases++;
 return f.timeout!=14000;
}
static bool forced_packet_regression(void){
 reset(10000,14000);flow_offload_refresh(&table,&f,true);cases++;
 assert(hw_refreshes==1);return f.timeout!=14000;
}
#ifndef EXPECT_BEFORE
static void stats_cases(void){
 reset(10000,11000);samples[0]=(struct flow_stats){.lastused=9500,.bytes=200,.pkts=2};
 samples[1]=(struct flow_stats){.lastused=10000,.bytes=900,.pkts=9};
 flow_offload_work_stats(&work);assert(f.timeout==13000 && cas_calls==1);
 for(unsigned d=0;d<2;d++){
  assert(stats_calls[d]==1 && acct_calls[d]==1 && bridge_calls[d]==1);
  assert(acct_bytes[d]==samples[d].bytes && acct_pkts[d]==samples[d].pkts);
  assert(bridge_samples[d]==samples[d].lastused);
 }
 cases++;
 /* A newer software refresh wins an in-flight STATS CAS. */
 reset(10000,11000);samples[0].lastused=10000;inject=true;injected_deadline=14000;
 flow_offload_work_stats(&work);assert(f.timeout==14000 && cas_calls==1 && cas_failures==1);cases++;
 /* A competing extension that is still older must not suppress progress. */
 reset(10000,11000);samples[0].lastused=10000;inject=true;injected_deadline=12000;
 flow_offload_work_stats(&work);assert(f.timeout==13000 && cas_calls==2 && cas_failures==1);cases++;
 reset(10000,13000);samples[0].lastused=10000;
 flow_offload_work_stats(&work);assert(f.timeout==13000 && !cas_calls);cases++;
 /* Already expired activity and exact-deadline activity cannot revive or
  * advance an expired flow awaiting GC. */
 reset(10000,9000);samples[0].lastused=6500;
 flow_offload_work_stats(&work);assert(f.timeout==9000 && !cas_calls);cases++;
 reset(10000,9500);samples[0].lastused=7000;
 flow_offload_work_stats(&work);assert(f.timeout==9500 && !cas_calls);cases++;
 /* Missing reply stats must not manufacture a second direction; zero is
  * the kernel stats ABI's no-activity sentinel, even at exact tick zero. */
 reset(10000,11000);f.flags=0;samples[1].lastused=20000;
 flow_offload_work_stats(&work);assert(f.timeout==11000 && !stats_calls[1] && !cas_calls);cases++;
 reset(10000,11000);samples[1].lastused=10000;
 flow_offload_work_stats(&work);assert(f.timeout==13000);cases++;
 /* New activity across the low32 deadline wrap must still extend. */
 reset(UINT32_MAX+501ULL,2000);
#ifdef MODEL_JIFFIES32
 samples[0].lastused=UINT32_MAX-500U;samples[1].lastused=500;
#else
 samples[0].lastused=UINT32_MAX-500U;samples[1].lastused=UINT32_MAX+501ULL;
#endif
 flow_offload_work_stats(&work);assert(f.timeout==3500);cases++;
 /* Direction order must not affect which activity wins. */
 struct flow_stats swap=samples[0];samples[0]=samples[1];samples[1]=swap;f.timeout=2000;
 flow_offload_work_stats(&work);assert(f.timeout==3500);cases++;
#ifndef MODEL_JIFFIES32
 /* Keep full-width timestamp ordering on ARM64; an idle direction can be
  * older than half of the u32 deadline cycle while its peer stays active. */
 reset(UINT32_MAX+100001ULL,101000);samples[0].lastused=jiffies-(1ULL<<31)-100;
 samples[1].lastused=jiffies;flow_offload_work_stats(&work);assert(f.timeout==103000);cases++;
 /* More importantly, one unused accepted hardware direction may remain
  * old while the opposite, unoffloaded software direction keeps renewing.
  * Truncating its ancient expiry before checking the full-width clock
  * would extend this live flow by almost half a u32 deadline cycle. */
 reset(UINT32_MAX+100001ULL,101000);samples[0].lastused=jiffies-(1ULL<<31)-10000;
 flow_offload_work_stats(&work);assert(f.timeout==101000 && !cas_calls);cases++;
#endif
 table.flags=0;f.timeout=102000;flow_offload_work_stats(&work);
 assert(!acct_calls[0] && !acct_calls[1]);cases++;
}
static void software_cases(void){
 reset(10000,12900);flow_offload_refresh(&table,&f,false);
 assert(f.timeout==12900 && !cas_calls && !hw_refreshes);cases++;
 reset(10000,12899);flow_offload_refresh(&table,&f,false);
 assert(f.timeout==13000 && cas_calls==1 && hw_refreshes==1);cases++;
 reset(10000,12950);flow_offload_refresh(&table,&f,true);
 assert(f.timeout==13000 && cas_calls==1 && hw_refreshes==1);cases++;
 reset(10000,13000);flow_offload_refresh(&table,&f,true);
 assert(f.timeout==13000 && !cas_calls && hw_refreshes==1);cases++;
 reset(10000,10000);inject=true;injected_deadline=12000;
 flow_offload_refresh(&table,&f,false);
 assert(f.timeout==13000 && cas_calls==2 && cas_failures==1 && hw_refreshes==1);cases++;
 reset(10000,10000);inject=true;injected_deadline=14000;
 flow_offload_refresh(&table,&f,true);
 assert(f.timeout==14000 && cas_calls==1 && cas_failures==1 && hw_refreshes==1);cases++;
 reset(UINT32_MAX+501ULL,UINT32_MAX-100U);flow_offload_refresh(&table,&f,false);
 assert(f.timeout==3500 && hw_refreshes==1);cases++;
 reset(10000,11000);table.hardware=false;flow_offload_refresh(&table,&f,false);
 assert(f.timeout==13000 && !hw_refreshes);cases++;
 reset(10000,11000);f.flags|=BIT(NF_FLOW_CLOSING);flow_offload_refresh(&table,&f,true);
 assert(f.timeout==13000 && !hw_refreshes);cases++;
 /* Timeout sysctl reduction applies to future extension, not revocation of
  * a previously granted deadline. force still signals hardware updates. */
 reset(10000,13000);duration=1000;flow_offload_refresh(&table,&f,false);
 assert(f.timeout==13000 && !cas_calls && !hw_refreshes);cases++;
 flow_offload_refresh(&table,&f,true);assert(f.timeout==13000 && hw_refreshes==1);cases++;
 jiffies=12200;flow_offload_refresh(&table,&f,false);
 assert(f.timeout==13200 && hw_refreshes==2);cases++;
}
static void modular_sweep(void){
 /* All deltas stay inside the signed-u32 half-range assumed by the real
  * nf_flow_timeout_delta. Exercise ordinary and low32 wrap neighborhoods. */
 for(unsigned round=0;round<4;round++)for(unsigned n=0;n<5000;n++){
  u64 now=round==0?10000+n:round==1?UINT32_MAX-4999ULL+n:
          round==2?UINT32_MAX+1ULL+n:2ULL*UINT32_MAX+10000+n;
  unsigned age=n%2500;
  int ahead=(int)(n%5001)-1000;
  u32 current=(u32)now+ahead,updated=(u32)now-age+3000;
  reset(now,current);
#ifdef MODEL_JIFFIES32
  samples[0].lastused=(u32)(now-age);
#else
  samples[0].lastused=now-age;
#endif
  flow_offload_work_stats(&work);
  __s32 remaining=(__s32)(updated-(u32)now),old_remaining=(__s32)(current-(u32)now);
  u32 expected=samples[0].lastused && remaining>0 && remaining>old_remaining?updated:current;
  assert(f.timeout==expected);cases++;
  reset(now,current);bool force=n&1;
  flow_offload_refresh(&table,&f,force);updated=(u32)now+3000;
  remaining=(__s32)(updated-(u32)now);old_remaining=(__s32)(current-(u32)now);
  expected=remaining>0 && (s64)remaining-old_remaining>(force?0:(__s32)HZ)?updated:current;
  assert(f.timeout==expected);cases++;
 }
}
static void maximum_timeout_cases(void){
 const unsigned long maximum=(unsigned long)(INT32_MAX/HZ)*HZ;
 /* Positive proc_dointvec_jiffies values permit this whole-second limit.
  * The old deadline is only one second expired, but the direct difference
  * to the new valid deadline exceeds the signed32 half-cycle. */
 reset(10000,9900);duration=maximum;samples[0].lastused=jiffies;
 flow_offload_work_stats(&work);assert(f.timeout==(u32)(jiffies+maximum) && cas_calls==1);cases++;
 reset(10000,9900);duration=maximum;flow_offload_refresh(&table,&f,false);
 assert(f.timeout==(u32)(jiffies+maximum) && cas_calls==1 && hw_refreshes==1);cases++;
 /* A concurrent max-duration refresh just across the half-cycle boundary
  * must be compared with a new clock after CAS failure, not stale now. */
 for(unsigned route=0;route<2;route++){
  reset(10000,9900);duration=maximum;samples[0].lastused=jiffies;
  inject=true;injected_now=jiffies+HZ;injected_deadline=(u32)(injected_now+maximum);
  if(route)flow_offload_refresh(&table,&f,false);else flow_offload_work_stats(&work);
  assert(f.timeout==injected_deadline && cas_failures==1 && cas_calls==1);cases++;
 }
 /* A delayed writer's sampled candidate can expire while CAS loses. */
 for(unsigned route=0;route<2;route++){
  reset(10000,9900);samples[0].lastused=jiffies;
  inject=true;injected_now=14000;injected_deadline=12900;
  if(route)flow_offload_refresh(&table,&f,false);else flow_offload_work_stats(&work);
  assert(f.timeout==12900 && cas_failures==1 && cas_calls==1);cases++;
 }
 for(unsigned n=0;n<1000;n++){
  u64 now=UINT32_MAX-500ULL+n;
  __s32 offsets[]={-1000,-1,0,1,INT32_MAX-1};
  for(unsigned k=0;k<sizeof(offsets)/sizeof(offsets[0]);k++){
   u32 old=(u32)now+offsets[k];
   reset(now,old);duration=maximum;samples[0].lastused=
#ifdef MODEL_JIFFIES32
    (u32)now;
#else
    now;
#endif
   flow_offload_work_stats(&work);
   u32 expected=samples[0].lastused && (s64)maximum>offsets[k]?(u32)(now+maximum):old;
   assert(f.timeout==expected);cases++;
   reset(now,old);duration=maximum;flow_offload_refresh(&table,&f,false);
   expected=(s64)maximum-offsets[k]>HZ?(u32)(now+maximum):old;
   assert(f.timeout==expected);cases++;
  }
 }
}
#endif
int main(void){
 bool wrap=wrap_regression(),empty=empty_stats_regression(),late=delayed_packet_regression();
 bool stale=stale_packet_regression(),forced=forced_packet_regression();
 printf("wrap_regression=%u no_activity_renewal=%u delayed_writer_regression=%u stale_writer_regression=%u forced_regression=%u\n",wrap,empty,late,stale,forced);
 fflush(stdout);
#ifdef EXPECT_BEFORE
 assert(wrap && empty && late && stale && forced);
#else
 assert(!wrap && !empty && !late && !stale && !forced);
 stats_cases();software_cases();modular_sweep();maximum_timeout_cases();
#endif
 printf("PASS: %u actual-function deadline cases\n",cases);
}
'''


def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


with tempfile.TemporaryDirectory(prefix="flow-timeout-") as directory:
    work = Path(directory)
    for name in ("nf_flow_table_core.c", "nf_flow_table_offload.c"):
        target = work / "net/netfilter" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.kernel / "net/netfilter" / name, target)
    if args.before:
        for name in ("230-flowtable-refresh-timeout-order.patch", "228-flowtable-stats-timeout-wrap.patch"):
            patch = ROOT / "port/overlay/target/linux/rtl9617c/patches-6.18" / name
            subprocess.run(["patch", "-R", "-p1", "--fuzz=0", "-i", str(patch)], cwd=work, check=True)
    core = (work / "net/netfilter/nf_flow_table_core.c").read_text()
    offload = (work / "net/netfilter/nf_flow_table_offload.c").read_text()
    production = function(offload, "flow_offload_work_stats") + function(core, "flow_offload_refresh")
    command = ["cc", "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
               "-fsanitize=address,undefined", "-g"]
    if args.before:
        command += ["-DEXPECT_BEFORE"]
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0", UBSAN_OPTIONS="halt_on_error=1")
    runs = []
    for bits in (64, 32):
        source = work / f"timeout-{bits}.c"
        binary = work / f"timeout-{bits}"
        source.write_text(COMMON + production + CASES)
        flags = ["-DMODEL_JIFFIES32"] if bits == 32 else []
        subprocess.run(command + flags + [str(source), "-o", str(binary)], check=True)
        result = subprocess.run([str(binary)], env=env, text=True, capture_output=True, preexec_fn=no_core)
        print(f"jiffies{bits}:\n{result.stdout}", end="")
        if result.returncode:
            print(result.stderr)
            result.check_returncode()
        runs.append({"jiffies_bits": bits, "output": result.stdout})
    mutations = {}
    if not args.before:
        mutations = {
            "stats_nonatomic_write": (
                "try_cmpxchg(&offload->flow->timeout, &timeout, updated)",
                "(WRITE_ONCE(offload->flow->timeout, updated), true)"),
            "stats_numeric_deadline_order": ("(__s32)(updated - (u32)now) <=\n\t\t\t    (__s32)(timeout - (u32)now)", "updated <= timeout"),
            "stats_direct_deadline_delta": ("(__s32)(updated - (u32)now) <=\n\t\t\t    (__s32)(timeout - (u32)now)", "(__s32)(updated - timeout) <= 0"),
            "stats_numeric_activity_order32": (
                "time_after((unsigned long)stats[1].lastused, lastused)", "stats[1].lastused > lastused"),
            "stats_expired_activity": ("!time_after(expires, now)", "false"),
            "stats_stale_clock_after_cas": ("now = jiffies;", "now = lastused;"),
            "software_nonatomic_write": (
                "try_cmpxchg(&flow->timeout, &old, timeout)",
                "(WRITE_ONCE(flow->timeout, timeout), true)"),
            "software_unsigned_delta": ("advance = (s64)(__s32)(timeout - now) - (__s32)(old - now);",
                                        "advance = (u32)(timeout - old);"),
            "software_narrow_deadline_delta": ("advance = (s64)(__s32)(timeout - now) - (__s32)(old - now);",
                                               "advance = (__s32)(timeout - old);"),
            "software_stale_clock_after_cas": ("now = nf_flowtable_time_stamp;",
                                                "now = timeout - flow_offload_get_timeout(flow);"),
            "force_drops_hardware_refresh": ("if (!force)\n\t\t\t\treturn;", "if (true)\n\t\t\t\treturn;"),
        }
        for name, (old, new) in mutations.items():
            assert production.count(old) == 1, name
            source, binary = work / f"{name}.c", work / name
            source.write_text(COMMON + production.replace(old, new) + CASES)
            flags = [] if name == "stats_expired_activity" else ["-DMODEL_JIFFIES32"]
            subprocess.run(command + flags + [str(source), "-o", str(binary)], check=True)
            result = subprocess.run([str(binary)], env=env, text=True, capture_output=True, preexec_fn=no_core)
            assert result.returncode != 0 and "Assertion" in result.stderr, (name, result.stdout, result.stderr)
            print(f"REJECTED: {name}")
    report = {
        "before": args.before, "production_sha256": hashlib.sha256(production.encode()).hexdigest(),
        "runs": runs, "mutations_rejected": list(mutations), "sanitizers": ["address", "undefined"],
        "scope": "actual prepared-kernel stats/refresh functions; modeled jiffies32/CAS interleavings, not an ARM32 ABI, network or hardware test",
        "timeout_domain": "u32 deadlines, nonnegative durations below signed-u32 half-range, zero stats means no activity",
        "hardware_verified": False,
    }
    name = "flowtable-timeout-order-before.json" if args.before else "flowtable-timeout-order.json"
    (ROOT / "artifacts" / name).write_text(json.dumps(report, indent=2) + "\n")
