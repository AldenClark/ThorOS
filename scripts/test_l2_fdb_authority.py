#!/usr/bin/env python3
"""Run the actual bridge CPU/HW FDB publication races, without emulating policy.

The hash table, clock and gate are test dependencies. The CPU update, hardware
publication and ownership-checked removal are extracted unchanged from patch
239; --kernel additionally requires byte-identical applied definitions.
"""
import argparse
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "port/overlay/target/linux/rtl9617c/patches-6.18/239-native-fdb-cpu-authority.patch"
NAMES = ("br_fdb_update", "br_rtl9617c_fdb_learn_publish",
         "br_rtl9617c_fdb_learn", "br_rtl9617c_fdb_forget")


def function(source, name):
    match = re.search(r"^(?:static\s+)?(?:void|bool|int)\s+" + name + r"\(", source, re.M)
    assert match, name
    brace = source.index("\n{", match.start()) + 1
    depth = 0
    for index in range(brace, len(source)):
        depth += (source[index] == "{") - (source[index] == "}")
        if not depth:
            return source[match.start():index + 1]
    raise AssertionError(name)


def production(kernel=None):
    patched = "\n".join(line[1:] for line in PATCH.read_text().splitlines()
                        if line.startswith((" ", "+")) and not line.startswith("+++"))
    context = re.search(r"struct br_rtl9617c_learn_ctx \{[^}]+\};", patched).group(0)
    functions = [function(patched, name) for name in NAMES]
    if kernel:
        actual = (kernel / "net/bridge/br_fdb.c").read_text()
        assert context in actual
        for name, body in zip(NAMES, functions):
            assert body == function(actual, name), name
    return context + "\n" + "\n".join(functions)


STUBS = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define BIT(n) (1UL << (n))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define likely(x) (x)
#define unlikely(x) (x)
#define ASSERT_RTNL() do {} while (0)
#define BR_LEARNING BIT(5)
#define BR_STATE_FORWARDING 3
#define RTM_NEWNEIGH 28
#define RTM_DELNEIGH 29
typedef uint16_t u16; typedef uint64_t u64;
enum { BR_FDB_LOCAL, BR_FDB_STATIC, BR_FDB_ADDED_BY_USER,
 BR_FDB_ADDED_BY_EXT_LEARN, BR_FDB_OFFLOADED, BR_FDB_STICKY,
 BR_FDB_LOCKED, BR_FDB_NOTIFY_INACTIVE, BR_FDB_DYNAMIC_LEARNED };
struct net_bridge; struct net_bridge_port;
struct net {u64 generation;unsigned active,begins,ends;bool hw_open;};
struct net_device {struct net_bridge_port *port;struct net *net;bool owned;const char *name;};
struct net_bridge_port {struct net_device *dev;struct net_bridge *br;unsigned flags,state;};
struct net_bridge_fdb_entry {unsigned long flags,updated,used;struct net_bridge_port *dst;unsigned char addr[6];u16 vid;bool valid;};
struct table {struct net_bridge *br;};
struct net_bridge {struct net_device *dev;int hash_lock;struct table fdb_hash_tbl;unsigned long age;int fdb_n_learned;struct net_bridge_fdb_entry entries[8];};
struct rtl9617c_switch_guard {struct net *net;};
static struct net ns;
static struct net_bridge bridge;
static struct net_device master,devices[3];
static struct net_bridge_port ports[3];
static struct rtl9617c_switch_guard guard;
static unsigned long jiffies;
static unsigned locks,creates,notifications,deleted,warnings;
static bool publishing,alloc_fails;
static void (*before_lock)(void);
static bool test_bit(unsigned bit,const unsigned long *p){return !!(*p&BIT(bit));}
static void set_bit(unsigned bit,unsigned long *p){*p|=BIT(bit);}
static void clear_bit(unsigned bit,unsigned long *p){*p&=~BIT(bit);}
static bool test_and_clear_bit(unsigned bit,unsigned long *p){bool old=test_bit(bit,p);clear_bit(bit,p);return old;}
static void atomic_dec(int *p){(*p)--;}
static unsigned long hold_time(const struct net_bridge *br){return br->age;}
static bool __fdb_mark_active(struct net_bridge_fdb_entry *fdb){return test_and_clear_bit(BR_FDB_NOTIFY_INACTIVE,&fdb->flags);}
static int net_ratelimit(void){return 1;}
#define br_warn(...) do {warnings++;} while (0)
#define trace_br_fdb_update(...) do {} while (0)
static void spin_lock(int *lock){
 if(before_lock){void (*hook)(void)=before_lock;before_lock=NULL;hook();}
 assert(!*lock);*lock=1;locks++;
}
static void spin_unlock(int *lock){assert(*lock);*lock=0;}
static void spin_lock_bh(int *lock){spin_lock(lock);}
static void spin_unlock_bh(int *lock){spin_unlock(lock);}
static struct net_bridge_fdb_entry *fdb_find_rcu(struct table *t,const unsigned char *addr,u16 vid){
 for(unsigned i=0;i<8;i++)if(t->br->entries[i].valid && t->br->entries[i].vid==vid && !memcmp(t->br->entries[i].addr,addr,6))return &t->br->entries[i];
 return NULL;
}
static struct net_bridge_fdb_entry *br_fdb_find(struct net_bridge *br,const unsigned char *addr,u16 vid){assert(br->hash_lock);return fdb_find_rcu(&br->fdb_hash_tbl,addr,vid);}
static struct net_bridge_fdb_entry *fdb_create(struct net_bridge *br,struct net_bridge_port *port,const unsigned char *addr,u16 vid,unsigned long flags){
 assert(br->hash_lock);
 if(!publishing && br->dev->owned)assert(ns.active && !ns.hw_open);
 creates++;
 if(alloc_fails || fdb_find_rcu(&br->fdb_hash_tbl,addr,vid))return NULL;
 for(unsigned i=0;i<8;i++)if(!br->entries[i].valid){
  br->entries[i]=(struct net_bridge_fdb_entry){.valid=true,.dst=port,.vid=vid,.flags=flags,.updated=jiffies,.used=jiffies};
  memcpy(br->entries[i].addr,addr,6);return &br->entries[i];
 }
 return NULL;
}
static struct net *rtl9617c_switch_policy_begin(const struct net_device *dev){
 assert(bridge.hash_lock && !publishing);
 if(!dev->owned)return NULL;
 assert(dev->net==&ns);ns.begins++;ns.active++;ns.generation++;ns.hw_open=false;return &ns;
}
static void rtl9617c_switch_policy_end(struct net *net){assert(net==&ns && !bridge.hash_lock && ns.active && !publishing);ns.active--;ns.ends++;}
static struct net_bridge_port *br_port_get_rtnl(const struct net_device *dev){return dev->port;}
static int rtl9617c_switch_guard_publish(struct rtl9617c_switch_guard *g,u64 epoch,int (*fn)(void *),void *ctx){
 assert(bridge.hash_lock && !publishing);
 if(g->net->active || g->net->generation!=epoch)return -EAGAIN;
 publishing=true;int ret=fn(ctx);publishing=false;return ret;
}
static void fdb_notify(struct net_bridge *br,const struct net_bridge_fdb_entry *fdb,int event,bool sw){
 assert(!publishing && fdb && event==RTM_NEWNEIGH);if(!sw)assert(br->hash_lock);notifications++;
}
static void br_switchdev_fdb_notify(struct net_bridge *br,const struct net_bridge_fdb_entry *fdb,int event){assert(br->hash_lock && !publishing && fdb && event==RTM_DELNEIGH);}
static void fdb_delete(struct net_bridge *br,struct net_bridge_fdb_entry *fdb,bool sw){assert(br->hash_lock && !sw && fdb->valid);fdb->valid=false;deleted++;}
'''

TESTS = r'''
static const unsigned char mac[6]={2,0,0,0,0,1};
static unsigned cases;
static void setup(void){
 ns=(struct net){.generation=100,.hw_open=true};
 bridge=(struct net_bridge){.age=300};
 master=(struct net_device){.net=&ns,.owned=true,.name="br0"};bridge.dev=&master;bridge.fdb_hash_tbl.br=&bridge;
 for(unsigned i=0;i<3;i++){devices[i]=(struct net_device){.net=&ns,.owned=i<2,.name="port"};ports[i]=(struct net_bridge_port){.dev=&devices[i],.br=&bridge,.state=BR_STATE_FORWARDING,.flags=BR_LEARNING};devices[i].port=&ports[i];}
 guard.net=&ns;locks=creates=notifications=deleted=warnings=0;jiffies=10;before_lock=NULL;publishing=alloc_fails=false;
}
static struct net_bridge_fdb_entry *entry(void){return fdb_find_rcu(&bridge.fdb_hash_tbl,mac,0);}
static void hardware_first(void){assert(!br_rtl9617c_fdb_learn(&devices[0],mac,&guard,ns.generation));}
static void assert_cpu(unsigned port){struct net_bridge_fdb_entry *f=entry();assert(f && f->dst==&ports[port] && !(f->flags&(BIT(BR_FDB_ADDED_BY_EXT_LEARN)|BIT(BR_FDB_OFFLOADED))) && !ns.active && ns.begins==ns.ends);}
int main(void){
 /* Empty Linux FDB, old LAN0 hardware snapshot, CPU first sees LAN1. */
 setup();u64 old=ns.generation;br_fdb_update(&bridge,&ports[1],mac,0,0);assert_cpu(1);
 assert(ns.generation==old+1 && !ns.hw_open && creates==1);
 struct net_bridge_fdb_entry saved=*entry();jiffies=20;
 assert(br_rtl9617c_fdb_learn(&devices[0],mac,&guard,old)==-EAGAIN);
 assert(!memcmp(entry(),&saved,sizeof(saved)));cases++;
 /* A current epoch is not authority to steal/refresh a CPU-owned key. */
 for(unsigned port=0;port<2;port++){
  assert(br_rtl9617c_fdb_learn(&devices[port],mac,&guard,ns.generation)==-EALREADY);
  assert(!memcmp(entry(),&saved,sizeof(saved)));assert(!br_rtl9617c_fdb_forget(&devices[port],mac));cases++;
 }
 /* Same-port EXT takeover fences the pending move and only once. */
 setup();hardware_first();old=ns.generation;jiffies=30;br_fdb_update(&bridge,&ports[0],mac,0,0);assert_cpu(0);
 assert(ns.generation==old+1);saved=*entry();assert(br_rtl9617c_fdb_learn(&devices[1],mac,&guard,old)==-EAGAIN);assert(!memcmp(entry(),&saved,sizeof(saved)));
 unsigned saved_locks=locks;old=ns.generation;
 for(unsigned i=0;i<16;i++){jiffies++;br_fdb_update(&bridge,&ports[0],mac,0,0);assert(locks==saved_locks && ns.generation==old);}
 assert_cpu(0);cases++;
 /* Hardware creates after CPU's initial miss, before CPU takes hash_lock. */
 setup();before_lock=hardware_first;br_fdb_update(&bridge,&ports[1],mac,0,0);assert_cpu(1);
 assert(creates==1 && ns.begins==1 && ns.generation==101);cases++;
 /* A real subsequent CPU move remains fenced; VID keys stay independent. */
 old=ns.generation;jiffies=50;br_fdb_update(&bridge,&ports[0],mac,0,0);assert_cpu(0);assert(ns.generation==old+1);
 br_fdb_update(&bridge,&ports[1],mac,10,0);assert(entry()->dst==&ports[0]);
 assert(fdb_find_rcu(&bridge.fdb_hash_tbl,mac,10)->dst==&ports[1]);cases++;
 /* Same-port EXT belonging to another driver must retain ownership. */
 setup();assert(!br_rtl9617c_fdb_learn(&devices[2],mac,&guard,ns.generation));saved=*entry();old=ns.generation;jiffies++;
 br_fdb_update(&bridge,&ports[2],mac,0,0);assert(entry()->flags==saved.flags && entry()->dst==saved.dst && ns.generation==old && !ns.begins);cases++;
 /* Hold-time zero and failed allocation preserve the gate's nesting. */
 setup();bridge.age=0;br_fdb_update(&bridge,&ports[0],mac,0,0);assert(!entry() && !creates && !ns.begins);cases++;
 setup();alloc_fails=true;br_fdb_update(&bridge,&ports[0],mac,0,0);assert(!entry() && ns.begins==1 && ns.ends==1 && !ns.active && !ns.hw_open);cases++;
 /* Protected local/sticky/static/user/locked entries are never HW-owned. */
 const unsigned protected[]={BR_FDB_LOCAL,BR_FDB_STICKY,BR_FDB_STATIC,BR_FDB_ADDED_BY_USER,BR_FDB_LOCKED};
 for(unsigned i=0;i<sizeof(protected)/sizeof(protected[0]);i++){
  setup();hardware_first();set_bit(protected[i],&entry()->flags);saved=*entry();
  assert(br_rtl9617c_fdb_learn(&devices[1],mac,&guard,ns.generation)==-EEXIST);
  assert(!br_rtl9617c_fdb_forget(&devices[0],mac));assert(!memcmp(entry(),&saved,sizeof(saved)));cases++;
 }
 setup();hardware_first();assert(br_rtl9617c_fdb_forget(&devices[0],mac) && !entry() && deleted==1);cases++;
 printf("Native FDB authority: %u targeted real-function race/ownership cases PASS\n",cases);
 return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--mutants", action="store_true")
    args = parser.parse_args()
    source = production(args.kernel)
    variants = {"production": source}
    changes = {
        "first_create_without_fence": ("if (!fdb) {\n\t\tpolicy = rtl9617c_switch_policy_begin(br->dev);", "if (!fdb) {\n\t\tpolicy = NULL;"),
        "miss_not_rechecked_under_lock": ("spin_lock(&br->hash_lock);\n\tfdb = fdb_find_rcu(&br->fdb_hash_tbl, addr, vid);", "spin_lock(&br->hash_lock);"),
        "same_port_ext_not_taken_over": ("bool takeover = test_bit(BR_FDB_ADDED_BY_EXT_LEARN, &fdb->flags)", "bool takeover = false && test_bit(BR_FDB_ADDED_BY_EXT_LEARN, &fdb->flags)"),
        "offloaded_flag_survives_takeover": ("clear_bit(BR_FDB_OFFLOADED, &fdb->flags);", "set_bit(BR_FDB_OFFLOADED, &fdb->flags);"),
        "hardware_steals_cpu_authority": ("if (fdb && !test_bit(BR_FDB_ADDED_BY_EXT_LEARN, &fdb->flags))\n\t\treturn -EALREADY;", "if (false)\n\t\treturn -EALREADY;"),
        "foreign_ext_is_stolen": ("takeover = !!policy;", "takeover = true;"),
        "unoffload_removes_cpu_entry": ("test_bit(BR_FDB_ADDED_BY_EXT_LEARN, &fdb->flags) &&\n\t    !test_bit(BR_FDB_ADDED_BY_USER", "true &&\n\t    !test_bit(BR_FDB_ADDED_BY_USER"),
    }
    if args.mutants:
        for name, (before, after) in changes.items():
            assert source.count(before) == 1, (name, source.count(before))
            variants[name] = source.replace(before, after, 1)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
    with tempfile.TemporaryDirectory(prefix="l2-fdb-authority-") as directory:
        work = Path(directory)
        for name, body in variants.items():
            cfile = work / (name + ".c")
            binary = work / name
            cfile.write_text(STUBS + body + TESTS)
            subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g", "-O1", "-fsanitize=address,undefined", "-fno-pie", "-no-pie", str(cfile), "-o", str(binary)], check=True)
            result = subprocess.run([str(binary)], env=env, text=True, capture_output=True)
            if name == "production":
                assert result.returncode == 0, result.stdout + result.stderr
                print(result.stdout.strip())
            else:
                assert result.returncode != 0, f"mutant survived: {name}"
                assert "Assertion" in result.stderr, result.stderr
        if args.mutants:
            print(f"Native FDB authority: {len(changes)} compilable semantic mutants rejected")


if __name__ == "__main__":
    main()
