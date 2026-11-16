#!/usr/bin/env python3
"""Execute the production read-only CPU-FDB preflight and VID/owner exclusions.

The linked FDB list and RCU lock are fixture dependencies; the actual helper
is extracted from patch 240. No hardware support is inferred by these tests.
"""
import argparse
import os
from pathlib import Path
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "port/overlay/target/linux/rtl9617c/patches-6.18/240-native-fdb-preflight.patch"

STUBS = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint16_t u16;
#define VLAN_VID_MASK 4095
#define BIT(n) (1UL << (n))
#define READ_ONCE(x) (x)
#define ASSERT_RTNL() assert(rtnl_held)
#define EXPORT_SYMBOL_GPL(name)
enum { BR_FDB_LOCAL, BR_FDB_ADDED_BY_USER, BR_FDB_ADDED_BY_EXT_LEARN,
 BR_FDB_STATIC, BR_FDB_OFFLOADED, BR_FDB_LOCKED, BR_FDB_STICKY };
struct net_bridge_port { unsigned int port; };
struct net_bridge_fdb_entry {
 struct {u16 vlan_id;} key;
 unsigned long flags, updated;
 struct net_bridge_port *dst;
 struct net_bridge_fdb_entry *next;
};
struct net_bridge {struct net_bridge_fdb_entry *fdb_list;};
struct net_device {bool bridge;struct net_bridge *priv;};
static bool rtnl_held=true;
static unsigned int readers,notifies,cases;
static void rcu_read_lock(void){readers++;}
static void rcu_read_unlock(void){assert(readers);readers--;}
static bool test_bit(unsigned int bit,const unsigned long *value){return !!(*value&BIT(bit));}
static bool netif_is_bridge_master(const struct net_device *dev){return dev->bridge;}
static struct net_bridge *netdev_priv(const struct net_device *dev){return dev->priv;}
#define hlist_for_each_entry_rcu(entry,head,member) \
 for((entry)=*(head);(entry);(entry)=(entry)->next)
static bool br_switchdev_fdb_notifies(const struct net_bridge_fdb_entry *fdb){
 assert(readers);notifies++;
 return !(fdb->flags&BIT(BR_FDB_LOCKED)) &&
  (!(fdb->flags&BIT(BR_FDB_ADDED_BY_USER)) ||
   (fdb->flags&(BIT(BR_FDB_STATIC)|BIT(BR_FDB_ADDED_BY_EXT_LEARN))));
}
'''

TESTS = r'''
int main(void){
 struct net_bridge_port port={.port=1};
 struct net_bridge_fdb_entry rows[8]={0},saved[8];
 struct net_bridge bridge={.fdb_list=rows};
 struct net_device master={.bridge=true,.priv=&bridge},foreign={.priv=&bridge};
 unsigned int count=91;
 assert(br_rtl9617c_fdb_cpu_count(NULL,0,&count)==-EINVAL && count==91);
 assert(br_rtl9617c_fdb_cpu_count(&foreign,0,&count)==-EINVAL && count==91);
 assert(br_rtl9617c_fdb_cpu_count(&master,4095,&count)==-EINVAL && count==91);
 assert(br_rtl9617c_fdb_cpu_count(&master,0,NULL)==-EINVAL);cases+=4;
 for(unsigned int i=0;i<8;i++){rows[i].dst=&port;rows[i].next=i<7?&rows[i+1]:NULL;}
 assert(!br_rtl9617c_fdb_cpu_count(&master,0,&count) && count==8);cases++;
 /* LOCAL/USER/EXT/LOCKED entries are not CPU-owned dynamic replay rows.
  * The OFFLOADED bit by itself does not confer external ownership. */
 rows[0].flags=BIT(BR_FDB_LOCAL);rows[1].flags=BIT(BR_FDB_ADDED_BY_USER)|BIT(BR_FDB_STATIC)|BIT(BR_FDB_STICKY);
 rows[2].flags=BIT(BR_FDB_ADDED_BY_EXT_LEARN);rows[3].flags=BIT(BR_FDB_LOCKED);
 rows[4].dst=NULL;rows[5].key.vlan_id=23;rows[6].flags=BIT(BR_FDB_OFFLOADED);
 memcpy(saved,rows,sizeof(rows));
 assert(!br_rtl9617c_fdb_cpu_count(&master,0,&count) && count==2);
 assert(!br_rtl9617c_fdb_cpu_count(&master,23,&count) && count==1);
 assert(!br_rtl9617c_fdb_cpu_count(&master,24,&count) && !count);
 assert(!memcmp(saved,rows,sizeof(rows)) && !readers && notifies);cases+=4;
 /* Expiry is bridge GC's decision. No timestamp is refreshed or row
  * withdrawn by preflight; a still-present row remains authoritative. */
 rows[7].updated=0;rows[7].flags=BIT(BR_FDB_STICKY);
 assert(!br_rtl9617c_fdb_cpu_count(&master,0,&count) && count==2 && !rows[7].updated);cases++;
 bridge.fdb_list=NULL;
 assert(!br_rtl9617c_fdb_cpu_count(&master,0,&count) && !count && !readers);cases++;
 printf("CPU FDB production preflight: %u read-only/VID/authority cases PASS\n",cases);
 return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path)
    args = parser.parse_args()
    source = "\n".join(line[1:] for line in PATCH.read_text().splitlines()
                       if line.startswith("+") and not line.startswith("+++"))
    if args.kernel:
        assert source.strip() in (args.kernel / "net/bridge/br_switchdev.c").read_text()
    variants = {"production": source}
    mutations = {
        "vid_ignored": ("fdb->key.vlan_id != vid ||", "false ||"),
        "local_counted": ("test_bit(BR_FDB_LOCAL, &fdb->flags) ||", "false ||"),
        "user_counted": ("test_bit(BR_FDB_ADDED_BY_USER, &fdb->flags) ||", "false ||"),
        "external_counted": ("test_bit(BR_FDB_ADDED_BY_EXT_LEARN, &fdb->flags) ||", "false ||"),
        "locked_counted": ("!br_switchdev_fdb_notifies(fdb) ||", "(br_switchdev_fdb_notifies(fdb), false) ||"),
        "missing_destination_counted": ("!READ_ONCE(fdb->dst))", "false)"),
        "offloaded_mistaken_for_external": ("!br_switchdev_fdb_notifies(fdb) ||", "test_bit(BR_FDB_OFFLOADED, &fdb->flags) || !br_switchdev_fdb_notifies(fdb) ||"),
    }
    for name, (before, after) in mutations.items():
        assert source.count(before) == 1, name
        variants[name] = source.replace(before, after, 1)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    environment = dict(os.environ)
    environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
    with tempfile.TemporaryDirectory(prefix="l2-fdb-preflight-") as directory:
        work = Path(directory)
        for name, body in variants.items():
            cfile = work / (name + ".c")
            binary = work / name
            cfile.write_text(STUBS + body + TESTS)
            subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                            "-g", "-O1", "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
                            str(cfile), "-o", str(binary)], check=True)
            result = subprocess.run([str(binary)], text=True, capture_output=True, env=environment)
            if name == "production":
                assert result.returncode == 0, result.stdout + result.stderr
                print(result.stdout.strip(), flush=True)
            else:
                assert result.returncode != 0 and "Assertion" in result.stderr, name + result.stderr
    print(f"CPU FDB preflight: {len(mutations)} compilable semantic mutants rejected")


if __name__ == "__main__":
    main()
