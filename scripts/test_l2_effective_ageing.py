#!/usr/bin/env python3
"""Execute the native bridge effective-age API and guarded STP writers.

Bodies are extracted verbatim from patch 234. --kernel additionally verifies
the same functions in an applied locked Linux tree, plus hold_time()/zero-age
semantics in its real bridge FDB implementation. The C fixture supplies only
kernel locking, timers and the policy gate; it does not replace the decisions.
"""
import argparse
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "port/overlay/target/linux/rtl9617c/patches-6.18/234-native-bridge-effective-ageing.patch"
NAMES = ("br_rtl9617c_fdb_hold_time", "__br_set_topology_change",
         "br_become_root_bridge", "br_record_config_timeout_values",
         "__br_set_forward_delay", "br_set_forward_delay")


def postimage(text):
    return "\n".join(line[1:] for line in text.splitlines()
                     if line.startswith((" ", "+")) and not line.startswith("+++")) + "\n"


def function(text, name):
    match = re.search(r"^(?:static\s+)?(?:int|long|void)\s+" + name + r"\(", text, re.M)
    if not match:
        raise AssertionError(f"missing production function {name}")
    brace = text.index("\n{", match.start()) + 1
    depth = 0
    for index in range(brace, len(text)):
        depth += (text[index] == "{") - (text[index] == "}")
        if not depth:
            return text[match.start():index + 1] + "\n"
    raise AssertionError(f"unterminated production function {name}")


STUBS = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#define HZ 250UL
#define USER_HZ 100UL
#define IFF_UP 1U
#define BR_NO_STP 0U
#define BR_KERNEL_STP 1U
#define BR_USER_STP 2U
#define BR_MIN_FORWARD_DELAY (2*HZ)
#define BR_MAX_FORWARD_DELAY (30*HZ)
#define READ_ONCE(x) (x)
#define ASSERT_RTNL() assert(rtnl_held)
struct net_bridge;
struct net_device {unsigned int flags;bool master;struct net_bridge *br;};
struct net_bridge {
 struct net_device *dev;unsigned int stp_enabled;bool root;unsigned char topology_change;
 unsigned long max_age,hello_time,forward_delay,bridge_max_age,bridge_hello_time;
 unsigned long bridge_forward_delay,ageing_time,bridge_ageing_time;
 int tcn_timer,hello_timer,lock;
};
struct br_config_bpdu {unsigned long max_age,hello_time,forward_delay;unsigned char topology_change;};
static struct net_device device;
static struct net_bridge bridge;
static bool rtnl_held,hardware_open;
static unsigned int begins,ends,depth,observations,age_updates,cases;
static unsigned long expected_forward,expected_age,jiffies=99;
static unsigned char expected_topology;
static int age_error;
static bool netif_is_bridge_master(const struct net_device *dev){return dev->master;}
static struct net_bridge *netdev_priv(const struct net_device *dev){return dev->br;}
static bool br_is_root_bridge(const struct net_bridge *br){return br->root;}
static unsigned long clock_t_to_jiffies(unsigned long value){return value*HZ/USER_HZ;}
static unsigned long jiffies_to_clock_t(unsigned long value){return value*USER_HZ/HZ;}
static void lock_bridge(int *lock){assert(lock==&bridge.lock && !*lock);*lock=1;}
static void unlock_bridge(int *lock){assert(lock==&bridge.lock && *lock && !depth);*lock=0;}
#define spin_lock_bh(lock) lock_bridge(lock)
#define spin_unlock_bh(lock) unlock_bridge(lock)
struct policy_scope {bool active;};
static struct policy_scope policy_begin(struct net_device *dev){
 if(!dev)return (struct policy_scope){0};
 assert(dev==&device && bridge.lock);
 if(!depth){
  /* Closing after a field mutation is too late, even if the final state
   * happens to be closed. Observe the exact pre-publication values. */
  assert(bridge.forward_delay==expected_forward && bridge.ageing_time==expected_age);
  assert(bridge.topology_change==expected_topology);
 }
 hardware_open=false;begins++;depth++;return (struct policy_scope){true};
}
static void policy_end(struct policy_scope *scope){
 if(!scope->active)return;
 assert(bridge.lock && depth && !hardware_open);depth--;ends++;
}
#define CLASS(name,var) struct policy_scope var __attribute__((cleanup(policy_end))) = policy_begin
#define br_debug(...) do{}while(0)
#define br_warn(...) do{}while(0)
static int __set_ageing_time(struct net_device *dev,unsigned long value){
 assert(dev==&device && bridge.lock && depth && !hardware_open);(void)value;age_updates++;
 return age_error;
}
void __br_set_topology_change(struct net_bridge *br,unsigned char val);
static void br_topology_change_detection(struct net_bridge *br){
 assert(br==&bridge && bridge.lock);__br_set_topology_change(br,br->topology_change);
}
static void timer_delete(int *timer){assert(timer==&bridge.tcn_timer && bridge.lock);observations++;}
static void br_config_bpdu_generation(struct net_bridge *br){assert(br==&bridge && bridge.lock);observations++;}
static void mod_timer(int *timer,unsigned long expiry){assert(timer==&bridge.hello_timer && bridge.lock && expiry==jiffies+bridge.hello_time);observations++;}
'''


TEST = r'''
static void setup(bool topology){
 bridge=(struct net_bridge){.dev=&device,.root=true,.stp_enabled=BR_KERNEL_STP,
  .forward_delay=15*HZ,.bridge_forward_delay=15*HZ,.ageing_time=300*HZ,
  .bridge_ageing_time=300*HZ,.topology_change=topology,.hello_time=2*HZ,
  .bridge_hello_time=2*HZ,.bridge_max_age=20*HZ};
 device=(struct net_device){.br=&bridge,.master=true,.flags=IFF_UP};
 rtnl_held=hardware_open=true;begins=ends=depth=observations=age_updates=0;age_error=0;
 expected_forward=bridge.forward_delay;expected_age=bridge.ageing_time;
 expected_topology=bridge.topology_change;
}
static void before(void){
 expected_forward=bridge.forward_delay;expected_age=bridge.ageing_time;
 expected_topology=bridge.topology_change;begins=ends=depth=0;hardware_open=true;
}
static void expect_scope(unsigned int count){assert(!depth && begins==count && ends==count);assert(hardware_open==!count);cases++;}
static void hold_time(void){
 unsigned long output=123;
 setup(false);device.master=false;
 assert(br_rtl9617c_fdb_hold_time(&device,&output)==-EINVAL && output==123);
 device.master=true;assert(br_rtl9617c_fdb_hold_time(&device,NULL)==-EINVAL);
 const unsigned long values[]={0,1,HZ-1,HZ,15*HZ,300*HZ,ULONG_MAX};
 for(unsigned int topo=0;topo<2;topo++)for(unsigned int a=0;a<7;a++)for(unsigned int f=0;f<7;f++){
  bridge.topology_change=topo;bridge.ageing_time=values[a];bridge.forward_delay=values[f];
  assert(!br_rtl9617c_fdb_hold_time(&device,&output));
  assert(output==(topo?values[f]:values[a]));cases++;
 }
 /* Positive raw jiffies must not become special no-learning zero after
  * USER_HZ rounding (the driver separately rejects non-whole seconds). */
 bridge.topology_change=false;bridge.ageing_time=1;
 assert(jiffies_to_clock_t(bridge.ageing_time)==0);
 assert(!br_rtl9617c_fdb_hold_time(&device,&output) && output==1);
 assert(!begins && !ends && hardware_open);
}
static void timeout_values(void){
 unsigned long output;
 for(unsigned int topo=0;topo<2;topo++)for(unsigned int changed=0;changed<2;changed++){
  setup(topo);struct br_config_bpdu bpdu={.forward_delay=(changed?7:15)*HZ,.topology_change=topo,.max_age=20*HZ,.hello_time=2*HZ};
  lock_bridge(&bridge.lock);br_record_config_timeout_values(&bridge,&bpdu);unlock_bridge(&bridge.lock);
  expect_scope(changed);assert(bridge.forward_delay==bpdu.forward_delay && !age_updates);
  assert(!br_rtl9617c_fdb_hold_time(&device,&output));assert(output==(topo?bpdu.forward_delay:300*HZ));
 }
 for(unsigned int failure=0;failure<2;failure++){
  setup(false);age_error=failure?-EIO:0;
  struct br_config_bpdu bpdu={.forward_delay=7*HZ,.topology_change=true};
  lock_bridge(&bridge.lock);br_record_config_timeout_values(&bridge,&bpdu);unlock_bridge(&bridge.lock);
  expect_scope(2);assert(age_updates==1 && bridge.topology_change);
  assert(bridge.ageing_time==(failure?300*HZ:14*HZ));
  assert(!br_rtl9617c_fdb_hold_time(&device,&output) && output==7*HZ);
 }
 /* Repeated TCN=true with a new root's delay still changes the effective
  * FDB lifetime: the topology-change setter itself is a no-op here. */
 setup(true);bridge.ageing_time=30*HZ;before();
 struct br_config_bpdu bpdu={.forward_delay=4*HZ,.topology_change=true};
 lock_bridge(&bridge.lock);br_record_config_timeout_values(&bridge,&bpdu);unlock_bridge(&bridge.lock);
 expect_scope(1);assert(bridge.ageing_time==30*HZ && !age_updates);
 assert(!br_rtl9617c_fdb_hold_time(&device,&output) && output==4*HZ);
}
static void root_and_setter(void){
 unsigned long output;
 for(unsigned int topo=0;topo<2;topo++)for(unsigned int changed=0;changed<2;changed++){
  setup(topo);bridge.bridge_forward_delay=(changed?4:15)*HZ;before();
  lock_bridge(&bridge.lock);br_become_root_bridge(&bridge);unlock_bridge(&bridge.lock);
  expect_scope(changed);assert(bridge.forward_delay==bridge.bridge_forward_delay && observations==3);
  assert(!br_rtl9617c_fdb_hold_time(&device,&output));assert(output==(topo?bridge.forward_delay:300*HZ));
 }
 for(unsigned int root=0;root<2;root++)for(unsigned int changed=0;changed<2;changed++){
  setup(true);bridge.root=root;unsigned long value=(changed?4:15)*HZ;before();
  lock_bridge(&bridge.lock);__br_set_forward_delay(&bridge,value);unlock_bridge(&bridge.lock);
  expect_scope(root && changed);assert(bridge.bridge_forward_delay==value);
  assert(bridge.forward_delay==(root?value:15*HZ));
 }
 setup(true);assert(br_set_forward_delay(&bridge,USER_HZ)==-ERANGE);
 expect_scope(0);assert(bridge.forward_delay==15*HZ && bridge.bridge_forward_delay==15*HZ);
 setup(true);assert(!br_set_forward_delay(&bridge,4*USER_HZ));
 expect_scope(1);assert(bridge.forward_delay==4*HZ);
 setup(false);bridge.stp_enabled=BR_NO_STP;assert(!br_set_forward_delay(&bridge,0));
 expect_scope(1);assert(!bridge.forward_delay);
 setup(true);bridge.stp_enabled=BR_USER_STP;
 lock_bridge(&bridge.lock);__br_set_topology_change(&bridge,false);unlock_bridge(&bridge.lock);
 expect_scope(1);assert(!age_updates && !bridge.topology_change);
 assert(!br_rtl9617c_fdb_hold_time(&device,&output) && output==300*HZ);
}
int main(void){hold_time();timeout_values();root_and_setter();
 printf("Native bridge effective ageing: %u raw-jiffy/STP/zero/guard/noop/error cases; HZ!=USER_HZ; host contract only\n",cases);return 0;}
'''


def once(text, old, new):
    if text.count(old) != 1:
        raise AssertionError(f"mutation anchor drift: {old}")
    return text.replace(old, new, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path)
    args = parser.parse_args()
    bodies = {name: function(postimage(PATCH.read_text()), name) for name in NAMES}
    if args.kernel:
        stp = (args.kernel / "net/bridge/br_stp.c").read_text()
        for name, body in bodies.items():
            if body != function(stp, name):
                raise AssertionError(f"applied kernel mismatch: {name}")
        fdb = (args.kernel / "net/bridge/br_fdb.c").read_text()
        assert "return br->topology_change ? br->forward_delay : br->ageing_time;" in fdb
        assert "if (hold_time(br) == 0)\n\t\treturn;" in fdb
        print("Applied locked Linux STP functions and actual FDB zero-age semantics match")
    source = "\n".join(bodies.values())
    mutants = {
        "generic_age_ignores_topology": once(source,
            "READ_ONCE(br->topology_change) ?", "false ?"),
        "jiffy_hold_time_rounded": once(source,
            "\treturn 0;\n", "\t*ticks = jiffies_to_clock_t(*ticks);\n\treturn 0;\n"),
    }
    for name in ("br_become_root_bridge", "br_record_config_timeout_values", "__br_set_forward_delay"):
        body = bodies[name]
        guard = re.search(r"\tCLASS\(rtl9617c_switch_policy, policy\)\n\t\t.*?;\n\n", body).group()
        mutants["unguarded_" + name] = once(source, body, once(body, guard, ""))
    body = bodies["__br_set_forward_delay"]
    guard = re.search(r"\tCLASS\(rtl9617c_switch_policy, policy\)\n\t\t.*?;\n\n", body).group()
    late = once(body, guard, "").replace("\t\tbr->forward_delay = br->bridge_forward_delay;\n",
        "\t\tbr->forward_delay = br->bridge_forward_delay;\n" + guard)
    mutants["forward_delay_guard_after_write"] = once(source, body, late)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = dict(os.environ)
    env.setdefault("ASAN_OPTIONS", "detect_leaks=0")
    with tempfile.TemporaryDirectory(prefix="l2-effective-age-") as directory:
        directory = Path(directory)
        for name, code in {"production": source, **mutants}.items():
            cfile, binary = directory / "test.c", directory / "test"
            cfile.write_text(STUBS + code + TEST)
            subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                            "-Wno-unused-function", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                            str(cfile), "-o", str(binary)], check=True)
            result = subprocess.run([str(binary)], env=env, capture_output=True, text=True)
            if name == "production":
                if result.returncode:
                    raise SystemExit(result.stdout + result.stderr)
                print(result.stdout.strip())
            else:
                if result.returncode != -6 or "Assertion" not in result.stderr:
                    raise SystemExit(f"mutation {name} did not fail a runtime assertion: {result}")
                print("Rejected mutation:", name)


if __name__ == "__main__":
    main()
