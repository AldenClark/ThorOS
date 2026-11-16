#!/usr/bin/env python3
"""Execute patch 237's real receive dispatch against bridge detach races.

Only kernel container/RCU plumbing is modelled. The actual early-dispatch
statement is taken from the patch, not rewritten as a Python predicate.
The complete bridge and receive core are compiled by kernel object CI.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "port/overlay/target/linux/rtl9617c/patches-6.18/237-native-bum-copy-lifetime.patch"


def postimage(text, file):
    active = False
    out = []
    for line in text.splitlines():
        if line.startswith("+++ b/"):
            active = line[6:] == file
        elif line.startswith(("---", "@@")):
            continue
        elif active and line.startswith(("+", " ")):
            out.append(line[1:])
    return "\n".join(out)


def block(text):
    start = text.index("\tif (rtl9617c_mcast_copy_present(skb)) {")
    pos = text.index("{", start) + 1
    depth = 1
    while depth:
        depth += (text[pos] == "{") - (text[pos] == "}")
        pos += 1
    return text[start:pos]


SHIM = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
struct sk_buff;
typedef int rx_handler_func_t(struct sk_buff **);
struct net_device {rx_handler_func_t *rx_handler;struct net_device *master;unsigned identity;};
struct sk_buff {struct net_device *dev;bool copy,freed,local_delivered;};
enum {RX_HANDLER_CONSUMED, RX_HANDLER_ANOTHER, RX_HANDLER_EXACT, RX_HANDLER_PASS};
enum {NET_RX_SUCCESS, NET_RX_DROP};
static struct {unsigned processed;} softnet_data;
static struct net_device master,port;
static unsigned bridge_calls,ordinary_calls,drops;
static bool epoch_valid,detach_after_validation,detach_during_bridge;
static int handler_result;
#define __this_cpu_inc(x) ((x)++)
#define rcu_dereference(p) (p)
static bool rtl9617c_mcast_copy_present(struct sk_buff *skb){return skb->copy;}
static struct net_device *netdev_master_upper_dev_get_rcu(struct net_device *dev){return dev->master;}
static bool rtl9617c_mcast_copy_valid(struct sk_buff *skb,struct net_device *dev,struct net_device *br) {
 bool valid=skb->copy&&dev==&port&&br==&master&&epoch_valid&&dev->identity==17;
 if(detach_after_validation) {
  /* policy BEGIN revokes, then unlink clears the live handler/master.
   * The already captured handler function remains callable under RCU. */
  detach_after_validation=false;epoch_valid=false;port.rx_handler=NULL;port.master=NULL;
 }
 return valid;
}
static int bridge_handler(struct sk_buff **packet) {
 struct sk_buff *skb=*packet;bridge_calls++;
 if(detach_during_bridge) {epoch_valid=false;port.master=NULL;}
 /* Model only the bridge's independently tested entry/finish epoch gate. */
 if(!rtl9617c_mcast_copy_valid(skb,skb->dev,skb->dev->master)) {
  skb->freed=true;return RX_HANDLER_CONSUMED;
 }
 if(handler_result==RX_HANDLER_CONSUMED) {skb->copy=false;skb->local_delivered=true;}
 return handler_result;
}
static int receive(struct sk_buff *packet) {
 struct sk_buff *skb=packet;rx_handler_func_t *rx_handler;int ret=NET_RX_DROP;
 ACTUAL_DISPATCH
 ordinary_calls++;return NET_RX_SUCCESS;
drop:
 drops++;skb->freed=true;ret=NET_RX_DROP;
out:
 return ret;
}
enum {BR_FDB_LOCAL};
struct fdb {unsigned long flags;};
static unsigned local_calls,software_forwarding;
static bool last_promisc;
#define test_bit(n,p) (!!(*(p)&(1UL<<(n))))
static int br_pass_frame_up(struct sk_buff *skb,bool promisc) {
 assert(skb->copy);local_calls++;last_promisc=promisc;return 71;
}
static int finish(struct sk_buff *skb,struct fdb *dst,bool local_rcv,bool promisc) {
 ACTUAL_NO_REFLOOD
 software_forwarding++;return 99;
drop:
 skb->freed=true;return 0;
}
static void setup(void) {
 master=(struct net_device){.identity=31};port=(struct net_device){.rx_handler=bridge_handler,.master=&master,.identity=17};
 bridge_calls=ordinary_calls=drops=softnet_data.processed=0;
 epoch_valid=true;detach_after_validation=detach_during_bridge=false;handler_result=RX_HANDLER_CONSUMED;
}
int main(void) {
 unsigned cases=0;struct sk_buff skb;
 setup();skb=(struct sk_buff){.dev=&port,.copy=false};assert(receive(&skb)==NET_RX_SUCCESS);
 assert(ordinary_calls==1&&!bridge_calls&&!drops);cases++;
 setup();skb=(struct sk_buff){.dev=&port,.copy=true};assert(receive(&skb)==NET_RX_SUCCESS);
 assert(!ordinary_calls&&bridge_calls==1&&skb.local_delivered&&!skb.copy&&softnet_data.processed==1);cases++;
 setup();skb=(struct sk_buff){.dev=&port,.copy=true};port.rx_handler=NULL;
 assert(receive(&skb)==NET_RX_DROP&&drops==1&&!ordinary_calls&&!bridge_calls);cases++;
 setup();skb=(struct sk_buff){.dev=&port,.copy=true};port.master=NULL;
 assert(receive(&skb)==NET_RX_DROP&&!ordinary_calls&&!bridge_calls);cases++;
 setup();skb=(struct sk_buff){.dev=&port,.copy=true};epoch_valid=false;
 assert(receive(&skb)==NET_RX_DROP&&!ordinary_calls&&!bridge_calls);cases++;
 setup();skb=(struct sk_buff){.dev=&port,.copy=true};port.identity=18;
 assert(receive(&skb)==NET_RX_DROP&&!ordinary_calls&&!bridge_calls);cases++;
 for(unsigned when=0;when<2;when++) {
  setup();skb=(struct sk_buff){.dev=&port,.copy=true};
  if(when)detach_during_bridge=true;else detach_after_validation=true;
  assert(receive(&skb)==NET_RX_SUCCESS&&bridge_calls==1&&skb.freed&&!skb.local_delivered&&!ordinary_calls);cases++;
 }
 for(unsigned result=RX_HANDLER_ANOTHER;result<=RX_HANDLER_PASS;result++) {
  setup();skb=(struct sk_buff){.dev=&port,.copy=true};handler_result=result;
  assert(receive(&skb)==NET_RX_DROP&&bridge_calls==1&&skb.freed&&!ordinary_calls&&!skb.local_delivered);cases++;
 }
 for(unsigned type=0;type<3;type++)for(unsigned local=0;local<2;local++)for(unsigned promisc=0;promisc<2;promisc++) {
  struct fdb dst={.flags=type==2?1:0};struct fdb *entry=type?&dst:NULL;
  skb=(struct sk_buff){.dev=&port,.copy=true};local_calls=software_forwarding=0;last_promisc=false;
  int result=finish(&skb,entry,local,promisc);
  if(type==2||local) {
   assert(result==71&&local_calls==1&&last_promisc==(type==2?false:!!promisc));
  } else assert(result==0&&skb.freed&&!local_calls);
  assert(!software_forwarding);cases++;
 }
 printf("MCE production net/core dispatch: %u missing-handler, captured-handler, detach, epoch and terminal-result cases passed\n",cases);
}
'''


def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run(dispatch, no_reflood):
    with tempfile.TemporaryDirectory(prefix="mcast-dispatch-") as directory:
        work = Path(directory)
        (work / "test.c").write_text(SHIM.replace("ACTUAL_DISPATCH", dispatch).replace("ACTUAL_NO_REFLOOD", no_reflood))
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        "-g", "-O1", "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
                        str(work / "test.c"), "-o", str(work / "test")], check=True)
        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "detect_leaks=0"
        return subprocess.run([str(work / "test")], capture_output=True, text=True,
                              env=env, preexec_fn=no_core)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path)
    args = parser.parse_args()
    actual = block(postimage(PATCH.read_text(), "net/core/dev.c"))
    bridge = postimage(PATCH.read_text(), "net/bridge/br_input.c")
    no_reflood = block(bridge[bridge.index("\t/* Hardware emitted"):])
    if args.kernel:
        if block((args.kernel / "net/core/dev.c").read_text()) != actual:
            raise AssertionError("full applied kernel dispatch differs from patch oracle")
    result = run(actual, no_reflood)
    if result.returncode:
        raise SystemExit(result.stdout + result.stderr)
    print(result.stdout, end="")
    for old, new in [("!rx_handler ||", "0 ||"),
                     ("!= RX_HANDLER_CONSUMED", "== -100")]:
        # Only meaningful mutations are kept: removing the handler guard
        # must crash/fail closed tests; accepting PASS must fail a terminal
        # result assertion. Epoch mutants run in the complete core test.
        changed = run(actual.replace(old, new), no_reflood)
        if not changed.returncode:
            raise AssertionError("mutation survived: " + old)
    (ROOT / "artifacts").mkdir(exist_ok=True)
    (ROOT / "artifacts/mcast-dispatch.json").write_text(json.dumps({
        "patch_sha256": hashlib.sha256(PATCH.read_bytes()).hexdigest(),
        "dispatch_cases": 11, "bridge_no_reflood_cases": 12, "hardware_verified": False,
        "full_kernel_dispatch_verified": bool(args.kernel)}, indent=2) + "\n")


if __name__ == "__main__":
    main()
