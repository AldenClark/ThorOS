#!/usr/bin/env python3
"""Execute prepared MTU/flags callsites and bridge-join entry scopes.

Actual dev.c functions are compiled unchanged against a counting guard and
driver/notifier backend. Full core guard concurrency/ownership is exercised
by test_l2_policy_races.py. Bridge tests execute the actual br_add_if entry
scopes, not its complete topology implementation. No ASIC claim is made.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--kernel", type=Path, required=True)
args = parser.parse_args()
dev = (args.kernel / "net/core/dev.c").read_text()
bridge = (args.kernel / "net/bridge/br_if.c").read_text()


def function(source, name):
    start = re.search(r"^[A-Za-z_][^\n]*\b" + name + r"\([^;]*?\)\s*\{", source, re.M).start()
    end = source.index("{", start) + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end] + "\n"


COMMON = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <linux/if.h>
struct net_device {unsigned int flags,gflags;int mtu,min_mtu,max_mtu;bool present,owned;};
struct net_bridge {struct net_device *dev;};
struct netlink_ext_ack {const char *_msg;};
static unsigned int gates,active,ends,pre_notifies,post_notifies,driver_calls,cases;
static int pre_error,driver_error,post_error;
static bool change_owner;
#define ASSERT_RTNL() ((void)0)
#define netdev_ops_assert_locked(dev) ((void)dev)
#define NL_SET_ERR_MSG(ack,msg) do {if(ack)(ack)->_msg=msg;}while(0)
static struct net_device *scope_begin(struct net_device *dev){if(!dev || !dev->owned)return NULL;gates++;active++;return dev;}
static void scope_end(struct net_device **dev){if(*dev){assert(active);active--;ends++;}}
#define CLASS(name,var) struct net_device *var __attribute__((cleanup(scope_end),unused))=scope_begin
static bool netif_device_present(struct net_device *dev){return dev->present;}
enum {NETDEV_PRECHANGEMTU,NETDEV_CHANGEMTU};
static int notifier_to_errno(int ret){return ret;}
static void assert_scope(const struct net_device *dev){assert(!dev->owned || active);}
static int call_netdevice_notifiers(int event,struct net_device *dev){assert(event==NETDEV_PRECHANGEMTU);assert_scope(dev);pre_notifies++;return pre_error;}
static int call_netdevice_notifiers_mtu(int event,struct net_device *dev,int old){
 assert(event==NETDEV_CHANGEMTU && old!=dev->mtu);assert_scope(dev);post_notifies++;return post_error;
}
static int __netif_set_mtu(struct net_device *dev,int mtu){
 assert_scope(dev);driver_calls++;if(driver_error)return driver_error;dev->mtu=mtu;return 0;
}
static void dev_change_rx_flags(struct net_device *dev,unsigned int flags){(void)flags;assert_scope(dev);}
static void dev_set_rx_mode(struct net_device *dev){(void)dev;}
static void __dev_close(struct net_device *dev){assert_scope(dev);dev->flags&=~IFF_UP;}
static int __dev_open(struct net_device *dev,struct netlink_ext_ack *extack){(void)extack;assert_scope(dev);dev->flags|=IFF_UP;return 0;}
static int __dev_set_promiscuity(struct net_device *dev,int inc,bool notify){
 (void)notify;assert_scope(dev);if(inc>0)dev->flags|=IFF_PROMISC;else dev->flags&=~IFF_PROMISC;return 0;
}
static void netif_set_allmulti(struct net_device *dev,int inc,bool notify){
 (void)notify;assert_scope(dev);if(inc>0)dev->flags|=IFF_ALLMULTI;else dev->flags&=~IFF_ALLMULTI;
}
static void __dev_notify_flags(struct net_device *dev,unsigned int old,unsigned int changed,unsigned int id,void *msg){
 (void)old;(void)id;(void)msg;if(changed)assert_scope(dev);
}
'''

TEST = r'''
static struct net_device fresh(void){
 gates=active=ends=pre_notifies=post_notifies=driver_calls=0;pre_error=driver_error=post_error=0;
 return (struct net_device){.flags=IFF_UP|IFF_MULTICAST|IFF_RUNNING|IFF_LOWER_UP,.mtu=1500,.min_mtu=68,.max_mtu=1500,.present=true,.owned=true};
}
static void mtu_cases(void){
 struct net_device dev=fresh();assert(!netif_set_mtu_ext(&dev,1500,NULL));assert(!gates && !pre_notifies && !driver_calls);cases++;
 const int invalid[]={-1,0,67,1501,65536};
 for(unsigned int i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++){
  dev=fresh();assert(netif_set_mtu_ext(&dev,invalid[i],NULL)==-EINVAL);assert(!gates && !pre_notifies && dev.mtu==1500);cases++;
 }
 dev=fresh();dev.present=false;assert(netif_set_mtu_ext(&dev,1400,NULL)==-ENODEV);assert(!gates && !pre_notifies);cases++;
 for(unsigned int error=0;error<4;error++){
  dev=fresh();if(error==1)pre_error=-EBUSY;if(error==2)driver_error=-EIO;if(error==3)post_error=-ERANGE;
  int ret=netif_set_mtu_ext(&dev,1400,NULL);assert((ret==0)==!error);
  assert(gates==1 && ends==1 && !active && dev.mtu==(error?1500:1400));
  assert(driver_calls==(error==1?0:error==3?2:1));cases++;
 }
 dev=fresh();dev.owned=false;assert(!netif_set_mtu_ext(&dev,1400,NULL));assert(!gates && driver_calls==1);cases++;
}
static void flag_cases(void){
 struct net_device dev=fresh();unsigned int requested=dev.flags;
 assert(!netif_change_flags(&dev,requested,NULL));assert(!gates);cases++;
 dev=fresh();requested=dev.flags^IFF_VOLATILE;
 assert(!netif_change_flags(&dev,requested,NULL));assert(!gates && dev.flags==(unsigned int)(IFF_UP|IFF_MULTICAST|IFF_RUNNING|IFF_LOWER_UP));cases++;
 const unsigned int modifiable=IFF_UP|IFF_DEBUG|IFF_NOTRAILERS|IFF_NOARP|IFF_DYNAMIC|IFF_MULTICAST|IFF_PORTSEL|IFF_AUTOMEDIA|IFF_PROMISC|IFF_ALLMULTI;
 for(unsigned int bit=0;bit<32;bit++){
  dev=fresh();requested=dev.flags^(1U<<bit);assert(!netif_change_flags(&dev,requested,NULL));
  assert((gates==1)==!!(modifiable&(1U<<bit)));assert(gates==ends && !active);cases++;
 }
 dev=fresh();dev.flags|=IFF_PROMISC;requested=dev.flags&~IFF_PROMISC;
 assert(!netif_change_flags(&dev,requested,NULL));assert(!gates && (dev.flags&IFF_PROMISC));cases++;
 dev=fresh();dev.flags|=IFF_PROMISC;dev.gflags=IFF_PROMISC;requested=dev.flags&~IFF_PROMISC;
 assert(!netif_change_flags(&dev,requested,NULL));assert(gates==1 && ends==1 && !(dev.flags&IFF_PROMISC));cases++;
 dev=fresh();dev.owned=false;assert(!netif_change_flags(&dev,dev.flags^IFF_UP,NULL));assert(!gates);cases++;
}
static void bridge_first_port(void){
 for(unsigned int type=0;type<3;type++){
  struct net_device port=fresh(),master=fresh();
  port.owned=type==0;master.owned=type==1;
  struct net_bridge bridge={.dev=&master};change_owner=port.owned||master.owned;
  join_scopes(&bridge,&port);
  assert((gates==1)==change_owner && gates==ends && !active);cases++;
 }
}
int main(void){mtu_cases();flag_cases();bridge_first_port();
 printf("Production policy callsites: %u no-op/invalid/real MTU, flags and first-port join scope cases PASS\n",cases);return 0;}
'''

functions = "\n".join(function(dev, name) for name in [
    "__dev_change_flags", "netif_change_flags", "dev_validate_mtu", "netif_set_mtu_ext",
])
entry = function(bridge, "br_add_if")
entry = entry[entry.index("{") + 1:entry.index("struct net_bridge_port *p;")]
assert "port_policy)(dev)" in entry and "policy)(br->dev)" in entry
functions += "static void join_scopes(struct net_bridge *br,struct net_device *dev){\n" + entry
functions += " assert(!change_owner || active); /* modeled topology publication */\n}\n"
mutations = {
    "noop_flags_close_gate": (re.search(r"CLASS\(rtl9617c_switch_policy, policy\)\(.*?dev : NULL\);", functions, re.S)[0],
                              "CLASS(rtl9617c_switch_policy, policy)(dev);"),
    "noop_mtu_close_gate": ("if (new_mtu == dev->mtu)", "if (new_mtu == dev->mtu && (scope_begin(dev), true))"),
    "first_managed_port_unguarded": ("CLASS(rtl9617c_switch_policy, port_policy)(dev);", "(void)dev;"),
}
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
environment = dict(os.environ)
environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
with tempfile.TemporaryDirectory(prefix="l2-policy-noop-") as directory:
    directory = Path(directory)
    for name in ["production", *mutations]:
        code = functions
        if name != "production":
            old, new = mutations[name]
            assert old in code, name
            code = code.replace(old, new, 1)
        (directory / "test.c").write_text(COMMON + code + TEST)
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                        str(directory / "test.c"), "-o", str(directory / "test")], check=True)
        result = subprocess.run([str(directory / "test")], env=environment, capture_output=True, text=True, timeout=30)
        if name == "production":
            assert result.returncode == 0, result.stdout + result.stderr
            print(result.stdout, end="")
        else:
            assert result.returncode != 0 and "Assertion" in result.stderr, (name, result.stderr)
            print(f"Runtime regression mutant rejected: {name}")
(ROOT / "artifacts").mkdir(exist_ok=True)
(ROOT / "artifacts/l2-policy-noop.json").write_text(json.dumps({
    "production_functions_sha256": hashlib.sha256(functions.encode()).hexdigest(),
    "mutations_rejected": list(mutations), "hardware_verified": False,
    "scope": "production dev.c MTU/flags and br_add_if entry scopes, modeled guard/driver/notifier; full gate concurrency in l2-policy-races",
}, indent=2) + "\n")
