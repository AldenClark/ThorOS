#!/usr/bin/env python3
"""Execute the production static-FDB publication and cleanup kernel API.

New API bodies and modified generic feedback are extracted from patch 232;
the generation gate is compiled verbatim from net/core/rtl9617c-switch.c.
--kernel verifies the same functions in an already patched Linux source tree.
The fixture supplies Linux container/locking plumbing, not offload decisions.
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
OVERLAY = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18"
PATCH = ROOT / "port/overlay/target/linux/rtl9617c/patches-6.18/232-native-static-fdb-feedback.patch"
GATE = OVERLAY / "net/core/rtl9617c-switch.c"
PUBLIC = OVERLAY / "include/linux/rtl9617c-switch.h"
NAMES = (
    "br_rtl9617c_fdb_owner_clear", "br_rtl9617c_fdb_owner_invalidate",
    "br_rtl9617c_fdb_offload_publish", "br_rtl9617c_fdb_offload",
    "br_rtl9617c_fdb_unoffload", "br_fdb_offloaded_set", "br_fdb_clear_offload",
)


def postimage(patch: str, path: str) -> str:
    active = False
    lines = []
    for line in patch.splitlines():
        if line.startswith("+++ b/"):
            active = line[6:] == path
        elif line.startswith("--- ") or line.startswith("@@"):
            continue
        elif active and line.startswith(("+", " ")):
            lines.append(line[1:])
    return "\n".join(lines) + "\n"


def function(source: str, name: str) -> str:
    match = re.search(r"^(?:static\s+)?(?:inline\s+)?(?:bool|int|void)\s+" + name + r"\(", source, re.M)
    if not match:
        raise AssertionError(f"missing production function: {name}")
    start = source.index("\n{", match.start()) + 1
    depth = 0
    for pos in range(start, len(source)):
        depth += (source[pos] == "{") - (source[pos] == "}")
        if not depth:
            return source[match.start():pos + 1] + "\n"
    raise AssertionError(f"unterminated production function: {name}")


def struct(source: str, name: str) -> str:
    start = source.index("struct " + name + " {")
    end = source.index("\n};", start) + 3
    return source[start:end] + "\n"


HEADERS = {
    "linux/types.h": "#pragma once\n#include <stdint.h>\n#include <stdbool.h>\ntypedef uint64_t u64;\ntypedef uint16_t u16;\ntypedef int64_t s64;\n",
    "linux/kconfig.h": "#pragma once\n#define CONFIG_BRIDGE 1\n#define CONFIG_NET_SWITCHDEV 1\n#define CONFIG_RTL9617C_SWITCH_GUARD 1\n#define IS_ENABLED(x) (x)\n#define IS_REACHABLE(x) (x)\n",
    "linux/list.h": "#pragma once\nstruct list_head { struct list_head *next, *prev; };\n",
    "linux/cleanup.h": "#pragma once\n#define DEFINE_CLASS(...)\n",
}

STUBS = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/rtl9617c-switch.h>
#define BIT(n) (1UL << (n))
#define S64_MAX INT64_MAX
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define ETH_ALEN 6
#define VLAN_VID_MASK 4095
#define RTM_NEWNEIGH 28
#define EXPORT_SYMBOL_GPL(name)
enum { BR_FDB_LOCAL, BR_FDB_STATIC, BR_FDB_STICKY, BR_FDB_LOCKED,
       BR_FDB_OFFLOADED, BR_FDB_ADDED_BY_USER, BR_FDB_ADDED_BY_EXT_LEARN };
struct net { struct rtl9617c_switch_net rtl9617c_switch; };
struct net_bridge;
struct net_bridge_port;
struct net_device { struct net *net; struct net_bridge *br; struct net_bridge_port *port; bool master; };
struct net_bridge_port { struct net_bridge *br; struct net_device *dev; };
struct net_bridge_fdb_entry {
 struct net_bridge_port *dst;
 struct { struct { unsigned char addr[ETH_ALEN]; } addr; u16 vlan_id; } key;
 unsigned long flags, updated, used;
 OWNER_FIELDS
};
struct test_fdb_list { struct net_bridge_fdb_entry *rows[8]; unsigned int count; };
struct net_bridge { int hash_lock; struct test_fdb_list fdb_list; struct net_device *dev; };
static int hash_depth, gate_depth, rtl9617c_switch_lock;
static bool rtnl_held, driver_mutex_held, invalidate_at_gate;
static struct net *gate_net;
static unsigned int notifications, finds, cases;
static unsigned long jiffies = 19;
static void lock_hash(int *lock) { assert(rtnl_held && !hash_depth && !gate_depth && !*lock); *lock = 1; hash_depth++; }
static void unlock_hash(int *lock) { assert(*lock && hash_depth == 1 && !gate_depth); hash_depth--; *lock = 0; }
#define spin_lock_bh(lock) lock_hash(lock)
#define spin_unlock_bh(lock) unlock_hash(lock)
#define spin_lock_irqsave(lock, flags) do { \
 (void)(lock); (flags)=0; assert(hash_depth == 1 && !gate_depth); gate_depth++; \
 if (invalidate_at_gate) { gate_net->rtl9617c_switch.generation++; invalidate_at_gate=false; } \
} while (0)
#define spin_unlock_irqrestore(lock, flags) do { \
 (void)(lock); (void)(flags); assert(hash_depth == 1 && gate_depth == 1); gate_depth--; \
} while (0)
#define ASSERT_RTNL() assert(rtnl_held)
static bool test_bit(unsigned int n, const unsigned long *flags) { return !!(*flags & BIT(n)); }
static bool test_and_set_bit(unsigned int n, unsigned long *flags) { bool old = test_bit(n, flags); *flags |= BIT(n); return old; }
static bool test_and_clear_bit(unsigned int n, unsigned long *flags) { bool old = test_bit(n, flags); *flags &= ~BIT(n); return old; }
static void change_bit(unsigned int n, unsigned long *flags) { *flags ^= BIT(n); }
static void clear_bit(unsigned int n, unsigned long *flags) { *flags &= ~BIT(n); }
typedef struct { s64 value; } atomic64_t;
#define ATOMIC64_INIT(n) { (n) }
static s64 atomic64_fetch_add_unless(atomic64_t *counter, s64 value, s64 limit) {
 s64 old=counter->value; assert(hash_depth == 1 && gate_depth == 1);
 if (old != limit) counter->value += value;
 return old;
}
static bool netif_is_bridge_master(const struct net_device *dev) { return dev->master; }
static struct net *dev_net(const struct net_device *dev) { return dev->net; }
static struct net_bridge *netdev_priv(const struct net_device *dev) { return dev->br; }
static struct net_bridge_port *br_port_get_rtnl(const struct net_device *dev) { assert(rtnl_held); return dev->port; }
static bool is_valid_ether_addr(const unsigned char *addr) {
 unsigned int any=0; for(unsigned int i=0; i<6; i++) any |= addr[i]; return any && !(addr[0]&1);
}
static struct net_bridge_fdb_entry *br_fdb_find(struct net_bridge *br, const unsigned char *addr, u16 vid) {
 assert(hash_depth == 1 && br->hash_lock); finds++;
 for(unsigned int i=0; i<br->fdb_list.count; i++) {
  struct net_bridge_fdb_entry *f=br->fdb_list.rows[i];
  if(f->key.vlan_id==vid && !memcmp(f->key.addr.addr,addr,6)) return f;
 }
 return NULL;
}
static void fdb_notify(struct net_bridge *br, struct net_bridge_fdb_entry *fdb, int type, bool swdev) {
 assert(rtnl_held && br->hash_lock && hash_depth == 1 && !gate_depth && !driver_mutex_held);
 assert(fdb && type==RTM_NEWNEIGH && !swdev); notifications++;
}
#define hlist_for_each_entry(f, head, member) \
 for(unsigned int h=0; h<(head)->count && ((f)=(head)->rows[h]); h++)
'''

TEST = r'''
static struct net net, other_net;
static struct net_bridge bridge, other_bridge;
static struct net_device master, port_dev, other_master, other_dev;
static struct net_bridge_port port, other_port;
static struct rtl9617c_switch_guard guard, other_guard;
static struct net_bridge_fdb_entry entry, second;
static const unsigned char mac[6]={2,0,0,0,0,7};
static const unsigned long stable=BIT(BR_FDB_STATIC)|BIT(BR_FDB_STICKY)|BIT(BR_FDB_ADDED_BY_USER);

/* The actual fdb_create initialization fragment is compiled here.  The
 * poisoned preimage models slab reuse, not a zero-initialized new object. */
static void create_row(struct net_bridge_fdb_entry *fdb, unsigned long flags) {
 CREATE_INITIALIZER
}
static void reset(unsigned long flags, bool local_port) {
 assert(!hash_depth && !gate_depth);
 net=(struct net){.rtl9617c_switch.generation=7}; other_net=(struct net){0};
 master=(struct net_device){.net=&net,.br=&bridge,.master=true};
 other_master=(struct net_device){.net=&other_net,.br=&other_bridge,.master=true};
 port=(struct net_bridge_port){.br=&bridge,.dev=&port_dev};
 other_port=(struct net_bridge_port){.br=&other_bridge,.dev=&other_dev};
 port_dev=(struct net_device){.net=&net,.port=&port};
 other_dev=(struct net_device){.net=&other_net,.port=&other_port};
 bridge=(struct net_bridge){.dev=&master}; other_bridge=(struct net_bridge){.dev=&other_master};
 guard=(struct rtl9617c_switch_guard){.net=&net,.registered=true};
 other_guard=(struct rtl9617c_switch_guard){.net=&net,.registered=true};
 memset(&entry,0xa5,sizeof(entry));
 create_row(&entry,flags);
 assert(!entry.rtl9617c_offload_owner && !entry.rtl9617c_offload_cookie);
 entry.dst=(flags & BIT(BR_FDB_LOCAL)) && !local_port ? NULL : &port;
 memcpy(entry.key.addr.addr,mac,6); entry.key.vlan_id=3;
 bridge.fdb_list.rows[0]=&entry; bridge.fdb_list.count=1;
 rtnl_held=true; driver_mutex_held=false; invalidate_at_gate=false; gate_net=&net;
 notifications=finds=0;
}
static int publish(bool local,u64 *cookie) {
 return br_rtl9617c_fdb_offload(&master,local?NULL:&port_dev,mac,3,local,&guard,7,cookie);
}
static bool cleanup(u64 cookie) {
 return br_rtl9617c_fdb_unoffload(&master,mac,3,&guard,cookie);
}
static void assertions(void) {
 assert(!hash_depth && !gate_depth && !bridge.hash_lock);
}

static void basic(void) {
 for(unsigned int kind=0;kind<3;kind++) {
  reset(kind?BIT(BR_FDB_LOCAL)|BIT(BR_FDB_STATIC):stable,kind==2);
  unsigned long original=entry.flags; struct net_bridge_port *dst=entry.dst;
  u64 cookie=0; assert(!publish(kind!=0,&cookie) && cookie);
  assert(entry.rtl9617c_offload_owner==&guard && entry.rtl9617c_offload_cookie==cookie);
  assert(entry.flags==(original|BIT(BR_FDB_OFFLOADED)) && entry.dst==dst && notifications==1);
  assert(!br_rtl9617c_fdb_unoffload(&master,mac,3,&other_guard,cookie));
  assert(!cleanup(cookie+1));
  assert(cleanup(cookie) && entry.flags==original && entry.dst==dst && notifications==2);
  assert(!entry.rtl9617c_offload_owner && !entry.rtl9617c_offload_cookie && !cleanup(cookie));
  assert(bridge.fdb_list.count==1 && bridge.fdb_list.rows[0]==&entry); assertions(); cases++;
 }
}

static void eligibility(void) {
 for(unsigned int flags=0;flags<(1U<<7);flags++) {
  bool local=!!(flags&BIT(BR_FDB_LOCAL));
  bool legal=!(flags&BIT(BR_FDB_LOCKED)) && !(flags&BIT(BR_FDB_OFFLOADED)) &&
             (local || ((flags&BIT(BR_FDB_STATIC)) && (flags&BIT(BR_FDB_STICKY))));
  reset(flags,false); u64 cookie=0xfeed; struct net_bridge_fdb_entry before=entry;
  int ret=publish(local,&cookie);
  if(legal) { assert(!ret && cookie!=0xfeed); assert(cleanup(cookie)); }
  else { assert(ret<0 && cookie==0xfeed && !memcmp(&entry,&before,sizeof(entry)) && !notifications); }
  assertions(); cases++;
 }
 reset(stable,false); entry.dst=&other_port; u64 cookie=0xfeed;
 assert(publish(false,&cookie)==-ESTALE && cookie==0xfeed); cases++;
 reset(BIT(BR_FDB_LOCAL),false); entry.dst=&other_port;
 assert(publish(true,&cookie)==-ESTALE && cookie==0xfeed); cases++;
 reset(stable,false);
 assert(publish(true,&cookie)==-ESTALE);
 assert(br_rtl9617c_fdb_offload(&master,&other_dev,mac,3,false,&guard,7,&cookie)==-ENODEV);
 port_dev.port=NULL;
 assert(publish(false,&cookie)==-ENODEV);
 assert(br_rtl9617c_fdb_offload(&other_master,&other_dev,mac,3,false,&guard,7,&cookie)==-EXDEV);
 assert(br_rtl9617c_fdb_offload(&master,NULL,mac,3,false,&guard,7,&cookie)==-EINVAL);
 assert(br_rtl9617c_fdb_offload(&master,&other_dev,mac,3,true,&guard,7,&cookie)==-EINVAL);
 assert(br_rtl9617c_fdb_offload(&master,NULL,mac,4095,true,&guard,7,&cookie)==-EINVAL);
 assert(br_rtl9617c_fdb_offload(&master,NULL,mac,3,true,&guard,7,NULL)==-EINVAL);
 assert(br_rtl9617c_fdb_offload(NULL,NULL,mac,3,true,&guard,7,&cookie)==-EINVAL);
 assert(br_rtl9617c_fdb_offload(&master,NULL,NULL,3,true,&guard,7,&cookie)==-EINVAL);
 assert(br_rtl9617c_fdb_offload(&master,NULL,mac,3,true,NULL,7,&cookie)==-EINVAL);
 assert(!cleanup(0)); cases++;
 reset(stable,false); bridge.fdb_list.count=0;
 assert(publish(false,&cookie)==-ENOENT && cookie==0xfeed); cases++;
}

static void epochs_and_aba(void) {
 reset(stable,false); u64 first=0, next=0; assert(!publish(false,&first));
 /* Same owner and policy epoch, but another successful publication. */
 assert(!publish(false,&next) && next>first);
 assert(!cleanup(first) && test_bit(BR_FDB_OFFLOADED,&entry.flags));
 assert(entry.rtl9617c_offload_cookie==next && notifications==1);
 assert(cleanup(next)); cases++;
 reset(stable,false); assert(!publish(false,&first));
 /* Delete/recreate the same key in the same slab address. */
 create_row(&entry,stable); assert(!entry.rtl9617c_offload_owner);
 assert(!cleanup(first) && !publish(false,&next) && next>first);
 assert(!cleanup(first) && test_bit(BR_FDB_OFFLOADED,&entry.flags));
 assert(cleanup(next)); cases++;
 reset(stable,false); assert(!publish(false,&first));
 /* Guard memory reused after unregister: the old opaque pointer matches,
  * but the newly issued publication cookie cannot match the stale record. */
 create_row(&entry,stable); guard.registered=false; guard.registered=true;
 assert(!publish(false,&next) && next>first && !cleanup(first)); assert(cleanup(next)); cases++;
 reset(stable,false); assert(!publish(false,&first));
 net.rtl9617c_switch.generation++; net.rtl9617c_switch.active=1; guard.registered=false;
 assert(cleanup(first)); /* Old-generation cleanup must still succeed. */ cases++;
 for(unsigned int blocker=0;blocker<8;blocker++) {
  reset(stable,false); u64 cookie=0xfeed;
  switch(blocker) {
   case 0: net.rtl9617c_switch.generation++; break;
   case 1: net.rtl9617c_switch.active=1; break;
   case 2: net.rtl9617c_switch.nf_blockers=1; break;
   case 3: net.rtl9617c_switch.tcx_blockers=1; break;
   case 4: net.rtl9617c_switch.xdp_blockers=1; break;
   case 5: net.rtl9617c_switch.poisoned=true; break;
   case 6: guard.registered=false; break;
   case 7: invalidate_at_gate=true; break;
  }
  assert(publish(false,&cookie)==-EAGAIN && cookie==0xfeed);
  assert(!finds && !entry.rtl9617c_offload_owner && !notifications);
  assertions(); cases++;
 }
}

static void foreign_owner(void) {
 reset(stable,false); u64 old=0; assert(!publish(false,&old));
 /* Generic feedback with an ALREADY-set bit still transfers ownership. */
 br_fdb_offloaded_set(&bridge,&port,mac,3,true);
 assert(!entry.rtl9617c_offload_owner && !entry.rtl9617c_offload_cookie);
 assert(!cleanup(old) && test_bit(BR_FDB_OFFLOADED,&entry.flags));
 u64 cookie=0xfeed; assert(publish(false,&cookie)==-EEXIST && cookie==0xfeed);
 br_fdb_offloaded_set(&bridge,&port,mac,3,false);
 assert(!publish(false,&cookie)); assert(cleanup(cookie)); cases++;
 reset(stable,false); assert(!publish(false,&old));
 br_fdb_clear_offload(&port_dev,3);
 assert(!entry.rtl9617c_offload_owner && !entry.rtl9617c_offload_cookie);
 assert(!test_bit(BR_FDB_OFFLOADED,&entry.flags) && !cleanup(old)); cases++;
 reset(stable,false); entry.rtl9617c_offload_owner=&other_guard; entry.rtl9617c_offload_cookie=73;
 assert(publish(false,&cookie)==-EEXIST && entry.rtl9617c_offload_cookie==73); cases++;
 reset(stable,false); assert(!publish(false,&old));
 /* Another native owner after a genuine row replacement. */
 create_row(&entry,stable);
 assert(!br_rtl9617c_fdb_offload(&master,&port_dev,mac,3,false,&other_guard,7,&cookie));
 assert(!cleanup(old) && entry.rtl9617c_offload_owner==&other_guard);
 assert(br_rtl9617c_fdb_unoffload(&master,mac,3,&other_guard,cookie)); cases++;
 reset(stable,false); assert(!publish(false,&old));
 second=entry; second.key.vlan_id=4; second.rtl9617c_offload_owner=&other_guard;
 bridge.fdb_list.rows[1]=&second; bridge.fdb_list.count=2;
 br_fdb_clear_offload(&port_dev,3);
 assert(test_bit(BR_FDB_OFFLOADED,&second.flags) && second.rtl9617c_offload_owner==&other_guard);
 assert(!cleanup(old)); cases++;
 /* The policy replacement hook clears only this driver's mark; it must
  * neither seize nor erase a generic driver's OFFLOADED bit. */
 reset(stable,false); assert(!publish(false,&old));
 assert(br_rtl9617c_fdb_owner_invalidate(&entry));
 assert(!cleanup(old) && !test_bit(BR_FDB_OFFLOADED,&entry.flags));
 entry.flags |= BIT(BR_FDB_OFFLOADED);
 assert(!br_rtl9617c_fdb_owner_invalidate(&entry) && test_bit(BR_FDB_OFFLOADED,&entry.flags)); cases++;
}

static void saturation(void) {
 reset(stable,false); br_rtl9617c_fdb_cookie.value=S64_MAX-1;
 u64 last=0, sentinel=0xfeed; assert(!publish(false,&last) && last==(u64)S64_MAX);
 for(unsigned int i=0;i<3;i++) {
  assert(publish(false,&sentinel)==-EOVERFLOW && sentinel==0xfeed);
  assert(entry.rtl9617c_offload_cookie==last && entry.rtl9617c_offload_owner==&guard);
  assert(br_rtl9617c_fdb_cookie.value==S64_MAX);
 }
 assert(cleanup(last)); cases++;
}
int main(void) {
 basic(); eligibility(); epochs_and_aba(); foreign_owner(); saturation(); assertions();
 printf("{\"cases\":%u,\"cookie_saturated\":true}\n",cases); return 0;
}
'''


def code_from_patch(text: str, gate: str):
    fdb = postimage(text, "net/bridge/br_fdb.c")
    private = postimage(text, "net/bridge/br_private.h")
    fields = re.search(r"\tstruct rtl9617c_switch_guard\s+\*rtl9617c_offload_owner;\n\tu64\s+rtl9617c_offload_cookie;", private)
    if not fields:
        raise AssertionError("missing per-entry owner/cookie storage")
    initializer = re.search(r"\tfdb->flags = flags;.*?\tfdb->updated = fdb->used = jiffies;", fdb, re.S)
    if not initializer:
        raise AssertionError("missing production slab initialization fragment")
    production = struct(fdb, "br_rtl9617c_offload_ctx")
    production += "static atomic64_t br_rtl9617c_fdb_cookie = ATOMIC64_INIT(0);\n"
    production += function(gate, "rtl9617c_switch_net_blocked")
    production += function(gate, "rtl9617c_switch_guard_publish")
    production += "\n".join(function(fdb, name) for name in NAMES)
    # Assert the real policy-mutating paths call the tested invalidation
    # helper; unlike initializer/API bodies these paths remain kernel-level.
    if fdb.count("br_rtl9617c_fdb_owner_invalidate(f);") != 2:
        raise AssertionError("both local destination migration hooks are required")
    if fdb.count("modified |= br_rtl9617c_fdb_owner_invalidate(fdb);") != 2:
        raise AssertionError("user replacement and external-learn hooks are required")
    return STUBS.replace("OWNER_FIELDS", fields.group()) + production + TEST.replace("CREATE_INITIALIZER", initializer.group()), fdb


def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run(code: str, sanitize: bool):
    with tempfile.TemporaryDirectory(prefix="l2-static-fdb-") as temp:
        work = Path(temp)
        for path, body in HEADERS.items():
            destination = work / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(body)
        (work / "linux/rtl9617c-switch.h").write_text(PUBLIC.read_text())
        source = work / "test.c"
        source.write_text(code)
        command = [os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                   "-Wno-unused-parameter", "-I", str(work), str(source), "-o", str(work / "test")]
        if sanitize:
            command[1:1] = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie"]
        built = subprocess.run(command, capture_output=True, text=True)
        if built.returncode:
            raise AssertionError(built.stdout + built.stderr)
        return subprocess.run([str(work / "test")], capture_output=True, text=True,
                              preexec_fn=no_core)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--mutants", action="store_true")
    parser.add_argument("--sanitize", action="store_true")
    args = parser.parse_args()
    patch = PATCH.read_text()
    gate = GATE.read_text()
    code, fdb = code_from_patch(patch, gate)
    if args.kernel:
        applied = (args.kernel / "net/bridge/br_fdb.c").read_text()
        for name in NAMES:
            if function(applied, name) != function(fdb, name):
                raise AssertionError(f"applied kernel differs: {name}")
        private = (args.kernel / "net/bridge/br_private.h").read_text()
        for field in ("rtl9617c_offload_owner", "rtl9617c_offload_cookie"):
            if field not in struct(private, "net_bridge_fdb_entry"):
                raise AssertionError(f"applied kernel lacks {field}")
    result = run(code, args.sanitize)
    if result.returncode:
        raise SystemExit(result.stdout + result.stderr)
    output = json.loads(result.stdout)
    mutations = {
        "cleanup_without_cookie": ("fdb->rtl9617c_offload_cookie == cookie", "true"),
        "cleanup_without_owner": ("fdb->rtl9617c_offload_owner == guard &&", "true &&"),
        "generic_does_not_transfer_owner": ("br_rtl9617c_fdb_owner_clear(fdb);\n\t\tif (offloaded", "if (offloaded"),
        "same_epoch_cookie_reused": ("ctx->cookie = previous + 1;", "ctx->cookie = 7;"),
        "reused_slab_keeps_owner": ("/* slab reuse must not inherit a deleted entry's publication cookie. */\n\tbr_rtl9617c_fdb_owner_clear(fdb);", "/* mutant: inherited slab state */"),
        "stale_generation_publishes": ("state->generation == generation", "((void)generation, true)"),
        "wrong_destination_publishes": ("dst != ctx->port ||", "false ||"),
        "movable_static_publishes": ("!test_bit(BR_FDB_STICKY, &fdb->flags)", "false"),
        "steal_generic_offload": ("(test_bit(BR_FDB_OFFLOADED, &fdb->flags) &&", "(false &&"),
        "notify_under_gate_lock": ("if (ctx.changed)\n\t\t\tfdb_notify", "if (ctx.changed)\n\t\t\tgate_depth++, fdb_notify"),
    }
    killed = []
    if args.mutants:
        for name, (before, after) in mutations.items():
            if code.count(before) != 1:
                raise AssertionError(f"mutation anchor not unique: {name}: {code.count(before)}")
            mutant = run(code.replace(before, after), False)
            if not mutant.returncode:
                raise AssertionError(f"SURVIVED: {name}")
            killed.append(name)
    output.update(patch_sha256=hashlib.sha256(patch.encode()).hexdigest(),
                  mutants_rejected=killed, sanitizers=args.sanitize, applied_kernel_checked=bool(args.kernel))
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
