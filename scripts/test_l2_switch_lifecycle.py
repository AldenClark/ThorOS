#!/usr/bin/env python3
"""Execute native switch capability/domain checks and admission callbacks.

Production functions are extracted unchanged from fe-switch.h. Hardware
recipe/indirect-window and core-policy races have separate executed tests.
The callback fixture verifies ordering/ownership, not silicon forwarding.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVERS = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"
SOURCE = DRIVERS / "rtl9617c-fe-switch.h"
source = SOURCE.read_text()


def function(name):
    start = source.index(name + "(")
    start = source.rfind("\n", 0, start) + 1
    if not source[start:].startswith("static "):
        start = source.rfind("\n", 0, start - 1) + 1
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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "rtl9617c-l2-format.h"
typedef uint32_t u32; typedef unsigned char u8;
#define FE_LAN_PORTS 5
#define ETH_ALEN 6
#define BIT(n) (1UL << (n))
#define GENMASK(high, low) ((~0UL >> (sizeof(unsigned long)*8-1-(high))) & (~0UL << (low)))
/* Linux 6.18 bridge flag ABI, independent of the implementation's allowlist. */
#define BR_BPDU_GUARD BIT(1)
#define BR_ROOT_BLOCK BIT(2)
#define BR_MULTICAST_FAST_LEAVE BIT(3)
#define BR_ADMIN_COST BIT(4)
#define BR_LEARNING BIT(5)
#define BR_FLOOD BIT(6)
#define BR_PROMISC BIT(7)
#define BR_LEARNING_SYNC BIT(9)
#define BR_MCAST_FLOOD BIT(11)
#define BR_BCAST_FLOOD BIT(14)
#define BR_BPDU_FILTER BIT(24)
#define BR_STATE_FORWARDING 3
#define READ_ONCE(value) (value)
#define WRITE_ONCE(target, value) ((target) = (value))
#define system_long_wq 7
static unsigned int hweight32(u32 value) { return __builtin_popcount(value); }
static bool is_valid_ether_addr(const unsigned char *mac) {
 unsigned int any = 0; for (unsigned int i = 0; i < 6; i++) any |= mac[i];
 return any && !(mac[0] & 1);
}
struct rtl_fe { bool shutting_down, engine_ready, enabled, route_admitted; };
struct rtl_fe_switch_hw { bool open, allow_arm; unsigned int closes, arms; u32 native, route; };
struct rtl_fe_bridge {
 struct rtl_fe *fe; struct rtl_fe_switch_hw hw;
 bool stopping, active, flow_allowed; u32 native_mask, route_mask, armed_route_mask;
 unsigned int work;
};
static void fe_switch_hw_gate(struct rtl_fe *fe, struct rtl_fe_switch_hw *hw) {
 assert(fe); hw->open = false; hw->closes++; fe->route_admitted=false;
}
static bool fe_switch_hw_arm(struct rtl_fe *fe, struct rtl_fe_switch_hw *hw, u32 native, u32 route) {
 assert(fe && fe->engine_ready && !fe->shutting_down);
 assert(!(native & route) && !((native | route) & ~31U));
 hw->arms++; hw->native = native; hw->route = route; hw->open = hw->allow_arm;
 fe->route_admitted = hw->allow_arm && fe->enabled;
 return hw->allow_arm;
}
static unsigned int queue_calls;
static bool queue_work(unsigned int queue, unsigned int *work) {
 assert(queue == system_long_wq); queue_calls++; bool idle = !*work; *work = 1; return idle;
}
'''

TEST = r'''
static unsigned int cases;
static void policy_and_domains(void) {
 const unsigned long ordinary = BR_BPDU_GUARD | BR_ROOT_BLOCK | BR_MULTICAST_FAST_LEAVE |
  BR_ADMIN_COST | BR_LEARNING | BR_FLOOD | BR_PROMISC | BR_LEARNING_SYNC |
  BR_MCAST_FLOOD | BR_BCAST_FLOOD | BR_BPDU_FILTER;
 struct fe_switch_plan plan = {0};
 for (unsigned int i = 0; i < 5; i++) { plan.flags[i] = BR_LEARNING; plan.state[i] = BR_STATE_FORWARDING; }
 for (unsigned int mask = 0; mask < 32; mask++) {
  plan.ports = mask;
  assert((fe_switch_plan_validate(&plan) == FE_SWITCH_OK) == (__builtin_popcount(mask) >= 2)); cases++;
 }
 plan.ports = 31;
 for (unsigned int port = 0; port < 5; port++) {
  for (unsigned int bit = 0; bit < sizeof(unsigned long) * 8; bit++) {
   plan.flags[port] = BR_LEARNING | BIT(bit);
   assert((fe_switch_plan_validate(&plan) == FE_SWITCH_OK) == !!(ordinary & BIT(bit))); cases++;
  }
  plan.flags[port] = ordinary & ~BR_LEARNING;
  assert(fe_switch_plan_validate(&plan) == FE_SWITCH_PORT_POLICY);
  plan.flags[port] = BR_LEARNING;
  for (unsigned int state = 0; state < 8; state++) {
   plan.state[port] = state;
   assert((fe_switch_plan_validate(&plan) == FE_SWITCH_OK) == (state == BR_STATE_FORWARDING)); cases++;
  }
  plan.state[port] = BR_STATE_FORWARDING;
 }
 for (unsigned int bit = 5; bit < 32; bit++) {
  plan.ports = 3U | (1U << bit);
  assert(fe_switch_plan_validate(&plan) != FE_SWITCH_OK); cases++;
 }
 plan.ports = 3;
 plan.multi_bridge = true; assert(fe_switch_plan_validate(&plan) == FE_SWITCH_MULTI_BRIDGE); plan.multi_bridge = false;
 plan.mixed = true; assert(fe_switch_plan_validate(&plan) == FE_SWITCH_MIXED_PORTS); plan.mixed = false;
 plan.vlan_filtering = true; assert(fe_switch_plan_validate(&plan) == FE_SWITCH_VLAN_UNSUPPORTED); plan.vlan_filtering = false;
 plan.private_policy = true; assert(fe_switch_plan_validate(&plan) == FE_SWITCH_PRIVATE_POLICY); plan.private_policy = false;
 plan.promisc = true; assert(fe_switch_plan_validate(&plan) == FE_SWITCH_PROMISC); plan.promisc = false;
 plan.software_policy = true; assert(fe_switch_plan_validate(&plan) == FE_SWITCH_GUARDED); plan.software_policy = false;
 plan.flags[4] = ~0UL; plan.state[4] = 0; /* Unselected ports confer no policy. */
 assert(fe_switch_plan_validate(&plan) == FE_SWITCH_OK);
 struct rtl_l2_fdb_entry entry = {.mac={2,0,0,0,0,1}, .valid=1};
 for (unsigned int vid = 0; vid < 4096; vid++) for (unsigned int sc = 0; sc < 2; sc++)
  for (unsigned int pcp = 0; pcp < 8; pcp++) {
   entry.key_vid=vid; entry.key_sc=sc; entry.key_dot1p=pcp;
   bool native = vid == 0 && sc == 0 && pcp == 0;
   assert(fe_switch_native_key(&entry) == native);
   assert(fe_switch_learned_owned(&entry, 31) == native); cases++;
  }
 entry.key_vid=entry.key_sc=entry.key_dot1p=0;
 for (unsigned int mask = 0; mask < 32; mask++) for (unsigned int port = 0; port < 64; port++) {
  entry.destination=port;
  assert(fe_switch_learned_owned(&entry, mask) == (port < 5 && (mask & (1U << port)))); cases++;
 }
 entry.destination=0;
 for (unsigned int condition=0; condition<5; condition++) {
  switch(condition) {
  case 0:entry.is_static=1;break;
  case 1:entry.multicast=1;break;
  case 2:entry.temporary=1;break;
  case 3:entry.in_station_move=1;break;
  case 4:entry.valid=0;break;
  }
  assert(!fe_switch_learned_owned(&entry,31));
  entry.is_static=entry.multicast=entry.temporary=entry.in_station_move=0;entry.valid=1;cases++;
 }
 for (unsigned int bit=0;bit<48;bit++) {
  memset(entry.mac,0,6);entry.mac[bit/8]=1U<<(bit%8);
  assert(fe_switch_learned_owned(&entry,31)==(bit!=0));cases++;
 }
 memset(entry.mac,0,6);assert(!fe_switch_learned_owned(&entry,31));
 memset(entry.mac,255,6);assert(!fe_switch_learned_owned(&entry,31));
}

static void admission_callbacks(void) {
 struct rtl_fe fe = {.engine_ready=true,.enabled=true};
 struct rtl_fe_bridge sw = {.fe=&fe,.hw={.allow_arm=true},.native_mask=3,.route_mask=28};
 assert(fe_switch_arm(&sw) && sw.active && sw.hw.open && sw.flow_allowed);
 assert(sw.hw.arms==1 && sw.hw.native==3 && sw.hw.route==28 && sw.armed_route_mask==28);
 fe_switch_gate(&sw);assert(!sw.active && !sw.hw.open && sw.hw.closes==1 && !sw.armed_route_mask && !sw.flow_allowed);
 fe.enabled=false;sw.route_mask=0;
 assert(fe_switch_arm(&sw) && sw.active && !sw.flow_allowed && !sw.armed_route_mask);
 fe_switch_gate(&sw);fe.enabled=true;
 sw.native_mask=0;sw.route_mask=31;
 assert(fe_switch_arm(&sw) && !sw.active && sw.hw.open && sw.flow_allowed); /* Route-only is not native L2. */
 fe_switch_gate(&sw);
 for(unsigned int condition=0;condition<3;condition++) {
  unsigned int arms=sw.hw.arms;
  if(condition==0)sw.stopping=true;
  if(condition==1)fe.shutting_down=true;
  if(condition==2)fe.engine_ready=false;
  assert(!fe_switch_arm(&sw) && sw.hw.arms==arms && !sw.hw.open);
  sw.stopping=fe.shutting_down=false;fe.engine_ready=true;cases++;
 }
 sw.native_mask=3;sw.route_mask=28;sw.hw.allow_arm=false;
 assert(!fe_switch_arm(&sw) && !sw.active && !sw.flow_allowed);
 fe_switch_queue(&sw);assert(queue_calls==1 && sw.work);
 sw.stopping=true;fe_switch_queue(&sw);assert(queue_calls==1);
 sw.stopping=false;sw.work=0;fe_switch_rebuild(&sw);assert(queue_calls==2 && sw.work);
}
int main(void) {
 policy_and_domains(); admission_callbacks();
 printf("Native switch production functions: %u policy/domain/admission cases; native VID0/SC0/PCP0 isolation, static/foreign row exclusion, stop/engine guards and deferred work passed (host model only)\n",cases);
 return 0;
}
'''

definitions = "\n".join(re.search(pattern, source, re.S)[0] for pattern in [
    r"enum fe_switch_reason \{.*?\n\};", r"struct fe_switch_plan \{.*?\n\};",
])
functions = "\n".join(function(name) for name in [
    "fe_switch_plan_validate", "fe_switch_native_key", "fe_switch_learned_owned",
    "fe_switch_queue", "fe_switch_gate", "fe_switch_rebuild", "fe_switch_arm",
])
with tempfile.TemporaryDirectory(prefix="l2-switch-lifecycle-") as directory:
    temporary = Path(directory)
    (temporary / "test.c").write_text(COMMON + definitions + functions + TEST)
    subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g",
                    "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
                    "-fno-sanitize-recover=all", "-I", str(DRIVERS),
                    str(temporary / "test.c"), "-o", str(temporary / "test")], check=True)
    environment = dict(os.environ)
    environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
    subprocess.run([str(temporary / "test")], check=True, env=environment)
(ROOT / "artifacts").mkdir(exist_ok=True)
(ROOT / "artifacts/l2-switch-lifecycle.json").write_text(json.dumps({
    "production_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
    "production_functions_sha256": hashlib.sha256(functions.encode()).hexdigest(),
    "scope": "capability/key ownership predicates and admission callbacks; not whole-worker or hardware validation",
    "hardware_verified": False,
}, indent=2) + "\n")
