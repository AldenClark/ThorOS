#!/usr/bin/env python3
"""Run production FE fallback admission for legal bridge-unreachable builds.

The shipped TYFZA1 configuration has built-in bridge/switchdev/guard and does
not use this branch. This checks a supported BRIDGE=n/m configuration variant,
not a claimed explanation or benchmark for production board throughput.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


root = Path(__file__).resolve().parents[1]
drivers = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
native = (drivers / 'rtl9617c-fe.c').read_text()
switch = (drivers / 'rtl9617c-fe-switch.h').read_text()
fallback = switch[switch.index('\n#else\n/* A built-in Ethernet driver'):]


def function(source, name):
    start = re.search(r'^static (?:bool|void|int) ' + name + r'\(', source, re.M).start()
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define BIT(n) (1U<<(n))
#define READ_ONCE(value) (value)
#define WRITE_ONCE(dst,value) ((dst)=(value))
#define FE_LAN_PORTS 5
#define FE_LAN_RX_CTRL(port) (0xa5f8+0x90*(port))
struct spinlock {bool held;};
#define spin_lock_irqsave(lock,flags) do{(flags)=0;assert(!(lock)->held);(lock)->held=true;}while(0)
#define spin_unlock_irqrestore(lock,flags) do{(void)(flags);assert((lock)->held);(lock)->held=false;}while(0)
struct rtl_fe {
 struct spinlock route_lock;
 bool enabled,prepared,engine_ready,shutting_down;
 bool route_gate_ready,route_admitted,route_gate_verified;
 unsigned int pending_withdrawals;
 uint32_t reg[0x10000/4],initial_lan[FE_LAN_PORTS];
 unsigned int writes,lan25_writes,lan16_writes,fail_cpu_mask,fail_route_mask;
};
static unsigned int fe_read(void *context,unsigned int reg){
 struct rtl_fe *fe=context;assert(reg<0x10000);return fe->reg[reg/4];
}
static void fe_write(void *context,unsigned int reg,unsigned int value){
 struct rtl_fe *fe=context;assert(reg<0x10000);fe->writes++;
 if(reg==0x3418 || reg==0x3424){
  assert(fe->route_lock.held);
  unsigned int side=reg==0x3424,profile=(value>>10)&15;
  if(profile==0)
   for(unsigned int port=0;port<FE_LAN_PORTS;port++)
    assert(((fe_read(fe,FE_LAN_RX_CTRL(port))>>16)&63)==16);
  if(profile==1 && (fe->fail_cpu_mask&BIT(side)))return;
  if(profile==0 && (fe->fail_route_mask&BIT(side)))return;
 } else {
  assert(reg>=FE_LAN_RX_CTRL(0) && reg<=FE_LAN_RX_CTRL(4));
  assert(!((reg-FE_LAN_RX_CTRL(0))%0x90));
  unsigned int port=(reg-FE_LAN_RX_CTRL(0))/0x90,target=(value>>16)&63;
  /* The fallback never changes unrelated port bits or enables native L2. */
  assert((value&~(BIT(28)|(63U<<16)))==
         (fe->initial_lan[port]&~(BIT(28)|(63U<<16))));
  assert(value&BIT(28));
  if(target==25){
   unsigned int expected=fe->pending_withdrawals?1:0;
   /* Independent data-plane oracle at the actual opening write. Check
    * real selector readbacks, not only the software admission flag. */
   assert(((fe_read(fe,0x3418)>>10)&15)==expected);
   assert(((fe_read(fe,0x3424)>>10)&15)==expected);
   assert(fe->pending_withdrawals?fe->route_gate_verified:fe->route_admitted);
   fe->lan25_writes++;
  } else {assert(target==16);fe->lan16_writes++;}
 }
 fe->reg[reg/4]=value;
}
'''

tests = r'''
static void initialize(struct rtl_fe *fe){
 memset(fe,0,sizeof(*fe));
 fe->enabled=fe->prepared=fe->engine_ready=fe->route_gate_ready=true;
 fe->reg[0x3418/4]=fe->reg[0x3424/4]=1U<<10;
 for(unsigned int port=0;port<FE_LAN_PORTS;port++)
  fe->reg[FE_LAN_RX_CTRL(port)/4]=fe->initial_lan[port]=
   0x18100400U|(port<<24)|port;
}
static void expect_lan(struct rtl_fe *fe,unsigned int target){
 for(unsigned int port=0;port<FE_LAN_PORTS;port++){
  unsigned int rx=fe_read(fe,FE_LAN_RX_CTRL(port));
  assert((rx&BIT(28)) && ((rx>>16)&63)==target);
 }
}
int main(void){
 struct rtl_fe fe;
 /* Valid baseline routing is still available without a reachable bridge. */
 initialize(&fe);fe_switch_reconcile_locked(&fe);
 assert(fe.route_admitted && fe_switch_flow_allowed(&fe));expect_lan(&fe,25);
 assert(fe.lan25_writes==FE_LAN_PORTS && !fe_switch_needs_recovery(&fe));
 for(unsigned int side=0;side<2;side++){
  initialize(&fe);fe_switch_reconcile_locked(&fe);
  fe.fail_cpu_mask=BIT(side);
  /* rtl_fe_flush_port/remove_port first close LAN. A subsequent failed
   * published-flow withdrawal latches routes but cannot prove this LPB
   * accepted profile1. Reconciliation must NOT reopen the closed RX. */
  assert(!fe_switch_quiesce_locked(&fe));expect_lan(&fe,16);
  fe.pending_withdrawals=1;fe_route_gate(&fe);
  assert(!fe.route_admitted && !fe.route_gate_verified);
  unsigned int opened=fe.lan25_writes;
  fe_switch_reconcile_locked(&fe);
  assert(fe.lan25_writes==opened && !fe.route_gate_verified);expect_lan(&fe,16);
  assert(!fe_switch_flow_allowed(&fe) && fe_switch_needs_recovery(&fe));
  /* Even if entry RX was still route25, a failed arm actively returns
   * LAN to CPU16 instead of merely suppressing another opening write. */
  for(unsigned int port=0;port<FE_LAN_PORTS;port++)
   fe.reg[FE_LAN_RX_CTRL(port)/4]=(fe.initial_lan[port]&~(63U<<16))|(25U<<16);
  fe_switch_reconcile_locked(&fe);expect_lan(&fe,16);
  assert(fe.lan25_writes==opened);
  /* Restored readback permits route25 -> CPU profile1, not a stale hash. */
  fe.fail_cpu_mask=0;fe_switch_reconcile_locked(&fe);expect_lan(&fe,25);
  assert(fe.route_gate_verified && !fe.route_admitted && !fe_switch_flow_allowed(&fe));
  assert(fe.pending_withdrawals==1 && fe.lan25_writes==opened+FE_LAN_PORTS);
  fe.pending_withdrawals=0;fe_switch_reconcile_locked(&fe);
  assert(fe.route_admitted && fe_switch_flow_allowed(&fe));expect_lan(&fe,25);
 }
 /* A normal route-open readback failure is likewise not permission to
  * expose RX25, even when no withdrawal latch happens to be present. */
 for(unsigned int side=0;side<2;side++){
  initialize(&fe);fe.fail_route_mask=BIT(side);
  fe_switch_reconcile_locked(&fe);expect_lan(&fe,16);
  assert(!fe.lan25_writes && !fe.route_admitted && fe.route_gate_verified);
  assert(!fe_switch_flow_allowed(&fe) && fe_switch_needs_recovery(&fe));
  fe.fail_route_mask=0;fe_switch_reconcile_locked(&fe);expect_lan(&fe,25);
  assert(fe.route_admitted && fe.lan25_writes==FE_LAN_PORTS);
 }
 /* An incomplete owner has no route admission authority. */
 initialize(&fe);fe.prepared=fe.route_gate_ready=false;
 fe_switch_reconcile_locked(&fe);expect_lan(&fe,16);
 assert(!fe.lan25_writes && !fe.route_admitted && !fe.route_gate_verified);
 for(unsigned int inactive=0;inactive<3;inactive++){
  initialize(&fe);
  if(inactive==0)fe.engine_ready=false;
  if(inactive==1)fe.enabled=false;
  if(inactive==2)fe.shutting_down=true;
  fe_switch_reconcile_locked(&fe);expect_lan(&fe,16);assert(!fe.writes);
  assert(!fe_switch_flow_allowed(&fe));
 }
 puts("Legal bridge-unreachable FE fallback: route/CPU selector readback precedes every RX25 opening; failure keeps CPU16; native production path unchanged");
}
'''

production = '\n'.join(function(native, name) for name in (
    'fe_route_select_locked', 'fe_route_gate', 'fe_route_arm'))
production += '\n'.join(function(fallback, name) for name in (
    'fe_switch_needs_recovery', 'fe_switch_quiesce_locked',
    'fe_switch_reconcile_locked', 'fe_switch_flow_allowed'))
check = '''\tfe_switch_quiesce_locked(fe);
\tif (!fe_route_arm(fe))
\t\treturn;
'''
assert production.count(check) == 1
reconcile = function(fallback, 'fe_switch_reconcile_locked')
old_order = reconcile.replace(check, '').replace(
    '\tfe_read(fe, FE_LAN_RX_CTRL(FE_LAN_PORTS - 1));',
    '\tfe_read(fe, FE_LAN_RX_CTRL(FE_LAN_PORTS - 1));\n\tfe_route_arm(fe);')
mutants = {
    'open_RX25_before_unchecked_arm': production.replace(reconcile, old_order),
    'ignore_failed_route_arm': production.replace(
        check, '\tfe_switch_quiesce_locked(fe);\n\tfe_route_arm(fe);\n'),
    'failure_does_not_return_existing_route_RX_to_CPU': production.replace(
        check, '\tif (!fe_route_arm(fe))\n\t\treturn;\n'),
}
with tempfile.TemporaryDirectory(dir=root / 'artifacts', prefix='fe-route-fallback-') as work:
    work = Path(work)
    source, binary = work / 'fallback.c', work / 'fallback'
    source.write_text(fixture + production + tests)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-g',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
    for name, changed in mutants.items():
        assert changed != production, name
        source, binary = work / (name + '.c'), work / name
        source.write_text(fixture + changed + tests)
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        str(source), '-o', str(binary)], check=True)
        result = subprocess.run([str(binary)], capture_output=True, text=True)
        assert result.returncode and 'Assertion' in result.stderr, name
        print('Fallback mutation rejected:', name)
(root / 'logs/fe-route-fallback.json').write_text(json.dumps({
    'FE_source_sha256': hashlib.sha256(native.encode()).hexdigest(),
    'switch_source_sha256': hashlib.sha256(switch.encode()).hexdigest(),
    'configuration': 'legal bridge-unreachable variant; not shipped TYFZA1 native-L2 path',
    'pending_CPU_gate_readback_precedes_RX25': True,
    'normal_route_arm_readback_precedes_RX25': True,
    'existing_RX25_quiesced_before_route_readmission': True,
    'failure_preserves_or_restores_CPU16': True,
    'unrelated_RX_bits_preserved': True,
    'inactive_or_shutdown_has_no_MMIO': True,
    'mutants_rejected': list(mutants),
    'sanitizers': ['ASan', 'UBSan'],
    'hardware_validation': False,
}, indent=2) + '\n')
