#!/usr/bin/env python3
"""Execute real cold fabric -> L3 destination -> native L2 -> L3 ownership.

Reuse only the MMIO transport literal from test_l2_hardware_recipe.py, never
import/execute its tests. The public cold wrapper, fabric implementation,
native prepare/arm/drain/restore and destination get/put are actual production
code. The real allocator's boot snapshot statement is extracted verbatim;
the full allocator has its separate fault oracle. This is not ASIC proof.
"""
import argparse
import ast
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVERS = ROOT / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'


def function(source, name):
    match = re.search(r'^.*\b' + re.escape(name) + r'\([^;]*?\)\s*\{', source, re.M)
    if match is None:
        raise RuntimeError('missing production function: ' + name)
    start = match.start()
    if source[start:].startswith(name):
        start = source.rfind('\n', 0, start - 1) + 1
    end, depth = source.index('{', start) + 1, 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


def change(source, old, new):
    if source.count(old) != 1:
        raise RuntimeError('fixture/production anchor changed: ' + old)
    return source.replace(old, new, 1)


FDB_MODEL = r'''
 if(m->pending_address==RTL_L2_FDB_ACCESS) {
  unsigned int command=m->pending_request&255U;
  assert(m->reg[RTL_L2_FDB_CONTROL/4]&RTL_L2_FDB_CMD_MODE);
  if(command==RTL_L2_FDB_SCAN) {
   assert(!m->fdb_valid && ((m->pending_request>>8)&8191U)==0);
   assert(m->reg[RTL_L2_FDB_CONTROL/4]&RTL_L2_FDB_LEARN_DISABLE);
   m->reg[RTL_L2_FDB_RETURN/4]=RTL_L2_FDB_STATUS_MISS;
  } else {
   /* The test uses one fixed MAC. Check literal key bits35..98, excluding
    * the mutable row flags, so a wrong query cannot hit this transport row. */
   if(m->fdb_valid)assert(!(((m->fdb[1]^m->pending_words[1])&0xfffffff8U) |
       (m->fdb[2]^m->pending_words[2]) | ((m->fdb[3]^m->pending_words[3])&7U)));
   switch(command) {
   case RTL_L2_FDB_READ:
    m->reg[RTL_L2_FDB_RETURN/4]=m->fdb_valid?(7<<4)|RTL_L2_FDB_STATUS_HIT:RTL_L2_FDB_STATUS_MISS;
    if(m->fdb_valid)for(unsigned int i=0;i<4;i++)m->reg[(RTL_L2_FDB_DATA0-4*i)/4]=m->fdb[i];
    break;
   case RTL_L2_FDB_APPEND:
    memcpy(m->fdb,m->pending_words,sizeof(m->fdb));m->fdb_valid=true;
    m->reg[RTL_L2_FDB_RETURN/4]=(7<<4)|RTL_L2_FDB_STATUS_HIT;break;
   case RTL_L2_FDB_DELETE:
    m->reg[RTL_L2_FDB_RETURN/4]=m->fdb_valid?RTL_L2_FDB_STATUS_HIT:RTL_L2_FDB_STATUS_MISS;
    m->fdb_valid=false;break;
   default:assert(false);
   }
  }
  m->reg[m->pending_address/4]=0;m->pending=false;return;
 }
'''

SUPPORT = r'''
#define IS_REACHABLE(option) (option)
#define IS_ENABLED(option) (option)
static bool CONFIG_BRIDGE=true,CONFIG_NET_SWITCHDEV=true,CONFIG_RTL9617C_SWITCH_GUARD=true;
static void mutex_lock(bool *lock){assert(!*lock);*lock=true;}
static void mutex_unlock(bool *lock){assert(*lock);*lock=false;}
static void ether_addr_copy(u8 *to,const u8 *from){memcpy(to,from,ETH_ALEN);}
static bool ether_addr_equal(const u8 *a,const u8 *b){return !memcmp(a,b,ETH_ALEN);}
static void *kzalloc(size_t bytes,unsigned int flags){assert(!flags);return calloc(1,bytes);}
static void kfree(void *p){assert(p);free(p);}
static unsigned int allocation_calls,allocation_fail;
static void *kvzalloc(size_t bytes,unsigned int flags){
 assert(!flags);return ++allocation_calls==allocation_fail?NULL:calloc(1,bytes);
}
static void *kvcalloc(size_t count,size_t bytes,unsigned int flags){
 assert(!flags);return ++allocation_calls==allocation_fail?NULL:calloc(count,bytes);
}
static void kvfree(void *p){free(p);}
static bool native_l2_ivl;
#define lockdep_assert_held(lock) assert(*(lock))
'''

TEST = r'''
static unsigned int lifecycle_cases,roundtrips;
static void route_roundtrip(void)
{
 const u8 mac[]={2,0x77,0x66,0x55,0x44,0x33};
 struct rtl_fe_flow a={},b={};
 unsigned int control=fe_read(&fe,RTL_L2_FDB_CONTROL),writes=model.control_writes,commands=model.commands;
 model.route_phase=true;
 assert(!fe_destination_get(&fe,&a,mac));
 assert(a.destination_owned && a.destination_owner && a.destination_owner->ready);
 assert(!fe_destination_get(&fe,&b,mac));
 assert(a.destination_owner==b.destination_owner && a.destination_owner->users==2);
 assert(model.commands==commands+3 && fe.destination_count==1);
 assert(!fe_destination_put(&fe,&a) && !a.destination_owned);
 assert(b.destination_owner->users==1 && model.commands==commands+3);
 assert(!fe_destination_put(&fe,&b) && !b.destination_owned);
 assert(model.commands==commands+4 && !fe.destination_count && RB_EMPTY_ROOT(&fe.destinations));
 assert(model.control_writes==writes && fe_read(&fe,RTL_L2_FDB_CONTROL)==control);
 assert(!model.fdb_valid);model.route_phase=false;roundtrips++;
}

static void lifetime(unsigned int boot,bool svl,bool learning,unsigned int native)
{
 reset();
 model.reg[RTL_L2_FDB_CONTROL/4]&=~(RTL_L2_FDB_CMD_MODE|RTL_L2_FDB_LEARN_DISABLE|RTL_L2_FDB_SW_AGE_SCAN);
 if(boot)model.reg[RTL_L2_FDB_CONTROL/4]|=RTL_L2_FDB_CMD_MODE;
 if(!learning)model.reg[RTL_L2_FDB_CONTROL/4]|=RTL_L2_FDB_LEARN_DISABLE;
 if(boot!=svl)model.reg[RTL_L2_FDB_CONTROL/4]|=RTL_L2_FDB_SW_AGE_SCAN;
 model.reg[RTL_L2_VLAN_MODE_CONTROL/4]=svl?3:2;
 model.reg[RTL_FABRIC_FRAME_LENGTH/4]=0x004023f1;
 model.reg[RTL_FABRIC_STORAGE_LENGTH/4]=9300;
 for(unsigned int p=0;p<5;p++) {
  model.reg[RTL_FABRIC_RX_MAC(p)/4]=0x1101;model.reg[FE_LAN_RX_CTRL(p)/4]|=BIT(5);
 }
 unsigned int before=fe_read(&fe,RTL_L2_FDB_CONTROL);
 oracle_allocate_snapshot(&fe);
 assert(fe.fdb_cmd_mode_saved==(boot?RTL_L2_FDB_CMD_MODE:0));
 /* No manual command-mode setup: real cold preparation must own CMD. */
 assert(!rtl_fe_fabric_cold_prepare(&fe));
 assert(fe.fabric.ready && !fe.fabric.poisoned && !fe.fabric.error);
 assert(fe.fabric.saved_control==before);
 assert(fe.fdb_cmd_mode_saved==(boot?RTL_L2_FDB_CMD_MODE:0));
 unsigned int cold=before|RTL_L2_FDB_CMD_MODE|RTL_L2_FDB_LEARN_DISABLE;
 assert(fe_read(&fe,RTL_L2_FDB_CONTROL)==cold);
 assert(fe.l2_owner && fe.l2_owner->sealed && !rtl_l2_owner_retained(fe.l2_owner));
 assert(fe.l2_owner->mc_error==-EOPNOTSUPP);
 assert(fe.mcast && fe.mcast->state.error==-EOPNOTSUPP);
 assert(!fe.mcast->state.contract_ready && fe.mcast->state.cold_reads==3);
 assert(model.commands==!svl && rtl_fabric_native_mtu_compatible(&fe.fabric));
 struct rtl_dq_io io=fe_io(&fe);assert(!rtl_fabric_check(&io,&fe.fabric));
 route_roundtrip(); /* Native L2 remains off: this was the missing cold dependency. */
 fe.enabled=fe.prepared=true;
 if(native==1) {
  unsigned int hash=model.reg[RTL_L2_FDB_HASH_CONTROL/4];
  model.reg[RTL_L2_FDB_HASH_CONTROL/4]|=RTL_L2_FDB_HASH_USE_PRIORITY;
  assert(fe_switch_hw_prepare(&fe,&hw,3,300,false,true)==-EOPNOTSUPP);
  assert(!hw.globals_owned && !hw.prepared && !hw.count);
  model.reg[RTL_L2_FDB_HASH_CONTROL/4]=hash;
  assert(fe_read(&fe,RTL_L2_FDB_CONTROL)==cold);route_roundtrip();
 } else if(native==2) {
  assert(!fe_switch_hw_prepare(&fe,&hw,3,300,false,true));
  assert(hw.globals_owned && hw.prepared && hw.drained && hw.control==cold);
  assert(hw.control&RTL_L2_FDB_CMD_MODE);route_roundtrip();
  assert(fe_switch_hw_arm(&fe,&hw,3,28,true,true));
  assert((fe_read(&fe,RTL_L2_FDB_CONTROL)&(RTL_L2_FDB_CMD_MODE|RTL_L2_FDB_LEARN_DISABLE))==RTL_L2_FDB_CMD_MODE);
  assert(!rtl_fabric_check(&io,&fe.fabric));route_roundtrip(); /* Active autonomous learning. */
  assert(!fe_switch_hw_drain(&fe,&hw));assert(!fe_switch_hw_restore(&fe,&hw));
  assert(!hw.globals_owned && !hw.prepared && !hw.count && !hw.limits_owned);
  assert(fe_read(&fe,RTL_L2_FDB_CONTROL)==cold);
  assert(!rtl_fabric_check(&io,&fe.fabric));route_roundtrip(); /* Native gone, routes remain legal. */
 }
 fe.enabled=fe.prepared=false;
 assert(!rtl_fe_fdb_restore_mode(&io,fe.fdb_cmd_mode_saved));
 assert((fe_read(&fe,RTL_L2_FDB_CONTROL)&RTL_L2_FDB_CMD_MODE)==(boot?RTL_L2_FDB_CMD_MODE:0));
 fe_mcast_free(&fe);fe_l2_owner_free(&fe);assert(!fe.l2_owner && !fe.mcast);
 lifecycle_cases++;
}
static void allocation_refusal(void)
{
 for(unsigned int failure=1;failure<=3;failure++) {
  reset();allocation_calls=0;allocation_fail=failure;
  unsigned int reads=model.commands,writes=model.writes;
  assert(rtl_fe_fabric_cold_prepare(&fe)==1);
  assert(!fe.l2_owner && !fe.fabric.ready && !fe.fabric.poisoned && fe.error==-ENOMEM);
  assert(model.commands==reads && model.writes==writes && !fe.lock);
 }
 allocation_fail=0;
}
static void inherited_admission(void)
{
 struct rtl_fe_mcast multicast={0};
 const unsigned registers[]={0xaa28,0x3834,0x38a0};
 reset();fe.mcast=&multicast;fe.lock=true;
 unsigned commands=model.commands,writes=model.writes;
 /* Even an all-zero hash/cache/base fixture is not a documented global
  * drain or an exclusive CPU-injection handoff. Run the real predicate. */
 assert(fe_mcast_inherited_l3_check(&fe)==-EOPNOTSUPP);
 assert(model.commands==commands && model.writes==writes);
 for(unsigned i=0;i<ARRAY_SIZE(registers);i++) {
  model.corrupt_read_address=registers[i];model.corrupt_read_value=~0U;
  assert(fe_mcast_inherited_l3_check(&fe)==-EIO);
  assert(multicast.state.cold_register==registers[i]);
  assert(!multicast.state.contract_ready && model.commands==commands && model.writes==writes);
 }
 fe.mcast=NULL;fe.lock=false;
}
static void inherited_failure_baseline(void)
{
 const unsigned registers[]={0xaa28,0x3834,0x38a0};
 for(unsigned i=0;i<ARRAY_SIZE(registers);i++) {
  reset();allocation_calls=0;allocation_fail=0;
  model.reg[RTL_FABRIC_FRAME_LENGTH/4]=0x004023f1;
  model.reg[RTL_FABRIC_STORAGE_LENGTH/4]=9300;
  for(unsigned p=0;p<5;p++) {
   model.reg[RTL_FABRIC_RX_MAC(p)/4]=0x1101;model.reg[FE_LAN_RX_CTRL(p)/4]|=BIT(5);
  }
  model.corrupt_read_address=registers[i];model.corrupt_read_value=~0U;
  oracle_allocate_snapshot(&fe);
  /* The actual public cold caller must keep its verified default fabric
   * usable when an optional, read-only MCE diagnostic fails. */
  assert(!rtl_fe_fabric_cold_prepare(&fe));
  assert(fe.fabric.ready && !fe.fabric.poisoned && !fe.fabric.error);
  assert(fe.l2_owner && fe.l2_owner->sealed && !fe.l2_owner->error);
  assert(!fe.l2_owner->failures && !rtl_l2_owner_retained(fe.l2_owner));
  assert(!fe.l2_owner->ledger.quarantined && !fe.l2_owner->journal.quarantined);
  assert(fe.l2_owner->mc_error==-EIO && fe.mcast->state.error==-EIO);
  assert(fe.mcast->state.cold_reads==i+1 && fe.mcast->state.cold_register==registers[i]);
  assert(!fe.mcast->state.contract_ready && !fe_mcast_available(&fe));
  assert(!fe_mcast_retained(&fe) && !model.pending);
  struct rtl_dq_io io=fe_io(&fe);assert(!rtl_fabric_check(&io,&fe.fabric));
  route_roundtrip(); /* Read failure must not strand ordinary L3 FDB users. */
  fe_mcast_free(&fe);fe_l2_owner_free(&fe);lifecycle_cases++;
 }
}
static void acquired_command_failure(void)
{
 /* Host-only boundary fixture: a separately named copy of the actual
  * wrapper receives an explicitly simulated inherited-owner proof. The
  * real predicate above remains closed; all commands below execute the
  * real cold root scanner and actual shared owner. */
 const unsigned failed_commands[]={1,64U*4U+128U+1U};
 for(unsigned i=0;i<ARRAY_SIZE(failed_commands);i++) {
  reset();allocation_calls=0;allocation_fail=0;
  model.reg[RTL_FABRIC_FRAME_LENGTH/4]=0x004023f1;
  model.reg[RTL_FABRIC_STORAGE_LENGTH/4]=9300;
  for(unsigned p=0;p<5;p++) {
   model.reg[RTL_FABRIC_RX_MAC(p)/4]=0x1101;model.reg[FE_LAN_RX_CTRL(p)/4]|=BIT(5);
  }
  assert(!fe_l2_owner_allocate(&fe));
  struct rtl_dq_io io=fe_io(&fe);
  assert(!rtl_fabric_cold_prepare(&io,&fe.fabric));
  memset(model.rows,0,sizeof(model.rows));
  model.reg[RTL_MCAST_CONTROL/4]=0x0002f0ff;
  model.reg[RTL_MCAST_NI_SOURCE/4]=RTL_MCAST_SOURCE|BIT(7);
  model.fail=model.commands+failed_commands[i];
  fe.lock=true;
  assert(test_cold_prepare_after_proven_handoff(&fe)==-ETIMEDOUT);
  assert(model.pending && fe.l2_owner->ledger.quarantined);
  assert(fe.l2_owner->error==-ETIMEDOUT && fe.l2_owner->failures==1);
  assert(fe.l2_owner->mc_error==-ETIMEDOUT && fe.mcast->state.error==-ETIMEDOUT);
  assert(rtl_l2_owner_retained(fe.l2_owner) && !fe_mcast_available(&fe));
  if(i) {
   assert(model.pending_address==RTL_L2_FDB_ACCESS && fe_mcast_retained(&fe));
   assert(fe.mcast->state.fdb_filter_owned);
  }
  unsigned commands=model.commands,writes=model.writes;
  assert(test_cold_prepare_after_proven_handoff(&fe)==-EBUSY);
  assert(model.commands==commands && model.writes==writes);
  complete(&model); /* A late command completion is not owner retirement. */
  assert(test_cold_prepare_after_proven_handoff(&fe)==-EBUSY);
  assert(rtl_l2_owner_retained(fe.l2_owner));
  if(i)assert(fe.mcast->state.fdb_filter_owned && fe_mcast_retained(&fe));
  assert(model.commands==commands && model.writes==writes);fe.lock=false;
  /* End only this emulated device; production final-free retains it. */
  fe_mcast_free(&fe);fe_l2_owner_free(&fe);lifecycle_cases++;
 }
}
static void profile_admission(void)
{
 struct rtl_fe_mcast multicast={0};
 reset();allocation_calls=0;allocation_fail=0;
 assert(!fe_mcast_available(&fe));
 fe.mcast=&multicast;multicast.state.contract_ready=true;
 assert(!fe_mcast_available(&fe));
 assert(!fe_l2_owner_allocate(&fe));
 assert(!fe_mcast_available(&fe));
 /* Exercise the real availability predicate independently of the failed
  * physical handoff above. Neither one ready bank nor a stale cold state
  * alone grants the immutable exact-MDB profile to FE preparation. */
 fe.l2_owner->ready_mask=1U<<RTL_L2_SHARED_MC_FIB;
 assert(!fe_mcast_available(&fe));
 fe.l2_owner->ready_mask=1U<<RTL_L2_SHARED_MC_VECTOR;
 assert(!fe_mcast_available(&fe));
 fe.l2_owner->ready_mask=RTL_L2_OWNER_MC_READY;
 assert(fe_mcast_available(&fe));
 CONFIG_BRIDGE=false;assert(!fe_mcast_available(&fe));CONFIG_BRIDGE=true;
 CONFIG_NET_SWITCHDEV=false;assert(!fe_mcast_available(&fe));CONFIG_NET_SWITCHDEV=true;
 CONFIG_RTL9617C_SWITCH_GUARD=false;assert(!fe_mcast_available(&fe));CONFIG_RTL9617C_SWITCH_GUARD=true;
 multicast.state.contract_ready=false;assert(!fe_mcast_available(&fe));
 multicast.state.contract_ready=true;
 fe.l2_owner->ledger.quarantined=true;assert(!fe_mcast_available(&fe));
 fe.l2_owner->ledger.quarantined=false;
 fe.l2_owner->journal.quarantined=true;assert(!fe_mcast_available(&fe));
 fe.l2_owner->journal.quarantined=false;
 fe_l2_owner_free(&fe);fe.mcast=NULL;
}
int main(void)
{
 inherited_admission();
 inherited_failure_baseline();
 acquired_command_failure();
 profile_admission();
 allocation_refusal();
 for(unsigned int boot=0;boot<2;boot++)for(unsigned int svl=0;svl<2;svl++)
  for(unsigned int learning=0;learning<2;learning++)for(unsigned int native=0;native<3;native++)
   lifetime(boot,svl,learning,native);
 printf("FDB cold lifecycle: %u boot/SVL/learning/native paths, %u real shared get/put roundtrips; native snapshots/restore retain CMD, boot handback and zero ordinary CTRL writes PASS (host only)\n",lifecycle_cases,roundtrips);
}
'''


def program_source():
    tree = ast.parse((ROOT / 'scripts/test_l2_hardware_recipe.py').read_text())
    recipe = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == 'TEST' for t in node.targets))
    prefix = recipe[:recipe.index('static void cpu_only(void)')]
    prefix = change(prefix, '#include "rtl9617c-l2-table.h"', '''#include "rtl9617c-l2-table.h"
#include <stddef.h>
#include <stdlib.h>
#include "rtl9617c_destination_tree.h"
#include "rtl9617c-fe-pipeline.h"
#include "rtl9617c-l2-owner.h"
#include "rtl9617c-mcast-cold.h"
static void usleep_range(unsigned int low,unsigned int high);
#include "rtl9617c-fabric.h"
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
#define ETH_ALEN 6
#define GFP_KERNEL 0
#define FE_DESTINATIONS (4096+32)
struct list_head {struct list_head *next,*prev;};''')
    prefix = change(prefix, 'struct model {', 'struct model {\n unsigned int fdb[4],control_writes;bool fdb_valid,route_phase;')
    prefix = change(prefix, 'unsigned pending_withdrawals; };', '''unsigned pending_withdrawals;
 struct rb_root destinations;unsigned int destination_count,fdb_cmd_mode_saved;
 struct rtl_fabric fabric;struct rtl_l2_owner *l2_owner;struct rtl_fe_mcast *mcast;
 int error;bool engine_ready,shutting_down,lock; };''')
    prefix = change(prefix, 'static unsigned int cases, fault_cases, cold_cases;\n', '')
    start = prefix.index(' if(m->pending_address==RTL_L2_FDB_ACCESS) {')
    end = prefix.index(' if(m->pending_address==RTL_L2_FDB_LIMIT_ACCESS) {', start)
    prefix = prefix[:start] + FDB_MODEL + prefix[end:]
    prefix = change(prefix, ' int t = table_at(address, false);',
                    ' int t = table_at(address, false);\n if(address==RTL_L2_FDB_CONTROL) {assert(!m->route_phase);m->control_writes++;}')
    prefix = change(prefix, ' memset(&model, 0, sizeof(model)); memset(&hw, 0, sizeof(hw));',
                    ' memset(&fe,0,sizeof(fe));fe.model=&model;\n memset(&model, 0, sizeof(model)); memset(&hw, 0, sizeof(hw));')
    native = (DRIVERS / 'rtl9617c-fe.c').read_text()
    multicast = (DRIVERS / 'rtl9617c-fe-mcast.h').read_text()
    out = prefix + SUPPORT
    out += re.search(r'^struct rtl_fe_mcast \{.*?^\};', multicast, re.M | re.S)[0] + '\n'
    out += function(native, 'fe_mcast_available')
    out += function(native, 'fe_mcast_inherited_l3_check')
    cold_wrapper = function(multicast, 'fe_mcast_cold_prepare')
    out += cold_wrapper
    out += '''/* Explicit host seam; never replaces the real production predicate. */
static int test_only_inherited_owner_proof(struct rtl_fe *fe)
{ assert(fe->lock && fe->fabric.ready && fe->mcast);return 0; }
'''
    out += cold_wrapper.replace('fe_mcast_cold_prepare(', 'test_cold_prepare_after_proven_handoff(', 1).replace(
        'fe_mcast_inherited_l3_check(fe)', 'test_only_inherited_owner_proof(fe)', 1)
    out += function(multicast, 'fe_mcast_free')
    out += function(multicast, 'fe_mcast_retained')
    for name in ('rtl_fe_destination', 'rtl_fe_flow'):
        out += re.search(r'^struct ' + name + r' \{.*?^\};', native, re.M | re.S)[0] + '\n'
    allocation = function(native, 'rtl_fe_allocate')
    snapshot = re.search(r'^\s*fe->fdb_cmd_mode_saved=fe_read\(fe,0x1c00\)&BIT\(31\);', allocation, re.M)
    if snapshot is None:
        raise RuntimeError('allocation boot snapshot changed: re-audit the dependency')
    out += 'static void oracle_allocate_snapshot(struct rtl_fe *fe) {\n' + snapshot[0] + '\n}\n'
    for name in ('fe_l2_owner_free','fe_l2_owner_allocate','rtl_fe_fabric_cold_prepare','fe_destination_find','fe_destination_index',
                 'fe_destination_retire','fe_destination_get','fe_destination_put'):
        out += function(native, name)
    return out + TEST


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    source = program_source()
    headers = {name:(DRIVERS / name).read_text() for name in
               ('rtl9617c-fabric.h','rtl9617c-fe-switch-hw.h','rtl9617c-fe-pipeline.h')}
    variants = [('production',source,headers)]
    if args.mutants:
        fabric = change(headers['rtl9617c-fabric.h'], 'RTL_L2_FDB_LEARN_DISABLE | RTL_L2_FDB_CMD_MODE))',
                        'RTL_L2_FDB_LEARN_DISABLE))')
        variants.append(('cold-returns-boot-cmd',source,{**headers,'rtl9617c-fabric.h':fabric}))
        switch = change(headers['rtl9617c-fe-switch-hw.h'], 'hw->control, FE_SW_FDB_OWNED_CONTROL);',
                        'hw->control & ~RTL_L2_FDB_CMD_MODE, FE_SW_FDB_OWNED_CONTROL);')
        variants.append(('native-releases-fe-mode',source,{**headers,'rtl9617c-fe-switch-hw.h':switch}))
        pipeline = change(headers['rtl9617c-fe-pipeline.h'],
            'ret=rtl_l2_fdb_command(io,(enum rtl_l2_fdb_command)command,0,words,&next);',
            'io->write(io->context,RTL_L2_FDB_CONTROL,io->read(io->context,RTL_L2_FDB_CONTROL));\n'
            ' ret=rtl_l2_fdb_command(io,(enum rtl_l2_fdb_command)command,0,words,&next);')
        variants.append(('ordinary-flow-writes-control',source,{**headers,'rtl9617c-fe-pipeline.h':pipeline}))
        lifetime = function(source, 'lifetime')
        late = change(source,lifetime,change(lifetime,'assert(!rtl_fe_fabric_cold_prepare(&fe));',
                      'assert(!rtl_fe_fabric_cold_prepare(&fe));oracle_allocate_snapshot(&fe);'))
        variants.append(('late-allocation-snapshot',late,headers))
        preflight_fault = change(source,
            '\tret = fe_mcast_inherited_l3_check(fe);',
            '\tret = fe_mcast_inherited_l3_check(fe);\n\tif (ret)rtl_l2_owner_fault(fe->l2_owner, ret);')
        variants.append(('read-only-preflight-poisons-baseline',preflight_fault,headers))
        command_fault = function(source, 'test_cold_prepare_after_proven_handoff')
        ignored = change(command_fault,
            '\t\trtl_l2_owner_fault(fe->l2_owner, ret);', '\t\t(void)ret;')
        variants.append(('acquired-command-loses-quarantine',change(source,command_fault,ignored),headers))
    environment = dict(os.environ);environment.setdefault('ASAN_OPTIONS','detect_leaks=0')
    with tempfile.TemporaryDirectory(prefix='fe-fdb-cold-life-') as temporary:
        build = Path(temporary);(build / 'linux').mkdir()
        (build / 'linux/delay.h').write_text('/* host transport supplies delay */\n')
        (build / 'linux/string.h').write_text('#include <string.h>\n')
        for name,body,copies in variants:
            for filename,contents in copies.items():
                (build / filename).write_text(contents)
            (build / 'test.c').write_text(body)
            subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-Wall','-Wextra','-Werror',
                '-Wno-unused-function','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',
                '-no-pie','-I',str(build),'-I',str(DRIVERS),'-I',str(ROOT / 'scripts/fixtures'),
                str(build / 'test.c'),'-o',str(build / 'test')],check=True)
            result = subprocess.run([str(build / 'test')],env=environment,text=True,capture_output=True)
            if name == 'production':
                if result.returncode:
                    raise AssertionError(result.stdout + result.stderr)
                print(result.stdout,end='')
            elif not result.returncode or 'Assertion' not in result.stderr:
                raise AssertionError(name + ' did not fail a semantic assertion:\n' + result.stderr)
            else:
                print('PASS: semantic assertion rejected ' + name)


if __name__ == '__main__':
    main()
