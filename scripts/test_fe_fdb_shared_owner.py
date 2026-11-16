#!/usr/bin/env python3
"""Exercise actual L3 DA-pin callers through the production shared FDB path.

This is a deterministic ownership/fault model, not an ASIC retirement proof.
The cold owner uses the real command-mode transition helper; live route
updates use the real fe_destination_get/put and never acquire another lease.
"""
import argparse
from pathlib import Path
import re
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
RELATIVE = Path("port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek")
DRIVER = ROOT / RELATIVE


def function(source, name):
    start = re.search(r"^static [^;{]*\b" + name + r"\(", source, re.M).start()
    end = source.index("{", start) + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end] + "\n"


SHIM = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "rtl9617c-fe-pipeline.h"
#include "rtl9617c_l2_mmio_model.h"
#include "rtl9617c_destination_tree.h"
typedef unsigned char u8;
#define ETH_ALEN 6
#define FE_DESTINATIONS (4096+32)
#define BIT(n) (1U<<(n))
#define GFP_KERNEL 0
static unsigned int allocations;
static void *allocate(size_t bytes) {void *p=calloc(1,bytes);assert(p);allocations++;return p;}
static void release(void *p) {assert(p && allocations);allocations--;free(p);}
#define kzalloc(bytes,flags) allocate(bytes)
#define kfree(p) release(p)
struct rtl_fe_destination;
struct rtl_fe_flow {
 struct rtl_fe_destination *destination_owner;
 bool destination_owned,destination_live;
 unsigned int destination_index;
 u8 destination[ETH_ALEN];
};
struct rtl_fe {struct rb_root destinations;unsigned int destination_count;};
static struct l2_mmio_model model;
static bool valid,pending_update;
static unsigned int stored[4],pending_row[4],pending_cmd,fail_at,mode_fault_at,cases;
static const u8 mac[6]={2,0x11,0x22,0x33,0x44,0x55};
static void ether_addr_copy(u8 *a,const u8 *b){memcpy(a,b,6);}
static void apply_pending(void) {
 if(!pending_update)return;
 if(pending_cmd==RTL_L2_FDB_APPEND){memcpy(stored,pending_row,sizeof(stored));valid=true;}
 if(pending_cmd==RTL_L2_FDB_DELETE)valid=false;
 pending_update=false;
}
static int fdb_command(void *ctx,unsigned int address,unsigned int value) {
 struct l2_mmio_model *m=ctx;
 if(address==RTL_L2_FDB_ACCESS) {
  unsigned int command=value&255U;
  m->fdb_status=command==RTL_L2_FDB_APPEND?RTL_L2_FDB_STATUS_HIT:
                valid?RTL_L2_FDB_STATUS_HIT:RTL_L2_FDB_STATUS_MISS;
  m->fdb_index=7;
  if(valid)memcpy(m->fdb_reply,stored,sizeof(stored));
  pending_cmd=command;
  pending_update=command==RTL_L2_FDB_APPEND || command==RTL_L2_FDB_DELETE;
  for(unsigned int i=0;i<4;i++)pending_row[i]=m->registers[(RTL_L2_FDB_DATA0-i*4)/4];
  if(m->commands+1==fail_at)m->next_error=-ETIMEDOUT;
  if(m->commands+1==mode_fault_at) {
   m->complete_control_override=true;
   m->complete_control_value=RTL_L2_FDB_LEARN_DISABLE;
  }
 }
 int ret=l2_model_command(ctx,address,value);
 if(!ret)apply_pending();
 return ret;
}
static struct rtl_dq_io fe_io(struct rtl_fe *fe) {
 (void)fe;return (struct rtl_dq_io){&model,l2_model_read,l2_model_write,fdb_command};
}
static void setup(struct rtl_fe *fe,unsigned int control) {
 assert(!allocations);
 memset(fe,0,sizeof(*fe));l2_model_init(&model);
 model.registers[RTL_L2_FDB_CONTROL/4]=control;
 valid=pending_update=false;fail_at=mode_fault_at=0;
 memset(stored,0,sizeof(stored));
}
static void complete(void) {l2_model_complete(&model);apply_pending();}
'''

CASES = r'''
static void live_routes(void) {
 struct rtl_fe fe;struct rtl_fe_flow one,two;
 for(unsigned int learning=0;learning<2;learning++)
 for(unsigned int toggle=0;toggle<2;toggle++)
 for(unsigned int original=0;original<2;original++) {
  unsigned int control=RTL_L2_FDB_CMD_MODE|(learning?0:RTL_L2_FDB_LEARN_DISABLE)|
                       (toggle?RTL_L2_FDB_SW_AGE_SCAN:0);
  setup(&fe,control);one=(struct rtl_fe_flow){0};two=(struct rtl_fe_flow){0};
  unsigned int saved[4];
  if(original) {
   valid=true;rtl_fe_fdb_key(stored,mac);
   stored[0]=(stored[0]&~(255U<<11))|(37U<<11)|BIT(6);
   memcpy(saved,stored,sizeof(saved));
  }
  assert(!fe_destination_get(&fe,&one,mac));
  assert(one.destination_owned && one.destination_owner->ready && one.destination_index==7);
  assert(valid && model.commands==3 && !model.control_writes && allocations==1);
  assert(!fe_destination_get(&fe,&two,mac));
  assert(one.destination_owner==two.destination_owner && model.commands==3 && allocations==1);
  assert(!fe_destination_put(&fe,&one));
  assert(model.commands==3 && !one.destination_owned && valid);
  assert(!fe_destination_put(&fe,&two));
  assert(model.commands==4 && !allocations && !fe.destination_count);
  assert(!model.control_writes && model.registers[RTL_L2_FDB_CONTROL/4]==control);
  assert(valid==!!original);
  if(original)assert(!memcmp(stored,saved,sizeof(saved)));
  cases++;
 }
}

static void owner_transitions(void) {
 struct rtl_fe fe;struct rtl_fe_flow flow={0};
 const unsigned int cold=RTL_L2_FDB_LEARN_DISABLE|RTL_L2_FDB_SW_AGE_SCAN;
 setup(&fe,cold);
 struct rtl_dq_io io=fe_io(&fe);
 /* Actual helper used by the cold fabric owner; ordinary L3 first refuses
  * the unowned mode, then works both with stopped and enabled learning. */
 assert(fe_destination_get(&fe,&flow,mac)==-EOPNOTSUPP);
 assert(!flow.destination_owned && !model.writes && !model.commands && !allocations);
 assert(!rtl_l2_fdb_command_mode(&io));
 assert(model.control_writes==1);
 model.registers[RTL_L2_FDB_CONTROL/4]&=~RTL_L2_FDB_LEARN_DISABLE;
 l2_model_trace_reset(&model);
 assert(!fe_destination_get(&fe,&flow,mac));
 assert(!fe_destination_put(&fe,&flow) && !model.control_writes && !allocations);
 cases++;

 setup(&fe,RTL_L2_FDB_CMD_MODE|cold);flow=(struct rtl_fe_flow){0};
 io=fe_io(&fe);model.next_error=-ETIMEDOUT;
 assert(rtl_l2_port_limit_write(&io,2,123)==-ETIMEDOUT);
 unsigned int writes=model.writes,commands=model.commands;
 assert(fe_destination_get(&fe,&flow,mac)==-EBUSY);
 assert(!flow.destination_owned && model.writes==writes && model.commands==commands);
 complete();l2_model_trace_reset(&model);
 /* The command has completed, but returning mode is the same owner's job. */
 assert(fe_destination_get(&fe,&flow,mac)==-EOPNOTSUPP);
 assert(!model.writes && !model.commands);
 assert(!rtl_l2_fdb_command_mode(&io));
 l2_model_trace_reset(&model);
 assert(!fe_destination_get(&fe,&flow,mac) && !model.control_writes);
 assert(!fe_destination_put(&fe,&flow) && !allocations);
 cases++;
}

static void faults(void) {
 struct rtl_fe fe;struct rtl_fe_flow flow,next;
 const unsigned int controls[]={0,~0U,RTL_L2_FDB_CMD_MODE|RTL_L2_FDB_INFO_INIT};
 const int errors[]={-EOPNOTSUPP,-EIO,-EOPNOTSUPP};
 for(unsigned int i=0;i<3;i++) {
  setup(&fe,controls[i]);flow=(struct rtl_fe_flow){0};
  assert(fe_destination_get(&fe,&flow,mac)==errors[i]);
  assert(!model.writes && !model.commands && !flow.destination_owned && !allocations);
  cases++;
 }
 for(unsigned int fault=1;fault<=3;fault++) {
  setup(&fe,RTL_L2_FDB_CMD_MODE);flow=(struct rtl_fe_flow){0};next=(struct rtl_fe_flow){0};
  fail_at=fault;
  assert(fe_destination_get(&fe,&flow,mac)==-ETIMEDOUT);
  assert(!model.control_writes);
  unsigned int writes=model.writes,commands=model.commands;
  assert(fe_destination_get(&fe,&next,mac)==-EBUSY);
  assert(model.writes==writes && model.commands==commands && !next.destination_owned);
  if(fault>1) {
   assert(flow.destination_owned && allocations==1 && !flow.destination_owner->ready);
   assert(fe_destination_put(&fe,&flow)==-EBUSY);
   assert(model.writes==writes && model.commands==commands && flow.destination_owned);
  } else assert(!flow.destination_owned && !allocations);
  complete();fail_at=0;l2_model_trace_reset(&model);
  if(flow.destination_owned)assert(!fe_destination_put(&fe,&flow));
  assert(!allocations && !fe.destination_count && !valid && !model.control_writes);
  cases++;
 }
 for(unsigned int fault=1;fault<=3;fault++) {
  setup(&fe,RTL_L2_FDB_CMD_MODE);flow=(struct rtl_fe_flow){0};
  mode_fault_at=fault;
  assert(fe_destination_get(&fe,&flow,mac)==-EIO);
  assert(!model.control_writes);
  if(fault>1)assert(flow.destination_owned && allocations==1 && !flow.destination_owner->ready);
  else assert(!flow.destination_owned && !allocations);
  model.complete_control_override=false;mode_fault_at=0;
  if(flow.destination_owned) {
   unsigned int writes=model.writes;
   assert(fe_destination_put(&fe,&flow)==-EOPNOTSUPP && model.writes==writes);
   struct rtl_dq_io io=fe_io(&fe);assert(!rtl_l2_fdb_command_mode(&io));
   l2_model_trace_reset(&model);assert(!fe_destination_put(&fe,&flow));
  }
  assert(!allocations && !valid && !model.control_writes);
  cases++;
 }
 /* Autonomous age-trigger edges may change between command completion
  * and readback. The L3 transport must not replay the old control image. */
 for(unsigned int toggle=0;toggle<2;toggle++) {
  unsigned int control=RTL_L2_FDB_CMD_MODE|(toggle?RTL_L2_FDB_SW_AGE_SCAN:0);
  setup(&fe,control);flow=(struct rtl_fe_flow){0};
  model.complete_control_xor=RTL_L2_FDB_SW_AGE_SCAN;
  assert(!fe_destination_get(&fe,&flow,mac));
  assert(model.registers[RTL_L2_FDB_CONTROL/4]==(control^RTL_L2_FDB_SW_AGE_SCAN));
  assert(!fe_destination_put(&fe,&flow) && !model.control_writes);
  assert(model.registers[RTL_L2_FDB_CONTROL/4]==control && !allocations);
  cases++;
 }
}
int main(void) {
 live_routes();owner_transitions();faults();
 printf("L3 shared FDB: %u real destination-owner cases; cold CMD handoff, active learning, pin sharing/restore, late-limit/APPEND, mode drift and scan edges PASS\n",cases);
}
'''


def run(source, header):
    names = ("fe_destination_find", "fe_destination_index", "fe_destination_retire",
             "fe_destination_get", "fe_destination_put")
    definition = re.search(r"struct rtl_fe_destination \{.*?\n\};", source, re.S).group()
    with tempfile.TemporaryDirectory(prefix="fe-fdb-shared-") as temp:
        wd = Path(temp)
        (wd / "rtl9617c-fe-pipeline.h").write_text(header)
        program = wd / "test.c"
        program.write_text(SHIM + definition + "\n" +
                           "\n".join(function(source, name) for name in names) + CASES)
        subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-function", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                        "-I", str(wd), "-I", str(DRIVER), "-I", str(ROOT / "scripts/fixtures"),
                        str(program), "-o", str(wd / "test")], check=True)
        return subprocess.run([str(wd / "test")], capture_output=True, text=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--negative-control", help="Old pipeline revision that must fail the same assertions")
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    source = (DRIVER / "rtl9617c-fe.c").read_text()
    header = (DRIVER / "rtl9617c-fe-pipeline.h").read_text()
    result = run(source, header)
    if result.returncode:
        raise SystemExit(result.stdout + result.stderr)
    print(result.stdout.strip())
    if args.negative_control:
        old = subprocess.check_output(["git", "show", args.negative_control + ":" +
                                       str(RELATIVE / "rtl9617c-fe-pipeline.h")], cwd=ROOT, text=True)
        result = run(source, old)
        if not result.returncode or "Assertion" not in result.stderr:
            raise SystemExit("Unsafe historical mode wrapper was not rejected by a runtime assertion")
        print("PASS: historical unchecked L3 CMD lease/replay rejected by the real-owner assertion")


if __name__ == "__main__":
    main()
