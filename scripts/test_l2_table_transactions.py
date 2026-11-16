#!/usr/bin/env python3
"""Execute production L2 table/FDB transactions with delayed MMIO completion.

This is a host fault-injection test, not a model-only copy of the driver, a
hardware packet test or a throughput result. Register/field correctness is
independently checked by test_l2_sdk_contract.py against pinned vendor inputs.
"""
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVERS = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"
FIXTURES = ROOT / "scripts/fixtures"

TEST = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include "rtl9617c_l2_mmio_model.h"

static struct l2_mmio_model model;
static unsigned int cases, rows_checked;
static const unsigned int marker[RTL_L2_TABLE_MAX_WORDS] =
 { 0x01234567, 0x89abcdef, 0x13579bdf, 0x2468ace0, 0xf00dcafe };

static void no_io(void) { assert(!model.event_count); }
static void no_mutation(void) { assert(!model.writes && !model.commands); }

static void table_cases(void)
{
 struct rtl_dq_io io = l2_model_io(&model);
 unsigned int table, index, word, result[RTL_L2_TABLE_MAX_WORDS];

 for (table = 0; table < RTL_L2_TBL_COUNT; table++) {
  const struct rtl_l2_table_layout *layout = &model.layouts[table];
  unsigned int input[RTL_L2_TABLE_MAX_WORDS];
  for (index = 0; index < layout->entries; index++) {
   for (word = 0; word < RTL_L2_TABLE_MAX_WORDS; word++)
    input[word] = 0xa5000000U ^ (table << 20) ^ (index << 8) ^ word;
   l2_model_trace_reset(&model);
   assert(!rtl_l2_table_write(&io, table, index, input));
   assert(model.writes == layout->words && model.commands == 1);
   assert(model.events[0].kind == L2_MODEL_READ && model.events[0].address == layout->access);
   for (word = 0; word < layout->words; word++) {
    assert(model.events[word + 1].kind == L2_MODEL_WRITE);
    assert(model.events[word + 1].address == layout->data0 - word * 4);
    assert(model.events[word + 1].value == input[word]);
   }
   memcpy(result, marker, sizeof(result));
   l2_model_trace_reset(&model);
   assert(!rtl_l2_table_read(&io, table, index, result));
   assert(!model.writes && model.commands == 1);
   assert(!memcmp(input, result, layout->words * sizeof(*result)));
   for (word = layout->words; word < RTL_L2_TABLE_MAX_WORDS; word++)
    assert(result[word] == marker[word]);
   rows_checked++;
  }
  /* Both sides of every table boundary fail before touching MMIO. */
  l2_model_trace_reset(&model);
  assert(rtl_l2_table_read(&io, table, layout->entries, result) == -EINVAL);
  assert(rtl_l2_table_write(&io, table, UINT_MAX, marker) == -EINVAL);
  assert(rtl_l2_table_read(&io, table, 0, NULL) == -EINVAL);
  assert(rtl_l2_table_write(&io, table, 0, NULL) == -EINVAL);
  no_io();
  /* An already-busy shared window must not receive even a DATA write. */
  model.registers[layout->access / 4] = RTL_L2_ACCESS_BUSY | 7;
  memcpy(result, marker, sizeof(result));
  assert(rtl_l2_table_write(&io, table, 0, marker) == -EBUSY);
  assert(rtl_l2_table_read(&io, table, 0, result) == -EBUSY);
  assert(!memcmp(result, marker, sizeof(result))); no_mutation();
  model.registers[layout->access / 4] = 0;
  /* Transport errors may complete late. A retry cannot overwrite staging. */
  for (unsigned int operation = 0; operation < 2; operation++)
   for (unsigned int fault = 0; fault < 2; fault++) {
    const int error = fault ? -EIO : -ETIMEDOUT;
    l2_model_trace_reset(&model); model.next_error = error;
    memcpy(result, marker, sizeof(result));
    int ret = operation ? rtl_l2_table_write(&io, table, 0, marker) :
                          rtl_l2_table_read(&io, table, 0, result);
    assert(ret == error && model.pending);
    assert(!memcmp(result, marker, sizeof(result)));
    unsigned int staged[RTL_L2_TABLE_MAX_WORDS];
    memcpy(staged, model.pending_words, sizeof(staged));
    l2_model_trace_reset(&model);
    assert(rtl_l2_table_write(&io, table, 1, input) == -EBUSY);
    assert(rtl_l2_table_read(&io, table, 1, result) == -EBUSY);
    no_mutation(); assert(!memcmp(staged, model.pending_words, sizeof(staged)));
    l2_model_complete(&model);
    l2_model_trace_reset(&model);
    assert(!rtl_l2_table_read(&io, table, 0, result));
    if (operation) assert(!memcmp(result, marker, layout->words * sizeof(*result)));
    cases++;
   }
  /* Rollback keeps the ORIGINAL row and ownership through failed retries. */
  struct rtl_l2_snapshot snapshot = {0}, original;
  l2_model_trace_reset(&model);
  assert(!rtl_l2_table_write(&io, table, 0, marker));
  assert(!rtl_l2_snapshot_take(&io, &snapshot, table, 0)); original = snapshot;
  l2_model_trace_reset(&model);
  assert(rtl_l2_snapshot_take(&io, &snapshot, table, 1) == -EALREADY); no_io();
  assert(!memcmp(&snapshot, &original, sizeof(snapshot)));
  assert(!rtl_l2_table_write(&io, table, 0, input));
  model.next_error = -ETIMEDOUT;
  assert(rtl_l2_snapshot_restore(&io, &snapshot) == -ETIMEDOUT);
  assert(!memcmp(&snapshot, &original, sizeof(snapshot)));
  l2_model_trace_reset(&model);
  assert(rtl_l2_snapshot_restore(&io, &snapshot) == -EBUSY); no_mutation();
  l2_model_complete(&model);
  l2_model_trace_reset(&model);
  assert(!rtl_l2_snapshot_restore(&io, &snapshot));
  assert(snapshot.valid && !memcmp(&snapshot, &original, sizeof(snapshot)));
  assert(!rtl_l2_table_read(&io, table, 0, result));
  assert(!memcmp(result, marker, layout->words * sizeof(*result)));
  cases++;
 }
 l2_model_trace_reset(&model);
 assert(rtl_l2_table_read(&io, (enum rtl_l2_table)-1, 0, result) == -EINVAL);
 assert(rtl_l2_table_write(&io, RTL_L2_TBL_COUNT, 0, marker) == -EINVAL);
 assert(rtl_l2_table_read(NULL, 0, 0, result) == -EINVAL);
 struct rtl_dq_io invalid = io; invalid.indirect = NULL;
 assert(rtl_l2_table_write(&invalid, 0, 0, marker) == -EINVAL);
 struct rtl_l2_snapshot invalid_snapshot = {0}, untouched = {0};
 assert(rtl_l2_snapshot_restore(&io, &invalid_snapshot) == -EINVAL);
 assert(rtl_l2_snapshot_take(&io, NULL, 0, 0) == -EINVAL);
 no_io();
 model.next_error = -ETIMEDOUT;
 assert(rtl_l2_snapshot_take(&io, &invalid_snapshot, 0, 0) == -ETIMEDOUT);
 assert(!memcmp(&invalid_snapshot, &untouched, sizeof(untouched)));
 l2_model_complete(&model);
}

static void fdb_cases(void)
{
 struct rtl_dq_io io = l2_model_io(&model);
 const unsigned int allowed[] = { RTL_L2_FDB_SCAN, RTL_L2_FDB_READ,
                                 RTL_L2_FDB_APPEND, RTL_L2_FDB_DELETE };
 struct rtl_l2_fdb_result result, sentinel;
 memset(&sentinel, 0xa5, sizeof(sentinel));
 const unsigned int mode = model.registers[RTL_L2_FDB_CONTROL / 4];
 for (unsigned int i = 0; i < 4; i++) model.fdb_reply[i] = marker[i];
 for (unsigned int command = 0; command < 256; command++) {
  bool valid = false;
  for (unsigned int i = 0; i < 4; i++) valid |= command == allowed[i];
  if (valid) continue;
  l2_model_trace_reset(&model); result = sentinel;
  assert(rtl_l2_fdb_command(&io, command, 0, marker, &result) == -EOPNOTSUPP);
  no_io(); assert(!memcmp(&result, &sentinel, sizeof(result))); cases++;
 }
 for (unsigned int i = 0; i < 4; i++) {
  unsigned int command = allowed[i];
  for (unsigned int status = 0; status < 16; status++) {
   l2_model_trace_reset(&model); result = sentinel;
   model.fdb_status = status; model.fdb_index = 13;
   assert(!rtl_l2_fdb_command(&io, command, 0, command == RTL_L2_FDB_SCAN ? NULL : marker, &result));
   assert(result.raw == 13 * 16 + status && result.status == status && result.index == 13);
   for (unsigned int word = 0; word < 4; word++)
    assert(result.words[word] == ((command == RTL_L2_FDB_READ || command == RTL_L2_FDB_SCAN) &&
           status == RTL_L2_FDB_STATUS_HIT ? marker[word] : 0));
   assert(model.commands == 1 && model.writes == 5);
   assert(model.registers[RTL_L2_FDB_CONTROL / 4] == mode); cases++;
  }
  for (unsigned int fault = 0; fault < 2; fault++) {
   model.next_error = fault ? -EIO : -ETIMEDOUT;
   l2_model_trace_reset(&model); result = sentinel;
   assert(rtl_l2_fdb_command(&io, command, 0, marker, &result) == (fault ? -EIO : -ETIMEDOUT));
   assert(!memcmp(&result, &sentinel, sizeof(result)));
   assert(model.registers[RTL_L2_FDB_CONTROL / 4] == mode);
   l2_model_trace_reset(&model);
   assert(rtl_l2_fdb_command(&io, RTL_L2_FDB_APPEND, 0, marker, &result) == -EBUSY);
   no_mutation(); l2_model_complete(&model); cases++;
  }
 }
 l2_model_trace_reset(&model); result = sentinel;
 model.registers[RTL_L2_FDB_CONTROL / 4] &= ~RTL_L2_FDB_CMD_MODE;
 assert(rtl_l2_fdb_command(&io, RTL_L2_FDB_READ, 0, marker, &result) == -EOPNOTSUPP);
 no_mutation(); assert(!memcmp(&result, &sentinel, sizeof(result)));
 model.registers[RTL_L2_FDB_CONTROL / 4] = mode;
 l2_model_trace_reset(&model);
 assert(rtl_l2_fdb_command(&io, RTL_L2_FDB_READ, 1, marker, &result) == -EINVAL);
 assert(rtl_l2_fdb_command(&io, RTL_L2_FDB_READ, 0, NULL, &result) == -EINVAL);
 assert(rtl_l2_fdb_command(&io, RTL_L2_FDB_SCAN, RTL_L2_FDB_ENTRIES, NULL, &result) == -EINVAL);
 assert(rtl_l2_fdb_command(&io, RTL_L2_FDB_SCAN, 0, NULL, NULL) == -EINVAL);
 no_io();
 /* A failed or partial scan never manufactures proof that a row is absent. */
 for (unsigned int status = 0; status < 16; status++) {
  l2_model_trace_reset(&model); result = sentinel;
  model.fdb_status = status; model.fdb_index = 19;
  int ret = rtl_l2_fdb_scan(&io, 17, &result);
  assert(ret == (status == 5 ? 1 : status == 15 ? 0 : -EIO));
  if (status == 5) assert(result.index == 19);
  else assert(!memcmp(&result, &sentinel, sizeof(result)));
  cases++;
 }
 model.fdb_status = RTL_L2_FDB_STATUS_HIT;
 const unsigned int bad_index[] = { 16, RTL_L2_FDB_ENTRIES, 8191 };
 for (unsigned int i = 0; i < 3; i++) {
  l2_model_trace_reset(&model); result = sentinel; model.fdb_index = bad_index[i];
  assert(rtl_l2_fdb_scan(&io, 17, &result) == -EIO);
  assert(!memcmp(&result, &sentinel, sizeof(result))); cases++;
 }
 l2_model_trace_reset(&model); result = sentinel;
 assert(!rtl_l2_fdb_scan(&io, RTL_L2_FDB_ENTRIES, &result));
 assert(rtl_l2_fdb_scan(&io, RTL_L2_FDB_ENTRIES + 1, &result) == -EINVAL);
 assert(rtl_l2_fdb_scan(&io, 0, NULL) == -EINVAL);
 assert(!memcmp(&result, &sentinel, sizeof(result))); no_io();
 model.fdb_index = RTL_L2_FDB_ENTRIES - 1;
 assert(rtl_l2_fdb_scan(&io, RTL_L2_FDB_ENTRIES - 1, &result) == 1);
 assert(result.index == RTL_L2_FDB_ENTRIES - 1);
}

static void mac_limit_cases(void)
{
 struct rtl_dq_io io = l2_model_io(&model);
 const unsigned int control = 0x1a123456U | RTL_L2_FDB_CMD_MODE | RTL_L2_FDB_LEARN_DISABLE;
 const unsigned int values[] = {0, RTL_L2_FDB_LIMIT_MAX, 0xdedbeef0U, UINT_MAX};
 unsigned int result;
 model.registers[RTL_L2_FDB_CONTROL / 4] = control;
 for(unsigned int port=0;port<RTL_L2_LOGICAL_PORTS;port++)
  for(unsigned int value=0;value<4;value++) {
   l2_model_trace_reset(&model);
   assert(!rtl_l2_port_limit_write(&io,port,values[value]));
   assert(model.port_limits[port]==values[value] && model.commands==1 && model.writes==3);
   assert(model.pending_value==(RTL_L2_ACCESS_BUSY|RTL_L2_ACCESS_WRITE|RTL_L2_FDB_LIMIT_SELECT|port));
   assert(model.registers[RTL_L2_FDB_CONTROL / 4]==control);
   l2_model_trace_reset(&model);result=0xabcdef01U;
   assert(!rtl_l2_port_limit_read(&io,port,&result) && result==values[value]);
   assert(model.commands==1 && model.writes==2 && model.registers[RTL_L2_FDB_CONTROL / 4]==control);
   cases++;
  }
 l2_model_trace_reset(&model);
 assert(rtl_l2_port_limit_read(NULL,0,&result)==-EINVAL);
 assert(rtl_l2_port_limit_read(&io,64,&result)==-EINVAL);
 assert(rtl_l2_port_limit_write(&io,UINT_MAX,0)==-EINVAL);
 assert(rtl_l2_port_limit_read(&io,0,NULL)==-EINVAL);
 assert(rtl_l2_port_limit_access(&io,0,&result,2)==-EINVAL);
 assert(rtl_l2_fdb_command_mode(NULL)==-EINVAL);no_io();
 for(unsigned int state=0;state<4;state++) {
  model.registers[RTL_L2_FDB_CONTROL / 4]=control;
  if(state==0)model.registers[RTL_L2_FDB_ACCESS / 4]=RTL_L2_ACCESS_BUSY;
  if(state==1)model.registers[RTL_L2_FDB_LIMIT_ACCESS / 4]=RTL_L2_ACCESS_BUSY;
  if(state==2)model.registers[RTL_L2_FDB_CONTROL / 4]&=~RTL_L2_FDB_LEARN_DISABLE;
  if(state==3)model.registers[RTL_L2_FDB_CONTROL / 4]&=~RTL_L2_FDB_CMD_MODE;
  unsigned int unchanged=model.registers[RTL_L2_FDB_CONTROL / 4];result=0xabcdef01;
  l2_model_trace_reset(&model);
  assert(rtl_l2_port_limit_read(&io,0,&result)==(state==3?-EOPNOTSUPP:-EBUSY));
  assert(rtl_l2_port_limit_write(&io,0,0)==(state==3?-EOPNOTSUPP:-EBUSY));
  assert(result==0xabcdef01 && model.registers[RTL_L2_FDB_CONTROL / 4]==unchanged);no_mutation();
  if(state<3){assert(rtl_l2_fdb_command_mode(&io)==-EBUSY);no_mutation();}
  else {assert(!rtl_l2_fdb_command_mode(&io));assert(model.registers[RTL_L2_FDB_CONTROL / 4]==control);}
  model.registers[RTL_L2_FDB_ACCESS / 4]=model.registers[RTL_L2_FDB_LIMIT_ACCESS / 4]=0;cases++;
 }
 for(unsigned int operation=0;operation<2;operation++)for(unsigned int fault=0;fault<2;fault++) {
  model.registers[RTL_L2_FDB_CONTROL / 4]=control;
  model.port_limits[17]=0xa5a50000;result=0xc0ffee00;
  model.next_error=fault?-EIO:-ETIMEDOUT;l2_model_trace_reset(&model);
  int ret=operation?rtl_l2_port_limit_write(&io,17,0x5a5a1fff):rtl_l2_port_limit_read(&io,17,&result);
  assert(ret==(fault?-EIO:-ETIMEDOUT) && model.pending && result==0xc0ffee00);
  assert(model.registers[RTL_L2_FDB_CONTROL / 4]==(control&~RTL_L2_FDB_CMD_MODE));
  unsigned int staged=model.pending_words[0];l2_model_trace_reset(&model);
  assert(rtl_l2_port_limit_write(&io,18,0)==-EBUSY);
  assert(rtl_l2_fdb_command_mode(&io)==-EBUSY);no_mutation();assert(model.pending_words[0]==staged);
  struct rtl_l2_fdb_result reply={.raw=0xabcdef01};
  assert(rtl_l2_fdb_command(&io,RTL_L2_FDB_APPEND,0,marker,&reply)==-EBUSY);
  assert(reply.raw==0xabcdef01);no_mutation();
  l2_model_complete(&model);l2_model_trace_reset(&model);
  assert(model.port_limits[17]==(operation?0x5a5a1fff:0xa5a50000));
  /* A new transaction cannot silently acquire somebody else's timed-out lease. */
  assert(rtl_l2_port_limit_read(&io,17,&result)==-EOPNOTSUPP && result==0xc0ffee00);no_mutation();
  assert(!rtl_l2_fdb_command_mode(&io));assert(model.registers[RTL_L2_FDB_CONTROL / 4]==control);
  l2_model_trace_reset(&model);
  assert(!rtl_l2_port_limit_read(&io,17,&result) && result==model.port_limits[17]);cases++;
 }
 /* Successful transport still may not release the lease if postconditions
  * fail. No partially validated read result reaches the caller. */
 for(unsigned int changed=0;changed<2;changed++) {
  model.registers[RTL_L2_FDB_CONTROL / 4]=control;result=0xc0ffee00;
  model.complete_busy_fdb=changed==0;model.complete_enable_learning=changed==1;
  l2_model_trace_reset(&model);
  assert(rtl_l2_port_limit_read(&io,17,&result)==-EBUSY && result==0xc0ffee00);
  assert(!(model.registers[RTL_L2_FDB_CONTROL / 4]&RTL_L2_FDB_CMD_MODE));
  model.complete_busy_fdb=model.complete_enable_learning=false;
  model.registers[RTL_L2_FDB_ACCESS / 4]=0;
  model.registers[RTL_L2_FDB_CONTROL / 4]|=RTL_L2_FDB_LEARN_DISABLE;
  l2_model_trace_reset(&model);assert(!rtl_l2_fdb_command_mode(&io));cases++;
 }
}

static void mode_lease_faults(void)
{
 struct rtl_dq_io io = l2_model_io(&model);
 const unsigned int control=0x1a123456U|RTL_L2_FDB_CMD_MODE|RTL_L2_FDB_LEARN_DISABLE;
 const unsigned int invalid[]={UINT_MAX,control|RTL_L2_FDB_INFO_INIT};
 unsigned int value;
 struct rtl_l2_fdb_result result,sentinel;
 memset(&sentinel,0xa5,sizeof(sentinel));
 l2_model_init(&model);l2_model_trace_reset(&model);
 assert(rtl_l2_fdb_control_read(&io,NULL)==-EINVAL);no_io();
 /* Neither an unreadable control register nor an unowned initialization
  * state permits DATA writes, command submission or mode recovery. */
 for(unsigned int i=0;i<2;i++){
  l2_model_init(&model);model.registers[RTL_L2_FDB_CONTROL/4]=invalid[i];
  value=0xc0ffee00;result=sentinel;int expected=i?-EOPNOTSUPP:-EIO;
  assert(rtl_l2_fdb_mode_idle(&io)==expected);
  assert(rtl_l2_fdb_command_mode(&io)==expected);
  assert(rtl_l2_port_limit_read(&io,17,&value)==expected);
  assert(rtl_l2_port_limit_write(&io,17,7)==expected);
  assert(rtl_l2_fdb_command(&io,RTL_L2_FDB_READ,0,marker,&result)==expected);
  assert(value==0xc0ffee00 && !memcmp(&result,&sentinel,sizeof(result)));
  assert(model.registers[RTL_L2_FDB_CONTROL/4]==invalid[i]);no_mutation();cases++;
 }
 /* A lost mode write must be detected before even DATA staging. A lost
  * CMD restore must not expose a successfully read value to the caller. */
 for(unsigned int operation=0;operation<2;operation++)for(unsigned int phase=1;phase<=2;phase++){
  l2_model_init(&model);model.registers[RTL_L2_FDB_CONTROL/4]=control;
  model.port_limits[17]=0x1234;value=0xc0ffee00;model.ignore_control_write_at=phase;
  int ret=operation?rtl_l2_port_limit_write(&io,17,9):rtl_l2_port_limit_read(&io,17,&value);
  assert(ret==-EIO && value==0xc0ffee00 && model.commands==phase-1);
  if(phase==1){assert(model.writes==1 && model.port_limits[17]==0x1234);}
  else {
   assert(!(model.registers[RTL_L2_FDB_CONTROL/4]&RTL_L2_FDB_CMD_MODE));
   assert(model.port_limits[17]==(operation?9U:0x1234U));
  }
  model.ignore_control_write_at=0;l2_model_trace_reset(&model);
  assert(!rtl_l2_fdb_command_mode(&io));
  assert(model.registers[RTL_L2_FDB_CONTROL/4]==control);
  assert(!rtl_l2_port_limit_read(&io,17,&value) && value==model.port_limits[17]);cases++;
 }
 /* The owner-only recovery path has the same verified postcondition. */
 l2_model_init(&model);model.registers[RTL_L2_FDB_CONTROL/4]=control&~RTL_L2_FDB_CMD_MODE;
 model.ignore_control_write_at=1;
 assert(rtl_l2_fdb_command_mode(&io)==-EIO && !model.commands);
 assert(!(model.registers[RTL_L2_FDB_CONTROL/4]&RTL_L2_FDB_CMD_MODE));
 model.ignore_control_write_at=0;assert(!rtl_l2_fdb_command_mode(&io));cases++;
 /* Every CTRL read boundary can be independently unreadable. The first
  * two precede the request; the fifth is the final CMD readback. */
 for(unsigned int phase=1;phase<=5;phase++){
  l2_model_init(&model);model.registers[RTL_L2_FDB_CONTROL/4]=control;
  model.port_limits[17]=0x1234;value=0xc0ffee00;
  model.corrupt_control_read_at=phase;model.corrupt_control_read_value=UINT_MAX;
  assert(rtl_l2_port_limit_read(&io,17,&value)==-EIO && value==0xc0ffee00);
  assert(model.commands==(phase>2) && model.control_writes==(phase==1?0U:phase==5?2U:1U));
  model.corrupt_control_read_at=0;l2_model_trace_reset(&model);
  assert(!rtl_l2_fdb_command_mode(&io));cases++;
 }
 /* Readback checks all stable bits, as well as CMD and learning-stop.
  * Corruption after either mode write cannot be reported as success. */
 for(unsigned int phase=1;phase<=2;phase++)for(unsigned int fault=0;fault<4;fault++){
  l2_model_init(&model);model.registers[RTL_L2_FDB_CONTROL/4]=control;value=0xc0ffee00;
  unsigned int target=phase==1?control&~RTL_L2_FDB_CMD_MODE:control;
  model.corrupt_control_write_at=phase;
  model.corrupt_control_value=fault==0?UINT_MAX:fault==1?target|RTL_L2_FDB_INFO_INIT:
   fault==2?target&~RTL_L2_FDB_LEARN_DISABLE:target^(1U<<13);
  int expected=fault==1?-EOPNOTSUPP:fault==2?-EBUSY:-EIO;
  assert(rtl_l2_port_limit_read(&io,17,&value)==expected && value==0xc0ffee00);
  assert(model.commands==phase-1 && model.control_writes==phase);cases++;
 }
 /* An unexpected CMD/init/unreadable state after transport completion
  * keeps output private and does not attempt a blind control restoration. */
 for(unsigned int fault=0;fault<3;fault++){
  l2_model_init(&model);model.registers[RTL_L2_FDB_CONTROL/4]=control;value=0xc0ffee00;
  model.complete_control_override=true;
  model.complete_control_value=fault==0?UINT_MAX:fault==1?control|RTL_L2_FDB_INFO_INIT:control;
  assert(rtl_l2_port_limit_read(&io,17,&value)==(fault==1?-EOPNOTSUPP:-EIO));
  assert(value==0xc0ffee00 && model.commands==1 && model.control_writes==1);cases++;
 }
 /* The SDK scan trigger is XOR/edge state: both levels are valid, and a
  * completion/data-read producer can change it without authorizing us to
  * toggle it back. Other live controls are preserved by the same fresh RMW. */
 for(unsigned int level=0;level<2;level++)for(unsigned int point=0;point<3;point++){
  l2_model_init(&model);
  unsigned int baseline=(control&~RTL_L2_FDB_SW_AGE_SCAN)|(level?RTL_L2_FDB_SW_AGE_SCAN:0);
  unsigned int changes=RTL_L2_FDB_SW_AGE_SCAN|(1U<<13);
  model.registers[RTL_L2_FDB_CONTROL/4]=baseline;model.port_limits[17]=0x1234;
  if(point==1)model.complete_control_xor=changes;
  if(point==2)model.after_limit_data_control_xor=changes;
  value=0xc0ffee00;assert(!rtl_l2_port_limit_read(&io,17,&value) && value==0x1234);
  assert(model.registers[RTL_L2_FDB_CONTROL/4]==(point?baseline^changes:baseline));
  model.complete_control_xor=model.after_limit_data_control_xor=0;
  model.registers[RTL_L2_FDB_CONTROL/4]^=RTL_L2_FDB_SW_AGE_SCAN;
  unsigned int steady=model.registers[RTL_L2_FDB_CONTROL/4];l2_model_trace_reset(&model);
  assert(!rtl_l2_port_limit_write(&io,17,9));assert(model.registers[RTL_L2_FDB_CONTROL/4]==steady);cases++;
 }
 /* A final state change while reading LIMIT DATA must be checked before
  * the CMD write. In particular initialization is never replayed. */
 const unsigned int late_changes[]={RTL_L2_FDB_CMD_MODE,RTL_L2_FDB_INFO_INIT,RTL_L2_FDB_LEARN_DISABLE};
 for(unsigned int i=0;i<3;i++){
  l2_model_init(&model);model.registers[RTL_L2_FDB_CONTROL/4]=control;
  model.after_limit_data_control_xor=late_changes[i];value=0xc0ffee00;
  assert(rtl_l2_port_limit_read(&io,17,&value)==(i==1?-EOPNOTSUPP:i==2?-EBUSY:-EIO));
  assert(value==0xc0ffee00 && model.commands==1 && model.control_writes==1);cases++;
 }
 /* Ordinary FDB operations do not acquire a learning-stop lease, but must
  * reject a bad mode/control both before staging and after completion. */
 for(unsigned int state=0;state<2;state++){
  l2_model_init(&model);model.registers[RTL_L2_FDB_CONTROL/4]=
   (control&~(RTL_L2_FDB_LEARN_DISABLE|RTL_L2_FDB_SW_AGE_SCAN))|(state?RTL_L2_FDB_SW_AGE_SCAN:0);
  model.complete_control_xor=RTL_L2_FDB_SW_AGE_SCAN;result=sentinel;
  assert(!rtl_l2_fdb_command(&io,RTL_L2_FDB_READ,0,marker,&result));
  assert(result.status==RTL_L2_FDB_STATUS_HIT && !model.control_writes);cases++;
 }
 for(unsigned int fault=0;fault<3;fault++){
  l2_model_init(&model);model.registers[RTL_L2_FDB_CONTROL/4]=control;result=sentinel;
  model.complete_control_override=true;
  model.complete_control_value=fault==0?UINT_MAX:fault==1?control|RTL_L2_FDB_INFO_INIT:control&~RTL_L2_FDB_CMD_MODE;
  assert(rtl_l2_fdb_command(&io,RTL_L2_FDB_APPEND,0,marker,&result)==(fault==1?-EOPNOTSUPP:-EIO));
  assert(!memcmp(&result,&sentinel,sizeof(result)) && model.commands==1 && model.fdb_effects==1);
  assert(!model.control_writes);cases++;
 }
}

int main(void)
{
 l2_model_init(&model);
 table_cases(); fdb_cases(); mac_limit_cases(); mode_lease_faults();
 printf("L2 production transactions: %u table rows; %u fault/status/boundary cases; late completion, snapshots and bounded scans PASS (host model only)\n",
        rows_checked, cases);
 return 0;
}
'''


def main():
    # Mutation checks deliberately abort assertions, without producing cores.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    table_header = (DRIVERS / "rtl9617c-l2-table.h").read_text()
    mutations = {
        "missing_busy_gate": (
            "if (io->read(io->context, layout.access) & RTL_L2_ACCESS_BUSY)",
            "if (0 && (io->read(io->context, layout.access) & RTL_L2_ACCESS_BUSY))",
        ),
        "snapshot_overwrite": ("if (snapshot->valid)", "if (0 && snapshot->valid)"),
        "scan_accepts_stale_index": (
            "next.status != RTL_L2_FDB_STATUS_HIT || next.index < start ||",
            "next.status != RTL_L2_FDB_STATUS_HIT || 0 ||",
        ),
        "mac_limit_wrong_mode": (
            "RTL_L2_FDB_CONTROL, control & ~RTL_L2_FDB_CMD_MODE",
            "RTL_L2_FDB_CONTROL, control",
        ),
        "mac_limit_live_learning": (
            "if (!(*control & RTL_L2_FDB_LEARN_DISABLE))",
            "if (0 && !(*control & RTL_L2_FDB_LEARN_DISABLE))",
        ),
        "mode_write_readback_ignored": (
            "return ((control ^ expected) & ~RTL_L2_FDB_SW_AGE_SCAN) ? -EIO : 0;",
            "return control == expected ? 0 : 0;",
        ),
        "mode_recovery_failure_ignored": (
            "return rtl_l2_fdb_mode_verify(io, control | RTL_L2_FDB_CMD_MODE);",
            "return (rtl_l2_fdb_mode_verify(io, control | RTL_L2_FDB_CMD_MODE), 0);",
        ),
        "mode_restore_exposes_unverified_result": (
            "\tret = rtl_l2_fdb_mode_verify(io, control | RTL_L2_FDB_CMD_MODE);",
            "\tif (!write) *word = result;\n\tret = rtl_l2_fdb_mode_verify(io, control | RTL_L2_FDB_CMD_MODE);",
        ),
        "mode_restore_replays_old_toggle": (
            "\t * never replay the pre-lease control snapshot or clear a trigger bit. */\n\tret = rtl_l2_fdb_mode_control(io, &control);",
            "\t * never replay the pre-lease control snapshot or clear a trigger bit. */\n\tret = 0;",
        ),
        "mode_accepts_unowned_init": (
            "if (value & RTL_L2_FDB_INFO_INIT)",
            "if (0 && (value & RTL_L2_FDB_INFO_INIT))",
        ),
        "mode_rejects_valid_scan_toggle": (
            "if (value & RTL_L2_FDB_INFO_INIT)",
            "if (value & RTL_L2_FDB_SW_AGE_SCAN) return -EBUSY;\n\tif (value & RTL_L2_FDB_INFO_INIT)",
        ),
        "mode_accepts_all_ones": (
            "if (value == ~0U)", "if (0 && value == ~0U)",
        ),
        "fdb_completion_mode_not_checked": (
            "if (!(control & RTL_L2_FDB_CMD_MODE))\n\t\treturn -EIO;",
            "if (0 && !(control & RTL_L2_FDB_CMD_MODE))\n\t\treturn -EIO;",
        ),
    }
    environment = dict(os.environ)
    # ASan/UBSan still run; LeakSanitizer cannot enumerate threads under the
    # sandbox's process tracer. This fixture uses static storage, not malloc.
    environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
    environment.setdefault("UBSAN_OPTIONS", "halt_on_error=1")
    with tempfile.TemporaryDirectory(prefix="l2-transactions-") as directory:
        temporary = Path(directory)
        source = temporary / "test.c"
        source.write_text(TEST)
        for name in ["production", *mutations]:
            include = temporary / name
            include.mkdir()
            if name != "production":
                old, new = mutations[name]
                if old not in table_header:
                    raise AssertionError(f"Mutation anchor changed: {name}")
                (include / "rtl9617c-l2-table.h").write_text(table_header.replace(old, new))
            binary = temporary / (name + ".bin")
            subprocess.run([
                os.environ.get("CC", "cc"), "-std=c11", "-O1", "-g",
                "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
                "-fno-sanitize-recover=all", "-fno-omit-frame-pointer",
                "-I", str(include), "-I", str(FIXTURES), "-I", str(DRIVERS),
                str(source), "-o", str(binary),
            ], check=True, cwd=temporary)
            result = subprocess.run([str(binary)], env=environment, cwd=temporary,
                                    text=True, capture_output=True)
            if name == "production":
                if result.returncode:
                    raise AssertionError(result.stdout + result.stderr)
                print(result.stdout, end="")
            elif result.returncode == 0 or "Assertion" not in result.stderr:
                raise AssertionError(
                    f"Mutation was not rejected by an invariant assertion: {name}\n" + result.stderr
                )
            else:
                print(f"Runtime regression mutant rejected: {name}", flush=True)
    evidence = {
        "production_headers": {
            name: hashlib.sha256((DRIVERS / name).read_bytes()).hexdigest()
            for name in ["rtl9617c-l2-format.h", "rtl9617c-l2-table.h"]
        },
        "sanitizers": ["address", "undefined"],
        "mutations_rejected": list(mutations),
        "hardware_verified": False,
        "throughput_measured": False,
    }
    (ROOT / "artifacts").mkdir(exist_ok=True)
    (ROOT / "artifacts/l2-table-transactions.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"L2 transaction oracle self-check: all {len(mutations)} deliberately broken production variants rejected")


if __name__ == "__main__":
    main()
