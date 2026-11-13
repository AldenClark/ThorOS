#!/usr/bin/env python3
"""Exercise FE DATA-window exclusion after a timed-out indirect command.

Production helpers are compiled unchanged. This is a fault-injection model,
not a claim that RTL9617C's hardware timeout/recovery has been exercised.
"""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
drivers = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "rtl9617c-fe-pipeline.h"
#include "rtl9617c-l2-table.h"

struct model {
 unsigned int registers[0x4000/4],writes,commands;
 bool leave_busy,false_success,limit_busy_after_fdb;
};
static unsigned int read_reg(void *context,unsigned int reg) {
 struct model *m=context;
 assert(!(reg&3) && reg<sizeof(m->registers));
 return m->registers[reg/4];
}
static void write_reg(void *context,unsigned int reg,unsigned int value) {
 struct model *m=context;
 assert(!(reg&3) && reg<sizeof(m->registers));
 m->writes++;m->registers[reg/4]=value;
}
static int command(void *context,unsigned int reg,unsigned int value) {
 struct model *m=context;
 unsigned int busy=(reg==0x38b0 || reg==0x38e0 || reg==0x393c)?1U:0x80000000U;
 assert(!(m->registers[reg/4]&busy));
 m->commands++;
 m->registers[reg/4]=m->leave_busy?value:0;
 if(reg==0x1ca0 && m->limit_busy_after_fdb)
  m->registers[0x1cb4/4]=RTL_L2_ACCESS_BUSY;
 return m->leave_busy && !m->false_success?-ETIMEDOUT:0;
}
static void stuck(struct model *m,unsigned int reg) {
 memset(m,0,sizeof(*m));
 m->registers[reg/4]=(reg==0x38b0 || reg==0x38e0 || reg==0x393c)?1U:0x80000000U;
}
static void untouched(struct model *m) {assert(!m->writes && !m->commands);}

int main(void) {
 struct model m={};
 const struct rtl_dq_io io={&m,read_reg,write_reg,command};
 const unsigned int words[8]={1,2,3,4,5,6,7,8};
 unsigned int fdb[4]={1,2,3,4},result=0x12345678;
 struct rtl_fe_cam_protocol binding={.bank=8,.index=3,.created=1};
 unsigned int header[RTL_FE_HEADER_WORDS]={},crc32=0x12345678;
 unsigned short crc16=0x1234;

 stuck(&m,0x3910);
 assert(rtl_fe_mask_write(&io,63,words)==-EBUSY);untouched(&m);
 stuck(&m,0x33b0);
 assert(rtl_fe_classifier_write(&io,1024,words)==-EBUSY);untouched(&m);
 stuck(&m,0x3200);
 assert(rtl_fe_source_mac_write(&io,3,words)==-EBUSY);untouched(&m);
 assert(rtl_fe_cam_protocol_put(&io,&binding)==-EBUSY && binding.created);untouched(&m);
 stuck(&m,0x1ca0);
 assert(rtl_fe_fdb_command(&io,0x85,fdb,&result)==-EBUSY);
 assert(result==0x12345678);untouched(&m);
 stuck(&m,0x1cb4);
 m.registers[0x1c00/4]=RTL_L2_FDB_LEARN_DISABLE;
 m.registers[0x1cb0/4]=0x76543210;
 assert(rtl_fe_fdb_command(&io,0x45,fdb,&result)==-EBUSY);
 assert(result==0x12345678 && m.registers[0x1c00/4]==RTL_L2_FDB_LEARN_DISABLE);
 assert(m.registers[0x1cb0/4]==0x76543210);untouched(&m);
 stuck(&m,0x38b0);
 assert(rtl_fe_cache_command(&io,17,0x1234,1)==-EBUSY);untouched(&m);
 stuck(&m,0x38e0);
 assert(rtl_fe_crc_hardware(&io,header,63,&crc32,&crc16)==-EBUSY);
 assert(crc32==0x12345678 && crc16==0x1234);untouched(&m);

 /* Timeout may leave a CAM write in flight. The next restore must not
  * modify any of the shared DATA registers until completion is observed. */
 memset(&m,0,sizeof(m));m.leave_busy=true;
 assert(rtl_fe_source_mac_write(&io,3,words)==-ETIMEDOUT);
 unsigned int staged[5],writes=m.writes,commands=m.commands;
 for(unsigned int i=0;i<5;i++)staged[i]=m.registers[(0x3214-i*4)/4];
 assert(rtl_fe_cam_protocol_put(&io,&binding)==-EBUSY && binding.created);
 assert(m.writes==writes && m.commands==commands);
 for(unsigned int i=0;i<5;i++)assert(staged[i]==m.registers[(0x3214-i*4)/4]);
 m.registers[0x3200/4]=0;m.leave_busy=false;
 assert(!rtl_fe_cam_protocol_put(&io,&binding) && !binding.created);
 assert(m.commands==commands+1);

 /* cpu_opt_mode is part of the outstanding FDB transaction, not merely a
  * wrapper convenience. A timeout must not switch it back to indirect mode.
  * The fabric lifecycle owner, not a later stateless command, restores the
  * original mode once every operation has drained. */
 for(unsigned int initial_mode=0;initial_mode<2;initial_mode++) {
  memset(&m,0,sizeof(m));m.leave_busy=true;
  unsigned int control=0x12345U|(initial_mode<<31);
  m.registers[0x1c00/4]=control;result=0x12345678;
  assert(rtl_fe_fdb_command(&io,0x45,fdb,&result)==-ETIMEDOUT);
  assert(m.registers[0x1c00/4]==(control|0x80000000U) && result==0x12345678);
  writes=m.writes;commands=m.commands;
  for(unsigned int i=0;i<4;i++)staged[i]=m.registers[(0x1cb0-i*4)/4];
  assert(rtl_fe_fdb_command(&io,0x85,fdb,&result)==-EBUSY);
  assert(m.writes==writes && m.commands==commands);
  for(unsigned int i=0;i<4;i++)assert(staged[i]==m.registers[(0x1cb0-i*4)/4]);
  m.registers[0x1ca0/4]=0;m.leave_busy=false;
  assert(!rtl_fe_fdb_command(&io,0x85,fdb,&result));
  assert(m.registers[0x1c00/4]==(control|0x80000000U));
  /* Only an external owner holding the original snapshot may restore it. */
  write_reg(&m,0x1c00,control);
  assert(m.registers[0x1c00/4]==control);
 }
 memset(&m,0,sizeof(m));m.leave_busy=true;m.false_success=true;
 assert(rtl_fe_fdb_command(&io,0x45,fdb,&result)==-EBUSY);
 assert(m.registers[0x1c00/4]&0x80000000U);

 /* The production MAC-limit helper really leases mode0 and can return
  * before that transaction completes. The subsequent L3 cleanup must not
  * flip mode1 or touch any DATA/return register during this late command. */
 memset(&m,0,sizeof(m));m.leave_busy=true;
 unsigned int limit_control=RTL_L2_FDB_CMD_MODE|RTL_L2_FDB_LEARN_DISABLE|0x12345;
 m.registers[0x1c00/4]=limit_control;
 assert(rtl_l2_port_limit_write(&io,3,123)==-ETIMEDOUT);
 assert(m.registers[0x1c00/4]==(limit_control&~RTL_L2_FDB_CMD_MODE));
 assert(m.registers[0x1cb4/4]&RTL_L2_ACCESS_BUSY);
 writes=m.writes;commands=m.commands;result=0x12345678;
 unsigned int registers_before[sizeof(m.registers)/sizeof(m.registers[0])];
 memcpy(registers_before,m.registers,sizeof(registers_before));
 assert(rtl_fe_fdb_command(&io,0x85,fdb,&result)==-EBUSY);
 assert(result==0x12345678 && m.writes==writes && m.commands==commands);
 assert(!memcmp(registers_before,m.registers,sizeof(registers_before)));
 assert(rtl_l2_fdb_command_mode(&io)==-EBUSY);
 assert(m.writes==writes && m.commands==commands);
 m.registers[0x1cb4/4]=0;m.leave_busy=false;
 assert(!rtl_l2_fdb_command_mode(&io));
 assert(!rtl_fe_fdb_command(&io,0x85,fdb,&result));
 assert(m.registers[0x1c00/4]==limit_control);

 /* Even a reported-success FDB command is not permission to restore mode
  * when the shared limit window is busy. No writes occur after the check. */
 memset(&m,0,sizeof(m));m.limit_busy_after_fdb=true;
 result=0x12345678;
 unsigned int fdb_before[4];memcpy(fdb_before,fdb,sizeof(fdb_before));
 assert(rtl_fe_fdb_command(&io,0x45,fdb,&result)==-EBUSY);
 assert(m.writes==6 && m.commands==1);
 assert(m.registers[0x1c00/4]&RTL_L2_FDB_CMD_MODE);
 assert(result==0x12345678 && !memcmp(fdb,fdb_before,sizeof(fdb_before)));

 memset(&m,0,sizeof(m));
 assert(!rtl_fe_mask_write(&io,63,words) && m.commands==2);
 assert(!rtl_fe_classifier_write(&io,1024,words) && m.commands==3);
 assert(!rtl_fe_source_mac_write(&io,3,words) && m.commands==4);
 assert(!rtl_fe_fdb_command(&io,0x85,fdb,&result) && m.commands==5);
 assert(!rtl_fe_cache_command(&io,17,0x1234,1) && m.commands==6);
 puts("FE indirect windows: busy/timeout never overwrites DATA or FDB/limit shared mode; real limit-timeout lease and post-completion exclusion; CAM ownership, idle recovery, bit0/bit31 checks passed");
}
'''

with tempfile.TemporaryDirectory(prefix='fe-window-') as directory:
    work = Path(directory)
    source, binary = work / 'window.c', work / 'window'
    source.write_text(fixture)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    '-I' + str(drivers), str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
