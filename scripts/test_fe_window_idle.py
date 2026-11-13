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

struct model {
 unsigned int registers[0x4000/4],writes,commands;
 bool leave_busy;
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
 return m->leave_busy?-ETIMEDOUT:0;
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

 memset(&m,0,sizeof(m));
 assert(!rtl_fe_mask_write(&io,63,words) && m.commands==2);
 assert(!rtl_fe_classifier_write(&io,1024,words) && m.commands==3);
 assert(!rtl_fe_source_mac_write(&io,3,words) && m.commands==4);
 assert(!rtl_fe_fdb_command(&io,0x85,fdb,&result) && m.commands==5);
 assert(!rtl_fe_cache_command(&io,17,0x1234,1) && m.commands==6);
 puts("FE indirect windows: busy/timeout never overwrites DATA; CAM restore retains ownership; idle recovery and bit0/bit31 checks passed");
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
