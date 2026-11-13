#!/usr/bin/env python3
"""Execute staged PON offload/CPU/stop changes, failure readback and retries.

The actual production mode/state functions are executed: failures retain the
committed FE owner and partial PDC map, not a claimed atomic rollback.
"""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
drivers = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
source = (drivers / 'rtl9617c-pon-pdc.c').read_text()

def function(name):
    start = re.search(r'^(?:static )?(?:int|ssize_t) ' + name + r'\(', source, re.M).start()
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

model = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "rtl9617c-pon-mode.h"
typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define FIELD_GET(mask,value) (((value)&(mask))>>__builtin_ctz(mask))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define PAGE_SIZE 4096
#define sysfs_emit(buf,...) snprintf(buf,PAGE_SIZE,__VA_ARGS__)
#define scnprintf snprintf
struct rtl9617c_pon {int mode,lock,control_lock,pdc_error;bool fe_enabled,fe_cpu_path,pdc_configured,puc_configured,traffic_enabled;void *ni_dev,*mac;unsigned char pdc_source[64];};
static int failure,disables,cpu_calls,enable_calls,pdc_failure=-1;
static unsigned int regs[0xa000/4],pdc[256][2],pdc_writes;
static void mutex_lock(int *lock){assert(!*lock);*lock=1;}
static void mutex_unlock(int *lock){assert(*lock);*lock=0;}
#define lockdep_assert_held(lock) assert(*(lock))
static int rtl9617c_ni_fe_enable(void *dev){(void)dev;enable_calls++;return failure;}
static int rtl9617c_ni_fe_cpu_path(void *dev){(void)dev;cpu_calls++;return failure;}
static int rtl9617c_ni_fe_disable(void *dev){(void)dev;disables++;return failure;}
static int rtl_pdc_access(struct rtl9617c_pon *p,unsigned int entry,bool write){
 (void)p;assert(entry<256);
 if((int)entry==pdc_failure)return -EIO;
 if(write){pdc[entry][0]=regs[0x9028/4];pdc[entry][1]=regs[0x9024/4];pdc_writes++;}
 else{regs[0x9028/4]=pdc[entry][0];regs[0x9024/4]=pdc[entry][1];}
 return 0;
}
static void writel(u32 v,void *p){*(u32 *)p=v;}
static u32 readl(void *p){return *(u32 *)p;}
'''
test = r'''
static void assert_business(unsigned int destination,bool bypass){
 for(unsigned int i=8;i<256;i++){
  assert(((pdc[i][0]>>3)&63)==destination && !!(pdc[i][0]&BIT(15))==bypass);
  assert(((pdc[i][0]>>9)&63)==7 && pdc[i][1]==(i<<4));
 }
}
static void assert_readback(struct rtl9617c_pon *pon,bool configured,int error){
 char state[PAGE_SIZE],prefix[64];
 assert(rtl_pon_pdc_state(pon,state)>0);
 snprintf(prefix,sizeof(prefix),"configured=%u error=%d ",configured,error);
 assert(!strncmp(state,prefix,strlen(prefix)));
}
static void assert_epon_business(unsigned int destination,bool bypass){
 for(unsigned int entry=0;entry<64;entry++)for(unsigned int bank=0;bank<2;bank++){
  unsigned int index=entry|(bank<<7);
  assert(((pdc[index][0]>>3)&63)==destination && !!(pdc[index][0]&BIT(15))==bypass);
  assert(((pdc[index][0]>>9)&63)==7 && pdc[index][1]==entry<<4);
 }
}
int main(void){
 for(int mode=RTL_PON_EPON_1G;mode<RTL_PON_MODE_COUNT;mode++){
  struct rtl9617c_pon pon={.mode=mode,.control_lock=1,.fe_enabled=true,.mac=regs};
  failure=-ETIMEDOUT;disables=0;
  assert(rtl_pon_fe_stop_locked(&pon)==-ETIMEDOUT);
  assert(pon.fe_enabled && disables==1 && !pon.lock);
  failure=0;
  assert(!rtl_pon_fe_stop_locked(&pon));
  assert(!pon.fe_enabled && !pon.fe_cpu_path && disables==2 && !pon.lock);
  pon.fe_cpu_path=true;failure=-ETIMEDOUT;
  assert(rtl_pon_fe_stop_locked(&pon)==-ETIMEDOUT && pon.fe_cpu_path);
  failure=0;assert(!rtl_pon_fe_stop_locked(&pon) && !pon.fe_cpu_path);
  memset(pon.pdc_source,32,sizeof(pon.pdc_source));
  pon.pdc_configured=pon.puc_configured=pon.traffic_enabled=true;
  pdc_failure=rtl_pon_mode_is_epon(mode)?0:8;
  assert(rtl_pon_fe_configure_locked(&pon,true)==-EIO && pon.fe_enabled && !pon.lock);
  pdc_failure=-1;pon.pdc_configured=false;
  assert(!rtl_pon_fe_stop_locked(&pon) && !pon.fe_enabled && !pon.fe_cpu_path);
  /* Successful cleanup without a map cannot repair the configuration fault. */
  assert(pon.pdc_error==-EIO);
  assert(rtl_pon_fe_configure_locked(&pon,true)==-EAGAIN);
  assert(pon.pdc_error==-EIO && !pon.pdc_configured);
  assert_readback(&pon,false,-EIO);
 }
 for(int mode=RTL_PON_EPON_1G;mode<RTL_PON_MODE_COUNT;mode++){
  struct rtl9617c_pon pon={.mode=mode,.control_lock=1,.mac=regs,
   .pdc_configured=true,.puc_configured=true,.traffic_enabled=true};
  bool epon=rtl_pon_mode_is_epon(mode);
  unsigned int first=epon?0:8;
  unsigned int control[256][2];
  for(unsigned int i=0;i<256;i++){
   pdc[i][0]=(16<<3)|(7<<9)|BIT(15)|(i<8&&!epon?BIT(31)|6:0);
   pdc[i][1]=(epon?(i&63):i)<<4;
  }
  for(unsigned int i=0;i<64;i++)pon.pdc_source[i]=32+i;
  memcpy(control,pdc,sizeof(control));
  pdc_failure=17;failure=0;
  assert(rtl_pon_fe_configure_locked(&pon,true)==-EIO);
  assert(pon.fe_enabled && !pon.fe_cpu_path && pon.pdc_configured && !pon.lock);
  assert(((pdc[first][0]>>3)&63)==24 && !(pdc[first][0]&BIT(15)));
  assert(((pdc[17][0]>>3)&63)==16 && (pdc[17][0]&BIT(15)));
  assert_readback(&pon,true,-EIO);
  /* The error remains visible until the entire failed transition is retried. */
  pdc_failure=-1;
  assert(!rtl_pon_fe_configure_locked(&pon,true));
  assert(pon.fe_enabled && !pon.fe_cpu_path && pon.pdc_configured && !pon.lock);
  assert_readback(&pon,true,0);
  if(epon)assert_epon_business(24,false);else assert_business(24,false);
  if(epon){
   for(unsigned int i=64;i<256;i++)if(i&64)assert(!memcmp(control[i],pdc[i],sizeof(pdc[i])));
  }else assert(!memcmp(control,pdc,8*sizeof(pdc[0])));
  /* A partial stop cannot relinquish the FE owner before every map changes. */
  pdc_failure=17;int before=disables;
  assert(rtl_pon_fe_stop_locked(&pon)==-EIO);
  assert(pon.fe_enabled && !pon.fe_cpu_path && pon.pdc_configured && disables==before);
  assert(((pdc[first][0]>>3)&63)==16 && (pdc[first][0]&BIT(15)));
  assert(((pdc[17][0]>>3)&63)==24 && !(pdc[17][0]&BIT(15)));
  assert_readback(&pon,true,-EIO);
  pdc_failure=-1;
  assert(!rtl_pon_fe_stop_locked(&pon));
  assert(!pon.fe_enabled && !pon.fe_cpu_path && pon.pdc_configured && disables==before+1);
  assert_readback(&pon,true,0);
  if(epon)assert_epon_business(16,true);else assert_business(16,true);
 }
 for(int mode=RTL_PON_GPON;mode<RTL_PON_MODE_COUNT;mode++){
  struct rtl9617c_pon pon={.mode=mode,.control_lock=1,.mac=regs,
   .pdc_configured=true,.puc_configured=true};
  unsigned int omci[8][2];
  for(unsigned int i=0;i<256;i++){
   pdc[i][0]=(16<<3)|(7<<9)|BIT(15)|(i<8?BIT(31)|6:0);
   pdc[i][1]=i<<4;
  }
  memcpy(omci,pdc,sizeof(omci));
  int before=cpu_calls;
  assert(!rtl_pon_fe_configure_locked(&pon,false));
  assert(pon.fe_cpu_path && !pon.fe_enabled && cpu_calls==before+1);
  assert_business(24,false);assert(!memcmp(omci,pdc,sizeof(omci)));
  assert(!rtl_pon_fe_configure_locked(&pon,true));
  assert(pon.fe_enabled && !pon.fe_cpu_path);assert_business(24,false);
  assert(!rtl_pon_fe_configure_locked(&pon,false));
  assert(!pon.fe_enabled && pon.fe_cpu_path);assert_business(24,false);
  assert(!memcmp(omci,pdc,sizeof(omci)));
  /* A failed CPU transition cannot move PDC or claim new NI ownership. */
  assert(!rtl_pon_fe_configure_locked(&pon,true));
  unsigned int writes=pdc_writes;failure=-ETIMEDOUT;
  assert(rtl_pon_fe_configure_locked(&pon,false)==-ETIMEDOUT);
  assert(pon.fe_enabled && !pon.fe_cpu_path && pdc_writes==writes);
  failure=0;assert(!rtl_pon_fe_configure_locked(&pon,false));
  assert(!rtl_pon_fe_stop_locked(&pon) && !pon.fe_cpu_path && !pon.fe_enabled);
  assert_business(16,true);assert(!memcmp(omci,pdc,sizeof(omci)));
  /* CPU mode also commits before the map; do not claim rollback on a fault. */
  pdc_failure=17;
  assert(rtl_pon_fe_configure_locked(&pon,false)==-EIO);
  assert(!pon.fe_enabled && pon.fe_cpu_path && pon.pdc_configured && !pon.lock);
  assert(((pdc[8][0]>>3)&63)==24 && ((pdc[17][0]>>3)&63)==16);
  assert_readback(&pon,true,-EIO);
  pdc_failure=-1;
  assert(!rtl_pon_fe_configure_locked(&pon,false));
  assert(!pon.fe_enabled && pon.fe_cpu_path && pon.pdc_configured && !pon.lock);
  assert_business(24,false);assert(!memcmp(omci,pdc,sizeof(omci)));
  assert_readback(&pon,true,0);
 }
 puts("PON FE: all-mode staged failures retain owners/maps, actual error readback and retry clear; CPU trap and OMCI isolation passed");
}
'''
constants = '\n'.join(re.findall(r'^#define .*$', source, re.M))
functions = '\n'.join(function(n) for n in ['rtl_pdc_write', 'rtl_pon_fe_set_locked', 'rtl_pon_fe_configure_locked', 'rtl_pon_fe_stop_locked', 'rtl_pon_pdc_state'])
with tempfile.TemporaryDirectory(prefix='pon-fe-stop-', dir=root / 'artifacts') as directory:
    directory = Path(directory)
    cfile = directory / 'test.c'
    binary = directory / 'test'
    cfile.write_text(model + constants + '\n' + functions + test)
    subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    '-I', str(drivers), str(cfile), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
