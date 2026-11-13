#!/usr/bin/env python3
"""Execute production ITU PDC/GEM setup: prepare CPU trap before business RX.

Reuses the existing GEM hardware model; this is a host ordering/state oracle,
not a test of the optical line or hardware packet editor.
"""
import ast
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
drivers = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--revision', help='Run the same behavior oracle against an older production commit')
args = parser.parse_args()

def production_source(file):
    relative = str((drivers / file).relative_to(root))
    return subprocess.check_output(['git', 'show', args.revision + ':' + relative], cwd=root, text=True) if args.revision else (drivers / file).read_text()

def function(file, name):
    source = production_source(file)
    start = re.search(r'^(?:static )?int ' + name + r'\(', source, re.M).start()
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

fixture_source = ast.parse((root / 'scripts/test_itu_gem_direction.py').read_text())
fixture = next(ast.literal_eval(n.value) for n in fixture_source.body
               if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'fixture' for t in n.targets))
fixture = fixture.replace('#define RTL_PON_GPON 0', '#include "rtl9617c-pon-mode.h"')
fixture = re.sub(r'bool fe_enabled,(?:fe_cpu_path,)? xgpon_restore_pending;', '''bool fe_enabled, fe_cpu_path, xgpon_restore_pending;
 bool mac_prepared,pdc_configured,puc_configured,traffic_enabled;
 int lock,control_lock,pdc_error;void *ni_dev,*dev;unsigned int pdc_source[64];''', fixture)
fixture = fixture.replace('static unsigned int registers[', 'static unsigned int pdc[256][2],pdc_writes;static bool ni_ready;\nstatic unsigned int registers[')
fixture = fixture.replace(' case 0x612c:', ''' case 0x9020:
  assert(index<256);
  if(command&BIT(30)){
   unsigned int word=registers[0x9028/4];
   if(index>=8 && ((word>>3)&63)==24)assert(ni_ready);
   pdc[index][0]=word;pdc[index][1]=registers[0x9024/4];pdc_writes++;
  }else{registers[0x9028/4]=pdc[index][0];registers[0x9024/4]=pdc[index][1];}
  break;
 case 0x612c:''')
model = r'''
static unsigned int cpu_calls;
static int cpu_failure;
static void mutex_lock(int *lock){assert(!*lock);*lock=1;}
static void mutex_unlock(int *lock){assert(*lock);*lock=0;}
#define lockdep_assert_held(lock) assert(*(lock))
#define dev_info(...) ((void)0)
static int rtl9617c_ni_fe_cpu_path(void *dev){(void)dev;cpu_calls++;if(cpu_failure)return cpu_failure;ni_ready=true;return 0;}
static unsigned int rtl_pon_data_source(unsigned int index,unsigned int word){(void)word;return index+32;}
static int rtl_pdc_access(struct rtl9617c_pon *pon,unsigned int index,bool write){return path_access(pon,0x9020,BIT(31)|(write?BIT(30):0)|index);}
static void rtl_pon_update(void *address,unsigned int mask,unsigned int value){writel((readl(address)&~mask)|value,address);}
'''
test = r'''
static void assert_omci(void){
 for(unsigned int i=0;i<8;i++){
  assert(pdc[i][0]==(BIT(31)|BIT(15)|(7<<9)|(16<<3)|6));
  assert(pdc[i][1]==((i+128)<<4));
 }
}
int main(void){
 for(unsigned int mode=RTL_PON_GPON;mode<RTL_PON_MODE_COUNT;mode++){
  memset(registers,0,sizeof(registers));memset(pdc,0,sizeof(pdc));pdc_writes=0;ni_ready=false;
  struct rtl9617c_pon pon={.mac=(void *)registers,.mode=mode,.control_lock=1,.mac_prepared=true};
  cpu_failure=-ETIMEDOUT;unsigned int before=cpu_calls;
  assert(rtl_pon_pdc_configure_locked(&pon)==-ETIMEDOUT);
  assert(!pon.pdc_configured && !pon.fe_cpu_path && pdc_writes==0 && cpu_calls==before+1);
  cpu_failure=0;fail_register=0x9020;
  assert(rtl_pon_pdc_configure_locked(&pon)==-ETIMEDOUT);
  assert(ni_ready && pon.fe_cpu_path && !pon.pdc_configured && pdc_writes==0);
  fail_register=0;
  assert(!rtl_pon_pdc_configure_locked(&pon));
  assert(ni_ready && pon.fe_cpu_path && !pon.fe_enabled && pon.pdc_configured && !pon.lock);
  assert_omci();
  for(unsigned int i=8;i<256;i++){
   assert(pdc[i][0]==((24<<3)|(7<<9)) && pdc[i][1]==((i-8)<<4));
  }
  /* New GEM maps must retain the CPU trap even while offload is disabled. */
  struct rtl_itu_paths paths={.count=3,.path={
   {.gem_id=1034,.index=8,.alloc_id=1218,.tcont=1,.pbits=255,.downstream_pbits=255},
   {.gem_id=1033,.index=9,.alloc_id=1218,.tcont=1,.pbits=255,.downstream_pbits=255},
   {.gem_id=1032,.index=10,.alloc_id=1218,.tcont=1,.pbits=255,.downstream_pbits=255}}};
  schedules=burst_waits=0;
  assert(!path_program(&pon,&paths));
  assert_omci();
  for(unsigned int i=8;i<=10;i++)assert(pdc[i][0]==((24<<3)|(7<<9)) && pdc[i][1]==(i<<4));
  /* PON-only MAC recovery must prepare/reuse CPU delivery before new maps. */
  pon.pdc_configured=false;
  assert(!rtl_pon_pdc_configure_locked(&pon) && pon.fe_cpu_path);
  assert_omci();
  schedules=burst_waits=0;assert(!path_program(&pon,&paths));
  for(unsigned int i=8;i<=10;i++)assert(pdc[i][0]==((24<<3)|(7<<9)));
  /* Existing accelerated ownership must not be silently forced to CPU mode. */
  pon.fe_enabled=true;pon.fe_cpu_path=false;before=cpu_calls;
  assert(!rtl_pon_pdc_configure_locked(&pon) && pon.fe_enabled && !pon.fe_cpu_path);
  assert(cpu_calls==before);assert_omci();
 }
 puts("ITU PDC/GEM: CPU preparation before admission; GEM8/9/10 retain trap through update/recovery; OMCI unchanged; active offload preserved");
}
'''
pdc_source = production_source('rtl9617c-pon-pdc.c')
constants = '\n'.join(re.findall(r'^#define .*$', pdc_source, re.M))
pdc_helpers = ['rtl_pdc_write'] if 'static int rtl_pdc_write(' in pdc_source else []
functions = '\n'.join([function('rtl9617c-pon-pdc.c', n) for n in
                       pdc_helpers + ['rtl_pdc_itu_configure', 'rtl_pon_pdc_configure_locked']]
                      + [function('rtl9617c-pon-path.c', 'path_program')])
with tempfile.TemporaryDirectory(prefix='itu-cpu-path-', dir=root / 'artifacts') as directory:
    cfile = Path(directory) / 'test.c'
    binary = Path(directory) / 'test'
    cfile.write_text(fixture + model + constants + '\n' + functions + test)
    subprocess.run(['cc', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    '-I', str(drivers), str(cfile), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

# Execute the actual exported NI wrapper, not only a PON-side stub. The FE
# stub counts calls so a zero-user request cannot snapshot shared schedulers.
ni_model = r'''
#include <assert.h>
#include <errno.h>
#include <stdio.h>
struct rtl_fe {int unused;};
struct rtl_xram {unsigned int engine_users;struct rtl_fe *fe;};
struct device {struct rtl_xram *data;};
#define READ_ONCE(value) (value)
static void *dev_get_drvdata(struct device *dev){return dev->data;}
static void *netdev_priv(void *dev){return dev;}
static unsigned int calls;static int result;
static int rtl_fe_cpu_path(struct rtl_fe *fe){assert(fe);calls++;return result;}
'''
ni_test = r'''
int main(void){
 struct rtl_fe fe={};struct rtl_xram xram={.fe=&fe};struct device dev={.data=&xram};
 result=-ETIMEDOUT;
 assert(rtl9617c_ni_fe_cpu_path(&dev)==-EAGAIN && calls==0);
 xram.engine_users=1;
 assert(rtl9617c_ni_fe_cpu_path(&dev)==-ETIMEDOUT && calls==1);
 result=0;assert(!rtl9617c_ni_fe_cpu_path(&dev) && calls==2);
 xram.engine_users=0;
 assert(rtl9617c_ni_fe_cpu_path(&dev)==-EAGAIN && calls==2);
 puts("NI CPU wrapper: no FE preparation before engine startup; active engine delegates and propagates errors");
}
'''
with tempfile.TemporaryDirectory(prefix='ni-cpu-order-', dir=root / 'artifacts') as directory:
    cfile = Path(directory) / 'test.c'
    binary = Path(directory) / 'test'
    cfile.write_text(ni_model + function('rtl9617c-xram.c', 'rtl9617c_ni_fe_cpu_path') + ni_test)
    subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-g', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', str(cfile), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

# Run the service's shell control flow against stateful NI/PDC mocks. Only
# absolute filesystem/identity executable paths are redirected to the fixture;
# the sequence and error propagation inside configure_link remain production.
service_relative = 'port/overlay/target/linux/rtl9617c/base-files/etc/init.d/pon'
service = subprocess.check_output(['git', 'show', args.revision + ':' + service_relative], cwd=root, text=True) if args.revision else (root / service_relative).read_text()
service_model = r'''
config_load(){ :; }
config_get_bool(){ eval "$1=1"; }
config_get(){
 case "$3" in mode) eval "$1=$MODE";; onu_mac) eval "$1=02:00:00:00:00:01";; *) return 89;; esac
}
pon_identity(){ return 0; }
uci(){ return 1; }
ip(){
 [ "$1" = link ] && [ "$2" = set ] && [ "$4" = up ] || return 90
 case "$3" in
 pon-omci)
  [ "$mac_ready" = 1 ] && [ "$puc_ready" = 1 ] || return 91
  [ "$FAIL_NI" = 0 ] || return 17
  ni_started=1;;
 pon0)
  [ "$ni_started" = 1 ] && [ "$pdc_ready" = 1 ] || return 92
  data_ready=1;;
 *) return 93;;
 esac
}
printf(){
 case "$pon_stage" in
 mac) mac_ready=1;;
 puc) [ "$mac_ready" = 1 ] || return 94; puc_ready=1;;
 pdc)
  # The real NI wrapper returns EAGAIN when the NI engine has no owner.
  [ "$ni_started" = 1 ] && [ "$puc_ready" = 1 ] || return 95
  pdc_ready=1;;
 activation)
  [ "$data_ready" = 1 ] && [ "$pdc_ready" = 1 ] || return 96
  activation_ready=1;;
 esac
 command printf "$@"
}
procd_open_instance(){ [ "$activation_ready" = 1 ]; }
procd_set_param(){ :; }
procd_close_instance(){ :; }
. "$SERVICE"
mac_ready=0;puc_ready=0;ni_started=0;pdc_ready=0;data_ready=0;activation_ready=0
pon_stage=device
configure_link
status=$?
if [ "$FAIL_NI" = 1 ]; then
 [ "$status" = 17 ] && [ "$pdc_ready" = 0 ] && [ "$activation_ready" = 0 ] || exit 97
else
 [ "$status" = 0 ] && [ "$ni_started" = 1 ] && [ "$pdc_ready" = 1 ] && [ "$activation_ready" = 1 ] || exit 98
fi
'''
with tempfile.TemporaryDirectory(prefix='pon-service-order-', dir=root / 'artifacts') as directory:
    directory = Path(directory)
    device = directory / 'device'
    runtime = directory / 'runtime'
    device.mkdir()
    runtime.mkdir()
    for name in ['serdes', 'fe', 'bosa', 'onu_mac', 'gpon_identity', 'xgpon_identity', 'mac', 'puc', 'pdc', 'activation']:
        (device / name).touch()
    fixture_service = service.replace('/sys/bus/platform/devices/4f5500000.pon', str(device)).replace('/var/run/', str(runtime) + '/').replace('/usr/sbin/pon-identity', 'pon_identity')
    service_file = directory / 'pon-service'
    service_file.write_text(fixture_service)
    harness = directory / 'test.sh'
    harness.write_text(service_model)
    import os
    for mode in ['gpon', 'xgpon', 'xgspon']:
        for fail_ni in ['0', '1']:
            subprocess.run(['sh', str(harness)], env={**os.environ, 'SERVICE': str(service_file),
                           'MODE': mode, 'FAIL_NI': fail_ni}, check=True)
print('ITU service: MAC/PUC then NI/OMCI up before PDC; NI startup failure prevents PDC and activation in all three ITU modes')
