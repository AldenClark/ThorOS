#!/usr/bin/env python3
"""Run actual PDC initialization/refresh against modeled LLID and PDC tables."""
import argparse
import json
from pathlib import Path
import re
import resource
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
drivers = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
source = (drivers / 'rtl9617c-pon-pdc.c').read_text()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--mutants', action='store_true')
args = parser.parse_args()


def function(name):
    start = re.search(r'^.*\b' + re.escape(name) + r'\([^;]*?\)\s*\{', source, re.M).start()
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


model = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "rtl9617c-pon-data.h"
#include "rtl9617c-pon-mode.h"
typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define dev_info(...) ((void)0)
struct mutex {bool held;};
struct rtl9617c_pon {void *mac,*dev,*ni_dev;int mode;bool fe_enabled,fe_cpu_path;struct mutex lock,control_lock;bool mac_prepared,pdc_configured,carrier;int pdc_error;unsigned char pdc_source[64];};
struct net {unsigned int unused;};
static struct net policy_net;
static unsigned int policy_depth,policy_begins,policy_ends;
static void rtl_pon_policy_begin(struct rtl9617c_pon *pon,struct net **policy)
{assert(pon->lock.held);if(!*policy){*policy=&policy_net;policy_depth++;policy_begins++;}}
static void rtl9617c_switch_policy_end(struct net *policy)
{if(policy){assert(policy==&policy_net && policy_depth);policy_depth--;policy_ends++;}}
static void rtl_pon_oam_carrier(struct rtl9617c_pon *pon)
{assert(pon->lock.held);if(pon->carrier!=pon->pdc_configured)assert(policy_depth);pon->carrier=pon->pdc_configured;}
static int rtl9617c_ni_fe_cpu_path(void *dev) {(void)dev;assert(0);return -EIO;}
static u32 registers[0xc000/4],maps[256][2];static unsigned int accesses,fail_access;
static unsigned int llid_reads,fault_read,drift_read;
static u32 fault_value;
static void mutex_lock(struct mutex *lock) {assert(!lock->held);lock->held=true;}
static void mutex_unlock(struct mutex *lock) {assert(lock->held);lock->held=false;}
#define lockdep_assert_held(lock) assert((lock)->held)
static u32 readl(const void *p) {
    u32 value;memcpy(&value,p,4);
    unsigned int offset=(const u32 *)p-registers;
    if(offset==0x168/4 || (offset>=0x64/4 && offset<(0x64+64*4)/4)) {
        llid_reads++;
        if(llid_reads==fault_read)return fault_value;
        if(llid_reads==drift_read)return value^BIT(24);
    }
    return value;
}
static void writel(u32 value,void *p) {
    unsigned int offset=(u32 *)p-registers;
    if(offset==0x9020/4 || offset==0x9024/4 || offset==0x9028/4)assert(policy_depth);
    if(offset==0x9020/4) {
        if(++accesses==fail_access) {memcpy(p,&value,4);return;}
        unsigned int index=value&255;
        if(value&BIT(30)) {maps[index][0]=registers[0x9028/4];maps[index][1]=registers[0x9024/4];}
        value&=~BIT(31);
    }
    memcpy(p,&value,4);
}
static void rtl_pon_update(void *p,u32 mask,u32 value) {writel((readl(p)&~mask)|(value&mask),p);}
#define readl_poll_timeout(p,v,condition,delay,timeout) ({(v)=readl(p);(condition)?0:-ETIMEDOUT;})
'''
tests = r'''
int main(void) {
    struct rtl9617c_pon pon={.mac=registers,.control_lock={true},.mac_prepared=true};
    registers[(0x64+17*4)/4]=BIT(23)|(8<<24)|0x1234;
    registers[(0x64+20*4)/4]=BIT(23)|BIT(22)|0x4321;
    assert(rtl_pon_pdc_configure_locked(&pon)==0&&pon.pdc_configured&&accesses==256);
    assert(pon.carrier && !policy_depth && policy_begins==policy_ends);
    for(unsigned int index=0;index<256;index++) {
        unsigned int entry=index&63;
        unsigned int expected=7;
        if(!(index&64))expected=entry==17?40:entry==20?32:32+(entry<32?entry:0);
        assert(((maps[index][0]>>9)&63)==7);
        assert(((maps[index][1]>>4)&511)==((index&64)?0:expected-32));
        assert(((maps[index][0]>>3)&63)==16 && (maps[index][0]&BIT(15)) && !(maps[index][1]&15));
        assert((maps[index][0]&7)==((index&64)?7:0));
    }
    /* Registration changes table slot17 from MAC8 to MAC3; only its two
     * business banks change, while MPCP/OAM remain in source7/COS7. */
    registers[(0x64+17*4)/4]=BIT(23)|(3<<24)|0x1234;
    pon.lock.held=true;
    unsigned int before=accesses;
    assert(rtl_pon_pdc_refresh(&pon)==0 && accesses==before+2);
    assert(((maps[17][1]>>4)&511)==3 && ((maps[145][1]>>4)&511)==3);
    assert(((maps[81][0]>>9)&63)==7 && ((maps[209][0]>>9)&63)==7);
    before=accesses;assert(rtl_pon_pdc_refresh(&pon)==0 && accesses==before);
    registers[(0x64+17*4)/4]=BIT(23)|(4<<24)|0x1234;
    fail_access=accesses+1;
    assert(rtl_pon_pdc_refresh(&pon)==-ETIMEDOUT && !pon.pdc_configured && pon.pdc_error==-ETIMEDOUT);
    assert(!pon.carrier && !policy_depth);
    pon.lock.held=false;fail_access=0;
    /* Timeout is not cancellation: a new request must not overwrite DATA
     * while the old hardware operation still owns its staging window. */
    u32 data0=registers[0x9028/4],data1=registers[0x9024/4];before=accesses;
    assert(rtl_pon_pdc_configure_locked(&pon)==-EBUSY && !pon.pdc_configured);
    assert(accesses==before && registers[0x9028/4]==data0 && registers[0x9024/4]==data1);
    assert(rtl_pdc_access(&pon,7,false)==-EBUSY && accesses==before);
    registers[0x9020/4]&=~BIT(31); /* Hardware eventually completes. */
    assert(rtl_pon_pdc_configure_locked(&pon)==0&&pon.pdc_configured);
    /* Every LLID read in full reconstruction is an actual MMIO access:
     * pre-window + 64 snapshot + post-window + 64 readback = 130. Failed
     * reads cannot reauthorize business forwarding, even with live MPCP. */
    unsigned int cases=0;
    for(unsigned int fail=1;fail<=130;fail++) {
        llid_reads=0;fault_read=fail;fault_value=~0U;
        unsigned int old_begins=policy_begins;
        assert(rtl_pon_pdc_configure_locked(&pon)==-EIO);
        assert(!pon.pdc_configured && !pon.carrier && pon.pdc_error==-EIO && !policy_depth &&
               policy_begins==old_begins+1 && policy_begins==policy_ends);
        fault_read=0;llid_reads=0;
        assert(!rtl_pon_pdc_configure_locked(&pon) && pon.pdc_configured && pon.carrier && llid_reads==130);
        cases++;
    }
    for(unsigned int fail=1;fail<=66;fail+=65) {
        llid_reads=0;fault_read=fail;fault_value=1;
        before=accesses;
        assert(rtl_pon_pdc_configure_locked(&pon)==-EBUSY);
        assert(!pon.pdc_configured && !pon.carrier && !policy_depth);
        if(fail==1)assert(accesses==before);
        fault_read=0;assert(!rtl_pon_pdc_configure_locked(&pon));cases++;
    }
    /* A different live LLID table after all PDC writes is still not a
     * verified map. Do not bless a snapshot from another registration. */
    for(unsigned int fail=67;fail<=130;fail++) {
        llid_reads=0;drift_read=fail;
        assert(rtl_pon_pdc_configure_locked(&pon)==-EAGAIN);
        assert(!pon.pdc_configured && !pon.carrier && !policy_depth);
        drift_read=0;assert(!rtl_pon_pdc_configure_locked(&pon));cases++;
    }
    for(unsigned int fail=1;fail<=256;fail++) {
        fail_access=accesses+fail;
        assert(rtl_pon_pdc_configure_locked(&pon)==-ETIMEDOUT);
        assert(!pon.pdc_configured && !pon.carrier && !policy_depth);
        fail_access=0;
        data0=registers[0x9028/4];data1=registers[0x9024/4];before=accesses;
        assert(rtl_pon_pdc_configure_locked(&pon)==-EBUSY);
        assert(accesses==before && registers[0x9028/4]==data0 && registers[0x9024/4]==data1 &&
               !pon.pdc_configured && !pon.carrier && !policy_depth);
        registers[0x9020/4]=0;
        assert(!rtl_pon_pdc_configure_locked(&pon) && pon.pdc_configured && pon.carrier);cases++;
    }
    /* An unreadable live LLID entry fails refresh without programming a
     * fabricated MAC31/multicast mapping. */
    pon.lock.held=true;llid_reads=0;fault_read=1;fault_value=~0U;before=accesses;
    assert(rtl_pon_pdc_refresh(&pon)==-EIO && accesses==before);
    assert(!pon.pdc_configured && !pon.carrier && !policy_depth);
    fault_read=0;pon.lock.held=false;
    assert(policy_begins==policy_ends && cases==452);
    puts("Actual PDC: 256 maps, LLID identity, persistent business carrier fault, 452 full-rebuild read/busy/drift/write fault cases, exact late-completion recovery and staging preservation passed");
}
'''
constants = '\n'.join(re.findall(r'^#define .*$', source, re.M))
code = model + constants + '\n' + ''.join(function(name) for name in ('rtl_pdc_access', 'rtl_pdc_write', 'rtl_pon_pdc_refresh', 'rtl_pdc_itu_configure', 'rtl_pon_pdc_configure_locked')) + tests
variants = [('production', code)]
if args.mutants:
    mutations = {
        'allow_pending_llid_rebuild': ('if (status == ~0U || (status & BIT(0))) {', 'if (status == ~0U) {'),
        'accept_unreadable_llid_snapshot': ('if (llids[index] == ~0U) {', 'if (false) {'),
        'accept_changed_llid_after_rebuild': ('if (status == ~0U || status != llids[index]) {', 'if (status == ~0U) {'),
        'leave_business_carrier_on_after_failure': ('if (epon_rebuild)\n\t\trtl_pon_oam_carrier(pon);',
                                                   'if (epon_rebuild && !ret)\n\t\trtl_pon_oam_carrier(pon);'),
        'end_before_business_carrier_publication': ('if (epon_rebuild)\n\t\trtl_pon_oam_carrier(pon);\n\trtl9617c_switch_policy_end(policy);',
                                                   'rtl9617c_switch_policy_end(policy);\n\tif (epon_rebuild)\n\t\trtl_pon_oam_carrier(pon);'),
    }
    for name, (before, after) in mutations.items():
        assert before in code, name
        variants.append((name, code.replace(before, after)))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
with tempfile.TemporaryDirectory(prefix='pdc-map-test-', dir=root / 'artifacts') as directory:
    directory = Path(directory)
    for variant, program in variants:
        cfile = directory / f'{variant}.c'
        binary = directory / variant
        cfile.write_text(program)
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-O1', '-g', '-fsanitize=address,undefined',
                        '-I', str(drivers), str(cfile), '-o', str(binary)], check=True)
        result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30)
        if variant == 'production':
            if result.returncode:
                print(result.stderr, end='')
                raise SystemExit(result.returncode)
            print(result.stdout, end='')
        else:
            assert result.returncode and 'Assertion' in result.stderr, result
            print(f'PDC recovery mutation rejected: {variant}')
(root / 'logs/pon-pdc-map-test.json').write_text(json.dumps({'actual_functions':True,'entries':256,
    'LLID_table_MAC_index_used':True,'changed_only_refresh':True,'failure_recovery_tested':True,
    'full_rebuild_fault_cases':452,'mutations_rejected':len(variants)-1,
    'hardware_access':False,'sanitizers':['ASan','UBSan']},indent=2)+'\n')
