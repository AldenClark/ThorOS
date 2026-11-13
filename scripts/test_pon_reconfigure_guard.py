#!/usr/bin/env python3
"""Run the production PDC/PUC public wrappers against an active ITU graph."""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c-pon.c').read_text()

def function(name):
    start = re.search(r'^int ' + name + r'\(', source, re.M).start()
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

model = r'''
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
struct mutex {int held;};
static void mutex_lock(struct mutex *m){assert(!m->held);m->held=1;}
static void mutex_unlock(struct mutex *m){assert(m->held);m->held=0;}
struct rtl9617c_pon {struct mutex control_lock,lock;bool itu_paths_ready;
 struct {int phase;} gpon_drain;int xgpon_recovery_phase;
 int pdc_calls,puc_calls;};
static int rtl_pon_pdc_configure_locked(struct rtl9617c_pon *p){assert(p->control_lock.held&&!p->lock.held);p->pdc_calls++;return -EIO;}
static int rtl_pon_puc_configure_locked(struct rtl9617c_pon *p){assert(p->control_lock.held&&!p->lock.held);p->puc_calls++;return -ENOSPC;}
'''
test = r'''
int main(void){
 struct rtl9617c_pon p={.itu_paths_ready=true};
 assert(rtl_pon_pdc_configure(&p)==-EBUSY && !p.pdc_calls);
 assert(rtl_pon_puc_configure(&p)==-EBUSY && !p.puc_calls);
 p.itu_paths_ready=false;
 assert(rtl_pon_pdc_configure(&p)==-EIO && p.pdc_calls==1);
 assert(rtl_pon_puc_configure(&p)==-ENOSPC && p.puc_calls==1);
 p.gpon_drain.phase=1;
 assert(rtl_pon_pdc_configure(&p)==-EBUSY && p.pdc_calls==1);
 assert(!p.lock.held&&!p.control_lock.held);
 return 0;
}
'''
with tempfile.TemporaryDirectory() as d:
    path = Path(d)
    c = path / 'test.c'
    c.write_text(model + function('rtl_pon_pdc_configure') + function('rtl_pon_puc_configure') + test)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(c), '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True)
print('PASS: live ITU graph blocks both standalone reconfigurations; other errors propagate')
