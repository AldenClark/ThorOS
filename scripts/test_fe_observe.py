#!/usr/bin/env python3
"""Admission rejection reasons are complete, numeric and not packet counters."""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
drivers = root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
source = (drivers / 'rtl9617c-fe.c').read_text()

def function(name):
    start = re.search(r'^static int ' + name + r'\(', source, re.M).start()
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include "rtl9617c-fe-observe.h"
struct rtl_fe {struct rtl_fe_observe observe;};
struct rtl_fe_port {struct rtl_fe *fe;};
struct rtl_fe_rule {unsigned int reject_reason;};
struct flow_cls_offload {unsigned long cookie;};
static int parse_error,install_error;
static unsigned int reason,installs;
static int fe_parse(struct rtl_fe_port *p,struct flow_cls_offload *c,struct rtl_fe_rule *r){
 (void)p;(void)c;r->reject_reason=reason;return parse_error;
}
static int fe_install(struct rtl_fe_port *p,struct rtl_fe_rule r,unsigned long cookie){
 (void)p;(void)r;(void)cookie;installs++;return install_error;
}
'''
test = r'''
int main(void){
 struct rtl_fe fe={0};struct rtl_fe_port port={.fe=&fe};struct flow_cls_offload cls={0};
 for(reason=0;reason<FE_REJECT_COUNT;reason++){
  parse_error=-EOPNOTSUPP;
  assert(fe_replace(&port,&cls)==-EOPNOTSUPP && !installs);
  assert(fe.observe.reason[reason]==1);
 }
 assert(fe.observe.parse_rejected==FE_REJECT_COUNT);
 parse_error=0;
 int errors[]={-EAGAIN,-ENODEV,-EEXIST,-EOPNOTSUPP,-ENOSPC,-ENOMEM,-EBUSY,-ETIMEDOUT,-EIO,-EINVAL,0};
 for(unsigned int i=0;i<sizeof(errors)/sizeof(errors[0]);i++){
  install_error=errors[i];assert(fe_replace(&port,&cls)==errors[i]);
 }
 assert(fe.observe.replace_requests==FE_REJECT_COUNT+11);
 assert(fe.observe.install_failed==10 && installs==11);
 assert(fe.observe.install_unavailable==2 && fe.observe.install_duplicate==1);
 assert(fe.observe.install_collision==1 && fe.observe.install_no_space==1);
 assert(fe.observe.install_no_memory==1 && fe.observe.install_io==3 && fe.observe.install_other==1);
 puts("FE admission: every unsupported predicate/PON rejection recorded; install errors classified separately; success is not a packet-hit claim");
}
'''
with tempfile.TemporaryDirectory(prefix='fe-observe-') as tmp:
    path = Path(tmp)
    (path / 'test.c').write_text(fixture + function('fe_replace') + test)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-I' + str(drivers),
                    str(path / 'test.c'), '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True)

callback = function('fe_block_callback')
assert 'cls->command==FLOW_CLS_REPLACE' in callback
assert 'ret!=-EOPNOTSUPP' not in callback
assert 'port->retired?-ENODEV' in callback
for field in ('admission_requests', 'parse_rejected', 'install_failed', 'reject_pon', 'install_collision'):
    assert field + '=' in source
