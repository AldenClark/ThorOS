#!/usr/bin/env python3
"""Compile and execute R13's actual root-only direct MCE sysfs getter.

Host MMIO model only; this never proves FE clock, MCE ownership, DDR retire,
or that a PHY forwards packets.  Runtime and failure modes are deliberately
tested without a live device or a writable callback.
"""
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek'
SOURCE = (DRIVER / 'rtl9617c-fe.c').read_text()
HANDOFF = (DRIVER / 'rtl9617c-mcast-handoff.h').read_text()
XRAM = (DRIVER / 'rtl9617c-xram.c').read_text()


def function(source, prefix, name):
    match = re.search(r'^' + re.escape(prefix) + r'\s+' + name + r'\(', source, re.M)
    assert match, name
    start = match.start()
    pos = source.index('{', start) + 1
    braces = 1
    while braces:
        braces += (source[pos] == '{') - (source[pos] == '}')
        pos += 1
    return source[start:pos]


GETTER = function(SOURCE, 'ssize_t', 'rtl_fe_mce_inherited_evidence')
READER = function(HANDOFF, 'static inline int', 'rtl_mcast_handoff_sample')
TYPES = re.search(r'enum rtl_mcast_handoff_sample\s*\{.*?\};\s*'
                  r'struct rtl_mcast_handoff\s*\{.*?\};', HANDOFF, re.S)
assert TYPES, 'missing real sample layout'
MACROS = HANDOFF[HANDOFF.index('#define RTL_MCAST_NEEDS_XRAM_FENCE'):
                 HANDOFF.index('enum rtl_mcast_handoff_sample')]
assert MACROS.count('#define RTL_MCAST_NEEDS_') == 5
assert 'static DEVICE_ATTR(mce_inherited, 0400, mce_inherited_show, NULL)' in XRAM
assert 'rtl_fe_mce_inherited_evidence(priv->fe, buf)' in XRAM
assert '&dev_attr_mce_inherited.attr' in XRAM and 'attr->mode' in XRAM
assert 'fe_write(' not in GETTER and 'fe_access(' not in GETTER
assert 'rtl_mcast_handoff_sample(&sample,&io)' in GETTER
assert 'clock_verified=0' in GETTER and 'retirement_verified=0' in GETTER
assert 'missing_contracts=0x1f' not in GETTER  # must be drawn from real contract

FIXTURE = r'''
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define PAGE_SIZE 4096
typedef unsigned long long u64;
struct rtl_dq_io {
 void *context;
 unsigned int (*read)(void *,unsigned int);
 void (*write)(void *,unsigned int,unsigned int);
 int (*indirect)(void *,unsigned int,unsigned int);
};
struct mock_mutex {bool held,blocked;};
struct rtl_fe {
 struct mock_mutex lock;
 unsigned int route_lock;
 bool engine_ready,shutting_down;
 struct {bool ready;} fabric;
 struct {struct {unsigned long long generation;} ledger;} *l2_owner;
 void *mcast;
 unsigned long long evidence_instance_ns;
 unsigned int words[5], reads, writes, selectors;
};
static bool mutex_trylock(struct mock_mutex *m) {
 if(m->blocked||m->held)return false;
 m->held=true;return true;
}
static void mutex_unlock(struct mock_mutex *m) {assert(m->held);m->held=false;}
#define spin_lock_irqsave(lock, flags) do { (void)(lock);(flags)=0; } while(0)
#define spin_unlock_irqrestore(lock, flags) do { (void)(lock);(void)(flags); } while(0)
static u64 ktime_get_ns(void) { static u64 clock=500;return clock+=10; }
static ssize_t output(char *buffer,size_t limit,const char *fmt,va_list ap) {
 int n=vsnprintf(buffer,limit,fmt,ap);
 assert(n>=0 && (size_t)n<limit);return n;
}
static ssize_t sysfs_emit(char *buffer,const char *fmt,...) {
 va_list ap;va_start(ap,fmt);
 ssize_t n=output(buffer,PAGE_SIZE,fmt,ap);
 va_end(ap);return n;
}
static ssize_t scnprintf(char *buffer,size_t limit,const char *fmt,...) {
 va_list ap;va_start(ap,fmt);
 ssize_t n=output(buffer,limit,fmt,ap);
 va_end(ap);return n;
}
static unsigned int fe_read(void *context,unsigned int address) {
 static const unsigned int addresses[5]={0xaa28,0x3400,0x3834,0x38a0,0xaa60};
 struct rtl_fe *fe=context;
 unsigned int i;
 for(i=0;i<5;i++)if(address==addresses[i])break;
 assert(i<5);assert(fe->reads==i);
 fe->reads++;
 return fe->words[i];
}
'''

TEST = r'''
int main(void) {
 struct rtl_fe fe={0};
 char page[PAGE_SIZE];
 ssize_t size;
 fe.engine_ready=true;fe.fabric.ready=false;
 fe.evidence_instance_ns=100;
 for(unsigned int i=0;i<5;i++)fe.words[i]=i+1;
 size=rtl_fe_mce_inherited_evidence(&fe,page);
 assert(size>0 && size<1024 && fe.reads==5 && !fe.writes && !fe.selectors);
 assert(!fe.lock.held);
 assert(strstr(page,"scope=runtime_direct") && strstr(page,"mmio_reads=5 mmio_writes=0"));
 assert(strstr(page,"clock_verified=0") && strstr(page,"handoff_verified=0 retirement_verified=0"));
 assert(strstr(page,"mce_owner=0") && strstr(page,"fabric_ready=0"));
 assert(strstr(page,"missing_contracts=0x1f sample_valid=0x1f"));
 assert(strstr(page,"sample_error=0") && strstr(page,"cache_ini=0x00000004"));

 fe.reads=0;fe.words[3]=0xffffffffU;
 size=rtl_fe_mce_inherited_evidence(&fe,page);
 assert(size>0 && fe.reads==5 && !fe.lock.held);
 assert(strstr(page,"sample_valid=0x17 sample_reads=5 sample_error=-5"));
 assert(strstr(page,"bad_register=0x38a0 bad_value=0xffffffff"));

 typeof(*fe.l2_owner) owner={.ledger={.generation=4294967297ULL}};
 fe.l2_owner=&owner;fe.mcast=&owner;fe.reads=0;fe.words[3]=4;
 size=rtl_fe_mce_inherited_evidence(&fe,page);
 assert(size>0 && fe.reads==5 && !fe.lock.held);
 assert(strstr(page,"mce_owner=1 owner_generation_valid=1 owner_generation=4294967297"));

 fe.reads=0;fe.lock.blocked=true;
 size=rtl_fe_mce_inherited_evidence(&fe,page);
 assert(size>0 && strstr(page,"reason=busy") && !fe.reads);
 fe.lock.blocked=false;fe.engine_ready=false;
 size=rtl_fe_mce_inherited_evidence(&fe,page);
 assert(size>0 && strstr(page,"reason=engine_down") && !fe.reads && !fe.lock.held);
 fe.engine_ready=true;fe.shutting_down=true;
 size=rtl_fe_mce_inherited_evidence(&fe,page);
 assert(size>0 && strstr(page,"reason=engine_down") && !fe.reads);
 size=rtl_fe_mce_inherited_evidence(NULL,page);
 assert(size>0 && strstr(page,"reason=no_fe") && !fe.reads);

 puts("FE MCE inherited production getter: exact five read-only CSRs, root gated, no-owner, allones, unavailable and page budget PASS");
 return 0;
}
'''


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0', LSAN_OPTIONS='detect_leaks=0')
    variants = {'production': GETTER}
    # Each regression intentionally fails one of the real getter scenarios.
    mutations = {
        'skip_engine_gate': ('if(!fe->engine_ready || fe->shutting_down)', 'if(0)'),
        'skip_read': ('ret=rtl_mcast_handoff_sample(&sample,&io);',
                      'memset(&sample,0,sizeof(sample)); ret=((void)io,0);'),
        'claim_handoff': ('handoff_verified=0 retirement_verified=0',
                          'handoff_verified=1 retirement_verified=1'),
        'ignore_busy': ('if(!mutex_trylock(&fe->lock))', 'if(0)'),
    }
    for name, (before, after) in mutations.items():
        assert GETTER.count(before) == 1, name
        variants[name] = GETTER.replace(before, after, 1)

    with tempfile.TemporaryDirectory(prefix='mce-inherited-host-') as directory:
        for name, getter in variants.items():
            path = Path(directory) / f'{name}.c'
            path.write_text(FIXTURE + MACROS + TYPES.group() + '\n' + READER + '\n' + getter + '\n' + TEST)
            binary = path.with_suffix('')
            platform_flags = [] if sys.platform == 'darwin' else ['-fno-pie', '-no-pie']
            subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                            '-Wno-unused-function',
                            '-O1', '-g', '-fsanitize=address,undefined', *platform_flags,
                            str(path), '-o', str(binary)],
                           check=True, text=True, capture_output=True)
            result = subprocess.run([str(binary)], env=env, capture_output=True, text=True)
            if name == 'production':
                assert result.returncode == 0, (name, result.stderr)
                print(result.stdout.strip())
            else:
                assert result.returncode != 0, (name, 'semantic mutation survived')
    print(f'MCE inherited getter: {len(mutations)} independent regression mutations rejected')


if __name__ == '__main__':
    main()
