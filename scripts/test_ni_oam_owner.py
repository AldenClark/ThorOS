#!/usr/bin/env python3
"""Exercise the production OAM map owner against shared-window failures.

The fake MMIO contract comes from the RTL77C generated PDPID table and L2
scheduler declarations: four banks, ACCESS[31], rbw[30], PDPID[3:0], and
independent scheduler fields. It does not model packet throughput. Compile
the actual FE helper and NI wrapper, including mutex ownership, then verify
that focused regressions are rejected by the same independent test cases.
"""
from pathlib import Path
import os
import re
import resource
import signal
import subprocess
import tempfile


root = Path(__file__).resolve().parents[1]
drivers = root / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"


def function(source, name):
    match = re.search(r"^.*\b" + name + r"\([^;]*?\)\s*\{", source, re.M)
    if not match:
        raise AssertionError(f"missing production function: {name}")
    start = match.start()
    end = source.index("{", start) + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end] + "\n"


source = (drivers / "rtl9617c-fe.c").read_text()
helpers = "".join(function(source, name) for name in (
    "fe_read", "fe_write", "fe_access", "fe_io"))
helpers += function((drivers / "rtl9617c-fe-table.h").read_text(), "rtl_fe_window_idle")
owner = function(source, "rtl_fe_oam_configure")
wrapper = function((drivers / "rtl9617c-xram.c").read_text(), "rtl9617c_ni_oam_configure")
assert "rtl_fe_oam_configure(priv->fe)" in wrapper
assert "writel" not in wrapper and "0x165" not in wrapper

fixture = r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define READ_ONCE(x) (x)
struct mutex {pthread_mutex_t native;atomic_uint waiting;};
static _Thread_local bool owns_fe;
static void mutex_lock(struct mutex *lock) {
 assert(!owns_fe);atomic_fetch_add(&lock->waiting,1);
 assert(!pthread_mutex_lock(&lock->native));
 atomic_fetch_sub(&lock->waiting,1);owns_fe=true;
}
static void mutex_unlock(struct mutex *lock) {
 assert(owns_fe);owns_fe=false;assert(!pthread_mutex_unlock(&lock->native));
}
struct rtl_fe {
 void *registers;struct mutex lock;
 bool shutting_down,engine_ready,base_failed;
 struct {bool poisoned;} fabric;
};
struct rtl_dq_io {
 void *context;
 unsigned int (*read)(void *,unsigned int);
 void (*write)(void *,unsigned int,unsigned int);
 int (*access)(void *,unsigned int,unsigned int);
};
struct rtl_xram {struct rtl_fe *fe;bool removing,engine_poisoned,host_active;};
struct device {struct rtl_xram *data;};
static void *dev_get_drvdata(struct device *dev) {return dev->data;}
static void *netdev_priv(void *data) {return data;}

/* PDPID ACCESS/DATA and scheduler layout are hardware-model constants. */
enum {ACCESS=0x1654,DATA=0x1658,PORT12=0x2394,PORTS=0x2300};
static u32 regs[65536/4],map[256],initial_map[256];
static unsigned commands,data_reads,data_writes,direct_writes;
static unsigned fail_command,busy_after_data_read,ignore_map,ignore_direct;
static unsigned failed_read_reg,failed_read_nth,failed_read_hits;
static u32 pending_command,pending_data;
static const unsigned bank[]={15,143,79,207};
static const u32 old_port=0x99002b00,old_ports=0xa3a30f3f;

static void complete_command(u32 value,u32 data) {
 unsigned index=value&255;
 if(value&BIT(30)) {
  if(index!=ignore_map)map[index]=data;
 } else regs[DATA/4]=map[index];
 regs[ACCESS/4]=value&~BIT(31);
}
static u32 readl(void *address) {
 unsigned reg=(char *)address-(char *)regs;
 assert(owns_fe && reg<sizeof(regs) && !(reg&3));
 u32 value=regs[reg/4];
 if(reg==DATA && ++data_reads==busy_after_data_read)
  regs[ACCESS/4]|=BIT(31);
 if(reg==failed_read_reg && ++failed_read_hits==failed_read_nth)return ~0U;
 return value;
}
static void writel(u32 value,void *address) {
 unsigned reg=(char *)address-(char *)regs;
 assert(owns_fe && reg<sizeof(regs) && !(reg&3));
 if(reg==DATA) {
  assert(!(regs[ACCESS/4]&BIT(31)));
  data_writes++;regs[reg/4]=value;
 } else if(reg==ACCESS) {
  assert(!(regs[reg/4]&BIT(31)) && (value&BIT(31)));
  commands++;regs[reg/4]=value;
  if(commands==fail_command) {
   pending_command=value;pending_data=regs[DATA/4];
  } else complete_command(value,regs[DATA/4]);
 } else {
  assert(reg==PORT12 || reg==PORTS);
  direct_writes++;
  if(reg!=ignore_direct)regs[reg/4]=value;
 }
}
/* Timed-out commands stay busy until finish_pending(), not host retry. */
#define readl_poll_timeout(p,v,condition,delay,timeout) ({(v)=readl(p);(condition)?0:-ETIMEDOUT;})
'''

cases = r'''
static void reset(struct rtl_fe *fe) {
 memset(regs,0,sizeof(regs));
 for(unsigned i=0;i<256;i++)map[i]=initial_map[i]=0x55000002U|(i<<8);
 regs[PORT12/4]=old_port;regs[PORTS/4]=old_ports;
 commands=data_reads=data_writes=direct_writes=0;
 fail_command=busy_after_data_read=ignore_direct=0;ignore_map=256;
 failed_read_reg=failed_read_nth=failed_read_hits=0;
 pending_command=pending_data=0;
 fe->shutting_down=fe->base_failed=fe->fabric.poisoned=false;fe->engine_ready=true;
}
static bool selected(unsigned i) {
 for(unsigned j=0;j<ARRAY_SIZE(bank);j++)if(i==bank[j])return true;
 return false;
}
static void installed(void) {
 for(unsigned i=0;i<256;i++)
  assert(map[i]==(selected(i)?((initial_map[i]&~15U)|12):initial_map[i]));
 assert(regs[PORT12/4]==((old_port&~0x00ff00ffU)|0x000600ffU));
 assert(regs[PORTS/4]==(old_ports|BIT(12)));
}
static void finish_pending(void) {
 assert(pending_command && (regs[ACCESS/4]&BIT(31)));
 complete_command(pending_command,pending_data);pending_command=0;fail_command=0;
}
static void no_mmio(void) {
 assert(!commands && !data_reads && !data_writes && !direct_writes);
}
static void lifecycle(struct rtl_fe *fe) {
 assert(rtl_fe_oam_configure(NULL)==-EOPNOTSUPP);
 reset(fe);fe->shutting_down=true;assert(rtl_fe_oam_configure(fe)==-ENODEV);no_mmio();
 reset(fe);fe->base_failed=true;assert(rtl_fe_oam_configure(fe)==-EIO);no_mmio();
 reset(fe);fe->fabric.poisoned=true;assert(rtl_fe_oam_configure(fe)==-EIO);no_mmio();
 reset(fe);fe->engine_ready=false;assert(rtl_fe_oam_configure(fe)==-EAGAIN);no_mmio();
 struct rtl_xram priv={.fe=fe,.host_active=true};struct device dev={.data=&priv};
 reset(fe);priv.removing=true;assert(rtl9617c_ni_oam_configure(&dev)==-ENODEV);no_mmio();
 priv.removing=false;priv.engine_poisoned=true;
 assert(rtl9617c_ni_oam_configure(&dev)==-EIO);no_mmio();
 priv.engine_poisoned=false;priv.host_active=false;
 assert(rtl9617c_ni_oam_configure(&dev)==-EAGAIN);no_mmio();
 priv.host_active=true;assert(!rtl9617c_ni_oam_configure(&dev));installed();
}
static void faults(struct rtl_fe *fe) {
 reset(fe);assert(!rtl_fe_oam_configure(fe));installed();
 assert(commands==12 && data_writes==4 && direct_writes==2);
 unsigned old_commands=commands,old_writes=data_writes,old_direct=direct_writes;
 assert(!rtl_fe_oam_configure(fe));installed();
 assert(commands==old_commands+4 && data_writes==old_writes && direct_writes==old_direct);
 /* A dirty inherited flush bit is not a valid, already-configured port. */
 regs[PORT12/4]|=BIT(15);
 assert(!rtl_fe_oam_configure(fe));installed();
 assert(data_writes==old_writes && direct_writes==old_direct+1);
 regs[PORT12/4]|=BIT(15);ignore_direct=PORT12;
 assert(rtl_fe_oam_configure(fe)==-EIO && (regs[PORT12/4]&BIT(15)));
 /* Neither initial busy nor busy observed between read and DATA permits staging. */
 reset(fe);regs[ACCESS/4]=BIT(31)|BIT(30)|24;
 assert(rtl_fe_oam_configure(fe)==-EBUSY);no_mmio();
 assert(regs[ACCESS/4]==(BIT(31)|BIT(30)|24));
 for(unsigned i=1;i<=4;i++) {
  reset(fe);busy_after_data_read=2*i-1;
  assert(rtl_fe_oam_configure(fe)==-EBUSY);
  assert(data_writes==i-1 && !direct_writes);
 }
 /* Each initial read, write and verification may independently time out. */
 for(unsigned i=1;i<=12;i++) {
  reset(fe);fail_command=i;
  assert(rtl_fe_oam_configure(fe)==-ETIMEDOUT && commands==i && !direct_writes);
  old_writes=data_writes;
  assert(rtl_fe_oam_configure(fe)==-EBUSY && commands==i && data_writes==old_writes);
  finish_pending();assert(!rtl_fe_oam_configure(fe));installed();
 }
 for(unsigned i=0;i<4;i++) {
  reset(fe);ignore_map=bank[i];
  assert(rtl_fe_oam_configure(fe)==-EIO && !direct_writes);
  assert((map[bank[i]]&15)==2);
  ignore_map=256;assert(!rtl_fe_oam_configure(fe));installed();
 }
 for(unsigned i=0;i<2;i++) {
  reset(fe);ignore_direct=i?PORTS:PORT12;
  assert(rtl_fe_oam_configure(fe)==-EIO);
  if(!i)assert(regs[PORTS/4]==old_ports);
  ignore_direct=0;assert(!rtl_fe_oam_configure(fe));installed();
 }
 /* Impossible bus reads must not become RMW payloads or success evidence. */
 for(unsigned i=1;i<=8;i++) {
  reset(fe);failed_read_reg=DATA;failed_read_nth=i;
  assert(rtl_fe_oam_configure(fe)==-EIO && data_writes==i/2 && !direct_writes);
  failed_read_reg=0;assert(!rtl_fe_oam_configure(fe));installed();
 }
 for(unsigned reg=0;reg<2;reg++)for(unsigned nth=1;nth<=2;nth++) {
  reset(fe);failed_read_reg=reg?PORTS:PORT12;failed_read_nth=nth;
  assert(rtl_fe_oam_configure(fe)==-EIO && direct_writes==reg+nth-1);
  failed_read_reg=0;assert(!rtl_fe_oam_configure(fe));installed();
 }
}
struct thread_arg {struct rtl_fe *fe;int result;};
static void *oam_thread(void *data) {
 struct thread_arg *arg=data;arg->result=rtl_fe_oam_configure(arg->fe);return NULL;
}
static void serialization(struct rtl_fe *fe) {
 struct thread_arg arg={fe,-1};pthread_t thread;
 reset(fe);mutex_lock(&fe->lock);
 assert(!pthread_create(&thread,NULL,oam_thread,&arg));
 unsigned attempt;
 for(attempt=0;attempt<1000000 && !atomic_load(&fe->lock.waiting);attempt++)sched_yield();
 assert(attempt<1000000);no_mmio();
 /* Existing FE owner completes a connector operation while OAM is blocked. */
 assert(!fe_access(fe,ACCESS,BIT(31)|24));
 u32 saved=fe_read(fe,DATA);
 fe_write(fe,DATA,saved);
 assert(!fe_access(fe,ACCESS,BIT(31)|BIT(30)|24));
 mutex_unlock(&fe->lock);
 assert(!pthread_join(thread,NULL) && arg.result==0);installed();
 assert(map[24]==saved && atomic_load(&fe->lock.waiting)==0);
}
int main(void) {
 struct rtl_fe fe={.registers=regs,.lock={.native=PTHREAD_MUTEX_INITIALIZER}};
 lifecycle(&fe);faults(&fe);serialization(&fe);
 assert(!owns_fe && !pthread_mutex_destroy(&fe.lock.native));
 puts("OAM owner: 4 banks, 12 command failures, 12 all-ones bus faults, busy retry/staging, readback, lifecycle, warm idempotence and FE concurrency passed");
}
'''


def changed(text, old, new):
    assert old in text, f"mutation target missing: {old!r}"
    return text.replace(old, new, 1)


mutants = {
    "unserialized-window": owner.replace("mutex_lock(&fe->lock);", "").replace(
        "mutex_unlock(&fe->lock);", ""),
    "busy-staging": changed(owner,
        "  ret=rtl_fe_window_idle(&io,0x1654);\n  if(ret)goto out;\n  fe_write",
        "  fe_write"),
    "missing-bank": changed(owner, "i<ARRAY_SIZE(index)", "i<ARRAY_SIZE(index)-1"),
    "missing-readback": changed(owner,
        "  if(value==~0U || (value&15)!=12) {ret=-EIO;goto out;}", ""),
    "scheduler-clobber": changed(owner,
        "(value&~0x00ff80ffU)|0x000600ffU", "0x000600ffU"),
    "inherited-flush": owner.replace("0x00ff80ffU", "0x00ff00ffU"),
    "suspended-engine": changed(owner,
        " if(!fe->engine_ready) {ret=-EAGAIN;goto out;}", ""),
    "hidden-timeout": changed(owner,
        "  ret=fe_access(fe,0x1654,BIT(31)|BIT(30)|index[i]);\n  if(ret)goto out;",
        "  ret=fe_access(fe,0x1654,BIT(31)|BIT(30)|index[i]);\n  if(ret) {ret=0;goto out;}"),
    "false-all-ones-success": changed(owner,
        " if(value==~0U || !(value&BIT(12)))ret=-EIO;",
        " if(!(value&BIT(12)))ret=-EIO;"),
}


def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


with tempfile.TemporaryDirectory(prefix="ni-oam-owner-") as temp:
    directory = Path(temp)
    for name, selected_owner in [("production", owner), *mutants.items()]:
        c = directory / f"{name}.c"
        exe = directory / name
        c.write_text(fixture + helpers + selected_owner + wrapper + cases)
        subprocess.run([
            "cc", "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=address,undefined", "-pthread", str(c), "-o", str(exe)
        ], check=True)
        result = subprocess.run([str(exe)], text=True, capture_output=True,
                                preexec_fn=no_core, timeout=20,
                                env=dict(os.environ, ASAN_OPTIONS="detect_leaks=0:halt_on_error=1",
                                         UBSAN_OPTIONS="halt_on_error=1"))
        if name == "production":
            if result.returncode:
                raise AssertionError(result.stdout + result.stderr)
            print(result.stdout, end="")
        elif not result.returncode:
            raise AssertionError(f"regression incorrectly passed: {name}")
        elif result.returncode != -signal.SIGABRT or "Assertion" not in result.stderr:
            raise AssertionError(f"mutation did not reach its test assertion: {name}\n{result.stderr}")
    print(f"OAM owner: {len(mutants)} focused mutation controls rejected")
