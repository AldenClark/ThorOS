#!/usr/bin/env python3
"""Execute real FE/FDB prerequisite code with a read-only host MMIO model.

R12 hardware has an unowned cold fabric and FDB CMD_MODE=0. A route must
reject that condition *before* reserving its Hash/source-MAC/DDR resources.
This does not turn on CMD_MODE or claim ASIC forwarding is working.
"""
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"
FE = (DRIVER / "rtl9617c-fe.c").read_text()
FDB = (DRIVER / "rtl9617c-l2-table.h").read_text()


def function(source, prefix, name):
    start = re.search(r"^" + prefix + r" " + name + r"\(", source, re.M)
    assert start, name
    start = start.start()
    finish = source.index("{", start) + 1
    depth = 1
    while depth:
        depth += (source[finish] == "{") - (source[finish] == "}")
        finish += 1
    return source[start:finish]


IO_VALID = function(FDB, "static inline int", "rtl_l2_io_valid")
CONTROL_READ = function(FDB, "static inline int", "rtl_l2_fdb_control_read")
PREFLIGHT = function(FE, "static int", "fe_destination_mode_preflight")
INSTALL = function(FE, "static int", "fe_install")
assert INSTALL.index("observe->stage=FE_INSTALL_FDB_MODE") < INSTALL.index(
    "rtl_fe_hash_bucket(crc16)"
), "preflight must precede hash index, cache and resource reservation"
assert INSTALL.index("ret=fe_destination_mode_preflight(fe)") < INSTALL.index(
    "__set_bit(index,fe->hashes)"
), "preflight must precede mutation of live owners"
assert INSTALL.index("ret=fe_destination_mode_preflight(fe)") < INSTALL.index(
    "flow=kzalloc"
), "preflight must precede flow allocation"
assert INSTALL.index("ret=fe_destination_mode_preflight(fe)") < INSTALL.index(
    "ret=fe_source_get"
), "preflight must precede source MAC allocation"
assert "ret=rtl_l2_fdb_command(io," in (DRIVER / "rtl9617c-fe-pipeline.h").read_text(), (
    "destination FDB command must retain its independent live mode recheck"
)

FIXTURE = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rtl9617c-fe-observe.h"
#define RTL_L2_ACCESS_BUSY 0x80000000U
#define RTL_L2_FDB_CONTROL 0x1c00U
#define RTL_L2_FDB_ACCESS 0x1ca0U
#define RTL_L2_FDB_LIMIT_ACCESS 0x1cb4U
#define RTL_L2_FDB_CMD_MODE 0x80000000U
#define RTL_L2_FDB_INFO_INIT (1U << 30)
struct rtl_dq_io {
 void *context;
 unsigned int (*read)(void *,unsigned int);
 void (*write)(void *,unsigned int,unsigned int);
 int (*indirect)(void *,unsigned int,unsigned int);
};
struct mock_io {
 unsigned int control,access,limit;
 unsigned int reads,writes,indirects;
};
struct rtl_l2_owner {
 unsigned int sealed;
 struct {unsigned int quarantined;} ledger;
 struct {unsigned int quarantined;} journal;
};
struct rtl_fe {
 struct {unsigned int ready,poisoned;} fabric;
 struct rtl_l2_owner *l2_owner;
 struct mock_io io;
 struct rtl_fe_observe observe;
};
static unsigned int mock_read(void *context,unsigned int addr) {
 struct mock_io *io=context;io->reads++;
 switch(addr){
 case RTL_L2_FDB_CONTROL:return io->control;
 case RTL_L2_FDB_ACCESS:return io->access;
 case RTL_L2_FDB_LIMIT_ACCESS:return io->limit;
 default:assert(0);return 0;
 }
}
static void mock_write(void *context,unsigned int addr,unsigned int value) {
 (void)addr;(void)value;((struct mock_io *)context)->writes++;
}
static int mock_indirect(void *context,unsigned int addr,unsigned int value) {
 (void)addr;(void)value;((struct mock_io *)context)->indirects++;return 0;
}
static struct rtl_dq_io fe_io(struct rtl_fe *fe) {
 return (struct rtl_dq_io){&fe->io,mock_read,mock_write,mock_indirect};
}
'''

TEST = r'''
static unsigned int cases;
#define SEMANTIC_CHECK(condition) do { \
 if (!(condition)) { \
  fprintf(stderr,"FDB_SEMANTIC_ASSERT reason=%u expr=%s\n",reason,#condition); \
  exit(73); \
 } \
} while(0)
static void prepare(struct rtl_fe *fe,struct rtl_l2_owner *owner) {
 memset(fe,0,sizeof(*fe));memset(owner,0,sizeof(*owner));
 owner->sealed=1;fe->fabric.ready=1;fe->l2_owner=owner;
 fe->io.control=0x9ca00ff9U; /* R12 raw value with CMD mode set in mock */
}
static void expect(struct rtl_fe *fe,int ret,unsigned int reason,unsigned int sampled) {
 SEMANTIC_CHECK(fe_destination_mode_preflight(fe)==ret);
 SEMANTIC_CHECK(fe->observe.last_fdb_mode_error==ret);
 SEMANTIC_CHECK(fe->observe.last_fdb_mode_reason==reason);
 SEMANTIC_CHECK(fe->observe.fdb_mode_reason[reason]==1);
 SEMANTIC_CHECK(fe->observe.last_fdb_mode_sampled==sampled);
 SEMANTIC_CHECK(fe->observe.last_fdb_mode_control==(sampled?fe->io.control:0));
 SEMANTIC_CHECK(!fe->io.writes && !fe->io.indirects);
 cases++;
}
int main(void){
 struct rtl_fe fe;struct rtl_l2_owner owner;
 prepare(&fe,&owner);fe.fabric.ready=0;
 expect(&fe,-EAGAIN,FE_FDB_MODE_FABRIC_UNREADY,0);
 assert(!fe.io.reads);
 prepare(&fe,&owner);fe.l2_owner=NULL;
 expect(&fe,-EAGAIN,FE_FDB_MODE_OWNER_UNREADY,0);
 assert(!fe.io.reads);
 prepare(&fe,&owner);owner.sealed=0;
 expect(&fe,-EAGAIN,FE_FDB_MODE_OWNER_UNREADY,0);
 assert(!fe.io.reads);
 prepare(&fe,&owner);fe.fabric.poisoned=1;
 expect(&fe,-EIO,FE_FDB_MODE_OWNER_FAULT,0);
 assert(!fe.io.reads);
 prepare(&fe,&owner);owner.ledger.quarantined=1;
 expect(&fe,-EIO,FE_FDB_MODE_OWNER_FAULT,0);
 assert(!fe.io.reads);
 prepare(&fe,&owner);owner.journal.quarantined=1;
 expect(&fe,-EIO,FE_FDB_MODE_OWNER_FAULT,0);
 assert(!fe.io.reads);
 prepare(&fe,&owner);fe.io.access=RTL_L2_ACCESS_BUSY;
 expect(&fe,-EBUSY,FE_FDB_MODE_WINDOW_BUSY,0);
 assert(fe.io.reads==2);
 prepare(&fe,&owner);fe.io.limit=RTL_L2_ACCESS_BUSY;
 expect(&fe,-EBUSY,FE_FDB_MODE_WINDOW_BUSY,0);
 assert(fe.io.reads==2);
 prepare(&fe,&owner);fe.io.access=~0U;
 expect(&fe,-EIO,FE_FDB_MODE_READ_ERROR,0);
 assert(fe.io.reads==2);
 prepare(&fe,&owner);fe.io.limit=~0U;
 expect(&fe,-EIO,FE_FDB_MODE_READ_ERROR,0);
 assert(fe.io.reads==2);
 prepare(&fe,&owner);fe.io.control|=RTL_L2_FDB_INFO_INIT;
 expect(&fe,-EOPNOTSUPP,FE_FDB_MODE_INFO_INIT,0);
 assert(fe.io.reads==3);
 prepare(&fe,&owner);fe.io.control=~0U;
 expect(&fe,-EIO,FE_FDB_MODE_READ_ERROR,0);
 assert(fe.io.reads==3);
 prepare(&fe,&owner);fe.io.control=0x1ca00ff9U; /* real R12 control */
 expect(&fe,-EOPNOTSUPP,FE_FDB_MODE_CMD_DISABLED,1);
 assert(fe.io.reads==3);
 prepare(&fe,&owner);
 expect(&fe,0,FE_FDB_MODE_READY,1);
 assert(fe.io.reads==3);
 /* Multiple different failures are counted rather than collapsed into
  * the last snapshot; do not confuse install stage with packet counts. */
 fe.io.control=0x1ca00ff9U;
 assert(fe_destination_mode_preflight(&fe)==-EOPNOTSUPP);
 assert(fe.observe.fdb_mode_reason[FE_FDB_MODE_READY]==1);
 assert(fe.observe.fdb_mode_reason[FE_FDB_MODE_CMD_DISABLED]==1);
 assert(fe.observe.last_fdb_mode_reason==FE_FDB_MODE_CMD_DISABLED);
 assert(fe.observe.last_fdb_mode_control==0x1ca00ff9U);
 assert(!fe.io.writes && !fe.io.indirects);
 printf("FE FDB-mode preflight: %u owner/mode/IO cases and mixed failure accounting PASS\n",cases);
 return 0;
}
'''


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = dict(os.environ)
    env.setdefault("ASAN_OPTIONS", "detect_leaks=0")
    mutations = {
        "skip_fabric": ("else if(!fe->fabric.ready)", "else if(0)"),
        "skip_owner": ("else if(!fe->l2_owner || !fe->l2_owner->sealed)", "else if(0)"),
        "skip_fault": ("if(fe->fabric.poisoned ||", "if(0 ||"),
        "skip_journal_quarantine": ("fe->l2_owner->journal.quarantined", "0"),
        "skip_live_probe": ("ret=rtl_l2_fdb_control_read(&io,&control);", "ret=((void)io,0);"),
        "ignore_cmd": ("if(!(control&RTL_L2_FDB_CMD_MODE))", "if(0)"),
        "invert_cmd": ("if(!(control&RTL_L2_FDB_CMD_MODE))", "if(control&RTL_L2_FDB_CMD_MODE)"),
    }
    # Reason codes are the actual enum constants in rtl9617c-fe-observe.h.
    # Only the intended fixture check may reject a mutant. Sanitizer crashes,
    # an unexpected signal or a failed compiler are never successes.
    expected_reasons = {
        "skip_fabric": 1, "skip_owner": 2, "skip_fault": 3,
        "skip_journal_quarantine": 3, "skip_live_probe": 4,
        "ignore_cmd": 6, "invert_cmd": 6,
    }
    variants = {"production": PREFLIGHT}
    for name, (before, after) in mutations.items():
        assert PREFLIGHT.count(before) == 1, name
        variants[name] = PREFLIGHT.replace(before, after, 1)
    with tempfile.TemporaryDirectory(prefix="fe-fdb-mode-") as directory:
        for name, body in variants.items():
            path = Path(directory) / (name + ".c")
            binary = path.with_suffix("")
            path.write_text(FIXTURE + IO_VALID + CONTROL_READ + body + TEST)
            # Apple Clang treats -no-pie as an unused/unsupported linker
            # argument under -Werror; Linux keeps the deterministic non-PIE
            # executable needed by this host ASan/UBSan model.
            platform_flags = [] if sys.platform == "darwin" else ["-fno-pie", "-no-pie"]
            # The skipped live-probe mutant intentionally leaves the extracted
            # read helper unused. That variant must compile and be rejected by
            # the runtime assertion, not by a compiler warning.
            mutation_flags = ["-Wno-unused-function"] if name == "skip_live_probe" else []
            subprocess.run([
                os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                "-g", "-O1", "-fsanitize=address,undefined", *platform_flags,
                *mutation_flags,
                "-I" + str(DRIVER), str(path), "-o", str(binary),
            ], check=True, capture_output=True, text=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True, env=env)
            if name == "production":
                assert result.returncode == 0, result.stderr
                print(result.stdout.strip(), flush=True)
            else:
                marker = f"FDB_SEMANTIC_ASSERT reason={expected_reasons[name]} expr="
                assert result.returncode == 73 and marker in result.stderr, (
                    name, result.returncode, result.stderr)
    print(f"FE FDB-mode preflight: {len(mutations)} semantic mutants rejected")


if __name__ == "__main__":
    main()
