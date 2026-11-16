#!/usr/bin/env python3
"""Run the production L2 rollback journal with bounded MMIO fault injection.

The test includes the real header, not a Python copy of its state machine.
It checks preservation/order/retained ownership; test_l2_sdk_contract.py is the
independent pinned-register oracle.  Neither test establishes wire throughput.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"
HEADER = DRIVER / "rtl9617c-l2-resources.h"

TEST = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "rtl9617c-l2-resources.h"

#define MAX_ROWS 16384U
struct model {
 unsigned int regs[0x10000 / 4];
 unsigned int rows[RTL_L2_TBL_COUNT][RTL_L2_VLAN_IDS][RTL_L2_TABLE_MAX_WORDS];
 struct rtl_l2_table_layout layout[RTL_L2_TBL_COUNT];
 unsigned int command, writes, reads, fault_at, ignore_at;
 int error;
 bool pending, checked[RTL_L2_TBL_COUNT];
 unsigned int pending_table, pending_index, pending_value;
 unsigned int staging[RTL_L2_TABLE_MAX_WORDS];
 unsigned int order_table[MAX_ROWS * 2], order_index[MAX_ROWS * 2], order_count;
};
static struct model m;
static struct rtl_l2_snapshot rows[MAX_ROWS];
static unsigned short row_index[MAX_ROWS];
static struct rtl_l2_journal journal;
static unsigned int count, cases, faults, tested_rows;

static unsigned int seed(unsigned int table, unsigned int index, unsigned int word)
{
 return 0xdead0000U ^ (table * 0x10101U) ^ (index * 0x101U) ^ word;
}
static unsigned int changed(unsigned int table, unsigned int index, unsigned int word)
{
 return seed(table, index, word) ^ 0x55aa55aaU;
}
static void complete(bool apply)
{
 unsigned int table = m.pending_table, index = m.pending_index, word;
 const struct rtl_l2_table_layout *l = &m.layout[table];
 assert(m.pending && (m.regs[l->access / 4] & RTL_L2_ACCESS_BUSY));
 if (m.pending_value & RTL_L2_ACCESS_WRITE) {
  assert(m.order_count < MAX_ROWS * 2);
  m.order_table[m.order_count] = table;
  m.order_index[m.order_count++] = index;
  for (word = 0; word < l->words; word++) {
   assert(m.regs[(l->data0 - 4 * word) / 4] == m.staging[word]);
   if (apply) m.rows[table][index][word] = m.staging[word];
  }
 } else {
  for (word = 0; word < l->words; word++)
   m.regs[(l->data0 - 4 * word) / 4] = m.rows[table][index][word];
 }
 m.regs[l->access / 4] = 0;
 m.pending = false;
}
static unsigned int mm_read(void *unused, unsigned int address)
{
 unsigned int table;
 (void)unused;
 assert(!(address & 3) && address < sizeof(m.regs));
 for (table = 0; table < RTL_L2_TBL_COUNT; table++) {
  const struct rtl_l2_table_layout *l = &m.layout[table];
  if (address == l->access)
   m.checked[table] = !(m.regs[address / 4] & RTL_L2_ACCESS_BUSY);
  if (address <= l->data0 && address > l->data0 - l->words * 4)
   assert(!(m.regs[l->access / 4] & RTL_L2_ACCESS_BUSY));
 }
 m.reads++;
 return m.regs[address / 4];
}
static void mm_write(void *unused, unsigned int address, unsigned int value)
{
 unsigned int table;
 bool matched = false;
 (void)unused;
 assert(!(address & 3) && address < sizeof(m.regs));
 for (table = 0; table < RTL_L2_TBL_COUNT; table++) {
  const struct rtl_l2_table_layout *l = &m.layout[table];
  if (address <= l->data0 && address > l->data0 - l->words * 4) {
   assert(m.checked[table]);
   assert(!(m.regs[l->access / 4] & RTL_L2_ACCESS_BUSY));
   matched = true;
  }
 }
 assert(matched); /* No global reset, FDB pin or unrelated register writes. */
 m.writes++;
 m.regs[address / 4] = value;
}
static int mm_command(void *unused, unsigned int address, unsigned int value)
{
 unsigned int table, word, index = value & ~(RTL_L2_ACCESS_BUSY | RTL_L2_ACCESS_WRITE);
 (void)unused;
 assert(!m.pending);
 for (table = 0; table < RTL_L2_TBL_COUNT; table++)
  if (address == m.layout[table].access) break;
 assert(table < RTL_L2_TBL_COUNT && index < m.layout[table].entries);
 assert(m.checked[table] && !(m.regs[address / 4] & RTL_L2_ACCESS_BUSY));
 assert(value & RTL_L2_ACCESS_BUSY);
 for (word = 0; word < m.layout[table].words; word++)
  m.staging[word] = m.regs[(m.layout[table].data0 - word * 4) / 4];
 m.pending = true; m.pending_table = table; m.pending_index = index;
 m.pending_value = value; m.regs[address / 4] = value;
 m.command++;
 if (m.command == m.fault_at) return m.error;
 complete(m.command != m.ignore_at);
 return 0;
}
static const struct rtl_dq_io io = { NULL, mm_read, mm_write, mm_command };

static void reset(unsigned int capacity)
{
 unsigned int table, index, word;
 memset(&m, 0, sizeof(m)); memset(&journal, 0, sizeof(journal));
 memset(rows, 0, sizeof(rows)); memset(row_index, 0xa5, sizeof(row_index)); count = 0;
 for (table = 0; table < RTL_L2_TBL_COUNT; table++) {
  assert(!rtl_l2_table_layout(table, &m.layout[table]));
  for (index = 0; index < m.layout[table].entries; index++)
   for (word = 0; word < m.layout[table].words; word++)
    m.rows[table][index][word] = seed(table, index, word);
 }
 assert(!rtl_l2_journal_init(&journal, row_index, rtl_l2_journal_index_count(), capacity));
}
static int replace(unsigned int table, unsigned int index)
{
 unsigned int word, values[RTL_L2_TABLE_MAX_WORDS];
 for (word = 0; word < RTL_L2_TABLE_MAX_WORDS; word++) values[word] = changed(table, index, word);
 return rtl_l2_journal_replace(&journal, &io, rows, &count, table, index, values);
}
static void baseline(void)
{
 for (unsigned int table = 0; table < RTL_L2_TBL_COUNT; table++)
  for (unsigned int index = 0; index < m.layout[table].entries; index++)
   for (unsigned int word = 0; word < m.layout[table].words; word++)
    assert(m.rows[table][index][word] == seed(table, index, word));
}
static void finish(void)
{
 assert(!rtl_l2_journal_restore(&journal, &io, rows, count, 1));
 assert(journal.restoring && journal.restored);
 assert(!rtl_l2_journal_release(&journal, rows, &count));
 assert(!count && !journal.quarantined && !journal.restoring && !journal.restored);
 for (unsigned int i = 0; i < journal.index_count; i++) assert(!row_index[i]);
 baseline();
}

static void geometry_and_capacity(void)
{
 /* Independent public silicon/API capacities, NOT a duplicate lookup of
  * the same production layouts. The pinned SDK suite checks the addresses. */
 const unsigned int expected[RTL_L2_TBL_COUNT] = {
  [RTL_L2_TBL_ILPB]=64, [RTL_L2_TBL_ELPB]=64, [RTL_L2_TBL_SPB]=256,
  [RTL_L2_TBL_DFT_FWD]=256, [RTL_L2_TBL_MEMBERSHIP_ID]=64,
  [RTL_L2_TBL_PORT_MEMBERSHIP]=64, [RTL_L2_TBL_VLAN_LAN_INDEX]=4096,
  [RTL_L2_TBL_VLAN_FIB]=128, [RTL_L2_TBL_MC_FIB]=64,
  [RTL_L2_TBL_MC_VECTOR]=256, [RTL_L2_TBL_REDIR_LDPID]=64,
  [RTL_L2_TBL_REDIR_DROP]=32, [RTL_L2_TBL_CF_KEY]=1024,
  [RTL_L2_TBL_CF_FIB]=512, [RTL_L2_TBL_IPPB]=64,
  [RTL_L2_TBL_SPECIAL_PRIORITY]=31,
  [RTL_L2_TBL_VLAN_WAN_S_INDEX]=4096, [RTL_L2_TBL_VLAN_WAN_C_INDEX]=4096
 };
 unsigned int total = 0, table, index;
 for (table = 0; table < RTL_L2_TBL_COUNT; table++) { assert(expected[table]); total += expected[table]; }
 assert(total == rtl_l2_journal_index_count() && total <= MAX_ROWS);
 reset(total);
 for (table = 0; table < RTL_L2_TBL_COUNT; table++) {
  assert(m.layout[table].entries == expected[table]);
  for (index = 0; index < expected[table]; index++) {
   unsigned int previous = count;
   struct rtl_l2_snapshot *snapshot = NULL;
   assert(!replace(table, index) && count == previous + 1);
   assert(!rtl_l2_journal_find(&journal, rows, count, table, index, &snapshot));
   assert(snapshot == &rows[previous] && snapshot->valid);
   for (unsigned int word = 0; word < m.layout[table].words; word++)
    assert(snapshot->words[word] == seed(table, index, word));
   tested_rows++;
  }
 }
 assert(count == total);
 /* A second write does not re-snapshot the already modified hardware. */
 unsigned int commands = m.command;
 assert(!replace(RTL_L2_TBL_MC_VECTOR, 7) && count == total && m.command == commands + 2);
 unsigned int values[RTL_L2_TABLE_MAX_WORDS] = {0};
 unsigned int writes = m.writes;
 assert(rtl_l2_journal_release(&journal, rows, &count) == -EBUSY);
 assert(rtl_l2_journal_restore(&journal, &io, rows, count, 0) == -EBUSY);
 assert(m.writes == writes && count == total);
 assert(rtl_l2_journal_replace(&journal, &io, rows, &count,
        RTL_L2_TBL_COUNT, 0, values) == -EINVAL && m.writes == writes);
 unsigned int first_restore = m.order_count;
 assert(!rtl_l2_journal_restore(&journal, &io, rows, count, 1));
 for (unsigned int i = 0; i < total; i++) {
  assert(m.order_table[first_restore + i] == (unsigned int)rows[total - i - 1].table);
  assert(m.order_index[first_restore + i] == rows[total - i - 1].index);
  assert(rows[i].valid);
 }
 assert(count == total && journal.restored);
 assert(replace(RTL_L2_TBL_MC_VECTOR, 7) == -EBUSY);
 assert(!rtl_l2_journal_release(&journal, rows, &count)); baseline(); cases++;
 reset(1); assert(!replace(RTL_L2_TBL_VLAN_FIB, 3)); writes = m.writes; commands = m.command;
 assert(replace(RTL_L2_TBL_VLAN_FIB, 4) == -ENOSPC);
 assert(m.writes == writes && m.command == commands && count == 1);
 assert(!replace(RTL_L2_TBL_VLAN_FIB, 3)); finish(); cases++;
}

static void programming_faults(void)
{
 for (unsigned int table = 0; table < RTL_L2_TBL_COUNT; table++)
  for (unsigned int phase = 1; phase <= 3; phase++)
   for (unsigned int error = 0; error < 2; error++)
    for (unsigned int late_commit = 0; late_commit < 2; late_commit++) {
     reset(4); unsigned int index = m.layout[table].entries - 1;
     m.error = error ? -EIO : -ETIMEDOUT; m.fault_at = phase;
     assert(replace(table, index) == m.error && m.pending && journal.quarantined);
     assert(count == (phase == 1 ? 0U : 1U));
     struct rtl_l2_snapshot saved = rows[0];
     unsigned int writes = m.writes, commands = m.command;
     assert(replace(table, 0) == -EBUSY); /* Same ACCESS, aliased DATA staging. */
     assert(replace((table + 1) % RTL_L2_TBL_COUNT, 0) == -EBUSY);
     assert(rtl_l2_journal_release(&journal, rows, &count) == -EBUSY);
     assert(rtl_l2_journal_restore(&journal, &io, rows, count, 0) == -EBUSY);
     assert(rtl_l2_journal_restore(&journal, &io, rows, count, 1) == -EBUSY);
     assert(m.writes == writes && m.command == commands);
     assert(!memcmp(&saved, &rows[0], sizeof(saved)));
     complete(late_commit != 0); m.fault_at = 0;
     finish(); faults++; cases++;
    }
 /* Completed-but-ignored writes must fail readback and retain the original. */
 for (unsigned int table = 0; table < RTL_L2_TBL_COUNT; table++) {
  reset(2); m.ignore_at = 2;
  assert(replace(table, 0) == -EIO && !m.pending && count == 1 && journal.quarantined);
  finish(); faults++; cases++;
 }
}

static void restore_faults(void)
{
 /* Inject every restore write and its verification read in a dependency
  * chain. Prior successful rollbacks stay owned until the whole retry wins. */
 const unsigned int tables[] = { RTL_L2_TBL_MC_FIB, RTL_L2_TBL_MC_VECTOR,
                               RTL_L2_TBL_VLAN_FIB, RTL_L2_TBL_VLAN_LAN_INDEX };
 for (unsigned int phase = 1; phase <= 8; phase++)
  for (unsigned int error = 0; error < 2; error++)
   for (unsigned int late_commit = 0; late_commit < 2; late_commit++) {
    reset(4);
    for (unsigned int i = 0; i < 4; i++) assert(!replace(tables[i], 7));
    struct rtl_l2_snapshot saved[4]; memcpy(saved, rows, sizeof(saved));
    unsigned short saved_map[MAX_ROWS]; memcpy(saved_map, row_index, sizeof(saved_map));
    m.error = error ? -EIO : -ETIMEDOUT; m.fault_at = m.command + phase;
    assert(rtl_l2_journal_restore(&journal, &io, rows, count, 1) == m.error);
    assert(count == 4 && journal.restoring && journal.quarantined && !journal.restored);
    assert(!memcmp(saved, rows, sizeof(saved)) && !memcmp(saved_map, row_index, sizeof(saved_map)));
    unsigned int writes = m.writes, commands = m.command;
    assert(rtl_l2_journal_release(&journal, rows, &count) == -EBUSY);
    assert(replace(RTL_L2_TBL_ILPB, 0) == -EBUSY);
    assert(rtl_l2_journal_restore(&journal, &io, rows, count, 1) == -EBUSY);
    assert(m.writes == writes && m.command == commands);
    complete(late_commit != 0); m.fault_at = 0;
    finish(); faults++; cases++;
   }
 for (unsigned int phase = 1; phase <= 7; phase += 2) {
  reset(4);
  for (unsigned int i = 0; i < 4; i++) assert(!replace(tables[i], 7));
  m.ignore_at = m.command + phase;
  assert(rtl_l2_journal_restore(&journal, &io, rows, count, 1) == -EIO);
  assert(count == 4 && journal.quarantined && !journal.restored);
  m.ignore_at = 0; finish(); faults++; cases++;
 }
}

static void validation(void)
{
 unsigned int total = rtl_l2_journal_index_count();
 struct rtl_l2_journal empty = {0}, saved;
 unsigned int values[RTL_L2_TABLE_MAX_WORDS] = {0};
 struct rtl_l2_snapshot *output = &rows[MAX_ROWS - 1];
 reset(2); saved = journal;
 assert(rtl_l2_journal_init(&journal, row_index, total, 2) == -EBUSY);
 assert(!memcmp(&journal, &saved, sizeof(saved)));
 assert(rtl_l2_journal_init(&empty, row_index, total - 1, 1) == -EINVAL);
 assert(rtl_l2_journal_init(&empty, row_index, total, 0x10000) == -EINVAL);
 assert(rtl_l2_journal_init(&empty, row_index, total, total + 1) == -EINVAL);
 assert(rtl_l2_journal_init(&empty, NULL, total, 1) == -EINVAL);
 assert(rtl_l2_journal_init(NULL, row_index, total, 1) == -EINVAL);
 assert(rtl_l2_journal_init(&empty, row_index, total, 0) == -EINVAL);
 assert(rtl_l2_journal_find(&journal, rows, count, RTL_L2_TBL_ILPB, 0, &output) == -ENOENT);
 assert(output == &rows[MAX_ROWS - 1]);
 assert(rtl_l2_journal_replace(&journal, &io, rows, &count, RTL_L2_TBL_ILPB, 64, values) == -EINVAL);
 assert(rtl_l2_journal_replace(&journal, &io, rows, &count, (enum rtl_l2_table)-1, 0, values) == -EINVAL);
 assert(rtl_l2_journal_replace(&journal, &io, rows, &count, RTL_L2_TBL_ILPB, 0, NULL) == -EINVAL);
 assert(rtl_l2_journal_snapshot(&journal, NULL, rows, &count, RTL_L2_TBL_ILPB, 0, &output) == -EINVAL);
 assert(!m.command && !m.writes && !m.reads);
 /* Zero, all-ones, reserved bits are legal raw snapshot data. */
 memset(m.rows[RTL_L2_TBL_CF_KEY][0], 0xff, sizeof(m.rows[0][0]));
 assert(!replace(RTL_L2_TBL_CF_KEY, 0));
 assert(!rtl_l2_journal_restore(&journal, &io, rows, count, 1));
 for (unsigned int w = 0; w < 3; w++) assert(m.rows[RTL_L2_TBL_CF_KEY][0][w] == UINT_MAX);
 assert(!rtl_l2_journal_release(&journal, rows, &count)); cases++;
 /* Corrupt slot->snapshot mapping must not restore a different foreign row. */
 reset(2); assert(!replace(RTL_L2_TBL_MC_FIB, 7)); assert(!replace(RTL_L2_TBL_MC_VECTOR, 9));
 unsigned int slot;
 assert(!rtl_l2_journal_slot(&journal, RTL_L2_TBL_MC_FIB, 7, &slot));
 row_index[slot] = 2;
 unsigned int writes = m.writes;
 assert(rtl_l2_journal_find(&journal, rows, count, RTL_L2_TBL_MC_FIB, 7, &output) == -EUCLEAN);
 assert(rtl_l2_journal_restore(&journal, &io, rows, count, 1) == -EUCLEAN);
 assert(count == 2 && m.writes == writes && journal.quarantined);
 row_index[slot] = 1; finish(); cases++;
 /* Back-to-back owners reuse the allocation only after verified release. */
 assert(!replace(RTL_L2_TBL_VLAN_FIB, 127)); finish(); cases++;
 /* A foreign owner's unrelated row can change while ours is leased.  It
  * must remain exactly as that owner left it, not match an initial image. */
 reset(2); assert(!replace(RTL_L2_TBL_VLAN_FIB, 11));
 m.rows[RTL_L2_TBL_MC_FIB][61][0] = 0x12345678U;
 assert(!rtl_l2_journal_restore(&journal, &io, rows, count, 1));
 assert(m.rows[RTL_L2_TBL_MC_FIB][61][0] == 0x12345678U);
 assert(!rtl_l2_journal_release(&journal, rows, &count)); cases++;
 /* A late foreign read owns a shared window even if our journal has no
  * snapshot of that table. Do not begin any rollback while it is busy. */
 reset(2); assert(!replace(RTL_L2_TBL_VLAN_FIB, 11));
 unsigned int foreign_access = m.layout[RTL_L2_TBL_MC_VECTOR].access;
 m.regs[foreign_access / 4] = RTL_L2_ACCESS_BUSY;
 writes = m.writes;
 assert(rtl_l2_journal_restore(&journal, &io, rows, count, 1) == -EBUSY);
 assert(m.writes == writes && count == 1 && journal.quarantined);
 m.regs[foreign_access / 4] = 0; finish(); cases++;
}

static void cf_reserved_readback(void)
{
 const enum rtl_l2_table tables[]={RTL_L2_TBL_CF_KEY,RTL_L2_TBL_CF_FIB};
 /* Independent documented DATA2 masks: KEY TOS/type/valid and FIB
  * CPRI/tag-edit/COS. Reserved read-as-zero is not a programming fault. */
 const unsigned int masks[]={0x1f8ffU,0x3ffU};
 for(unsigned int t=0;t<2;t++)for(unsigned int bit=0;bit<32;bit++) {
  unsigned int expected[RTL_L2_TABLE_MAX_WORDS];
  reset(2);memcpy(expected,m.rows[tables[t]][0],sizeof(expected));
  expected[2]^=1U<<bit;
  assert(rtl_l2_journal_verify(&io,tables[t],0,expected)==
         ((masks[t]&(1U<<bit))?-EIO:0));
  for(unsigned int w=0;w<2;w++) {
   memcpy(expected,m.rows[tables[t]][0],sizeof(expected));expected[w]^=1U<<bit;
   assert(rtl_l2_journal_verify(&io,tables[t],0,expected)==-EIO);
  }
  cases++;
 }
}

int main(void)
{
 geometry_and_capacity(); programming_faults(); restore_faults(); validation(); cf_reserved_readback();
 printf("{\"cases\":%u,\"faults\":%u,\"rows\":%u}\n", cases, faults, tested_rows);
 return 0;
}
'''


def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run(header: str, sanitizer: bool = False) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory(prefix="rtl-l2-resources-") as temp:
        work = Path(temp)
        (work / HEADER.name).write_text(header)
        source = work / "test.c"
        source.write_text(TEST)
        binary = work / "test"
        command = [os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                   "-I", str(work), "-I", str(DRIVER), str(source), "-o", str(binary)]
        if sanitizer:
            command[1:1] = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie"]
        subprocess.run(command, check=True, capture_output=True, text=True)
        env = os.environ.copy()
        return subprocess.run([str(binary)], capture_output=True, text=True,
                              preexec_fn=no_core, env=env)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mutants", action="store_true")
    parser.add_argument("--sanitize", action="store_true")
    args = parser.parse_args()
    header = HEADER.read_text()
    actual = run(header, args.sanitize)
    if actual.returncode:
        raise SystemExit(actual.stdout + actual.stderr)
    result = json.loads(actual.stdout)
    result["header_sha256"] = hashlib.sha256(header.encode()).hexdigest()
    mutants = {
        "skip_write_readback": ("ret = rtl_l2_journal_verify(io, table, index, words);", "ret = 0;"),
        "forget_quarantine": ("if (journal->quarantined || journal->restoring)", "if (journal->restoring)"),
        "rollback_without_drain": ("if (!drained)", "if (drained == 0xffffffffU)"),
        "release_unrestored_owner": ("if (!journal->restored)", "if (0)"),
        "skip_restore_readback": ("ret = rtl_l2_journal_verify(io, row->table, row->index, row->words);", "ret = 0;"),
        "replace_original_snapshot": ("*snapshot = original;\n\t\treturn 0;", "*snapshot = original;\n\t\treturn rtl_l2_table_read(io, table, index, original->words);"),
        "wrong_rollback_order": ("const struct rtl_l2_snapshot *row = &rows[i - 1];", "const struct rtl_l2_snapshot *row = &rows[count - i];"),
        "discard_restored_rows_early": ("journal->restored = 1;", "((struct rtl_l2_snapshot *)rows)[0].valid = 0;\n\tjournal->restored = 1;"),
        "ignore_foreign_busy_window": ("if (io->read(io->context, layout.access) & RTL_L2_ACCESS_BUSY)", "if (0 && (io->read(io->context, layout.access) & RTL_L2_ACCESS_BUSY))"),
        "reject_cf_reserved_read_as_zero": ("mask = 0x1f8ffU;", "mask = ~0U;"),
        "ignore_cf_valid_bit": ("mask = 0x1f8ffU;", "mask = 0xf8ffU;"),
    }
    rejected = []
    if args.mutants:
        for name, (before, after) in mutants.items():
            if header.count(before) != 1:
                raise SystemExit(f"Mutation is not unique: {name}")
            mutated = run(header.replace(before, after))
            if not mutated.returncode:
                raise SystemExit(f"SURVIVED: {name}")
            rejected.append(name)
    result["mutants_rejected"] = rejected
    result["sanitizers"] = args.sanitize
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
