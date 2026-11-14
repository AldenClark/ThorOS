#!/usr/bin/env python3
"""Execute the cold fabric owner against inherited state and MMIO failures.

The model checks control ownership, ordering and readback. It does not model
ASIC timing or establish a full L3/DDR retirement contract.
"""
import hashlib
import argparse
import json
import os
from pathlib import Path
import resource
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"
HEADER = DRIVER / "rtl9617c-fabric.h"
REGISTER_SHA = "ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0"

TEST = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
static unsigned int delays;
static void usleep_range(unsigned int low, unsigned int high)
 { assert(low==10 && high==20); delays++; }
#include "rtl9617c-fabric.h"

struct model {
 unsigned int reg[0x10000/4], original[0x10000/4];
 unsigned int writes, scans, vlan_writes, reads, pp_reads;
 unsigned int pending_reg, pending_remaining, permanent_pending;
 unsigned int drop_reg, drop_occurrence, drop_seen;
 unsigned int inherited, scan_result, scan_timeout, busy_on_scan;
 unsigned int corrupt_vlan, rollback_stuck, write_busy;
 unsigned int rx_writes[5];
};
static struct model m;
static unsigned int cases;

static bool fdb_busy(void) {
 return (m.reg[RTL_L2_FDB_ACCESS/4] |
         m.reg[RTL_L2_FDB_LIMIT_ACCESS/4]) & RTL_L2_ACCESS_BUSY;
}
static unsigned int read_reg(void *ctx,unsigned int reg) {
 (void)ctx;assert(!(reg&3) && reg<sizeof(m.reg));m.reads++;
 if(reg==0x11c0)m.pp_reads++;
 if(reg==m.pending_reg && (m.pending_remaining || m.permanent_pending)) {
  if(m.pending_remaining)m.pending_remaining--;
  return reg==0x11c0?1U:2U;
 }
 return m.reg[reg/4];
}
static void write_reg(void *ctx,unsigned int reg,unsigned int value) {
 (void)ctx;assert(!(reg&3) && reg<sizeof(m.reg));m.writes++;
 /* Read-only framing policy: no hidden UNI shrink or storage/TPID write. */
 assert(reg!=RTL_FABRIC_FRAME_LENGTH && reg!=RTL_FABRIC_STORAGE_LENGTH && !(reg>=0x1108 && reg<=0x1114));
 if(reg==RTL_L2_FDB_CONTROL ||
    (reg>=0x1c18 && reg<=RTL_L2_FDB_FILTER_WORD0) ||
    reg==RTL_L2_FDB_RETURN ||
    (reg<=RTL_L2_FDB_DATA0 && reg>RTL_L2_FDB_DATA0-RTL_L2_FDB_WORDS*4)) {
  assert(!fdb_busy());
 }
 for(unsigned i=0;i<5;i++)if(reg==RTL_FABRIC_RX(i)) {
  m.rx_writes[i]++;
  assert((value&RTL_FABRIC_RX_OVERSIZE_ALLOW)==(m.original[reg/4]&RTL_FABRIC_RX_OVERSIZE_ALLOW));
 }
 if(reg==m.drop_reg && ++m.drop_seen==m.drop_occurrence)return;
 if(reg==RTL_L2_VLAN_MODE_CONTROL) {
  m.vlan_writes++;
  assert(m.pp_reads>=3 && m.scans);
  assert(m.reg[RTL_L2_FDB_CONTROL/4]&RTL_L2_FDB_LEARN_DISABLE);
  for(unsigned int i=0;i<5;i++)
   assert((m.reg[RTL_FABRIC_RX(i)/4]&RTL_FABRIC_RX_SELECTOR)==RTL_FABRIC_RX_CPU);
  if(m.vlan_writes==1 && m.corrupt_vlan)value^=0x10;
  if(m.vlan_writes>1 && m.rollback_stuck)value|=1;
 }
 m.reg[reg/4]=value;
}
static int indirect(void *ctx,unsigned int reg,unsigned int value) {
 (void)ctx;assert(reg==RTL_L2_FDB_ACCESS && !fdb_busy());
 assert((value&255U)==RTL_L2_FDB_SCAN);
 assert((value>>8 & 8191U)==0);
 assert(m.reg[RTL_L2_FDB_CONTROL/4]&RTL_L2_FDB_LEARN_DISABLE);
 assert(m.reg[RTL_L2_FDB_CONTROL/4]&RTL_L2_FDB_CMD_MODE);
 /* Independent literal all-valid filter predicates. The inherited narrow
  * filter would hide the row and produce a false empty result. */
 assert((m.reg[0x1c28/4]&63U)==0);
 assert((m.reg[0x1c24/4]&63U)==63U);
 assert((m.reg[0x1c18/4]&0x7fffU)==0x7ffeU);
 assert(m.pp_reads>=3);m.scans++;
 m.reg[reg/4]=value;
 if(m.scan_timeout)return -ETIMEDOUT;
 m.reg[reg/4]=0;
 m.reg[RTL_L2_FDB_RETURN/4]=m.inherited ?
  RTL_L2_FDB_STATUS_HIT|(4127U<<4):m.scan_result;
 if(m.inherited) {
  struct rtl_l2_fdb_entry row={.mac={2,1,2,3,4,5},.valid=1,
   .destination=63,.key_vid=4094,.key_sc=1,.age=3};
  unsigned int words[RTL_L2_FDB_WORDS];
  row.is_static=m.inherited==2;row.multicast=m.inherited==3;
  assert(!rtl_l2_fdb_encode(words,&row));
  for(unsigned i=0;i<RTL_L2_FDB_WORDS;i++)m.reg[(RTL_L2_FDB_DATA0-i*4)/4]=words[i];
 }
 if(m.busy_on_scan)m.reg[RTL_L2_FDB_LIMIT_ACCESS/4]=RTL_L2_ACCESS_BUSY;
 return 0;
}
static struct rtl_dq_io io={&m,read_reg,write_reg,indirect};
/*SDK_DECL*/

static void setup(unsigned int seed) {
 memset(&m,0,sizeof(m));delays=0;
 for(unsigned i=0;i<sizeof(m.reg)/sizeof(m.reg[0]);i++)
  m.reg[i]=(i*2654435761U)^seed;
 m.reg[RTL_L2_FDB_CONTROL/4]=0x10800ff9U;
 m.reg[RTL_L2_FDB_ACCESS/4]=m.reg[RTL_L2_FDB_LIMIT_ACCESS/4]=0;
 m.reg[RTL_L2_VLAN_MODE_CONTROL/4]=(seed&0xffffffe0U)|2;
 m.reg[0x11c0/4]=0x12341234;m.reg[0x1534/4]=0;
 m.reg[0x175c/4]=m.reg[0x1904/4]=0;
 m.reg[0xa034/4]=0x004023f1;m.reg[0xa038/4]=0x2454;
 m.reg[0x1108/4]=m.reg[0x110c/4]=m.reg[0x1110/4]=0x8100;
 m.reg[0x1114/4]=0x9100;
 /* Deliberately narrow inherited SCAN predicates. */
 m.reg[0x1c28/4]|=31;m.reg[0x1c24/4]&=~63U;m.reg[0x1c18/4]&=~0x7fffU;
 m.scan_result=RTL_L2_FDB_STATUS_MISS;
 memcpy(m.original,m.reg,sizeof(m.reg));
}
static void command_restored(const struct rtl_fabric *f) {
 assert(m.reg[RTL_L2_FDB_CONTROL/4]==(m.original[RTL_L2_FDB_CONTROL/4]|
  (f->ready?RTL_L2_FDB_LEARN_DISABLE:0)));
 for(unsigned i=0;i<RTL_L2_FDB_FILTER_WORDS;i++)
  assert(m.reg[(RTL_L2_FDB_FILTER_WORD0-i*4)/4]==
         m.original[(RTL_L2_FDB_FILTER_WORD0-i*4)/4]);
}
static void baseline_preserved(const struct rtl_fabric *f) {
 (void)f;assert(m.reg[0xa034/4]==m.original[0xa034/4]);
 assert(m.reg[0xa038/4]==m.original[0xa038/4]);
 for(unsigned i=0;i<4;i++)assert(m.reg[(0x1108+i*4)/4]==m.original[(0x1108+i*4)/4]);
 for(unsigned i=0;i<5;i++) {
  unsigned reg=RTL_FABRIC_RX(i)/4;
  assert((m.reg[reg]&~(RTL_FABRIC_RX_SELECTOR|RTL_FABRIC_RX_OVERSIZE_ALLOW))==(m.original[reg]&~(RTL_FABRIC_RX_SELECTOR|RTL_FABRIC_RX_OVERSIZE_ALLOW)));
  assert((m.reg[reg]&RTL_FABRIC_RX_OVERSIZE_ALLOW)==(m.original[reg]&RTL_FABRIC_RX_OVERSIZE_ALLOW));
 }
}
int main(void) {
 for(unsigned seed=0;seed<128;seed++) {
  struct rtl_fabric f={};setup(seed*0x10001U);
  assert(!rtl_fabric_cold_prepare(&io,&f));
  assert(f.ready && f.changed && !f.refusal && !f.poisoned);
  assert(m.reg[0x1414/4]==(m.original[0x1414/4]|1));
  assert(m.scans==1 && m.pp_reads>=4);
  assert(f.packet_length==0x004023f1 && (f.packet_length&0x3fffU)>=1526);
  assert(!rtl_fabric_native_mtu_compatible(&f));
  command_restored(&f);baseline_preserved(&f);
  unsigned writes=m.writes,scans=m.scans;
  assert(!rtl_fabric_cold_prepare(&io,&f));assert(!rtl_fabric_check(&io,&f));
  assert(m.writes==writes && m.scans==scans);cases++;
 }
 for(unsigned inherited=1;inherited<=3;inherited++) {
  struct rtl_fabric f={};setup(1);m.inherited=inherited;
  assert(rtl_fabric_cold_prepare(&io,&f)==-EOPNOTSUPP);
  assert(!f.ready && f.refusal && !f.poisoned && !m.vlan_writes);
  assert(m.scans==1);command_restored(&f);baseline_preserved(&f);cases++;
 }
 for(unsigned stage=0;stage<4;stage++) {
  unsigned regs[]={0x11c0,0x1534,0x175c,0x1904};
  for(unsigned permanent=0;permanent<2;permanent++) {
   struct rtl_fabric f={};setup(stage);m.pending_reg=regs[stage];
   m.pending_remaining=7;m.permanent_pending=permanent;
   int ret=rtl_fabric_cold_prepare(&io,&f);
   assert(permanent ? ret==-ETIMEDOUT : ret==0);
   assert(!f.poisoned);assert(permanent ? !m.scans : m.scans==1);
   command_restored(&f);cases++;
  }
 }
 for(unsigned window=0;window<2;window++) {
  struct rtl_fabric f={};setup(0);
  m.reg[(window?RTL_L2_FDB_LIMIT_ACCESS:RTL_L2_FDB_ACCESS)/4]=RTL_L2_ACCESS_BUSY;
  assert(rtl_fabric_cold_prepare(&io,&f)==-EBUSY);
  assert(f.refusal && !f.poisoned && !m.writes && !m.scans);cases++;
 }
 {
  struct rtl_fabric f={};setup(0);m.scan_timeout=1;
  assert(rtl_fabric_cold_prepare(&io,&f)==-ETIMEDOUT);
  assert(f.poisoned && !f.ready && !m.vlan_writes && m.scans==1);
  unsigned writes=m.writes;assert(rtl_fabric_cold_prepare(&io,&f)==-EIO);
  assert(m.writes==writes);cases++;
 }
 {
  struct rtl_fabric f={};setup(0);m.busy_on_scan=1;
  assert(rtl_fabric_cold_prepare(&io,&f)==-EBUSY);
  assert(f.poisoned && !f.ready && !m.vlan_writes);cases++;
 }
 for(unsigned port=0;port<5;port++) {
  struct rtl_fabric f={};setup(port);
  m.drop_reg=RTL_FABRIC_RX(port);m.drop_occurrence=1;
  assert(rtl_fabric_cold_prepare(&io,&f)==-EIO);
  assert(f.poisoned && !f.ready && !m.scans);cases++;
 }
 for(unsigned kind=0;kind<4;kind++) {
  struct rtl_fabric f={};setup(0);
  if(kind==0){m.drop_reg=RTL_FABRIC_RX(2);m.drop_occurrence=1;}
  if(kind==1){m.drop_reg=RTL_L2_FDB_CONTROL;m.drop_occurrence=1;}
  if(kind==2){m.drop_reg=RTL_L2_VLAN_MODE_CONTROL;m.drop_occurrence=1;}
  if(kind==3){m.corrupt_vlan=1;m.rollback_stuck=1;}
  assert(rtl_fabric_cold_prepare(&io,&f)==-EIO);
  assert(!f.ready);
  if(kind==2){assert(!f.poisoned && f.refusal);command_restored(&f);}
  else assert(f.poisoned);
  baseline_preserved(&f);cases++;
 }
 for(unsigned index=0;index<RTL_L2_FDB_FILTER_WORDS;index++) {
  struct rtl_fabric f={};setup(index);m.drop_reg=RTL_L2_FDB_FILTER_WORD0-index*4;
  m.drop_occurrence=1;
  int ret=rtl_fabric_cold_prepare(&io,&f);
  if(index==0 || index==1 || index==4)assert(ret==-EIO && !f.poisoned);
  else assert(!ret); /* SDK intentionally leaves ignored comparisons intact. */
  command_restored(&f);cases++;
 }
 for(unsigned index=0;index<3;index++) {
  unsigned words[]={0,1,4};
  struct rtl_fabric f={};setup(index);
  m.drop_reg=RTL_L2_FDB_FILTER_WORD0-words[index]*4;m.drop_occurrence=2;
  assert(rtl_fabric_cold_prepare(&io,&f)==-EIO);
  assert(f.poisoned && !f.ready && m.vlan_writes==1);cases++;
 }
 {
  struct rtl_fabric f={};setup(0);
  m.drop_reg=RTL_L2_FDB_CONTROL;m.drop_occurrence=3;
  assert(rtl_fabric_cold_prepare(&io,&f)==-EIO);
  assert(f.poisoned && !f.ready && m.vlan_writes==1);cases++;
 }
 for(unsigned kind=0;kind<8;kind++) {
  struct rtl_fabric f={};setup(kind);assert(!rtl_fabric_cold_prepare(&io,&f));
  unsigned regs[]={0x1414,0xa034,0xa038,0x1108,0x110c,0x1110,0x1114,0xa034};
  unsigned bits[]={1,1,1,1,1,1,1,1U<<31};
  m.reg[regs[kind]/4]^=bits[kind];unsigned writes=m.writes;
  assert(rtl_fabric_check(&io,&f)==(kind==7?0:-EIO));
  assert(m.writes==writes);cases++;
 }
 {
  struct rtl_fabric f={};setup(0);m.reg[0x1414/4]|=1;
  assert(!rtl_fabric_cold_prepare(&io,&f));
  assert(f.ready && !f.changed && !m.scans && !m.vlan_writes && m.pp_reads>=3);
  baseline_preserved(&f);cases++;
 }
 {
  struct rtl_fabric f={};setup(0);m.scan_result=13;
  assert(rtl_fabric_cold_prepare(&io,&f)==-EIO);
  assert(f.refusal && !f.poisoned && !m.vlan_writes);command_restored(&f);cases++;
 }
 {
  struct rtl_fabric f={};setup(0);m.reg[RTL_L2_FDB_CONTROL/4]|=1U<<30;
  assert(rtl_fabric_cold_prepare(&io,&f)==-EBUSY);
  assert(!m.writes && f.refusal && !f.poisoned);cases++;
 }
 for(unsigned kind=0;kind<4;kind++) {
  struct rtl_fabric f={};setup(kind);
  if(kind==0)m.reg[0xa034/4]=(63U<<16)|9201;
  if(kind==1)m.reg[0xa034/4]=(64U<<16)|63;
  if(kind==2)m.reg[0xa038/4]=9200;
  if(kind==3)m.reg[0xa034/4]=(1023U<<16)|9201;
  memcpy(m.original,m.reg,sizeof(m.reg));
  int ret=rtl_fabric_cold_prepare(&io,&f);
  if(kind<3)assert(ret==-EOPNOTSUPP && f.refusal && !m.writes && !f.poisoned);
  else {assert(!ret && f.ready);baseline_preserved(&f);}
  cases++;
 }
 for(unsigned size=0;size<8;size++)for(unsigned ports=0;ports<32;ports++) {
  const unsigned int maximum[]={63,64,1518,1522,1523,1526,9201,16383};
  struct rtl_fabric f={};setup(size+ports);
  m.reg[0xa034/4]=(64U<<16)|maximum[size];m.reg[0xa038/4]=16383;
  for(unsigned port=0;port<5;port++) {
   unsigned reg=RTL_FABRIC_RX(port)/4;
   m.reg[reg]=(m.reg[reg]&~RTL_FABRIC_RX_OVERSIZE_ALLOW)|((ports&(1U<<port))?RTL_FABRIC_RX_OVERSIZE_ALLOW:0);
  }
  memcpy(m.original,m.reg,sizeof(m.reg));
  int ret=rtl_fabric_cold_prepare(&io,&f);
  if(size==0)assert(ret==-EOPNOTSUPP);
  else assert(!ret && f.ready);
  unsigned reads=m.reads,writes=m.writes;
  assert(rtl_fabric_native_mtu_compatible(&f)==(size>=1 && size<=3 && ports==0));
  assert(m.reads==reads && m.writes==writes);
  baseline_preserved(&f);cases++;
 }
 for(unsigned port=0;port<5;port++) {
  struct rtl_fabric f={};setup(port);assert(!rtl_fabric_cold_prepare(&io,&f));
  m.reg[RTL_FABRIC_RX(port)/4]^=RTL_FABRIC_RX_OVERSIZE_ALLOW;
  unsigned writes=m.writes;assert(rtl_fabric_check(&io,&f)==-EIO);
  assert(m.writes==writes);cases++;
 }
 {
  struct rtl_fabric f={};setup(0);assert(!rtl_fabric_native_mtu_compatible(&f));
  assert(!rtl_fabric_native_mtu_compatible(NULL));
  assert(!rtl_fabric_cold_prepare(&io,&f));f.poisoned=1;
  assert(!rtl_fabric_native_mtu_compatible(&f));cases++;
 }
 /*SDK_RUN*/
 printf("{\"cases\":%u,\"hardware_timing_verified\":false,\"framing_tpids_or_storage_written\":false}\n",cases);
 return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registers", type=Path, help="Pinned independent RTL8277C register unions")
    args = parser.parse_args()
    production = HEADER.read_text()
    mutants = {
        "missing_initial_drain": production.replace("ret = rtl_fabric_drain(io);", "ret = 0;"),
        "inherited_fdb_ignored": production.replace(
            "if (ret > 0)\n\t\t\tret = -EOPNOTSUPP;", "if (ret > 0)\n\t\t\tret = 0;", 1),
        "old_narrow_scan_filter": production.replace("rtl_l2_fdb_scan_filter(filter);", "/* deliberately omitted */"),
        "missing_mode_readback": production.replace(
            "ret = rtl_fabric_match(io, fabric, RTL_L2_VLAN_MODE_CONTROL, ~0U,\n\t\t\tfabric->original_vlan_mode | RTL_L2_VLAN_MODE_SVL);",
            "ret = 0;"),
        "shrinking_legacy_frame_budget": production.replace(
            "fabric->packet_length = fabric->original_packet_length;",
            "fabric->packet_length = (fabric->original_packet_length & ~0x3fffU) | 1522U;\n\tio->write(io->context, RTL_FABRIC_FRAME_LENGTH, fabric->packet_length);"),
        "discarding_legacy_oversize_policy": production.replace(
            "(value & ~RTL_FABRIC_RX_SELECTOR) | RTL_FABRIC_RX_CPU);",
            "((value & ~RTL_FABRIC_RX_SELECTOR) | RTL_FABRIC_RX_CPU) & ~RTL_FABRIC_RX_OVERSIZE_ALLOW);", 1),
        "false_native_mtu_compatibility": production.replace(
            "maximum > RTL_FABRIC_NATIVE_MAX_FRAME", "maximum > 16383U", 1),
        "warm_rewrites_baseline": production.replace(
            "return rtl_fabric_check(io, fabric);", "{ fabric->ready = 0; return rtl_fabric_cold_prepare(io, fabric); }", 1),
    }
    assert all(text != production for text in mutants.values())
    expected_assertions = {
        "missing_initial_drain": "m.pp_reads>=3",
        "inherited_fdb_ignored": "rtl_fabric_cold_prepare(&io,&f)==-EOPNOTSUPP",
        "old_narrow_scan_filter": "(m.reg[0x1c28/4]&63U)==0",
        "missing_mode_readback": "rtl_fabric_cold_prepare(&io,&f)==-EIO",
        "shrinking_legacy_frame_budget": "reg!=RTL_FABRIC_FRAME_LENGTH",
        "discarding_legacy_oversize_policy": "(value&RTL_FABRIC_RX_OVERSIZE_ALLOW)==(m.original[reg/4]&RTL_FABRIC_RX_OVERSIZE_ALLOW)",
        "false_native_mtu_compatibility": "rtl_fabric_native_mtu_compatible(&f)==(size>=1 && size<=3 && ports==0)",
        "warm_rewrites_baseline": "m.writes==writes && m.scans==scans",
    }
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    evidence = None
    test = TEST
    if args.registers:
        raw = args.registers.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == REGISTER_SHA, "Unpinned register input"
        source = raw.decode()
        names = ("L2FE_PLC_VLAN_MODE_CTRL", "NI_HV_GLB_PKT_LEN_CFG",
                 "NI_HV_GLB_PKT_STOR_LEN_CFG", "NI_HV_PT_RX_CNTRL_CFG")
        unions = []
        for name in names:
            match = re.search(r"typedef volatile union \{(?:(?!typedef volatile union).)*?\} " + name + r"_t;", source, re.S)
            assert match, name
            unions.append(match.group())
        declaration = "typedef unsigned int ca_uint32_t;\n" + "\n".join(unions) + r'''
static void sdk_oracle(void) {
 L2FE_PLC_VLAN_MODE_CTRL_t vlan={.wrd=2};vlan.bf.l2e_glb_vlan_mode=1;assert(vlan.wrd==3);
 NI_HV_GLB_PKT_LEN_CFG_t length={.wrd=0x004023f1};
 assert(length.bf.min_pkt_size==64 && length.bf.max_pkt_size==9201);
 length.bf.max_pkt_size=1522;assert(length.wrd==0x004005f2);
 NI_HV_GLB_PKT_STOR_LEN_CFG_t storage={.wrd=0x2454};assert(storage.bf.max_stor_pkt_len==9300);
 NI_HV_PT_RX_CNTRL_CFG_t rx={.wrd=0};rx.bf.ovr_drop_dis=1;assert(rx.wrd==(1U<<5));
}
'''
        test = test.replace("/*SDK_DECL*/", declaration).replace("/*SDK_RUN*/", "sdk_oracle();")
    with tempfile.TemporaryDirectory(prefix="thoros-fabric-") as temporary:
        build = Path(temporary)
        (build / "linux").mkdir()
        (build / "linux/delay.h").write_text("/* Delay stub is in test source. */\n")
        # Host portability only; target builds use Linux's actual errno header.
        if sys.platform == "darwin":
            (build / "linux/errno.h").write_text("#include <errno.h>\n")
        (build / "test.c").write_text(test)
        for name, source in [("production", production), *mutants.items()]:
            (build / HEADER.name).write_text(source)
            link_flags = [] if sys.platform == "darwin" else ["-no-pie"]
            subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                            *link_flags, "-I", str(build), "-I", str(DRIVER), str(build / "test.c"),
                            "-o", str(build / "test")], check=True)
            result = subprocess.run([str(build / "test")], text=True, capture_output=True,
                                    env={**os.environ, "ASAN_OPTIONS": "detect_leaks=0"})
            if name == "production":
                if result.returncode:
                    raise AssertionError(result.stderr)
                evidence = json.loads(result.stdout)
                print("PASS cold fabric:", result.stdout.strip())
            else:
                assert (result.returncode and "assert" in result.stderr.lower()
                        and expected_assertions[name] in result.stderr), (name, result.stderr)
                print("PASS mutation rejected:", name)
    evidence.update(production_sha256=hashlib.sha256(HEADER.read_bytes()).hexdigest(),
                    mutants_rejected=list(mutants), sanitizers=["address", "undefined"],
                    actual_sdk_registers_verified=bool(args.registers))
    (ROOT / "artifacts").mkdir(exist_ok=True)
    (ROOT / "artifacts/fabric-baseline.json").write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()
