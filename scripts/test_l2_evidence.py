#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute passive L2 sampling and the actual sysfs/QM diagnostic readers.

With --registers, compile the independently pinned RTL8277C generated unions
as the field/address oracle. No hardware access and no forwarding claim.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"
HEADER_SHA = "ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0"
REGISTERS = {
    "MCE_CONTROL": "NI_HV_MCE_CTL_REG",
    "MCE_ACCESS": "NI_HV_MCE_INDX_LKUP_ACCESS",
    "MCFIB_ACCESS": "L2FE_ARB_MC_FIB_TBL_ACCESS",
    "ARB_CONTROL": "L2FE_ARB_ARB_CTRL",
    "ARB_EXT": "L2FE_ARB_ARB_CTRL_EXT",
    "FDB_CONTROL": "L2FE_L2E_CTRL",
    "FDB_AGING": "L2FE_L2E_AGING_CTRL",
    "FDB_ACCESS": "L2FE_L2E_FDB_ACCESS",
    "FDB_LIMIT_ACCESS": "L2FE_L2E_PORT_MAC_CNT_LMT_ACCESS",
    "VLAN_MODE": "L2FE_PLC_VLAN_MODE_CTRL",
    "HASH_CONTROL": "L2FE_PLC_HASH_CTRL",
    "FLOOD_ACCESS": "L2FE_PLE_DFT_FWD_ACCESS",
}


def function(source, name):
    match = re.search(r"^ssize_t " + name + r"\(", source, re.M)
    if not match:
        raise ValueError(f"missing production function {name}")
    start = match.start()
    end = source.index("{", start) + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end] + "\n"


SHIM = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include "rtl9617c-l2-evidence.h"
typedef unsigned long long u64;
typedef uint32_t u32;
typedef uint32_t ca_uint32_t;
#define PAGE_SIZE 4096
#define READ_ONCE(v) (v)
#define WRITE_ONCE(x,v) ((x)=(v))
#include "rtl9617c-mcast-observe.h"
#define RMU_CTRL 0x6104
#define ES_CTRL 0x6108
#define EQ_ID 4
#define CPU_READY 0x6368
#define EPP_WRITE 0x7000
#define EPP_READ 0x7100
struct mutex { bool held, deny; };
struct rtl_fe { struct mutex lock; bool engine_ready, shutting_down; int route_lock; };
struct rtl_qm_rx {
 void *ni; u64 memory_dma; u32 last_address,last_size,last_header[2];
 u64 voq_packets[8],voq_yields[8],poll_budget_hits,cpu_packets,cpu_bytes,ring_errors,buffer_errors;
 unsigned rx_prefetch,pppoe_rx_checksum,next_voq;
 struct rtl_mcast_observe mcast_observe;
 struct {
  unsigned pending,peak,count[2],eq_peak[2];
  u64 retries,returned,eq_retries[2],eq_returned[2],eq_full_stalls[2];
  u64 eq_bad_credit[2],eq_bad_ready[2];
 } refill;
};
static u32 registers[0x10000 / 4], before[0x10000 / 4];
static unsigned int reads, writes, locks, unlocks, fake_time;
static bool in_spin, strict;
static unsigned int seen[0x10000 / 4];
static const unsigned int expected_offsets[] = {
 0xaa60,0xaa64,0x1634,0x1600,0x160c,0x1c00,0x1c04,0x1ca0,
 0x1cb4,0x1414,0x1400,0x1564,0xa5f8,0xa688,0xa718,0xa7a8,0xa838,
};
static bool allowed(unsigned int offset) {
 for(unsigned i=0;i<sizeof(expected_offsets)/sizeof(expected_offsets[0]);i++)
  if(offset==expected_offsets[i])return true;
 return false;
}
static unsigned int fe_read(void *ctx,unsigned int offset) {
 if(ctx)assert(((struct rtl_fe *)ctx)->lock.held && in_spin);
 assert(!(offset&3) && offset<sizeof(registers));
 if(strict)assert(allowed(offset));
 reads++;seen[offset/4]++;return registers[offset/4];
}
static u32 readl(void *p) {return fe_read(NULL,(unsigned int)((char *)p-(char *)registers));}
static void writel(u32 value,void *p) {writes++;*(u32 *)p=value;}
static int mutex_trylock(struct mutex *lock) {
 if(lock->deny)return 0;assert(!lock->held);lock->held=true;locks++;return 1;
}
static void mutex_unlock(struct mutex *lock) {assert(lock->held);lock->held=false;unlocks++;}
#define spin_lock_irqsave(lock,flags) do{(void)(lock);(flags)=42;assert(!in_spin);in_spin=true;}while(0)
#define spin_unlock_irqrestore(lock,flags) do{(void)(lock);assert((flags)==42 && in_spin);in_spin=false;}while(0)
static u64 ktime_get_ns(void) {return ++fake_time;}
static int scnprintf(char *buf,size_t cap,const char *format,...) {
 va_list ap;va_start(ap,format);int n=vsnprintf(buf,cap,format,ap);va_end(ap);
 return n<0?0:((size_t)n<cap?n:(cap?(int)cap-1:0));
}
static int sysfs_emit(char *buf,const char *format,...) {
 va_list ap;va_start(ap,format);int n=vsnprintf(buf,PAGE_SIZE,format,ap);va_end(ap);
 assert(n>=0 && n<PAGE_SIZE);return n;
}
static void setup(unsigned int seed) {
 reads=writes=locks=unlocks=0;strict=true;in_spin=false;
 memset(seen,0,sizeof(seen));
 for(unsigned int i=0;i<sizeof(registers)/sizeof(registers[0]);i++)
  registers[i]=(i*2654435761U)^seed;
 memcpy(before,registers,sizeof(before));
}
'''

CASES = r'''
int main(void) {
 struct rtl_dq_io io={.read=fe_read};struct rtl_l2_evidence sample;
 struct rtl_fe fe={.engine_ready=true};char output[PAGE_SIZE];
 setup(0xdeadbeefU);
 assert(rtl_l2_evidence_read(NULL,&sample)==-EINVAL && !reads);
 assert(rtl_l2_evidence_read(&io,NULL)==-EINVAL && !reads);
 struct rtl_dq_io invalid={0};assert(rtl_l2_evidence_read(&invalid,&sample)==-EINVAL && !reads);
 for(unsigned bit=0;bit<32;bit++) {
  setup(bit);registers[0xaa60/4]=1U<<bit;registers[0x1600/4]=1U<<bit;
  registers[0x160c/4]=1U<<bit;memcpy(before,registers,sizeof(before));
  assert(!rtl_l2_evidence_read(&io,&sample));
  assert(sample.mce_copy_lspid_to_pol==(bit==17));
  assert(sample.mce_flush_requested==(bit==18));
  assert(sample.arb_keep_original_lspid==(bit==31));
  assert(sample.arb_mc_membership_check==(bit==0));
  assert(reads==17 && !writes && !memcmp(before,registers,sizeof(before)));
  for(unsigned i=0;i<17;i++)assert(seen[expected_offsets[i]/4]==1);
  for(unsigned i=0;i<12;i++)assert(sample.words[i]==before[expected_offsets[i]/4]);
  for(unsigned i=0;i<5;i++)assert(sample.lan_rx[i]==before[expected_offsets[12+i]/4]);
  sdk_oracle(&sample);
 }
 /* Decode the exact observed IVL reset value and independent negative
  * patterns through the production getter, without a bridge/request model.
  * Sweep unrelated bits as well so compatibility cannot become a loose
  * nonzero test or compare the entire control word to a magic default. */
 for(unsigned bit=0;bit<32;bit++)for(unsigned svl=0;svl<2;svl++)
  for(unsigned priority=0;priority<2;priority++) {
   setup(bit);
   registers[0x1414/4]=((1U<<bit)&~1U)|2U|svl;
   registers[0x1400/4]=((1U<<bit)&~64U)|(priority<<6);
   memcpy(before,registers,sizeof(before));
   assert(rtl_fe_l2_evidence(&fe,output)>0);
   assert(strstr(output,svl?"native_l2_svl_compatible=1 ":"native_l2_svl_compatible=0 "));
   assert(strstr(output,priority?"native_l2_priority_key_compatible=0 ":"native_l2_priority_key_compatible=1 "));
   assert(strstr(output,"native_l2_prerequisites_complete=0"));
   assert(!writes && reads==17 && locks==1 && unlocks==1 && !in_spin);
   assert(!memcmp(before,registers,sizeof(before)));
   assert(!rtl_l2_evidence_read(&io,&sample));sdk_oracle(&sample);
  }
 /* A failure of either baseline read must not make that prerequisite
  * compatible. Keep the healthy peer independent and the raw failed word
  * visible; observation still performs exactly the same 17 reads. */
 const unsigned failed_baseline[]={0x1414,0x1400};
 for(unsigned i=0;i<2;i++) {
  setup(i);registers[0x1414/4]=3;registers[0x1400/4]=0;
  registers[failed_baseline[i]/4]=~0U;memcpy(before,registers,sizeof(before));
  assert(rtl_fe_l2_evidence(&fe,output)>0);
  assert(strstr(output,i?"native_l2_svl_compatible=1 ":"native_l2_svl_compatible=0 "));
  assert(strstr(output,i?"native_l2_priority_key_compatible=0 ":"native_l2_priority_key_compatible=1 "));
  assert(strstr(output,i?"hash_control=0xffffffff\n":"vlan_mode=0xffffffff\n"));
  assert(strstr(output,"native_l2_prerequisites_complete=0"));
  assert(reads==17 && !writes && locks==1 && unlocks==1 && !in_spin);
  for(unsigned j=0;j<17;j++)assert(seen[expected_offsets[j]/4]==1);
  assert(!memcmp(before,registers,sizeof(before)));
  assert(!rtl_l2_evidence_read(&io,&sample));
  assert(sample.words[i?RTL_L2_EVIDENCE_HASH_CONTROL:RTL_L2_EVIDENCE_VLAN_MODE]==~0U);
  sdk_oracle(&sample);
 }
 setup(42);
 assert(rtl_fe_l2_evidence(NULL,output)>0 && strstr(output,"reason=no_fe") && !reads);
 fe.lock.deny=true;assert(rtl_fe_l2_evidence(&fe,output)==-EBUSY && !reads);
 fe.lock.deny=false;fe.engine_ready=false;
 assert(rtl_fe_l2_evidence(&fe,output)>0 && strstr(output,"reason=engine_down") && !reads);
 fe.engine_ready=true;fe.shutting_down=true;
 assert(rtl_fe_l2_evidence(&fe,output)>0 && !reads);
 fe.shutting_down=false;
 for(unsigned i=0;i<64;i++) {
  setup(i);assert(rtl_fe_l2_evidence(&fe,output)>0);
  assert(!writes && reads==17 && locks==1 && unlocks==1 && !in_spin);
  assert(!memcmp(before,registers,sizeof(before)));
  assert(strstr(output,"atomic_snapshot=0") && strstr(output,"forwarding_proven=0"));
  assert(strstr(output,"retirement_proven=0") && strstr(output,"hw_port=4"));
 }
 struct rtl_qm_rx qm={.ni=registers};
 qm.refill.count[0]=3;qm.refill.count[1]=5;
 qm.refill.eq_peak[0]=7;qm.refill.eq_peak[1]=11;
 qm.refill.eq_retries[0]=13;qm.refill.eq_retries[1]=17;
 qm.refill.eq_returned[0]=19;qm.refill.eq_returned[1]=23;
 qm.refill.eq_full_stalls[0]=29;qm.refill.eq_full_stalls[1]=31;
 qm.refill.eq_bad_credit[0]=0x100000025ULL;qm.refill.eq_bad_credit[1]=0x10000002bULL;
 qm.refill.eq_bad_ready[0]=0x100000031ULL;qm.refill.eq_bad_ready[1]=0x100000035ULL;
 for(unsigned q=0;q<8;q++)qm.voq_yields[q]=0x100000000ULL+q;
 qm.next_voq=6;
 qm.mcast_observe=(struct rtl_mcast_observe){
  .hdr_bum=0x100000000ULL,.source27=0x100000001ULL,.source27_cpu=0x100000002ULL,
  .source27_ptp=0x100000003ULL,.source27_pol_nonzero=0x100000004ULL,
  .source27_mirror=0x100000005ULL,.last_source27_header=0x1234567890abcdefULL,
 };
 for(unsigned i=0;i<32;i++) {
  setup(i);strict=false;registers[0x105c/4]=1U<<i;
  memcpy(before,registers,sizeof(before));
  assert(rtl_qm_rx_state(&qm,output)>0);
  assert(strstr(output,"monitor_selector=") && strstr(output,"monitor_atomic=0"));
  assert(strstr(output,"refill_eq4_pending=3 refill_eq5_pending=5"));
  assert(strstr(output,"refill_eq4_peak=7 refill_eq5_peak=11"));
  assert(strstr(output,"refill_eq4_retries=13 refill_eq5_retries=17"));
  assert(strstr(output,"refill_eq4_returned=19 refill_eq5_returned=23"));
  assert(strstr(output,"refill_eq4_full_stalls=29 refill_eq5_full_stalls=31"));
  assert(strstr(output,"refill_eq4_bad_credit=4294967333 refill_eq5_bad_credit=4294967339"));
  assert(strstr(output,"refill_eq4_bad_ready=4294967345 refill_eq5_bad_ready=4294967349"));
  assert(!writes && !memcmp(before,registers,sizeof(before)));
  unsigned int reads_before=reads;
  assert(rtl_qm_rx_voq_state(&qm,output)>0);
  assert(strstr(output,"refill_eq4_pending=3 refill_eq5_pending=5"));
  assert(strstr(output,"refill_eq4_full_stalls=29 refill_eq5_full_stalls=31"));
  assert(strstr(output,"refill_eq4_bad_credit=4294967333 refill_eq5_bad_credit=4294967339"));
  assert(strstr(output,"refill_eq4_bad_ready=4294967345 refill_eq5_bad_ready=4294967349"));
  assert(strstr(output,"voq7_yields=4294967303 voq6_yields=4294967302"));
  assert(strstr(output,"voq1_yields=4294967297 voq0_yields=4294967296 next_voq=6"));
  assert(strstr(output,"mc_rx_hdr_bum=4294967296 mc_rx_source27=4294967297"));
  assert(strstr(output,"mc_rx_source27_cpu=4294967298 mc_rx_source27_ptp=4294967299"));
  assert(strstr(output,"mc_rx_source27_pol=4294967300 mc_rx_source27_mirror=4294967301"));
  assert(strstr(output,"mc_rx_last_header=1234567890abcdef mc_rx_forwarding_proven=0\n"));
  assert(!writes && reads==reads_before && !memcmp(before,registers,sizeof(before)));
 }
 /* Old cumulative keys also remain lossless above 32 bits. */
 qm.refill.retries=qm.refill.returned=~0ULL;
 qm.refill.eq_retries[0]=qm.refill.eq_retries[1]=~0ULL;
 qm.refill.eq_returned[0]=qm.refill.eq_returned[1]=~0ULL;
 qm.refill.eq_full_stalls[0]=qm.refill.eq_full_stalls[1]=~0ULL;
 assert(rtl_qm_rx_state(&qm,output)>0);
 assert(strstr(output,"refill_retries=18446744073709551615 refill_returned=18446744073709551615"));
 unsigned reads_before=reads;assert(rtl_qm_rx_voq_state(&qm,output)>0 && reads==reads_before);
 assert(strstr(output,"refill_eq4_retries=18446744073709551615 refill_eq5_retries=18446744073709551615"));
 assert(strstr(output,"refill_eq4_returned=18446744073709551615 refill_eq5_returned=18446744073709551615"));
 assert(strstr(output,"refill_eq4_full_stalls=18446744073709551615 refill_eq5_full_stalls=18446744073709551615"));
 puts("PASS: passive L2: 32 field bits, 128 baseline combinations, 2 isolated baseline read faults, 64 live snapshots, no-FE/down/shutdown/busy; QM 32 selectors unchanged, 64-bit faults/fairness/metadata-only evidence");
}
'''


def sdk_oracle(path):
    if path is None:
        return "static void sdk_oracle(const struct rtl_l2_evidence *s){(void)s;}\n"
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != HEADER_SHA:
        raise SystemExit("RTL8277C generated header pin mismatch")
    text = data.decode()
    names = [*REGISTERS.values(), "NI_HV_PT_RX_CNTRL_CFG"]
    result = ""
    for name in names:
        match = re.search(r"^#define " + name + r"\s+0x", text, re.M)
        if not match:
            raise ValueError(f"SDK register absent: {name}")
        start = match.start()
        end = text.index("#endif /* !__ASSEMBLER__ */", start)
        result += text[start:end] + "#endif\n"
    result += "static void sdk_oracle(const struct rtl_l2_evidence *s) {\n"
    for index, (name, original) in enumerate(REGISTERS.items()):
        result += f"assert(expected_offsets[{index}]=={original}-0xf4300000U);\n"
        result += f"assert(s->words[RTL_L2_EVIDENCE_{name}]==registers[({original}-0xf4300000U)/4]);\n"
    result += r'''
 NI_HV_MCE_CTL_REG_t m={.wrd=s->words[RTL_L2_EVIDENCE_MCE_CONTROL]};
 L2FE_ARB_ARB_CTRL_t a={.wrd=s->words[RTL_L2_EVIDENCE_ARB_CONTROL]};
 L2FE_ARB_ARB_CTRL_EXT_t e={.wrd=s->words[RTL_L2_EVIDENCE_ARB_EXT]};
 L2FE_PLC_VLAN_MODE_CTRL_t v={.wrd=s->words[RTL_L2_EVIDENCE_VLAN_MODE]};
 L2FE_PLC_HASH_CTRL_t h={.wrd=s->words[RTL_L2_EVIDENCE_HASH_CONTROL]};
 assert((v.wrd!=~0U && v.bf.l2e_glb_vlan_mode)==s->native_l2_svl_compatible);
 assert((h.wrd!=~0U && !h.bf.use_dot1p_l2e)==s->native_l2_priority_key_compatible);
 assert(m.bf.cp_lspid_to_pol_id_en==s->mce_copy_lspid_to_pol);
 assert(m.bf.buf_flush_en==s->mce_flush_requested);
 assert(a.bf.keep_o_lspid_en_for_mc==s->arb_keep_original_lspid);
 assert(e.bf.mc_pkt_port_mmshp_chk_en==s->arb_mc_membership_check);
 assert(RTL_L2_EVIDENCE_LAN_BASE==NI_HV_PT_RX_CNTRL_CFG-0xf4300000U);
 for(unsigned i=0;i<5;i++) {
  NI_HV_PT_RX_CNTRL_CFG_t p={.wrd=s->lan_rx[i]};
  assert(p.bf.rxctrl_byp_dpid==((s->lan_rx[i]>>16)&63));
  assert(p.bf.rxctrl_byp_en==((s->lan_rx[i]>>28)&1));
 }
}
'''
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registers", type=Path)
    args = parser.parse_args()
    fe = function((DRIVER / "rtl9617c-fe.c").read_text(), "rtl_fe_l2_evidence")
    qm_source = (DRIVER / "rtl9617c-qm.c").read_text()
    qm = (function(qm_source, "rtl_qm_rx_state") +
          function(qm_source, "rtl_qm_rx_voq_state"))
    header = (DRIVER / "rtl9617c-l2-evidence.h").read_text()

    def change_once(text, old, new):
        assert text.count(old) == 1, f"mutation target drift: {old}"
        return text.replace(old, new, 1)

    variants = [
        ("production", fe, qm, header),
        ("selector_write_mutant", fe, change_once(qm,
         "u32 monitor_selector =", "writel(0x82, rx->ni + 0x105c);\n\tu32 monitor_selector ="), header),
        ("svl_compatibility_mutant", fe, qm, change_once(header,
         "& RTL_L2_VLAN_MODE_SVL", "& 2U")),
        ("svl_failed_read_mutant", fe, qm, change_once(header,
         "sample->words[RTL_L2_EVIDENCE_VLAN_MODE] != ~0U &&", "true &&")),
        ("priority_compatibility_mutant", fe, qm, change_once(header,
         "!(sample->words[RTL_L2_EVIDENCE_HASH_CONTROL]", "!!(sample->words[RTL_L2_EVIDENCE_HASH_CONTROL]")),
        ("mce_field_mutant", fe, qm, change_once(header, ">> 17", ">> 16")),
        ("counter_read_mutant", fe, qm, change_once(header, "0xaa60U", "0xaa70U")),
        ("table_data_read_mutant", fe, qm, change_once(header, "0xaa64U", "0xaa68U")),
        ("shutdown_read_mutant", change_once(fe, " || fe->shutting_down", ""), qm, header),
        ("unlocked_read_mutant", change_once(fe,
         "spin_lock_irqsave(&fe->route_lock,flags);", "flags=42;"), qm, header),
    ]
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with tempfile.TemporaryDirectory(prefix="l2-passive-") as tmp:
        directory = Path(tmp)
        for name, fe_variant, qm_variant, header_variant in variants:
            variant_dir = directory / name
            variant_dir.mkdir()
            source, binary = variant_dir / "test.c", variant_dir / "test"
            (variant_dir / "rtl9617c-l2-evidence.h").write_text(header_variant)
            source.write_text(SHIM + sdk_oracle(args.registers) + fe_variant + qm_variant + CASES)
            subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g",
                            "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
                            "-Wno-misleading-indentation", "-fsanitize=address,undefined",
                            "-I", str(DRIVER), str(source), "-o", str(binary)], check=True)
            env = dict(os.environ)
            env.setdefault("ASAN_OPTIONS", "detect_leaks=0")
            env.setdefault("UBSAN_OPTIONS", "halt_on_error=1")
            result = subprocess.run([str(binary)], env=env, capture_output=True, text=True)
            if name == "production":
                if result.returncode:
                    raise SystemExit(result.stdout + result.stderr)
                print(result.stdout.strip())
            else:
                assert result.returncode and "Assertion" in result.stderr, result
                print(f"PASS: {name} rejected by runtime assertion")
    if args.registers:
        print("PASS: 12 addresses and metadata/LAN fields checked against pinned independent RTL8277C unions")


if __name__ == "__main__":
    main()
