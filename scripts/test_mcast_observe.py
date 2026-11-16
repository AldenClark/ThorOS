#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute passive multicast HeaderA observation, optionally with pinned SDK.

The helper observes validated CPU RX metadata before the source demux. It
never decides forwarding or original ingress, and cannot prove MCE retirement.
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
NAME = "rtl9617c-mcast-observe.h"
SDK_PATH = Path("ca-network-engine/1.0-r0/ca-network-engine-1.0/aal-77c/include")
PINS = {
    "aal_common.h": "6b5b388ed35fd7dd9b91115961da41551b143948e67e50c7f3ae6390817a4b98",
    "aal_port.h": "190e4c0c2ac7e99515162fac8775fb33c5ee605423d3809b09bda85708c99f7e",
}

PRELUDE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define WRITE_ONCE(x,v) ((x)=(v))
#include "rtl9617c-mcast-observe.h"
'''

CASES = r'''
int main(void) {
 const unsigned policers[]={0,1,26,27,31,56,255,256,511};
 unsigned cases=0;
 assert(sizeof(struct rtl_mcast_observe)==56);
 for(unsigned format=0;format<4;format++)for(unsigned source=0;source<64;source++)
 for(unsigned type=0;type<4;type++)for(unsigned mirror=0;mirror<2;mirror++)
 for(unsigned p=0;p<9;p++)for(unsigned cpu=0;cpu<2;cpu++)for(unsigned group=0;group<2;group++) {
  unsigned h0=(policers[p]<<18)|(type<<11)|(mirror<<14)|(cpu<<31)|(group?255U:0U);
  unsigned h1=(format<<30)|(72U<<15)|(source<<9)|(16U<<3)|7U;
  struct rtl_mcast_observe o={
   .hdr_bum=0xffffffffULL,.source27=0xffffffffULL,.source27_cpu=0xffffffffULL,
   .source27_ptp=0xffffffffULL,.source27_pol_nonzero=0xffffffffULL,
   .source27_mirror=0xffffffffULL,.last_source27_header=0x1234567812345678ULL,
  },before=o;
  sdk_oracle(h0,h1,format,source,type,mirror,policers[p],cpu,group?255U:0U);
  rtl_mcast_observe_rx(&o,h0,h1,64);
  assert(o.hdr_bum==before.hdr_bum+(format!=3&&type!=0));
  assert(o.source27==before.source27+(source==27));
  assert(o.source27_cpu==before.source27_cpu+(source==27&&format==2));
  assert(o.source27_ptp==before.source27_ptp+(source==27&&format==3));
  assert(o.source27_pol_nonzero==before.source27_pol_nonzero+
         (source==27&&format!=3&&policers[p]!=0));
  assert(o.source27_mirror==before.source27_mirror+(source==27&&format!=3&&mirror));
  assert(o.last_source27_header==(source==27?((uint64_t)h0<<32)|h1:before.last_source27_header));
  before=o;
  rtl_mcast_observe_rx(&o,h0,h1,0);
  rtl_mcast_observe_rx(&o,h0,h1,13);
  assert(!memcmp(&o,&before,sizeof(o)));
  rtl_mcast_observe_rx(NULL,h0,h1,64);
  cases++;
 }
 /* No ordinary source must overwrite the last unassigned-MC candidate.
  * PON source7/32..63, CPU0=16, and a kept LAN source stay distinct. */
 struct rtl_mcast_observe o={0};
 unsigned h0=(56U<<18)|(2U<<11),h1=(2U<<30)|(27U<<9);
 rtl_mcast_observe_rx(&o,h0,h1,64);
 for(unsigned s=0;s<64;s++)if(s!=27)
  rtl_mcast_observe_rx(&o,h0,(2U<<30)|(s<<9),64);
 assert(o.hdr_bum==64&&o.source27==1&&o.source27_cpu==1);
 assert(o.source27_pol_nonzero==1&&!o.source27_ptp&&!o.source27_mirror);
 assert(o.last_source27_header==((uint64_t)h0<<32|h1));
 printf("PASS: multicast RX metadata: %u HeaderA vectors, 64-bit counters, PTP overload, source27 demux and malformed-frame exclusion; no forwarding claim\n",cases);
}
'''


def oracle(sdk):
    signature = ("static void sdk_oracle(unsigned h0,unsigned h1,unsigned format,unsigned source,"
                 "unsigned type,unsigned mirror,unsigned policer,unsigned cpu,unsigned group)")
    if sdk is None:
        return signature + r'''{
 (void)h0;(void)h1;(void)format;(void)source;(void)type;
 (void)mirror;(void)policer;(void)cpu;(void)group;
}
'''
    texts = {}
    for name, expected in PINS.items():
        content = (sdk / SDK_PATH / name).read_bytes()
        if hashlib.sha256(content).hexdigest() != expected:
            raise SystemExit(f"Pinned SDK mismatch: {name}")
        texts[name] = content.decode()
    matched = re.search(r"typedef union \{\s*uint64_t bits64;.*?\} HEADER_A_T;", texts["aal_common.h"], re.S)
    if not matched:
        raise SystemExit("Pinned HEADER_A_T missing")
    port = re.search(r"^#define AAL_LPORT_MC\s+(0x[0-9a-fA-F]+)", texts["aal_port.h"], re.M)
    if not port:
        raise SystemExit("Pinned MC source definition missing")
    return matched.group(0) + f"\n#define AAL_LPORT_MC {port.group(1)}\n" + signature + r'''{
 HEADER_A_T h={0};
 h.bits32.bits32_h=h0;h.bits32.bits32_l=h1;
 assert(sizeof(h)==8&&AAL_LPORT_MC==27);
 assert(h.bits.hdr_type==format&&h.bits.lspid==source);
 assert(h.bits.ldpid==16&&h.bits.cos==7&&h.bits.pkt_size==72);
 assert(h.bits.bits_32_63.pkt_info.rx_pkt_type==type);
 assert(h.bits.bits_32_63.pkt_info.mirror==mirror);
 assert(h.bits.bits_32_63.pkt_info.pol_id==policer);
 assert(h.bits.bits_32_63.pkt_info.cpu_flg==cpu);
 assert(h.bits.bits_32_63.pkt_info.mcgid==group);
}
'''


def run(header, oracle_source):
    with tempfile.TemporaryDirectory(prefix="rtl-mcast-observe-") as temp:
        wd = Path(temp)
        (wd / NAME).write_text(header)
        (wd / "test.c").write_text(PRELUDE + oracle_source + CASES)
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall",
                        "-Wextra", "-Werror", "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
                        "-I", str(wd), str(wd / "test.c"), "-o", str(wd / "test")], check=True)
        env = dict(os.environ)
        env.setdefault("ASAN_OPTIONS", "detect_leaks=0")
        env.setdefault("UBSAN_OPTIONS", "halt_on_error=1")
        return subprocess.run([str(wd / "test")], env=env, capture_output=True, text=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path)
    parser.add_argument("--mutants", action="store_true")
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    header = (DRIVER / NAME).read_text()
    source = oracle(args.sdk)
    result = run(header, source)
    if result.returncode:
        raise SystemExit(result.stdout + result.stderr)
    print(result.stdout.strip())
    if args.sdk:
        print("PASS: actual pinned aal-77c HEADER_A_T union and AAL_LPORT_MC definition")
    if args.mutants:
        mutations = {
            "wrong_MC_source": ("source != 27", "source != 7"),
            "PTP_interpreted_as_packet_info": ("format != 3", "format <= 3"),
            "wrong_header_type": ("header1 >> 30", "header1 >> 29"),
            "wrong_policer_bits": ("header0 >> 18", "header0 >> 17"),
            "swapped_HeaderA_pair": ("((unsigned long long)header0 << 32) | header1",
                                     "((unsigned long long)header1 << 32) | header0"),
            "malformed_frame_observed": ("length < 14", "length < 1"),
        }
        for name, (old, new) in mutations.items():
            if old not in header:
                raise SystemExit(f"Mutation target missing: {name}")
            result = run(header.replace(old, new), source)
            if not result.returncode or "Assertion" not in result.stderr:
                raise SystemExit(f"Mutation not rejected by assertion: {name}\n{result.stdout}{result.stderr}")
            print(f"PASS: rejected {name}")


if __name__ == "__main__":
    main()
