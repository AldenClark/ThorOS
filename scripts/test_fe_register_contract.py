#!/usr/bin/env python3
"""Validate FE MMIO encoding against the externally pinned RTL8277C header.

Input: jameywine/GPL-for-GP3000@5090fbcb6ba743dd7b1314811ef557bad0460147,
linux-5.10.x/include/soc/cortina/rtl8277c_registers.h (silicon, not FPGA).
Usage: python3 scripts/test_fe_register_contract.py --registers /path/to/header
Only relevant unmodified generated declarations are compiled in a host model.
No device accesses and no assertion of physical forwarding performance.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"
PIN = "5090fbcb6ba743dd7b1314811ef557bad0460147"
SHA256 = "ce5940a274a14c91e5bf3cf96e4583d2d1d086ae601eb716566dfc70d87633e0"
WINDOWS = {
    "L2FE_ARB_PDPID_MAP_TBL_ACCESS": "access",
    "L2FE_L2E_FDB_ACCESS": "access",
    "L3FE_GLB_EGRESS_L3_IF_TBL_ACCESS": "access",
    "L3FE_PP_FIELD_CAM_ACCESS": "access",
    "L3FE_CLS_FIB_TBL_ACCESS": "access",
    "L3FE_PE_TX_IFID_CNT_TBL_ACCESS": "access",
    "L3FE_FE_L3E_HS_CACHE_CTRL_REQ": "req_sts",
    "L3FE_FE_L3E_HS_SWO_CTRL": "cmd_sts",
    "L3FE_FE_L3E_HS_CACHE_HASH_ACCESS": "status",
    "L3FE_FE_L3E_HS_MASK_MEM_ACCESS": "status",
    "L3FE_FE_L3E_HS_HASH_AGE_MEM_ACCESS": "age",
    "L3FE_FE_L3E_HS_MEM_INI": "req_sts",
}
CONFIGS = [
    "L3FE_FE_L3E_HS_HASH_INI", "L3FE_FE_L3E_HS_OVERFLOW_INI",
    "L3FE_FE_L3E_HS_DEFAULT_INI", "L3FE_FE_L3E_HS_CACHE_INI",
    "L3FE_FE_L3E_HS_CACHE_CTRL", "L3FE_FE_L3E_HS_CACHE_MISC",
    "L3FE_FE_L3E_HS_CACHE_HASH_DATA1", "L3FE_AXIM2_CONFIG",
    "L2FE_L2E_FDB_DATA0", "L2FE_L2E_FDB_DATA1", "L2FE_L2E_FDB_DATA2",
    "L2FE_L2E_FDB_DATA3",
]


def declaration(header, name):
    start = re.search(r"^#define " + name + r"\s+0x", header, re.M).start()
    end = header.index("#endif /* !__ASSEMBLER__ */", start)
    return header[start:end] + "#endif /* !__ASSEMBLER__ */\n"


COMMON = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "rtl9617c-fe-pipeline.h"
typedef uint32_t ca_uint32_t;
#define OFFSET(reg) ((reg)-0xf4300000U)
struct model {unsigned int reg[0x4000/4],last_access,last_value,commands;};
static unsigned int read_reg(void *context,unsigned int reg)
{
 struct model *m=context;assert(reg<0x4000 && !(reg&3));return m->reg[reg/4];
}
static void write_reg(void *context,unsigned int reg,unsigned int value)
{
 struct model *m=context;assert(reg<0x4000 && !(reg&3));m->reg[reg/4]=value;
}
static int command(void *context,unsigned int reg,unsigned int value)
{
 struct model *m=context;m->last_access=reg;m->last_value=value;m->commands++;return 0;
}
'''
TEST = r'''
int main(void)
{
 struct model m={0};
 struct rtl_dq_io io={&m,read_reg,write_reg,command};
 check_windows(&m,&io);
 memset(&m,0,sizeof(m));
 rtl_fe_dma_tables(&io,0x03400000,2);
 L3FE_FE_L3E_HS_HASH_INI_t hash={.wrd=read_reg(&m,OFFSET(L3FE_FE_L3E_HS_HASH_INI))};
 L3FE_FE_L3E_HS_CACHE_INI_t cache={.wrd=read_reg(&m,OFFSET(L3FE_FE_L3E_HS_CACHE_INI))};
 L3FE_FE_L3E_HS_OVERFLOW_INI_t overflow={.wrd=read_reg(&m,OFFSET(L3FE_FE_L3E_HS_OVERFLOW_INI))};
 L3FE_FE_L3E_HS_DEFAULT_INI_t defaults={.wrd=read_reg(&m,OFFSET(L3FE_FE_L3E_HS_DEFAULT_INI))};
 assert(hash.bf.hb_size==3 && hash.bf.ht_size==7 && hash.bf.ha_width==4);
 assert(!hash.bf.def_reg); /* Keep defaults in DDR (SDK AXI-hang workaround). */
 assert(cache.bf.ct_size==4 && cache.bf.ca_width==3 && cache.bf.fib_sram);
 assert(!cache.bf.cache_half && cache.bf.cache_age0_hit);
 assert(overflow.bf.oa_width==4 && defaults.bf.da_width==1);
 L3FE_AXIM2_CONFIG_t axi_before={.wrd=0};
 axi_before.bf.axi_xbus_len=2;axi_before.bf.read_cacheline_trans_en=1;
 write_reg(&m,OFFSET(L3FE_AXIM2_CONFIG),axi_before.wrd);
 rtl_fe_cache_start(&io);
 L3FE_AXIM2_CONFIG_t axi={.wrd=read_reg(&m,OFFSET(L3FE_AXIM2_CONFIG))};
 L3FE_FE_L3E_HS_CACHE_MISC_t misc={.wrd=read_reg(&m,OFFSET(L3FE_FE_L3E_HS_CACHE_MISC))};
 assert(axi.bf.axi_read_outtrans_num==15 && axi.bf.axi_write_outtrans_num==15);
 assert(axi.bf.axi_xbus_len==2 && axi.bf.read_cacheline_trans_en);
 assert(misc.bf.crep_en && misc.bf.s3_ra_en && !misc.bf.s2_ra_en && !misc.bf.s3_loc_n);
 for(unsigned int crc=0;crc<65536;crc+=257) {
  for(unsigned int slot=0;slot<32;slot++) {
   assert(!rtl_fe_cache_command(&io,slot,(unsigned short)crc,1));
   L3FE_FE_L3E_HS_CACHE_CTRL_t control={.wrd=read_reg(&m,OFFSET(L3FE_FE_L3E_HS_CACHE_CTRL))};
   assert(control.bf.slot==slot && control.bf.crc16==crc && control.bf.cmd==1);
   assert(control.bf.age==3 && !control.bf.loc && !control.bf.aqm_prot && !control.bf.pri);
   assert(m.last_access==OFFSET(L3FE_FE_L3E_HS_CACHE_CTRL_REQ));
   L3FE_FE_L3E_HS_CACHE_CTRL_REQ_t request={.wrd=m.last_value};
   assert(request.bf.req_sts);
  }
 }
 L3FE_GLB_EGRESS_L3_IF_TBL_ACCESS_t eif={.wrd=~0U};
 assert(eif.bf.addr==31); /* Physical recipe table, not TX MIB capacity. */
 L3FE_PE_TX_IFID_CNT_TBL_ACCESS_t counter={.wrd=~0U};
 assert(counter.bf.addr==63);
 L3FE_FE_L3E_HS_CACHE_HASH_DATA1_t key={.wrd=0};
 key.bf.crc16=0x1fff;key.bf.slot=31;key.bf.location=1;
 assert(key.wrd==0x7ffff); /* Exact snapshot identity, not age/priority. */
 for(unsigned int bit=0;bit<48;bit++) {
  uint64_t address=UINT64_C(1)<<bit;
  unsigned char mac[6];unsigned int words[4];
  for(unsigned int i=0;i<6;i++)mac[i]=address>>(8*(5-i));
  rtl_fe_fdb_key(words,mac);
  L2FE_L2E_FDB_DATA0_t a={.wrd=words[0]};
  L2FE_L2E_FDB_DATA1_t b={.wrd=words[1]};
  L2FE_L2E_FDB_DATA2_t c={.wrd=words[2]};
  L2FE_L2E_FDB_DATA3_t d={.wrd=words[3]};
  assert((((uint64_t)d.bf.mac_addr<<45)|((uint64_t)c.bf.mac_addr<<13)|b.bf.mac_addr)==address);
  assert(a.bf.is_static && a.bf.sa_permit && a.bf.da_permit && !a.bf.mc_flag);
  assert(a.bf.aging_sts==255 && !b.bf.key_vid && !b.bf.key_dot1p && !b.bf.key_scind);
 }
 puts("Pinned RTL8277C silicon registers: 12 ACCESS busy contracts, DDR/cache sizing, "
  "AXI RMW, 8192 invalidate encodings, EIF/MIB capacity, cache identity and 48 FDB MAC bits PASS (model only)");
 return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registers", required=True, type=Path)
    args = parser.parse_args()
    data = args.registers.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise SystemExit("Generated header SHA256 does not match the pinned silicon reference")
    header = data.decode()
    source = COMMON + "\n".join(declaration(header, name) for name in [*WINDOWS, *CONFIGS])
    source += "\nstatic void check_windows(struct model *m,struct rtl_dq_io *io) {\n"
    for name, field in WINDOWS.items():
        source += f"""
 {{ {name}_t value={{.wrd=0}};
 value.bf.{field}=1;
 write_reg(m,OFFSET({name}),value.wrd);
 assert(rtl_fe_window_idle(io,OFFSET({name}))==-EBUSY);
 write_reg(m,OFFSET({name}),~value.wrd);
 assert(!rtl_fe_window_idle(io,OFFSET({name})));
 }}
"""
    source += "}\n" + TEST
    with tempfile.TemporaryDirectory(prefix="fe-register-contract-") as temporary:
        directory = Path(temporary)
        c_file, binary = directory / "test.c", directory / "test"
        c_file.write_text(source)
        subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                        "-I", str(DRIVER), str(c_file), "-o", str(binary)], check=True)
        environment = dict(os.environ)
        environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
        environment.setdefault("UBSAN_OPTIONS", "halt_on_error=1")
        subprocess.run([str(binary)], check=True, env=environment)
    print(f"Reference: jameywine/GPL-for-GP3000@{PIN}; generated header SHA256 verified")


if __name__ == "__main__":
    main()
