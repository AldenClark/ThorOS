#!/usr/bin/env python3
"""Exercise production L3 DA-reference keys and fail-closed FDB ownership tags.

This is a host format/ownership test, not an ASIC packet-forwarding simulator.
The separate test_fe_register_contract.py decodes the same output with the
unmodified, pinned RTL8277C silicon register declarations.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek"

TEST = r'''
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "rtl9617c-fe-pipeline.h"

int main(void)
{
 const unsigned char mac[6]={2,0x77,0x66,0x55,0x44,0x33};
 unsigned int pin[4],row[4];
 rtl_fe_fdb_key(pin,mac);
 assert(rtl_fe_fdb_is_pin_domain(pin) && rtl_fe_fdb_is_pin(pin));
 assert(RTL_FE_FDB_PIN_VID==4095 && RTL_FE_FDB_PIN_SCIND==1 &&
        RTL_FE_FDB_PIN_DOT1P==0 && RTL_FE_FDB_PIN_PORT==16);

 /* Even the same MAC, same CPU port and same static flags in a normal
  * Linux bridge domain must not be mistaken for an L3-owned reference. */
 for(unsigned int vid=0;vid<4095;vid++) {
  for(unsigned int sc=0;sc<2;sc++)for(unsigned int pcp=0;pcp<8;pcp++) {
   memcpy(row,pin,sizeof(row));
   rtl_fe_bits_set(row,39,12,vid);
   rtl_fe_bits_set(row,38,1,sc);
   rtl_fe_bits_set(row,35,3,pcp);
   assert(!rtl_fe_fdb_is_pin_domain(row) && !rtl_fe_fdb_is_pin(row));
   assert(memcmp(row,pin,sizeof(row)));
  }
 }

 /* SC/PCP corruption in the reserved VID must remain excluded from an L2
  * scan/flush even though it is no longer a shareable L3 DA reference. */
 for(unsigned int sc=0;sc<2;sc++)for(unsigned int pcp=0;pcp<8;pcp++) {
  memcpy(row,pin,sizeof(row));
  rtl_fe_bits_set(row,38,1,sc);
  rtl_fe_bits_set(row,35,3,pcp);
  assert(rtl_fe_fdb_is_pin_domain(row));
  assert(rtl_fe_fdb_is_pin(row)==(sc==1 && pcp==0));
 }

 /* No dynamic, temporary, movable, multicast, invalid or blocked row can
  * be borrowed as a ready L3 owner, but none may be deleted by the L2 owner.
  * Mutable refresh and ageing fields do not change object identity. */
 const unsigned int type_bits[]={0,1,2,3,4,5,7,8,9,10,19,20,21};
 for(unsigned int i=0;i<sizeof(type_bits)/sizeof(type_bits[0]);i++) {
  memcpy(row,pin,sizeof(row));row[0]^=1U<<type_bits[i];
  assert(rtl_fe_fdb_is_pin_domain(row) && !rtl_fe_fdb_is_pin(row));
 }
 for(unsigned int age=0;age<256;age++)for(unsigned int refreshed=0;refreshed<2;refreshed++) {
  memcpy(row,pin,sizeof(row));
  rtl_fe_bits_set(row,11,8,age);rtl_fe_bits_set(row,6,1,refreshed);
  assert(rtl_fe_fdb_is_pin_domain(row) && rtl_fe_fdb_is_pin(row));
 }
 puts("FDB DA namespace: 65520 ordinary VLAN/SC/PCP keys, static-local CPU coexistence, reserved malformed rows and mutable age/refresh PASS (host only)");
 return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="fe-fdb-domain-") as temporary:
    directory = Path(temporary)
    source, binary = directory / "test.c", directory / "test"
    source.write_text(TEST)
    subprocess.run([os.environ.get("CC", "cc"), "-O1", "-g", "-std=c11",
                    "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
                    "-fno-sanitize-recover=all", "-I", str(DRIVER),
                    str(source), "-o", str(binary)], check=True)
    environment = dict(os.environ)
    environment.setdefault("ASAN_OPTIONS", "detect_leaks=0")
    environment.setdefault("UBSAN_OPTIONS", "halt_on_error=1")
    subprocess.run([str(binary)], check=True, env=environment)
